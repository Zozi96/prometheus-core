//! Hook fast path (spec #43, ticket #51): the retained `PreToolUse`
//! guards, answered natively.
//!
//! Scope is ADR-0010's: secret-path denial (an interactive ask on the
//! hosts that support one) and the non-blocking unchanged whole-file
//! reread warning. Every other event, tool, and command — direct
//! `dotnet`/`cargo` checks and parent edits included — passes with {}.
//! The Python `pretool_guard` is the behavioural oracle; the parity
//! suite in the Prometheus repo (tests/test_hook_fastpath_parity.py)
//! replays synthesized events through both and compares replies and
//! reread session state.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Small JSON helpers with Python semantics.
// ---------------------------------------------------------------------------

/// Python truthiness for a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object().and_then(|map| map.get(key))
}

/// `a or b` where the operands are event fields (missing reads as falsy).
fn py_or<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    match a {
        Some(value) if truthy(value) => Some(value),
        _ => b,
    }
}

fn as_str(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or("")
}

/// Python `str.casefold()` for the inputs this module sees. Rust's
/// lowercase mapping differs from casefold only outside ASCII/Latin-1
/// (e.g. `ß`); hook tool names and paths here are ASCII in practice.
fn casefold(text: &str) -> String {
    text.to_lowercase()
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (SESSION_ID) or with `:` (CALL_ID).
fn id_fullmatch(text: &str, allow_colon: bool) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    let rest_ok = chars.all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '_' | '-')
            || (allow_colon && c == ':')
    });
    rest_ok && text.chars().count() <= 128
}

fn tool_of(event: &Value) -> &str {
    as_str(py_or(get(event, "tool_name"), get(event, "toolName")))
}

fn input_of(event: &Value) -> Option<&Map<String, Value>> {
    get(event, "tool_input").and_then(Value::as_object)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Session storage: the per-session reread state directory.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn my_uid() -> u32 {
    unsafe { libc::getuid() }
}

struct Session {
    id: String,
}

impl Session {
    fn new(id: &str) -> Session {
        Session { id: id.to_string() }
    }

    /// record_path(session_id).parent: the per-session directory.
    fn dir(&self) -> PathBuf {
        session_parent().join(&self.id)
    }


}

/// The `prometheus` or `prometheus-<uid>` directory holding every session.
fn session_parent() -> PathBuf {
    #[cfg(unix)]
    {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            let path = PathBuf::from(&runtime);
            if path.is_absolute() {
                if let Ok(info) = std::fs::metadata(&path) {
                    use std::os::unix::fs::MetadataExt;
                    if info.is_dir() && info.uid() == my_uid() {
                        return path.join("prometheus");
                    }
                }
            }
        }
        std::env::temp_dir().join(format!("prometheus-{}", my_uid()))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("prometheus")
    }
}

#[cfg(unix)]
fn create_dir_700(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_dir_700(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

/// Resolve a path the way Python's `Path.resolve()` does for the shapes
/// hook inputs carry: existing components are canonicalized (symlinks
/// followed), the rest is appended and normalized lexically.
fn resolve_loose(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::RootDir => out.push(Path::new("/")),
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(name);
                if let Ok(canonical) = std::fs::canonicalize(&out) {
                    out = canonical;
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Secret paths: mirrors secret_read.py and the _secret_* functions.
// ---------------------------------------------------------------------------

const SECRET_SUFFIXES: [&str; 4] = [".example", ".sample", ".template", ".dist"];
const SECRET_EXTENSIONS: [&str; 6] = [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"];
const SECRET_BASENAMES: [&str; 13] = [
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".netrc", ".npmrc", ".pypirc",
    ".htpasswd", "auth.json", "credentials", "credentials.json", "secrets.json",
    "secrets.yml",
];
const SECRET_BASENAMES_EXTRA: &str = "secrets.yaml";
const SECRET_DIRS: [&str; 3] = [".ssh", ".aws", ".gnupg"];

fn secret_basenames() -> [&'static str; 14] {
    let mut all = [""; 14];
    all[..13].copy_from_slice(&SECRET_BASENAMES);
    all[13] = SECRET_BASENAMES_EXTRA;
    all
}

/// secret_read.secret_path_denied: a denial reason, or "".
fn secret_path_denied(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let parts: Vec<&str> = slashed
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let Some(basename_raw) = parts.last() else {
        return String::new();
    };
    let basename = casefold(basename_raw);
    if SECRET_SUFFIXES.iter().any(|suffix| basename.ends_with(suffix)) {
        return String::new();
    }
    let mut matched = String::new();
    if basename.starts_with(".env") {
        matched = basename.clone();
    } else if SECRET_EXTENSIONS.iter().any(|ext| basename.ends_with(ext)) {
        matched = basename.clone();
    } else if secret_basenames().contains(&basename.as_str()) {
        matched = basename.clone();
    } else if basename.starts_with("credentials") || basename.starts_with("secrets.") {
        matched = basename.clone();
    } else if basename.starts_with("id_") && !basename.ends_with(".pub") {
        matched = basename.clone();
    } else {
        for part in &parts {
            if SECRET_DIRS.contains(&casefold(part).as_str()) {
                matched = (*part).to_string();
                break;
            }
        }
    }
    if matched.is_empty() {
        return String::new();
    }
    format!("secret path '{matched}' is blocked; name '{matched}' in your prompt to allow it this turn")
}

/// sureforge_hook.secret_denied for one raw path value.
fn secret_denied(raw: Option<&Value>) -> String {
    let Some(raw) = raw.and_then(Value::as_str) else {
        return String::new();
    };
    let mut path = raw.trim().to_string();
    let chars: Vec<char> = path.chars().collect();
    if chars.len() >= 2 && chars[0] == chars[chars.len() - 1] && matches!(chars[0], '"' | '\'') {
        path = chars[1..chars.len() - 1].iter().collect::<String>().trim().to_string();
    }
    path = path.replace('\\', "/");
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    secret_path_denied(&path)
}

fn glob_secret_denied(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let cut = chars
        .iter()
        .position(|c| *c == '*' || *c == '?')
        .unwrap_or(chars.len());
    let prefix: String = chars[..cut].iter().collect();
    if prefix.is_empty() {
        return String::new();
    }
    let reason = secret_denied(Some(&Value::String(prefix.clone())));
    if !reason.is_empty() {
        return reason;
    }
    if cut == chars.len() {
        return String::new();
    }
    let base = casefold(prefix.replace('\\', "/").rsplit('/').next().unwrap_or(""));
    if !base.starts_with('.') && !base.starts_with("id_") && base.chars().count() < 4 {
        return String::new();
    }
    // Sorted order, where the Python oracle iterates a frozenset: when two
    // basenames share the prefix the oracle's named file varies by process
    // hash seed, so no order can match every run; sorted is deterministic.
    let mut names: Vec<&str> = secret_basenames().into_iter().collect();
    names.push(".env");
    names.sort_unstable();
    for name in names {
        if name.starts_with(&base) {
            return format!(
                "secret path '{name}' is blocked; name '{name}' in your prompt to allow it this turn"
            );
        }
    }
    String::new()
}

fn command_token_denied(token: &str) -> String {
    for candidate in token.split('=') {
        let reason = secret_denied(Some(&Value::String(candidate.to_string())));
        if !reason.is_empty() {
            return reason;
        }
        let reason = glob_secret_denied(candidate);
        if !reason.is_empty() {
            return reason;
        }
        // A `rev:path` git object operand names a tree path after the colon.
        if let Some(colon) = candidate.find(':') {
            let head = &candidate[..colon];
            let tail = &candidate[colon + 1..];
            if !head.is_empty() && !head.chars().any(char::is_whitespace) && !tail.is_empty() {
                let reason = command_token_denied(tail);
                if !reason.is_empty() {
                    return reason;
                }
            }
        }
    }
    String::new()
}

fn is_command_split(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '$' | '(' | ')' | '{' | '}' | '|' | ';' | '&' | '<' | '>')
}

fn split_command(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        if is_command_split(c) {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// sureforge_hook.secret_command_denied over a shell/eval string.
fn secret_command_denied(command: Option<&Value>) -> String {
    let Some(command) = command.and_then(Value::as_str) else {
        return String::new();
    };
    let stripped: String = command.chars().filter(|c| !matches!(c, '"' | '\'' | '`')).collect();
    for token in split_command(&stripped) {
        let reason = command_token_denied(&token);
        if !reason.is_empty() {
            return reason;
        }
    }
    // Quoted fragments: a quote-stripped scan can merge away a path inside
    // quotes, so each quoted span is scanned on its own as well.
    let chars: Vec<char> = command.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !matches!(chars[index], '"' | '\'' | '`') {
            index += 1;
            continue;
        }
        let Some(close) = (index + 1..chars.len()).find(|&at| matches!(chars[at], '"' | '\'' | '`')) else {
            break;
        };
        let fragment: String = chars[index + 1..close].iter().collect();
        for token in split_command(&fragment) {
            let reason = command_token_denied(&token);
            if !reason.is_empty() {
                return reason;
            }
        }
        index = close + 1;
    }
    String::new()
}

/// sureforge_hook._secret_tool_denial.
fn secret_tool_denial(event: &Value) -> String {
    let empty = Map::new();
    let inp = input_of(event).unwrap_or(&empty);
    for key in ["file_path", "path", "paths", "pattern", "glob", "notebook_path"] {
        let value = inp.get(key);
        match value {
            Some(Value::Array(items)) => {
                for item in items {
                    let reason = secret_denied(Some(item));
                    if !reason.is_empty() {
                        return reason;
                    }
                }
            }
            Some(item) => {
                let reason = secret_denied(Some(item));
                if !reason.is_empty() {
                    return reason;
                }
            }
            None => {
                let reason = secret_denied(None);
                if !reason.is_empty() {
                    return reason;
                }
            }
        }
    }
    secret_command_denied(inp.get("command"))
}

const FILE_READ_KEYS: [&str; 9] = [
    "file_path", "path", "paths", "pattern", "glob", "filePath", "target_file",
    "notebook_path", "target",
];

fn command_has_secret(command: &str) -> bool {
    for token in split_command(command) {
        if token.is_empty() {
            continue;
        }
        if !secret_path_denied(&token).is_empty() {
            return true;
        }
        if let Some(colon) = token.find(':') {
            if !secret_path_denied(&token[colon + 1..]).is_empty() {
                return true;
            }
        }
    }
    false
}

fn event_mentions_secret(event: &Value) -> bool {
    let mut sources: Vec<&Map<String, Value>> = Vec::new();
    for key in ["tool_input", "input"] {
        if let Some(map) = get(event, key).and_then(Value::as_object) {
            sources.push(map);
        }
    }
    if let Some(map) = event.as_object() {
        sources.push(map);
    }
    for source in sources {
        for key in FILE_READ_KEYS {
            let value = source.get(key);
            let items: Vec<&Value> = match value {
                Some(Value::Array(items)) => items.iter().collect(),
                Some(item) => vec![item],
                None => vec![],
            };
            for item in items {
                if let Value::String(text) = item {
                    if !secret_path_denied(text).is_empty() {
                        return true;
                    }
                }
            }
        }
        for key in ["command", "code", "input"] {
            if let Some(Value::String(command)) = source.get(key) {
                if command_has_secret(command) {
                    return true;
                }
            }
        }
    }
    false
}

fn file_reads(host: &str) -> Option<&'static [&'static str]> {
    match host {
        "claude" => Some(&["Read", "Grep", "Glob", "LS", "NotebookRead"]),
        "cursor" | "droid" => Some(&["Read", "Grep", "Glob", "LS", "Search", "Find"]),
        "devin" => Some(&[
            "read", "grep", "glob", "ls", "search", "find", "Read", "Grep",
            "Glob", "LS", "Search", "Find",
        ]),
        "omp" => Some(&[
            "read", "glob", "grep", "find", "ast_grep", "lsp", "web_search",
            "fetch", "search", "ask", "todo", "wait", "think", "yield", "goal",
            "recall", "reflect", "retain", "context_notes", "new_context",
            "security_scan", "report_tool_issue", "resolve", "reject", "propose",
        ]),
        _ => None,
    }
}

/// secret_read.read_failure_allows: a non-secret file read may proceed when
/// the gate itself failed; anything else stays fail-closed.
fn read_failure_allows(host: &str, event: &Value) -> bool {
    let tool = tool_of(event);
    if tool.is_empty() {
        return false;
    }
    let Some(allowed) = file_reads(&casefold(host)) else {
        return false;
    };
    if !allowed.contains(&tool) {
        return false;
    }
    !event_mentions_secret(event)
}

fn ask_reply(reason: &str) -> Value {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": reason,
    }})
}

// ---------------------------------------------------------------------------
// Unchanged-reread warning: mirrors read_warning.whole_file_warning.
// ---------------------------------------------------------------------------

const REREAD_MESSAGE: &str =
    "Unchanged whole-file reread: use the previous read or request a focused range.";
const REREAD_MAX_BYTES: u64 = 16 * 1024 * 1024;
const PARTIAL_KEYS: [&str; 9] = [
    "offset", "start", "end", "range", "start_line", "end_line", "startline",
    "endline", "view_range",
];

fn owner_private_existing(folder: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent = folder.parent();
        for path in [parent, Some(folder)] {
            let Some(path) = path else { return false };
            match std::fs::symlink_metadata(path) {
                Ok(info) => {
                    if !info.file_type().is_dir() || info.uid() != my_uid() || info.mode() & 0o077 != 0 {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }
    #[cfg(not(unix))]
    {
        folder.is_dir() && !folder.is_symlink()
    }
}

fn hash_file(path: &Path) -> Option<String> {
    use std::io::Read;
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options
    };
    #[cfg(not(unix))]
    let options = std::fs::OpenOptions::new().read(true).clone();
    let mut file = options.open(path).ok()?;
    let info = file.metadata().ok()?;
    if !info.is_file() || info.len() > REREAD_MAX_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1 << 20];
    let mut total: u64 = 0;
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            return Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect());
        }
        total += read as u64;
        if total > REREAD_MAX_BYTES {
            return None;
        }
        hasher.update(&buffer[..read]);
    }
}

enum StoredHash {
    Absent,
    Malformed,
    Present(String),
}

fn read_reread_state(path: &Path) -> StoredHash {
    use std::io::Read;
    if path.is_symlink() {
        return StoredHash::Malformed;
    }
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options
    };
    #[cfg(not(unix))]
    let options = std::fs::OpenOptions::new().read(true).clone();
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return StoredHash::Absent,
        Err(_) => return StoredHash::Malformed,
    };
    let info = match file.metadata() {
        Ok(info) => info,
        Err(_) => return StoredHash::Malformed,
    };
    if !info.is_file() || info.len() > 128 {
        return StoredHash::Malformed;
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return StoredHash::Malformed;
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text.trim().to_string(),
        Err(_) => return StoredHash::Malformed,
    };
    let valid = text.len() == 64
        && text.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if valid {
        StoredHash::Present(text)
    } else {
        StoredHash::Malformed
    }
}

fn write_reread_state(path: &Path, digest: &str) {
    if path.is_symlink() {
        return;
    }
    let Some(parent) = path.parent() else { return };
    let tmp = parent.join(format!(".reread-{}-{}", std::process::id(), digest));
    if std::fs::write(&tmp, format!("{digest}\n")).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// read_warning.whole_file_warning: MESSAGE on an unchanged whole-file
/// reread, else "". Advisory only; every failure is "".
fn whole_file_warning(
    host: &str,
    event: &Value,
    session: &Session,
    root: &Path,
    active: bool,
) -> String {
    // _read_path: the whole-file read's path, or "".
    if host == "omp" || casefold(tool_of(event)) != "read" {
        return String::new();
    }
    let empty = Map::new();
    let inp = get(event, "tool_input")
        .and_then(Value::as_object)
        .or_else(|| get(event, "input").and_then(Value::as_object))
        .unwrap_or(&empty);
    let lowered: Vec<String> = inp.keys().map(|key| casefold(key)).collect();
    if PARTIAL_KEYS.iter().any(|key| lowered.iter().any(|item| item == key))
        || lowered.iter().any(|item| item == "limit")
    {
        return String::new();
    }
    let mut raw = "";
    for key in ["file_path", "filePath", "path"] {
        if let Some(Value::String(text)) = inp.get(key) {
            if !text.trim().is_empty() {
                raw = text;
                break;
            }
        }
    }
    if raw.is_empty() || !id_fullmatch(&session.id, false) {
        return String::new();
    }
    let folder = session.dir();
    if active {
        // No SessionStart creates the session dir any more (ADR-0010):
        // the reread guard creates it owner-private on first use. An
        // existing insecure dir is never repaired, only refused below.
        if let Some(parent) = folder.parent() {
            let _ = create_dir_700(parent);
        }
        let _ = create_dir_700(&folder);
    }
    if !owner_private_existing(&folder) {
        return String::new();
    }
    if !secret_path_denied(raw).is_empty() {
        return String::new();
    }
    let target_path = {
        let candidate = Path::new(raw);
        if candidate.is_absolute() {
            resolve_loose(candidate)
        } else {
            resolve_loose(&root.join(candidate))
        }
    };
    let target = target_path.to_string_lossy().into_owned();
    if !secret_path_denied(&target).is_empty() {
        return String::new();
    }
    let info = match std::fs::metadata(&target_path) {
        Ok(info) => info,
        Err(_) => return String::new(),
    };
    if !info.is_file() || info.len() > REREAD_MAX_BYTES {
        return String::new();
    }
    let Some(digest) = hash_file(&target_path) else {
        return String::new();
    };
    let canonical = resolve_loose(root).to_string_lossy().into_owned();
    let mut key_bytes = canonical.into_bytes();
    key_bytes.push(0);
    key_bytes.extend_from_slice(target.as_bytes());
    let key = sha256_hex(&key_bytes);
    let state = folder.join(format!("reread-{key}"));
    match read_reread_state(&state) {
        StoredHash::Malformed => String::new(),
        StoredHash::Present(stored) if stored == digest => REREAD_MESSAGE.to_string(),
        _ => {
            if active {
                write_reread_state(&state, &digest);
            }
            String::new()
        }
    }
}

fn read_warn_reply(host: &str, event: &Value, session: &Session, root: &Path, active: bool) -> Value {
    let text = whole_file_warning(host, event, session, root, active);
    if text.is_empty() {
        return json!({});
    }
    json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": text}})
}

// ---------------------------------------------------------------------------
// Routing: mirrors the adapters' envelope validation, guard_stop's
// PreToolUse failure posture, and dispatch's per-tool-call events.
// ---------------------------------------------------------------------------

const SECRET_ASK_HOSTS: [&str; 4] = ["claude", "droid", "devin", "muse"];

/// One answered event: the reply object the host adapter would print, and
/// the normalized decision the shadow log records.
pub struct Outcome {
    pub reply: Value,
    pub decision: &'static str,
    pub reason: String,
    pub event_name: String,
    pub tool: String,
}

/// How the binary was invoked: shadow mode (the default) never writes
/// session state — the Python hook still governs and its writes are the
/// state both sides read. `--active` is the takeover posture and is not
/// wired into any host configuration by this ticket.
pub struct Options {
    pub active: bool,
    pub shadow_log: Option<String>,
}

fn outcome_from_reply(reply: Value, event_name: &str, tool: &str) -> Outcome {
    let mut decision = "allow";
    let mut reason = String::new();
    if let Some(out) = get(&reply, "hookSpecificOutput") {
        if let Some(found) = get(out, "permissionDecision").and_then(Value::as_str) {
            if found == "ask" || found == "deny" {
                decision = if found == "ask" { "ask" } else { "deny" };
                reason = as_str(get(out, "permissionDecisionReason")).to_string();
            }
        }
        if decision == "allow" {
            if let Some(text) = get(out, "additionalContext").and_then(Value::as_str) {
                decision = "warn";
                reason = text.to_string();
            }
        }
    }
    if decision == "allow" {
        if let Some(text) = get(&reply, "systemMessage").and_then(Value::as_str) {
            decision = "warn";
            reason = text.to_string();
        }
    }
    Outcome {
        reply,
        decision,
        reason,
        event_name: event_name.to_string(),
        tool: tool.to_string(),
    }
}

fn allow_outcome(event_name: &str, tool: &str) -> Outcome {
    outcome_from_reply(json!({}), event_name, tool)
}

fn event_name_raw(event: &Value) -> String {
    as_str(py_or(
        py_or(get(event, "hook_event_name"), get(event, "hookEventName")),
        get(event, "event_name"),
    ))
    .to_string()
}

fn normalized_name(event: &Value) -> String {
    casefold(&event_name_raw(event)).replace('_', "")
}

fn valid_session_id(event: &Value) -> Option<String> {
    let value = get(event, "session_id").and_then(Value::as_str)?;
    if id_fullmatch(value, false) {
        Some(value.to_string())
    } else {
        None
    }
}

fn resolve_root(cwd: &str) -> Result<PathBuf, &'static str> {
    let resolved = match std::fs::canonicalize(cwd) {
        Ok(path) => path,
        Err(_) => return Err("cwd-invalid"),
    };
    if !resolved.is_dir() {
        return Err("cwd-not-directory");
    }
    Ok(resolved)
}

/// The adapters' reply to an envelope problem: a PreToolUse event asks
/// (unless it is a non-secret file read, which proceeds), anything else
/// gets the warning as a systemMessage.
fn problem_reply(host: &str, event: &Value, problem: &str, name: &str, tool: &str) -> Outcome {
    if name == "pretooluse" {
        if read_failure_allows(host, event) {
            return allow_outcome(name, tool);
        }
        return outcome_from_reply(
            ask_reply(&format!("Hook warning: {problem} — consent could not be evaluated")),
            name,
            tool,
        );
    }
    outcome_from_reply(
        json!({"systemMessage": format!("Hook warning: {problem}")}),
        name,
        tool,
    )
}

/// The retained PreToolUse guards (ADR-0010): a secret path earns an
/// interactive ask, an unchanged whole-file reread earns a warning, and
/// everything else passes. No direct-check denial, no write counters.
fn record_tool_call(host: &str, event: &Value, session: &Session, root: &Path, opts: &Options) -> Value {
    if SECRET_ASK_HOSTS.contains(&host) {
        let reason = secret_tool_denial(event);
        if !reason.is_empty() {
            return ask_reply(&reason);
        }
    }
    if matches!(host, "claude" | "droid" | "muse") {
        return read_warn_reply(host, event, session, root, opts.active);
    }
    json!({})
}

fn dispatch_level(host: &str, event: &Value, session: &Session, root: &Path, opts: &Options) -> Outcome {
    let name = normalized_name(event);
    let tool = tool_of(event).to_string();
    match name.as_str() {
        "pretooluse" => outcome_from_reply(record_tool_call(host, event, session, root, opts), &name, &tool),
        _ => allow_outcome(&name, &tool),
    }
}

/// DEVIN_PROJECT_DIR, else the event's cwd (the adapter's root candidate).
fn devin_candidate(event: &Value) -> Option<String> {
    if let Ok(value) = std::env::var("DEVIN_PROJECT_DIR") {
        if !value.is_empty() {
            return Some(value);
        }
    }
    let cwd = as_str(get(event, "cwd"));
    if cwd.is_empty() {
        None
    } else {
        Some(cwd.to_string())
    }
}

fn claude_envelope(host: &str, event: &Value, opts: &Options) -> Outcome {
    let name = normalized_name(event);
    let tool = tool_of(event).to_string();
    let cwd = as_str(get(event, "cwd"));
    if cwd.is_empty() {
        return problem_reply(host, event, "cwd-missing", &name, &tool);
    }
    let Some(session_id) = valid_session_id(event) else {
        return problem_reply(host, event, "session-id-invalid", &name, &tool);
    };
    match resolve_root(cwd) {
        Ok(root) => dispatch_level(host, event, &Session::new(&session_id), &root, opts),
        Err(problem) => problem_reply(host, event, problem, &name, &tool),
    }
}

fn droid_envelope(event: &Value, opts: &Options) -> Outcome {
    let name = normalized_name(event);
    let tool = tool_of(event).to_string();
    let Some(session_id) = valid_session_id(event) else {
        return problem_reply("droid", event, "session-id-invalid", &name, &tool);
    };
    let cwd = as_str(get(event, "cwd"));
    if cwd.is_empty() {
        return problem_reply("droid", event, "cwd-missing", &name, &tool);
    }
    match resolve_root(cwd) {
        Ok(root) => dispatch_level("droid", event, &Session::new(&session_id), &root, opts),
        Err(problem) => problem_reply("droid", event, problem, &name, &tool),
    }
}

fn devin_envelope(event: &Value, opts: &Options) -> Outcome {
    let name = normalized_name(event);
    let tool = tool_of(event).to_string();
    // The adapter answers a non-secret read before the gate loads.
    if name == "pretooluse"
        && casefold(tool_of(event)) == "read"
        && read_failure_allows("devin", event)
    {
        let candidate = devin_candidate(event);
        let candidate_path = match candidate {
            Some(text) => PathBuf::from(text),
            None => std::env::current_dir().unwrap_or_default(),
        };
        let session = Session::new(as_str(get(event, "session_id")));
        let reply = read_warn_reply("devin", event, &session, &candidate_path, opts.active);
        return outcome_from_reply(reply, &name, &tool);
    }
    let Some(session_id) = valid_session_id(event) else {
        return problem_reply("devin", event, "session-id-invalid", &name, &tool);
    };
    let root = match devin_candidate(event) {
        Some(path) => match std::fs::canonicalize(&path) {
            Ok(resolved) if resolved.is_dir() => resolved,
            Ok(_) => return problem_reply("devin", event, "root-not-directory", &name, &tool),
            Err(_) => return problem_reply("devin", event, "root-invalid", &name, &tool),
        },
        None => match std::env::current_dir() {
            Ok(dir) => dir,
            Err(_) => return problem_reply("devin", event, "root-invalid", &name, &tool),
        },
    };
    dispatch_level("devin", event, &Session::new(&session_id), &root, opts)
}

fn handle_inner(host: &str, raw: &[u8], opts: &Options) -> Outcome {
    let parsed: Option<Value> = serde_json::from_slice(raw).ok();
    let Some(event) = parsed.as_ref().filter(|value| value.is_object()) else {
        // Unparseable, or not an object: the adapters warn and move on.
        // Claude names a non-object payload "event-malformed".
        let problem = if host == "claude" && parsed.is_some() {
            "event-malformed"
        } else {
            "invalid-json"
        };
        return outcome_from_reply(
            json!({"systemMessage": format!("Hook warning: {problem}")}),
            "",
            "",
        );
    };
    match host {
        "droid" => droid_envelope(event, opts),
        "devin" => devin_envelope(event, opts),
        // "muse" events arrive in the Claude shape and its record_tool_call
        // row is the direct-check list only; claude_envelope routes it
        // through the same envelope, and record_tool_call's claude-only
        // fallthrough keys on the host name.
        _ => claude_envelope(host, event, opts),
    }
}

/// Answer one hook event for `host` from the raw stdin bytes. Total by
/// construction: malformed input yields the adapters' structured warning,
/// never a panic and never a denial the oracle would not have made.
pub fn handle(host: &str, raw: &[u8], opts: &Options, started: Instant) -> (Outcome, f64) {
    let outcome = handle_inner(host, raw, opts);
    (outcome, started.elapsed().as_secs_f64() * 1000.0)
}

/// The session id a raw event carries, for the shadow log; "" when the
/// event does not parse or names none.
pub fn session_id_of(raw: &[u8]) -> String {
    let parsed: Option<Value> = serde_json::from_slice(raw).ok();
    match parsed.as_ref().and_then(|value| get(value, "session_id")) {
        Some(Value::String(text)) => text.clone(),
        _ => String::new(),
    }
}

/// The shadow log record for one answered event: one JSON object per line,
/// keys sorted, no wall-clock fields, so two runs diff cleanly. `ms` is
/// the only volatile field and comparators ignore it.
pub fn log_record(host: &str, session_id: &str, outcome: &Outcome, ms: f64) -> Value {
    let mut record = Map::new();
    record.insert("schema".into(), json!(1));
    record.insert("host".into(), json!(host));
    record.insert("event".into(), json!(outcome.event_name));
    record.insert("session".into(), json!(session_id));
    record.insert("tool".into(), json!(outcome.tool));
    record.insert("decision".into(), json!(outcome.decision));
    record.insert("reason".into(), json!(outcome.reason));
    record.insert("reply".into(), outcome.reply.clone());
    record.insert("ms".into(), json!(ms));
    Value::Object(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_path_table() {
        for (path, denied) in [
            (".env", true),
            (".env.example", false),
            ("config/secrets.yml", true),
            ("config/secrets.yml.template", false),
            ("keys/id_rsa", true),
            ("keys/id_rsa.pub", false),
            ("keys/id_backup", true),
            (".ssh/config", true),
            ("cert.pem", true),
            ("credentials.csv", true),
            ("src/app.py", false),
            ("", false),
        ] {
            assert_eq!(denied, !secret_path_denied(path).is_empty(), "{path}");
        }
    }

    fn run(host: &str, event: Value) -> Outcome {
        let opts = Options { active: true, shadow_log: None };
        let (outcome, _) = handle(host, event.to_string().as_bytes(), &opts, Instant::now());
        outcome
    }

    fn pretool(tool: &str, input: Value) -> Value {
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
            "cwd": std::env::temp_dir().to_string_lossy(),
            "session_id": "t61test",
        })
    }

    #[test]
    fn direct_checks_and_edits_pass() {
        // ADR-0010: no direct-check denial and no write counters.
        for command in ["dotnet test", "cargo test", "dotnet build", "cargo b"] {
            let outcome = run("claude", pretool("Bash", json!({"command": command})));
            assert_eq!(outcome.reply, json!({}), "{command}");
            assert_eq!(outcome.decision, "allow", "{command}");
        }
        for _ in 0..6 {
            let outcome = run("droid", pretool("Edit", json!({"file_path": "src/a.rs"})));
            assert_eq!(outcome.reply, json!({}));
        }
    }

    #[test]
    fn secret_still_asks_and_stop_never_blocks() {
        let outcome = run("claude", pretool("Read", json!({"file_path": ".env"})));
        assert_eq!(outcome.decision, "ask");
        let stop = run("claude", json!({
            "hook_event_name": "Stop",
            "cwd": std::env::temp_dir().to_string_lossy(),
            "session_id": "t61test",
        }));
        assert_eq!(stop.reply, json!({}));
        assert_eq!(stop.decision, "allow");
    }

}
