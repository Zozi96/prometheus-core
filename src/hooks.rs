//! Hook fast path (spec #43, ticket #51): the per-tool-call decisions the
//! Python gate makes in `record_tool_call` (runtime/sureforge_hook.py) and
//! the Droid PostToolUse gate, answered natively.
//!
//! The Python runtime is the behavioural oracle (ADR-0007 D5). Each section
//! below mirrors named Python functions; the differential parity suite in
//! the Prometheus repo (tests/test_hook_fastpath_parity.py) replays
//! synthesized events through both implementations and compares replies and
//! decision-bearing session state.
//!
//! Scope, exactly as the ticket names it: secret-path denial (an
//! interactive ask on the hosts that support one), direct-check denial
//! naming the run-check equivalent (ADR-0004), and the per-session Droid
//! writer/tool counters, plus the unchanged-reread warning those hosts
//! return on the same path. Claude's attribution classification, omp's and
//! Cursor's own adapter gates, the Droid adapter's dispatch registry, and
//! every other event type stay with the Python runtime: the binary logs a
//! `delegate` decision and answers {}. The Droid PostToolUse counter
//! resync also delegates: it is keyed to the tree fingerprint, which the
//! scan owns (tickets #47-#49); rebuilding that pipeline here would create
//! a second fingerprint implementation to keep in parity.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
// Session storage: mirrors record_path / secure_dir / _read / _write.
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

    fn file(&self, name: &str) -> PathBuf {
        self.dir().join(name)
    }

    /// sureforge_hook._read: file text stripped, "" on any failure.
    fn read(&self, name: &str) -> String {
        match std::fs::read_to_string(self.file(name)) {
            Ok(text) => text.trim().to_string(),
            Err(_) => String::new(),
        }
    }

    /// sureforge_hook._write. A no-op in shadow mode: the governing Python
    /// hook performs the write and both sides read the same result.
    fn write(&self, name: &str, text: &str, append: bool, active: bool) {
        if !active {
            return;
        }
        write_file(&self.file(name), text, append);
    }

    /// sureforge_hook.secure_dir. In shadow mode nothing is created and no
    /// mode is relaxed; the verdict is the one Python reaches after its
    /// own creation, because the governing process performs it.
    fn secure_dir(&self, active: bool) -> bool {
        secure_dir(&self.dir(), active)
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

fn write_file(path: &Path, text: &str, append: bool) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if let Ok(mut file) = options.open(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        let _ = file.write_all(text.as_bytes());
    }
}

fn secure_dir(folder: &Path, active: bool) -> bool {
    let parent = match folder.parent() {
        Some(parent) => parent.to_path_buf(),
        None => return false,
    };
    if active {
        let _ = create_dir_700(&parent);
        let _ = create_dir_700(folder);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for path in [&parent, folder] {
            match std::fs::symlink_metadata(path) {
                Ok(info) => {
                    if !info.is_dir() || info.uid() != my_uid() || info.mode() & 0o022 != 0 {
                        return false;
                    }
                    if active && info.mode() & 0o077 != 0 {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            path,
                            std::fs::Permissions::from_mode(0o700),
                        );
                    }
                }
                // Missing in shadow mode: Python's creation would land a
                // fresh 0700 directory owned by this user, which passes.
                Err(_) if !active && !path.exists() => {}
                Err(_) => return false,
            }
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = folder;
        true
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

/// Python `len(text.splitlines())`: boundaries are \n, \r (with \r\n one
/// boundary), \v, \f, \x1c-\x1e, \x85, \u2028 and \u2029.
fn splitlines_count(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut boundaries = 0usize;
    let mut index = 0usize;
    let mut ends_on_boundary = false;
    while index < chars.len() {
        let c = chars[index];
        let boundary = matches!(
            c,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}'
                | '\u{2028}' | '\u{2029}'
        );
        if boundary {
            boundaries += 1;
            ends_on_boundary = true;
            if c == '\r' && index + 1 < chars.len() && chars[index + 1] == '\n' {
                index += 1;
            }
        } else {
            ends_on_boundary = false;
        }
        index += 1;
    }
    if ends_on_boundary {
        boundaries
    } else {
        boundaries + 1
    }
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
const GENERIC_SECRET_BASENAMES: [&str; 8] = [
    "config", "credentials", "known_hosts", "authorized_keys", "auth", "key",
    "secret", "token",
];

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

fn norm_secret_path(raw: &str) -> String {
    raw.replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Chars that continue a path token in prose (_PATH_CHARS).
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '_' | '.' | '/' | '\\' | '~' | '+' | '@' | '%' | ':' | '=' | '-')
}

fn prompt_bounded(prompt: &[char], needle: &[char]) -> bool {
    if needle.len() < 3 || needle.len() > prompt.len() {
        return false;
    }
    for start in 0..=(prompt.len() - needle.len()) {
        if &prompt[start..start + needle.len()] != needle {
            continue;
        }
        let before_ok = start == 0 || !is_path_char(prompt[start - 1]);
        let end = start + needle.len();
        let after_ok = end == prompt.len() || !is_path_char(prompt[end]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// sureforge_hook.prompt_allows_secret over the latest recorded prompt.
fn prompt_allows_secret(candidate: &str, session: &Session) -> bool {
    if !id_fullmatch(&session.id, false) {
        return false;
    }
    let text = match std::fs::read_to_string(session.file("prompts.jsonl")) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let mut prompt = String::new();
    for line in text.split('\n') {
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            if let Value::String(found) = value {
                prompt = found;
            }
        }
    }
    if prompt.is_empty() {
        return false;
    }
    let lowered: Vec<char> = casefold(&prompt).chars().collect();
    let norm = norm_secret_path(&casefold(candidate));
    if norm.is_empty() {
        return false;
    }
    let parts: Vec<&str> = norm.split('/').collect();
    let basename = parts[parts.len() - 1];
    let strict = GENERIC_SECRET_BASENAMES.contains(&basename)
        || parts.iter().any(|part| SECRET_DIRS.contains(part));
    if !strict {
        let base_chars: Vec<char> = basename.chars().collect();
        let norm_chars: Vec<char> = norm.chars().collect();
        if prompt_bounded(&lowered, &base_chars) || prompt_bounded(&lowered, &norm_chars) {
            return true;
        }
    }
    // Qualified path tokens in the prompt: a token unlocks a path it ends.
    let mut index = 0usize;
    while index < lowered.len() {
        if !is_path_char(lowered[index]) {
            index += 1;
            continue;
        }
        let start = index;
        let mut has_slash = false;
        while index < lowered.len() && is_path_char(lowered[index]) {
            if lowered[index] == '/' || lowered[index] == '\\' {
                has_slash = true;
            }
            index += 1;
        }
        if !has_slash {
            continue;
        }
        let token: String = lowered[start..index].iter().collect();
        let token = norm_secret_path(&token);
        if token.is_empty() {
            continue;
        }
        if token == norm || norm.ends_with(&format!("/{token}")) {
            return true;
        }
    }
    false
}

/// sureforge_hook.secret_denied for one raw path value.
fn secret_denied(raw: Option<&Value>, session: &Session) -> String {
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
    let reason = secret_path_denied(&path);
    if !reason.is_empty() && prompt_allows_secret(&path, session) {
        return String::new();
    }
    reason
}

fn glob_secret_denied(token: &str, session: &Session) -> String {
    let chars: Vec<char> = token.chars().collect();
    let cut = chars
        .iter()
        .position(|c| *c == '*' || *c == '?')
        .unwrap_or(chars.len());
    let prefix: String = chars[..cut].iter().collect();
    if prefix.is_empty() {
        return String::new();
    }
    let reason = secret_denied(Some(&Value::String(prefix.clone())), session);
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

fn command_token_denied(token: &str, session: &Session) -> String {
    for candidate in token.split('=') {
        let reason = secret_denied(Some(&Value::String(candidate.to_string())), session);
        if !reason.is_empty() {
            return reason;
        }
        let reason = glob_secret_denied(candidate, session);
        if !reason.is_empty() {
            return reason;
        }
        // A `rev:path` git object operand names a tree path after the colon.
        if let Some(colon) = candidate.find(':') {
            let head = &candidate[..colon];
            let tail = &candidate[colon + 1..];
            if !head.is_empty() && !head.chars().any(char::is_whitespace) && !tail.is_empty() {
                let reason = command_token_denied(tail, session);
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
fn secret_command_denied(command: Option<&Value>, session: &Session) -> String {
    let Some(command) = command.and_then(Value::as_str) else {
        return String::new();
    };
    let stripped: String = command.chars().filter(|c| !matches!(c, '"' | '\'' | '`')).collect();
    for token in split_command(&stripped) {
        let reason = command_token_denied(&token, session);
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
            let reason = command_token_denied(&token, session);
            if !reason.is_empty() {
                return reason;
            }
        }
        index = close + 1;
    }
    String::new()
}

/// sureforge_hook._secret_tool_denial.
fn secret_tool_denial(event: &Value, session: &Session) -> String {
    let empty = Map::new();
    let inp = input_of(event).unwrap_or(&empty);
    for key in ["file_path", "path", "paths", "pattern", "glob", "notebook_path"] {
        let value = inp.get(key);
        match value {
            Some(Value::Array(items)) => {
                for item in items {
                    let reason = secret_denied(Some(item), session);
                    if !reason.is_empty() {
                        return reason;
                    }
                }
            }
            Some(item) => {
                let reason = secret_denied(Some(item), session);
                if !reason.is_empty() {
                    return reason;
                }
            }
            None => {
                let reason = secret_denied(None, session);
                if !reason.is_empty() {
                    return reason;
                }
            }
        }
    }
    secret_command_denied(inp.get("command"), session)
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

// ---------------------------------------------------------------------------
// Shell scanning and the ADR-0004 direct-check denial.
// Mirrors _shell_segments, _segment_tokens (shlex), _command_substitutions,
// _compiled_check_name, _compiled_program_name, direct_check_denial.
// ---------------------------------------------------------------------------

fn shell_segments(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut segments: Vec<String> = Vec::new();
    let mut current: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        if let Some(open) = quote {
            current.push(c);
            if c == '\\' && open == '"' && index + 1 < chars.len() {
                current.push(chars[index + 1]);
                index += 2;
                continue;
            }
            if c == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(c, '\'' | '"' | '`') {
            quote = Some(c);
            current.push(c);
            index += 1;
            continue;
        }
        if c == '\\' && index + 1 < chars.len() {
            current.push(c);
            current.push(chars[index + 1]);
            index += 2;
            continue;
        }
        if c == '#' && (current.is_empty() || current[current.len() - 1].is_whitespace()) {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        let pair = index + 1 < chars.len()
            && ((chars[index] == '&' && chars[index + 1] == '&')
                || (chars[index] == '|' && chars[index + 1] == '|'));
        if pair || matches!(c, ';' | '|' | '&' | '\n') {
            segments.push(current.iter().collect());
            current = Vec::new();
            index += if pair { 2 } else { 1 };
            continue;
        }
        current.push(c);
        index += 1;
    }
    segments.push(current.iter().collect());
    segments
        .iter()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .collect()
}

/// POSIX shlex (Python `shlex.split`, comments disabled). Err on an
/// unterminated quote or escape, where Python raises ValueError and the
/// caller falls back to a plain whitespace split.
fn shlex_split(text: &str) -> Result<Vec<String>, ()> {
    #[derive(PartialEq)]
    enum State {
        Normal,
        Single,
        Double,
    }
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut has_token = false;
    let mut state = State::Normal;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match state {
            State::Normal => {
                if c.is_whitespace() {
                    if has_token {
                        tokens.push(std::mem::take(&mut token));
                        has_token = false;
                    }
                } else if c == '\'' {
                    state = State::Single;
                    has_token = true;
                } else if c == '"' {
                    state = State::Double;
                    has_token = true;
                } else if c == '\\' {
                    has_token = true;
                    match chars.next() {
                        Some('\n') => {}
                        Some(escaped) => token.push(escaped),
                        None => return Err(()),
                    }
                } else {
                    has_token = true;
                    token.push(c);
                }
            }
            State::Single => {
                if c == '\'' {
                    state = State::Normal;
                } else {
                    token.push(c);
                }
            }
            State::Double => {
                if c == '"' {
                    state = State::Normal;
                } else if c == '\\' {
                    // CPython shlex, unlike a POSIX shell, escapes only the
                    // quote itself and the escape character inside double
                    // quotes; before anything else the backslash is literal
                    // and the next character is processed normally.
                    match chars.peek() {
                        Some('"' | '\\') => {
                            token.push(chars.next().unwrap_or_default());
                        }
                        _ => token.push('\\'),
                    }
                } else {
                    token.push(c);
                }
            }
        }
    }
    if state != State::Normal {
        return Err(());
    }
    if has_token {
        tokens.push(token);
    }
    Ok(tokens)
}

fn segment_tokens(text: &str) -> Vec<String> {
    let mut text = text.trim().to_string();
    while text.starts_with('(') || text.starts_with('{') {
        text = text[1..].trim_start().to_string();
    }
    while text.ends_with(')') || text.ends_with('}') {
        text = text[..text.len() - 1].trim_end().to_string();
    }
    if text.is_empty() {
        return Vec::new();
    }
    match shlex_split(&text) {
        Ok(tokens) => tokens.into_iter().filter(|token| !token.is_empty()).collect(),
        Err(()) => text.split_whitespace().map(str::to_string).collect(),
    }
}

fn command_name(token: &str) -> String {
    let name = token.replace('\\', "/");
    let name = name.rsplit('/').next().unwrap_or("");
    let lowered = casefold(name);
    let stripped = if lowered.ends_with(".exe") {
        &name[..name.len() - 4]
    } else {
        name
    };
    casefold(stripped)
}

fn command_substitutions(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut bodies = Vec::new();
    let mut quote: Option<char> = None;
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        if c == '\\' && quote != Some('\'') {
            index += 2;
            continue;
        }
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(c, '\'' | '"' | '`') {
            quote = Some(c);
            index += 1;
            continue;
        }
        if c == '$' && index + 1 < chars.len() && chars[index + 1] == '(' {
            let mut depth = 1usize;
            let mut cursor = index + 2;
            while cursor < chars.len() && depth > 0 {
                if chars[cursor] == '(' {
                    depth += 1;
                } else if chars[cursor] == ')' {
                    depth -= 1;
                }
                cursor += 1;
            }
            if depth > 0 {
                index = cursor;
                continue;
            }
            bodies.push(chars[index + 2..cursor - 1].iter().collect());
            index = cursor;
            continue;
        }
        index += 1;
    }
    bodies
}

const SHELL_BINARIES: [&str; 9] = [
    "sh", "bash", "dash", "zsh", "ksh", "fish", "cmd", "powershell", "pwsh",
];
const SHELL_EVAL: [&str; 5] = ["-c", "-lc", "-cl", "/c", "-command"];
const COMPILED_WRAPPERS: [&str; 7] = ["env", "command", "exec", "nohup", "nice", "time", "sudo"];

fn wrapper_value_flags(name: &str) -> &'static [&'static str] {
    match name {
        "sudo" => &["-u", "-g", "-C", "-D", "-R", "-T", "-h", "-p", "-r", "-t", "-U"],
        "env" => &["-u", "-C", "-S"],
        "nice" => &["-n"],
        "timeout" => &["-k", "-s"],
        _ => &[],
    }
}

fn env_assign(token: &str) -> bool {
    // ^[A-Za-z_][A-Za-z0-9_]*=
    let mut chars = token.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    for c in chars {
        if c == '=' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    false
}

fn compiled_program_name(tokens: &[String]) -> String {
    if tokens.is_empty() {
        return String::new();
    }
    let name = command_name(&tokens[0]);
    let args = &tokens[1..];
    if name == "msbuild" {
        return "msbuild".to_string();
    }
    if name == "dotnet" {
        let mut index = 0usize;
        while index < args.len() {
            let folded = casefold(&args[index]);
            if ["--info", "--version", "-d", "--diagnostics", "-h", "--help"].contains(&folded.as_str()) {
                index += 1;
                continue;
            }
            if ["-v", "--verbosity"].contains(&folded.as_str()) {
                index += 2;
                continue;
            }
            if args[index].starts_with('-') || args[index].starts_with('/') {
                index += 1;
                continue;
            }
            return if ["build", "test", "msbuild"].contains(&folded.as_str()) {
                format!("dotnet {folded}")
            } else {
                String::new()
            };
        }
        return String::new();
    }
    if name == "cargo" {
        let mut index = 0usize;
        while index < args.len() {
            let folded = casefold(&args[index]);
            if folded.starts_with('+')
                || ["-v", "--verbose", "-q", "--quiet", "--locked", "--frozen", "--offline"]
                    .contains(&folded.as_str())
            {
                index += 1;
                continue;
            }
            if ["--color", "--config", "-C", "-Z"].contains(&folded.as_str()) {
                index += 2;
                continue;
            }
            if args[index].starts_with('-') {
                index += 1;
                continue;
            }
            let subcommand = match folded.as_str() {
                "b" => "build".to_string(),
                "t" => "test".to_string(),
                _ => folded,
            };
            return if ["build", "test"].contains(&subcommand.as_str()) {
                format!("cargo {subcommand}")
            } else {
                String::new()
            };
        }
        return String::new();
    }
    String::new()
}

fn compiled_check_name(tokens: &[String], depth: usize) -> String {
    if depth > 4 || tokens.is_empty() {
        return String::new();
    }
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        let name = command_name(token);
        if !token.starts_with('-') && env_assign(token) {
            index += 1;
            continue;
        }
        if COMPILED_WRAPPERS.contains(&name.as_str()) {
            index += 1;
            let values = wrapper_value_flags(&name);
            while index < tokens.len() && tokens[index].starts_with('-') {
                let takes_value = values.contains(&tokens[index].as_str());
                index += 1;
                if takes_value {
                    index += 1;
                }
            }
            continue;
        }
        if name == "timeout" {
            index += 1;
            while index < tokens.len() && tokens[index].starts_with('-') {
                index += 1;
            }
            index += 1; // the duration
            continue;
        }
        if SHELL_BINARIES.contains(&name.as_str()) {
            let following = if index + 1 < tokens.len() {
                casefold(&tokens[index + 1])
            } else {
                String::new()
            };
            if SHELL_EVAL.contains(&following.as_str()) {
                let inner = tokens[index + 2..].join(" ");
                return compiled_check_name(&segment_tokens(&inner), depth + 1);
            }
            return String::new();
        }
        return compiled_program_name(&tokens[index..]);
    }
    String::new()
}

fn run_check_segment(tokens: &[String]) -> bool {
    if !tokens.iter().any(|token| command_name(token) == "sureforge_hook.py") {
        return false;
    }
    tokens.iter().any(|token| token == "run-check")
}

fn direct_check_message(name: &str, session_id: Option<&str>) -> String {
    let hook = "python3 ~/.agents/prometheus/sureforge_hook.py run-check";
    let gate = if session_id.is_some() { " --gate <gate.json>" } else { "" };
    format!(
        "`{name}` is a compiled check; run it through run-check, not the shell. \
         Use `{hook} --changed{gate} --log <log>` for the changed plan, or \
         `{hook}{gate} --log <log> -- {name} <args>` for that one command. \
         A test run already builds: run-check runs the incremental build before \
         dotnet test or cargo test, so a separate build step is unnecessary."
    )
}

/// sureforge_hook.direct_check_denial.
fn direct_check_denial(command: Option<&Value>, session_id: Option<&str>) -> String {
    let Some(command) = command.and_then(Value::as_str) else {
        return String::new();
    };
    if command.trim().is_empty() {
        return String::new();
    }
    let mut segments = shell_segments(command);
    for body in command_substitutions(command) {
        segments.extend(shell_segments(&body));
    }
    for segment in &segments {
        let tokens = segment_tokens(segment);
        if tokens.is_empty() || run_check_segment(&tokens) {
            continue;
        }
        let name = compiled_check_name(&tokens, 0);
        if !name.is_empty() {
            return direct_check_message(&name, session_id);
        }
    }
    String::new()
}

const COMPILED_SHELL_TOOLS: [&str; 8] = [
    "Bash", "PowerShell", "Execute", "Shell", "bash", "exec", "run_terminal_cmd",
    "terminal",
];

/// sureforge_hook._direct_check_tool_denial.
fn direct_check_tool_denial(event: &Value, session_id: &str) -> String {
    let tool = tool_of(event);
    if !COMPILED_SHELL_TOOLS.contains(&tool) {
        return String::new();
    }
    for key in ["tool_input", "input"] {
        let Some(inp) = get(event, key).and_then(Value::as_object) else {
            continue;
        };
        for name in ["command", "cmd"] {
            let reason = direct_check_denial(inp.get(name), Some(session_id));
            if !reason.is_empty() {
                return reason;
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Droid counters: mirrors the _droid_* functions and _load/_save_counter.
// ---------------------------------------------------------------------------

const DELEGATE_MIN_FILES: i64 = 5;
const DELEGATE_MIN_LINES: i64 = 200;
const DROID_COUNTED_TOOLS: [&str; 3] = ["Edit", "Create", "ApplyPatch"];
const DROID_INHERIT_ROLES: [&str; 2] = ["zeus", "hephaestus"];
const WRITER_LEAVES: [&str; 3] = ["hephaestus", "achilles", "heracles"];

fn ask_reply(reason: &str) -> Value {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": reason,
    }})
}

fn deny_reply(reason: &str) -> Value {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }})
}

fn droid_role(value: Option<&Value>) -> String {
    let Some(text) = value.and_then(Value::as_str) else {
        return String::new();
    };
    let trimmed = text.trim();
    casefold(trimmed.rsplit(':').next().unwrap_or(""))
}

struct Counter {
    files: i64,
    lines: i64,
    measured: bool,
    paths: Vec<String>,
}

fn json_int(value: Option<&Value>) -> Option<i64> {
    // Python `type(x) is int`: JSON booleans and floats do not qualify.
    value.and_then(Value::as_i64)
}

fn load_counter(session: &Session) -> Counter {
    let text = session.read("write-counter.json");
    let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let empty = Map::new();
    let map = data.as_object().unwrap_or(&empty);
    let mut paths: Vec<String> = match map.get("paths") {
        Some(Value::Array(items)) => {
            let mut found: Vec<String> = items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            found.sort();
            found.dedup();
            found
        }
        _ => Vec::new(),
    };
    paths.sort();
    let files = match json_int(map.get("files")) {
        Some(n) if n >= 0 => n,
        _ => paths.len() as i64,
    };
    let lines = match json_int(map.get("lines")) {
        Some(n) if n >= 0 => n,
        _ => 0,
    };
    let measured = match map.get("measured") {
        Some(Value::Bool(flag)) => *flag,
        _ => true,
    };
    Counter { files, lines, measured, paths }
}

fn save_counter(session: &Session, data: &Counter, active: bool) {
    if !session.secure_dir(active) {
        return;
    }
    let text = json!({
        "files": data.files, "lines": data.lines,
        "measured": data.measured, "paths": data.paths,
    })
    .to_string();
    session.write("write-counter.json", &text, false, active);
}

fn counter_reached(data: &Counter) -> bool {
    if !data.measured && data.files < DELEGATE_MIN_FILES {
        return false;
    }
    data.files >= DELEGATE_MIN_FILES || data.lines >= DELEGATE_MIN_LINES
}

fn delegate_reason(data: &Counter) -> String {
    let shown = if data.measured {
        data.lines.to_string()
    } else {
        "unmeasured".to_string()
    };
    format!(
        "SureForge: scope reports delegate yes for this turn ({} files, {} lines vs baseline; \
         limits {} files / {} lines). Stop writing here and hand the remainder \
         to hephaestus (Task).",
        data.files, shown, DELEGATE_MIN_FILES, DELEGATE_MIN_LINES
    )
}

fn counter_add(session: &Session, paths: &[String], lines: i64, active: bool) -> Counter {
    let mut data = load_counter(session);
    let mut added = 0i64;
    for path in paths {
        if !path.is_empty() && !data.paths.contains(path) {
            data.paths.push(path.clone());
            added += 1;
        }
    }
    data.paths.sort();
    data.files += added;
    data.lines += lines.max(0);
    data.measured = true;
    save_counter(session, &data, active);
    data
}

fn load_writers(session: &Session) -> BTreeMap<String, (String, String)> {
    let text = session.read("writers.json");
    let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let mut clean = BTreeMap::new();
    if let Some(map) = data.as_object() {
        for (key, row) in map {
            if key.is_empty() {
                continue;
            }
            let Some(row) = row.as_object() else { continue };
            let role = as_str(row.get("role"));
            if !WRITER_LEAVES.contains(&role) {
                continue;
            }
            let label = as_str(row.get("label")).to_string();
            clean.insert(key.clone(), (role.to_string(), label));
        }
    }
    clean
}

fn save_writers(session: &Session, writers: &BTreeMap<String, (String, String)>, active: bool) {
    if !session.secure_dir(active) {
        return;
    }
    let mut map = Map::new();
    for (key, (role, label)) in writers {
        map.insert(key.clone(), json!({"label": label, "role": role}));
    }
    session.write("writers.json", &Value::Object(map).to_string(), false, active);
}

fn droid_label_key(value: Option<&Value>) -> String {
    let text = value.and_then(Value::as_str).unwrap_or("").trim();
    if text.is_empty() || text.chars().count() > 512 {
        return String::new();
    }
    sha256_hex(text.as_bytes())
}

fn droid_call_id(event: &Value) -> String {
    let mut sources: Vec<&Map<String, Value>> = Vec::new();
    if let Some(map) = event.as_object() {
        sources.push(map);
    }
    if let Some(map) = input_of(event) {
        sources.push(map);
    }
    for source in sources {
        for key in ["tool_use_id", "toolUseId", "tool_call_id", "toolCallId"] {
            if let Some(Value::String(value)) = source.get(key) {
                let trimmed = value.trim();
                if id_fullmatch(trimmed, true) {
                    return trimmed.to_string();
                }
            }
        }
    }
    String::new()
}

/// droid_hook's writer tracking, called only after every deny check passed.
fn note_writer(session: &Session, event: &Value, active: bool) {
    if tool_of(event) != "Task" {
        return;
    }
    let empty = Map::new();
    let inp = input_of(event).unwrap_or(&empty);
    let role = droid_role(inp.get("subagent_type"));
    if !WRITER_LEAVES.contains(&role.as_str()) {
        return;
    }
    let label = droid_label_key(inp.get("description"));
    let mut ident = droid_call_id(event);
    if ident.is_empty() {
        if label.is_empty() {
            return;
        }
        ident = format!("label:{label}");
    }
    let mut writers = load_writers(session);
    writers.insert(ident, (role, label));
    save_writers(session, &writers, active);
}

/// _norm_tool_path: repo-relative posix path when inside root.
fn norm_tool_path(value: Option<&Value>, root: Option<&Path>) -> String {
    let Some(raw) = value.and_then(Value::as_str) else {
        return String::new();
    };
    let mut text = raw.replace('\\', "/").trim().to_string();
    while let Some(rest) = text.strip_prefix("./") {
        text = rest.to_string();
    }
    let Some(root) = root else {
        return text;
    };
    if text.is_empty() {
        return text;
    }
    let base = resolve_loose(root);
    let candidate = if Path::new(&text).is_absolute() {
        PathBuf::from(&text)
    } else {
        base.join(&text)
    };
    let resolved = resolve_loose(&candidate);
    match resolved.strip_prefix(&base) {
        Ok(relative) => {
            let joined = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if joined.is_empty() {
                ".".to_string()
            } else {
                joined
            }
        }
        Err(_) => text,
    }
}

fn string_field<'a>(inp: &'a Map<String, Value>, keys: &[&str]) -> &'a str {
    for key in keys {
        if let Some(Value::String(text)) = inp.get(*key) {
            return text;
        }
    }
    ""
}

/// _droid_input_delta: paths and changed lines implied by tool_input.
fn droid_input_delta(tool: &str, inp: &Map<String, Value>, root: Option<&Path>) -> (Vec<String>, i64) {
    if tool == "ApplyPatch" {
        let text = string_field(inp, &["input", "patch", "diff", "unified_diff", "unifiedDiff"]);
        let mut paths = Vec::new();
        let mut lines = 0i64;
        for line in splitlines(text) {
            let line = line.as_str();
            let found = patch_file_header(line)
                .or_else(|| git_file_header(line))
                .or_else(|| plus_file_header(line));
            if let Some(path) = found {
                let path = norm_tool_path(Some(&Value::String(path)), root);
                if !path.is_empty() && path != "/dev/null" {
                    paths.push(path);
                }
                continue;
            }
            if (line.starts_with('+') || line.starts_with('-'))
                && !line.starts_with("+++")
                && !line.starts_with("---")
            {
                lines += 1;
            }
        }
        return (paths, lines);
    }
    let path = norm_tool_path(
        inp.get("file_path")
            .or_else(|| inp.get("path"))
            .or_else(|| inp.get("filePath"))
            .or_else(|| inp.get("target_file")),
        root,
    );
    let paths = if path.is_empty() { Vec::new() } else { vec![path] };
    if tool == "Create" {
        let body = string_field(inp, &["content", "contents", "file_text", "new_str", "new_string", "newString"]);
        return (paths, splitlines_count(body) as i64);
    }
    let old = string_field(inp, &["old_str", "old_string", "oldString"]);
    let new = string_field(inp, &["new_str", "new_string", "newString"]);
    (paths, (splitlines_count(old) + splitlines_count(new)) as i64)
}

fn patch_file_header(line: &str) -> Option<String> {
    // ^\*\*\* (?:Update|Add|Delete) File: (.+)$
    let rest = line.strip_prefix("*** ")?;
    for verb in ["Update File: ", "Add File: ", "Delete File: "] {
        if let Some(path) = rest.strip_prefix(verb) {
            if !path.is_empty() {
                return Some(path.to_string());
            }
        }
    }
    None
}

fn git_file_header(line: &str) -> Option<String> {
    // ^diff --git a/.+ b/(.+)$
    let rest = line.strip_prefix("diff --git a/")?;
    let at = rest.rfind(" b/")?;
    if at == 0 {
        return None;
    }
    let path = &rest[at + 3..];
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn plus_file_header(line: &str) -> Option<String> {
    // ^\+\+\+ (?:b/)?(.+)$
    let rest = line.strip_prefix("+++ ")?;
    let path = rest.strip_prefix("b/").unwrap_or(rest);
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn droid_exempt(session: &Session) -> bool {
    if session.file("child-session").is_file() || !load_writers(session).is_empty() {
        return true;
    }
    session.read("baseline").is_empty()
}

fn complexity_mode() -> &'static str {
    match std::env::var("PROMETHEUS_DROID_COMPLEXITY") {
        Ok(raw) if casefold(raw.trim()) == "deny" => "deny",
        _ => "warn",
    }
}

fn droid_task_gate(session: &Session, inp: &Map<String, Value>, active: bool) -> Value {
    let role = droid_role(inp.get("subagent_type"));
    if !DROID_INHERIT_ROLES.contains(&role.as_str()) {
        return json!({});
    }
    if complexity_mode() != "deny" {
        // Warn mode logs key names and the role only, never values.
        if session.secure_dir(active) {
            let mut keys: Vec<&str> = inp.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let shown: Vec<&str> = keys.into_iter().filter(|key| key.chars().count() <= 64).collect();
            let line = json!({"keys": shown, "subagent_type": role}).to_string();
            session.write("complexity-tasks.jsonl", &(line + "\n"), true, active);
        }
        return json!({});
    }
    let value = inp.get("complexity");
    if let Some(Value::String(text)) = value {
        if ["light", "medium", "heavy"].contains(&casefold(text.trim()).as_str()) {
            return json!({});
        }
    }
    deny_reply(&format!(
        "SureForge: add complexity (light, medium, or heavy) to this {role} Task. The field is required."
    ))
}

/// _droid_write_gate: brake parent writes from the per-turn counter.
fn droid_write_gate(session: &Session, event: &Value, root: &Path, active: bool) -> Value {
    let tool = tool_of(event);
    let empty = Map::new();
    let inp = input_of(event).unwrap_or(&empty);
    if tool == "Task" {
        return droid_task_gate(session, inp, active);
    }
    if tool == "Execute" || !DROID_COUNTED_TOOLS.contains(&tool) {
        return json!({});
    }
    if droid_exempt(session) {
        return json!({});
    }
    let current = load_counter(session);
    if counter_reached(&current) {
        return deny_reply(&delegate_reason(&current));
    }
    let (paths, lines) = droid_input_delta(tool, inp, Some(root));
    counter_add(session, &paths, lines, active);
    json!({})
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

/// Python `str.splitlines()` as owned lines (boundaries per splitlines_count).
fn splitlines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}'
                | '\u{2028}' | '\u{2029}'
        );
        if boundary {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            lines.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

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

const SECRET_ASK_HOSTS: [&str; 3] = ["claude", "droid", "devin"];
const DIRECT_CHECK_HOSTS: [&str; 4] = ["claude", "droid", "devin", "muse"];
const CLAUDE_READ_ONLY_TOOLS: [&str; 21] = [
    "Read", "Grep", "Glob", "LS", "NotebookRead", "WebFetch", "WebSearch",
    "TodoWrite", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
    "TaskOutput", "TaskStop", "ToolSearch", "AskUserQuestion", "LSP",
    "EnterPlanMode", "ExitPlanMode", "ListMcpResourcesTool",
    "ReadMcpResourceTool",
];

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

fn delegate_outcome(reason: &str, event_name: &str, tool: &str) -> Outcome {
    Outcome {
        reply: json!({}),
        decision: "delegate",
        reason: reason.to_string(),
        event_name: event_name.to_string(),
        tool: tool.to_string(),
    }
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

/// sureforge_hook.record_tool_call, minus the bookkeeping that never
/// changes a reply (host/attribution markers stay with Python).
fn record_tool_call(host: &str, event: &Value, session: &Session, root: &Path, opts: &Options) -> Value {
    if SECRET_ASK_HOSTS.contains(&host) {
        let reason = secret_tool_denial(event, session);
        if !reason.is_empty() {
            return ask_reply(&reason);
        }
    }
    if DIRECT_CHECK_HOSTS.contains(&host) {
        let direct = direct_check_tool_denial(event, &session.id);
        if !direct.is_empty() {
            return deny_reply(&direct);
        }
    }
    if host == "droid" {
        // The secret check above runs before the storage check, like the
        // oracle: a secret path earns its ask without session storage.
        if !session.dir().is_dir() || !session.secure_dir(opts.active) {
            return json!({});
        }
        let reply = droid_write_gate(session, event, root, opts.active);
        if reply != json!({}) {
            return reply;
        }
        return read_warn_reply("droid", event, session, root, opts.active);
    }
    if host == "claude" {
        if !session.secure_dir(opts.active) {
            return json!({});
        }
        // An invalid attribution id ends classification with {} before any
        // advisory; the markers themselves are Python bookkeeping.
        for key in ["agent_id", "tool_use_id", "agent_type"] {
            if let Some(value) = get(event, key) {
                let empty_string = matches!(value, Value::String(text) if text.is_empty());
                let valid = matches!(value, Value::String(text) if id_fullmatch(text, true));
                if !value.is_null() && !empty_string && !valid {
                    return json!({});
                }
            }
        }
        if CLAUDE_READ_ONLY_TOOLS.contains(&tool_of(event)) {
            return read_warn_reply("claude", event, session, root, opts.active);
        }
        return json!({});
    }
    json!({})
}

fn dispatch_level(host: &str, event: &Value, session: &Session, root: &Path, opts: &Options) -> Outcome {
    let name = normalized_name(event);
    let tool = tool_of(event).to_string();
    match name.as_str() {
        "pretooluse" => {
            let reply = record_tool_call(host, event, session, root, opts);
            if host == "droid" {
                // droid_hook._track_droid_writer: writers enter the
                // in-flight set only after the gate allows the Task.
                let blocked = reply.get("systemMessage").is_some()
                    || matches!(
                        get(&reply, "hookSpecificOutput")
                            .and_then(|out| get(out, "permissionDecision"))
                            .and_then(Value::as_str),
                        Some("ask") | Some("deny")
                    );
                if !blocked {
                    note_writer(session, event, opts.active);
                }
            }
            outcome_from_reply(reply, &name, &tool)
        }
        "posttooluse" => {
            if host != "droid" {
                return allow_outcome(&name, &tool);
            }
            if !session.dir().is_dir() || !session.secure_dir(opts.active) {
                return allow_outcome(&name, &tool);
            }
            if tool != "Execute" || droid_exempt(session) {
                return allow_outcome(&name, &tool);
            }
            // _droid_post_execute resyncs the counter from a git diff keyed
            // to the tree fingerprint. That fingerprint is the scan's
            // (tickets #47-#49); until the core serves it, Python governs
            // this one event and the binary says so in the log.
            delegate_outcome(
                "posttooluse-resync: keyed to the tree fingerprint (tickets #47-#49)",
                &name,
                &tool,
            )
        }
        _ => delegate_outcome("event-not-fastpath", &name, &tool),
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

    #[test]
    fn segments_split_like_the_oracle() {
        assert_eq!(
            shell_segments("make test && dotnet build"),
            vec!["make test".to_string(), "dotnet build".to_string()]
        );
        assert_eq!(
            shell_segments("echo 'a;b' ; ls # dotnet build\n"),
            vec!["echo 'a;b'".to_string(), "ls".to_string()]
        );
    }

    #[test]
    fn compiled_names() {
        let tokens = |text: &str| segment_tokens(text);
        assert_eq!(compiled_check_name(&tokens("dotnet build"), 0), "dotnet build");
        assert_eq!(compiled_check_name(&tokens("cargo b"), 0), "cargo build");
        assert_eq!(compiled_check_name(&tokens("echo dotnet build"), 0), "");
        assert_eq!(compiled_check_name(&tokens("sudo -u me dotnet test"), 0), "dotnet test");
        assert_eq!(compiled_check_name(&tokens("dotnet run"), 0), "");
    }

    #[test]
    fn splitlines_counts() {
        assert_eq!(splitlines_count(""), 0);
        assert_eq!(splitlines_count("a"), 1);
        assert_eq!(splitlines_count("a\n"), 1);
        assert_eq!(splitlines_count("a\nb"), 2);
        assert_eq!(splitlines_count("a\r\nb"), 2);
    }
}
