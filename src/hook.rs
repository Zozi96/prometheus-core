//! Native `PreToolUse` safety, read-budget, and command-rewrite guards (ADR-0010, ADR-0012, ADR-0014).
//!
//! Answers `prometheus-kit hook <host>`:
//! - Secret-path guard on structured file tools.
//! - Four-state `Guided deny-once` on large file reads (>= 200 lines) and unchanged rereads;
//!   below 200 lines warns only on hosts whose `PreToolUse` context reaches the model (`claude`, `muse`).
//! - Deterministic Tier-1 shell auto-rewrite and Tier-2 `Guided deny-once` (coexisting with RTK).
//! - High-waste structured-file inline dumps: `Use-time hint` on context-delivering hosts,
//!   `Guided deny-once` on large files on no-context hosts.
//!
//! Every other event, tool, and edit passes silently, and direct checks never trigger `permissionDecision`.

use crate::metrics::{self, Host, Rule};
use crate::store::{ensure_private_dir, sha256_hex};
use serde_json::{json, Map, Value};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const REREAD_MESSAGE: &str =
    "Unchanged whole-file reread: use the previous read or request a focused range (`prometheus-kit slice`).";
pub const REREAD_DENIAL_MESSAGE: &str = "Unchanged reread denied once: reuse the earlier read or request a focused range (`prometheus-kit slice <path>:<start>-<end>`). Retry the same read if that content left your context.";
pub const LARGE_READ_LINES: usize = 200;
pub const LARGE_STRUCTURED_BYTES: usize = 8 * 1024;
const REREAD_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// True only for hosts whose `PreToolUse` protocol delivers non-blocking
/// context (`additionalContext`) to the model (ADR-0014 D3).
pub fn host_delivers_pretool_context(host: &str) -> bool {
    matches!(host, "claude" | "muse")
}

fn read_hint_disabled() -> bool {
    std::env::var_os("PROMETHEUS_KIT_NO_READ_HINT").as_deref() == Some(OsStr::new("1"))
}
const PARTIAL_KEYS: [&str; 10] = [
    "offset",
    "start",
    "end",
    "range",
    "start_line",
    "end_line",
    "startline",
    "endline",
    "view_range",
    "limit",
];

const SECRET_SUFFIXES: [&str; 4] = [".example", ".sample", ".template", ".dist"];
const SECRET_EXTENSIONS: [&str; 6] = [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"];
const SECRET_BASENAMES: [&str; 14] = [
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".htpasswd",
    "auth.json",
    "credentials",
    "credentials.json",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
];
const SECRET_DIRS: [&str; 3] = [".ssh", ".aws", ".gnupg"];

const OTHER_HOSTS: [&str; 3] = ["CURSOR_PROJECT_DIR", "DEVIN_PROJECT_DIR", "GROK_SESSION_ID"];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

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

fn py_or<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    match a {
        Some(value) if truthy(value) => Some(value),
        _ => b,
    }
}

fn as_str(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or("")
}

fn casefold(text: &str) -> String {
    text.to_lowercase()
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
fn valid_session_id_str(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && text.chars().count() <= 128
}

fn tool_name(event: &Value) -> &str {
    as_str(py_or(get(event, "tool_name"), get(event, "toolName")))
}

fn event_name_normalized(event: &Value) -> String {
    let raw = as_str(py_or(
        py_or(get(event, "hook_event_name"), get(event, "hookEventName")),
        get(event, "event_name"),
    ));
    casefold(raw).replace('_', "")
}

/// Mirrors `secret_read.secret_path_denied`.
pub fn secret_path_denied(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let parts: Vec<&str> = slashed
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let Some(basename_raw) = parts.last() else {
        return String::new();
    };
    let basename = casefold(basename_raw);
    if SECRET_SUFFIXES
        .iter()
        .any(|suffix| basename.ends_with(suffix))
    {
        return String::new();
    }
    let mut matched = String::new();
    if basename.starts_with(".env")
        || SECRET_EXTENSIONS.iter().any(|ext| basename.ends_with(ext))
        || SECRET_BASENAMES.contains(&basename.as_str())
        || basename.starts_with("credentials")
        || basename.starts_with("secrets.")
        || (basename.starts_with("id_") && !basename.ends_with(".pub"))
    {
        matched = basename;
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
    format!(
        "secret path '{matched}' is blocked; name '{matched}' in your prompt to allow it this turn"
    )
}

fn secret_denied(raw: Option<&Value>) -> String {
    let Some(raw) = raw.and_then(Value::as_str) else {
        return String::new();
    };
    let mut path = raw.trim().to_string();
    let chars: Vec<char> = path.chars().collect();
    if chars.len() >= 2 && chars[0] == chars[chars.len() - 1] && matches!(chars[0], '"' | '\'') {
        path = chars[1..chars.len() - 1]
            .iter()
            .collect::<String>()
            .trim()
            .to_string();
    }
    path = path.replace('\\', "/");
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    secret_path_denied(&path)
}

/// Literal secret-path check for shell rewrite passthrough (`hook_rewrite.rs`):
/// keeps commands mentioning secret file operands unrewritten without ever
/// emitting a permission `ask`/`deny`.
pub(crate) fn command_token_denied(token: &str) -> String {
    for candidate in token.split('=') {
        let reason = secret_denied(Some(&Value::String(candidate.to_string())));
        if !reason.is_empty() {
            return reason;
        }
        // A `rev:path` git object operand names a tree path after the colon (`HEAD:.env`).
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
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '$' | '(' | ')' | '{' | '}' | '|' | ';' | '&' | '<' | '>'
        )
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

fn check_keys_for_secret(source: &Map<String, Value>, keys: &[&str]) -> String {
    for key in keys {
        match source.get(*key) {
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
            None => {}
        }
    }
    String::new()
}

fn secret_tool_denial(event: &Value) -> String {
    const KEYS: [&str; 8] = [
        "file_path",
        "filePath",
        "AbsolutePath",
        "path",
        "paths",
        "pattern",
        "glob",
        "notebook_path",
    ];
    for key in ["tool_input", "input"] {
        if let Some(inp) = get(event, key).and_then(Value::as_object) {
            let reason = check_keys_for_secret(inp, &KEYS);
            if !reason.is_empty() {
                return reason;
            }
        }
    }
    String::new()
}

fn cursor_secret_denied(event: &Value) -> String {
    const KEYS: [&str; 10] = [
        "relative_workspace_path",
        "relativeWorkspacePath",
        "path",
        "file_path",
        "filePath",
        "AbsolutePath",
        "target_file",
        "paths",
        "pattern",
        "glob",
    ];
    for key in ["tool_input", "input"] {
        if let Some(inp) = get(event, key).and_then(Value::as_object) {
            let reason = check_keys_for_secret(inp, &KEYS);
            if !reason.is_empty() {
                return reason;
            }
        }
    }
    if let Some(obj) = event.as_object() {
        return check_keys_for_secret(obj, &KEYS);
    }
    String::new()
}

const FILE_READ_KEYS: [&str; 12] = [
    "file_path",
    "path",
    "paths",
    "pattern",
    "glob",
    "filePath",
    "AbsolutePath",
    "target_file",
    "relative_workspace_path",
    "relativeWorkspacePath",
    "notebook_path",
    "target",
];

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
            let items: Vec<&Value> = match source.get(key) {
                Some(Value::Array(items)) => items.iter().collect(),
                Some(item) => vec![item],
                None => vec![],
            };
            for item in items {
                if !secret_denied(Some(item)).is_empty() {
                    return true;
                }
            }
        }
    }
    false
}

fn file_reads(host: &str) -> Option<&'static [&'static str]> {
    match host {
        "claude" | "muse" => Some(&["Read", "Grep", "Glob", "LS", "NotebookRead"]),
        "cursor" | "droid" => Some(&["Read", "Grep", "Glob", "LS", "Search", "Find"]),
        "devin" => Some(&[
            "read",
            "grep",
            "glob",
            "ls",
            "search",
            "find",
            "Read",
            "Grep",
            "Glob",
            "LS",
            "Search",
            "Find",
        ]),
        _ => None,
    }
}

fn read_failure_allows(host: &str, event: &Value) -> bool {
    let tool = tool_name(event);
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
// Unchanged-reread guard: warn below LARGE_READ_LINES, deny once at or
// above (ADR-0013 D6).
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn my_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn session_dir(session_id: &str) -> Option<PathBuf> {
    let parent = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mut from_xdg = None;
            if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
                let p = PathBuf::from(&runtime);
                if p.is_absolute() {
                    if let Ok(info) = std::fs::metadata(&p) {
                        if info.is_dir() && info.uid() == my_uid() {
                            from_xdg = Some(p.join("prometheus"));
                        }
                    }
                }
            }
            from_xdg.unwrap_or_else(|| std::env::temp_dir().join(format!("prometheus-{}", my_uid())))
        }
        #[cfg(not(unix))]
        {
            std::env::temp_dir().join("prometheus")
        }
    };
    let folder = parent.join(session_id);
    // Lazily create owner-private 0o700 dirs on first use; an existing
    // insecure directory is never repaired or trusted.
    ensure_private_dir(&parent).ok()?;
    ensure_private_dir(&folder).ok()?;
    Some(folder)
}

fn resolve_loose(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    let mut out = if path.is_absolute() {
        PathBuf::new()
    } else {
        let cur = std::env::current_dir().unwrap_or_default();
        std::fs::canonicalize(&cur).unwrap_or(cur)
    };
    for component in path.components() {
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

fn open_nofollow_nonblock(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn hash_file(path: &Path) -> Option<(String, usize)> {
    let mut file = open_nofollow_nonblock(path).ok()?;
    let info = file.metadata().ok()?;
    if !info.is_file() || info.len() > REREAD_MAX_BYTES {
        return None;
    }
    let cap = usize::try_from(info.len().min(REREAD_MAX_BYTES)).ok()?;
    let mut contents = Vec::with_capacity(cap);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 {
            let mut line_count = contents.iter().filter(|&&b| b == b'\n').count();
            if !contents.is_empty() && !contents.ends_with(b"\n") {
                line_count += 1;
            }
            return Some((sha256_hex(&contents), line_count));
        }
        if contents.len() + n > REREAD_MAX_BYTES as usize {
            return None;
        }
        contents.extend_from_slice(&chunk[..n]);
    }
}

pub fn first_read_denial_message(path: &Path, lines: usize) -> String {
    if crate::outline::Lang::from_path(path).is_some() {
        format!(
            "Large whole-file read ({lines} lines) denied once: use `~/.agents/prometheus/prometheus-kit outline <path>` then `slice <path>::<Symbol>` or `<path>:<start>-<end>`, or pass a ranged read (`offset`/`limit`, `StartLine`/`EndLine`). Retry the same read if you need the entire file."
        )
    } else {
        format!(
            "Large whole-file read ({lines} lines) denied once: use `~/.agents/prometheus/prometheus-kit slice <path>:<start>-<end>` (or `compact <log>`), or pass a ranged read (`offset`/`limit`, `StartLine`/`EndLine`). Retry the same read if you need the entire file."
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    Seen,
    FirstDenied,
    RereadDenied,
}

enum StoredHash {
    Absent,
    Malformed,
    Present { digest: String, state: ReadState },
}

/// Safely read a small, regular, non-symlink session state file (up to `max_len` bytes).
/// Returns `Ok(None)` if absent, `Ok(Some(text))` on success, `Err(())` if symlink/FIFO/malformed.
fn read_state_file(path: &Path, max_len: usize) -> Result<Option<String>, ()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(()),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    }
    let mut file = match open_nofollow_nonblock(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let info = file.metadata().map_err(|_| ())?;
    if !info.is_file() || info.len() > max_len as u64 {
        return Err(());
    }
    let mut buf = vec![0u8; max_len + 1];
    let mut total = 0usize;
    loop {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > max_len {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    }
    std::str::from_utf8(&buf[..total])
        .map(|s| Some(s.to_owned()))
        .map_err(|_| ())
}

/// Atomically write a private (`0o600`) session state file, refusing existing symlinks.
fn write_state_file(path: &Path, prefix: &str, content: &[u8]) -> bool {
    use std::io::Write;
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{prefix}-{}-{seq}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let Ok(mut file) = options.open(&tmp) else {
        return false;
    };
    let write_ok = file.write_all(content).is_ok();
    drop(file);
    if !write_ok || std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    true
}

/// Stream-count lines and bytes of a regular, non-symlink file using a stack buffer
/// (no full-file heap copy or hashing). Returns `None` for non-regular/unreadable files.
/// When `info.len() > REREAD_MAX_BYTES`, returns `Some((file_bytes, None))` without reading.
fn inspect_structured_file_size(path: &Path) -> Option<(usize, Option<usize>)> {
    let mut file = open_nofollow_nonblock(path).ok()?;
    let info = file.metadata().ok()?;
    if !info.is_file() {
        return None;
    }
    let meta_len = usize::try_from(info.len().min(usize::MAX as u64)).ok()?;
    if info.len() > REREAD_MAX_BYTES {
        return Some((meta_len, None));
    }
    let mut chunk = [0u8; 64 * 1024];
    let mut total_bytes = 0usize;
    let mut lines = 0usize;
    let mut last_byte = None::<u8>;
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 {
            if total_bytes > 0 && last_byte != Some(b'\n') {
                lines += 1;
            }
            return Some((total_bytes, Some(lines)));
        }
        total_bytes = total_bytes.saturating_add(n);
        lines += chunk[..n].iter().filter(|&&b| b == b'\n').count();
        last_byte = Some(chunk[n - 1]);
        if total_bytes as u64 > REREAD_MAX_BYTES {
            return Some((total_bytes, None));
        }
    }
}

fn read_reread_state(path: &Path) -> StoredHash {
    let raw = match read_state_file(path, 128) {
        Ok(Some(text)) => text,
        Ok(None) => return StoredHash::Absent,
        Err(()) => return StoredHash::Malformed,
    };
    // Three shapes: "<64 lowercase hex>" (seen), "<hash> first-denied" (first
    // large whole-file read denied, retry pending), or "<hash> denied" (reread
    // denied, retry pending).
    let text = raw.trim();
    let (digest, state) = if let Some(head) = text.strip_suffix(" first-denied") {
        (head, ReadState::FirstDenied)
    } else if let Some(head) = text.strip_suffix(" denied") {
        (head, ReadState::RereadDenied)
    } else {
        (text, ReadState::Seen)
    };
    let valid = digest.len() == 64
        && digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if valid {
        StoredHash::Present {
            digest: digest.to_string(),
            state,
        }
    } else {
        StoredHash::Malformed
    }
}

fn write_reread_state(path: &Path, digest: &str, state: ReadState) -> bool {
    let suffix = match state {
        ReadState::Seen => "",
        ReadState::FirstDenied => " first-denied",
        ReadState::RereadDenied => " denied",
    };
    write_state_file(path, "reread", format!("{digest}{suffix}\n").as_bytes())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DenyMarker {
    Absent,
    Denied,
    Allowed,
    Malformed,
}

fn read_deny_marker(path: &Path) -> DenyMarker {
    match read_state_file(path, 32) {
        Ok(None) => DenyMarker::Absent,
        Ok(Some(raw)) => match raw.trim() {
            "denied" => DenyMarker::Denied,
            "allowed" => DenyMarker::Allowed,
            _ => DenyMarker::Malformed,
        },
        Err(()) => DenyMarker::Malformed,
    }
}

fn write_deny_marker(path: &Path, text: &str) -> bool {
    write_state_file(path, "deny", text.as_bytes())
}

/// Shared Tier-2 shell `Guided deny-once` state machine (ADR-0014).
/// Returns `Some(reason)` on first denial and `None` on immediate retry or fail-open.
pub(crate) fn shell_deny_once_decision(
    host: &str,
    session_id: &str,
    event_cwd: Option<&Path>,
    command: &str,
    suggested: &str,
) -> Option<String> {
    if !valid_session_id_str(session_id) {
        return None;
    }
    let folder = session_dir(session_id)?;
    let cwd_str = event_cwd
        .filter(|p| !p.as_os_str().is_empty())
        .map(resolve_loose)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut key_bytes = Vec::with_capacity(cwd_str.len() + 1 + command.len());
    key_bytes.extend_from_slice(cwd_str.as_bytes());
    key_bytes.push(0);
    key_bytes.extend_from_slice(command.as_bytes());
    let marker = folder.join(format!("shell-deny-{}", sha256_hex(&key_bytes)));
    let record = |rule: Rule, raw: usize, emitted: usize| {
        if let Some(h) = Host::from_hook(host) {
            metrics::record(h, rule, raw, emitted);
        }
    };
    match read_deny_marker(&marker) {
        DenyMarker::Malformed => None,
        DenyMarker::Denied => {
            let _ = std::fs::remove_file(&marker);
            record(Rule::AllowedRetry, 0, command.len());
            None
        }
        DenyMarker::Absent | DenyMarker::Allowed => {
            if !write_deny_marker(&marker, "denied\n") {
                return None;
            }
            let reason = format!(
                "Covered shell command denied once: run `{suggested}` instead for token-budgeted output. Retry the same command if you still need raw shell output."
            );
            record(Rule::ShellDenial, command.len(), reason.len());
            Some(reason)
        }
    }
}

/// Read-tool path plus the partial-read entries (casefolded key, value)
/// sorted by key; an empty vec means a whole-file read.
fn read_path(event: &Value, host: &str) -> Option<(String, Vec<(String, Value)>)> {
    let tool = casefold(tool_name(event));
    let is_read = tool == "read" || (host == "antigravity" && tool == "view_file");
    if !is_read {
        return None;
    }
    let empty = Map::new();
    let inp = get(event, "tool_input")
        .and_then(Value::as_object)
        .or_else(|| get(event, "input").and_then(Value::as_object))
        .unwrap_or(&empty);
    let mut partial: Vec<(String, Value)> = inp
        .iter()
        .filter_map(|(key, value)| {
            let lower = casefold(key);
            // A null partial parameter is an omitted one: whole-file read.
            if value.is_null() || !PARTIAL_KEYS.contains(&lower.as_str()) {
                return None;
            }
            Some((lower, value.clone()))
        })
        .collect();
    partial.sort_by(|a, b| a.0.cmp(&b.0));
    for key in ["file_path", "filePath", "path", "AbsolutePath"] {
        if let Some(Value::String(text)) = inp.get(key) {
            if !text.trim().is_empty() {
                return Some((text.clone(), partial));
            }
        }
    }
    None
}

/// Bytes the read would return: the whole file for a whole-file read; for an
/// `offset`/`limit` or `(start_line|startline, end_line|endline)` range a
/// proportional slice; 0 for any other shape.
fn read_bytes_estimate(partial: &[(String, Value)], file_bytes: usize, lines: usize) -> usize {
    if partial.is_empty() {
        return file_bytes;
    }
    if lines == 0 {
        return 0;
    }
    let lines_u = lines as u128;
    // Check paired start/end line keys (e.g. Antigravity StartLine/EndLine).
    if partial.len() == 2 {
        let mut s_line = None::<u128>;
        let mut e_line = None::<u128>;
        for (key, value) in partial {
            if let Some(num) = value.as_u64() {
                match key.as_str() {
                    "start_line" | "startline" if s_line.is_none() => s_line = Some(u128::from(num)),
                    "end_line" | "endline" if e_line.is_none() => e_line = Some(u128::from(num)),
                    _ => {}
                }
            }
        }
        if let (Some(s), Some(e)) = (s_line, e_line) {
            if s >= 1 && e >= s {
                let start = s.saturating_sub(1);
                let want = (e - s + 1).min(lines_u.saturating_sub(start));
                return (file_bytes as u128 * want / lines_u) as usize;
            }
            return 0;
        }
    }
    let mut offset = 0u128;
    let mut limit = None::<u128>;
    let mut seen_offset = false;
    let mut seen_limit = false;
    for (key, value) in partial {
        let Some(num) = value.as_u64() else {
            return 0;
        };
        match key.as_str() {
            "offset" if !seen_offset => {
                seen_offset = true;
                offset = u128::from(num);
            }
            "limit" if !seen_limit => {
                seen_limit = true;
                limit = Some(u128::from(num));
            }
            _ => return 0,
        }
    }
    let start = offset.saturating_sub(1);
    let want = limit.unwrap_or(lines_u).min(lines_u.saturating_sub(start));
    (file_bytes as u128 * want / lines_u) as usize
}

/// The read-budget guard verdict for one Read event: pass, warn, or deny.
#[derive(Debug, PartialEq)]
pub enum ReadGuard {
    Pass,
    Warn(String),
    Deny(String),
}

/// Four-state `Guided deny-once` read guard (ADR-0014 D4 / ADR-0013 D6):
/// 1. First unranged whole-file read of a file >= `LARGE_READ_LINES` -> deny once.
/// 2. Immediate retry of that same whole-file read -> allow and record hash.
/// 3. Subsequent unchanged reread (whole file or identical range) -> deny once.
/// 4. Immediate retry after compaction/context loss -> allow.
///
/// First-time ranged reads always pass; files < 200 lines warn on unchanged reread
/// only on hosts that deliver `PreToolUse` context (`claude`, `muse`).
pub fn read_guard(
    host: &str,
    event: &Value,
    session_id: &str,
    root: Option<&Path>,
) -> ReadGuard {
    let Some((raw, partial)) = read_path(event, host) else {
        return ReadGuard::Pass;
    };
    if !valid_session_id_str(session_id) {
        return ReadGuard::Pass;
    }
    let Some(folder) = session_dir(session_id) else {
        return ReadGuard::Pass;
    };
    if !secret_path_denied(&raw).is_empty() {
        return ReadGuard::Pass;
    }
    let base: PathBuf = match root {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => match get(event, "cwd").and_then(Value::as_str) {
            Some(c) if !c.is_empty() => PathBuf::from(c),
            _ => return ReadGuard::Pass,
        },
    };
    let canonical = resolve_loose(&base);
    let candidate = Path::new(&raw);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    };
    let target_path = resolve_loose(&joined);
    let target_str = target_path.to_string_lossy();
    if !secret_path_denied(&target_str).is_empty() {
        return ReadGuard::Pass;
    }
    let Ok(info) = std::fs::metadata(&target_path) else {
        return ReadGuard::Pass;
    };
    if !info.is_file() || info.len() > REREAD_MAX_BYTES {
        return ReadGuard::Pass;
    }
    let Some((digest, line_count)) = hash_file(&target_path) else {
        return ReadGuard::Pass;
    };
    // Small files never touch reread state for ranged reads or on hosts that
    // drop non-blocking `PreToolUse` warnings (neither can warn or deny).
    if line_count < LARGE_READ_LINES && (!partial.is_empty() || !host_delivers_pretool_context(host)) {
        return ReadGuard::Pass;
    }
    let canonical_str = canonical.to_string_lossy();
    let mut key_bytes = Vec::with_capacity(canonical_str.len() + 1 + target_str.len());
    key_bytes.extend_from_slice(canonical_str.as_bytes());
    key_bytes.push(0);
    key_bytes.extend_from_slice(target_str.as_bytes());
    if !partial.is_empty() {
        let signature = partial
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\0");
        key_bytes.push(0);
        key_bytes.extend_from_slice(signature.as_bytes());
    }
    let key = sha256_hex(&key_bytes);
    let state = folder.join(format!("reread-{key}"));
    let large = line_count >= LARGE_READ_LINES;
    let estimate = read_bytes_estimate(&partial, info.len() as usize, line_count);
    let record = |rule: Rule, raw: usize, emitted: usize| {
        if let Some(host) = Host::from_hook(host) {
            metrics::record(host, rule, raw, emitted);
        }
    };
    match read_reread_state(&state) {
        StoredHash::Malformed => ReadGuard::Pass,
        StoredHash::Present {
            digest: stored,
            state: prev,
        } if stored == digest => match prev {
            ReadState::FirstDenied | ReadState::RereadDenied => {
                // Retry re-pays the bytes credited to the denial; record it
                // even if advancing state fails, and transition to Seen.
                write_reread_state(&state, &digest, ReadState::Seen);
                record(Rule::AllowedRetry, 0, estimate);
                ReadGuard::Pass
            }
            ReadState::Seen => {
                if large {
                    // Fail open when the marker cannot advance so we never deny forever.
                    if write_reread_state(&state, &digest, ReadState::RereadDenied) {
                        record(Rule::RereadDenial, estimate, REREAD_DENIAL_MESSAGE.len());
                        ReadGuard::Deny(REREAD_DENIAL_MESSAGE.to_string())
                    } else {
                        ReadGuard::Pass
                    }
                } else if host_delivers_pretool_context(host) {
                    record(Rule::RereadWarning, 0, REREAD_MESSAGE.len());
                    ReadGuard::Warn(REREAD_MESSAGE.to_string())
                } else {
                    ReadGuard::Pass
                }
            }
        },
        _ => {
            if partial.is_empty() && large && !read_hint_disabled() {
                // First unranged whole-file read of a 200+ line file: deny once,
                // failing open if state cannot be persisted.
                if write_reread_state(&state, &digest, ReadState::FirstDenied) {
                    let msg = first_read_denial_message(&target_path, line_count);
                    record(Rule::FirstReadDenial, estimate, msg.len());
                    ReadGuard::Deny(msg)
                } else {
                    ReadGuard::Pass
                }
            } else {
                write_reread_state(&state, &digest, ReadState::Seen);
                ReadGuard::Pass
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Structured-file inline dumps (#77 / ADR-0014 D3):
// - On hosts that deliver `PreToolUse` context (`claude`, `muse`): show a
//   non-blocking `Use-time hint` at most once per session.
// - On hosts without `PreToolUse` context (`droid`, `cursor`, `devin`, `omp`,
//   `antigravity`, `grok`): suppress inert hints and promote large structured
//   file dumps (>= 200 lines or >= 8 KiB) to `Guided deny-once` with retry.
// ---------------------------------------------------------------------------

const HINT_MARKER: &str = "hint-slice-selector";

fn inline_structured_operand(event: &Value) -> Option<(String, String)> {
    let tool = tool_name(event);
    if !crate::hook_rewrite::is_shell_tool(tool) {
        return None;
    }
    let empty = Map::new();
    let inp = get(event, "tool_input")
        .and_then(Value::as_object)
        .or_else(|| get(event, "input").and_then(Value::as_object))
        .unwrap_or(&empty);
    let (_, command) = crate::hook_rewrite::extract_shell_command(inp)?;
    let tokens = split_command(command);
    let first = tokens.first()?;
    let program = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first.as_str())
        .to_ascii_lowercase();
    let is_python = matches!(program.as_str(), "python" | "python3")
        && (tokens.iter().any(|t| t == "-c") || command.contains("<<"));
    let is_node = program == "node" && tokens.iter().any(|t| t == "-e");
    let is_jq = program == "jq";
    if !is_python && !is_node && !is_jq {
        return None;
    }
    let file = tokens.iter().skip(1).find(|t| {
        let lower = t.to_ascii_lowercase();
        lower.ends_with(".json")
            || lower.ends_with(".jsonl")
            || (!is_jq
                && (lower.ends_with(".yaml")
                    || lower.ends_with(".yml")
                    || lower.ends_with(".toml")))
    })?;
    if !command_token_denied(file).is_empty() {
        return None;
    }
    Some((command.to_owned(), file.clone()))
}

pub fn use_time_hint(host: &str, event: &Value, session_id: &str) -> Option<String> {
    if !host_delivers_pretool_context(host) || !valid_session_id_str(session_id) {
        return None;
    }
    let (command, file) = inline_structured_operand(event)?;
    let folder = session_dir(session_id)?;
    let marker = folder.join(HINT_MARKER);
    // First writer wins: `create_new` fails when the marker already
    // exists (or is a pre-planted symlink), and the hint stays silent.
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&marker).ok()?;
    }
    let hint = format!(
        "Hint: `prometheus-kit slice '{file}::<selector>'` reads part of that structured file without an inline script; selectors include `@count`, `@keys` and `@fields(a,b)` — e.g. `prometheus-kit slice '{file}::@count'`."
    );
    if let Some(metrics_host) = Host::from_hook(host) {
        metrics::record(metrics_host, Rule::UseTimeHint, command.len(), hint.len());
    }
    Some(hint)
}

pub fn inline_dump_guard(
    host: &str,
    event: &Value,
    session_id: &str,
    root: Option<&Path>,
) -> ReadGuard {
    if host_delivers_pretool_context(host) {
        return match use_time_hint(host, event, session_id) {
            Some(hint) => ReadGuard::Warn(hint),
            None => ReadGuard::Pass,
        };
    }
    if !valid_session_id_str(session_id) {
        return ReadGuard::Pass;
    }
    let Some((_, file)) = inline_structured_operand(event) else {
        return ReadGuard::Pass;
    };
    if !secret_path_denied(&file).is_empty() {
        return ReadGuard::Pass;
    }
    let base: PathBuf = match root {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => match get(event, "cwd").and_then(Value::as_str) {
            Some(c) if !c.is_empty() => PathBuf::from(c),
            _ => return ReadGuard::Pass,
        },
    };
    let canonical = resolve_loose(&base);
    let candidate = Path::new(&file);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    };
    let target_path = resolve_loose(&joined);
    let target_str = target_path.to_string_lossy();
    if !secret_path_denied(&target_str).is_empty() {
        return ReadGuard::Pass;
    }
    let Ok(info) = std::fs::metadata(&target_path) else {
        return ReadGuard::Pass;
    };
    if !info.is_file() {
        return ReadGuard::Pass;
    }
    let Some(folder) = session_dir(session_id) else {
        return ReadGuard::Pass;
    };
    let canonical_str = canonical.to_string_lossy();
    let mut key_bytes = Vec::with_capacity(canonical_str.len() + 1 + target_str.len());
    key_bytes.extend_from_slice(canonical_str.as_bytes());
    key_bytes.push(0);
    key_bytes.extend_from_slice(target_str.as_bytes());
    let marker = folder.join(format!("inline-dump-{}", sha256_hex(&key_bytes)));
    let record = |rule: Rule, raw: usize, emitted: usize| {
        if let Some(h) = Host::from_hook(host) {
            metrics::record(h, rule, raw, emitted);
        }
    };
    let meta_bytes = usize::try_from(info.len().min(usize::MAX as u64)).unwrap_or(usize::MAX);
    match read_deny_marker(&marker) {
        DenyMarker::Malformed | DenyMarker::Allowed => ReadGuard::Pass,
        DenyMarker::Denied => {
            write_deny_marker(&marker, "allowed\n");
            record(Rule::AllowedRetry, 0, meta_bytes);
            ReadGuard::Pass
        }
        DenyMarker::Absent => {
            let Some((file_bytes, maybe_lines)) = inspect_structured_file_size(&target_path) else {
                return ReadGuard::Pass;
            };
            let is_large = maybe_lines.is_none_or(|lines| lines >= LARGE_READ_LINES)
                || file_bytes >= LARGE_STRUCTURED_BYTES;
            if !is_large {
                return ReadGuard::Pass;
            }
            if !write_deny_marker(&marker, "denied\n") {
                return ReadGuard::Pass;
            }
            let safe_file: String = file.chars().filter(|c| !c.is_control()).collect();
            let size_label = match maybe_lines {
                Some(lines) if lines >= LARGE_READ_LINES => format!("{lines} lines"),
                _ => format!("{} KiB", file_bytes.div_ceil(1024)),
            };
            let msg = format!(
                "Large structured file inline dump ({safe_file}, {size_label}) denied once: use `~/.agents/prometheus/prometheus-kit slice '{safe_file}::<selector>'` (`@count`, `@keys`, `@fields(a,b)`) instead of an inline script. Retry the same command if you still need the raw script."
            );
            record(Rule::InlineDumpDenial, file_bytes, msg.len());
            ReadGuard::Deny(msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Host adapters & envelope handling.
// ---------------------------------------------------------------------------

fn ask_reply(reason: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    })
}

fn warn_reply(text: &str) -> Value {
    if text.is_empty() {
        json!({})
    } else {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": text,
            }
        })
    }
}

/// Host envelope for the read/inline-dump guard: warnings emit only on hosts
/// that deliver non-blocking `PreToolUse` context (`claude`, `muse`); denials
/// use each host's native blocking reply shape.
fn read_guard_reply(host: &str, guard: ReadGuard) -> Value {
    match guard {
        ReadGuard::Pass => json!({}),
        ReadGuard::Warn(text) => {
            if host_delivers_pretool_context(host) {
                warn_reply(&text)
            } else {
                json!({})
            }
        }
        ReadGuard::Deny(text) => match host {
            "claude" | "droid" | "muse" => json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": text,
                }
            }),
            "devin" => json!({"decision": "block", "reason": text}),
            "cursor" => json!({
                "permission": "deny",
                "user_message": text,
                "agent_message": text,
            }),
            _ => json!({}),
        },
    }
}

fn cursor_deny_reply(reason: &str) -> Value {
    let text = format!("Prometheus: {reason}.");
    json!({
        "permission": "deny",
        "user_message": text,
        "agent_message": text,
    })
}

fn problem_reply(host: &str, event: Option<&Value>, problem: &str) -> Value {
    let is_pretool = event
        .map(|ev| event_name_normalized(ev) == "pretooluse")
        .unwrap_or(false);
    if is_pretool {
        if let Some(ev) = event {
            if read_failure_allows(host, ev) {
                return json!({});
            }
        }
        return ask_reply(&format!(
            "Hook warning: {problem} — consent could not be evaluated"
        ));
    }
    json!({"systemMessage": format!("Hook warning: {problem}")})
}

fn resolve_dir(path: &str) -> Result<PathBuf, &'static str> {
    let resolved = std::fs::canonicalize(path).map_err(|_| "cwd-invalid")?;
    if !resolved.is_dir() {
        return Err("cwd-not-directory");
    }
    Ok(resolved)
}

fn handle_claude_or_muse(host: &str, raw: &[u8]) -> Value {
    if host == "claude"
        && OTHER_HOSTS
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
    {
        return json!({});
    }
    let parsed: Option<Value> = serde_json::from_slice(raw).ok();
    let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
        let problem = if parsed.is_some() {
            "event-malformed"
        } else {
            "invalid-json"
        };
        return problem_reply(host, None, problem);
    };
    let cwd = as_str(get(event, "cwd"));
    if cwd.is_empty() {
        return problem_reply(host, Some(event), "cwd-missing");
    }
    let session_id = as_str(get(event, "session_id"));
    if !valid_session_id_str(session_id) {
        return problem_reply(host, Some(event), "session-id-invalid");
    }
    let root = match resolve_dir(cwd) {
        Ok(root) => root,
        Err(problem) => return problem_reply(host, Some(event), problem),
    };
    if event_name_normalized(event) != "pretooluse" {
        return json!({});
    }
    let denial = secret_tool_denial(event);
    if !denial.is_empty() {
        return ask_reply(&denial);
    }
    if let Some(reply) = crate::hook_rewrite::rewrite_command_reply(host, event) {
        return reply;
    }
    let dump = inline_dump_guard(host, event, session_id, Some(&root));
    if dump != ReadGuard::Pass {
        return read_guard_reply(host, dump);
    }
    read_guard_reply(
        host,
        read_guard(host, event, session_id, Some(&root)),
    )
}

fn handle_droid(raw: &[u8]) -> Value {
    let parsed: Option<Value> = serde_json::from_slice(raw).ok();
    let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
        return json!({"systemMessage": "Hook warning: invalid-json"});
    };
    let session_id = as_str(get(event, "session_id"));
    if !valid_session_id_str(session_id) {
        return problem_reply("droid", Some(event), "session-id-invalid");
    }
    let cwd = as_str(get(event, "cwd"));
    if cwd.is_empty() {
        return problem_reply("droid", Some(event), "cwd-missing");
    }
    let root = match resolve_dir(cwd) {
        Ok(root) => root,
        Err(problem) => return problem_reply("droid", Some(event), problem),
    };
    if event_name_normalized(event) != "pretooluse" {
        return json!({});
    }
    let denial = secret_tool_denial(event);
    if !denial.is_empty() {
        return ask_reply(&denial);
    }
    if let Some(reply) = crate::hook_rewrite::rewrite_command_reply("droid", event) {
        return reply;
    }
    let dump = inline_dump_guard("droid", event, session_id, Some(&root));
    if dump != ReadGuard::Pass {
        return read_guard_reply("droid", dump);
    }
    read_guard_reply(
        "droid",
        read_guard("droid", event, session_id, Some(&root)),
    )
}

fn devin_candidate(event: &Value) -> Option<PathBuf> {
    if let Ok(value) = std::env::var("DEVIN_PROJECT_DIR") {
        if !value.is_empty() {
            return Some(PathBuf::from(value));
        }
    }
    let cwd = as_str(get(event, "cwd"));
    if !cwd.is_empty() {
        return Some(PathBuf::from(cwd));
    }
    std::env::current_dir().ok()
}

fn handle_devin(raw: &[u8]) -> Value {
    let parsed: Option<Value> = serde_json::from_slice(raw).ok();
    let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
        return json!({"systemMessage": "Hook warning: invalid-json"});
    };
    if event_name_normalized(event) != "pretooluse" {
        return json!({});
    }
    if casefold(tool_name(event)) == "read" && read_failure_allows("devin", event) {
        let session_id = as_str(get(event, "session_id"));
        let candidate = devin_candidate(event);
        return read_guard_reply(
            "devin",
            read_guard("devin", event, session_id, candidate.as_deref()),
        );
    }
    let session_id = as_str(get(event, "session_id"));
    if !valid_session_id_str(session_id) {
        return problem_reply("devin", Some(event), "session-id-invalid");
    }
    let Some(candidate) = devin_candidate(event) else {
        return problem_reply("devin", Some(event), "root-invalid");
    };
    let root = match std::fs::canonicalize(&candidate) {
        Ok(resolved) if resolved.is_dir() => resolved,
        Ok(_) => return problem_reply("devin", Some(event), "root-not-directory"),
        Err(_) => return problem_reply("devin", Some(event), "root-invalid"),
    };
    let denial = secret_tool_denial(event);
    if !denial.is_empty() {
        return ask_reply(&denial);
    }
    let dump = inline_dump_guard("devin", event, session_id, Some(&root));
    if dump != ReadGuard::Pass {
        return read_guard_reply("devin", dump);
    }
    read_guard_reply(
        "devin",
        read_guard("devin", event, session_id, Some(&root)),
    )
}

fn push_root(roots: &mut Vec<PathBuf>, candidate: &Path) {
    if candidate.as_os_str().is_empty() {
        return;
    }
    if let Ok(resolved) = std::fs::canonicalize(candidate) {
        if resolved.is_dir() && !roots.contains(&resolved) {
            roots.push(resolved);
        }
    }
}

fn cursor_roots(event: &Value) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(Value::Array(listed)) = get(event, "workspace_roots") {
        for entry in listed {
            if let Value::String(text) = entry {
                if !text.is_empty() {
                    push_root(&mut roots, Path::new(text));
                }
            }
        }
    }
    if roots.is_empty() {
        let cwd = as_str(get(event, "cwd"));
        if !cwd.is_empty() {
            push_root(&mut roots, Path::new(cwd));
        }
        if roots.is_empty() {
            if let Ok(cur) = std::env::current_dir() {
                push_root(&mut roots, &cur);
            }
        }
    }
    roots
}

fn handle_cursor(raw: &[u8]) -> Value {
    let parsed: Option<Value> = serde_json::from_slice(raw).ok();
    let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
        return json!({});
    };
    let name = event_name_normalized(event);
    if name == "beforesubmitprompt" {
        return json!({"continue": true});
    }
    if name != "pretooluse" {
        return json!({});
    }
    let session_id = as_str(py_or(get(event, "session_id"), get(event, "conversation_id")));
    if !valid_session_id_str(session_id) {
        if read_failure_allows("cursor", event) {
            return json!({});
        }
        return cursor_deny_reply("the secret guard failed");
    }
    let reason = cursor_secret_denied(event);
    if !reason.is_empty() {
        return cursor_deny_reply(&reason);
    }
    let roots = cursor_roots(event);
    let dump = inline_dump_guard(
        "cursor",
        event,
        session_id,
        roots.first().map(PathBuf::as_path),
    );
    if dump != ReadGuard::Pass {
        return read_guard_reply("cursor", dump);
    }
    read_guard_reply(
        "cursor",
        read_guard(
            "cursor",
            event,
            session_id,
            roots.first().map(PathBuf::as_path),
        ),
    )
}

pub fn is_supported_host(host: &str) -> bool {
    matches!(host, "claude" | "cursor" | "devin" | "droid" | "muse")
}

/// Evaluate one hook event from raw stdin JSON for `host`.
pub fn run_hook(host: &str, raw_stdin: &[u8]) -> Value {
    match host {
        "claude" | "muse" => handle_claude_or_muse(host, raw_stdin),
        "droid" => handle_droid(raw_stdin),
        "devin" => handle_devin(raw_stdin),
        "cursor" => handle_cursor(raw_stdin),
        _ => json!({}),
    }
}

/// Fail-closed fallback reply if hook evaluation panics.
pub fn panic_fallback(host: &str) -> Value {
    if host == "cursor" {
        cursor_deny_reply("the secret guard failed")
    } else {
        ask_reply("consent could not be evaluated")
    }
}

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::MutexGuard;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_guard() -> MutexGuard<'static, ()> {
        TEST_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "prom_hook_ut_{tag}_{}_{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct EnvOverride {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvOverride {
        fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
            let mut saved = Vec::new();
            for &(k, v) in pairs {
                saved.push((k, std::env::var(k).ok()));
                match v {
                    Some(val) => unsafe { std::env::set_var(k, val) },
                    None => unsafe { std::env::remove_var(k) },
                }
            }
            Self { saved }
        }
    }

    impl Drop for EnvOverride {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..).rev() {
                match v {
                    Some(val) => unsafe { std::env::set_var(k, val) },
                    None => unsafe { std::env::remove_var(k) },
                }
            }
        }
    }

    #[test]
    fn secret_path_classification_matches_contract() {
        for (path, denied) in [
            (".env", true),
            (".env.local", true),
            (".env.example", false),
            (".env.sample", false),
            (".env.template", false),
            (".env.dist", false),
            ("config/secrets.yml", true),
            ("config/secrets.yaml", true),
            ("config/secrets.json", true),
            ("config/secrets.yml.template", false),
            ("keys/id_rsa", true),
            ("keys/id_rsa.pub", false),
            ("keys/id_backup", true),
            (".ssh/config", true),
            ("dir/.AWS/credentials", true),
            ("dir/.gnupg/secring.gpg", true),
            ("cert.pem", true),
            ("priv.key", true),
            ("credentials.csv", true),
            ("auth.json", true),
            (".npmrc", true),
            ("src/app.py", false),
            ("", false),
        ] {
            assert_eq!(denied, !secret_path_denied(path).is_empty(), "path={path}");
        }
    }

    #[test]
    fn shell_commands_never_trigger_secret_ask_while_file_tools_do() {
        let _g = env_guard();
        let tmp = TempDir::new("shell_no_ask");
        let _env = EnvOverride::set(&[
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
            ("PROMETHEUS_KIT_RTK_COEXIST", Some("0")),
            ("PROMETHEUS_KIT_NO_REWRITE", None),
        ]);
        // Structured file tools still block secret paths across every host.
        for tool_input in [
            json!({"file_path": ".env"}),
            json!({"file_path": "config/secrets.yml"}),
            json!({"file_path": ".ssh/id_rsa"}),
            json!({"pattern": "**/*.pem"}),
        ] {
            for host in ["claude", "droid", "devin", "muse"] {
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "tool_input": tool_input,
                    "cwd": tmp.0,
                    "session_id": "s-file",
                });
                let reply = run_hook(host, ev.to_string().as_bytes());
                assert_eq!(
                    "ask",
                    reply["hookSpecificOutput"]["permissionDecision"],
                    "{host} {tool_input}"
                );
            }
            let cev = json!({
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": tool_input,
                "workspace_roots": [tmp.0],
                "conversation_id": "s-file-cursor",
            });
            assert_eq!(
                "deny",
                run_hook("cursor", cev.to_string().as_bytes())["permission"],
                "cursor {tool_input}"
            );
        }

        // Shell commands never trigger secret `ask`/`deny` across any host.
        for cmd in [
            "cat .env",
            "cat .*",
            "git show HEAD:.env",
            r#"for r in prometheus prometheos; do git -C $r ls-files | sed 's/.*\.//' | sort; done"#,
            r#"grep -n "Command::new\|\.env(" tests/prometheus_kit.rs"#,
            "python3 -c 'import re, secrets; print(re.search(r\".*\", secrets.token_hex(4)))'",
            r#"awk '/^\s*fn .*\(\)/ {print}' src/lib.rs"#,
            r#"pgrep -af "vitest|node .*test""#,
            "du -sh /tmp/repo/* /tmp/repo/.*",
        ] {
            let devin_ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "exec",
                "tool_input": {"command": cmd},
                "cwd": tmp.0,
                "session_id": "s-devin",
            });
            assert_eq!(
                json!({}),
                run_hook("devin", devin_ev.to_string().as_bytes()),
                "devin {cmd}"
            );
            for host in ["claude", "droid", "muse"] {
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "cwd": tmp.0,
                    "session_id": "s-host",
                });
                let reply = run_hook(host, ev.to_string().as_bytes());
                assert!(
                    reply["hookSpecificOutput"].get("permissionDecision").is_none(),
                    "{host} {cmd}: {reply}"
                );
            }
            let cursor_ev = json!({
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": cmd},
                "workspace_roots": [tmp.0],
                "conversation_id": "s-cursor",
            });
            assert_eq!(
                json!({}),
                run_hook("cursor", cursor_ev.to_string().as_bytes()),
                "cursor {cmd}"
            );
        }

        // Literal secret operands still opt out of command rewriting (passthrough).
        for passthrough in [
            "cat .env",
            "head -n 5 .env.local",
            "git show HEAD:.env",
            "rg foo .env",
            "dotnet test --settings .env | tail -5",
        ] {
            assert!(
                crate::hook_rewrite::rewrite_command_str(
                    passthrough,
                    "'/bin/prometheus-kit'",
                    false,
                    None,
                )
                .is_none(),
                "{passthrough} must pass through unrewritten"
            );
        }
        // Quoted regexes with `.*` rewrite cleanly on POSIX.
        #[cfg(not(windows))]
        for rw_cmd in [
            "rg 'fn .*keep_log' src",
            "rg '.*keep_log' src",
            "rg 'fn .*' src",
            "rg '(.*)' src",
        ] {
            let rewritten = crate::hook_rewrite::rewrite_command_str(
                rw_cmd,
                "'/bin/prometheus-kit'",
                false,
                None,
            )
            .unwrap_or_else(|| panic!("{rw_cmd} should rewrite cleanly"));
            assert!(rewritten.contains("search"), "{rewritten}");
        }
    }

    #[test]
    fn resolve_loose_keeps_dot_non_empty() {
        let resolved = resolve_loose(Path::new("."));
        assert!(!resolved.as_os_str().is_empty());
        assert!(resolved.is_absolute());
        let rel = resolve_loose(Path::new("./nonexistent_child_xyz"));
        assert!(rel.is_absolute());
        assert!(rel.ends_with("nonexistent_child_xyz"));
    }

    #[test]
    fn direct_checks_and_edits_pass_across_hosts() {
        let _g = env_guard();
        let tmp = TempDir::new("pass");
        let _env = EnvOverride::set(&[
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
            ("PROMETHEUS_KIT_RTK_COEXIST", Some("0")),
            ("PROMETHEUS_KIT_NO_REWRITE", None),
        ]);
        for host in ["claude", "droid", "devin", "muse"] {
            for cmd in ["sudo dotnet test", "env cargo build"] {
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "cwd": tmp.0,
                    "session_id": "s1",
                });
                assert_eq!(json!({}), run_hook(host, ev.to_string().as_bytes()), "{host} {cmd}");
            }
            for cmd in ["dotnet test", "cargo test"] {
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "cwd": tmp.0,
                    "session_id": "s1",
                });
                let reply = run_hook(host, ev.to_string().as_bytes());
                assert!(
                    reply["hookSpecificOutput"].get("permissionDecision").is_none(),
                    "{host} {cmd} must never ask/deny"
                );
                if host == "devin" {
                    assert_eq!(json!({}), reply, "{host} {cmd}");
                } else {
                    let rewritten = reply["hookSpecificOutput"]["updatedInput"]["command"]
                        .as_str()
                        .expect("updatedInput.command");
                    assert!(
                        rewritten.contains("compact --mode test --"),
                        "{host} {cmd}: {rewritten}"
                    );
                }
            }
            for _ in 0..6 {
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Edit",
                    "tool_input": {"file_path": "src/a.rs"},
                    "cwd": tmp.0,
                    "session_id": "s1",
                });
                assert_eq!(json!({}), run_hook(host, ev.to_string().as_bytes()));
            }
        }
        {
            let _no_rw = EnvOverride::set(&[("PROMETHEUS_KIT_NO_REWRITE", Some("1"))]);
            let ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "dotnet test"},
                "cwd": tmp.0,
                "session_id": "s1",
            });
            assert_eq!(json!({}), run_hook("droid", ev.to_string().as_bytes()));
        }
        for cmd in [
            "sed -n '1,5p' .env",
            "git show HEAD:.env",
            "dotnet test --settings .env",
        ] {
            for host in ["claude", "droid"] {
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Execute",
                    "tool_input": {"command": cmd},
                    "cwd": tmp.0,
                    "session_id": "s1",
                });
                assert_eq!(json!({}), run_hook(host, ev.to_string().as_bytes()), "{host} {cmd}");
            }
        }
    }

    #[test]
    fn claude_short_circuits_when_other_host_env_is_set_but_muse_does_not() {
        let _g = env_guard();
        let tmp = TempDir::new("other");
        let _env = EnvOverride::set(&[("CURSOR_PROJECT_DIR", Some("/tmp"))]);
        let ev = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env"},
            "cwd": tmp.0,
            "session_id": "s1",
        });
        assert_eq!(json!({}), run_hook("claude", ev.to_string().as_bytes()));
        let muse_reply = run_hook("muse", ev.to_string().as_bytes());
        assert_eq!("ask", muse_reply["hookSpecificOutput"]["permissionDecision"]);
    }

    #[test]
    fn malformed_and_lifecycle_envelopes_match_adapters() {
        let _g = env_guard();
        let tmp = TempDir::new("env");
        let _env = EnvOverride::set(&[
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
        ]);
        let claude_arr = run_hook("claude", b"[]");
        assert!(claude_arr["systemMessage"]
            .as_str()
            .unwrap()
            .contains("event-malformed"));
        let claude_bad = run_hook("claude", b"{");
        assert!(claude_bad["systemMessage"]
            .as_str()
            .unwrap()
            .contains("invalid-json"));
        assert_eq!(
            json!({"continue": true}),
            run_hook("cursor", br#"{"hook_event_name":"beforeSubmitPrompt"}"#)
        );
        assert_eq!(
            json!({}),
            run_hook("devin", br#"{"hook_event_name":"Stop"}"#)
        );
        let claude_stop_missing = run_hook("claude", br#"{"hook_event_name":"Stop"}"#);
        assert!(claude_stop_missing["systemMessage"]
            .as_str()
            .unwrap()
            .contains("Hook warning"));
        // Non-secret Read proceeds even if session_id/cwd are missing.
        let non_secret_read = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "README.md"},
        });
        for host in ["claude", "droid", "devin", "muse", "cursor"] {
            assert_eq!(
                json!({}),
                run_hook(host, non_secret_read.to_string().as_bytes()),
                "{host}"
            );
        }
        // Secret Read with missing session_id fails closed.
        let secret_read = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env"},
            "cwd": tmp.0,
        });
        assert_eq!(
            "ask",
            run_hook("claude", secret_read.to_string().as_bytes())["hookSpecificOutput"]
                ["permissionDecision"]
        );
        assert_eq!(
            "deny",
            run_hook("cursor", secret_read.to_string().as_bytes())["permission"]
        );
    }

    #[test]
    fn reread_warns_and_respects_security_and_edits() {
        let _g = env_guard();
        let tmp = TempDir::new("reread");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _env = EnvOverride::set(&[
            ("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap())),
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
        ]);
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let file = repo.join("a.py");
        fs::write(&file, "x = 1\n").unwrap();

        let ev = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "a.py"},
            "cwd": repo,
            "session_id": "s-reread",
        });
        assert_eq!(json!({}), run_hook("claude", ev.to_string().as_bytes()));
        let second = run_hook("claude", ev.to_string().as_bytes());
        assert_eq!(REREAD_MESSAGE, second["hookSpecificOutput"]["additionalContext"]);
        assert!(second["hookSpecificOutput"].get("permissionDecision").is_none());

        // Partial read does not warn, does not reset stored hash, and — on a
        // small file — never touches reread state, so it passes every time.
        let partial = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "a.py", "offset": 1, "limit": 5},
            "cwd": repo,
            "session_id": "s-reread",
        });
        assert_eq!(json!({}), run_hook("claude", partial.to_string().as_bytes()));
        assert_eq!(json!({}), run_hook("claude", partial.to_string().as_bytes()));
        let third = run_hook("claude", ev.to_string().as_bytes());
        assert_eq!(REREAD_MESSAGE, third["hookSpecificOutput"]["additionalContext"]);

        // Edited file updates hash without warning, then next reread warns.
        fs::write(&file, "x = 2\n").unwrap();
        assert_eq!(json!({}), run_hook("claude", ev.to_string().as_bytes()));
        let fourth = run_hook("claude", ev.to_string().as_bytes());
        assert_eq!(REREAD_MESSAGE, fourth["hookSpecificOutput"]["additionalContext"]);

        // Cursor drops non-blocking PreToolUse context, so <200-line rereads stay silent (ADR-0014 D3).
        let cev = json!({
            "hook_event_name": "preToolUse",
            "tool_name": "Read",
            "tool_input": {"path": "a.py"},
            "workspace_roots": [repo],
            "conversation_id": "s-cursor",
        });
        assert_eq!(json!({}), run_hook("cursor", cev.to_string().as_bytes()));
        assert_eq!(json!({}), run_hook("cursor", cev.to_string().as_bytes()));
        // Droid and Devin also suppress inert <200-line reread warnings.
        let dev = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "a.py"},
            "cwd": repo,
            "session_id": "s-droid",
        });
        assert_eq!(json!({}), run_hook("droid", dev.to_string().as_bytes()));
        assert_eq!(json!({}), run_hook("droid", dev.to_string().as_bytes()));
        assert_eq!(json!({}), run_hook("devin", dev.to_string().as_bytes()));
        assert_eq!(json!({}), run_hook("devin", dev.to_string().as_bytes()));
    }

    #[test]
    fn use_time_hint_fires_once_per_session_and_leaves_the_command_unchanged() {
        let _g = env_guard();
        let tmp = TempDir::new("hint");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _env = EnvOverride::set(&[
            ("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap())),
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
        ]);
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        // Session ids are unique per run: on Windows the session dir is
        // the shared temp dir (no XDG_RUNTIME_DIR), so a fixed id would
        // inherit the marker a previous test run left behind.
        let uniq = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let sid = |n: &str| format!("s-hint{n}-{uniq}");

        let py = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "python3 -c 'import json; d=json.load(open(\"data.json\")); print(len(d[\"users\"]))'"},
            "cwd": repo,
            "session_id": sid(""),
        });
        let first = run_hook("claude", py.to_string().as_bytes());
        let ctx = first["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("first inline parse gets the hint");
        assert!(ctx.contains("prometheus-kit slice 'data.json::<selector>'"), "{ctx}");
        assert!(ctx.contains("@count"), "{ctx}");
        // The command runs unchanged: no rewrite, no permission decision.
        assert!(first["hookSpecificOutput"].get("updatedInput").is_none());
        assert!(first["hookSpecificOutput"].get("permissionDecision").is_none());
        // Once per session per rule: the same session stays silent, even
        // for a different interpreter shape.
        assert_eq!(json!({}), run_hook("claude", py.to_string().as_bytes()));
        let jq = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "jq '.users | length' data.json"},
            "cwd": repo,
            "session_id": sid(""),
        });
        assert_eq!(json!({}), run_hook("claude", jq.to_string().as_bytes()));
        // A new session gets the hint again (jq form).
        let jq2 = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "jq '.users | length' data.json"},
            "cwd": repo,
            "session_id": sid("2"),
        });
        let jq_reply = run_hook("claude", jq2.to_string().as_bytes());
        assert!(jq_reply["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|c| c.contains("@fields")));
        // Heredoc and node forms fire in their own sessions.
        let heredoc = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "python3 - <<'EOF'\nimport yaml\nd = yaml.safe_load(open('cfg.yaml'))\nprint(d['meta'])\nEOF"},
            "cwd": repo,
            "session_id": sid("3"),
        });
        let hd = run_hook("claude", heredoc.to_string().as_bytes());
        assert!(hd["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|c| c.contains("cfg.yaml")));
        let node = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "node -e \"console.log(Object.keys(require('./cfg.toml')))\" cfg.toml"},
            "cwd": repo,
            "session_id": sid("4"),
        });
        // `node -e` with the file only inside the script text has no
        // structured-file operand token after the program, but the
        // trailing cfg.toml operand names it.
        let nd = run_hook("claude", node.to_string().as_bytes());
        assert!(nd["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|c| c.contains("cfg.toml")));
        // No structured file, or no interpreter shape: silence.
        let plain = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "python3 -c 'print(1)'"},
            "cwd": repo,
            "session_id": sid("5"),
        });
        assert_eq!(json!({}), run_hook("claude", plain.to_string().as_bytes()));
        let ls = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la data.json"},
            "cwd": repo,
            "session_id": sid("6"),
        });
        assert_eq!(json!({}), run_hook("claude", ls.to_string().as_bytes()));
    }

    #[cfg(unix)]
    #[test]
    fn reread_refuses_symlinks_fifos_and_insecure_dirs() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let _g = env_guard();
        let tmp = TempDir::new("sec");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        let _env = EnvOverride::set(&[("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap()))]);

        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let secret = repo.join(".env");
        fs::write(&secret, "SECRET=1\n").unwrap();
        let link = repo.join("plain_link");
        symlink(&secret, &link).unwrap();

        assert_eq!(
            ReadGuard::Pass,
            read_guard(
                "claude",
                &json!({"tool_name": "Read", "tool_input": {"file_path": link}}),
                "s-sec",
                Some(&repo),
            )
        );
        assert_eq!(
            ReadGuard::Pass,
            read_guard(
                "claude",
                &json!({"tool_name": "Read", "tool_input": {"file_path": link}}),
                "s-sec",
                Some(&repo),
            )
        );

        // Insecure 0o755 session dir is refused and never chmod'd — even for
        // a large file read twice, which must fail open rather than deny.
        let bad_sess = rt.join("prometheus").join("s-bad");
        fs::create_dir_all(&bad_sess).unwrap();
        fs::set_permissions(&bad_sess, fs::Permissions::from_mode(0o755)).unwrap();
        let file = repo.join("a.py");
        fs::write(&file, "x = 1\n".repeat(220)).unwrap();
        for _ in 0..2 {
            assert_eq!(
                ReadGuard::Pass,
                read_guard(
                    "claude",
                    &json!({"tool_name": "Read", "tool_input": {"file_path": file}}),
                    "s-bad",
                    Some(&repo),
                )
            );
        }
        assert_eq!(
            0o755,
            fs::metadata(&bad_sess).unwrap().permissions().mode() & 0o777
        );
    }

    #[test]
    fn large_whole_file_read_advises_outline_slice_and_respects_reread() {
        let _g = env_guard();
        let tmp = TempDir::new("large_read");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _env = EnvOverride::set(&[
            ("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap())),
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
            ("PROMETHEUS_KIT_NO_READ_HINT", None),
        ]);
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();

        let small_rs = repo.join("small.rs");
        fs::write(&small_rs, "fn a() {}\n".repeat(199)).unwrap();
        let ev_small = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "small.rs"},
            "cwd": repo,
            "session_id": "s-large",
        });
        assert_eq!(json!({}), run_hook("droid", ev_small.to_string().as_bytes()));

        let big_rs = repo.join("big.rs");
        fs::write(&big_rs, "fn a() {}\n".repeat(220)).unwrap();
        let ev_big = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "big.rs"},
            "cwd": repo,
            "session_id": "s-large",
        });
        // State 1: first unranged whole-file read of >=200 lines denies once.
        let first = run_hook("droid", ev_big.to_string().as_bytes());
        assert_eq!("deny", first["hookSpecificOutput"]["permissionDecision"]);
        let first_reason = first["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("first-read denial reason");
        assert!(first_reason.contains("220 lines"), "{first_reason}");
        assert!(first_reason.contains("outline"), "{first_reason}");
        assert!(first_reason.contains("slice"), "{first_reason}");
        assert!(first["hookSpecificOutput"].get("additionalContext").is_none());

        // State 2: immediate retry of the first whole-file read passes and records hash.
        assert_eq!(json!({}), run_hook("droid", ev_big.to_string().as_bytes()));

        // State 3: subsequent unchanged whole-file reread denies once with exact envelope.
        let deny_env = || {
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": REREAD_DENIAL_MESSAGE,
                }
            })
        };
        let third = run_hook("droid", ev_big.to_string().as_bytes());
        assert_eq!(deny_env(), third);
        assert!(third["hookSpecificOutput"].get("additionalContext").is_none());
        // State 4: immediate retry after context loss passes; next unchanged read denies again.
        assert_eq!(json!({}), run_hook("droid", ev_big.to_string().as_bytes()));
        let fifth = run_hook("droid", ev_big.to_string().as_bytes());
        assert_eq!(deny_env(), fifth);

        // An edit while a denial is pending resets to State 1 (first-read denial for new content).
        fs::write(&big_rs, "fn b() {}\n".repeat(220)).unwrap();
        let after_edit = run_hook("droid", ev_big.to_string().as_bytes());
        assert_eq!("deny", after_edit["hookSpecificOutput"]["permissionDecision"]);
        assert!(after_edit["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("220 lines"));
        // Retry passes and records new hash; next unchanged read is reread denial.
        assert_eq!(json!({}), run_hook("droid", ev_big.to_string().as_bytes()));
        let after_edit_reread = run_hook("droid", ev_big.to_string().as_bytes());
        assert_eq!(deny_env(), after_edit_reread);

        // First-time ranged reads ALWAYS pass without blocking; identical range rereads deny once.
        let range = |offset: u64, limit: u64| {
            json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "big.rs", "offset": offset, "limit": limit},
                "cwd": repo,
                "session_id": "s-large",
            })
        };
        assert_eq!(json!({}), run_hook("droid", range(1, 50).to_string().as_bytes()));
        assert_eq!(deny_env(), run_hook("droid", range(1, 50).to_string().as_bytes()));
        assert_eq!(json!({}), run_hook("droid", range(1, 50).to_string().as_bytes()));
        assert_eq!(json!({}), run_hook("droid", range(51, 50).to_string().as_bytes()));
        // Range reads never touched the whole-file key: its pending denial
        // resolves as the allowed retry, then denies again.
        assert_eq!(json!({}), run_hook("droid", ev_big.to_string().as_bytes()));
        assert_eq!(deny_env(), run_hook("droid", ev_big.to_string().as_bytes()));

        // Partial read on large file with a fresh range passes silently.
        let partial = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "big.rs", "offset": 1, "limit": 10},
            "cwd": repo,
            "session_id": "s-large",
        });
        assert_eq!(json!({}), run_hook("droid", partial.to_string().as_bytes()));

        // Large non-code log file first-read denial suggests slice / compact.
        let big_log = repo.join("run.log");
        fs::write(&big_log, "line\n".repeat(220)).unwrap();
        let ev_log = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "run.log"},
            "cwd": repo,
            "session_id": "s-large",
        });
        let log_reply = run_hook("droid", ev_log.to_string().as_bytes());
        assert_eq!("deny", log_reply["hookSpecificOutput"]["permissionDecision"]);
        let log_reason = log_reply["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("log denial reason");
        assert!(log_reason.contains("slice"), "{log_reason}");
        assert!(log_reason.contains("compact"), "{log_reason}");

        // Large secret .env file triggers secret ask, never first-read denial.
        let big_env = repo.join(".env");
        fs::write(&big_env, "K=V\n".repeat(220)).unwrap();
        let ev_env = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env"},
            "cwd": repo,
            "session_id": "s-large",
        });
        let env_reply = run_hook("droid", ev_env.to_string().as_bytes());
        assert_eq!("ask", env_reply["hookSpecificOutput"]["permissionDecision"]);

        // PROMETHEUS_KIT_NO_READ_HINT=1 skips first-read denial while keeping
        // the deny-once reread guard active.
        {
            let _no_hint = EnvOverride::set(&[("PROMETHEUS_KIT_NO_READ_HINT", Some("1"))]);
            let hinted_rs = repo.join("hinted.rs");
            fs::write(&hinted_rs, "fn b() {}\n".repeat(220)).unwrap();
            let ev_hint = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "hinted.rs"},
                "cwd": repo,
                "session_id": "s-large",
            });
            assert_eq!(json!({}), run_hook("droid", ev_hint.to_string().as_bytes()));
            let second_hint = run_hook("droid", ev_hint.to_string().as_bytes());
            assert_eq!(
                "deny",
                second_hint["hookSpecificOutput"]["permissionDecision"]
            );
        }
    }

    #[test]
    fn reread_denial_uses_each_host_envelope() {
        assert!(REREAD_DENIAL_MESSAGE.contains("prometheus-kit slice"));
        let _g = env_guard();
        let tmp = TempDir::new("deny_hosts");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _env = EnvOverride::set(&[
            ("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap())),
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
        ]);
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let big_path = repo.join("big.rs");
        fs::write(&big_path, "fn a() {}\n".repeat(220)).unwrap();
        let expected_first_msg = first_read_denial_message(&big_path, 220);

        for (host, session) in [
            ("claude", "s-deny-claude"),
            ("cursor", "s-deny-cursor"),
            ("devin", "s-deny-devin"),
            ("droid", "s-deny-droid"),
            ("muse", "s-deny-muse"),
        ] {
            let ev = match host {
                "cursor" => json!({
                    "hook_event_name": "preToolUse",
                    "tool_name": "Read",
                    "tool_input": {"path": "big.rs"},
                    "workspace_roots": [repo],
                    "conversation_id": session,
                }),
                "devin" => json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "read",
                    "tool_input": {"file_path": "big.rs"},
                    "cwd": repo,
                    "session_id": session,
                }),
                _ => json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "tool_input": {"file_path": "big.rs"},
                    "cwd": repo,
                    "session_id": session,
                }),
            };
            let bytes = ev.to_string().into_bytes();
            let envelope_for = |msg: &str| match host {
                "claude" | "droid" | "muse" => json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": msg,
                    }
                }),
                "devin" => json!({"decision": "block", "reason": msg}),
                "cursor" => json!({
                    "permission": "deny",
                    "user_message": msg,
                    "agent_message": msg,
                }),
                _ => unreachable!(),
            };
            // State 1: first unranged whole-file read denies once.
            assert_eq!(envelope_for(&expected_first_msg), run_hook(host, &bytes), "host={host} state 1");
            // State 2: immediate retry passes and records hash.
            assert_eq!(json!({}), run_hook(host, &bytes), "host={host} state 2");
            // State 3: unchanged reread denies once.
            assert_eq!(envelope_for(REREAD_DENIAL_MESSAGE), run_hook(host, &bytes), "host={host} state 3");
            // State 4: immediate retry passes.
            assert_eq!(json!({}), run_hook(host, &bytes), "host={host} state 4");
        }
    }

    #[cfg(unix)]
    #[test]
    fn reread_denial_fails_open_when_state_cannot_advance() {
        use std::os::unix::fs::PermissionsExt;
        if my_uid() == 0 {
            return;
        }
        let _g = env_guard();
        let tmp = TempDir::new("deny_failopen");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        let _env = EnvOverride::set(&[("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap()))]);
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join("big.rs"), "fn a() {}\n".repeat(220)).unwrap();
        let session = "s-failopen";
        let folder = rt.join("prometheus").join(session);
        let ev = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "big.rs"},
            "cwd": repo,
            "session_id": session,
        });
        let bytes = ev.to_string().into_bytes();
        // Lock the session dir read-only BEFORE first read: first-read denial must fail open.
        let parent = rt.join("prometheus");
        fs::create_dir_all(&folder).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o500)).unwrap();
        for _ in 0..2 {
            assert_eq!(json!({}), run_hook("claude", &bytes), "unwritable first read must fail open");
        }
        // Unlock so Call 1 denies and Call 2 records Seen, then re-lock before Call 3 reread.
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
        let first = run_hook("claude", &bytes);
        assert_eq!("deny", first["hookSpecificOutput"]["permissionDecision"]);
        assert_eq!(json!({}), run_hook("claude", &bytes));
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o500)).unwrap();
        for _ in 0..2 {
            let reply = run_hook("claude", &bytes);
            assert_ne!(
                "deny",
                reply["hookSpecificOutput"]["permissionDecision"],
                "unwritable reread state must never deny"
            );
        }
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn null_partial_parameters_count_as_a_whole_file_read() {
        let _g = env_guard();
        let tmp = TempDir::new("null_partial");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _env = EnvOverride::set(&[
            ("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap())),
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
        ]);
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join("big.rs"), "fn a() {}\n".repeat(220)).unwrap();

        let ev = |session: &str, nulls: bool| {
            let mut input = json!({"file_path": "big.rs"});
            if nulls {
                input["offset"] = Value::Null;
                input["limit"] = Value::Null;
            }
            json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": input,
                "cwd": repo,
                "session_id": session,
            })
        };

        // Plain read (state 1 deny) -> nulled retry (state 2 pass) -> plain reread (state 3 deny)
        // share the same whole-file state key.
        let whole = ev("s-null-a", false);
        let first = run_hook("claude", whole.to_string().as_bytes());
        assert_eq!("deny", first["hookSpecificOutput"]["permissionDecision"]);
        let nulled = ev("s-null-a", true);
        assert_eq!(json!({}), run_hook("claude", nulled.to_string().as_bytes()));
        let third = run_hook("claude", nulled.to_string().as_bytes());
        assert_eq!("deny", third["hookSpecificOutput"]["permissionDecision"]);
        assert_eq!(REREAD_DENIAL_MESSAGE, third["hookSpecificOutput"]["permissionDecisionReason"]);

        // On a fresh session the null-variant first read is State 1 first-read denial.
        let fresh = ev("s-null-b", true);
        let fresh_reply = run_hook("claude", fresh.to_string().as_bytes());
        assert_eq!("deny", fresh_reply["hookSpecificOutput"]["permissionDecision"]);
        assert!(fresh_reply["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("220 lines"));
    }

    #[test]
    fn no_context_hosts_promote_large_inline_dumps_and_suppress_dead_hints() {
        let _g = env_guard();
        let tmp = TempDir::new("inline_dump_deny");
        let rt = tmp.0.join("xdg");
        fs::create_dir_all(&rt).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _env = EnvOverride::set(&[
            ("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap())),
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
            ("PROMETHEUS_KIT_RTK_COEXIST", Some("0")),
        ]);
        let repo = tmp.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join("small.json"), "{\"a\": 1}\n").unwrap();
        let big_json: String = format!(
            "{{\n{}\n}}\n",
            (0..220)
                .map(|i| format!("  \"k{i}\": {i}"))
                .collect::<Vec<_>>()
                .join(",\n")
        );
        fs::write(repo.join("big.json"), &big_json).unwrap();
        fs::write(repo.join("secrets.json"), &big_json).unwrap();

        let uniq = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        );
        for (host, tool) in [("droid", "Execute"), ("cursor", "Shell"), ("devin", "exec")] {
            let sid = format!("s-dump-{host}-{uniq}");
            let make_ev = |cmd: &str| match host {
                "cursor" => json!({
                    "hook_event_name": "preToolUse",
                    "tool_name": tool,
                    "tool_input": {"command": cmd},
                    "workspace_roots": [repo],
                    "conversation_id": sid,
                }),
                _ => json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": tool,
                    "tool_input": {"command": cmd},
                    "cwd": repo,
                    "session_id": sid,
                }),
            };
            // Small or nonexistent structured files stay silent (no dead warning!).
            assert_eq!(json!({}), run_hook(host, make_ev("jq '.a' small.json").to_string().as_bytes()), "{host} small");
            assert_eq!(json!({}), run_hook(host, make_ev("jq '.a' missing.json").to_string().as_bytes()), "{host} missing");
            // Secret structured files never trigger inline-dump denial.
            assert_eq!(json!({}), run_hook(host, make_ev("jq '.k0' secrets.json").to_string().as_bytes()), "{host} secret");

            // Large structured file triggers Guided deny-once with computed selector guidance,
            // immediate retry passes, and subsequent call stays silent.
            let big_ev = make_ev("jq '.k0' big.json").to_string().into_bytes();
            let first = run_hook(host, &big_ev);
            let reason = match host {
                "droid" => {
                    assert_eq!("deny", first["hookSpecificOutput"]["permissionDecision"]);
                    first["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap()
                }
                "cursor" => {
                    assert_eq!("deny", first["permission"]);
                    first["agent_message"].as_str().unwrap()
                }
                "devin" => {
                    assert_eq!("block", first["decision"]);
                    first["reason"].as_str().unwrap()
                }
                _ => unreachable!(),
            };
            assert!(reason.contains("@count") && reason.contains("@keys") && reason.contains("@fields"), "{host}: {reason}");
            assert_eq!(json!({}), run_hook(host, &big_ev), "{host} retry");
            assert_eq!(json!({}), run_hook(host, &big_ev), "{host} after retry");
        }

        // Cover python3 -c (YAML/TOML), node -e, minified >=8KiB single-line JSON,
        // >16 MiB structured files, and unwritable-dir fail-open.
        fs::write(repo.join("big.yaml"), "item: 1\n".repeat(220)).unwrap();
        fs::write(repo.join("big.toml"), "k = 1\n".repeat(220)).unwrap();
        fs::write(repo.join("minified.json"), format!("{{\"x\":\"{}\"}}", "a".repeat(9000))).unwrap();
        let huge = repo.join("huge.json");
        {
            let f = std::fs::File::create(&huge).unwrap();
            f.set_len(REREAD_MAX_BYTES + 4096).unwrap();
        }
        let sid_v = format!("s-dump-variants-{uniq}");
        for cmd in [
            "python3 -c \"import yaml; print(yaml.safe_load(open('big.yaml')))\" big.yaml",
            "python3 -c \"import tomllib; print(tomllib.load(open('big.toml','rb')))\" big.toml",
            "node -e \"console.log(require('./minified.json'))\" minified.json",
            "jq '.x' huge.json",
        ] {
            let ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Execute",
                "tool_input": {"command": cmd},
                "cwd": repo,
                "session_id": sid_v,
            })
            .to_string()
            .into_bytes();
            let first = run_hook("droid", &ev);
            assert_eq!("deny", first["hookSpecificOutput"]["permissionDecision"], "cmd={cmd}");
            assert_eq!(json!({}), run_hook("droid", &ev), "retry cmd={cmd}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if my_uid() != 0 {
                let ro_sid = format!("s-dump-ro-{uniq}");
                let parent = rt.join("prometheus");
                let ro_dir = parent.join(&ro_sid);
                fs::create_dir_all(&ro_dir).unwrap();
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o500)).unwrap();
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Execute",
                    "tool_input": {"command": "jq '.k0' big.json"},
                    "cwd": repo,
                    "session_id": ro_sid,
                });
                assert_eq!(json!({}), run_hook("droid", ev.to_string().as_bytes()));
                fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
    }

    #[test]
    fn secret_guard_blocks_input_filepath_and_absolute_path_aliases() {
        let _g = env_guard();
        let tmp = TempDir::new("secret_aliases");
        let _env = EnvOverride::set(&[
            ("CURSOR_PROJECT_DIR", None),
            ("DEVIN_PROJECT_DIR", None),
            ("GROK_SESSION_ID", None),
        ]);
        // Devin input.filePath alias (with and without session_id) must fail closed on secret paths.
        let devin_alias = json!({
            "hook_event_name": "PreToolUse",
            "toolName": "read",
            "input": {"filePath": ".env"},
            "cwd": tmp.0,
            "session_id": "s-devin-sec",
        });
        assert_eq!(
            "ask",
            run_hook("devin", devin_alias.to_string().as_bytes())["hookSpecificOutput"]["permissionDecision"]
        );
        let devin_no_sid = json!({
            "hook_event_name": "PreToolUse",
            "toolName": "read",
            "input": {"filePath": ".env"},
            "cwd": tmp.0,
        });
        assert_eq!(
            "ask",
            run_hook("devin", devin_no_sid.to_string().as_bytes())["hookSpecificOutput"]["permissionDecision"]
        );
        // AbsolutePath secret key must fail closed across all five hosts (with and without session_id).
        for host in ["claude", "droid", "devin", "muse"] {
            for with_sid in [true, false] {
                let mut ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "tool_input": {"AbsolutePath": ".env"},
                    "cwd": tmp.0,
                });
                if with_sid {
                    ev["session_id"] = json!("s-abs-sec");
                }
                assert_eq!(
                    "ask",
                    run_hook(host, ev.to_string().as_bytes())["hookSpecificOutput"]["permissionDecision"],
                    "host={host} with_sid={with_sid}"
                );
            }
        }
        for with_sid in [true, false] {
            let mut ev = json!({
                "hook_event_name": "preToolUse",
                "tool_name": "Read",
                "tool_input": {"AbsolutePath": ".env"},
                "workspace_roots": [tmp.0],
            });
            if with_sid {
                ev["conversation_id"] = json!("s-abs-cursor");
            }
            assert_eq!(
                "deny",
                run_hook("cursor", ev.to_string().as_bytes())["permission"],
                "cursor with_sid={with_sid}"
            );
        }
    }

    #[test]
    fn read_bytes_estimate_matches_range_shapes() {
        let p = |items: Vec<(&str, Value)>| -> Vec<(String, Value)> {
            items
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect()
        };
        assert_eq!(read_bytes_estimate(&[], 1000, 250), 1000);
        assert_eq!(
            read_bytes_estimate(&p(vec![("offset", json!(1))]), 1000, 250),
            1000
        );
        assert_eq!(
            read_bytes_estimate(
                &p(vec![("offset", json!(200)), ("limit", json!(1))]),
                2000,
                200
            ),
            10
        );
        assert_eq!(
            read_bytes_estimate(
                &p(vec![("offset", json!(0)), ("limit", json!(50))]),
                2500,
                250
            ),
            500
        );
        assert_eq!(
            read_bytes_estimate(
                &p(vec![("endline", json!(60)), ("startline", json!(11))]),
                2500,
                250
            ),
            500
        );
        assert_eq!(
            read_bytes_estimate(
                &p(vec![("end_line", json!(10)), ("start_line", json!(1))]),
                2000,
                200
            ),
            100
        );
        assert_eq!(
            read_bytes_estimate(&p(vec![("start_line", json!(3))]), 1000, 250),
            0
        );
        assert_eq!(
            read_bytes_estimate(&p(vec![("offset", json!("5"))]), 1000, 250),
            0
        );
        assert_eq!(
            read_bytes_estimate(
                &p(vec![("offset", json!(1)), ("offset", json!(2))]),
                1000,
                250
            ),
            0
        );
        assert_eq!(
            read_bytes_estimate(&p(vec![("limit", json!(5))]), 100, 0),
            0
        );
    }
}
