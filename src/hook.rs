//! Native `PreToolUse` safety, read-budget, and command-rewrite guards (ADR-0010, ADR-0012).
//!
//! Answers `prometheus-kit hook <claude|cursor|devin|droid|muse>`:
//! - Secret-path guard (`ask` on Claude/Droid/Devin/Muse, `deny` on Cursor).
//! - Large whole-file read advisory (>= 200 lines) and non-blocking unchanged reread warning.
//! - Deterministic shell auto-rewrite via `updatedInput` on Claude/Droid/Muse (coexisting with RTK).
//!
//! Every other event, tool, and edit passes with `{}` (or `{"continue": true}` for
//! Cursor's `beforeSubmitPrompt`), and direct checks never trigger `permissionDecision`.

use crate::store::{ensure_private_dir, sha256_hex};
use serde_json::{json, Map, Value};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const REREAD_MESSAGE: &str =
    "Unchanged whole-file reread: use the previous read or request a focused range (`prometheus-kit slice`).";
pub const LARGE_READ_LINES: usize = 200;
const REREAD_MAX_BYTES: u64 = 16 * 1024 * 1024;
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
// Sorted union of SECRET_BASENAMES and ".env" for deterministic glob prefix matching.
const SECRET_GLOB_BASENAMES: [&str; 15] = [
    ".env",
    ".htpasswd",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
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
    for name in SECRET_GLOB_BASENAMES {
        if name.starts_with(&base) {
            return format!(
                "secret path '{name}' is blocked; name '{name}' in your prompt to allow it this turn"
            );
        }
    }
    String::new()
}

pub(crate) fn command_token_denied(token: &str) -> String {
    for candidate in token.split('=') {
        let reason = secret_denied(Some(&Value::String(candidate.to_string())));
        if !reason.is_empty() {
            return reason;
        }
        let reason = glob_secret_denied(candidate);
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

fn is_unquoted_shell_sep(c: char) -> bool {
    c.is_whitespace() || matches!(c, '|' | ';' | '&' | '<' | '>' | '(' | ')' | '{' | '}' | '`')
}

fn decode_ansi_c_escape(chars: &[char], i: &mut usize, out: &mut String) {
    if *i >= chars.len() {
        return;
    }
    let esc = chars[*i];
    *i += 1;
    match esc {
        'a' => out.push('\x07'),
        'b' => out.push('\x08'),
        'e' | 'E' => out.push('\x1b'),
        'f' => out.push('\x0c'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'v' => out.push('\x0b'),
        '\\' | '\'' | '"' | '?' => out.push(esc),
        'x' => {
            let start = *i;
            let mut count = 0usize;
            while *i < chars.len() && count < 2 && chars[*i].is_ascii_hexdigit() {
                *i += 1;
                count += 1;
            }
            if count > 0 {
                let hex: String = chars[start..*i].iter().collect();
                if let Ok(val) = u32::from_str_radix(&hex, 16) {
                    if let Some(ch) = char::from_u32(val) {
                        out.push(ch);
                        return;
                    }
                }
            }
            out.push('x');
        }
        'u' | 'U' => {
            let max_digits = if esc == 'u' { 4 } else { 8 };
            let start = *i;
            let mut count = 0usize;
            while *i < chars.len() && count < max_digits && chars[*i].is_ascii_hexdigit() {
                *i += 1;
                count += 1;
            }
            if count > 0 {
                let hex: String = chars[start..*i].iter().collect();
                if let Ok(val) = u32::from_str_radix(&hex, 16) {
                    if let Some(ch) = char::from_u32(val) {
                        out.push(ch);
                        return;
                    }
                }
            }
            out.push(esc);
        }
        '0'..='7' => {
            let start = *i - 1;
            let mut count = 1usize;
            while *i < chars.len() && count < 3 && matches!(chars[*i], '0'..='7') {
                *i += 1;
                count += 1;
            }
            let oct: String = chars[start..*i].iter().collect();
            if let Ok(val) = u32::from_str_radix(&oct, 8) {
                if let Some(ch) = char::from_u32(val & 0xff) {
                    out.push(ch);
                }
            }
        }
        other => out.push(other),
    }
}

/// Produce POSIX-unescaped tokens (handling `\c` escapes, `'...'`, `"..."`, and `$'...'`).
fn posix_decoded_tokens(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut i = 0usize;

    while i < chars.len() {
        let ch = chars[i];
        if is_unquoted_shell_sep(ch) {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            i += 1;
            continue;
        }
        if ch == '$' && i + 1 < chars.len() && chars[i + 1] == '\'' {
            i += 2;
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' {
                    i += 1;
                    decode_ansi_c_escape(&chars, &mut i, &mut current);
                } else {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            if i < chars.len() {
                i += 1;
            }
            continue;
        }
        if ch == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                current.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                i += 1;
            }
            continue;
        }
        if ch == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    let next = chars[i + 1];
                    if next == '\n' {
                        i += 2;
                    } else if matches!(next, '"' | '\\' | '$' | '`') {
                        current.push(next);
                        i += 2;
                    } else {
                        current.push('\\');
                        current.push(next);
                        i += 2;
                    }
                } else {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            if i < chars.len() {
                i += 1;
            }
            continue;
        }
        if ch == '\\' {
            if i + 1 < chars.len() {
                if chars[i + 1] != '\n' {
                    current.push(chars[i + 1]);
                }
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        current.push(ch);
        i += 1;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn secret_command_denied(command: Option<&Value>) -> String {
    let Some(command) = command.and_then(Value::as_str) else {
        return String::new();
    };
    let stripped: String = command
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '`'))
        .collect();
    for token in split_command(&stripped) {
        let reason = command_token_denied(&token);
        if !reason.is_empty() {
            return reason;
        }
    }
    let chars: Vec<char> = command.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        if !matches!(chars[index], '"' | '\'' | '`') {
            index += 1;
            continue;
        }
        let Some(close) = (index + 1..chars.len()).find(|&at| matches!(chars[at], '"' | '\'' | '`'))
        else {
            break;
        };
        let fragment: String = chars[index + 1..close].iter().collect();
        for token in split_command(&fragment) {
            let reason = command_token_denied(&token);
            if !reason.is_empty() {
                return reason;
            }
        }
        index = if chars[index] == chars[close] {
            close + 1
        } else {
            close
        };
    }
    for token in posix_decoded_tokens(command) {
        let reason = command_token_denied(&token);
        if !reason.is_empty() {
            return reason;
        }
        for sub in split_command(&token) {
            let reason = command_token_denied(&sub);
            if !reason.is_empty() {
                return reason;
            }
        }
    }
    String::new()
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
    let empty = Map::new();
    let inp = get(event, "tool_input")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let reason = check_keys_for_secret(
        inp,
        &["file_path", "path", "paths", "pattern", "glob", "notebook_path"],
    );
    if !reason.is_empty() {
        return reason;
    }
    secret_command_denied(inp.get("command"))
}

fn cursor_secret_denied(event: &Value) -> String {
    const KEYS: [&str; 8] = [
        "relative_workspace_path",
        "relativeWorkspacePath",
        "path",
        "file_path",
        "target_file",
        "paths",
        "pattern",
        "glob",
    ];
    let empty = Map::new();
    let tool_input = get(event, "tool_input")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let reason = check_keys_for_secret(tool_input, &KEYS);
    if !reason.is_empty() {
        return reason;
    }
    if let Some(obj) = event.as_object() {
        let reason = check_keys_for_secret(obj, &KEYS);
        if !reason.is_empty() {
            return reason;
        }
    }
    let command = tool_input
        .get("command")
        .filter(|v| v.is_string())
        .or_else(|| get(event, "command").filter(|v| v.is_string()));
    secret_command_denied(command)
}

const FILE_READ_KEYS: [&str; 9] = [
    "file_path",
    "path",
    "paths",
    "pattern",
    "glob",
    "filePath",
    "target_file",
    "notebook_path",
    "target",
];

fn command_has_secret(command: &str) -> bool {
    if !secret_command_denied(Some(&Value::String(command.to_string()))).is_empty() {
        return true;
    }
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
            let items: Vec<&Value> = match source.get(key) {
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
// Unchanged whole-file reread warning: mirrors runtime/read_warning.py.
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

fn large_read_advisory(path: &Path, lines: usize) -> String {
    if lines < LARGE_READ_LINES
        || std::env::var_os("PROMETHEUS_KIT_NO_READ_HINT").as_deref() == Some(OsStr::new("1"))
    {
        return String::new();
    }
    if crate::outline::Lang::from_path(path).is_some() {
        format!(
            "Large whole-file read ({lines} lines): prefer `~/.agents/prometheus/prometheus-kit outline <path>` then `slice <path>::<Symbol>` or `<path>:<start>-<end>` to stay within token budget."
        )
    } else {
        format!(
            "Large whole-file read ({lines} lines): prefer `~/.agents/prometheus/prometheus-kit slice <path>:<start>-<end>` (or `compact <log>`) instead of dumping whole large files."
        )
    }
}

enum StoredHash {
    Absent,
    Malformed,
    Present(String),
}

fn read_reread_state(path: &Path) -> StoredHash {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return StoredHash::Malformed,
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return StoredHash::Absent,
        Err(_) => return StoredHash::Malformed,
    }
    let mut file = match open_nofollow_nonblock(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return StoredHash::Absent,
        Err(_) => return StoredHash::Malformed,
    };
    let info = match file.metadata() {
        Ok(info) => info,
        Err(_) => return StoredHash::Malformed,
    };
    if !info.is_file() || info.len() > 128 {
        return StoredHash::Malformed;
    }
    let mut buf = [0u8; 129];
    let mut total = 0usize;
    loop {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > 128 {
                    return StoredHash::Malformed;
                }
            }
            Err(_) => return StoredHash::Malformed,
        }
    }
    let Ok(raw) = std::str::from_utf8(&buf[..total]) else {
        return StoredHash::Malformed;
    };
    let text = raw.trim().to_string();
    let valid = text.len() == 64
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if valid {
        StoredHash::Present(text)
    } else {
        StoredHash::Malformed
    }
}

fn write_reread_state(path: &Path, digest: &str) {
    use std::io::Write;
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return;
    }
    let Some(parent) = path.parent() else {
        return;
    };
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".reread-{}-{seq}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let Ok(mut file) = options.open(&tmp) else {
        return;
    };
    let write_ok = file.write_all(format!("{digest}\n").as_bytes()).is_ok();
    drop(file);
    if !write_ok || std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

fn read_path(event: &Value, host: &str) -> Option<String> {
    if host == "omp" || casefold(tool_name(event)) != "read" {
        return None;
    }
    let empty = Map::new();
    let inp = get(event, "tool_input")
        .and_then(Value::as_object)
        .or_else(|| get(event, "input").and_then(Value::as_object))
        .unwrap_or(&empty);
    for key in inp.keys() {
        let lower = casefold(key);
        if PARTIAL_KEYS.iter().any(|partial| *partial == lower) {
            return None;
        }
    }
    for key in ["file_path", "filePath", "path"] {
        if let Some(Value::String(text)) = inp.get(key) {
            if !text.trim().is_empty() {
                return Some(text.clone());
            }
        }
    }
    None
}

pub fn whole_file_warning(host: &str, event: &Value, session_id: &str, root: Option<&Path>) -> String {
    let Some(raw) = read_path(event, host) else {
        return String::new();
    };
    if !valid_session_id_str(session_id) {
        return String::new();
    }
    let Some(folder) = session_dir(session_id) else {
        return String::new();
    };
    if !secret_path_denied(&raw).is_empty() {
        return String::new();
    }
    let base: PathBuf = match root {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => match get(event, "cwd").and_then(Value::as_str) {
            Some(c) if !c.is_empty() => PathBuf::from(c),
            _ => return String::new(),
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
        return String::new();
    }
    let Ok(info) = std::fs::metadata(&target_path) else {
        return String::new();
    };
    if !info.is_file() || info.len() > REREAD_MAX_BYTES {
        return String::new();
    }
    let Some((digest, line_count)) = hash_file(&target_path) else {
        return String::new();
    };
    let canonical_str = canonical.to_string_lossy();
    let mut key_bytes = Vec::with_capacity(canonical_str.len() + 1 + target_str.len());
    key_bytes.extend_from_slice(canonical_str.as_bytes());
    key_bytes.push(0);
    key_bytes.extend_from_slice(target_str.as_bytes());
    let key = sha256_hex(&key_bytes);
    let state = folder.join(format!("reread-{key}"));
    match read_reread_state(&state) {
        StoredHash::Malformed => String::new(),
        StoredHash::Present(stored) if stored == digest => REREAD_MESSAGE.to_string(),
        _ => {
            write_reread_state(&state, &digest);
            large_read_advisory(&target_path, line_count)
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

fn cursor_deny_reply(reason: &str) -> Value {
    let text = format!("SureForge: {reason}.");
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
    let warning = whole_file_warning(host, event, session_id, Some(&root));
    warn_reply(&warning)
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
    let warning = whole_file_warning("droid", event, session_id, Some(&root));
    warn_reply(&warning)
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
        let warning = whole_file_warning("devin", event, session_id, candidate.as_deref());
        return warn_reply(&warning);
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
    let warning = whole_file_warning("devin", event, session_id, Some(&root));
    warn_reply(&warning)
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
    let warning = whole_file_warning("cursor", event, session_id, roots.first().map(PathBuf::as_path));
    if warning.is_empty() {
        json!({})
    } else {
        json!({"agent_message": warning})
    }
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
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Serialize tests that inspect or mutate process environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
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
    fn secret_command_and_glob_detection() {
        assert!(!secret_command_denied(Some(&json!("cat .env"))).is_empty());
        assert!(!secret_command_denied(Some(&json!("cat .en*"))).is_empty());
        assert!(!secret_command_denied(Some(&json!("git show HEAD:.env"))).is_empty());
        assert!(!secret_command_denied(Some(&json!("python3 -c \"open('.env')\""))).is_empty());
        assert!(!secret_command_denied(Some(&json!("echo \"a'b/.env'c\""))).is_empty());
        assert!(!secret_command_denied(Some(&json!("FOO=.ssh/id_rsa cmd"))).is_empty());
        assert!(!secret_command_denied(Some(&json!(r"cat dir\.env"))).is_empty());
        for escaped in [
            r"sed -n '1,5p' .e\nv",
            r"rg key .e\nv",
            r"git diff -- .e\nv",
            r"git -C .s\sh status",
            r"dotnet test --settings .e\nv",
            r"sed -n '1,5p' .s\sh/id_\rsa",
            r"dotnet test --settings $'\x2eenv'",
            r"cat $'\056env'",
            r"git show HEAD:.e\nv",
        ] {
            assert!(
                !secret_command_denied(Some(&json!(escaped))).is_empty(),
                "escaped={escaped}"
            );
        }
        assert!(secret_command_denied(Some(&json!("cat src/*"))).is_empty());
        assert!(secret_command_denied(Some(&json!("dotnet test"))).is_empty());
        assert!(secret_command_denied(Some(&json!("cargo test"))).is_empty());
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
        for escaped in [
            r"sed -n '1,5p' .e\nv",
            r"rg key .e\nv",
            r"git diff -- .e\nv",
            r"git -C .s\sh status",
            r"dotnet test --settings .e\nv",
            r"sed -n '1,5p' .s\sh/id_\rsa",
            r"dotnet test --settings $'\x2eenv'",
            r"cat $'\056env'",
            r"git show HEAD:.e\nv",
            r"cat dir\.env",
        ] {
            for host in ["claude", "droid"] {
                let ev = json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Execute",
                    "tool_input": {"command": escaped},
                    "cwd": tmp.0,
                    "session_id": "s1",
                });
                let reply = run_hook(host, ev.to_string().as_bytes());
                assert_eq!(
                    "ask",
                    reply["hookSpecificOutput"]["permissionDecision"],
                    "{host} {escaped}"
                );
                assert!(
                    reply["hookSpecificOutput"].get("updatedInput").is_none(),
                    "{host} {escaped}"
                );
            }
            let cev = json!({
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": escaped},
                "workspace_roots": [tmp.0],
                "conversation_id": "s1",
            });
            assert_eq!(
                "deny",
                run_hook("cursor", cev.to_string().as_bytes())["permission"],
                "cursor {escaped}"
            );
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

        // Partial read does not warn and does not reset stored hash.
        let partial = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "a.py", "offset": 1, "limit": 5},
            "cwd": repo,
            "session_id": "s-reread",
        });
        assert_eq!(json!({}), run_hook("claude", partial.to_string().as_bytes()));
        let third = run_hook("claude", ev.to_string().as_bytes());
        assert_eq!(REREAD_MESSAGE, third["hookSpecificOutput"]["additionalContext"]);

        // Edited file updates hash without warning, then next reread warns.
        fs::write(&file, "x = 2\n").unwrap();
        assert_eq!(json!({}), run_hook("claude", ev.to_string().as_bytes()));
        let fourth = run_hook("claude", ev.to_string().as_bytes());
        assert_eq!(REREAD_MESSAGE, fourth["hookSpecificOutput"]["additionalContext"]);

        // Cursor emits agent_message without permission key.
        let cev = json!({
            "hook_event_name": "preToolUse",
            "tool_name": "Read",
            "tool_input": {"path": "a.py"},
            "workspace_roots": [repo],
            "conversation_id": "s-cursor",
        });
        assert_eq!(json!({}), run_hook("cursor", cev.to_string().as_bytes()));
        let csecond = run_hook("cursor", cev.to_string().as_bytes());
        assert_eq!(REREAD_MESSAGE, csecond["agent_message"]);
        assert!(csecond.get("permission").is_none());
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
            "",
            whole_file_warning(
                "claude",
                &json!({"tool_name": "Read", "tool_input": {"file_path": link}}),
                "s-sec",
                Some(&repo),
            )
        );
        assert_eq!(
            "",
            whole_file_warning(
                "claude",
                &json!({"tool_name": "Read", "tool_input": {"file_path": link}}),
                "s-sec",
                Some(&repo),
            )
        );

        // Insecure 0o755 session dir is refused and never chmod'd.
        let bad_sess = rt.join("prometheus").join("s-bad");
        fs::create_dir_all(&bad_sess).unwrap();
        fs::set_permissions(&bad_sess, fs::Permissions::from_mode(0o755)).unwrap();
        let file = repo.join("a.py");
        fs::write(&file, "x = 1\n").unwrap();
        assert_eq!(
            "",
            whole_file_warning(
                "claude",
                &json!({"tool_name": "Read", "tool_input": {"file_path": file}}),
                "s-bad",
                Some(&repo),
            )
        );
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
        let first = run_hook("droid", ev_big.to_string().as_bytes());
        let first_ctx = first["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("large read advisory");
        assert!(first_ctx.contains("220 lines"), "{first_ctx}");
        assert!(first_ctx.contains("outline"), "{first_ctx}");
        assert!(first_ctx.contains("slice"), "{first_ctx}");
        assert!(first["hookSpecificOutput"].get("permissionDecision").is_none());

        // Second unchanged whole-file read emits REREAD_MESSAGE.
        let second = run_hook("droid", ev_big.to_string().as_bytes());
        assert_eq!(REREAD_MESSAGE, second["hookSpecificOutput"]["additionalContext"]);

        // Partial read on large file passes silently.
        let partial = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "big.rs", "offset": 1, "limit": 50},
            "cwd": repo,
            "session_id": "s-large",
        });
        assert_eq!(json!({}), run_hook("droid", partial.to_string().as_bytes()));

        // Large non-code log file suggests slice / compact.
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
        let log_ctx = log_reply["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("log advisory");
        assert!(log_ctx.contains("slice"), "{log_ctx}");
        assert!(log_ctx.contains("compact"), "{log_ctx}");

        // Large secret .env file triggers secret ask, never advisory.
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

        // PROMETHEUS_KIT_NO_READ_HINT=1 suppresses advisory on first read, keeps reread warning.
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
            assert_eq!(REREAD_MESSAGE, second_hint["hookSpecificOutput"]["additionalContext"]);
        }
    }
}
