//! Deterministic `PreToolUse` command auto-rewrite rules (coexists with RTK).
//!
//! Rewrites eligible read/search/diff/build/test shell commands into
//! `prometheus-kit` invocations using the host `updatedInput` envelope, without
//! changing `permissionDecision`.

use crate::outline::Lang;
use serde_json::{json, Map, Value};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_HOOK_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShellToken {
    value: String,
    has_expansion: bool,
}

/// Returns `true` when `PROMETHEUS_KIT_NO_REWRITE=1` is set.
fn rewrite_disabled() -> bool {
    std::env::var_os("PROMETHEUS_KIT_NO_REWRITE").as_deref() == Some(OsStr::new("1"))
}

fn read_config_bounded(path: &Path) -> Option<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options.open(path).ok()?;
    let info = file.metadata().ok()?;
    if !info.is_file() || info.len() > MAX_HOOK_CONFIG_BYTES {
        return None;
    }
    let cap = usize::try_from(info.len().min(MAX_HOOK_CONFIG_BYTES)).ok()?;
    let mut contents = Vec::with_capacity(cap);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 {
            return Some(contents);
        }
        if contents.len() + n > MAX_HOOK_CONFIG_BYTES as usize {
            return None;
        }
        contents.extend_from_slice(&chunk[..n]);
    }
}

/// Returns `true` when RTK's hook is active for `host` (env override or hook config).
pub fn rtk_hook_active(host: &str) -> bool {
    if let Ok(val) = std::env::var("PROMETHEUS_KIT_RTK_COEXIST") {
        match val.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => return true,
            "0" | "false" | "no" => return false,
            _ => {}
        }
    }
    if host == "grok" {
        return grok_dir_has_rtk_hook();
    }
    let Some(config_path) = host_hooks_config_path(host) else {
        return false;
    };
    json_file_has_rtk_hook(&config_path)
}

fn json_file_has_rtk_hook(config_path: &Path) -> bool {
    let Some(bytes) = read_config_bounded(config_path) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    json_has_rtk_hook(&parsed)
}

fn abs_env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn abs_home_dir() -> Option<PathBuf> {
    crate::droid_mode::default_home()
        .ok()
        .filter(|p| p.is_absolute())
}

fn grok_dir_has_rtk_hook_in(home: Option<&Path>) -> bool {
    let Some(home) = home.filter(|p| p.is_absolute()) else {
        return false;
    };
    let dir = home.join(".grok").join("hooks");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries.take(64).flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") && json_file_has_rtk_hook(&path)
        {
            return true;
        }
    }
    false
}

fn grok_dir_has_rtk_hook() -> bool {
    grok_dir_has_rtk_hook_in(abs_home_dir().as_deref())
}

fn host_hooks_config_path_in(
    host: &str,
    home: Option<&Path>,
    xdg: Option<&Path>,
    agy: Option<&Path>,
) -> Option<PathBuf> {
    let abs_home = home.filter(|p| p.is_absolute());
    let abs_xdg = xdg.filter(|p| p.is_absolute());
    let abs_agy = agy.filter(|p| p.is_absolute());
    match host {
        "droid" => Some(abs_home?.join(".factory").join("hooks.json")),
        "claude" => Some(abs_home?.join(".claude").join("settings.json")),
        "cursor" => Some(abs_home?.join(".cursor").join("hooks.json")),
        "devin" => {
            let base = match abs_xdg {
                Some(dir) => dir.to_path_buf(),
                None => abs_home?.join(".config"),
            };
            Some(base.join("devin").join("config.json"))
        }
        "antigravity" => {
            let base = match abs_agy {
                Some(dir) => dir.to_path_buf(),
                None => abs_home?.join(".gemini").join("config"),
            };
            Some(base.join("hooks.json"))
        }
        "muse" => {
            let base = match abs_xdg {
                Some(dir) => dir.to_path_buf(),
                None => abs_home?.join(".config"),
            };
            Some(base.join("muse").join("settings.json"))
        }
        _ => None,
    }
}

fn host_hooks_config_path(host: &str) -> Option<PathBuf> {
    let xdg = abs_env_dir("XDG_CONFIG_HOME");
    let agy = abs_env_dir("AGY_CONFIG_DIR");
    let home = abs_home_dir();
    host_hooks_config_path_in(host, home.as_deref(), xdg.as_deref(), agy.as_deref())
}

fn json_has_rtk_hook(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(cmd)) = map.get("command") {
                if command_invokes_rtk_hook(cmd) {
                    return true;
                }
            }
            map.values().any(json_has_rtk_hook)
        }
        Value::Array(items) => items.iter().any(json_has_rtk_hook),
        _ => false,
    }
}

fn command_invokes_rtk_hook(cmd: &str) -> bool {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    words.windows(2).any(|pair| {
        let bin = pair[0].trim_matches(&['\'', '"', ';'][..]);
        let name = Path::new(bin)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(bin)
            .to_ascii_lowercase();
        (name == "rtk" || name == "rtk.exe") && pair[1].trim_matches(';').eq_ignore_ascii_case("hook")
    })
}

pub(crate) fn is_shell_tool(tool_name: &str) -> bool {
    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "execute"
            | "bash"
            | "shell"
            | "exec"
            | "run_command"
            | "run_shell_command"
            | "run_terminal_command"
            | "terminal"
    )
}

fn kit_bin_quoted() -> Option<String> {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("prometheus-kit"));
    try_shell_quote(&exe.to_string_lossy())
}

pub fn quote_posix(arg: &str) -> Option<String> {
    if arg.contains(['\0', '\n', '\r']) {
        return None;
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Some(out)
}

pub fn quote_windows(arg: &str) -> Option<String> {
    if arg.is_empty()
        || arg.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '"' | '\''
                        | '`'
                        | '$'
                        | '%'
                        | '&'
                        | '|'
                        | ';'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '^'
                        | '!'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | ','
                )
        })
    {
        return None;
    }
    if arg.chars().any(char::is_whitespace) {
        if arg.ends_with('\\') {
            return None;
        }
        Some(format!("\"{arg}\""))
    } else {
        Some(arg.to_owned())
    }
}

/// Quote an argument safely for the host shell, returning `None` if unsafe.
pub fn try_shell_quote(arg: &str) -> Option<String> {
    #[cfg(windows)]
    {
        quote_windows(arg)
    }
    #[cfg(not(windows))]
    {
        quote_posix(arg)
    }
}

/// True when the truncated-runner prefix holds shell syntax the compact
/// rewrite cannot faithfully re-emit: an unquoted comment-start `#`, an
/// unquoted escape gluing words across a boundary (`\ `, `\<tab>`), unquoted
/// subshell parentheses, or the `$"…"` locale form. Mid-word `#`, quoted
/// occurrences, and other literal text stay allowed.
fn unsupported_truncated_syntax(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < b.len() {
        let c = b[i];
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'\\' => {
                if i + 1 < b.len() && matches!(b[i + 1], b' ' | b'\t') {
                    return true;
                }
                i += 1;
            }
            b'#' => {
                let word_start = i == 0 || matches!(b[i - 1], b' ' | b'\t' | b'(' | b')');
                if word_start {
                    return true;
                }
            }
            b'(' | b')' => return true,
            b'$' if b.get(i + 1) == Some(&b'"') => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// The tail after a terminal `|` must be exactly `head` or `tail` followed by
/// nothing, `-N`, or `-n N` (N ascii decimal digits) — space/tab separators
/// only. Anything else (other filters, flags, redirects, extra words,
/// attached `-nN`, signed counts) is not a plain truncation.
fn valid_trunc_tail(tail: &str) -> bool {
    let t = tail.trim_matches([' ', '\t']);
    for verb in ["head", "tail"] {
        let Some(rest) = t.strip_prefix(verb) else {
            continue;
        };
        if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
            return false;
        }
        let rest = rest.trim_matches([' ', '\t']);
        if rest.is_empty() {
            return true;
        }
        if let Some(digits) = rest.strip_prefix('-') {
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                return true;
            }
        }
        if let Some(after_n) = rest.strip_prefix("-n") {
            if !after_n.starts_with([' ', '\t']) {
                return false;
            }
            let digits = after_n.trim_start_matches([' ', '\t']);
            return !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
        }
        return false;
    }
    false
}

/// Terminal `| head`/`| tail [-n] N` truncation pipe: return the verbatim
/// runner prefix (cd prefix included, quotes and flags untouched) when the
/// tail is a plain bounded truncation. Anything ambiguous — nested or
/// additional pipes, comments, redirects, non-shell whitespace, unbalanced
/// quoting — returns None and the command passes through untouched.
fn truncated_runner(command: &str) -> Option<&str> {
    // Only space/tab may separate shell words; CR/LF/NUL and other Unicode
    // whitespace never appear in a safe one-line command.
    if command.contains('\0')
        || command
            .chars()
            .any(|c| c.is_whitespace() && c != ' ' && c != '\t')
    {
        return None;
    }
    let (prefix, tail) = command.rsplit_once('|')?;
    if !valid_trunc_tail(tail) {
        return None;
    }
    let mut runner = prefix.trim_end_matches([' ', '\t']);
    // One pass refuses comment starts, boundary-glued escapes, subshell
    // parens, and the `$"…"` locale form before the redirect is stripped —
    // a `#` at a word boundary would have commented out the pipe itself.
    if unsupported_truncated_syntax(runner) {
        return None;
    }
    // Optional literal ` 2>&1` (stderr folded into stdout, which compact
    // captures anyway): strip only at a word boundary.
    if let Some(head) = runner.strip_suffix("2>&1") {
        if head.ends_with([' ', '\t']) {
            runner = head.trim_end_matches([' ', '\t']);
        }
    }
    // A trailing escape would bind to whatever follows; quote balance and
    // metacharacters are enforced by the strict scan/split in the caller.
    if runner.ends_with('\\') {
        return None;
    }
    Some(runner)
}

/// Scan the command for dangerous shell metacharacters and extract at most one
/// unquoted `&&` separator (for a leading `cd <dir> && <rest>` prefix).
fn scan_and_split_cd_prefix(command: &str) -> Option<(Option<&str>, &str)> {
    if command.contains('\n')
        || command.contains('\r')
        || command.contains('\0')
        || command.contains('`')
        || command.contains("$(")
        || command.contains("$'")
    {
        return None;
    }

    let bytes = command.as_bytes();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut amp_pos: Option<usize> = None;

    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if b == b'\\' {
                if i + 1 >= bytes.len() {
                    return None;
                }
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\\' => {
                if i + 1 >= bytes.len() {
                    return None;
                }
                i += 2;
            }
            b'\'' => {
                in_single = true;
                i += 1;
            }
            b'"' => {
                in_double = true;
                i += 1;
            }
            b'$' if bytes.get(i + 1) == Some(&b'"') => return None,
            b'|' | b';' | b'>' | b'<' => return None,
            b'&' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    if i + 2 < bytes.len() && bytes[i + 2] == b'&' {
                        return None;
                    }
                    if amp_pos.is_some() {
                        return None;
                    }
                    amp_pos = Some(i);
                    i += 2;
                } else {
                    return None;
                }
            }
            _ => i += 1,
        }
    }

    if in_single || in_double {
        return None;
    }

    if let Some(at) = amp_pos {
        let lhs = command[..at].trim();
        let rhs = command[at + 2..].trim();
        if lhs.is_empty() || rhs.is_empty() {
            return None;
        }
        let lhs_tokens = shell_split(lhs)?;
        if lhs_tokens.len() != 2
            || lhs_tokens[0].value != "cd"
            || lhs_tokens[1].value.is_empty()
            || lhs_tokens[1].value == "-"
            || !crate::hook::command_token_denied(&lhs_tokens[1].value).is_empty()
        {
            return None;
        }
        Some((Some(lhs), rhs))
    } else {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some((None, trimmed))
        }
    }
}

fn is_param_start(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '_' | '{' | '*' | '@' | '#' | '?' | '$' | '!' | '-' | '\''
        )
}

fn shell_split(text: &str) -> Option<Vec<ShellToken>> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut value = String::new();
        let mut has_expansion = false;
        let mut started_unquoted_tilde = chars[i] == '~';

        while i < chars.len() && !chars[i].is_whitespace() {
            match chars[i] {
                '\'' => {
                    started_unquoted_tilde = false;
                    i += 1;
                    while i < chars.len() && chars[i] != '\'' {
                        value.push(chars[i]);
                        i += 1;
                    }
                    if i >= chars.len() {
                        return None;
                    }
                    i += 1;
                }
                '"' => {
                    started_unquoted_tilde = false;
                    i += 1;
                    while i < chars.len() && chars[i] != '"' {
                        if chars[i] == '\\' {
                            i += 1;
                            if i >= chars.len() {
                                return None;
                            }
                            if matches!(chars[i], '"' | '\\' | '$' | '`') {
                                value.push(chars[i]);
                            } else {
                                value.push('\\');
                                value.push(chars[i]);
                            }
                            i += 1;
                        } else {
                            if chars[i] == '$'
                                && i + 1 < chars.len()
                                && is_param_start(chars[i + 1])
                            {
                                has_expansion = true;
                            }
                            value.push(chars[i]);
                            i += 1;
                        }
                    }
                    if i >= chars.len() {
                        return None;
                    }
                    i += 1;
                }
                '\\' => {
                    i += 1;
                    if i >= chars.len() {
                        return None;
                    }
                    value.push(chars[i]);
                    i += 1;
                }
                ch => {
                    if matches!(ch, '*' | '?' | '[' | '{' | '}') {
                        has_expansion = true;
                    }
                    if ch == '$' && i + 1 < chars.len() && is_param_start(chars[i + 1]) {
                        has_expansion = true;
                    }
                    if value.is_empty() && ch == '~' && started_unquoted_tilde {
                        has_expansion = true;
                    }
                    value.push(ch);
                    i += 1;
                }
            }
        }
        tokens.push(ShellToken {
            value,
            has_expansion,
        });
    }

    Some(tokens)
}

fn basename_lower(cmd0: &str) -> String {
    Path::new(cmd0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd0)
        .to_ascii_lowercase()
}

fn is_excluded_wrapper(cmd0: &str) -> bool {
    if cmd0.contains('=') {
        return true;
    }
    matches!(
        basename_lower(cmd0).as_str(),
        "sudo"
            | "doas"
            | "env"
            | "rtk"
            | "rtk.exe"
            | "time"
            | "watch"
            | "nohup"
            | "timeout"
            | "prometheus-kit"
            | "prometheus-kit.exe"
            | "prometheus-check"
            | "prometheus-check.exe"
    )
}

fn parse_sed_range(expr: &str) -> Option<(usize, usize)> {
    let body = expr.strip_suffix('p')?;
    let (start_s, end_s) = body.split_once(',')?;
    if start_s.is_empty()
        || end_s.is_empty()
        || !start_s.bytes().all(|b| b.is_ascii_digit())
        || !end_s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let start: usize = start_s.parse().ok()?;
    let end: usize = end_s.parse().ok()?;
    if start >= 1 && end >= start {
        Some((start, end))
    } else {
        None
    }
}

fn is_safe_sed_path(token: &ShellToken) -> bool {
    let p = token.value.as_str();
    !token.has_expansion
        && !p.is_empty()
        && p != "-"
        && !p.starts_with('-')
        && !p
            .chars()
            .any(|c| matches!(c, '$' | '*' | '?' | '[' | ']' | '~' | '{' | '}'))
}

fn resolve_git_dir(cd_prefix: Option<&str>, git_c_dir: Option<&str>, event_cwd: Option<&Path>) -> Option<PathBuf> {
    if let Some(dir) = git_c_dir {
        let p = PathBuf::from(dir);
        if p.is_absolute() {
            return Some(p);
        }
        return event_cwd.map(|c| c.join(p));
    }
    if let Some(prefix) = cd_prefix {
        if let Some(tokens) = shell_split(prefix) {
            if tokens.len() == 2 && !tokens[1].has_expansion {
                let p = PathBuf::from(&tokens[1].value);
                if p.is_absolute() {
                    return Some(p);
                }
                return event_cwd.map(|c| c.join(p));
            }
        }
    }
    event_cwd.map(Path::to_path_buf)
}

fn rewrite_git(
    tokens: &[ShellToken],
    kit_bin: &str,
    cd_prefix: Option<&str>,
    event_cwd: Option<&Path>,
) -> Option<String> {
    rewrite_git_inner(tokens, kit_bin, cd_prefix, event_cwd, false)
}

/// With `rtk` active the kit defers every `git` form `rtk` compacts; the one
/// exception is `git show <rev>`, which the `rtk` history shows it leaves
/// raw (ADR-0013 D7, #75), so only that subcommand is rewritten here.
fn rewrite_git_show_only(
    tokens: &[ShellToken],
    kit_bin: &str,
    cd_prefix: Option<&str>,
    event_cwd: Option<&Path>,
) -> Option<String> {
    rewrite_git_inner(tokens, kit_bin, cd_prefix, event_cwd, true)
}

fn rewrite_git_inner(
    tokens: &[ShellToken],
    kit_bin: &str,
    cd_prefix: Option<&str>,
    event_cwd: Option<&Path>,
    show_only: bool,
) -> Option<String> {
    let mut idx = 1usize;
    let mut git_c_dir: Option<&ShellToken> = None;

    if idx < tokens.len() && tokens[idx].value == "-C" {
        let dir = tokens.get(idx + 1)?;
        if dir.value.is_empty() || dir.has_expansion {
            return None;
        }
        git_c_dir = Some(dir);
        idx += 2;
    }

    let subcmd = tokens.get(idx)?.value.as_str();
    if show_only && subcmd != "show" {
        return None;
    }
    idx += 1;

    let mut parts = vec![kit_bin.to_owned(), "diff".to_owned()];
    if let Some(dir) = git_c_dir {
        parts.push("--root".to_owned());
        parts.push(try_shell_quote(&dir.value)?);
    }

    match subcmd {
        "status" => {
            for tok in &tokens[idx..] {
                let arg = tok.value.as_str();
                let allowed = matches!(arg, "--short" | "--branch")
                    || (arg.starts_with('-')
                        && !arg.starts_with("--")
                        && arg.len() > 1
                        && arg[1..].chars().all(|c| matches!(c, 's' | 'b')));
                if !allowed {
                    return None;
                }
            }
            parts.push("--status".to_owned());
            Some(parts.join(" "))
        }
        "diff" => {
            let mut staged = false;
            let mut stat = false;
            let mut context: Option<usize> = None;
            let mut base_ref: Option<&ShellToken> = None;
            let mut paths: Vec<&ShellToken> = Vec::new();
            let mut positional_only = false;

            let mut j = idx;
            while j < tokens.len() {
                let tok = &tokens[j];
                let arg = tok.value.as_str();
                if positional_only {
                    if tok.has_expansion {
                        return None;
                    }
                    paths.push(tok);
                    j += 1;
                    continue;
                }
                match arg {
                    "--" => positional_only = true,
                    "--staged" | "--cached" => staged = true,
                    "--stat" => stat = true,
                    "--unified" => {
                        let next = tokens.get(j + 1)?;
                        let n: usize = next.value.parse().ok()?;
                        context = Some(n);
                        j += 1;
                    }
                    _ if arg.starts_with("--unified=") => {
                        let n: usize = arg["--unified=".len()..].parse().ok()?;
                        context = Some(n);
                    }
                    _ if arg.starts_with("-U") && arg.len() > 2 => {
                        let n: usize = arg[2..].parse().ok()?;
                        context = Some(n);
                    }
                    _ if arg.starts_with('-') => return None,
                    _ => {
                        if base_ref.is_some() || arg.is_empty() || arg.contains(':') || tok.has_expansion {
                            return None;
                        }
                        base_ref = Some(tok);
                    }
                }
                j += 1;
            }

            if let Some(candidate) = base_ref {
                let repo_dir = resolve_git_dir(
                    cd_prefix,
                    git_c_dir.map(|t| t.value.as_str()),
                    event_cwd,
                );
                let exists_as_path = paths.is_empty()
                    && !positional_only
                    && repo_dir.is_some_and(|d| d.join(&candidate.value).exists());
                if exists_as_path {
                    paths.push(candidate);
                    base_ref = None;
                } else if staged {
                    // `prometheus-kit diff` treats --staged and --base as mutually exclusive.
                    return None;
                }
            }

            if staged {
                parts.push("--staged".to_owned());
            }
            if stat {
                parts.push("--stat".to_owned());
            }
            if let Some(n) = context {
                parts.push("-C".to_owned());
                parts.push(n.to_string());
            }
            if let Some(base) = base_ref {
                parts.push("--base".to_owned());
                parts.push(try_shell_quote(&base.value)?);
            }
            if !paths.is_empty() {
                parts.push("--".to_owned());
                for p in paths {
                    parts.push(try_shell_quote(&p.value)?);
                }
            }
            Some(parts.join(" "))
        }
        "show" => {
            let mut stat = false;
            let mut rev: Option<&ShellToken> = None;
            for tok in &tokens[idx..] {
                let arg = tok.value.as_str();
                match arg {
                    "--stat" => stat = true,
                    _ if arg.starts_with('-') => return None,
                    _ => {
                        if rev.is_some() || arg.is_empty() || arg.contains(':') || tok.has_expansion {
                            return None;
                        }
                        rev = Some(tok);
                    }
                }
            }
            let rev = rev?;
            parts.push("--commit".to_owned());
            parts.push(try_shell_quote(&rev.value)?);
            if stat {
                parts.push("--stat".to_owned());
            }
            Some(parts.join(" "))
        }
        _ => None,
    }
}

fn rewrite_rg(tokens: &[ShellToken], kit_bin: &str) -> Option<String> {
    let mut ignore_case = false;
    let mut fixed_strings = false;
    let mut word_regexp = false;
    let mut files_only = false;
    let mut hidden = false;
    let mut no_ignore = false;
    let mut globs: Vec<String> = Vec::new();
    let mut lang_type: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut positional_only = false;

    let mut i = 1usize;
    while i < tokens.len() {
        let tok = &tokens[i];
        let arg = tok.value.as_str();
        if positional_only {
            if tok.has_expansion {
                return None;
            }
            positionals.push(tok.value.clone());
            i += 1;
            continue;
        }
        match arg {
            "--" => positional_only = true,
            "-i" | "--ignore-case" => ignore_case = true,
            "-F" | "--fixed-strings" => fixed_strings = true,
            "-w" | "--word-regexp" => word_regexp = true,
            "-l" | "--files-with-matches" => files_only = true,
            "--hidden" => hidden = true,
            "--no-ignore" => no_ignore = true,
            "-g" | "--glob" => {
                let val = tokens.get(i + 1)?;
                if val.value.is_empty() || val.has_expansion {
                    return None;
                }
                globs.push(val.value.clone());
                i += 1;
            }
            _ if arg.starts_with("--glob=") => {
                let v = &arg["--glob=".len()..];
                if v.is_empty() || tok.has_expansion {
                    return None;
                }
                globs.push(v.to_owned());
            }
            "-t" | "--type" => {
                if lang_type.is_some() {
                    return None;
                }
                let val = tokens.get(i + 1)?;
                if val.has_expansion || Lang::from_name(&val.value).is_none() {
                    return None;
                }
                lang_type = Some(val.value.clone());
                i += 1;
            }
            _ if arg.starts_with("--type=") => {
                if lang_type.is_some() {
                    return None;
                }
                let v = &arg["--type=".len()..];
                if tok.has_expansion || Lang::from_name(v).is_none() {
                    return None;
                }
                lang_type = Some(v.to_owned());
            }
            _ if arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.len() > 2
                && arg[1..].chars().all(|c| matches!(c, 'i' | 'F' | 'w' | 'l')) =>
            {
                for c in arg[1..].chars() {
                    match c {
                        'i' => ignore_case = true,
                        'F' => fixed_strings = true,
                        'w' => word_regexp = true,
                        'l' => files_only = true,
                        _ => {}
                    }
                }
            }
            _ if arg.starts_with('-') => return None,
            _ => {
                if tok.has_expansion {
                    return None;
                }
                positionals.push(tok.value.clone());
            }
        }
        i += 1;
    }

    if positionals.is_empty() {
        return None;
    }

    let mut parts = vec![kit_bin.to_owned(), "search".to_owned()];
    if ignore_case {
        parts.push("-i".to_owned());
    }
    if fixed_strings {
        parts.push("-F".to_owned());
    }
    if word_regexp {
        parts.push("-w".to_owned());
    }
    if files_only {
        parts.push("--files-only".to_owned());
    }
    if hidden {
        parts.push("--hidden".to_owned());
    }
    if no_ignore {
        parts.push("--no-ignore".to_owned());
    }
    for g in globs {
        parts.push("--glob".to_owned());
        parts.push(try_shell_quote(&g)?);
    }
    if let Some(t) = lang_type {
        parts.push("--type".to_owned());
        parts.push(try_shell_quote(&t)?);
    }
    parts.push("--symbols".to_owned());
    parts.push("--".to_owned());
    for pos in positionals {
        parts.push(try_shell_quote(&pos)?);
    }
    Some(parts.join(" "))
}

/// One safe file argument for the dump rewrites (`head`/`tail`/`cat`/`nl`):
/// the same path rules as the `sed -n` rewrite — one literal path, no
/// expansions, no stdin marker, no flag-shaped token.
fn dump_file_arg(token: &ShellToken) -> Option<&str> {
    if is_safe_sed_path(token) {
        Some(token.value.as_str())
    } else {
        None
    }
}

fn parse_dump_count(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: usize = value.parse().ok()?;
    if n >= 1 {
        Some(n)
    } else {
        None
    }
}

/// `head`/`tail`/`cat`/`nl` over one safe file → `slice` (#75). These are
/// the file dumps `rtk` leaves raw (ADR-0013 D7), so the rewrite applies
/// whether or not `rtk` is active. Only the documented flag forms are
/// supported; anything else (several files, `-c`, `-f`, `-q`, a pipeline —
/// already refused by the caller's scan) returns `None` untouched.
///
/// - `head [-n N | -N] <file>` → `slice <file>:1-N` (default N = 10)
/// - `tail [-n N | -N] <file>` → `slice <file>:-N` (the last N lines);
///   `tail -n +N <file>` → `slice <file>:N-` (from line N to the end)
/// - `cat <file>` / `nl <file>` → `slice <file>:1-` (the whole file,
///   under slice's default token budget)
fn rewrite_file_dump(cmd0: &str, tokens: &[ShellToken], kit_bin: &str) -> Option<String> {
    let args = &tokens[1..];
    // An optional `--` separator before the single file.
    let args: &[ShellToken] = match args.first() {
        Some(t) if t.value == "--" => &args[1..],
        _ => args,
    };
    let slice_for = |spec: String| -> Option<String> {
        Some(format!("{kit_bin} slice {}", try_shell_quote(&spec)?))
    };
    match cmd0 {
        "cat" | "nl" => {
            if args.len() != 1 {
                return None;
            }
            let file = dump_file_arg(&args[0])?;
            slice_for(format!("{file}:1-"))
        }
        "head" | "tail" => {
            let mut count: Option<usize> = None;
            let mut from_line: Option<usize> = None;
            let mut file: Option<&ShellToken> = None;
            let mut i = 0usize;
            while i < args.len() {
                let arg = args[i].value.as_str();
                if file.is_some() {
                    return None;
                }
                match arg {
                    "-n" | "--lines" => {
                        let val = &args.get(i + 1)?.value;
                        if let Some(n) = val.strip_prefix('+') {
                            if cmd0 != "tail" {
                                return None;
                            }
                            from_line = Some(parse_dump_count(n)?);
                        } else {
                            count = Some(parse_dump_count(val)?);
                        }
                        i += 1;
                    }
                    _ if arg.starts_with("--lines=") => {
                        let val = &arg["--lines=".len()..];
                        if let Some(n) = val.strip_prefix('+') {
                            if cmd0 != "tail" {
                                return None;
                            }
                            from_line = Some(parse_dump_count(n)?);
                        } else {
                            count = Some(parse_dump_count(val)?);
                        }
                    }
                    _ if arg.starts_with('-')
                        && arg.len() > 1
                        && arg[1..].bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        // The attached form: `head -5` / `tail -5`.
                        count = Some(parse_dump_count(&arg[1..])?);
                    }
                    _ if arg.starts_with('-') => return None,
                    _ => file = Some(&args[i]),
                }
                i += 1;
            }
            let file = dump_file_arg(file?)?;
            if cmd0 == "head" {
                if from_line.is_some() {
                    return None;
                }
                let n = count.unwrap_or(10);
                slice_for(format!("{file}:1-{n}"))
            } else if let Some(n) = from_line {
                slice_for(format!("{file}:{n}-"))
            } else {
                let n = count.unwrap_or(10);
                slice_for(format!("{file}:-{n}"))
            }
        }
        _ => None,
    }
}

/// `grep` over files or directories → `search` (#75), with or without
/// `rtk` active (`rtk` leaves `grep` raw; ADR-0013 D7). Only flags whose
/// meaning `search` reproduces are supported; inverting, counting,
/// context, colour, Perl/byte modes and similar return `None` untouched.
/// The pattern is the first positional (or the `-e` argument); every
/// remaining positional is a search path, exactly as in `rewrite_rg`.
fn rewrite_grep(tokens: &[ShellToken], kit_bin: &str) -> Option<String> {
    let mut ignore_case = false;
    let mut fixed_strings = false;
    let mut word_regexp = false;
    let mut files_only = false;
    let mut extended = false;
    let mut pattern: Option<String> = None;
    let mut globs: Vec<String> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();
    let mut positional_only = false;

    let mut i = 1usize;
    while i < tokens.len() {
        let tok = &tokens[i];
        let arg = tok.value.as_str();
        if positional_only {
            if tok.has_expansion {
                return None;
            }
            positionals.push(tok.value.clone());
            i += 1;
            continue;
        }
        match arg {
            "--" => positional_only = true,
            "-i" | "--ignore-case" => ignore_case = true,
            "-F" | "--fixed-strings" => fixed_strings = true,
            "-w" | "--word-regexp" => word_regexp = true,
            "-l" | "--files-with-matches" => files_only = true,
            "-E" | "--extended-regexp" => extended = true,
            // Output-shape flags `search` already matches: it prints
            // grouped, line-numbered matches, one per line.
            "-n" | "--line-number" | "-H" | "--with-filename" | "-h" | "--no-filename"
            | "-r" | "-R" | "--recursive" | "-s" | "--no-messages" => {}
            "-e" | "--regexp" => {
                if pattern.is_some() {
                    return None;
                }
                let val = tokens.get(i + 1)?;
                if val.value.is_empty() || val.has_expansion {
                    return None;
                }
                pattern = Some(val.value.clone());
                i += 1;
            }
            _ if arg.starts_with("--regexp=") => {
                if pattern.is_some() {
                    return None;
                }
                let v = &arg["--regexp=".len()..];
                if v.is_empty() || tok.has_expansion {
                    return None;
                }
                pattern = Some(v.to_owned());
            }
            _ if arg.starts_with("--include=") => {
                let v = &arg["--include=".len()..];
                if v.is_empty() || tok.has_expansion {
                    return None;
                }
                globs.push(v.to_owned());
            }
            "--include" => {
                let val = tokens.get(i + 1)?;
                if val.value.is_empty() || val.has_expansion {
                    return None;
                }
                globs.push(val.value.clone());
                i += 1;
            }
            _ if arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.len() > 1
                && arg[1..]
                    .chars()
                    .all(|c| matches!(c, 'i' | 'F' | 'w' | 'l' | 'E' | 'n' | 'H' | 'h' | 'r' | 'R' | 's')) =>
            {
                for c in arg[1..].chars() {
                    match c {
                        'i' => ignore_case = true,
                        'F' => fixed_strings = true,
                        'w' => word_regexp = true,
                        'l' => files_only = true,
                        'E' => extended = true,
                        _ => {}
                    }
                }
            }
            _ if arg.starts_with('-') => return None,
            _ => {
                if tok.has_expansion {
                    return None;
                }
                positionals.push(tok.value.clone());
            }
        }
        i += 1;
    }
    let _ = extended; // `search` patterns are regexes, like `grep -E`.

    let pattern = match pattern {
        Some(p) => p,
        None => {
            if positionals.is_empty() {
                return None;
            }
            positionals.remove(0)
        }
    };
    // `grep` needs at least one explicit path here: with none it reads
    // stdin or the working tree implicitly, which `search` does not
    // reproduce faithfully enough to rewrite blind.
    if positionals.is_empty() {
        return None;
    }

    let mut parts = vec![kit_bin.to_owned(), "search".to_owned()];
    if ignore_case {
        parts.push("-i".to_owned());
    }
    if fixed_strings {
        parts.push("-F".to_owned());
    }
    if word_regexp {
        parts.push("-w".to_owned());
    }
    if files_only {
        parts.push("--files-only".to_owned());
    }
    for g in globs {
        parts.push("--glob".to_owned());
        parts.push(try_shell_quote(&g)?);
    }
    parts.push("--symbols".to_owned());
    parts.push("--".to_owned());
    parts.push(try_shell_quote(&pattern)?);
    for pos in positionals {
        parts.push(try_shell_quote(&pos)?);
    }
    Some(parts.join(" "))
}

/// Read-only `gh` log pulls → `compact --mode log` (#76, ADR-0013 D2(a):
/// a hook rewrite to an existing verb, no new verb). Only the exact
/// `gh run view … --log|--log-failed` shape is rewritten, re-emitting the
/// original command verbatim after `--`, so the full log stays
/// recoverable through compact's spillover file. Structured output
/// (`--json`/`--jq`/`--template`), browser/exit-status forms, and every
/// other `gh` shape — including all writes (`create`, `merge`, `comment`,
/// `edit`, `close`, `gh api` with a method or fields), which can never
/// match this shape — are left untouched.
fn rewrite_gh_log(tokens: &[ShellToken], kit_bin: &str, rest: &str) -> Option<String> {
    if tokens.len() < 4
        || tokens[1].value != "run"
        || tokens[2].value != "view"
    {
        return None;
    }
    let mut log_flags = 0usize;
    let mut positionals = 0usize;
    let mut i = 3usize;
    while i < tokens.len() {
        let arg = tokens[i].value.as_str();
        match arg {
            "--log" | "--log-failed" => log_flags += 1,
            "--job" | "--attempt" | "-R" | "--repo" => {
                let val = tokens.get(i + 1)?;
                if val.value.is_empty() {
                    return None;
                }
                i += 1;
            }
            _ if arg.starts_with("--job=")
                || arg.starts_with("--attempt=")
                || arg.starts_with("--repo=") =>
            {
                if arg.ends_with('=') {
                    return None;
                }
            }
            // Structured output and behaviour-changing flags never rewrite.
            "--json" | "--jq" | "--template" | "-q" | "--web" | "-w" | "--exit-status" => {
                return None;
            }
            _ if arg.starts_with("--json=")
                || arg.starts_with("--jq=")
                || arg.starts_with("--template=") =>
            {
                return None;
            }
            _ if arg.starts_with('-') => return None,
            _ => {
                positionals += 1;
                if positionals > 1 {
                    return None;
                }
            }
        }
        i += 1;
    }
    if log_flags != 1 {
        return None;
    }
    Some(format!("{kit_bin} compact --mode log -- {rest}"))
}

/// Literal-prefix predicate for the measured RTK 1.2.0 piped replies: the
/// claimed form must end at a literal ASCII space — a tab or extra spacing
/// right after the command does not count.
fn word_prefix(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|tail| tail.is_empty() || tail.starts_with(' '))
}

/// Whether the raw piped runner `rest` (truncation and cd prefix already
/// stripped) spells a form RTK 1.2.0 claims: literal `pytest` or
/// `python[3] -m pytest` prefixes matched with single spaces, or a
/// cargo/dotnet/go/mvn command followed by a space and an eligible
/// subcommand — extra whitespace or tabs after that first separator still
/// match, per the measured replies. Everything else keeps the kit log.
fn rtk_claims_piped(rest: &str, cmd: &str, arg1: Option<&str>, arg2: Option<&str>) -> bool {
    if word_prefix(rest, "pytest")
        || word_prefix(rest, "python -m pytest")
        || word_prefix(rest, "python3 -m pytest")
    {
        return true;
    }
    if !matches!(cmd, "cargo" | "dotnet" | "go" | "mvn") {
        return false;
    }
    if !matches!(
        (cmd, arg1, arg2),
        ("cargo", Some("build" | "check" | "clippy" | "test"), _)
            | ("dotnet", Some("restore" | "build"), _)
            | ("go", Some("build" | "test"), _)
            | ("mvn", Some("test"), _)
    ) {
        return false;
    }
    rest.strip_prefix(cmd)
        .and_then(|s| s.strip_prefix(' '))
        .is_some_and(|s| {
            s.trim_start_matches([' ', '\t'])
                .strip_prefix(arg1.unwrap_or(""))
                .is_some_and(|tail| tail.is_empty() || tail.starts_with([' ', '\t']))
        })
}

/// Runner command → compact mode (`"build"`/`"test"`), or None when the
/// command is not an eligible runner or RTK claims it. `piped` carries the
/// raw runner text for truncated forms — RTK's piped claims were measured
/// on literal spellings only, so path-qualified or quoted runners are never
/// deferred. Plain commands keep the original always/standalone split.
fn runner_mode(
    cmd: &str,
    arg1: Option<&str>,
    arg2: Option<&str>,
    rtk_active: bool,
    piped: Option<&str>,
) -> Option<&'static str> {
    // Empirical split (rtk 1.2.0 probes): piped `dotnet restore|build`,
    // `cargo build|check|clippy|test`, `go build|test`, `mvn test`, `pytest`,
    // and `python[3] -m pytest` are claimed by RTK; tsc/jest/vitest,
    // dotnet test/format, msbuild, unittest, npm/pnpm/yarn/bun test, and
    // gradle/gradlew test are not, so kit keeps their logs.
    let rtk_defers = rtk_active
        && match piped {
            Some(rest) => rtk_claims_piped(rest, cmd, arg1, arg2),
            None => matches!(
                (cmd, arg1, arg2),
                ("dotnet", Some("build"), _)
                    | ("cargo", Some("build" | "check" | "clippy" | "test"), _)
                    | ("go", Some("build" | "test"), _)
                    | ("tsc", _, _)
                    | ("pytest" | "jest" | "vitest", _, _)
                    | ("python" | "python3", Some("-m"), Some("pytest"))
            ),
        };
    if rtk_defers {
        return None;
    }
    match (cmd, arg1, arg2) {
        ("dotnet", Some("test"), _) => Some("test"),
        ("dotnet", Some("restore" | "format" | "build"), _) => Some("build"),
        ("msbuild" | "msbuild.exe", _, _) => Some("build"),
        ("python" | "python3", Some("-m"), Some("unittest")) => Some("test"),
        ("npm", Some("test"), _) | ("npm", Some("run"), Some("test")) => Some("test"),
        ("pnpm" | "yarn" | "bun", Some("test"), _) => Some("test"),
        ("mvn" | "gradle" | "gradlew", Some("test"), _) => Some("test"),
        ("tsc", _, _) => Some("build"),
        ("cargo", Some("build" | "check" | "clippy"), _) => Some("build"),
        ("cargo", Some("test"), _) => Some("test"),
        ("go", Some("build"), _) => Some("build"),
        ("go", Some("test"), _) => Some("test"),
        ("pytest" | "jest" | "vitest", _, _) => Some("test"),
        ("python" | "python3", Some("-m"), Some("pytest")) => Some("test"),
        _ => None,
    }
}

/// Pure command rewriter parameterized by quoted binary path, RTK status, and optional cwd.
pub fn rewrite_command_str(
    command: &str,
    kit_bin: &str,
    rtk_active: bool,
    event_cwd: Option<&Path>,
) -> Option<String> {
    let truncated = truncated_runner(command);
    let (cd_prefix, rest) = scan_and_split_cd_prefix(truncated.unwrap_or(command))?;
    let tokens = shell_split(rest)?;
    // Piped truncation additionally refuses token expansions anywhere in the
    // runner or its `cd` prefix — an expanded word could resolve to anything,
    // so the command passes through untouched.
    if truncated.is_some()
        && (tokens.iter().any(|t| t.has_expansion)
            || cd_prefix.is_some_and(|prefix| {
                shell_split(prefix).is_none_or(|ts| ts.iter().any(|t| t.has_expansion))
            }))
    {
        return None;
    }
    let first = tokens.first()?;
    if is_excluded_wrapper(&first.value) {
        return None;
    }
    if tokens
        .iter()
        .any(|tok| !crate::hook::command_token_denied(&tok.value).is_empty())
    {
        return None;
    }

    let cmd0 = basename_lower(&first.value);
    let arg1 = tokens.get(1).map(|t| t.value.as_str());
    let arg2 = tokens.get(2).map(|t| t.value.as_str());

    let rewritten_tail = if truncated.is_some() {
        // Piped truncation: runners only (no sed/git/rg fallback) — compact
        // keeps the guaranteed raw log instead of the pipe's silent cut. The
        // RTK deferral matches the literal spellings its replies claimed.
        let mode = runner_mode(&cmd0, arg1, arg2, rtk_active, Some(rest))?;
        format!("{kit_bin} compact --mode {mode} --keep-log -- {rest}")
    } else {
        match cmd0.as_str() {
            "sed" if tokens.len() == 4 && arg1 == Some("-n") => {
                let (start, end) = parse_sed_range(&tokens[2].value)?;
                if !is_safe_sed_path(&tokens[3]) {
                    return None;
                }
                let spec = format!("{}:{start}-{end}", tokens[3].value);
                Some(format!("{kit_bin} slice {}", try_shell_quote(&spec)?))
            }
            "git" if !rtk_active => rewrite_git(&tokens, kit_bin, cd_prefix, event_cwd),
            // With `rtk` active, only the forms its history leaves raw are
            // taken (#75): `git show`, the file dumps, and `grep`.
            "git" => rewrite_git_show_only(&tokens, kit_bin, cd_prefix, event_cwd),
            "head" | "tail" | "cat" | "nl" => rewrite_file_dump(&cmd0, &tokens, kit_bin),
            "grep" => rewrite_grep(&tokens, kit_bin),
            "gh" => rewrite_gh_log(&tokens, kit_bin, rest),
            "rg" if !rtk_active => rewrite_rg(&tokens, kit_bin),
            _ => runner_mode(&cmd0, arg1, arg2, rtk_active, None)
                .map(|mode| format!("{kit_bin} compact --mode {mode} -- {rest}")),
        }?
    };

    if let Some(prefix) = cd_prefix {
        Some(format!("{prefix} && {rewritten_tail}"))
    } else {
        Some(rewritten_tail)
    }
}

/// Interception capability tier for shell commands (ADR-0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellPolicyTier {
    /// Tier 1: transparently rewrite covered shell commands.
    Rewrite,
    /// Tier 2: deny once naming the exact `prometheus-kit` command, allow immediate retry.
    DenyOnce,
}

/// Shared outcome of evaluating a shell tool call across Tier 1 and Tier 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellAction {
    Pass,
    Rewrite {
        command_key: String,
        rewritten: String,
        raw_bytes: usize,
    },
    DenyOnce {
        reason: String,
        suggested: String,
        raw_bytes: usize,
    },
}

pub(crate) fn extract_shell_command(
    tool_input: &Map<String, Value>,
) -> Option<(&'static str, &str)> {
    for key in ["command", "CommandLine"] {
        if let Some(cmd) = tool_input
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
        {
            return Some((key, cmd));
        }
    }
    None
}

/// Shared Tier-1 / Tier-2 shell evaluation helper honoring `rtk` deferral (ADR-0013 D7).
pub fn evaluate_shell_policy(
    host: &str,
    tier: ShellPolicyTier,
    tool_name: &str,
    tool_input: &Map<String, Value>,
    session_id: &str,
    event_cwd: Option<&Path>,
) -> ShellAction {
    if rewrite_disabled() || !is_shell_tool(tool_name) {
        return ShellAction::Pass;
    }
    let Some((command_key, command)) = extract_shell_command(tool_input) else {
        return ShellAction::Pass;
    };
    let rtk_active = rtk_hook_active(host);
    let Some(kit_bin) = kit_bin_quoted() else {
        return ShellAction::Pass;
    };
    let Some(rewritten) = rewrite_command_str(command, &kit_bin, rtk_active, event_cwd) else {
        return ShellAction::Pass;
    };
    match tier {
        ShellPolicyTier::Rewrite => {
            if let Some(metrics_host) = crate::metrics::Host::from_hook(host) {
                crate::metrics::record(
                    metrics_host,
                    crate::metrics::Rule::ShellRewrite,
                    command.len(),
                    rewritten.len(),
                );
            }
            ShellAction::Rewrite {
                command_key: command_key.to_owned(),
                rewritten,
                raw_bytes: command.len(),
            }
        }
        ShellPolicyTier::DenyOnce => {
            match crate::hook::shell_deny_once_decision(host, session_id, event_cwd, command, &rewritten) {
                Some(reason) => ShellAction::DenyOnce {
                    reason,
                    suggested: rewritten,
                    raw_bytes: command.len(),
                },
                None => ShellAction::Pass,
            }
        }
    }
}

/// Evaluate a `PreToolUse` event for shell command auto-rewrite (Claude/Devin/Droid/Muse envelope).
/// Returns `None` when the command should pass through unchanged.
pub fn rewrite_command_reply(host: &str, event: &Value) -> Option<Value> {
    let event_cwd = event
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(Path::new);
    rewrite_command_reply_with_cwd(host, event, event_cwd)
}

pub fn rewrite_command_reply_with_cwd(
    host: &str,
    event: &Value,
    event_cwd: Option<&Path>,
) -> Option<Value> {
    if !matches!(host, "claude" | "devin" | "droid" | "muse") {
        return None;
    }
    let tool = event
        .get("tool_name")
        .or_else(|| event.get("toolName"))
        .and_then(Value::as_str)?;
    let tool_input = event
        .get("tool_input")
        .or_else(|| event.get("input"))
        .and_then(Value::as_object)?;
    let session_id = event
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    match evaluate_shell_policy(
        host,
        ShellPolicyTier::Rewrite,
        tool,
        tool_input,
        session_id,
        event_cwd,
    ) {
        ShellAction::Rewrite {
            command_key,
            rewritten,
            ..
        } => {
            let mut updated: Map<String, Value> = tool_input.clone();
            updated.insert(command_key, Value::String(rewritten));
            Some(json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecisionReason": "prometheus-kit auto-rewrite",
                    "updatedInput": Value::Object(updated),
                }
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::MutexGuard;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_guard() -> MutexGuard<'static, ()> {
        crate::hook::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner())
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

    const KIT: &str = "'/opt/prometheus-kit'";

    #[test]
    fn always_eligible_rewrites_run_with_or_without_rtk() {
        for rtk in [false, true] {
            assert_eq!(
                Some(format!("{KIT} compact --mode test -- dotnet test Foo.csproj --filter 'A|B'")),
                rewrite_command_str("dotnet test Foo.csproj --filter 'A|B'", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!("cd '/my repo' && {KIT} compact --mode test -- dotnet test")),
                rewrite_command_str("cd '/my repo' && dotnet test", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!("{KIT} compact --mode build -- dotnet restore src/App.sln")),
                rewrite_command_str("dotnet restore src/App.sln", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!("{KIT} compact --mode build -- dotnet format --verify-no-changes")),
                rewrite_command_str("dotnet format --verify-no-changes", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!("{KIT} compact --mode test -- python3 -m unittest discover -s tests")),
                rewrite_command_str("python3 -m unittest discover -s tests", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!("{KIT} compact --mode test -- npm run test -- --watch=false")),
                rewrite_command_str("npm run test -- --watch=false", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!("{KIT} compact --mode test -- pnpm test")),
                rewrite_command_str("pnpm test", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!("{KIT} compact --mode test -- ./gradlew test")),
                rewrite_command_str("./gradlew test", KIT, rtk, None)
            );
            assert_eq!(
                Some(format!(
                    "{KIT} slice {}",
                    try_shell_quote("src/a b.py:10-40").unwrap()
                )),
                rewrite_command_str("sed -n '10,40p' 'src/a b.py'", KIT, rtk, None)
            );
        }
    }

    #[test]
    fn rtk_gap_rewrites_run_with_or_without_rtk() {
        // #75: the forms `rtk` leaves raw are rewritten in both states.
        let q = |s: &str| try_shell_quote(s).unwrap();
        for rtk in [false, true] {
            assert_eq!(
                Some(format!("{KIT} slice {}", q("src/a.py:1-20"))),
                rewrite_command_str("head -n 20 src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} slice {}", q("src/a.py:1-5"))),
                rewrite_command_str("head -5 src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} slice {}", q("src/a.py:1-10"))),
                rewrite_command_str("head src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} slice {}", q("src/a.py:-20"))),
                rewrite_command_str("tail -n 20 src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} slice {}", q("src/a.py:50-"))),
                rewrite_command_str("tail -n +50 src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} slice {}", q("src/a.py:1-"))),
                rewrite_command_str("cat src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} slice {}", q("src/a.py:1-"))),
                rewrite_command_str("nl src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!(
                    "{KIT} search -i -F --symbols -- {} {}",
                    q("needle"),
                    q("src/")
                )),
                rewrite_command_str("grep -i -F needle src/", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!(
                    "{KIT} search --symbols -- {} {} {}",
                    q("needle"),
                    q("src/a.py"),
                    q("src/b.py")
                )),
                rewrite_command_str("grep -rn needle src/a.py src/b.py", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} diff --commit {}", q("HEAD~1"))),
                rewrite_command_str("git show HEAD~1", KIT, rtk, None),
                "rtk={rtk}"
            );
            assert_eq!(
                Some(format!("{KIT} diff --commit {} --stat", q("HEAD~1"))),
                rewrite_command_str("git show --stat HEAD~1", KIT, rtk, None),
                "rtk={rtk}"
            );
            // A `cd` prefix is preserved, as with the other rewrites.
            assert_eq!(
                Some(format!(
                    "cd '/my repo' && {KIT} slice {}",
                    q("src/a.py:1-")
                )),
                rewrite_command_str("cd '/my repo' && cat src/a.py", KIT, rtk, None),
                "rtk={rtk}"
            );
        }
    }

    #[test]
    fn rtk_gap_rewrites_leave_unsupported_forms_untouched() {
        for rtk in [false, true] {
            for cmd in [
                // Several paths, unsupported flags, stdin, expansions.
                "head -n 5 src/a.py src/b.py",
                "head -c 100 src/a.py",
                "head -n 0 src/a.py",
                "tail -f src/a.py",
                "tail -n 5 -",
                "cat src/a.py src/b.py",
                "cat -e src/a.py",
                "cat $FILE",
                "cat *.py",
                "nl -b a src/a.py",
                "grep -v needle src/",
                "grep -c needle src/",
                "grep -A 3 needle src/",
                "grep needle",
                "grep $PAT src/",
                // Secret paths: the guard check inside the rewriter
                // refuses these before any rewrite is produced.
                "cat .env",
                "head -n 5 .env.local",
                "grep needle .env",
                "git show HEAD:.env",
            ] {
                assert_eq!(
                    None,
                    rewrite_command_str(cmd, KIT, rtk, None),
                    "rtk={rtk} cmd={cmd}"
                );
            }
        }
    }

    #[test]
    fn gh_log_pulls_rewrite_to_compact_log_in_both_rtk_states() {
        for rtk in [false, true] {
            for cmd in [
                "gh run view 12345 --log",
                "gh run view 12345 --log-failed",
                "gh run view --log",
                "gh run view 12345 --job 678 --log",
                "gh run view --attempt 2 --log-failed 12345",
                "gh run view -R owner/repo 12345 --log",
            ] {
                assert_eq!(
                    Some(format!("{KIT} compact --mode log -- {cmd}")),
                    rewrite_command_str(cmd, KIT, rtk, None),
                    "rtk={rtk} cmd={cmd}"
                );
            }
            // A global `-R` before the subcommand is not a supported
            // shape (`run` is not at index 1) and stays untouched.
            assert_eq!(
                None,
                rewrite_command_str("gh -R owner/repo run view 12345 --log", KIT, rtk, None),
                "rtk={rtk}"
            );
        }
    }

    #[test]
    fn gh_non_log_and_write_forms_are_never_rewritten() {
        for rtk in [false, true] {
            for cmd in [
                // No log flag, or a different read shape.
                "gh run view 12345",
                "gh run list --limit 5",
                "gh pr view 42",
                "gh run view 12345 --log --log-failed",
                "gh run view 12345 --job 1 --job 2 --log extra1 extra2",
                // Structured output stays untouched.
                "gh run view 12345 --log --json conclusion",
                "gh run view 12345 --log --jq .conclusion",
                "gh run view 12345 --log --template '{{.}}'",
                // Behaviour-changing flags.
                "gh run view 12345 --log --web",
                "gh run view 12345 --log --exit-status",
                // Writes and API mutations are never touched.
                "gh pr create --title x",
                "gh pr merge 42",
                "gh issue comment 7 --body hi",
                "gh issue edit 7 --title x",
                "gh issue close 7",
                "gh api repos/o/r/actions/runs/1/logs -X DELETE",
                "gh api -X POST repos/o/r/issues -f title=x",
                "gh run rerun 12345",
                "gh run cancel 12345",
            ] {
                assert_eq!(
                    None,
                    rewrite_command_str(cmd, KIT, rtk, None),
                    "rtk={rtk} cmd={cmd}"
                );
            }
        }
    }

    #[test]
    fn standalone_rewrites_defer_when_rtk_is_active() {
        for cmd in [
            "dotnet build App.csproj",
            "cargo test --locked",
            "cargo clippy",
            "go test ./...",
            "pytest tests/",
            "git status -sb",
            "git diff --staged --stat",
            "rg -i foo src/",
        ] {
            assert_eq!(None, rewrite_command_str(cmd, KIT, true, None), "rtk=true cmd={cmd}");
            assert!(
                rewrite_command_str(cmd, KIT, false, None).is_some(),
                "rtk=false cmd={cmd}"
            );
        }
    }

    #[test]
    fn git_and_rg_rewrites_map_flags_safely() {
        let q = |s: &str| try_shell_quote(s).unwrap();
        assert_eq!(
            Some(format!("{KIT} diff --root {} --status", q("/repo"))),
            rewrite_command_str("git -C /repo status --short --branch", KIT, false, None)
        );
        assert_eq!(
            None,
            rewrite_command_str("git status --porcelain=v1", KIT, false, None)
        );
        assert_eq!(
            Some(format!(
                "{KIT} diff --root {} --staged --stat -C 5 -- {} {}",
                q("/repo"),
                q("src/a.rs"),
                q("src/b.rs")
            )),
            rewrite_command_str(
                "git -C /repo diff --cached --stat -U5 -- src/a.rs src/b.rs",
                KIT,
                false,
                None
            )
        );
        assert_eq!(
            Some(format!(
                "{KIT} diff --base {} -- {}",
                q("origin/main"),
                q("src/a.rs")
            )),
            rewrite_command_str("git diff origin/main -- src/a.rs", KIT, false, None)
        );
        assert_eq!(
            None,
            rewrite_command_str("git diff --staged main", KIT, false, None)
        );
        assert_eq!(
            None,
            rewrite_command_str("git diff --name-only", KIT, false, None)
        );
        assert_eq!(
            None,
            rewrite_command_str("git show HEAD:.env", KIT, false, None)
        );
        assert_eq!(
            Some(format!("{KIT} diff --commit {} --stat", q("HEAD~1"))),
            rewrite_command_str("git show --stat HEAD~1", KIT, false, None)
        );
        assert_eq!(
            Some(format!(
                "{KIT} search -i --files-only --glob {} --type {} --symbols -- {} {}",
                q("src/foo.cs"),
                q("cs"),
                q("LinkActivePerks"),
                q("src/")
            )),
            rewrite_command_str(
                "rg -i -l -g 'src/foo.cs' -t cs LinkActivePerks src/",
                KIT,
                false,
                None
            )
        );
        #[cfg(not(windows))]
        assert_eq!(
            Some(format!(
                "{KIT} search -i --files-only --glob '*.cs' --type 'cs' --symbols -- 'LinkActivePerks' 'src/'"
            )),
            rewrite_command_str(
                "rg -i -l -g '*.cs' -t cs LinkActivePerks src/",
                KIT,
                false,
                None
            )
        );
        assert_eq!(
            None,
            rewrite_command_str("rg -A 3 foo src/", KIT, false, None)
        );
        assert_eq!(
            None,
            rewrite_command_str("rg -t nonexistentfoo bar src/", KIT, false, None)
        );
        assert_eq!(
            None,
            rewrite_command_str("rg foo src/*.cs", KIT, false, None)
        );
    }

    #[test]
    fn safety_passthroughs_never_rewrite() {
        for cmd in [
            "dotnet test | tee test.log",
            "dotnet test; echo done",
            "dotnet test > out.txt",
            "dotnet test &",
            "cd /tmp && dotnet build && dotnet test",
            "echo ok && dotnet test",
            "VAR=1 dotnet test",
            "sudo dotnet test",
            "env cargo build",
            "rtk git status",
            "prometheus-kit diff",
            "~/.agents/prometheus/prometheus-check -- dotnet test",
            "dotnet test $(pwd)",
            "dotnet test `pwd`",
            "dotnet test\necho hi",
            "sed -n '0,5p' a.py",
            "sed -n '10,5p' a.py",
            "sed -n '1,5p' *.py",
            "sed -n '1,5p' ~/.zshrc",
            "sed -n '1,5p' -",
            "sed -n '1,5p' {a,b}.rs",
            "rg foo {a,b}",
            "rg $- src/",
            r"dotnet test --settings $'\x2eenv'",
            r"sed -n '1,5p' .e\nv",
            r"rg key .e\nv",
            r"git diff -- .e\nv",
            r"git -C .s\sh status",
            r"dotnet test --settings .e\nv",
            r"sed -n '1,5p' .s\sh/id_\rsa",
            r"cd .s\sh && dotnet test",
            "dotnet test 'unclosed",
        ] {
            assert_eq!(None, rewrite_command_str(cmd, KIT, false, None), "cmd={cmd}");
        }
    }

    #[test]
    fn quote_windows_and_posix_prevent_injection() {
        for bad in [
            "",
            "foo&calc",
            "foo|calc",
            "foo>out.txt",
            "foo<in.txt",
            "foo;calc",
            "a\"&calc",
            "a'b",
            "`calc`",
            "$env:PATH",
            "%PATH%",
            "foo(bar)",
            "foo^bar",
            "foo!bar",
            "*.cs",
            "foo?bar",
            "a[0]",
            "{a,b}",
            "a,b",
            "C:\\Program Files\\bad\\",
            "line1\nline2",
        ] {
            assert_eq!(None, quote_windows(bad), "bad={bad}");
        }
        assert_eq!(Some("src/a.rs".to_owned()), quote_windows("src/a.rs"));
        assert_eq!(
            Some("\"C:\\Program Files\\prometheus-kit.exe\"".to_owned()),
            quote_windows("C:\\Program Files\\prometheus-kit.exe")
        );
        assert_eq!(None, quote_posix("a\nb"));
        assert_eq!(Some("'a'\\''b'".to_owned()), quote_posix("a'b"));
    }

    #[test]
    fn host_envelope_and_rtk_config_detection() {
        let _g = env_guard();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("prom_rw_{}_{nanos}", std::process::id()));
        let factory = tmp.join(".factory");
        fs::create_dir_all(&factory).unwrap();
        fs::write(
            factory.join("hooks.json"),
            r#"{"PreToolUse":[{"matcher":"Execute","hooks":[{"type":"command","command":"rtk hook droid"}]}]}"#,
        )
        .unwrap();

        {
            let _env = EnvOverride::set(&[
                ("HOME", Some(tmp.to_str().unwrap())),
                ("USERPROFILE", Some(tmp.to_str().unwrap())),
                ("PROMETHEUS_KIT_RTK_COEXIST", None),
                ("PROMETHEUS_KIT_NO_REWRITE", None),
            ]);
            assert!(rtk_hook_active("droid"));
            assert!(!rtk_hook_active("claude"));

            // With RTK active on droid: git diff passes through, dotnet test rewrites & preserves metadata.
            let git_ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Execute",
                "tool_input": {"command": "git status", "summary": "s", "riskLevel": "low"}
            });
            assert_eq!(None, rewrite_command_reply("droid", &git_ev));

            let dotnet_ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Execute",
                "tool_input": {"command": "dotnet test App.csproj", "summary": "run tests", "riskLevel": "medium", "timeout": 120}
            });
            let reply = rewrite_command_reply("droid", &dotnet_ev).unwrap();
            let out = &reply["hookSpecificOutput"];
            assert_eq!("PreToolUse", out["hookEventName"]);
            assert!(out.get("permissionDecision").is_none());
            assert_eq!("run tests", out["updatedInput"]["summary"]);
            assert_eq!("medium", out["updatedInput"]["riskLevel"]);
            assert_eq!(120, out["updatedInput"]["timeout"]);
            assert!(out["updatedInput"]["command"]
                .as_str()
                .unwrap()
                .contains("compact --mode test -- dotnet test App.csproj"));

            // Cursor uses its own flat `updated_input` envelope in `handle_cursor`,
            // while Devin uses the shared `hookSpecificOutput.updatedInput` envelope.
            assert_eq!(None, rewrite_command_reply("cursor", &dotnet_ev));
            let devin_reply = rewrite_command_reply("devin", &dotnet_ev).unwrap();
            assert!(devin_reply["hookSpecificOutput"]["updatedInput"]["command"]
                .as_str()
                .unwrap()
                .contains("compact --mode test -- dotnet test App.csproj"));
        }

        {
            let _env = EnvOverride::set(&[
                ("HOME", Some(tmp.to_str().unwrap())),
                ("USERPROFILE", Some(tmp.to_str().unwrap())),
                ("PROMETHEUS_KIT_RTK_COEXIST", None),
                ("PROMETHEUS_KIT_NO_REWRITE", Some("1")),
            ]);
            let dotnet_ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "dotnet test"}
            });
            assert_eq!(None, rewrite_command_reply("claude", &dotnet_ev));
        }

        #[cfg(unix)]
        {
            let fifo_home = tmp.join("fifo_home");
            let fifo_factory = fifo_home.join(".factory");
            fs::create_dir_all(&fifo_factory).unwrap();
            let fifo_path = fifo_factory.join("hooks.json");
            let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
            unsafe {
                libc::mkfifo(c_path.as_ptr(), 0o600);
            }
            let _env = EnvOverride::set(&[
                ("HOME", Some(fifo_home.to_str().unwrap())),
                ("PROMETHEUS_KIT_RTK_COEXIST", None),
            ]);
            assert!(!rtk_hook_active("droid"));
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn truncated_runner_table_covers_groups_tails_counts_and_rtk() {
        // Every eligible runner group -> expected compact mode.
        let runners: &[(&str, &str)] = &[
            ("dotnet test", "test"),
            ("dotnet restore", "build"),
            ("dotnet build", "build"),
            ("dotnet format", "build"),
            ("msbuild", "build"),
            ("msbuild.exe", "build"),
            ("python -m unittest", "test"),
            ("python3 -m unittest", "test"),
            ("python -m pytest", "test"),
            ("python3 -m pytest", "test"),
            ("npm test", "test"),
            ("npm run test", "test"),
            ("pnpm test", "test"),
            ("yarn test", "test"),
            ("bun test", "test"),
            ("mvn test", "test"),
            ("gradle test", "test"),
            ("gradlew test", "test"),
            ("./gradlew test", "test"),
            ("cargo build", "build"),
            ("cargo check", "build"),
            ("cargo clippy", "build"),
            ("cargo test", "test"),
            ("go build", "build"),
            ("go test", "test"),
            ("tsc", "build"),
            ("pytest", "test"),
            ("jest", "test"),
            ("vitest", "test"),
        ];
        // Groups RTK verifiably claims in piped form (rtk 1.2.0 probes) defer
        // when rtk_active; every other runner keeps the keep-log rewrite.
        let rtk_deferred = |runner: &str| {
            matches!(
                runner,
                "dotnet restore"
                    | "dotnet build"
                    | "cargo build"
                    | "cargo check"
                    | "cargo clippy"
                    | "cargo test"
                    | "go build"
                    | "go test"
                    | "mvn test"
                    | "pytest"
                    | "python -m pytest"
                    | "python3 -m pytest"
            )
        };
        let tails = [
            "| tail",
            "| tail -5",
            "| tail -n 5",
            "| tail -n  5",
            "| head",
            "| head -3",
            "| head -n 3",
            "|tail -5",
        ];
        for &(runner, mode) in runners {
            for tail in tails {
                for redirect in ["", " 2>&1"] {
                    let input = format!("{runner}{redirect} {tail}");
                    let expected = Some(format!(
                        "{KIT} compact --mode {mode} --keep-log -- {runner}"
                    ));
                    assert_eq!(
                        expected,
                        rewrite_command_str(&input, KIT, false, None),
                        "rtk=false input={input}"
                    );
                    let expected_rtk = if rtk_deferred(runner) {
                        None
                    } else {
                        expected.clone()
                    };
                    assert_eq!(
                        expected_rtk,
                        rewrite_command_str(&input, KIT, true, None),
                        "rtk=true input={input}"
                    );
                }
            }
        }
    }

    #[test]
    fn truncated_runner_rejects_ambiguous_and_unsafe_forms() {
        for cmd in [
            // Not a plain head/tail truncation.
            "dotnet test | tee out.log",
            "dotnet test | wc -l",
            "dotnet test | tail -5 | head -3",
            "dotnet test | tail -5 | tail -2",
            "dotnet test | tail -5; echo done",
            "dotnet test | tail -5 && echo ok",
            "dotnet test | tail -5 > out.txt",
            "dotnet test | tail -n5",
            "dotnet test | tail -n +5",
            "dotnet test | tail -n -5",
            "dotnet test | tail -c 5",
            "dotnet test | tail -f",
            "dotnet test | tail --lines=5",
            "dotnet test | tail -5 extra",
            "dotnet test | tail -5 'x'",
            "dotnet test | Tail -5",
            "dotnet test | tail -",
            "dotnet test | tail -n",
            "dotnet test | tail -n ",
            "dotnet test | heads -5",
            "dotnet test | tailx",
            // Redirects and operators inside the runner part.
            "dotnet test > out.txt | tail -5",
            "dotnet test 2>err.log | tail -5",
            "dotnet test >&2 | tail -5",
            "dotnet test || tail -5",
            "dotnet test | tail -5 || echo x",
            "dotnet test & tail -5",
            // Comments: the pipe may sit inside the comment.
            "dotnet test # note | tail -5",
            "dotnet test # | tail -5",
            // Wrappers and env prefixes stay excluded.
            "sudo dotnet test | tail -5",
            "VAR=1 dotnet test | tail -5",
            "env dotnet test | tail -5",
            // Whitespace, quoting, and escape hazards.
            "dotnet test |\u{a0}tail -5",
            "dotnet test | tail -5\n",
            "dotnet test | tail -5\r",
            "dotnet test\0| tail -5",
            "dotnet test 'unclosed | tail -5",
            "dotnet test \"unclosed | tail -5",
            "dotnet test x2>&1 | tail -5",
            "dotnet test 2>&1 2>&1 | tail -5",
            // Piped non-runners get no fallback to sed/git/rg rewrites.
            "ls -la | tail -5",
            "sed -n '1,5p' f.py | tail -3",
            "git status | tail -2",
            "rg foo src/ | tail -5",
            "echo hi | tail -3",
        ] {
            assert_eq!(None, rewrite_command_str(cmd, KIT, false, None), "cmd={cmd}");
            assert_eq!(None, rewrite_command_str(cmd, KIT, true, None), "rtk cmd={cmd}");
        }
    }

    #[test]
    fn truncated_runner_preserves_quotes_cd_prefix_and_literals() {
        assert_eq!(
            Some(format!(
                "{KIT} compact --mode test --keep-log -- dotnet test --filter 'A|B'"
            )),
            rewrite_command_str("dotnet test --filter 'A|B' | tail -40", KIT, false, None)
        );
        assert_eq!(
            Some(format!(
                "{KIT} compact --mode test --keep-log -- dotnet test --filter \"A|B\""
            )),
            rewrite_command_str("dotnet test --filter \"A|B\" | tail -40", KIT, false, None)
        );
        assert_eq!(
            Some(format!(
                "cd '/my repo' && {KIT} compact --mode test --keep-log -- dotnet test"
            )),
            rewrite_command_str("cd '/my repo' && dotnet test 2>&1 | tail -20", KIT, false, None)
        );
        // Mid-word and quoted `#` are literal arguments, not comments.
        assert_eq!(
            Some(format!(
                "{KIT} compact --mode test --keep-log -- dotnet test --name 'C#' arg#x"
            )),
            rewrite_command_str("dotnet test --name 'C#' arg#x | tail -5", KIT, false, None)
        );
        // Tab separators are shell whitespace; a glued pipe still splits.
        assert_eq!(
            Some(format!("{KIT} compact --mode test --keep-log -- dotnet test")),
            rewrite_command_str("dotnet test\t|\ttail\t-5", KIT, false, None)
        );
        assert_eq!(
            Some(format!("{KIT} compact --mode build --keep-log -- cargo build")),
            rewrite_command_str("cargo build|tail -3", KIT, false, None)
        );
    }

    #[test]
    fn truncated_runner_secret_args_still_refused() {
        for cmd in [
            "dotnet test --settings .env | tail -5",
            "dotnet test .env | tail -5",
            "dotnet test cert.pem | tail -5",
            "dotnet test --filter 'A|B' --config id_rsa | tail -5",
        ] {
            assert_eq!(None, rewrite_command_str(cmd, KIT, false, None), "cmd={cmd}");
            assert_eq!(None, rewrite_command_str(cmd, KIT, true, None), "rtk cmd={cmd}");
        }
    }

    #[test]
    fn truncated_runner_rtk_deferral_requires_literal_spelling() {
        // (input, keep-log rewrite when not deferred). RTK 1.2.0 claims only
        // the literal raw spellings its replies matched; path-qualified,
        // quoted, tab-separated, or case-differing forms keep the kit log.
        let cases: &[(&str, &str)] = &[
            (
                "/usr/bin/pytest | tail -5",
                "compact --mode test --keep-log -- /usr/bin/pytest",
            ),
            (
                "./pytest | tail -5",
                "compact --mode test --keep-log -- ./pytest",
            ),
            (
                "\"pytest\" | tail -5",
                "compact --mode test --keep-log -- \"pytest\"",
            ),
            (
                "'/usr/bin/pytest' | tail -5",
                "compact --mode test --keep-log -- '/usr/bin/pytest'",
            ),
            ("PyTest | tail -5", "compact --mode test --keep-log -- PyTest"),
            (
                "python -m pytest | tail -5",
                "compact --mode test --keep-log -- python -m pytest",
            ),
            (
                "python \"-m\" pytest | tail -5",
                "compact --mode test --keep-log -- python \"-m\" pytest",
            ),
            (
                "python -m \"pytest\" | tail -5",
                "compact --mode test --keep-log -- python -m \"pytest\"",
            ),
            (
                "/usr/bin/python -m pytest | tail -5",
                "compact --mode test --keep-log -- /usr/bin/python -m pytest",
            ),
            (
                "dotnet restore | tail -5",
                "compact --mode build --keep-log -- dotnet restore",
            ),
            (
                "dotnet \"restore\" | tail -5",
                "compact --mode build --keep-log -- dotnet \"restore\"",
            ),
            (
                "cargo \"test\" | tail -5",
                "compact --mode test --keep-log -- cargo \"test\"",
            ),
            (
                "mvn \"test\" | tail -5",
                "compact --mode test --keep-log -- mvn \"test\"",
            ),
        ];
        for &(input, expected_tail) in cases {
            let expected = Some(format!("{KIT} {expected_tail}"));
            // Without RTK every eligible runner rewrites the same way.
            assert_eq!(expected, rewrite_command_str(input, KIT, false, None), "rtk=false {input}");
            // With RTK only the literal claimed spellings defer (None); the
            // rest keep the same keep-log rewrite.
            let deferred = matches!(
                input,
                "python -m pytest | tail -5" | "dotnet restore | tail -5"
            );
            let expected_rtk = if deferred { None } else { expected.clone() };
            assert_eq!(expected_rtk, rewrite_command_str(input, KIT, true, None), "rtk=true {input}");
        }
        // Literal claimed spellings still defer under RTK — including tabs
        // between later flag tokens and space-tab before the subcommand,
        // with or without the folded `2>&1`.
        for input in [
            "pytest | tail -5",
            "pytest tests -q | tail -20",
            "pytest tests -q 2>&1 | tail -20",
            "python3 -m pytest | tail -5",
            "cargo test | tail -5",
            "cargo test\t-q | tail -5",
            "cargo \ttest | tail -5",
            "cargo test 2>&1 | tail -5",
            "dotnet build\t-v | tail -5",
            "go test\t-race | tail -5",
            "mvn test | tail -5",
        ] {
            assert_eq!(None, rewrite_command_str(input, KIT, true, None), "rtk defer {input}");
            assert!(
                rewrite_command_str(input, KIT, false, None).is_some(),
                "rtk=false rewrite {input}"
            );
        }
        // Measured non-claims: a tab right after the executable, doubled or
        // tabbed spacing inside the literal python prefix, and a tab where
        // RTK demands the ASCII-space boundary all keep the kit log.
        for (input, expected_tail) in [
            ("cargo\ttest | tail -5", "compact --mode test --keep-log -- cargo\ttest"),
            ("pytest\t-q | tail -5", "compact --mode test --keep-log -- pytest\t-q"),
            (
                "python  -m pytest | tail -5",
                "compact --mode test --keep-log -- python  -m pytest",
            ),
            (
                "python -m pytest\t-q | tail -5",
                "compact --mode test --keep-log -- python -m pytest\t-q",
            ),
            (
                "python\t-m pytest | tail -5",
                "compact --mode test --keep-log -- python\t-m pytest",
            ),
        ] {
            let expected = Some(format!("{KIT} {expected_tail}"));
            assert_eq!(expected, rewrite_command_str(input, KIT, true, None), "rtk={input}");
            assert_eq!(expected, rewrite_command_str(input, KIT, false, None), "plain={input}");
        }
    }

    #[test]
    fn truncated_runner_rejects_token_expansions() {
        for cmd in [
            "dotnet test $FILTER | tail -5",
            "dotnet test *.cs | tail -5",
            "dotnet test ~ | tail -5",
            "pytest tests/${DIR} | tail -5",
            "cd $HOME && dotnet test | tail -5",
            "cd ~/src && dotnet test | tail -5",
        ] {
            assert_eq!(None, rewrite_command_str(cmd, KIT, false, None), "cmd={cmd}");
            assert_eq!(None, rewrite_command_str(cmd, KIT, true, None), "rtk cmd={cmd}");
        }
        // Plain (non-piped) commands keep their existing expansion tolerance.
        assert!(
            rewrite_command_str("dotnet test $FILTER", KIT, false, None).is_some(),
            "plain commands are unchanged"
        );
    }

    #[test]
    fn truncated_runner_rejects_escaped_whitespace() {
        for cmd in [
            "dotnet test --filter=A\\ B | tail -5",
            "dotnet test foo\\ bar | tail -5",
            "pytest tests\\ -q | tail -5",
        ] {
            assert_eq!(None, rewrite_command_str(cmd, KIT, false, None), "cmd={cmd}");
            assert_eq!(None, rewrite_command_str(cmd, KIT, true, None), "rtk cmd={cmd}");
        }
        // A quoted backslash-space is literal argument text, not an escape.
        assert_eq!(
            Some(format!(
                "{KIT} compact --mode test --keep-log -- dotnet test 'a\\ b'"
            )),
            rewrite_command_str("dotnet test 'a\\ b' | tail -5", KIT, false, None)
        );
    }

    #[test]
    fn truncated_runner_unsupported_syntax_and_chains_pass_through() {
        // Quoted parentheses and a single-quoted dollar stay literal args.
        assert_eq!(
            Some(format!(
                "{KIT} compact --mode test --keep-log -- dotnet test --filter='(a|b)'"
            )),
            rewrite_command_str("dotnet test --filter='(a|b)' | tail -5", KIT, false, None)
        );
        assert_eq!(
            Some(format!(
                "{KIT} compact --mode test --keep-log -- dotnet test --name='$x'"
            )),
            rewrite_command_str("dotnet test --name='$x' | tail -5", KIT, false, None)
        );
        assert_eq!(
            Some(format!(
                "{KIT} compact --mode test --keep-log -- dotnet test \"foo$\""
            )),
            rewrite_command_str("dotnet test \"foo$\" | tail -5", KIT, false, None)
        );
        // Unquoted parens, the `$"…"` locale form, an extra filter in the
        // chain, and a second `cd` all pass through untouched — matcher
        // only, nothing is executed.
        for cmd in [
            "dotnet test (release) | tail -5",
            "dotnet test foo) | tail -5",
            "jest () ( echo hi ) | tail -5",
            "pytest !(slow) | tail -5",
            "dotnet test $\"hello\" | tail -5",
            "dotnet test $\".env\" | tail -5",
            "dotnet test --settings $\".env\"",
            "cd $\".ssh\" && git status",
            "cat $\".env\"",
            "dotnet test | grep FAIL",
            "dotnet test | grep error | tail -5",
            "cd a && cd b && dotnet test | tail -5",
        ] {
            assert_eq!(None, rewrite_command_str(cmd, KIT, false, None), "cmd={cmd}");
            assert_eq!(None, rewrite_command_str(cmd, KIT, true, None), "rtk cmd={cmd}");
        }
    }

    #[test]
    fn shared_shell_policy_supports_tier1_rewrite_tier2_deny_once_and_rtk_deferral() {
        let _g = env_guard();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("prom_tier2_{}_{nanos}", std::process::id()));
        let rt = tmp.join("xdg");
        let repo = tmp.join("repo");
        fs::create_dir_all(&rt).unwrap();
        fs::create_dir_all(&repo).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rt, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _env = EnvOverride::set(&[
            ("XDG_RUNTIME_DIR", Some(rt.to_str().unwrap())),
            ("PROMETHEUS_KIT_NO_REWRITE", None),
            ("PROMETHEUS_KIT_RTK_COEXIST", Some("0")),
        ]);
        let mut inp = Map::new();
        inp.insert("command".into(), json!("git status"));
        let sid = format!("s-tier2-{nanos}");

        // Tier 1 rewrites directly.
        match evaluate_shell_policy("claude", ShellPolicyTier::Rewrite, "Bash", &inp, &sid, Some(&repo)) {
            ShellAction::Rewrite { command_key, rewritten, .. } => {
                assert_eq!(command_key, "command");
                assert!(rewritten.contains("diff --status"), "{rewritten}");
            }
            other => panic!("expected Rewrite, got {other:?}"),
        }

        // Tier 2 denies once naming the exact kit command, allows immediate retry,
        // and denies again on a later repeat.
        match evaluate_shell_policy("grok", ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo)) {
            ShellAction::DenyOnce { reason, suggested, .. } => {
                assert!(suggested.contains("diff --status"), "{suggested}");
                assert!(reason.contains(&suggested), "{reason}");
            }
            other => panic!("expected DenyOnce, got {other:?}"),
        }
        assert_eq!(
            ShellAction::Pass,
            evaluate_shell_policy("grok", ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo))
        );
        assert!(matches!(
            evaluate_shell_policy("grok", ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo)),
            ShellAction::DenyOnce { .. }
        ));

        // With RTK active, RTK-owned commands defer in BOTH Tier 1 and Tier 2,
        // while RTK-gap commands (`dotnet test`) still apply in both tiers.
        let _rtk = EnvOverride::set(&[("PROMETHEUS_KIT_RTK_COEXIST", Some("1"))]);
        assert_eq!(
            ShellAction::Pass,
            evaluate_shell_policy("claude", ShellPolicyTier::Rewrite, "Bash", &inp, &sid, Some(&repo))
        );
        assert_eq!(
            ShellAction::Pass,
            evaluate_shell_policy("grok", ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo))
        );

        let mut dt_inp = Map::new();
        dt_inp.insert("command".into(), json!("dotnet test"));
        assert!(matches!(
            evaluate_shell_policy("grok", ShellPolicyTier::DenyOnce, "bash", &dt_inp, &sid, Some(&repo)),
            ShellAction::DenyOnce { .. }
        ));

        // Antigravity CommandLine key is also supported by the shared helper.
        let mut agy_inp = Map::new();
        agy_inp.insert("CommandLine".into(), json!("dotnet test"));
        match evaluate_shell_policy("antigravity", ShellPolicyTier::Rewrite, "run_command", &agy_inp, &sid, Some(&repo)) {
            ShellAction::Rewrite { command_key, rewritten, .. } => {
                assert_eq!(command_key, "CommandLine");
                assert!(rewritten.contains("compact --mode test"), "{rewritten}");
            }
            other => panic!("expected CommandLine Rewrite, got {other:?}"),
        }

        // Tier-2 fails open on unwritable session directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if unsafe { libc::getuid() } != 0 {
                let _no_rtk = EnvOverride::set(&[("PROMETHEUS_KIT_RTK_COEXIST", Some("0"))]);
                let ro_sid = format!("s-ro-{nanos}");
                let parent = rt.join("prometheus");
                let ro_dir = parent.join(&ro_sid);
                fs::create_dir_all(&ro_dir).unwrap();
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o500)).unwrap();
                assert_eq!(
                    ShellAction::Pass,
                    evaluate_shell_policy("grok", ShellPolicyTier::DenyOnce, "bash", &inp, &ro_sid, Some(&repo))
                );
                fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rtk_hook_active_detects_all_host_configs_and_rejects_relative_env_dirs() {
        let _g = env_guard();
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let tmp = std::env::temp_dir().join(format!("prom_rtk_cfg_{}_{nanos}", std::process::id()));
        let home = tmp.join("home");
        let xdg = tmp.join("xdg_cfg");
        let agy = tmp.join("agy_cfg");
        fs::create_dir_all(home.join(".grok/hooks")).unwrap();
        fs::create_dir_all(home.join(".cursor")).unwrap();
        fs::create_dir_all(xdg.join("devin")).unwrap();
        fs::create_dir_all(&agy).unwrap();

        let rtk_json = json!({"PreToolUse": [{"hooks": [{"type": "command", "command": "rtk hook"}]}]}).to_string();
        fs::write(home.join(".grok/hooks/rtk.json"), &rtk_json).unwrap();
        fs::write(home.join(".cursor/hooks.json"), &rtk_json).unwrap();
        fs::write(xdg.join("devin/config.json"), &rtk_json).unwrap();
        fs::write(agy.join("hooks.json"), &rtk_json).unwrap();

        // Pure path resolution & grok dir scan work without mutating process-wide HOME.
        assert!(grok_dir_has_rtk_hook_in(Some(&home)));
        assert!(!grok_dir_has_rtk_hook_in(None));
        assert!(!grok_dir_has_rtk_hook_in(Some(Path::new("relative/home"))));

        assert_eq!(
            Some(home.join(".cursor/hooks.json")),
            host_hooks_config_path_in("cursor", Some(&home), Some(&xdg), Some(&agy))
        );
        assert!(json_file_has_rtk_hook(
            &host_hooks_config_path_in("cursor", Some(&home), None, None).unwrap()
        ));
        // Env overrides (XDG_CONFIG_HOME / AGY_CONFIG_DIR) resolve even when home is None.
        assert_eq!(
            Some(xdg.join("devin/config.json")),
            host_hooks_config_path_in("devin", None, Some(&xdg), None)
        );
        assert_eq!(
            Some(agy.join("hooks.json")),
            host_hooks_config_path_in("antigravity", None, None, Some(&agy))
        );
        // Relative dirs are rejected (defense-in-depth).
        assert_eq!(
            None,
            host_hooks_config_path_in(
                "cursor",
                Some(Path::new("relative/home")),
                Some(Path::new("relative/xdg")),
                Some(Path::new("relative/agy")),
            )
        );
        assert_eq!(
            None,
            host_hooks_config_path_in("devin", None, Some(Path::new("relative/xdg")), None)
        );
        assert_eq!(
            None,
            host_hooks_config_path_in("antigravity", None, None, Some(Path::new("relative/agy")))
        );

        // Live env resolution for XDG_CONFIG_HOME and AGY_CONFIG_DIR (no HOME mutation).
        {
            let _env = EnvOverride::set(&[
                ("PROMETHEUS_KIT_RTK_COEXIST", None),
                ("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap())),
                ("AGY_CONFIG_DIR", Some(agy.to_str().unwrap())),
            ]);
            assert!(rtk_hook_active("devin"));
            assert!(rtk_hook_active("antigravity"));
        }
        {
            let _env = EnvOverride::set(&[
                ("PROMETHEUS_KIT_RTK_COEXIST", None),
                ("XDG_CONFIG_HOME", Some("relative/xdg")),
                ("AGY_CONFIG_DIR", Some("relative/agy")),
            ]);
            assert_eq!(None, abs_env_dir("XDG_CONFIG_HOME"));
            assert_eq!(None, abs_env_dir("AGY_CONFIG_DIR"));
        }
        let _ = fs::remove_dir_all(&tmp);
    }
}
