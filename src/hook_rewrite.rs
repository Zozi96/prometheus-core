//! Deterministic `PreToolUse` command auto-rewrite rules (coexists with RTK).
//!
//! Rewrites eligible read/search/diff/build/test shell commands into
//! `prometheus-kit` invocations using the host `updatedInput` envelope, without
//! changing `permissionDecision`.

use serde_json::{Map, Value};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

pub mod rules;

pub use rules::shell_rewrite_rules;

const MAX_HOOK_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShellToken {
    value: String,
    has_expansion: bool,
}

/// `PROMETHEUS_KIT_NO_REWRITE=1` in a raw env value (read once at the edge).
pub(crate) fn rewrite_disabled_from(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
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

/// RTK-hook presence for `host` from host configuration files only, given
/// the home / XDG / Antigravity config dirs as values. Called once while the
/// ambient facts are built at the hook edge (#102); the decision itself never
/// reads a host configuration file.
pub(crate) fn rtk_config_active_in(
    host: crate::hook_decide::Host,
    home: Option<&Path>,
    xdg: Option<&Path>,
    agy: Option<&Path>,
) -> bool {
    if host == crate::hook_decide::Host::Grok {
        return grok_dir_has_rtk_hook_in(home);
    }
    let Some(config_path) = host_hooks_config_path_in(host, home, xdg, agy) else {
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

fn host_hooks_config_path_in(
    host: crate::hook_decide::Host,
    home: Option<&Path>,
    xdg: Option<&Path>,
    agy: Option<&Path>,
) -> Option<PathBuf> {
    let abs_home = home.filter(|p| p.is_absolute());
    let abs_xdg = xdg.filter(|p| p.is_absolute());
    let abs_agy = agy.filter(|p| p.is_absolute());
    match host {
        crate::hook_decide::Host::Droid => Some(abs_home?.join(".factory").join("hooks.json")),
        crate::hook_decide::Host::Claude => Some(abs_home?.join(".claude").join("settings.json")),
        crate::hook_decide::Host::Cursor => Some(abs_home?.join(".cursor").join("hooks.json")),
        crate::hook_decide::Host::Devin => {
            let base = match abs_xdg {
                Some(dir) => dir.to_path_buf(),
                None => abs_home?.join(".config"),
            };
            Some(base.join("devin").join("config.json"))
        }
        crate::hook_decide::Host::Antigravity => {
            let base = match abs_agy {
                Some(dir) => dir.to_path_buf(),
                None => abs_home?.join(".gemini").join("config"),
            };
            Some(base.join("hooks.json"))
        }
        crate::hook_decide::Host::Muse => {
            let base = match abs_xdg {
                Some(dir) => dir.to_path_buf(),
                None => abs_home?.join(".config"),
            };
            Some(base.join("muse").join("settings.json"))
        }
        _ => None,
    }
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

fn kit_bin_quoted(ambient: &crate::hook::AmbientFacts) -> Option<String> {
    try_shell_quote(&ambient.exe_path.to_string_lossy())
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
    // Piped truncation is runner-only inside the rule table: compact keeps
    // the guaranteed raw log instead of the pipe's silent cut.
    let context = rules::RewriteContext {
        kit_bin,
        truncated: truncated.is_some(),
        rest,
        cd_prefix,
        event_cwd,
    };
    let rewritten_tail = rules::rewrite_with_rule_table(&cmd0, &tokens, rtk_active, &context)?;

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
    /// Pass, but the attempt produced metrics (a Guided deny-once retry
    /// records AllowedRetry even though the command runs).
    PassWithMetrics(Vec<crate::metrics::MetricRecord>),
    Rewrite {
        command_key: String,
        rewritten: String,
        raw_bytes: usize,
        metrics: Vec<crate::metrics::MetricRecord>,
    },
    DenyOnce {
        reason: String,
        suggested: String,
        raw_bytes: usize,
        metrics: Vec<crate::metrics::MetricRecord>,
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
    ambient: &crate::hook::AmbientFacts,
    rtk_active: bool,
    tier: ShellPolicyTier,
    tool_name: &str,
    tool_input: &Map<String, Value>,
    session_id: &str,
    event_cwd: Option<&Path>,
) -> ShellAction {
    if ambient.rewrite_disabled || !is_shell_tool(tool_name) {
        return ShellAction::Pass;
    }
    let Some((command_key, command)) = extract_shell_command(tool_input) else {
        return ShellAction::Pass;
    };
    let Some(kit_bin) = kit_bin_quoted(ambient) else {
        return ShellAction::Pass;
    };
    let Some(rewritten) = rewrite_command_str(command, &kit_bin, rtk_active, event_cwd) else {
        return ShellAction::Pass;
    };
    let rewritten_len = rewritten.len();
    match tier {
        ShellPolicyTier::Rewrite => ShellAction::Rewrite {
            command_key: command_key.to_owned(),
            rewritten,
            raw_bytes: command.len(),
            metrics: vec![crate::metrics::MetricRecord {
                rule: crate::metrics::Rule::ShellRewrite,
                raw_bytes: command.len(),
                emitted_bytes: rewritten_len,
            }],
        },
        ShellPolicyTier::DenyOnce => {
            match crate::hook::shell_deny_once_decision(session_id, event_cwd, command, &rewritten, ambient) {
                (Some(reason), metrics) => ShellAction::DenyOnce {
                    reason,
                    suggested: rewritten,
                    raw_bytes: command.len(),
                    metrics,
                },
                (None, metrics) if metrics.is_empty() => ShellAction::Pass,
                (None, metrics) => ShellAction::PassWithMetrics(metrics),
            }
        }
    }
}

#[cfg(test)]
mod tests {

    fn base_amb() -> crate::hook::AmbientFacts {
        let mut a = crate::hook::AmbientFacts {
            other_host_markers_present: false,
            devin_project_dir: None,
            rewrite_disabled: false,
            rtk_coexist: None,
            rtk_config_active: std::collections::BTreeMap::new(),
            xdg_runtime_dir: None,
            temp_dir: std::env::temp_dir(),
            session_parent: PathBuf::new(),
            process_cwd: std::env::current_dir().ok(),
            home_dir: None,
            xdg_config_home: None,
            agy_config_dir: None,
            exe_path: std::env::current_exe()
                .unwrap_or_else(|_| PathBuf::from("prometheus-kit")),
        };
        a.recompute_derived();
        a
    }
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

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
                "gh run view 12345 --job foo= --log",
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
                "gh run view 12345 --job=foo= --log",
                "gh run view 12345 --attempt=2= --log",
                "gh run view 12345 --repo=owner/repo= --log",
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
            let amb = {
                let mut a = base_amb();
                a.home_dir = Some(PathBuf::from(tmp.to_str().unwrap()));
                a.home_dir = Some(PathBuf::from(tmp.to_str().unwrap()));
                a.rtk_coexist = None;
                a.rewrite_disabled = false;
                a.recompute_derived();
                a
            };
            assert!(amb.rtk_active(crate::hook_decide::Host::Droid));
            assert!(!amb.rtk_active(crate::hook_decide::Host::Claude));

            // With RTK active on droid: git diff passes through, dotnet test
            // rewrites. (The reply-envelope assertions that used the deleted
            // rewrite_command_reply helper are covered at the entry point by
            // hook::tests::direct_checks_and_edits_pass_across_hosts and the
            // adapter reply tests in hook_decide.)
            let git_ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Execute",
                "tool_input": {"command": "git status", "summary": "s", "riskLevel": "low"}
            });
            assert!(matches!(
                evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Droid), ShellPolicyTier::Rewrite, "Execute", git_ev["tool_input"].as_object().unwrap(), "", None),
                ShellAction::Pass | ShellAction::PassWithMetrics(_)
            ));

            let dotnet_ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Execute",
                "tool_input": {"command": "dotnet test App.csproj", "summary": "run tests", "riskLevel": "medium", "timeout": 120}
            });
            match evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Droid), ShellPolicyTier::Rewrite, "Execute", dotnet_ev["tool_input"].as_object().unwrap(), "", None) {
                ShellAction::Rewrite { rewritten, .. } => {
                    assert!(rewritten.contains("compact --mode test -- dotnet test App.csproj"), "{rewritten}");
                }
                other => panic!("expected Rewrite, got {other:?}"),
            }
        }

        {
            let amb = {
                let mut a = base_amb();
                a.home_dir = Some(PathBuf::from(tmp.to_str().unwrap()));
                a.rtk_coexist = None;
                a.rewrite_disabled = true;
                a.recompute_derived();
                a
            };
            let dotnet_inp = {
                let mut m = Map::new();
                m.insert("command".into(), json!("dotnet test"));
                m
            };
            assert!(matches!(
                evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Claude), ShellPolicyTier::Rewrite, "Bash", &dotnet_inp, "", None),
                ShellAction::Pass
            ));
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
            let amb = {
                let mut a = base_amb();
                a.home_dir = Some(PathBuf::from(fifo_home.to_str().unwrap()));
                a.rtk_coexist = None;
                a.recompute_derived();
                a
            };
            assert!(!amb.rtk_active(crate::hook_decide::Host::Droid));
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rewrite_rule_metadata_is_enumerable_versioned_and_complete() {
        let rules = shell_rewrite_rules();
        assert!(rules.len() >= 11);
        let mut ids = std::collections::BTreeSet::new();
        let mut families = std::collections::BTreeSet::new();
        for rule in rules {
            assert!(ids.insert(rule.id), "duplicate rule id {}", rule.id);
            assert_eq!(rules::RTK_VERIFIED_VERSION, rule.rtk.verified_version, "{}", rule.id);
            assert!(!rule.head.commands.is_empty(), "{}", rule.id);
            families.insert(match rule.target {
                rules::TargetSpec::SliceSedRange => "slice-range",
                rules::TargetSpec::GitStatus | rules::TargetSpec::GitDiff | rules::TargetSpec::GitShow => {
                    "git-diff"
                }
                rules::TargetSpec::SearchRg | rules::TargetSpec::SearchGrep => "search",
                rules::TargetSpec::FileDump(_) => "file-dump",
                rules::TargetSpec::CompactLog => "compact-log",
                rules::TargetSpec::CompactRunner { .. } => "compact-runner",
            });
            if let rules::ParserSpec::Structured(spec) = rule.parser {
                if let Some(id) = spec.numeric_short_flag {
                    assert!(
                        spec.flags.iter().any(|flag| flag.id == id),
                        "numeric short flag {id} in {} has no flag spec",
                        rule.id
                    );
                }
                let mut flag_ids = std::collections::BTreeSet::new();
                for flag in spec.flags {
                    assert!(flag_ids.insert(flag.id), "duplicate flag {} in {}", flag.id, rule.id);
                    assert!(
                        !flag.exact.is_empty() || !flag.attached_prefixes.is_empty() || flag.cluster.is_some(),
                        "flag {} in {} has no spelling",
                        flag.id,
                        rule.id
                    );
                    if !flag.attached_prefixes.is_empty() {
                        assert!(flag.value.is_some(), "attached valueless flag {} in {}", flag.id, rule.id);
                    }
                    if flag.cluster.is_some() {
                        assert!(flag.value.is_none(), "clustered value flag {} in {}", flag.id, rule.id);
                    }
                }
            }
        }
        for family in [
            "slice-range",
            "git-diff",
            "search",
            "file-dump",
            "compact-log",
            "compact-runner",
        ] {
            assert!(families.contains(family), "missing rewrite family {family}");
        }
    }

    #[test]
    fn truncated_runner_table_covers_groups_tails_counts_and_rtk() {
        // Independent oracle for runner mode and measured piped RTK deferral.
        // Metadata enumeration below only checks that the declarative table is
        // complete against this oracle; behavior expectations never derive
        // from the implementation under test.
        let runners: &[(&str, &str, bool)] = &[
            ("dotnet test", "test", false),
            ("dotnet restore", "build", true),
            ("dotnet format", "build", false),
            ("dotnet build", "build", true),
            ("msbuild", "build", false),
            ("msbuild.exe", "build", false),
            ("python -m unittest", "test", false),
            ("python3 -m unittest", "test", false),
            ("python -m pytest", "test", true),
            ("python3 -m pytest", "test", true),
            ("npm test", "test", false),
            ("npm run test", "test", false),
            ("pnpm test", "test", false),
            ("yarn test", "test", false),
            ("bun test", "test", false),
            ("mvn test", "test", true),
            ("gradle test", "test", false),
            ("gradlew test", "test", false),
            ("./gradlew test", "test", false),
            ("cargo build", "build", true),
            ("cargo check", "build", true),
            ("cargo clippy", "build", true),
            ("cargo test", "test", true),
            ("go build", "build", true),
            ("go test", "test", true),
            ("tsc", "build", false),
            ("pytest", "test", true),
            ("jest", "test", false),
            ("vitest", "test", false),
        ];

        let mut metadata_runners = std::collections::BTreeSet::new();
        for rule in shell_rewrite_rules() {
            let rules::TargetSpec::CompactRunner { mode } = rule.target else {
                continue;
            };
            let piped_deferred = match rule.rtk.posture {
                rules::RtkPosture::Runner {
                    piped_claim: rules::RtkPipedClaim::None,
                    ..
                } => false,
                rules::RtkPosture::Runner { .. } => true,
                _ => false,
            };
            for command in rule.head.commands {
                let mut words = vec![(*command).to_owned()];
                words.extend(rule.head.argv_prefix.iter().map(|word| (*word).to_owned()));
                let runner = words.join(" ");
                metadata_runners.insert((runner.clone(), mode, piped_deferred));
                if *command == "gradlew" {
                    metadata_runners.insert((format!("./{runner}"), mode, piped_deferred));
                }
            }
        }
        let oracle: std::collections::BTreeSet<_> = runners
            .iter()
            .map(|(runner, mode, deferred)| ((*runner).to_owned(), *mode, *deferred))
            .collect();
        assert_eq!(oracle, metadata_runners, "runner metadata does not match independent oracle");

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
        for &(runner, mode, rtk_deferred) in runners {
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
                    let expected_rtk = if rtk_deferred { None } else { expected.clone() };
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
        let amb = {
            let mut a = base_amb();
            a.xdg_runtime_dir = Some(PathBuf::from(rt.to_str().unwrap()));
            a.rewrite_disabled = false;
            a.rtk_coexist = Some("0".to_string());
            a.recompute_derived();
            a
        };
        let mut inp = Map::new();
        inp.insert("command".into(), json!("git status"));
        let sid = format!("s-tier2-{nanos}");

        // Tier 1 rewrites directly.
        match evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Claude), ShellPolicyTier::Rewrite, "Bash", &inp, &sid, Some(&repo)) {
            ShellAction::Rewrite { command_key, rewritten, .. } => {
                assert_eq!(command_key, "command");
                assert!(rewritten.contains("diff --status"), "{rewritten}");
            }
            other => panic!("expected Rewrite, got {other:?}"),
        }

        // Tier 2 denies once naming the exact kit command, allows immediate retry,
        // and denies again on a later repeat.
        match evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Grok), ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo)) {
            ShellAction::DenyOnce { reason, suggested, .. } => {
                assert!(suggested.contains("diff --status"), "{suggested}");
                assert!(reason.contains(&suggested), "{reason}");
            }
            other => panic!("expected DenyOnce, got {other:?}"),
        }
        // The retry passes, carrying the AllowedRetry metric as data (#103;
        // the same behaviour is asserted at the decide interface in
        // hook_decide::tests::decide_table_secret_rewrite_deny_once_advisory_hint_pass).
        match evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Grok), ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo)) {
            ShellAction::PassWithMetrics(metrics) => {
                assert_eq!(1, metrics.len());
                assert_eq!(crate::metrics::Rule::AllowedRetry, metrics[0].rule);
            }
            other => panic!("expected PassWithMetrics, got {other:?}"),
        }
        assert!(matches!(
            evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Grok), ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo)),
            ShellAction::DenyOnce { .. }
        ));

        // With RTK active, RTK-owned commands defer in BOTH Tier 1 and Tier 2,
        // while RTK-gap commands (`dotnet test`) still apply in both tiers.
        let amb = {
            let mut a = amb.clone();
            a.rtk_coexist = Some("1".to_string());
            a.recompute_derived();
            a
        };
        assert_eq!(
            ShellAction::Pass,
            evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Claude), ShellPolicyTier::Rewrite, "Bash", &inp, &sid, Some(&repo))
        );
        assert_eq!(
            ShellAction::Pass,
            evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Grok), ShellPolicyTier::DenyOnce, "bash", &inp, &sid, Some(&repo))
        );

        let mut dt_inp = Map::new();
        dt_inp.insert("command".into(), json!("dotnet test"));
        assert!(matches!(
            evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Grok), ShellPolicyTier::DenyOnce, "bash", &dt_inp, &sid, Some(&repo)),
            ShellAction::DenyOnce { .. }
        ));

        // Antigravity CommandLine key is also supported by the shared helper.
        let mut agy_inp = Map::new();
        agy_inp.insert("CommandLine".into(), json!("dotnet test"));
        match evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Antigravity), ShellPolicyTier::Rewrite, "run_command", &agy_inp, &sid, Some(&repo)) {
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
                let amb = {
                    let mut a = amb.clone();
                    a.rtk_coexist = Some("0".to_string());
                    a.recompute_derived();
                    a
                };
                let ro_sid = format!("s-ro-{nanos}");
                let parent = rt.join("prometheus");
                let ro_dir = parent.join(&ro_sid);
                fs::create_dir_all(&ro_dir).unwrap();
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o500)).unwrap();
                assert_eq!(
                    ShellAction::Pass,
                    evaluate_shell_policy(&amb, amb.rtk_active(crate::hook_decide::Host::Grok), ShellPolicyTier::DenyOnce, "bash", &inp, &ro_sid, Some(&repo))
                );
                fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rtk_hook_active_detects_all_host_configs_and_rejects_relative_env_dirs() {
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
            host_hooks_config_path_in(crate::hook_decide::Host::Cursor, Some(&home), Some(&xdg), Some(&agy))
        );
        assert!(json_file_has_rtk_hook(
            &host_hooks_config_path_in(crate::hook_decide::Host::Cursor, Some(&home), None, None).unwrap()
        ));
        // Env overrides (XDG_CONFIG_HOME / AGY_CONFIG_DIR) resolve even when home is None.
        assert_eq!(
            Some(xdg.join("devin/config.json")),
            host_hooks_config_path_in(crate::hook_decide::Host::Devin, None, Some(&xdg), None)
        );
        assert_eq!(
            Some(agy.join("hooks.json")),
            host_hooks_config_path_in(crate::hook_decide::Host::Antigravity, None, None, Some(&agy))
        );
        // Relative dirs are rejected (defense-in-depth).
        assert_eq!(
            None,
            host_hooks_config_path_in(
                crate::hook_decide::Host::Cursor,
                Some(Path::new("relative/home")),
                Some(Path::new("relative/xdg")),
                Some(Path::new("relative/agy")),
            )
        );
        assert_eq!(
            None,
            host_hooks_config_path_in(crate::hook_decide::Host::Devin, None, Some(Path::new("relative/xdg")), None)
        );
        assert_eq!(
            None,
            host_hooks_config_path_in(crate::hook_decide::Host::Antigravity, None, None, Some(Path::new("relative/agy")))
        );

        // Live env resolution for XDG_CONFIG_HOME and AGY_CONFIG_DIR (no HOME mutation).
        {
            let amb = {
                let mut a = base_amb();
                a.rtk_coexist = None;
                a.xdg_config_home = Some(PathBuf::from(xdg.to_str().unwrap()));
                a.agy_config_dir = Some(PathBuf::from(agy.to_str().unwrap()));
                a.recompute_derived();
                a
            };
            assert!(amb.rtk_active(crate::hook_decide::Host::Devin));
            assert!(amb.rtk_active(crate::hook_decide::Host::Antigravity));
        }
        {
            let amb = {
                let mut a = base_amb();
                a.rtk_coexist = None;
                a.xdg_config_home = Some(PathBuf::from("relative/xdg"));
                a.agy_config_dir = Some(PathBuf::from("relative/agy"));
                a.recompute_derived();
                a
            };
            // Relative config dirs are rejected when the ambient facts are
            // built, so neither host reports an RTK hook.
            assert!(!amb.rtk_active(crate::hook_decide::Host::Devin));
            assert!(!amb.rtk_active(crate::hook_decide::Host::Antigravity));
        }
        let _ = fs::remove_dir_all(&tmp);
    }
}
