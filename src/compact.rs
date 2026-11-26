//! Deterministic CLI, build, test, and log output compactor (`prometheus-kit compact`).

use crate::budget::{self, KeepPolicy};
use crate::check::Counts;
use crate::kit_util::{approx_tokens, clip_end, strip_ansi_and_cr, write_spillover_log};
use crate::failure_summary::{failure_omission_notice, render_failure_summary};
use crate::logs::{parse_log, FailureDetail};
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

pub const DEFAULT_COMPACT_MAX_TOKENS: usize = 1500;
pub const DEFAULT_COMPACT_TAIL_LINES: usize = 25;
const MAX_LINE_CHARS: usize = 260;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactMode {
    Auto,
    Build,
    Test,
    Log,
    Generic,
}

impl CompactMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(CompactMode::Auto),
            "build" => Some(CompactMode::Build),
            "test" => Some(CompactMode::Test),
            "log" => Some(CompactMode::Log),
            "generic" => Some(CompactMode::Generic),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CompactMode::Auto => "auto",
            CompactMode::Build => "build",
            CompactMode::Test => "test",
            CompactMode::Log => "log",
            CompactMode::Generic => "generic",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompactOptions {
    pub mode: CompactMode,
    pub max_tokens: usize,
    pub tail_lines: usize,
    pub save_log: Option<PathBuf>,
    pub allow_spillover: bool,
}

impl Default for CompactOptions {
    fn default() -> Self {
        Self {
            mode: CompactMode::Auto,
            max_tokens: DEFAULT_COMPACT_MAX_TOKENS,
            tail_lines: DEFAULT_COMPACT_TAIL_LINES,
            save_log: None,
            allow_spillover: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiagnosticGroup {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub count: usize,
    pub locations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompactResult {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_counts: Option<Counts>,
    pub diagnostics: Vec<DiagnosticGroup>,
    pub failing_lines: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failure_details: Vec<FailureDetail>,
    #[serde(skip)]
    pub failure_total: usize,
    /// Set when the caller already prints the log pointer (compact --keep-log).
    #[serde(skip)]
    pub log_path_in_prefix: bool,
    pub lines: Vec<String>,
    pub raw_lines: usize,
    pub raw_tokens: usize,
    pub out_tokens: usize,
    pub saved_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    pub truncated: bool,
    pub omitted_items: usize,
    /// Budget-trimmed typed failure rows, already included in `omitted_items`.
    #[serde(skip)]
    pub omitted_failure_details: usize,
    /// Byte length of the raw input this result was compacted from; metrics-only.
    #[serde(skip)]
    pub raw_bytes: usize,
}

/// Run an external command, compact its combined stdout + stderr, and preserve its exit code.
pub fn compact_command(
    command: &[String],
    opts: &CompactOptions,
) -> Result<(CompactResult, i32), String> {
    if command.is_empty() {
        return Err("compact: expected a command after `--`".to_owned());
    }
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", command[0]))?;

    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();

    let out_handle = std::thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(ref mut r) = out_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = std::thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(ref mut r) = err_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    let status = child.wait().map_err(|e| format!("{}: {e}", command[0]))?;
    let exit_code = status.code().unwrap_or(1);

    let out_bytes = out_handle.join().unwrap_or_default();
    let err_bytes = err_handle.join().unwrap_or_default();
    let mut combined = String::from_utf8_lossy(&out_bytes).into_owned();
    if !err_bytes.is_empty() {
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&err_bytes));
    }

    let mut result = compact_text(&combined, Some(exit_code), opts);
    // Raw is the child's actual stdout+stderr byte counts, before lossy
    // UTF-8 conversion or the inserted separator newline.
    result.raw_bytes = out_bytes.len() + err_bytes.len();
    Ok((result, exit_code))
}

/// Run `command` exactly once, capturing merged stdout+stderr bytes in write
/// order plus the exit status. Unlike [`compact_command`] the raw `Vec<u8>`
/// keeps CR, ANSI escapes, and invalid UTF-8 untouched — `compact
/// --keep-log` persists it as the guaranteed full log. Unix signal deaths
/// report `128 + signal`; other platforms fall back to 1. A mid-capture pipe
/// read error is returned alongside the partial bytes and status in the
/// third tuple element so the caller can emit what arrived without claiming
/// a complete log.
pub fn capture_command_log(
    command: &[String],
) -> std::io::Result<(Vec<u8>, i32, Option<std::io::Error>)> {
    use std::io::Read;
    if command.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty command",
        ));
    }
    // One pipe shared by both streams preserves interleaved write order.
    let (mut reader, writer) = std::io::pipe()?;
    let stdout = writer.try_clone()?;
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdout(stdout)
        .stderr(writer)
        .spawn()?;
    // The builder's writer copies close with it after spawn; only the
    // child's fds remain, so EOF arrives when the child exits.

    let mut raw = Vec::new();
    let read_error = reader.read_to_end(&mut raw).err();
    // Drop our end so a blocked writer sees EPIPE instead of deadlocking the
    // reap below; bytes already read and the exit status stay authoritative.
    drop(reader);
    let status = child.wait()?;
    #[cfg(unix)]
    let code = {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
    };
    #[cfg(not(unix))]
    let code = status.code().unwrap_or(1);
    Ok((raw, code, read_error))
}

struct Regexes {
    msbuild: Regex,
    msbuild_tool: Regex,
    rustc: Regex,
    rust_loc: Regex,
    tsc_dash: Regex,
    generic_diag: Regex,
    py_frame: Regex,
    py_exc: Regex,
    dotnet_framework: Regex,
    js_framework: Regex,
    rust_framework: Regex,
}

fn regexes() -> &'static Regexes {
    static RE: OnceLock<Regexes> = OnceLock::new();
    RE.get_or_init(|| Regexes {
        msbuild: Regex::new(
            r"^\s*(.+?)\((\d+)(?:,\d+)?\):\s*(error|fatal error|warning)\s+([A-Za-z]{1,8}\d+):\s*(.+?)(?:\s+\[[^\]]+\])?\s*$",
        )
        .unwrap(),
        msbuild_tool: Regex::new(
            r"^\s*(?:MSBUILD|CSC|VBC)\s*:\s*(error|warning)\s+([A-Za-z0-9]+):\s*(.+?)\s*$",
        )
        .unwrap(),
        rustc: Regex::new(
            r"^\s*(error|warning)(?:\[([A-Za-z0-9]+)\])?:\s*(.+?)\s*$",
        )
        .unwrap(),
        rust_loc: Regex::new(r"^\s*-->\s*(.+?:\d+:\d+)\s*$").unwrap(),
        tsc_dash: Regex::new(
            r"^\s*(.+?):(\d+):\d+\s*-\s*(error|warning)\s+(TS\d+):\s*(.+?)\s*$",
        )
        .unwrap(),
        generic_diag: Regex::new(
            r"^\s*([^\s:][^:]*):(\d+)(?::\d+)?:\s*(error|fatal error|warning):\s*(.+?)\s*$",
        )
        .unwrap(),
        py_frame: Regex::new(r#"^\s*File "([^"]+)", line (\d+)(?:, in (.+))?\s*$"#).unwrap(),
        py_exc: Regex::new(
            r"^\s*([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Failure|Exit))\s*:\s*(.+?)\s*$",
        )
        .unwrap(),
        dotnet_framework: Regex::new(
            r"^\s*at\s+(?:System|Microsoft|Xunit|NUnit|Moq|Internal)\.",
        )
        .unwrap(),
        js_framework: Regex::new(
            r"^\s*at\s+.*(?:node_modules|node:internal|\(internal/)",
        )
        .unwrap(),
        rust_framework: Regex::new(
            r"^\s*\d+:\s*(?:std|core|alloc|tokio|backtrace)::",
        )
        .unwrap(),
    })
}

fn is_boilerplate_noise(trimmed: &str, mode: CompactMode) -> bool {
    if matches!(mode, CompactMode::Generic) {
        return false;
    }
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("error") || lower.contains("warning") || lower.contains("failed") {
        return false;
    }
    // MSBuild / dotnet restore / build project copy chatter
    if trimmed.starts_with("Determining projects to restore")
        || trimmed.starts_with("All projects are up-to-date for restore")
        || trimmed.starts_with("Restored ")
        || trimmed.starts_with("MSBuild version ")
        || (trimmed.contains(" -> ") && (trimmed.ends_with(".dll") || trimmed.ends_with(".exe")))
    {
        return true;
    }
    // Cargo progress noise
    if trimmed.starts_with("Compiling ")
        || trimmed.starts_with("Downloading ")
        || trimmed.starts_with("Downloaded ")
        || trimmed.starts_with("Updating crates.io index")
        || trimmed.starts_with("Locking ")
        || trimmed.starts_with("Fresh ")
        || trimmed.starts_with("Checking ")
    {
        return true;
    }
    // npm / pip download progress noise
    if trimmed.starts_with("npm http fetch ") || trimmed.starts_with("Collecting ") {
        return true;
    }
    false
}

fn is_framework_frame(line: &str) -> bool {
    let re = regexes();
    if re.dotnet_framework.is_match(line)
        || re.js_framework.is_match(line)
        || re.rust_framework.is_match(line)
    {
        return true;
    }
    if let Some(cap) = re.py_frame.captures(line) {
        let file = &cap[1];
        return file.contains("site-packages")
            || file.contains("/lib/python")
            || file.contains("importlib");
    }
    false
}

fn fold_frames_and_repeats(lines: &[String]) -> Vec<String> {
    // 1. Fold runs of >= 3 framework stack frames
    let mut folded_frames = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    while i < lines.len() {
        if is_framework_frame(&lines[i]) {
            let start = i;
            while i < lines.len() && is_framework_frame(&lines[i]) {
                i += 1;
            }
            let count = i - start;
            if count >= 3 {
                folded_frames.push(lines[start].clone());
                folded_frames.push(format!("... ({} framework frames collapsed)", count - 1));
            } else {
                for line in &lines[start..i] {
                    folded_frames.push(line.clone());
                }
            }
        } else {
            folded_frames.push(lines[i].clone());
            i += 1;
        }
    }

    // 2. Fold consecutive identical non-empty lines
    let mut out: Vec<String> = Vec::with_capacity(folded_frames.len());
    let mut idx = 0usize;
    while idx < folded_frames.len() {
        let cur = &folded_frames[idx];
        let mut run = 1usize;
        while idx + run < folded_frames.len() && folded_frames[idx + run] == *cur {
            run += 1;
        }
        if run > 1 && !cur.trim().is_empty() {
            out.push(format!("{cur} (x{run})"));
        } else {
            for item in &folded_frames[idx..idx + run] {
                out.push(item.clone());
            }
        }
        idx += run;
    }
    out
}

fn push_diag(
    groups: &mut Vec<DiagnosticGroup>,
    index: &mut HashMap<(String, String, String), usize>,
    severity: &str,
    code: &str,
    message: &str,
    location: Option<String>,
) {
    let sev = if severity.contains("error") {
        "error".to_owned()
    } else {
        "warning".to_owned()
    };
    let key = (sev.clone(), code.to_owned(), message.to_owned());
    if let Some(&slot) = index.get(&key) {
        let g = &mut groups[slot];
        g.count += 1;
        if let Some(loc) = location {
            if !g.locations.iter().any(|x| x == &loc) && g.locations.len() < 12 {
                g.locations.push(loc);
            }
        }
    } else {
        let slot = groups.len();
        index.insert(key, slot);
        let mut locations = Vec::new();
        if let Some(loc) = location {
            locations.push(loc);
        }
        groups.push(DiagnosticGroup {
            severity: sev,
            code: code.to_owned(),
            message: message.to_owned(),
            count: 1,
            locations,
        });
    }
}

fn extract_diagnostics(
    lines: &[&str],
    mode: CompactMode,
) -> (Vec<DiagnosticGroup>, HashSet<usize>) {
    let mut groups = Vec::new();
    let mut index = HashMap::new();
    let mut diag_lines = HashSet::new();
    if matches!(mode, CompactMode::Generic) {
        return (groups, diag_lines);
    }

    let re = regexes();
    let mut last_py_loc: Option<String> = None;
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        if let Some(cap) = re.msbuild.captures(line) {
            let loc = format!("{}:{}", cap[1].trim(), &cap[2]);
            push_diag(&mut groups, &mut index, &cap[3], &cap[4], &cap[5], Some(loc));
            diag_lines.insert(i);
            i += 1;
            continue;
        }
        if let Some(cap) = re.tsc_dash.captures(line) {
            let loc = format!("{}:{}", cap[1].trim(), &cap[2]);
            push_diag(&mut groups, &mut index, &cap[3], &cap[4], &cap[5], Some(loc));
            diag_lines.insert(i);
            i += 1;
            continue;
        }
        if let Some(cap) = re.msbuild_tool.captures(line) {
            push_diag(&mut groups, &mut index, &cap[1], &cap[2], &cap[3], None);
            diag_lines.insert(i);
            i += 1;
            continue;
        }
        if let Some(cap) = re.rustc.captures(line) {
            let msg = &cap[3];
            // Skip rustc summary totals (`could not compile ... due to 2 previous errors`, `generated 3 warnings`)
            if !msg.starts_with("could not compile ") && !msg.contains(" generated ") {
                let code = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let mut loc = None;
                if let Some(next_line) = lines.get(i + 1) {
                    if let Some(lcap) = re.rust_loc.captures(next_line) {
                        loc = Some(lcap[1].to_owned());
                        diag_lines.insert(i + 1);
                    }
                }
                push_diag(&mut groups, &mut index, &cap[1], code, msg, loc);
                diag_lines.insert(i);
            }
            i += 1;
            continue;
        }
        if let Some(cap) = re.generic_diag.captures(line) {
            let loc = format!("{}:{}", cap[1].trim(), &cap[2]);
            push_diag(&mut groups, &mut index, &cap[3], "", &cap[4], Some(loc));
            diag_lines.insert(i);
            i += 1;
            continue;
        }
        if let Some(cap) = re.py_frame.captures(line) {
            last_py_loc = Some(format!("{}:{}", &cap[1], &cap[2]));
        } else if let Some(cap) = re.py_exc.captures(trimmed) {
            push_diag(
                &mut groups,
                &mut index,
                "error",
                &cap[1],
                &cap[2],
                last_py_loc.take(),
            );
            diag_lines.insert(i);
        }

        i += 1;
    }

    // Prioritize errors ahead of warnings, preserving relative order within each severity.
    groups.sort_by_key(|g| if g.severity == "error" { 0u8 } else { 1u8 });
    (groups, diag_lines)
}

pub fn format_diagnostic(g: &DiagnosticGroup) -> String {
    let sev = if g.count > 1 {
        format!("[{} x{}]", g.severity, g.count)
    } else {
        format!("[{}]", g.severity)
    };
    let head = if g.code.is_empty() {
        format!("{sev} {}", g.message)
    } else {
        format!("{sev} {}: {}", g.code, g.message)
    };
    let line = if g.locations.is_empty() {
        head
    } else {
        let shown: Vec<&str> = g.locations.iter().take(4).map(String::as_str).collect();
        let extra = if g.count > shown.len() {
            format!(" (+{} more)", g.count - shown.len())
        } else {
            String::new()
        };
        format!("{head} — {}{extra}", shown.join(", "))
    };
    clip_end(&line, MAX_LINE_CHARS).0
}

fn parsed_failure_view(counts: Option<Counts>, details: &[FailureDetail]) -> crate::logs::ParsedLog {
    crate::logs::ParsedLog {
        counts,
        error: None,
        failing_lines: Vec::new(),
        failed_tests: details
            .iter()
            .map(|detail| detail.selector.clone())
            .collect(),
        failure_details: details.to_vec(),
    }
}

fn typed_failure_summary_complete(counts: Option<Counts>, details: &[FailureDetail]) -> bool {
    if details.is_empty() {
        return false;
    }
    let parsed = parsed_failure_view(counts, details);
    !render_failure_summary(&parsed, None)
        .last()
        .is_some_and(|line| line.contains("failures omitted"))
}

fn typed_details_budget_trimmed(res: &CompactResult, max_tokens: usize) -> bool {
    if max_tokens == 0 || res.failure_details.is_empty() {
        return false;
    }
    let original = res.failure_details.len();
    let mut text = res.clone();
    budget::trim_structured(
        &mut text,
        max_tokens,
        |state| render_compact_text_inner(state, true),
        compact_trim_step,
    );
    let mut json = res.clone();
    budget::trim_structured(
        &mut json,
        max_tokens,
        |state| serde_json::to_string(state).unwrap_or_else(|_| "{}".to_owned()),
        compact_trim_step,
    );
    text.failure_details.len() < original || json.failure_details.len() < original
}

pub fn compact_text(raw: &str, exit_code: Option<i32>, opts: &CompactOptions) -> CompactResult {
    let normalized = strip_ansi_and_cr(raw);
    let raw_lines_vec: Vec<&str> = normalized.lines().collect();
    let raw_lines = raw_lines_vec.len();
    let raw_tokens = approx_tokens(raw);

    let (test_counts, mut failing_lines, failure_details) =
        if matches!(opts.mode, CompactMode::Auto | CompactMode::Test) {
            let parsed = parse_log(&normalized, exit_code.map(i64::from));
            let fl: Vec<String> = if parsed.failure_details.is_empty() {
                parsed
                    .failing_lines
                    .iter()
                    .map(|line| clip_end(line.trim(), MAX_LINE_CHARS).0)
                    .collect()
            } else {
                Vec::new()
            };
            (parsed.counts, fl, parsed.failure_details)
        } else {
            (None, Vec::new(), Vec::new())
        };
    let has_typed_failures = !failure_details.is_empty();

    let (mut diagnostics, diag_line_indices) = extract_diagnostics(&raw_lines_vec, opts.mode);
    if has_typed_failures {
        diagnostics.retain(|group| {
            group.message.is_empty()
                || !failure_details.iter().any(|detail| {
                    let with_code = if group.code.is_empty() {
                        group.message.clone()
                    } else {
                        format!("{}: {}", group.code, group.message)
                    };
                    detail.message == with_code || detail.message == group.message
                })
        });
    }

    let mut filtered_lines: Vec<String> = Vec::new();
    for (idx, &line) in raw_lines_vec.iter().enumerate() {
        if diag_line_indices.contains(&idx) {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_boilerplate_noise(trimmed, opts.mode) {
            continue;
        }
        filtered_lines.push(clip_end(line.trim_end(), MAX_LINE_CHARS).0);
    }

    let folded = fold_frames_and_repeats(&filtered_lines);
    let show_tail = matches!(opts.mode, CompactMode::Generic | CompactMode::Log)
        || (diagnostics.is_empty() && test_counts.is_none() && !has_typed_failures)
        || (exit_code.unwrap_or(0) != 0 && !has_typed_failures);

    let selected_lines = if !show_tail || opts.tail_lines == 0 {
        Vec::new()
    } else if folded.len() <= opts.tail_lines {
        folded
    } else if matches!(opts.mode, CompactMode::Generic | CompactMode::Log) && opts.tail_lines > 8 {
        let head_n = 5.min(opts.tail_lines / 3);
        let tail_n = opts.tail_lines - head_n;
        let omitted = folded.len() - head_n - tail_n;
        let mut picked = Vec::with_capacity(opts.tail_lines + 1);
        picked.extend(folded[..head_n].iter().cloned());
        picked.push(format!("... ({omitted} intermediate lines omitted)"));
        picked.extend(folded[folded.len() - tail_n..].iter().cloned());
        picked
    } else {
        let omitted = folded.len() - opts.tail_lines;
        let mut picked = Vec::with_capacity(opts.tail_lines + 1);
        picked.push(format!("... ({omitted} earlier lines omitted)"));
        picked.extend(folded[folded.len() - opts.tail_lines..].iter().cloned());
        picked
    };

    // Deduplicate failing_lines against diagnostic lines if identical
    if !diagnostics.is_empty() && !failing_lines.is_empty() {
        failing_lines.truncate(20);
    }

    let failure_total = if failure_details.is_empty() {
        0
    } else {
        failure_details.len().max(
            test_counts
                .and_then(|counts| usize::try_from(counts.failed).ok())
                .unwrap_or(0),
        )
    };
    let mut result = CompactResult {
        mode: opts.mode.as_str().to_owned(),
        exit_code,
        test_counts,
        diagnostics,
        failing_lines,
        failure_total,
        log_path_in_prefix: false,
        failure_details,
        lines: selected_lines,
        raw_lines,
        raw_tokens,
        out_tokens: 0,
        saved_pct: 0.0,
        log_path: None,
        truncated: false,
        omitted_items: 0,
        omitted_failure_details: 0,
        raw_bytes: raw.len(),
    };

    let preview_text = render_compact_text_inner(&result, false);
    let out_tok_est = approx_tokens(&preview_text);
    let typed_complete = typed_failure_summary_complete(test_counts, &result.failure_details);
    let budget_trims_typed = typed_details_budget_trimmed(&result, opts.max_tokens);
    let nonzero_needs_log = exit_code.is_some_and(|code| code != 0) && !typed_complete;
    let file_typed_needs_log = exit_code.is_none() && has_typed_failures && !typed_complete;
    let size_needs_log = raw_tokens > out_tok_est.saturating_add(150);
    let need_spillover = opts.save_log.is_some()
        || (opts.allow_spillover
            && (nonzero_needs_log || file_typed_needs_log || size_needs_log || budget_trims_typed));
    if need_spillover {
        if let Some(path) = write_spillover_log(opts.save_log.as_deref(), "compact", &normalized) {
            result.log_path = Some(path.to_string_lossy().to_string());
        }
    }

    // The stored result stays untrimmed; both renders apply the tail
    // Keep policy through the budget module, measured per format.
    let final_text = render_compact_text(&result, opts.max_tokens);
    result.out_tokens = approx_tokens(&final_text);
    result.saved_pct = if raw_tokens > 0 {
        ((1.0 - (result.out_tokens as f64 / raw_tokens as f64)) * 100.0).max(-999.9)
    } else {
        0.0
    };
    result
}

/// `compact`'s Keep policy is **tail**, by the rule its text output has
/// always followed: the oldest lines are dropped first, then failing
/// lines from the end, then diagnostics from the end — but at least one
/// diagnostic is always kept, its locations and message trimmed last.
/// One give-up, shared by the text and `--json` trims so both formats
/// keep the same parts of the same input.
fn compact_trim_step(res: &mut CompactResult) -> bool {
    if !res.lines.is_empty() {
        res.lines.remove(0);
        res.truncated = true;
        res.omitted_items += 1;
        return true;
    }
    if !res.failure_details.is_empty() {
        res.failure_details.pop();
        res.truncated = true;
        res.omitted_items += 1;
        res.omitted_failure_details += 1;
        return true;
    }
    if !res.failing_lines.is_empty() {
        res.failing_lines.pop();
        res.truncated = true;
        res.omitted_items += 1;
        return true;
    }
    if res.diagnostics.len() > 1 {
        res.diagnostics.pop();
        res.truncated = true;
        res.omitted_items += 1;
        return true;
    }
    if let Some(first) = res.diagnostics.first_mut() {
        if first.locations.len() > 1 {
            first.locations.pop();
            res.truncated = true;
            return true;
        }
        if first.message.chars().count() > 40 {
            first.message = clip_end(&first.message, 40).0;
            res.truncated = true;
            return true;
        }
    }
    false
}

fn nonfailure_omitted_items(res: &CompactResult) -> usize {
    res.omitted_items
        .saturating_sub(res.omitted_failure_details)
}

/// The `compact` truncation notice for a (possibly trimmed) result,
/// without its trailing newline. Wording is unchanged. Typed failure rows
/// carry their own omission notice, so they are not double-counted here.
fn compact_notice(res: &CompactResult) -> String {
    format!(
        "... (+{} omitted lines/diagnostics; see full log or --max-tokens)",
        nonfailure_omitted_items(res)
    )
}

fn render_compact_text_inner(res: &CompactResult, with_footer: bool) -> String {
    let mut out = String::new();
    let mut head_parts = Vec::new();
    if let Some(c) = res.test_counts {
        head_parts.push(format!(
            "tests: passed {} failed {} skipped {} total {}",
            c.passed, c.failed, c.skipped, c.total
        ));
    }
    if let Some(code) = res.exit_code {
        head_parts.push(format!("exit {code}"));
    }
    if !head_parts.is_empty() {
        out.push_str(&head_parts.join(" | "));
        out.push('\n');
    }

    for g in &res.diagnostics {
        out.push_str(&format_diagnostic(g));
        out.push('\n');
    }
    let mut parsed = parsed_failure_view(res.test_counts, &res.failure_details);
    if res.failure_total > 0 {
        let mut counts = parsed.counts.unwrap_or_default();
        counts.failed = i64::try_from(res.failure_total).unwrap_or(counts.failed);
        parsed.counts = Some(counts);
    }
    for line in render_failure_summary(&parsed, res.log_path.as_deref()) {
        out.push_str(&line);
        out.push('\n');
    }
    if res.failure_total > 0 && res.failure_details.is_empty() {
        out.push_str(&failure_omission_notice(
            res.failure_total,
            res.log_path.as_deref(),
        ));
        out.push('\n');
    }
    for f in &res.failing_lines {
        out.push_str(&format!("fail: {f}\n"));
    }
    for l in &res.lines {
        out.push_str(l);
        out.push('\n');
    }
    if res.truncated && nonfailure_omitted_items(res) > 0 {
        out.push_str(&compact_notice(res));
        out.push('\n');
    }
    if with_footer {
        if res.failure_total > 0 {
            // Typed failure output is already the compaction. Keep only the
            // recoverability pointer: the full savings footer can cost more
            // bytes than a small failing corpus log itself.
            if let Some(path) = &res.log_path {
                if !res.log_path_in_prefix {
                    out.push_str(&format!("log: {path}\n"));
                }
            }
        } else {
            let cur_tok = approx_tokens(&out);
            let pct = if res.raw_tokens > 0 {
                (1.0 - (cur_tok as f64 / res.raw_tokens as f64)) * 100.0
            } else {
                0.0
            };
            let mut footer = format!(
                "raw: {}L (~{} tok) -> ~{} tok ({:.1}% saved)",
                res.raw_lines, res.raw_tokens, cur_tok, pct
            );
            if let Some(path) = &res.log_path {
                if !res.log_path_in_prefix {
                    footer.push_str(&format!(" | log: {path}"));
                }
            }
            out.push_str(&footer);
            out.push('\n');
        }
    }
    out
}

pub fn render_compact_text(res: &CompactResult, max_tokens: usize) -> String {
    let Some(budget) = budget::tokens_to_bytes(max_tokens) else {
        return render_compact_text_inner(res, true);
    };
    let mut trimmed = res.clone();
    budget::trim_structured(
        &mut trimmed,
        max_tokens,
        |s| render_compact_text_inner(s, true),
        compact_trim_step,
    );
    let rendered = render_compact_text_inner(&trimmed, true);
    if rendered.len() <= budget {
        return rendered;
    }
    // Structured trimming is exhausted (lines/failing_lines empty, at
    // most one diagnostic left) and the output still exceeds the
    // budget. Drop the savings footer first so metadata never crowds
    // out the surviving diagnostic or header.
    let rendered_no_footer = render_compact_text_inner(&trimmed, false);
    if rendered_no_footer.len() <= budget {
        return rendered_no_footer;
    }
    let failure_notice = rendered_no_footer
        .lines()
        .find(|line| line.starts_with("... (") && line.contains(" failures omitted;"))
        .map(str::to_owned);
    let notice = if let Some(notice) = failure_notice {
        notice
    } else if trimmed.truncated && nonfailure_omitted_items(&trimmed) > 0 {
        compact_notice(&trimmed)
    } else {
        "... (truncated; see full log or --max-tokens)".to_owned()
    };
    budget::finish_text(rendered_no_footer, max_tokens, KeepPolicy::Tail, &notice)
}

pub fn render_compact_json(res: &CompactResult, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return serde_json::to_string(res).unwrap_or_else(|_| "{}".to_owned());
    }
    // Same tail policy as text, measured against the JSON document;
    // the smallest valid document wins over the budget.
    let mut trimmed = res.clone();
    budget::trim_structured(
        &mut trimmed,
        max_tokens,
        |s| serde_json::to_string(s).unwrap_or_else(|_| "{}".to_owned()),
        compact_trim_step,
    );
    serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicates_msbuild_and_rustc_diagnostics_and_folds_stacktraces() {
        let raw = "\
  Determining projects to restore...\n\
  All projects are up-to-date for restore.\n\
  Core -> /tmp/Core.dll\n\
src/A.cs(12,5): error CS0103: The name 'Foo' does not exist in the current context [/tmp/App.csproj]\n\
src/B.cs(44,9): error CS0103: The name 'Foo' does not exist in the current context [/tmp/App.csproj]\n\
src/C.cs(7,1): warning CS0168: Unused variable 'x' [/tmp/App.csproj]\n\
   at App.Service.Run() in /src/Service.cs:line 10\n\
   at System.Threading.Tasks.Task.Execute()\n\
   at System.Runtime.CompilerServices.TaskAwaiter.GetResult()\n\
   at Microsoft.AspNetCore.Mvc.Controller.Invoke()\n\
   at Xunit.Sdk.TestInvoker.Invoke()\n\
";
        let opts = CompactOptions {
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let res = compact_text(raw, Some(1), &opts);
        assert_eq!(res.diagnostics.len(), 2);
        assert_eq!(res.diagnostics[0].severity, "error");
        assert_eq!(res.diagnostics[0].code, "CS0103");
        assert_eq!(res.diagnostics[0].count, 2);
        assert_eq!(res.diagnostics[0].locations, vec!["src/A.cs:12", "src/B.cs:44"]);
        assert_eq!(res.diagnostics[1].severity, "warning");
        assert!(res
            .lines
            .iter()
            .any(|l| l.contains("framework frames collapsed")));
        assert!(!res
            .lines
            .iter()
            .any(|l| l.contains("Determining projects to restore")));
    }

    #[test]
    fn parses_test_summary_and_enforces_json_budget() {
        let mut raw = String::from("running 40 tests\n");
        for i in 0..80 {
            raw.push_str(&format!("src/f{i}.rs:10:5: error: unexpected token number {i}\n"));
        }
        raw.push_str("test result: FAILED. 38 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n");
        let opts = CompactOptions {
            max_tokens: 120,
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let res = compact_text(&raw, Some(1), &opts);
        assert_eq!(res.test_counts.unwrap().failed, 2);
        let txt = render_compact_text(&res, opts.max_tokens);
        assert!(txt.len() <= 120 * 4);
        let json = render_compact_json(&res, opts.max_tokens);
        assert!(json.len() <= 120 * 4);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["truncated"], serde_json::Value::Bool(true));
    }

    fn generic_lines_result() -> CompactResult {
        let raw: String = (1..=12).map(|i| format!("line-{i:02}\n")).collect();
        let opts = CompactOptions {
            mode: CompactMode::Generic,
            max_tokens: 0,
            allow_spillover: false,
            ..CompactOptions::default()
        };
        compact_text(&raw, None, &opts)
    }

    // Exact-output budget-edge tests (#101).
    #[test]
    fn compact_text_budget_edge_exact_fit_one_token_less_and_below_notice() {
        let res = generic_lines_result();
        assert_eq!(res.lines.len(), 12);
        let full = render_compact_text(&res, 0);
        assert_eq!(
            full,
            "line-01\nline-02\nline-03\nline-04\nline-05\nline-06\nline-07\nline-08\n\
             line-09\nline-10\nline-11\nline-12\n\
             raw: 12L (~24 tok) -> ~24 tok (0.0% saved)\n"
        );
        let exact = full.len().div_ceil(4);
        assert_eq!(render_compact_text(&res, exact), full);
        // One token less: the tail survives — the oldest lines are
        // dropped first, the cut lands on a line end, and the compact
        // notice survives.
        let less = render_compact_text(&res, exact - 1);
        assert_eq!(
            less,
            "line-10\nline-11\nline-12\n\
             ... (+9 omitted lines/diagnostics; see full log or --max-tokens)\n\
             raw: 12L (~24 tok) -> ~22 tok (8.3% saved)\n"
        );
        assert!(less.len() <= (exact - 1) * 4);
        // Budget smaller than the notice: the notice alone.
        assert_eq!(
            render_compact_text(&res, 5),
            "... (+12 omitted lines/diagnostics; see full log or --max-tokens)\n"
        );
    }

    #[test]
    fn compact_json_budget_edge_exact_fit_one_token_less_and_below_smallest_valid() {
        let res = generic_lines_result();
        let full = render_compact_json(&res, 0);
        let exact = full.len().div_ceil(4);
        assert_eq!(render_compact_json(&res, exact), full);
        // One token less, measured against the JSON size: only the
        // oldest line is given up — the same tail rule as text.
        let less = render_compact_json(&res, exact - 1);
        let parsed: serde_json::Value = serde_json::from_str(&less).unwrap();
        assert!(less.len() <= (exact - 1) * 4);
        assert_eq!(parsed["truncated"], serde_json::Value::Bool(true));
        assert_eq!(parsed["omitted_items"], serde_json::Value::from(1));
        let lines: Vec<&str> = parsed["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        assert_eq!(lines.len(), 11);
        assert_eq!(lines[0], "line-02");
        assert_eq!(lines[10], "line-12");
        // Below the smallest valid document: validity wins.
        let tiny = render_compact_json(&res, 1);
        let parsed: serde_json::Value = serde_json::from_str(&tiny).unwrap();
        assert_eq!(parsed["lines"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["truncated"], serde_json::Value::Bool(true));
        assert!(tiny.len() > 4);
    }

    #[test]
    fn compact_text_and_json_keep_the_same_parts_at_the_same_budget() {
        // Long lines: one line costs more than the JSON overhead, so a
        // budget exists where both formats give up exactly the oldest
        // line and keep the same remaining parts.
        let raw: String = (1..=10)
            .map(|i| format!("line-{i:02} {}\n", "x".repeat(190)))
            .collect();
        let opts = CompactOptions {
            mode: CompactMode::Generic,
            max_tokens: 0,
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let res = compact_text(&raw, None, &opts);
        assert_eq!(res.lines.len(), 10);
        let text = render_compact_text(&res, 500);
        let json = render_compact_json(&res, 500);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let json_lines: Vec<String> = parsed["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            json_lines.len(),
            9,
            "json drops exactly the oldest line: {json_lines:?}"
        );
        assert!(!json_lines.iter().any(|l| l.starts_with("line-01")));
        for line in &json_lines {
            assert!(text.contains(line), "text keeps the same line: {line}");
        }
        assert!(!text.contains("line-01"), "text drops the oldest line too");
        assert!(text.contains("omitted lines/diagnostics"));
    }

    #[test]
    fn compact_keeps_at_least_one_diagnostic_in_both_formats() {
        let mut raw = String::new();
        for i in 0..6 {
            raw.push_str(&format!(
                "src/f{i}.rs:10:5: error: problem number {i} with a fairly long explanation text\n"
            ));
        }
        let opts = CompactOptions {
            mode: CompactMode::Build,
            max_tokens: 0,
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let res = compact_text(&raw, Some(1), &opts);
        assert_eq!(res.diagnostics.len(), 6);
        let text = render_compact_text(&res, 100);
        let json = render_compact_json(&res, 100);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let diags = parsed["diagnostics"].as_array().unwrap();
        assert_eq!(
            diags.len(),
            1,
            "json keeps exactly one diagnostic: {diags:?}"
        );
        assert!(
            diags[0]["message"]
                .as_str()
                .unwrap()
                .contains("problem number 0"),
            "the first diagnostic group survives in json"
        );
        assert!(
            text.contains("problem number 0"),
            "the same first diagnostic survives in text: {text}"
        );
        assert!(
            !text.contains("problem number 5"),
            "later diagnostics are given up in text"
        );
    }

    #[test]
    fn compact_text_tight_budget_keeps_only_diagnostic_over_savings_footer() {
        let raw = "src/main.rs:10:5: error: type mismatch on return value\n";
        let opts = CompactOptions {
            mode: CompactMode::Build,
            max_tokens: 0,
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let res = compact_text(raw, Some(1), &opts);
        assert_eq!(res.diagnostics.len(), 1);
        let without_footer = render_compact_text_inner(&res, false);
        let with_footer = render_compact_text_inner(&res, true);
        // Budget fits header + diagnostic, but cannot fit the savings footer.
        let tight_tokens = without_footer.len().div_ceil(4);
        assert!(with_footer.len() > tight_tokens * 4);
        let out = render_compact_text(&res, tight_tokens);
        assert!(out.len() <= tight_tokens * 4, "over budget: {out:?}");
        assert!(out.contains("type mismatch on return value"), "{out}");
        assert!(!out.contains("raw:"), "footer must be dropped first: {out}");
    }

    #[test]
    fn compact_text_ultra_tight_budget_emits_notice_instead_of_dropping_diagnostic_silently() {
        let raw = "src/main.rs:10:5: error: type mismatch on return value\n";
        let opts = CompactOptions {
            mode: CompactMode::Build,
            max_tokens: 0,
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let res = compact_text(raw, Some(1), &opts);
        // Budget too small even for the diagnostic line alone.
        let out = render_compact_text(&res, 5);
        assert!(!out.contains("raw:"), "footer must not displace notice: {out}");
        assert!(
            out.contains("truncated; see full log or --max-tokens"),
            "must emit truncation notice: {out}"
        );
    }

    #[test]
    fn compact_command_preserves_exit_code() {
        let cmd = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "echo ok_line; echo err_line >&2; exit 7".to_owned(),
        ];
        let opts = CompactOptions {
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let (res, code) = compact_command(&cmd, &opts).unwrap();
        assert_eq!(code, 7);
        assert_eq!(res.exit_code, Some(7));
        assert!(res.lines.iter().any(|l| l.contains("ok_line")));
        assert!(res.lines.iter().any(|l| l.contains("err_line")));
    }
}
