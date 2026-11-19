//! Deterministic CLI, build, test, and log output compactor (`prometheus-kit compact`).

use crate::check::{counts_of, Counts};
use crate::kit_util::{
    approx_tokens, clip_end, clip_to_byte_budget, strip_ansi_and_cr, write_spillover_log,
};
use crate::logs::parse_document;
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
    pub lines: Vec<String>,
    pub raw_lines: usize,
    pub raw_tokens: usize,
    pub out_tokens: usize,
    pub saved_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    pub truncated: bool,
    pub omitted_items: usize,
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

    let result = compact_text(&combined, Some(exit_code), opts);
    Ok((result, exit_code))
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

pub fn compact_text(raw: &str, exit_code: Option<i32>, opts: &CompactOptions) -> CompactResult {
    let normalized = strip_ansi_and_cr(raw);
    let raw_lines_vec: Vec<&str> = normalized.lines().collect();
    let raw_lines = raw_lines_vec.len();
    let raw_tokens = approx_tokens(raw);

    let (test_counts, mut failing_lines) = if matches!(opts.mode, CompactMode::Auto | CompactMode::Test)
    {
        let doc = parse_document(&normalized, exit_code.map(i64::from));
        let counts = counts_of(&doc);
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap_or(serde_json::Value::Null);
        let fl: Vec<String> = parsed
            .get("failing_lines")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| clip_end(s.trim(), MAX_LINE_CHARS).0))
                    .collect()
            })
            .unwrap_or_default();
        (counts, fl)
    } else {
        (None, Vec::new())
    };

    let (diagnostics, diag_line_indices) = extract_diagnostics(&raw_lines_vec, opts.mode);

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
        || (diagnostics.is_empty() && test_counts.is_none())
        || exit_code.unwrap_or(0) != 0;

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

    let mut result = CompactResult {
        mode: opts.mode.as_str().to_owned(),
        exit_code,
        test_counts,
        diagnostics,
        failing_lines,
        lines: selected_lines,
        raw_lines,
        raw_tokens,
        out_tokens: 0,
        saved_pct: 0.0,
        log_path: None,
        truncated: false,
        omitted_items: 0,
    };

    let preview_text = render_compact_text_inner(&result, false);
    let out_tok_est = approx_tokens(&preview_text);
    let need_spillover = opts.save_log.is_some()
        || (opts.allow_spillover
            && (exit_code.unwrap_or(0) != 0 || raw_tokens > out_tok_est.saturating_add(150)));
    if need_spillover {
        if let Some(path) = write_spillover_log(opts.save_log.as_deref(), "compact", &normalized) {
            result.log_path = Some(path.to_string_lossy().to_string());
        }
    }

    // Apply budget to text view metadata cleanly
    apply_compact_budget(&mut result, opts.max_tokens);
    let final_text = render_compact_text_inner(&result, true);
    result.out_tokens = approx_tokens(&final_text);
    result.saved_pct = if raw_tokens > 0 {
        ((1.0 - (result.out_tokens as f64 / raw_tokens as f64)) * 100.0).max(-999.9)
    } else {
        0.0
    };
    result
}

fn apply_compact_budget(res: &mut CompactResult, max_tokens: usize) {
    if max_tokens == 0 {
        return;
    }
    let budget_chars = max_tokens.saturating_mul(4);
    loop {
        let text = render_compact_text_inner(res, true);
        if text.len() <= budget_chars {
            break;
        }
        if !res.lines.is_empty() {
            res.lines.remove(0);
            res.truncated = true;
            res.omitted_items += 1;
            continue;
        }
        if !res.failing_lines.is_empty() {
            res.failing_lines.pop();
            res.truncated = true;
            res.omitted_items += 1;
            continue;
        }
        if res.diagnostics.len() > 1 {
            res.diagnostics.pop();
            res.truncated = true;
            res.omitted_items += 1;
            continue;
        }
        if let Some(first) = res.diagnostics.first_mut() {
            if first.locations.len() > 1 {
                first.locations.pop();
                res.truncated = true;
                continue;
            }
            if first.message.chars().count() > 40 {
                first.message = clip_end(&first.message, 40).0;
                res.truncated = true;
                continue;
            }
        }
        break;
    }
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
    for f in &res.failing_lines {
        out.push_str(&format!("fail: {f}\n"));
    }
    for l in &res.lines {
        out.push_str(l);
        out.push('\n');
    }
    if res.truncated && res.omitted_items > 0 {
        out.push_str(&format!(
            "... (+{} omitted lines/diagnostics; see full log or --max-tokens)\n",
            res.omitted_items
        ));
    }
    if with_footer {
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
            footer.push_str(&format!(" | log: {path}"));
        }
        out.push_str(&footer);
        out.push('\n');
    }
    out
}

pub fn render_compact_text(res: &CompactResult, max_tokens: usize) -> String {
    let out = render_compact_text_inner(res, true);
    if max_tokens > 0 {
        return clip_to_byte_budget(&out, max_tokens.saturating_mul(4));
    }
    out
}

pub fn render_compact_json(res: &CompactResult, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return serde_json::to_string(res).unwrap_or_else(|_| "{}".to_owned());
    }
    let budget_chars = max_tokens.saturating_mul(4);
    let mut trimmed = res.clone();
    loop {
        let encoded = serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned());
        if encoded.len() <= budget_chars {
            return encoded;
        }
        if !trimmed.lines.is_empty() {
            trimmed.lines.remove(0);
            trimmed.truncated = true;
            trimmed.omitted_items += 1;
            continue;
        }
        if !trimmed.failing_lines.is_empty() {
            trimmed.failing_lines.pop();
            trimmed.truncated = true;
            trimmed.omitted_items += 1;
            continue;
        }
        if !trimmed.diagnostics.is_empty() {
            trimmed.diagnostics.pop();
            trimmed.truncated = true;
            trimmed.omitted_items += 1;
            continue;
        }
        return encoded;
    }
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
