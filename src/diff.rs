//! Compact structural git status, diff, and commit summary (`prometheus-kit diff`).

use crate::check::parse_status_z;
use crate::kit_util::{clip_end, clip_to_byte_budget, is_noise_path};
use crate::outline::{flatten_items, outline_source, read_text_file, Lang, OutlineItem, OutlineOptions};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_DIFF_MAX_TOKENS: usize = 2500;
pub const DEFAULT_DIFF_CONTEXT: usize = 2;
pub const DEFAULT_DIFF_MAX_HUNK_LINES: usize = 40;
const MAX_DIFF_LINE_CHARS: usize = 500;
const LARGE_NEW_OR_DEL_THRESHOLD: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffMode {
    Worktree,
    Staged,
    Base(String),
    Commit(String),
    Status,
}

#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub root: PathBuf,
    pub mode: DiffMode,
    pub paths: Vec<PathBuf>,
    pub stat_only: bool,
    pub symbol_filter: Option<String>,
    pub context_lines: usize,
    pub max_hunk_lines: usize,
    pub max_tokens: usize,
    pub include_noise: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            mode: DiffMode::Worktree,
            paths: Vec::new(),
            stat_only: false,
            symbol_filter: None,
            context_lines: DEFAULT_DIFF_CONTEXT,
            max_hunk_lines: DEFAULT_DIFF_MAX_HUNK_LINES,
            max_tokens: DEFAULT_DIFF_MAX_TOKENS,
            include_noise: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffHunk {
    pub header: String,
    pub new_start: usize,
    pub new_count: usize,
    pub symbols: Vec<String>,
    pub lines: Vec<String>,
    pub omitted_lines: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffFile {
    pub path: String,
    pub status: String,
    pub added: usize,
    pub deleted: usize,
    pub symbols: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_note: Option<String>,
    pub hunks: Vec<DiffHunk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSummary {
    pub branch: String,
    pub staged: Vec<String>,
    pub unstaged: Vec<String>,
    pub untracked: Vec<String>,
    pub unmerged: Vec<String>,
    pub excluded_noise: Vec<String>,
    pub truncated: bool,
    pub omitted_entries: usize,
    /// Byte length of the raw `git status -z` output; metrics-only.
    #[serde(skip)]
    pub raw_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum DiffOutput {
    #[serde(rename = "status")]
    Status(StatusSummary),
    #[serde(rename = "diff")]
    Diff {
        /// Byte length of the raw unified diff captured from git; metrics-only.
        #[serde(skip)]
        raw_bytes: usize,
        /// Content removed by symbol/stat filtering before budget trims; metrics-only.
        #[serde(skip)]
        filtered_output: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        commit_header: Option<String>,
        files: Vec<DiffFile>,
        excluded_noise: Vec<String>,
        total_files: usize,
        total_added: usize,
        total_deleted: usize,
        truncated: bool,
        omitted_files: usize,
    },
}

fn run_git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["-c", "core.quotePath=false"])
        .args(args)
        .output()
        .map_err(|e| format!("git failed: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("git {} failed with exit {:?}", args.first().copied().unwrap_or(""), out.status.code())
        } else {
            stderr
        });
    }
    Ok(out.stdout)
}

fn repo_root_of(root: &Path) -> Result<PathBuf, String> {
    let raw = run_git(root, &["rev-parse", "--show-toplevel"])?;
    let s = String::from_utf8_lossy(&raw).trim().to_owned();
    if s.is_empty() {
        Err("could not resolve git repository root".to_owned())
    } else {
        Ok(PathBuf::from(s))
    }
}

fn run_status(repo_root: &Path, opts: &DiffOptions) -> Result<DiffOutput, String> {
    let mut args = vec!["status", "--porcelain=v1", "-b", "-z"];
    let path_strs: Vec<String> = opts
        .paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    if !path_strs.is_empty() {
        args.push("--");
        for p in &path_strs {
            args.push(p);
        }
    }
    let raw = run_git(repo_root, &args)?;
    let (branch, rest) = if raw.starts_with(b"## ") {
        if let Some(pos) = raw.iter().position(|&b| b == 0) {
            let b = String::from_utf8_lossy(&raw[3..pos]).trim().to_owned();
            (b, &raw[pos + 1..])
        } else {
            (String::from_utf8_lossy(&raw[3..]).trim().to_owned(), &[][..])
        }
    } else {
        (String::from("(unknown)"), raw.as_slice())
    };

    let entries = parse_status_z(rest);
    let mut staged = Vec::new();
    let mut unstaged = Vec::new();
    let mut untracked = Vec::new();
    let mut unmerged = Vec::new();
    let mut excluded_noise = Vec::new();
    let explicit = !opts.paths.is_empty();

    for e in entries {
        if !opts.include_noise && !explicit && is_noise_path(&e.path) {
            if !excluded_noise.contains(&e.path) {
                excluded_noise.push(e.path);
            }
            continue;
        }
        if e.x == '?' && e.y == '?' {
            untracked.push(e.path);
            continue;
        }
        if e.x == 'U' || e.y == 'U' || (e.x, e.y) == ('A', 'A') || (e.x, e.y) == ('D', 'D') {
            unmerged.push(format!("{}{} {}", e.x, e.y, e.path));
            continue;
        }
        if e.x != ' ' {
            let label = match &e.from {
                Some(old) => format!("{} {old} -> {}", e.x, e.path),
                None => format!("{} {}", e.x, e.path),
            };
            staged.push(label);
        }
        if e.y != ' ' {
            unstaged.push(format!("{} {}", e.y, e.path));
        }
    }

    let mut summary = StatusSummary {
        branch,
        staged,
        unstaged,
        untracked,
        unmerged,
        excluded_noise,
        truncated: false,
        omitted_entries: 0,
        raw_bytes: raw.len(),
    };
    enforce_status_text_budget(&mut summary, opts.max_tokens);
    Ok(DiffOutput::Status(summary))
}

fn enforce_status_text_budget(s: &mut StatusSummary, max_tokens: usize) {
    if max_tokens == 0 {
        return;
    }
    let budget = max_tokens.saturating_mul(4);
    loop {
        let out = DiffOutput::Status(s.clone());
        let txt = render_diff_text(&out, 0);
        if txt.len() <= budget {
            break;
        }
        if s.excluded_noise.len() > 1 {
            s.excluded_noise.pop();
            s.truncated = true;
            s.omitted_entries += 1;
        } else if !s.untracked.is_empty() {
            s.untracked.pop();
            s.truncated = true;
            s.omitted_entries += 1;
        } else if !s.unstaged.is_empty() {
            s.unstaged.pop();
            s.truncated = true;
            s.omitted_entries += 1;
        } else if !s.staged.is_empty() {
            s.staged.pop();
            s.truncated = true;
            s.omitted_entries += 1;
        } else {
            break;
        }
    }
}

fn strip_ab_prefix(s: &str) -> &str {
    s.strip_prefix("a/")
        .or_else(|| s.strip_prefix("b/"))
        .unwrap_or(s)
}

fn parse_diff_git_paths(line: &str) -> (String, String) {
    let rest = line.strip_prefix("diff --git ").unwrap_or(line).trim();
    // Handle `a/<path> b/<path>` cleanly when paths have no ` b/` ambiguity; `--- `/`+++ ` overrides below when present.
    if let Some(pos) = rest.find(" b/") {
        let a = strip_ab_prefix(rest[..pos].trim()).to_owned();
        let b = strip_ab_prefix(rest[pos + 1..].trim()).to_owned();
        return (a, b);
    }
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() >= 2 {
        return (
            strip_ab_prefix(parts[0]).to_owned(),
            strip_ab_prefix(parts[1]).to_owned(),
        );
    }
    (rest.to_owned(), rest.to_owned())
}

fn parse_hunk_range(header: &str) -> (usize, usize) {
    // Format: `@@ -os,oc +ns,nc @@...`
    let after_at = header.strip_prefix("@@ ").unwrap_or(header);
    let Some(plus_part) = after_at.split_whitespace().find(|s| s.starts_with('+')) else {
        return (1, 1);
    };
    let nums = &plus_part[1..];
    if let Some((s, c)) = nums.split_once(',') {
        let start = s.parse::<usize>().unwrap_or(1).max(1);
        let count = c.parse::<usize>().unwrap_or(1);
        (start, count)
    } else {
        (nums.parse::<usize>().unwrap_or(1).max(1), 1)
    }
}

fn parse_unified_diff(raw: &str, max_hunk_lines: usize) -> (Option<String>, Vec<DiffFile>) {
    let mut commit_header_lines = Vec::new();
    let mut files: Vec<DiffFile> = Vec::new();
    let mut cur_file: Option<DiffFile> = None;
    let mut cur_hunk: Option<DiffHunk> = None;
    let mut seen_diff = false;

    let flush_hunk = |cf: &mut Option<DiffFile>, ch: &mut Option<DiffHunk>| {
        if let (Some(f), Some(h)) = (cf.as_mut(), ch.take()) {
            f.hunks.push(h);
        }
    };
    let flush_file = |files: &mut Vec<DiffFile>, cf: &mut Option<DiffFile>, ch: &mut Option<DiffHunk>| {
        flush_hunk(cf, ch);
        if let Some(f) = cf.take() {
            files.push(f);
        }
    };

    for line in raw.lines() {
        if line.starts_with("diff --git ") {
            seen_diff = true;
            flush_file(&mut files, &mut cur_file, &mut cur_hunk);
            let (_, b_path) = parse_diff_git_paths(line);
            cur_file = Some(DiffFile {
                path: b_path,
                status: "modified".to_owned(),
                added: 0,
                deleted: 0,
                symbols: Vec::new(),
                summary_note: None,
                hunks: Vec::new(),
            });
            continue;
        }
        if !seen_diff {
            if !line.trim().is_empty() && commit_header_lines.len() < 4 {
                commit_header_lines.push(clip_end(line, 160).0);
            }
            continue;
        }
        let Some(f) = cur_file.as_mut() else {
            continue;
        };

        if cur_hunk.is_none() {
            if line.starts_with("new file mode") {
                f.status = "added".to_owned();
                continue;
            }
            if line.starts_with("deleted file mode") {
                f.status = "deleted".to_owned();
                continue;
            }
            if line.starts_with("rename from ") {
                f.status = "renamed".to_owned();
                continue;
            }
            if let Some(rest) = line.strip_prefix("rename to ") {
                f.status = "renamed".to_owned();
                f.path = rest.trim().to_owned();
                continue;
            }
            if line.starts_with("Binary files ") || line == "GIT binary patch" {
                f.status = "binary".to_owned();
                continue;
            }
            if let Some(rest) = line.strip_prefix("+++ ") {
                let p = rest.trim();
                if p != "/dev/null" {
                    f.path = strip_ab_prefix(p).to_owned();
                }
                continue;
            }
            if line.starts_with("--- ")
                || line.starts_with("index ")
                || line.starts_with("old mode ")
                || line.starts_with("new mode ")
                || line.starts_with("similarity index ")
            {
                continue;
            }
        }

        if line.starts_with("@@ ") {
            flush_hunk(&mut cur_file, &mut cur_hunk);
            let (ns, nc) = parse_hunk_range(line);
            cur_hunk = Some(DiffHunk {
                header: clip_end(line, 160).0,
                new_start: ns,
                new_count: nc,
                symbols: Vec::new(),
                lines: Vec::new(),
                omitted_lines: 0,
            });
            continue;
        }

        if let Some(h) = cur_hunk.as_mut() {
            if line.starts_with('+') {
                f.added += 1;
            } else if line.starts_with('-') {
                f.deleted += 1;
            } else if line.starts_with("\\ No newline") {
                continue;
            }
            if max_hunk_lines == 0 || h.lines.len() < max_hunk_lines {
                h.lines.push(clip_end(line, MAX_DIFF_LINE_CHARS).0);
            } else {
                h.omitted_lines += 1;
            }
        }
    }

    flush_file(&mut files, &mut cur_file, &mut cur_hunk);
    let commit_header = if commit_header_lines.is_empty() {
        None
    } else {
        Some(commit_header_lines.join(" | "))
    };
    (commit_header, files)
}

fn symbols_for_range(flat: &[&OutlineItem], start: usize, count: usize) -> Vec<String> {
    let end = start + count.saturating_sub(1);
    let mut deepest: Vec<&OutlineItem> = Vec::new();
    for &it in flat {
        if it.end_line >= start && it.start_line <= end {
            deepest.push(it);
        }
    }
    // Prefer leaf-most overlapping items (drop ancestor containers when a child also overlaps)
    let mut picked = Vec::new();
    for &it in &deepest {
        let has_more_specific_child = deepest.iter().any(|&other| {
            other.depth > it.depth
                && other.start_line >= it.start_line
                && other.end_line <= it.end_line
        });
        if !has_more_specific_child && !picked.iter().any(|x| x == &it.qualified_name) {
            picked.push(it.qualified_name.clone());
        }
    }
    picked
}

fn annotate_file_symbols(repo_root: &Path, f: &mut DiffFile) {
    if f.status == "deleted" || f.status == "binary" || f.hunks.is_empty() {
        return;
    }
    let full = repo_root.join(&f.path);
    let Some(lang) = Lang::from_path(&full) else {
        return;
    };
    let Ok((src, _)) = read_text_file(&full) else {
        return;
    };
    let doc = outline_source(
        &f.path,
        &src,
        lang,
        &OutlineOptions {
            include_all: true,
            ..OutlineOptions::default()
        },
    );
    let flat = flatten_items(&doc.items);
    let mut file_syms = BTreeSet::new();
    for h in &mut f.hunks {
        let syms = symbols_for_range(&flat, h.new_start, h.new_count);
        for s in &syms {
            file_syms.insert(s.clone());
        }
        h.symbols = syms;
    }
    f.symbols = file_syms.into_iter().collect();
}

pub fn execute_diff(opts: &DiffOptions) -> Result<DiffOutput, String> {
    let repo_root = repo_root_of(&opts.root)?;
    if matches!(opts.mode, DiffMode::Status) {
        return run_status(&repo_root, opts);
    }

    let ctx_flag = format!("-U{}", opts.context_lines);
    let path_strs: Vec<String> = opts
        .paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let raw_bytes = match &opts.mode {
        DiffMode::Worktree => {
            let has_head = run_git(&repo_root, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]).is_ok();
            let mut args = vec!["diff", "--no-color", "--no-ext-diff", &ctx_flag];
            if has_head {
                args.insert(1, "HEAD");
            }
            if !path_strs.is_empty() {
                args.push("--");
                for p in &path_strs {
                    args.push(p);
                }
            }
            let mut out = run_git(&repo_root, &args)?;
            if !has_head {
                let mut staged_args = vec!["diff", "--cached", "--no-color", "--no-ext-diff", &ctx_flag];
                if !path_strs.is_empty() {
                    staged_args.push("--");
                    for p in &path_strs {
                        staged_args.push(p);
                    }
                }
                if let Ok(staged) = run_git(&repo_root, &staged_args) {
                    if !staged.is_empty() {
                        out.extend_from_slice(&staged);
                    }
                }
            }
            out
        }
        DiffMode::Staged => {
            let mut args = vec!["diff", "--cached", "--no-color", "--no-ext-diff", &ctx_flag];
            if !path_strs.is_empty() {
                args.push("--");
                for p in &path_strs {
                    args.push(p);
                }
            }
            run_git(&repo_root, &args)?
        }
        DiffMode::Base(base_ref) => {
            let mut args = vec!["diff", base_ref.as_str(), "--no-color", "--no-ext-diff", &ctx_flag];
            if !path_strs.is_empty() {
                args.push("--");
                for p in &path_strs {
                    args.push(p);
                }
            }
            run_git(&repo_root, &args)?
        }
        DiffMode::Commit(rev) => {
            let mut args = vec![
                "show",
                "--format=medium",
                "--no-color",
                "--no-ext-diff",
                &ctx_flag,
                rev.as_str(),
            ];
            if !path_strs.is_empty() {
                args.push("--");
                for p in &path_strs {
                    args.push(p);
                }
            }
            run_git(&repo_root, &args)?
        }
        DiffMode::Status => unreachable!(),
    };

    let raw_text = String::from_utf8_lossy(&raw_bytes);
    let (commit_header, parsed_files) = parse_unified_diff(&raw_text, opts.max_hunk_lines);

    let explicit = !opts.paths.is_empty();
    let mut excluded_noise = Vec::new();
    let mut files = Vec::new();
    let mut filtered_output = false;

    for mut f in parsed_files {
        if !opts.include_noise && !explicit && is_noise_path(&f.path) {
            excluded_noise.push(format!("{} (+{}/-{})", f.path, f.added, f.deleted));
            continue;
        }
        annotate_file_symbols(&repo_root, &mut f);

        if let Some(sym_q) = opts.symbol_filter.as_deref() {
            let q_lower = sym_q.trim().to_ascii_lowercase();
            if !q_lower.is_empty() {
                let before = f.hunks.len();
                f.hunks.retain(|h| {
                    h.symbols
                        .iter()
                        .any(|s| s.to_ascii_lowercase().contains(&q_lower))
                });
                filtered_output |= before != f.hunks.len() || f.hunks.is_empty();
                if f.hunks.is_empty() {
                    continue;
                }
                let mut filtered_syms = BTreeSet::new();
                for h in &f.hunks {
                    for s in &h.symbols {
                        filtered_syms.insert(s.clone());
                    }
                }
                f.symbols = filtered_syms.into_iter().collect();
            }
        }

        if opts.stat_only {
            filtered_output |= !f.hunks.is_empty();
            f.hunks.clear();
        } else if !explicit && opts.max_hunk_lines > 0 {
            if f.status == "added" && f.added > LARGE_NEW_OR_DEL_THRESHOLD {
                f.summary_note = Some(format!(
                    "[new file, +{}L — inspect with outline/slice]",
                    f.added
                ));
                f.hunks.clear();
            } else if f.status == "deleted" && f.deleted > LARGE_NEW_OR_DEL_THRESHOLD {
                f.summary_note = Some(format!("[deleted file, -{}L]", f.deleted));
                f.hunks.clear();
            }
        }

        files.push(f);
    }

    let total_files = files.len();
    let total_added: usize = files.iter().map(|f| f.added).sum();
    let total_deleted: usize = files.iter().map(|f| f.deleted).sum();

    let mut out = DiffOutput::Diff {
        raw_bytes: raw_bytes.len(),
        filtered_output,
        commit_header,
        files,
        excluded_noise,
        total_files,
        total_added,
        total_deleted,
        truncated: false,
        omitted_files: 0,
    };
    apply_diff_text_budget(&mut out, opts.max_tokens);
    Ok(out)
}

fn trim_one_diff_step(out: &mut DiffOutput) -> bool {
    let DiffOutput::Diff {
        commit_header,
        files,
        excluded_noise,
        truncated,
        omitted_files,
        ..
    } = out
    else {
        return false;
    };
    // 1. Collapse hunks and trailing symbol annotations on trailing files first.
    for f in files.iter_mut().rev() {
        if let Some(last_h) = f.hunks.last_mut() {
            if last_h.lines.len() > 2 {
                last_h.lines.pop();
                last_h.omitted_lines += 1;
                *truncated = true;
                return true;
            }
        }
        if f.hunks.len() > 1 {
            f.hunks.pop();
            *truncated = true;
            return true;
        }
        if !f.hunks.is_empty() {
            f.hunks.clear();
            f.summary_note = Some("[hunks omitted due to --max-tokens]".to_owned());
            *truncated = true;
            return true;
        }
        if !f.symbols.is_empty() {
            f.symbols.pop();
            *truncated = true;
            return true;
        }
        if f.summary_note.is_some() {
            f.summary_note = None;
            *truncated = true;
            return true;
        }
    }
    // 2. Drop trailing files (including down to 0 files if a single file exceeds the budget).
    if !files.is_empty() {
        files.pop();
        *omitted_files += 1;
        *truncated = true;
        return true;
    }
    if !excluded_noise.is_empty() {
        excluded_noise.pop();
        *truncated = true;
        return true;
    }
    if commit_header.is_some() {
        *commit_header = None;
        *truncated = true;
        return true;
    }
    false
}

fn apply_diff_text_budget(out: &mut DiffOutput, max_tokens: usize) {
    if max_tokens == 0 {
        return;
    }
    let budget = max_tokens.saturating_mul(4);
    loop {
        let txt = render_diff_text(out, 0);
        if txt.len() <= budget {
            break;
        }
        if !trim_one_diff_step(out) {
            break;
        }
    }
}

pub fn render_diff_text(out: &DiffOutput, max_tokens: usize) -> String {
    let mut s = String::new();
    match out {
        DiffOutput::Status(st) => {
            s.push_str(&format!("branch: {}\n", st.branch));
            if st.staged.is_empty()
                && st.unstaged.is_empty()
                && st.untracked.is_empty()
                && st.unmerged.is_empty()
                && st.excluded_noise.is_empty()
            {
                s.push_str("working tree clean\n");
            } else {
                if !st.unmerged.is_empty() {
                    s.push_str(&format!("unmerged ({}): {}\n", st.unmerged.len(), st.unmerged.join(", ")));
                }
                if !st.staged.is_empty() {
                    s.push_str(&format!("staged ({}): {}\n", st.staged.len(), st.staged.join(", ")));
                }
                if !st.unstaged.is_empty() {
                    s.push_str(&format!("unstaged ({}): {}\n", st.unstaged.len(), st.unstaged.join(", ")));
                }
                if !st.untracked.is_empty() {
                    s.push_str(&format!("untracked ({}): {}\n", st.untracked.len(), st.untracked.join(", ")));
                }
                if !st.excluded_noise.is_empty() {
                    s.push_str(&format!(
                        "excluded noise ({}): {}\n",
                        st.excluded_noise.len(),
                        st.excluded_noise.join(", ")
                    ));
                }
                if st.truncated {
                    s.push_str(&format!(
                        "... (+{} omitted status entries; pass --max-tokens)\n",
                        st.omitted_entries
                    ));
                }
            }
        }
        DiffOutput::Diff {
            commit_header,
            files,
            excluded_noise,
            total_files,
            total_added,
            total_deleted,
            truncated,
            omitted_files,
            ..
        } => {
            if let Some(hdr) = commit_header {
                s.push_str(&format!("commit: {hdr}\n"));
            }
            if files.is_empty() && excluded_noise.is_empty() && !*truncated {
                s.push_str("no changes\n");
                return s;
            }
            s.push_str(&format!(
                "summary: {total_files} files (+{total_added}/-{total_deleted})\n"
            ));
            for f in files {
                let syms = if f.symbols.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", f.symbols.join(", "))
                };
                let note = f
                    .summary_note
                    .as_deref()
                    .map(|n| format!(" {n}"))
                    .unwrap_or_default();
                s.push_str(&format!(
                    "  {} ({}, +{}/-{}){syms}{note}\n",
                    f.path, f.status, f.added, f.deleted
                ));
            }
            if !excluded_noise.is_empty() {
                s.push_str(&format!(
                    "excluded noise ({} files): {}\n",
                    excluded_noise.len(),
                    excluded_noise.join(", ")
                ));
            }
            for f in files {
                if f.hunks.is_empty() {
                    continue;
                }
                s.push_str(&format!("\n--- {} ---\n", f.path));
                for h in &f.hunks {
                    if h.symbols.is_empty() {
                        s.push_str(&format!("{}\n", h.header));
                    } else {
                        s.push_str(&format!("{} [{}]\n", h.header, h.symbols.join(", ")));
                    }
                    for line in &h.lines {
                        s.push_str(line);
                        s.push('\n');
                    }
                    if h.omitted_lines > 0 {
                        s.push_str(&format!("... (+{} hunk lines omitted)\n", h.omitted_lines));
                    }
                }
            }
            if *truncated {
                s.push_str(&format!(
                    "... (diff compacted to budget; {} files omitted; narrow with paths/--symbol or --max-tokens)\n",
                    omitted_files
                ));
            }
        }
    }
    if max_tokens > 0 {
        return clip_to_byte_budget(&s, max_tokens.saturating_mul(4));
    }
    s
}

pub fn render_diff_json(out: &DiffOutput, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return serde_json::to_string(out).unwrap_or_else(|_| "{}".to_owned());
    }
    let budget = max_tokens.saturating_mul(4);
    let mut trimmed = out.clone();
    loop {
        let encoded = serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned());
        if encoded.len() <= budget {
            return encoded;
        }
        match &mut trimmed {
            DiffOutput::Status(st) => {
                if !st.excluded_noise.is_empty() {
                    st.excluded_noise.pop();
                } else if !st.untracked.is_empty() {
                    st.untracked.pop();
                } else if !st.unstaged.is_empty() {
                    st.unstaged.pop();
                } else if !st.staged.is_empty() {
                    st.staged.pop();
                } else {
                    return encoded;
                }
                st.truncated = true;
                st.omitted_entries += 1;
            }
            DiffOutput::Diff { .. } => {
                if !trim_one_diff_step(&mut trimmed) {
                    if let DiffOutput::Diff { excluded_noise, truncated, .. } = &mut trimmed {
                        if !excluded_noise.is_empty() {
                            excluded_noise.pop();
                            *truncated = true;
                            continue;
                        }
                    }
                    return encoded;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct GitTmp(PathBuf);
    impl GitTmp {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let d = std::env::temp_dir().join(format!("prom_diff_{tag}_{}_{nanos}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            let tmp = Self(d);
            tmp.git(&["init"]);
            tmp.git(&["config", "user.email", "t@example.com"]);
            tmp.git(&["config", "user.name", "Test"]);
            tmp
        }
        fn git(&self, args: &[&str]) {
            let st = Command::new("git")
                .arg("-C")
                .arg(&self.0)
                .args(args)
                .status()
                .unwrap();
            assert!(st.success(), "git {args:?} failed");
        }
        fn write(&self, rel: &str, text: &str) {
            let p = self.0.join(rel);
            if let Some(par) = p.parent() {
                std::fs::create_dir_all(par).unwrap();
            }
            std::fs::write(p, text).unwrap();
        }
    }
    impl Drop for GitTmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn status_diff_noise_exclusion_and_symbol_filter() {
        let tmp = GitTmp::new("work");
        let pad = "\n// spacer\n".repeat(6);
        tmp.write(
            "src/lib.rs",
            &format!("pub fn alpha() -> i32 {{\n    1\n}}\n{pad}\npub fn beta() -> i32 {{\n    2\n}}\n"),
        );
        tmp.write("Cargo.lock", "# v1\n");
        tmp.git(&["add", "-A"]);
        tmp.git(&["commit", "-m", "init"]);

        // Modify both alpha & beta plus noise Cargo.lock, and add untracked file
        tmp.write(
            "src/lib.rs",
            &format!("pub fn alpha() -> i32 {{\n    10\n}}\n{pad}\npub fn beta() -> i32 {{\n    20\n}}\n"),
        );
        tmp.write("Cargo.lock", "# v2\n");
        tmp.write("notes.txt", "untracked\n");

        let st = execute_diff(&DiffOptions {
            root: tmp.0.clone(),
            mode: DiffMode::Status,
            ..DiffOptions::default()
        })
        .unwrap();
        let st_txt = render_diff_text(&st, 2500);
        assert!(st_txt.contains("unstaged (1): M src/lib.rs"));
        assert!(st_txt.contains("excluded noise (1): Cargo.lock"));

        let d = execute_diff(&DiffOptions {
            root: tmp.0.clone(),
            mode: DiffMode::Worktree,
            symbol_filter: Some("beta".to_owned()),
            ..DiffOptions::default()
        })
        .unwrap();
        let d_txt = render_diff_text(&d, 2500);
        assert!(d_txt.contains("beta"));
        assert!(!d_txt.contains("10"));
        assert!(d_txt.contains("excluded noise (1 files): Cargo.lock"));

        let json = render_diff_json(&d, 200);
        assert!(json.len() <= 200 * 4);

        // Tight commit diff JSON budget on single file with symbols + commit header
        let c = execute_diff(&DiffOptions {
            root: tmp.0.clone(),
            mode: DiffMode::Commit("HEAD".to_owned()),
            max_tokens: 70,
            ..DiffOptions::default()
        })
        .unwrap();
        let c_txt = render_diff_text(&c, 70);
        assert!(c_txt.len() <= 70 * 4, "commit text len {}", c_txt.len());
        let c_json = render_diff_json(&c, 70);
        assert!(c_json.len() <= 70 * 4, "commit json len {}", c_json.len());
    }
}
