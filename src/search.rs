//! Budgeted, grouped, line-clipped, optionally symbol-annotated search (`prometheus-kit search`).

use crate::budget::{self, KeepPolicy};
use crate::kit_util::{clip_centered, is_noise_path};
use crate::outline::{flatten_items, outline_source, Lang, OutlineOptions};
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use regex::RegexBuilder;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_SEARCH_MAX_PER_FILE: usize = 5;
pub const DEFAULT_SEARCH_MAX_FILES: usize = 30;
pub const DEFAULT_SEARCH_MAX_TOKENS: usize = 2000;
pub const DEFAULT_SEARCH_MAX_LINE_CHARS: usize = 180;
const MAX_SEARCH_FILE_BYTES: usize = 16 * 1024 * 1024;
const BINARY_PROBE_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub pattern: String,
    pub paths: Vec<PathBuf>,
    pub ignore_case: bool,
    pub fixed_strings: bool,
    pub word_regexp: bool,
    pub globs: Vec<String>,
    pub lang_type: Option<Lang>,
    pub max_per_file: usize,
    pub max_files: usize,
    pub max_tokens: usize,
    pub max_line_chars: usize,
    pub annotate_symbols: bool,
    pub files_only: bool,
    pub include_noise: bool,
    pub hidden: bool,
    pub no_ignore: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            paths: vec![PathBuf::from(".")],
            ignore_case: false,
            fixed_strings: false,
            word_regexp: false,
            globs: Vec::new(),
            lang_type: None,
            max_per_file: DEFAULT_SEARCH_MAX_PER_FILE,
            max_files: DEFAULT_SEARCH_MAX_FILES,
            max_tokens: DEFAULT_SEARCH_MAX_TOKENS,
            max_line_chars: DEFAULT_SEARCH_MAX_LINE_CHARS,
            annotate_symbols: false,
            files_only: false,
            include_noise: false,
            hidden: false,
            no_ignore: false,
        }
    }
}

#[derive(Debug)]
pub enum SearchError {
    Usage(String),
    Io(String),
}

impl SearchError {
    pub fn exit_code(&self) -> i32 {
        match self {
            SearchError::Usage(_) => 2,
            SearchError::Io(_) => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            SearchError::Usage(m) | SearchError::Io(m) => m,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchMatch {
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub text: String,
    #[serde(skip_serializing_if = "is_false")]
    pub clipped: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchFileGroup {
    pub path: String,
    pub total_matches: usize,
    pub matches: Vec<SearchMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub files: Vec<SearchFileGroup>,
    pub total_matches: usize,
    pub total_files: usize,
    pub shown_matches: usize,
    pub shown_files: usize,
    pub omitted_matches: usize,
    pub omitted_files: usize,
    pub truncated: bool,
    /// Byte length of matching raw lines (or displayed paths for --files-only);
    /// metrics-only, never serialized.
    #[serde(skip)]
    pub raw_bytes: usize,
}

fn read_searchable_text(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SEARCH_FILE_BYTES as u64 {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(256 * 1024));
    file.take(MAX_SEARCH_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > MAX_SEARCH_FILE_BYTES {
        return None;
    }
    let probe = &buf[..buf.len().min(BINARY_PROBE_BYTES)];
    if probe.contains(&0) {
        return None;
    }
    Some(match String::from_utf8(buf) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

fn display_rel(path: &Path) -> String {
    let s = path.to_string_lossy();
    s.strip_prefix("./")
        .or_else(|| s.strip_prefix(".\\"))
        .unwrap_or(&s)
        .replace('\\', "/")
}

fn collect_candidate_files(opts: &SearchOptions) -> Result<Vec<(PathBuf, String)>, SearchError> {
    let roots = if opts.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        opts.paths.clone()
    };
    for p in &roots {
        if !p.exists() {
            return Err(SearchError::Io(format!(
                "{}: No such file or directory",
                p.display()
            )));
        }
    }

    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();

    for root in &roots {
        if root.is_file() {
            let disp = display_rel(root);
            if let Some(wanted) = opts.lang_type {
                if Lang::from_path(root) != Some(wanted) {
                    continue;
                }
            }
            if seen.insert(root.clone()) {
                candidates.push((root.clone(), disp));
            }
            continue;
        }

        let mut wb = WalkBuilder::new(root);
        wb.hidden(!opts.hidden)
            .git_ignore(!opts.no_ignore)
            .git_global(!opts.no_ignore)
            .git_exclude(!opts.no_ignore)
            .ignore(!opts.no_ignore)
            .parents(!opts.no_ignore);

        if !opts.globs.is_empty() {
            let mut ob = OverrideBuilder::new(root);
            for g in &opts.globs {
                ob.add(g)
                    .map_err(|e| SearchError::Usage(format!("invalid --glob `{g}`: {e}")))?;
            }
            let overrides = ob
                .build()
                .map_err(|e| SearchError::Usage(format!("invalid --glob: {e}")))?;
            wb.overrides(overrides);
        }

        for entry in wb.build().flatten() {
            let path = entry.path();
            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(path);
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if !opts.include_noise && is_noise_path(&rel_str) {
                continue;
            }
            if let Some(wanted) = opts.lang_type {
                if Lang::from_path(path) != Some(wanted) {
                    continue;
                }
            }
            let owned = path.to_path_buf();
            if seen.insert(owned.clone()) {
                candidates.push((owned, display_rel(path)));
            }
        }
    }

    candidates.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(candidates)
}

fn find_enclosing_symbol(
    flat: &[&crate::outline::OutlineItem],
    line_no: usize,
) -> Option<String> {
    let mut best: Option<&crate::outline::OutlineItem> = None;
    for &it in flat {
        if it.start_line <= line_no && line_no <= it.end_line {
            let replace = match best {
                None => true,
                Some(prev) => {
                    it.depth > prev.depth
                        || (it.depth == prev.depth
                            && (it.end_line - it.start_line) < (prev.end_line - prev.start_line))
                }
            };
            if replace {
                best = Some(it);
            }
        }
    }
    best.map(|it| it.qualified_name.clone())
}

pub fn execute_search(opts: &SearchOptions) -> Result<SearchResult, SearchError> {
    if opts.pattern.is_empty() {
        return Err(SearchError::Usage("search pattern cannot be empty".to_owned()));
    }
    let mut expr = if opts.fixed_strings {
        regex::escape(&opts.pattern)
    } else {
        opts.pattern.clone()
    };
    if opts.word_regexp {
        expr = format!(r"\b(?:{expr})\b");
    }
    let re = RegexBuilder::new(&expr)
        .case_insensitive(opts.ignore_case)
        .build()
        .map_err(|e| SearchError::Usage(format!("invalid regex `{}`: {e}", opts.pattern)))?;

    let candidates = collect_candidate_files(opts)?;
    let mut files = Vec::new();
    let mut total_matches = 0usize;
    let mut total_files = 0usize;
    let mut raw_bytes = 0usize;

    for (path, disp) in candidates {
        let Some(text) = read_searchable_text(&path) else {
            continue;
        };
        let mut file_matches = 0usize;
        let mut kept: Vec<(usize, String, bool)> = Vec::new();

        // split_inclusive keeps each raw line's terminator for byte accounting;
        // the match input strips '\n' then a paired '\r' exactly like
        // str::lines (a trailing CR on an unterminated last piece is kept).
        for (idx, piece) in text.split_inclusive('\n').enumerate() {
            let had_nl = piece.ends_with('\n');
            let mut raw_line = piece.strip_suffix('\n').unwrap_or(piece);
            if had_nl {
                raw_line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            }
            if let Some(m) = re.find(raw_line) {
                file_matches += 1;
                if !opts.files_only {
                    raw_bytes += piece.len();
                }
                if !opts.files_only && (opts.max_per_file == 0 || kept.len() < opts.max_per_file) {
                    let (clipped_txt, clipped) =
                        clip_centered(raw_line.trim_end(), m.start(), m.end(), opts.max_line_chars);
                    kept.push((idx + 1, clipped_txt, clipped));
                }
            }
        }

        if file_matches == 0 {
            continue;
        }
        total_files += 1;
        total_matches += file_matches;

        if opts.files_only {
            raw_bytes += disp.len() + 1;
        }

        if opts.max_files > 0 && files.len() >= opts.max_files {
            continue;
        }

        let matches = if opts.files_only {
            Vec::new()
        } else if opts.annotate_symbols {
            if let Some(lang) = Lang::from_path(&path) {
                let doc = outline_source(
                    &disp,
                    &text,
                    lang,
                    &OutlineOptions {
                        include_all: true,
                        ..OutlineOptions::default()
                    },
                );
                let flat = flatten_items(&doc.items);
                kept.into_iter()
                    .map(|(ln, txt, clipped)| SearchMatch {
                        line: ln,
                        symbol: find_enclosing_symbol(&flat, ln),
                        text: txt,
                        clipped,
                    })
                    .collect()
            } else {
                kept.into_iter()
                    .map(|(ln, txt, clipped)| SearchMatch {
                        line: ln,
                        symbol: None,
                        text: txt,
                        clipped,
                    })
                    .collect()
            }
        } else {
            kept.into_iter()
                .map(|(ln, txt, clipped)| SearchMatch {
                    line: ln,
                    symbol: None,
                    text: txt,
                    clipped,
                })
                .collect()
        };

        files.push(SearchFileGroup {
            path: disp,
            total_matches: file_matches,
            matches,
        });
    }

    let mut res = build_search_result(files, total_matches, total_files, opts.files_only);
    res.raw_bytes = raw_bytes;
    Ok(res)
}

fn build_search_result(
    files: Vec<SearchFileGroup>,
    total_matches: usize,
    total_files: usize,
    files_only: bool,
) -> SearchResult {
    let shown_files = files.len();
    let shown_matches: usize = if files_only {
        files.iter().map(|f| f.total_matches).sum()
    } else {
        files.iter().map(|f| f.matches.len()).sum()
    };
    let omitted_files = total_files.saturating_sub(shown_files);
    let omitted_matches = total_matches.saturating_sub(shown_matches);
    let truncated = omitted_files > 0 || omitted_matches > 0;
    SearchResult {
        files,
        total_matches,
        total_files,
        shown_matches,
        shown_files,
        omitted_matches,
        omitted_files,
        truncated,
        raw_bytes: 0,
    }
}

fn recompute_search_counts(res: &mut SearchResult, files_only: bool) {
    res.shown_files = res.files.len();
    res.shown_matches = if files_only {
        res.files.iter().map(|f| f.total_matches).sum()
    } else {
        res.files.iter().map(|f| f.matches.len()).sum()
    };
    res.omitted_files = res.total_files.saturating_sub(res.shown_files);
    res.omitted_matches = res.total_matches.saturating_sub(res.shown_matches);
    res.truncated = res.omitted_files > 0 || res.omitted_matches > 0;
}

/// `search`'s Keep policy is **head**: one give-up drops the last shown
/// match of the last file (while it still shows more than one), then the
/// last file itself. The budget module owns the loop and the conversion.
fn search_trim_step(res: &mut SearchResult, files_only: bool) -> bool {
    if res.files.is_empty() {
        return false;
    }
    if !files_only {
        if let Some(last) = res.files.last_mut() {
            if last.matches.len() > 1 {
                last.matches.pop();
                recompute_search_counts(res, files_only);
                return true;
            }
        }
    }
    res.files.pop();
    recompute_search_counts(res, files_only);
    true
}

/// The `search` truncation notice for a (possibly trimmed) result,
/// without its trailing newline. Wording is unchanged.
fn search_notice(res: &SearchResult) -> String {
    format!(
        "... (+{} omitted matches across {} files; narrow with --glob/--type or --max-tokens)",
        res.omitted_matches, res.omitted_files
    )
}

pub fn render_search_text(res: &SearchResult, opts: &SearchOptions) -> String {
    if opts.max_tokens == 0 {
        return render_search_text_inner(res, opts);
    }
    let mut trimmed = res.clone();
    budget::trim_structured(
        &mut trimmed,
        opts.max_tokens,
        |s| render_search_text_inner(s, opts),
        |s| search_trim_step(s, opts.files_only),
    );
    let notice = if trimmed.truncated {
        search_notice(&trimmed)
    } else {
        String::new()
    };
    budget::finish_text(
        render_search_text_inner(&trimmed, opts),
        opts.max_tokens,
        KeepPolicy::Head,
        &notice,
    )
}

fn render_search_text_inner(res: &SearchResult, opts: &SearchOptions) -> String {
    if res.total_matches == 0 {
        return "0 matches\n".to_owned();
    }
    let mut out = String::new();
    for fg in &res.files {
        if opts.files_only {
            out.push_str(&format!("{} ({} matches)\n", fg.path, fg.total_matches));
            continue;
        }
        let extra = fg.total_matches.saturating_sub(fg.matches.len());
        if extra > 0 {
            out.push_str(&format!(
                "{} ({} matches, +{} omitted)\n",
                fg.path, fg.total_matches, extra
            ));
        } else {
            out.push_str(&format!("{} ({} matches)\n", fg.path, fg.total_matches));
        }
        for m in &fg.matches {
            match &m.symbol {
                Some(sym) => out.push_str(&format!("  L{} [{sym}]: {}\n", m.line, m.text)),
                None => out.push_str(&format!("  L{}: {}\n", m.line, m.text)),
            }
        }
    }
    if res.truncated {
        out.push_str(&search_notice(res));
        out.push('\n');
    }
    out
}

pub fn render_search_json(res: &SearchResult, opts: &SearchOptions) -> String {
    if opts.max_tokens == 0 {
        return serde_json::to_string(res).unwrap_or_else(|_| "{}".to_owned());
    }
    // Trimmed against the JSON size, never the text rendering: the same
    // head step, measured by the budget module on the encoded document.
    // The smallest valid document (no files left) is returned even when
    // it still exceeds the budget.
    let mut trimmed = res.clone();
    budget::trim_structured(
        &mut trimmed,
        opts.max_tokens,
        |s| serde_json::to_string(s).unwrap_or_else(|_| "{}".to_owned()),
        |s| search_trim_step(s, opts.files_only),
    );
    serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let d = std::env::temp_dir().join(format!("prom_search_{tag}_{}_{nanos}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
        fn write(&self, rel: &str, data: &[u8]) {
            let p = self.0.join(rel);
            if let Some(par) = p.parent() {
                std::fs::create_dir_all(par).unwrap();
            }
            std::fs::write(p, data).unwrap();
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn skips_noise_clips_long_lines_and_annotates_symbols() {
        let tmp = Tmp::new("sym");
        tmp.write(
            "src/svc.rs",
            b"pub struct Svc;\nimpl Svc {\n    pub fn compute_total(&self) -> i32 {\n        let needle = 42;\n        needle\n    }\n}\n",
        );
        let huge = format!("{}needle{}", "x".repeat(400), "y".repeat(400));
        tmp.write("src/min.js", huge.as_bytes());
        tmp.write("package-lock.json", b"\"needle\": 1\n");
        tmp.write("assets/app.min.js", b"var needle=1;\n");

        let opts = SearchOptions {
            pattern: "needle".to_owned(),
            paths: vec![tmp.0.clone()],
            annotate_symbols: true,
            max_line_chars: 100,
            ..SearchOptions::default()
        };
        let res = execute_search(&opts).unwrap();
        assert_eq!(res.total_files, 2); // package-lock.json and app.min.js excluded
        let rs_group = res.files.iter().find(|f| f.path.ends_with("svc.rs")).unwrap();
        assert_eq!(rs_group.matches[0].symbol.as_deref(), Some("Svc::compute_total"));
        let js_group = res.files.iter().find(|f| f.path.ends_with("min.js")).unwrap();
        assert!(js_group.matches[0].clipped);
        assert!(js_group.matches[0].text.contains("needle"));
        assert!(js_group.matches[0].text.len() < 150);
    }

    /// Match texts are long on purpose: the ~95-byte truncation notice
    /// must not dwarf a single dropped match at the budget edge.
    fn sample_texts() -> (String, String, String, String) {
        (
            format!("alpha needle one {}", "x".repeat(40)),
            format!("alpha needle two {}", "y".repeat(40)),
            format!("beta needle three {}", "z".repeat(40)),
            format!("beta needle four {}", "w".repeat(40)),
        )
    }

    fn sample_result() -> SearchResult {
        let (t1, t2, t3, t4) = sample_texts();
        let m = |line: usize, text: String| SearchMatch {
            line,
            symbol: None,
            text,
            clipped: false,
        };
        SearchResult {
            files: vec![
                SearchFileGroup {
                    path: "a.rs".to_owned(),
                    total_matches: 2,
                    matches: vec![m(1, t1), m(2, t2)],
                },
                SearchFileGroup {
                    path: "b.rs".to_owned(),
                    total_matches: 2,
                    matches: vec![m(3, t3), m(4, t4)],
                },
            ],
            total_matches: 4,
            total_files: 2,
            shown_matches: 4,
            shown_files: 2,
            omitted_matches: 0,
            omitted_files: 0,
            truncated: false,
            raw_bytes: 0,
        }
    }

    fn budgeted_opts(max_tokens: usize) -> SearchOptions {
        SearchOptions {
            max_tokens,
            ..SearchOptions::default()
        }
    }

    // Exact-output budget-edge tests (#99). They replace
    // `enforces_max_tokens_in_text_and_json`, which only asserted
    // lengths; these pin the exact bytes at the edge.
    #[test]
    fn search_text_budget_edge_exact_fit_one_token_less_and_below_notice() {
        let (t1, t2, t3, t4) = sample_texts();
        let res = sample_result();
        let full = render_search_text(&res, &budgeted_opts(0));
        assert_eq!(
            full,
            format!(
                "a.rs (2 matches)\n  L1: {t1}\n  L2: {t2}\n\
                 b.rs (2 matches)\n  L3: {t3}\n  L4: {t4}\n"
            )
        );
        let exact = full.len().div_ceil(4);
        // Exact fit: the whole rendering survives.
        assert_eq!(render_search_text(&res, &budgeted_opts(exact)), full);
        // One token less: head is kept (all of a.rs, nothing of b.rs),
        // the cut lands on a line end, and the search notice survives
        // with the recomputed counts.
        let less = render_search_text(&res, &budgeted_opts(exact - 1));
        assert_eq!(
            less,
            format!(
                "a.rs (2 matches)\n  L1: {t1}\n  L2: {t2}\n\
                 ... (+2 omitted matches across 1 files; narrow with --glob/--type or --max-tokens)\n"
            )
        );
        assert!(less.len() <= (exact - 1) * 4);
        // Budget smaller than the notice: the notice alone.
        let tiny = render_search_text(&res, &budgeted_opts(10));
        assert_eq!(
            tiny,
            "... (+4 omitted matches across 2 files; narrow with --glob/--type or --max-tokens)\n"
        );
    }

    #[test]
    fn search_json_budget_edge_exact_fit_one_token_less_and_below_smallest_valid() {
        let (t1, t2, t3, t4) = sample_texts();
        let res = sample_result();
        let full = render_search_json(&res, &budgeted_opts(0));
        assert_eq!(
            full,
            format!(
                "{{\"files\":[{{\"path\":\"a.rs\",\"total_matches\":2,\"matches\":[\
                 {{\"line\":1,\"text\":\"{t1}\"}},{{\"line\":2,\"text\":\"{t2}\"}}]}},\
                 {{\"path\":\"b.rs\",\"total_matches\":2,\"matches\":[\
                 {{\"line\":3,\"text\":\"{t3}\"}},{{\"line\":4,\"text\":\"{t4}\"}}]}}],\
                 \"total_matches\":4,\"total_files\":2,\"shown_matches\":4,\"shown_files\":2,\
                 \"omitted_matches\":0,\"omitted_files\":0,\"truncated\":false}}"
            )
        );
        let exact = full.len().div_ceil(4);
        // A result that fits the budget as JSON is returned whole.
        assert_eq!(render_search_json(&res, &budgeted_opts(exact)), full);
        // One token less, measured against the JSON size: only the last
        // match of the last file is given up.
        let less = render_search_json(&res, &budgeted_opts(exact - 1));
        assert_eq!(
            less,
            format!(
                "{{\"files\":[{{\"path\":\"a.rs\",\"total_matches\":2,\"matches\":[\
                 {{\"line\":1,\"text\":\"{t1}\"}},{{\"line\":2,\"text\":\"{t2}\"}}]}},\
                 {{\"path\":\"b.rs\",\"total_matches\":2,\"matches\":[\
                 {{\"line\":3,\"text\":\"{t3}\"}}]}}],\
                 \"total_matches\":4,\"total_files\":2,\"shown_matches\":3,\"shown_files\":2,\
                 \"omitted_matches\":1,\"omitted_files\":0,\"truncated\":true}}"
            )
        );
        assert!(less.len() <= (exact - 1) * 4);
        // Below the smallest valid document: validity wins, the empty
        // document is returned whole even though it exceeds the budget.
        let tiny = render_search_json(&res, &budgeted_opts(1));
        assert_eq!(
            tiny,
            "{\"files\":[],\"total_matches\":4,\"total_files\":2,\"shown_matches\":0,\
             \"shown_files\":0,\"omitted_matches\":4,\"omitted_files\":2,\"truncated\":true}"
        );
        assert!(tiny.len() > 4);
        let _: serde_json::Value = serde_json::from_str(&tiny).unwrap();
    }

    #[test]
    fn search_execute_does_not_pretrim_and_run_twice_is_byte_identical() {
        let tmp = Tmp::new("twice");
        for i in 0..6 {
            tmp.write(
                &format!("f{i}.ts"),
                format!("const TARGET_{i} = \"some longer value {i}\";\n").as_bytes(),
            );
        }
        let opts = SearchOptions {
            pattern: "TARGET_".to_owned(),
            paths: vec![tmp.0.clone()],
            max_tokens: 40,
            ..SearchOptions::default()
        };
        let first = execute_search(&opts).unwrap();
        // Execution no longer trims by the text rendering: every file
        // and match is still in the result; only the renders trim.
        assert_eq!(first.files.len(), 6);
        assert!(first.files.iter().all(|f| f.matches.len() == 1));
        let second = execute_search(&opts).unwrap();
        assert_eq!(
            render_search_text(&first, &opts),
            render_search_text(&second, &opts)
        );
        assert_eq!(
            render_search_json(&first, &opts),
            render_search_json(&second, &opts)
        );
        let txt = render_search_text(&first, &opts);
        assert!(txt.len() <= 40 * 4);
        assert!(txt.contains("omitted matches"));
        let json = render_search_json(&first, &opts);
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn invalid_regex_returns_usage_error() {
        let opts = SearchOptions {
            pattern: "[unclosed".to_owned(),
            ..SearchOptions::default()
        };
        let err = execute_search(&opts).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }
}
