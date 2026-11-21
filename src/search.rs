//! Budgeted, grouped, line-clipped, optionally symbol-annotated search (`prometheus-kit search`).

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
    apply_search_text_budget(&mut res, opts);
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

fn apply_search_text_budget(res: &mut SearchResult, opts: &SearchOptions) {
    if opts.max_tokens == 0 {
        return;
    }
    let budget_chars = opts.max_tokens.saturating_mul(4);
    loop {
        let rendered = render_search_text(res, opts);
        if rendered.len() <= budget_chars || res.files.is_empty() {
            break;
        }
        if !opts.files_only {
            if let Some(last) = res.files.last_mut() {
                if last.matches.len() > 1 {
                    last.matches.pop();
                    recompute_search_counts(res, opts.files_only);
                    continue;
                }
            }
        }
        res.files.pop();
        recompute_search_counts(res, opts.files_only);
    }
}

pub fn render_search_text(res: &SearchResult, opts: &SearchOptions) -> String {
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
        out.push_str(&format!(
            "... (+{} omitted matches across {} files; narrow with --glob/--type or --max-tokens)\n",
            res.omitted_matches, res.omitted_files
        ));
    }
    if opts.max_tokens > 0 {
        return crate::kit_util::clip_to_byte_budget(&out, opts.max_tokens.saturating_mul(4));
    }
    out
}

pub fn render_search_json(res: &SearchResult, opts: &SearchOptions) -> String {
    if opts.max_tokens == 0 {
        return serde_json::to_string(res).unwrap_or_else(|_| "{}".to_owned());
    }
    let budget_chars = opts.max_tokens.saturating_mul(4);
    let mut trimmed = res.clone();
    loop {
        let encoded = serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned());
        if encoded.len() <= budget_chars || trimmed.files.is_empty() {
            return encoded;
        }
        if !opts.files_only {
            if let Some(last) = trimmed.files.last_mut() {
                if last.matches.len() > 1 {
                    last.matches.pop();
                    recompute_search_counts(&mut trimmed, opts.files_only);
                    continue;
                }
            }
        }
        trimmed.files.pop();
        recompute_search_counts(&mut trimmed, opts.files_only);
    }
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

    #[test]
    fn enforces_max_tokens_in_text_and_json() {
        let tmp = Tmp::new("budget");
        for i in 0..20 {
            let body: String = (0..10)
                .map(|j| format!("const TARGET_{i}_{j} = \"value_{i}_{j}\";\n"))
                .collect();
            tmp.write(&format!("f{i}.ts"), body.as_bytes());
        }
        let opts = SearchOptions {
            pattern: "TARGET_".to_owned(),
            paths: vec![tmp.0.clone()],
            max_tokens: 160,
            ..SearchOptions::default()
        };
        let res = execute_search(&opts).unwrap();
        assert!(res.truncated);
        let txt = render_search_text(&res, &opts);
        assert!(txt.len() <= 160 * 4);
        let json = render_search_json(&res, &opts);
        assert!(json.len() <= 160 * 4);
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
