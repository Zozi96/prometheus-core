//! Structural file outline extraction with strict token budgets.

pub mod code;
pub mod lexer;
pub mod structured;

use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const BINARY_PROBE_BYTES: usize = 8192;
pub const DEFAULT_OUTLINE_MAX_TOKENS: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    CSharp,
    Razor,
    Rust,
    Python,
    TypeScript,
    JavaScript,
    Go,
    PowerShell,
    Json,
    Jsonl,
    Yaml,
    Toml,
    Markdown,
}

impl Lang {
    pub fn as_str(&self) -> &'static str {
        match self {
            Lang::CSharp => "csharp",
            Lang::Razor => "razor",
            Lang::Rust => "rust",
            Lang::Python => "python",
            Lang::TypeScript => "typescript",
            Lang::JavaScript => "javascript",
            Lang::Go => "go",
            Lang::PowerShell => "powershell",
            Lang::Json => "json",
            Lang::Jsonl => "jsonl",
            Lang::Yaml => "yaml",
            Lang::Toml => "toml",
            Lang::Markdown => "markdown",
        }
    }

    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "cs" => Some(Lang::CSharp),
            "razor" | "cshtml" => Some(Lang::Razor),
            "rs" => Some(Lang::Rust),
            "py" | "pyi" => Some(Lang::Python),
            "ts" | "tsx" | "mts" | "cts" => Some(Lang::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Lang::JavaScript),
            "go" => Some(Lang::Go),
            "ps1" | "psm1" | "psd1" => Some(Lang::PowerShell),
            "json" | "jsonc" => Some(Lang::Json),
            "jsonl" | "ndjson" => Some(Lang::Jsonl),
            "yml" | "yaml" => Some(Lang::Yaml),
            "toml" => Some(Lang::Toml),
            "md" | "markdown" | "mdx" => Some(Lang::Markdown),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "cs" | "csharp" | "c#" => Some(Lang::CSharp),
            "razor" | "cshtml" => Some(Lang::Razor),
            "rs" | "rust" => Some(Lang::Rust),
            "py" | "python" => Some(Lang::Python),
            "ts" | "tsx" | "typescript" => Some(Lang::TypeScript),
            "js" | "jsx" | "javascript" => Some(Lang::JavaScript),
            "go" | "golang" => Some(Lang::Go),
            "ps" | "ps1" | "psm1" | "psd1" | "powershell" => Some(Lang::PowerShell),
            "json" | "jsonc" => Some(Lang::Json),
            "jsonl" | "ndjson" => Some(Lang::Jsonl),
            "yml" | "yaml" => Some(Lang::Yaml),
            "toml" => Some(Lang::Toml),
            "md" | "markdown" | "mdx" => Some(Lang::Markdown),
            _ => None,
        }
    }

    pub fn default_depth(&self) -> usize {
        match self {
            Lang::Json | Lang::Yaml | Lang::Toml => 3,
            _ => 2,
        }
    }

    pub fn is_structured(&self) -> bool {
        matches!(
            self,
            Lang::Json | Lang::Jsonl | Lang::Yaml | Lang::Toml | Lang::Markdown
        )
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OutlineItem {
    pub kind: String,
    pub name: String,
    pub qualified_name: String,
    pub signature: String,
    pub start_line: usize,
    pub end_line: usize,
    pub depth: usize,
    pub children: Vec<OutlineItem>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OutlineDoc {
    pub path: String,
    pub lang: String,
    pub total_lines: usize,
    pub imports: Vec<String>,
    pub items: Vec<OutlineItem>,
    pub warnings: Vec<String>,
    /// Byte length of the source this doc was parsed from; metrics-only, never serialized.
    #[serde(skip)]
    pub raw_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct OutlineOptions {
    pub max_depth: Option<usize>,
    pub max_tokens: usize,
    pub kinds: Vec<String>,
    pub filter: Option<String>,
    pub include_imports: bool,
    pub include_all: bool,
}

impl Default for OutlineOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            max_tokens: DEFAULT_OUTLINE_MAX_TOKENS,
            kinds: Vec::new(),
            filter: None,
            include_imports: false,
            include_all: false,
        }
    }
}

/// Read a UTF-8 (or lossy UTF-8) regular text file up to `MAX_FILE_BYTES`, rejecting directories and binary files.
pub fn read_text_file(path: &Path) -> Result<(String, Vec<String>), String> {
    read_text_file_sized(path).map(|(text, warnings, _)| (text, warnings))
}

/// Like [`read_text_file`], also returning the original byte count before UTF-8 decode.
pub fn read_text_file_sized(path: &Path) -> Result<(String, Vec<String>, usize), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.len() > MAX_FILE_BYTES as u64 {
        return Err(format!(
            "{}: file exceeds {MAX_FILE_BYTES} bytes limit",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(1024 * 1024));
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if buf.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{}: file exceeds {MAX_FILE_BYTES} bytes limit",
            path.display()
        ));
    }
    let raw_bytes = buf.len();
    let probe_len = buf.len().min(BINARY_PROBE_BYTES);
    if buf[..probe_len].contains(&0) {
        return Err(format!("{}: binary file skipped", path.display()));
    }
    match String::from_utf8(buf) {
        Ok(text) => Ok((text, Vec::new(), raw_bytes)),
        Err(err) => {
            let lossy = String::from_utf8_lossy(err.as_bytes()).into_owned();
            Ok((
                lossy,
                vec!["non-UTF-8 bytes replaced with U+FFFD".to_owned()],
                raw_bytes,
            ))
        }
    }
}

pub fn outline_source(path: &str, src: &str, lang: Lang, opts: &OutlineOptions) -> OutlineDoc {
    let idx = lexer::LineIndex::new(src);
    let mut doc = if lang.is_structured() {
        structured::parse_structured(path, src, &idx, lang, opts)
    } else {
        code::parse_code(path, src, &idx, lang, opts)
    };
    doc.total_lines = idx.total_lines();
    doc.raw_bytes = src.len();
    doc
}

pub fn outline_file(
    path: &Path,
    lang_override: Option<Lang>,
    opts: &OutlineOptions,
) -> Result<OutlineDoc, String> {
    let lang = lang_override
        .or_else(|| Lang::from_path(path))
        .ok_or_else(|| {
            format!(
                "{}: unsupported file type (pass --lang to specify)",
                path.display()
            )
        })?;
    let (src, mut warnings, raw_bytes) = read_text_file_sized(path)?;
    let mut doc = outline_source(&path.to_string_lossy(), &src, lang, opts);
    doc.raw_bytes = raw_bytes;
    warnings.extend(doc.warnings);
    doc.warnings = warnings;
    Ok(doc)
}

pub fn flatten_items(items: &[OutlineItem]) -> Vec<&OutlineItem> {
    let mut out = Vec::new();
    fn visit<'a>(items: &'a [OutlineItem], out: &mut Vec<&'a OutlineItem>) {
        for item in items {
            out.push(item);
            visit(&item.children, out);
        }
    }
    visit(items, &mut out);
    out
}

fn count_items(items: &[OutlineItem]) -> usize {
    items.iter().map(|it| 1 + count_items(&it.children)).sum()
}

fn kind_alias(raw: &str) -> &str {
    match raw {
        "fn" | "func" => "function",
        "cls" => "class",
        "iface" => "interface",
        "sec" | "section" => "heading",
        "prop" => "property",
        "ctor" => "constructor",
        "ns" => "namespace",
        "rec" => "record",
        "mod" => "module",
        "attr" => "directive",
        other => other,
    }
}

fn kind_matches(item_kind: &str, kinds: &[String]) -> bool {
    if kinds.is_empty() {
        return true;
    }
    let item_norm = kind_alias(&item_kind.to_ascii_lowercase()).to_owned();
    kinds.iter().any(|k| {
        let lower = k.trim().to_ascii_lowercase();
        let wanted = kind_alias(&lower);
        item_norm == wanted || item_kind.eq_ignore_ascii_case(k.trim())
    })
}

fn text_matches(item: &OutlineItem, filter_lower: &str) -> bool {
    item.name.to_ascii_lowercase().contains(filter_lower)
        || item
            .qualified_name
            .to_ascii_lowercase()
            .contains(filter_lower)
        || item.signature.to_ascii_lowercase().contains(filter_lower)
}

fn filter_items(
    items: &[OutlineItem],
    max_depth: usize,
    kinds: &[String],
    filter_lower: Option<&str>,
    ancestor_filter_hit: bool,
) -> Vec<OutlineItem> {
    let mut out = Vec::new();
    for item in items {
        if item.depth > max_depth {
            continue;
        }
        let this_filter_hit = match filter_lower {
            Some(f) => ancestor_filter_hit || text_matches(item, f),
            None => true,
        };
        let child_filter_inherited = match filter_lower {
            Some(f) => ancestor_filter_hit || text_matches(item, f),
            None => true,
        };
        let children = filter_items(
            &item.children,
            max_depth,
            kinds,
            filter_lower,
            child_filter_inherited,
        );
        let self_ok = this_filter_hit && kind_matches(&item.kind, kinds);
        if self_ok || !children.is_empty() {
            let mut cloned = item.clone();
            cloned.children = children;
            out.push(cloned);
        }
    }
    out
}

fn effective_depth(doc: &OutlineDoc, opts: &OutlineOptions) -> usize {
    if let Some(d) = opts.max_depth {
        return d;
    }
    if opts.filter.is_some() || !opts.kinds.is_empty() {
        return usize::MAX;
    }
    Lang::from_name(&doc.lang)
        .map(|l| l.default_depth())
        .unwrap_or(2)
}

fn filtered_doc(doc: &OutlineDoc, opts: &OutlineOptions) -> OutlineDoc {
    let max_depth = effective_depth(doc, opts);
    let filter_lower = opts
        .filter
        .as_deref()
        .map(|f| f.trim().to_ascii_lowercase())
        .filter(|f| !f.is_empty());
    let items = filter_items(
        &doc.items,
        max_depth,
        &opts.kinds,
        filter_lower.as_deref(),
        false,
    );
    OutlineDoc {
        path: doc.path.clone(),
        lang: doc.lang.clone(),
        total_lines: doc.total_lines,
        imports: if opts.include_imports {
            doc.imports.clone()
        } else {
            Vec::new()
        },
        items,
        warnings: doc.warnings.clone(),
        raw_bytes: doc.raw_bytes,
    }
}

fn format_line_range(start: usize, end: usize) -> String {
    if start == end {
        format!("L{start}")
    } else {
        format!("L{start}-L{end}")
    }
}

pub fn render_outline_text(docs: &[OutlineDoc], opts: &OutlineOptions) -> String {
    let budget_chars = if opts.max_tokens == 0 {
        usize::MAX
    } else {
        opts.max_tokens.saturating_mul(4)
    };
    const RESERVE: usize = 84;
    let filtered: Vec<OutlineDoc> = docs.iter().map(|d| filtered_doc(d, opts)).collect();
    let total_filtered_items: usize = filtered.iter().map(|d| count_items(&d.items)).sum();

    let mut out = String::new();
    let mut emitted_items = 0usize;
    let mut truncated = false;

    for (doc_idx, doc) in filtered.iter().enumerate() {
        if doc_idx > 0 {
            if out.len() + 1 >= budget_chars.saturating_sub(RESERVE) {
                truncated = true;
                break;
            }
            out.push('\n');
        }
        let header = format!("{} [{}, {} lines]\n", doc.path, doc.lang, doc.total_lines);
        if !out.is_empty() && out.len() + header.len() > budget_chars.saturating_sub(RESERVE) {
            truncated = true;
            break;
        }
        out.push_str(&header);
        for w in &doc.warnings {
            let line = format!("  warning: {w}\n");
            if out.len() + line.len() <= budget_chars.saturating_sub(RESERVE) {
                out.push_str(&line);
            }
        }
        if opts.include_imports && !doc.imports.is_empty() {
            let joined = doc.imports.join(", ");
            let line = format!(
                "  imports: {}\n",
                lexer::normalize_signature(&joined, 200)
            );
            if out.len() + line.len() <= budget_chars.saturating_sub(RESERVE) {
                out.push_str(&line);
            }
        }
        if doc.items.is_empty() {
            let empty_line = "  (no matching items)\n";
            if out.len() + empty_line.len() <= budget_chars {
                out.push_str(empty_line);
            }
            continue;
        }

        fn emit_items(
            items: &[OutlineItem],
            indent: usize,
            out: &mut String,
            emitted_items: &mut usize,
            budget_chars: usize,
        ) -> bool {
            for item in items {
                let pad = "  ".repeat(indent);
                let range = format_line_range(item.start_line, item.end_line);
                let line = format!("{pad}{range} {}\n", item.signature);
                if *emitted_items > 0 && out.len() + line.len() + RESERVE > budget_chars {
                    return false;
                }
                if *emitted_items == 0 && budget_chars != usize::MAX && out.len() + line.len() > budget_chars {
                    let keep = budget_chars.saturating_sub(out.len() + RESERVE).max(32);
                    let clipped = lexer::normalize_signature(&item.signature, keep);
                    out.push_str(&format!("{pad}{range} {clipped}\n"));
                    *emitted_items += 1;
                    return false;
                }
                out.push_str(&line);
                *emitted_items += 1;
                if !emit_items(&item.children, indent + 1, out, emitted_items, budget_chars) {
                    return false;
                }
            }
            true
        }

        if !emit_items(&doc.items, 1, &mut out, &mut emitted_items, budget_chars) {
            truncated = true;
            break;
        }
    }

    if truncated {
        let omitted = total_filtered_items.saturating_sub(emitted_items);
        if omitted > 0 || filtered.len() > 1 {
            out.push_str(&format!(
                "... (+{omitted} omitted items; narrow with --depth, --filter, or --max-tokens)\n"
            ));
        }
    }
    out
}

#[derive(Serialize)]
struct OutlineJsonResponse {
    docs: Vec<OutlineDoc>,
    truncated: bool,
    omitted_items: usize,
}

fn prune_items_for_budget(
    items: &[OutlineItem],
    remaining: &mut usize,
    omitted: &mut usize,
) -> Vec<OutlineItem> {
    let mut out = Vec::new();
    for item in items {
        if *remaining == 0 {
            *omitted += 1 + count_items(&item.children);
            continue;
        }
        *remaining -= 1;
        let children = prune_items_for_budget(&item.children, remaining, omitted);
        let mut cloned = item.clone();
        cloned.children = children;
        out.push(cloned);
    }
    out
}

pub fn render_outline_json(docs: &[OutlineDoc], opts: &OutlineOptions) -> String {
    let mut filtered: Vec<OutlineDoc> = docs.iter().map(|d| filtered_doc(d, opts)).collect();
    if opts.max_tokens == 0 {
        let resp = OutlineJsonResponse {
            docs: filtered,
            truncated: false,
            omitted_items: 0,
        };
        return serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_owned());
    }
    let budget_chars = opts.max_tokens.saturating_mul(4);
    let total_items: usize = filtered.iter().map(|d| count_items(&d.items)).sum();
    let full = OutlineJsonResponse {
        docs: filtered.clone(),
        truncated: false,
        omitted_items: 0,
    };
    let serialized = serde_json::to_string(&full).unwrap_or_else(|_| "{}".to_owned());
    if serialized.len() <= budget_chars || total_items == 0 {
        return serialized;
    }
    // Binary search maximum item count whose emitted compact JSON fits within budget_chars.
    let mut lo = 1usize;
    let mut hi = total_items;
    let mut best_json = None;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let mut rem = mid;
        let mut omitted = 0usize;
        let mut candidate_docs = Vec::with_capacity(filtered.len());
        for d in &filtered {
            let mut cd = d.clone();
            cd.items = prune_items_for_budget(&d.items, &mut rem, &mut omitted);
            candidate_docs.push(cd);
        }
        let resp = OutlineJsonResponse {
            docs: candidate_docs,
            truncated: omitted > 0,
            omitted_items: omitted,
        };
        let encoded = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_owned());
        if encoded.len() <= budget_chars {
            best_json = Some(encoded);
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }
    match best_json {
        Some(encoded) => encoded,
        None => {
            let mut omitted = 0usize;
            for d in &mut filtered {
                omitted += count_items(&d.items);
                d.items.clear();
            }
            let resp = OutlineJsonResponse {
                docs: filtered,
                truncated: omitted > 0,
                omitted_items: omitted,
            };
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_owned())
        }
    }
}
