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
pub struct OutlineError {
    pub path: String,
    pub message: String,
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
    decode_text_bytes(&path.to_string_lossy(), buf)
}

/// Decode bounded bytes with the same binary and UTF-8 contract as file reads.
pub(crate) fn decode_text_bytes(
    display: &str,
    buf: Vec<u8>,
) -> Result<(String, Vec<String>, usize), String> {
    let raw_bytes = buf.len();
    let probe_len = buf.len().min(BINARY_PROBE_BYTES);
    if buf[..probe_len].contains(&0) {
        return Err(format!("{display}: binary file skipped"));
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
    render_outline_text_with_errors(docs, &[], opts)
}

/// Drop the last item in document order (deepest child of the last
/// top-level item first). One give-up of `outline`'s head Keep policy.
fn drop_last_item(items: &mut Vec<OutlineItem>) -> bool {
    let Some(last) = items.last_mut() else {
        return false;
    };
    if !last.children.is_empty() {
        return drop_last_item(&mut last.children);
    }
    items.pop();
    true
}

/// `outline`'s head-policy give-up across several docs: the last item
/// of the last doc that still has items.
fn outline_trim_step(docs: &mut [OutlineDoc], omitted_items: &mut usize) -> bool {
    for doc in docs.iter_mut().rev() {
        if drop_last_item(&mut doc.items) {
            *omitted_items += 1;
            return true;
        }
    }
    false
}

/// The TEXT path's give-up: like [`outline_trim_step`], but working
/// strictly from the end — once the last doc has no items left, the
/// doc itself (its header) is dropped before any earlier doc loses
/// another item. Without this, batch outlines whose headers alone
/// exceed the budget stripped EVERY symbol from the first file even
/// when that file's full outline plus the notice would have fit
/// (Devin Review, "Later outline headers crowd out symbols"): the
/// head Keep policy applies to document sections and their items
/// together. The JSON path keeps [`outline_trim_step`]: its smallest
/// valid document still carries each doc's shell.
fn outline_text_trim_step(
    docs: &mut Vec<OutlineDoc>,
    omitted_items: &mut usize,
    omitted_docs: &mut usize,
) -> bool {
    let Some(last) = docs.last_mut() else {
        return false;
    };
    if drop_last_item(&mut last.items) {
        *omitted_items += 1;
        return true;
    }
    docs.pop();
    *omitted_docs += 1;
    true
}

/// Exact first-fit trim for batch text outlines, in the give-up
/// order of [`outline_text_trim_step`].
///
/// Two failure modes shape this design. First, rendered length is
/// NOT monotone in the step count for batch text — the step that
/// first drops an item after whole files were dropped switches the
/// notice from its files-only to its combined wording (longer),
/// and the step that empties a file swaps its last item line for
/// the "(no matching items)" placeholder (which can be longer) —
/// so a fitting state can sit between two over-budget states, and
/// the generic bisect skipped it and dropped a file that fit
/// (Devin Review, "Fitting file dropped from outline"). Second,
/// searching by rendering candidate states is quadratic on large
/// batches: every probe re-rendered the surviving prefix and the
/// earlier segmented search cloned it twice per dropped file
/// (Devin Review, "Quadratic slowdown for batch outlines").
///
/// So the search never renders or clones at all. Per-doc render
/// lengths are precomputed once (drop order is the reverse of the
/// render's pre-order, because [`drop_last_item`] removes the last
/// leaf each step), the notice length is arithmetic, and the error
/// tail length uses a precomputed prefix-sum model mirroring
/// `budget::append_error_lines` exactly — so each fit probe is O(1)
/// for document/notice lengths (and when no errors are present) and
/// O(log M) via binary search over error messages when errors exist.
/// The search walks segment by segment (one segment = the trailing
/// file's items, then the file itself): if the segment's end state
/// does not fit, the whole segment is consumed with no further
/// evaluations; if it fits, the first fitting prefix inside the
/// segment is found by checking the two possible growth points
/// (the first item drop; the item drop that empties the file)
/// explicitly and bisecting the strictly shrinking range between
/// them. Only the chosen step count is materialized, applied to
/// the real state once.
fn trim_outline_text(
    state: &mut (Vec<OutlineDoc>, usize, usize),
    opts: &OutlineOptions,
    messages: &[String],
) {
    let Some(budget) = crate::budget::tokens_to_bytes(opts.max_tokens) else {
        return;
    };
    let measures: Vec<DocMeasure> = state
        .0
        .iter()
        .enumerate()
        .map(|(idx, doc)| measure_doc(doc, idx, opts))
        .collect();
    // full_prefix[s] = rendered length of the first s docs, whole.
    let mut full_prefix = vec![0usize; measures.len() + 1];
    for (i, m) in measures.iter().enumerate() {
        full_prefix[i + 1] = full_prefix[i] + m.full_len();
    }
    let error_model = ErrorTailModel::new(messages);
    let fit =
        |surviving: usize, partial_drops: usize, omitted_items: usize, omitted_docs: usize| {
            let docs_len = if surviving == 0 {
                outline_notice_len(omitted_items, omitted_docs)
            } else {
                let m = &measures[surviving - 1];
                full_prefix[surviving - 1]
                    + m.partial_len(partial_drops)
                    + outline_notice_len(omitted_items, omitted_docs)
            };
            docs_len + error_model.tail_len(docs_len, opts.max_tokens) <= budget
        };
    if fit(measures.len(), 0, 0, 0) {
        return;
    }
    // Invariant: the current search state does not fit; find its
    // first fitting successor in give-up order, as a step count.
    let mut steps = 0usize;
    let mut surviving = measures.len();
    let mut omitted_items = 0usize;
    let mut omitted_docs = 0usize;
    let chosen = loop {
        if surviving == 0 {
            break steps;
        }
        let m = &measures[surviving - 1];
        let end_items = omitted_items + m.item_count;
        let end_docs = omitted_docs + 1;
        if !fit(surviving - 1, 0, end_items, end_docs) {
            // The whole segment is consumed; its end is the new
            // (still non-fitting) current state.
            steps += m.item_count + 1;
            omitted_items = end_items;
            omitted_docs = end_docs;
            surviving -= 1;
            continue;
        }
        if m.item_count == 0 {
            break steps + 1;
        }
        // First item drop: the notice may appear here, or switch
        // from files-only to combined wording — check it directly.
        if fit(surviving, 1, omitted_items + 1, omitted_docs) {
            break steps + 1;
        }
        // Strictly shrinking range: item drops 2..item_count (the
        // file still has items afterwards, the notice composition
        // is stable) — bisect it.
        if m.item_count >= 3 {
            let last_zone = m.item_count - 1;
            if fit(
                surviving,
                last_zone,
                omitted_items + last_zone,
                omitted_docs,
            ) {
                let (mut lo, mut hi) = (1usize, last_zone);
                while lo + 1 < hi {
                    let mid = lo + (hi - lo) / 2;
                    if fit(surviving, mid, omitted_items + mid, omitted_docs) {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }
                break steps + hi;
            }
        }
        // The item drop that empties the file (placeholder swap).
        if m.item_count >= 2 && fit(surviving, m.item_count, end_items, omitted_docs) {
            break steps + m.item_count;
        }
        break steps + m.item_count + 1;
    };
    for _ in 0..chosen {
        if !outline_text_trim_step(&mut state.0, &mut state.1, &mut state.2) {
            break;
        }
    }
}

/// One doc's precomputed render lengths for [`trim_outline_text`].
struct DocMeasure {
    /// Separator, header, warnings and imports lines: everything
    /// that survives item drops.
    fixed: usize,
    /// Sum of all item line lengths.
    items_total: usize,
    /// `drop_suffix[k]` = total length of the first k dropped item
    /// lines, in drop order (the reverse of render order).
    drop_suffix: Vec<usize>,
    item_count: usize,
}

impl DocMeasure {
    fn full_len(&self) -> usize {
        self.fixed
            + if self.item_count > 0 {
                self.items_total
            } else {
                OUTLINE_NO_ITEMS_LEN
            }
    }

    fn partial_len(&self, drops: usize) -> usize {
        self.fixed
            + if drops < self.item_count {
                self.items_total - self.drop_suffix[drops]
            } else {
                OUTLINE_NO_ITEMS_LEN
            }
    }
}

/// The rendered placeholder for a doc with no items:
/// `"  (no matching items)\n"`.
const OUTLINE_NO_ITEMS_LEN: usize = 22;

fn measure_doc(doc: &OutlineDoc, idx: usize, opts: &OutlineOptions) -> DocMeasure {
    let mut fixed = if idx > 0 { 1 } else { 0 };
    fixed += doc.path.len() + doc.lang.len() + digits(doc.total_lines) + 12;
    for w in &doc.warnings {
        fixed += w.len() + 12;
    }
    if opts.include_imports && !doc.imports.is_empty() {
        let joined = doc.imports.join(", ");
        fixed += lexer::normalize_signature(&joined, 200).len() + 12;
    }
    fn walk(items: &[OutlineItem], indent: usize, lines: &mut Vec<usize>) {
        for item in items {
            let range_len = if item.start_line == item.end_line {
                digits(item.start_line) + 1
            } else {
                digits(item.start_line) + digits(item.end_line) + 3
            };
            lines.push(2 * indent + range_len + 1 + item.signature.len() + 1);
            walk(&item.children, indent + 1, lines);
        }
    }
    let mut lines = Vec::new();
    walk(&doc.items, 1, &mut lines);
    let item_count = lines.len();
    let items_total: usize = lines.iter().sum();
    let mut drop_suffix = vec![0usize; item_count + 1];
    for k in 1..=item_count {
        drop_suffix[k] = drop_suffix[k - 1] + lines[item_count - k];
    }
    DocMeasure {
        fixed,
        items_total,
        drop_suffix,
        item_count,
    }
}

fn digits(n: usize) -> usize {
    if n == 0 { 1 } else { (n.ilog10() + 1) as usize }
}

/// [`outline_notice`]'s rendered length including its newline, or
/// 0 when there is no notice. Mirrors the format exactly: the
/// items-only and files-only wordings share a fixed length, the
/// combined wording is longer by a fixed amount.
fn outline_notice_len(omitted_items: usize, omitted_docs: usize) -> usize {
    match (omitted_items, omitted_docs) {
        (0, 0) => 0,
        (items, 0) => 69 + digits(items) + 1,
        (0, docs) => 69 + digits(docs) + 1,
        (items, docs) => 86 + digits(items) + digits(docs) + 1,
    }
}

/// Precomputed prefix-sum model for `budget::append_error_lines`,
/// answering [`ErrorTailModel::tail_len`] in O(log M) via binary search
/// (and O(1) when `messages` is empty). Locked to the real function by
/// `outline_length_model_mirrors_the_real_renderers`.
struct ErrorTailModel<'a> {
    messages: &'a [String],
    prefix: Vec<usize>,
}

impl<'a> ErrorTailModel<'a> {
    fn new(messages: &'a [String]) -> Self {
        let mut prefix = Vec::with_capacity(messages.len() + 1);
        prefix.push(0);
        for message in messages {
            let prev = *prefix.last().unwrap_or(&0);
            prefix.push(prev + message.len() + 8); // "error: " + message + "\n"
        }
        Self { messages, prefix }
    }

    fn tail_len(&self, docs_len: usize, max_tokens: usize) -> usize {
        if self.messages.is_empty() {
            return 0;
        }
        let n = self.messages.len();
        let budget_chars = crate::budget::byte_budget_or_max(max_tokens);
        let sep = usize::from(docs_len > 0 && (budget_chars == usize::MAX || docs_len + 1 < budget_chars));
        if budget_chars == usize::MAX {
            return sep + self.prefix[n];
        }
        let cur0 = docs_len + sep;
        let non_last_fit = self.prefix[1..n]
            .partition_point(|&cum| cur0.saturating_add(cum).saturating_add(36) <= budget_chars);
        if non_last_fit == n - 1 && cur0.saturating_add(self.prefix[n]) <= budget_chars {
            return sep + self.prefix[n];
        }
        let mut emitted = non_last_fit;
        let mut extra = sep + self.prefix[emitted];
        let cur = cur0 + self.prefix[emitted];
        if emitted == 0 && cur.saturating_add(16) < budget_chars {
            let reserve = if n > 1 { 36 } else { 0 };
            let avail = budget_chars.saturating_sub(cur + 8 + reserve).max(16);
            extra += lexer::normalize_signature(&self.messages[0], avail).len() + 8;
            emitted = 1;
        }
        let omitted = n - emitted;
        if omitted > 0 {
            // "... (+{omitted} omitted errors)\n"
            extra += 23 + digits(omitted);
        }
        extra
    }
}

/// The `outline` truncation notice, without its trailing newline.
/// The items-only wording is the historical one; dropped file
/// sections are disclosed alongside it (Devin Review, "Silent file
/// omissions in outlines": a dropped doc whose items were already
/// gone — or which never had matching items — used to leave the
/// omitted count at zero and suppress the notice entirely).
fn outline_notice(omitted_items: usize, omitted_docs: usize) -> String {
    match (omitted_items, omitted_docs) {
        (0, 0) => String::new(),
        (items, 0) => {
            format!("... (+{items} omitted items; narrow with --depth, --filter, or --max-tokens)")
        }
        (0, docs) => {
            format!("... (+{docs} omitted files; narrow with --depth, --filter, or --max-tokens)")
        }
        (items, docs) => format!(
            "... (+{items} omitted items, +{docs} omitted files; narrow with --depth, --filter, or --max-tokens)"
        ),
    }
}

fn render_outline_text_docs(
    docs: &[OutlineDoc],
    omitted_items: usize,
    omitted_docs: usize,
    opts: &OutlineOptions,
) -> String {
    let mut out = String::new();
    for (doc_idx, doc) in docs.iter().enumerate() {
        if doc_idx > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "{} [{}, {} lines]\n",
            doc.path, doc.lang, doc.total_lines
        ));
        for w in &doc.warnings {
            out.push_str(&format!("  warning: {w}\n"));
        }
        if opts.include_imports && !doc.imports.is_empty() {
            let joined = doc.imports.join(", ");
            out.push_str(&format!(
                "  imports: {}\n",
                lexer::normalize_signature(&joined, 200)
            ));
        }
        if doc.items.is_empty() {
            out.push_str("  (no matching items)\n");
            continue;
        }
        fn emit_items(items: &[OutlineItem], indent: usize, out: &mut String) {
            for item in items {
                let pad = "  ".repeat(indent);
                let range = format_line_range(item.start_line, item.end_line);
                out.push_str(&format!("{pad}{range} {}\n", item.signature));
                emit_items(&item.children, indent + 1, out);
            }
        }
        emit_items(&doc.items, 1, &mut out);
    }
    if omitted_items > 0 || omitted_docs > 0 {
        out.push_str(&outline_notice(omitted_items, omitted_docs));
        out.push('\n');
    }
    out
}

pub fn render_outline_text_with_errors(
    docs: &[OutlineDoc],
    errors: &[OutlineError],
    opts: &OutlineOptions,
) -> String {
    let filtered: Vec<OutlineDoc> = docs.iter().map(|d| filtered_doc(d, opts)).collect();
    let messages: Vec<String> = errors.iter().map(|e| e.message.clone()).collect();
    if opts.max_tokens == 0 {
        let mut out = render_outline_text_docs(&filtered, 0, 0, opts);
        crate::budget::append_error_lines(
            &mut out,
            &messages,
            0,
            lexer::normalize_signature,
        );
        return out;
    }
    // Head policy: items are given up from the end of the document
    // order, and a trailing doc whose items are gone is dropped
    // whole (header included) before earlier docs lose items; the
    // error tail is appended under the same budget by the budget
    // module's shared routine. The trim itself is the exact
    // length-model search above (trim_outline_text): batch text
    // length is not monotone in the step count, so the generic
    // bisect could skip a fitting state, and rendering candidates
    // would be quadratic on large batches.
    let mut state = (filtered, 0usize, 0usize);
    trim_outline_text(&mut state, opts, &messages);
    let (docs, omitted, omitted_docs) = &state;
    let mut out = render_outline_text_docs(docs, *omitted, *omitted_docs, opts);
    crate::budget::append_error_lines(
        &mut out,
        &messages,
        opts.max_tokens,
        lexer::normalize_signature,
    );
    let notice = outline_notice(*omitted, *omitted_docs);
    crate::budget::finish_text(
        out,
        opts.max_tokens,
        crate::budget::KeepPolicy::Head,
        &notice,
    )
}

/// The one shared JSON error-list cap (budget module), instantiated
/// for outline errors.
fn cap_outline_errors(errors: &[OutlineError], max_bytes: usize) -> (Vec<OutlineError>, bool) {
    crate::budget::cap_error_list(errors, max_bytes, |omitted| OutlineError {
        path: "...".to_owned(),
        message: format!("... (+{omitted} omitted errors)"),
    })
}

#[derive(Clone, Serialize)]
struct OutlineJsonResponse {
    docs: Vec<OutlineDoc>,
    truncated: bool,
    omitted_items: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<OutlineError>,
}

pub fn render_outline_json(docs: &[OutlineDoc], opts: &OutlineOptions) -> String {
    render_outline_json_with_errors(docs, &[], opts)
}

pub fn render_outline_json_with_errors(
    docs: &[OutlineDoc],
    errors: &[OutlineError],
    opts: &OutlineOptions,
) -> String {
    let filtered: Vec<OutlineDoc> = docs.iter().map(|d| filtered_doc(d, opts)).collect();
    if opts.max_tokens == 0 {
        let resp = OutlineJsonResponse {
            docs: filtered,
            truncated: false,
            omitted_items: 0,
            errors: errors.to_vec(),
        };
        return serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_owned());
    }
    let budget_chars = crate::budget::byte_budget_or_max(opts.max_tokens);
    let total_items: usize = filtered.iter().map(|d| count_items(&d.items)).sum();
    let full = OutlineJsonResponse {
        docs: filtered.clone(),
        truncated: false,
        omitted_items: 0,
        errors: errors.to_vec(),
    };
    let serialized = serde_json::to_string(&full).unwrap_or_else(|_| "{}".to_owned());
    if serialized.len() <= budget_chars {
        return serialized;
    }
    let err_budget = if filtered.is_empty() {
        budget_chars.saturating_sub(96)
    } else {
        (budget_chars / 2).max(96)
    };
    let (capped_errors, errors_clipped) = cap_outline_errors(errors, err_budget);
    if total_items == 0 {
        let resp = OutlineJsonResponse {
            docs: filtered,
            truncated: errors_clipped,
            omitted_items: 0,
            errors: capped_errors,
        };
        return serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_owned());
    }
    // Head policy through the budget module, measured against the JSON
    // document: items are given up from the end of the document order.
    // The smallest valid document (no items left) wins over the budget.
    // Bisect variant, as in the text path: every step removes a whole
    // serialized item — far longer than the omitted-count digits it
    // can grow — so rendered length is monotone in the step count.
    let mut state = OutlineJsonResponse {
        docs: filtered,
        truncated: errors_clipped,
        omitted_items: 0,
        errors: capped_errors,
    };
    crate::budget::trim_structured_bisect(
        &mut state,
        opts.max_tokens,
        |s| serde_json::to_string(s).unwrap_or_else(|_| "{}".to_owned()),
        |s| {
            let mut omitted = s.omitted_items;
            let stepped = outline_trim_step(&mut s.docs, &mut omitted);
            if stepped {
                s.omitted_items = omitted;
                s.truncated = true;
            }
            stepped
        },
    );
    serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> (OutlineDoc, (String, String, String)) {
        let sigs = (
            format!("pub fn alpha({})", "x".repeat(30)),
            format!("pub fn beta({})", "y".repeat(30)),
            format!("pub fn gamma({})", "z".repeat(30)),
        );
        let item = |name: &str, sig: &String, line: usize| OutlineItem {
            kind: "function".to_owned(),
            name: name.to_owned(),
            qualified_name: name.to_owned(),
            signature: sig.clone(),
            start_line: line,
            end_line: line,
            depth: 0,
            children: vec![],
        };
        let doc = OutlineDoc {
            path: "a.rs".to_owned(),
            lang: "rust".to_owned(),
            total_lines: 3,
            imports: vec![],
            items: vec![
                item("alpha", &sigs.0, 1),
                item("beta", &sigs.1, 2),
                item("gamma", &sigs.2, 3),
            ],
            warnings: vec![],
            raw_bytes: 0,
        };
        (doc, sigs)
    }

    #[test]
    fn outline_bisect_trim_matches_sequential_on_a_large_doc() {
        // Regression (Devin Review BUG_..._0003): the outline trim
        // searches instead of re-rendering after every dropped
        // item; on a large doc its output must stay byte-identical
        // to the sequential trim, in text and in JSON. (The JSON
        // search is the generic bisect; the text search is the
        // exact segmented one — batch text length is not monotone
        // in the step count, see trim_outline_text.)
        let sig = format!("pub fn f({})", "x".repeat(24));
        let items: Vec<OutlineItem> = (0..120)
            .map(|i| OutlineItem {
                kind: "function".to_owned(),
                name: format!("f{i}"),
                qualified_name: format!("f{i}"),
                signature: sig.clone(),
                start_line: i + 1,
                end_line: i + 1,
                depth: 0,
                children: vec![],
            })
            .collect();
        let doc = OutlineDoc {
            path: "big.rs".to_owned(),
            lang: "rust".to_owned(),
            total_lines: 120,
            imports: vec![],
            items,
            warnings: vec![],
            raw_bytes: 0,
        };
        for max_tokens in [40usize, 90, 200, 700] {
            let opts = OutlineOptions {
                max_tokens,
                ..OutlineOptions::default()
            };
            // Text: reproduce the production pipeline with the
            // sequential trim and compare byte for byte.
            let filtered: Vec<OutlineDoc> = std::slice::from_ref(&doc)
                .iter()
                .map(|d| filtered_doc(d, &opts))
                .collect();
            let mut seq_state = (filtered, 0usize, 0usize);
            crate::budget::trim_structured(
                &mut seq_state,
                max_tokens,
                |(docs, omitted, omitted_docs)| {
                    render_outline_text_docs(docs, *omitted, *omitted_docs, &opts)
                },
                |(docs, omitted, omitted_docs)| outline_text_trim_step(docs, omitted, omitted_docs),
            );
            let (seq_docs, seq_omitted, seq_omitted_docs) = &seq_state;
            let mut seq_out =
                render_outline_text_docs(seq_docs, *seq_omitted, *seq_omitted_docs, &opts);
            let seq_notice = outline_notice(*seq_omitted, *seq_omitted_docs);
            seq_out = crate::budget::finish_text(
                seq_out,
                max_tokens,
                crate::budget::KeepPolicy::Head,
                &seq_notice,
            );
            assert_eq!(
                render_outline_text_with_errors(std::slice::from_ref(&doc), &[], &opts),
                seq_out,
                "text, max_tokens {max_tokens}"
            );
            // JSON: same comparison at the response level.
            let filtered: Vec<OutlineDoc> = std::slice::from_ref(&doc)
                .iter()
                .map(|d| filtered_doc(d, &opts))
                .collect();
            let mut seq_resp = OutlineJsonResponse {
                docs: filtered,
                truncated: false,
                omitted_items: 0,
                errors: vec![],
            };
            crate::budget::trim_structured(
                &mut seq_resp,
                max_tokens,
                |s| serde_json::to_string(s).unwrap_or_else(|_| "{}".to_owned()),
                |s| {
                    let mut omitted = s.omitted_items;
                    let stepped = outline_trim_step(&mut s.docs, &mut omitted);
                    if stepped {
                        s.omitted_items = omitted;
                        s.truncated = true;
                    }
                    stepped
                },
            );
            let seq_json = serde_json::to_string(&seq_resp).unwrap();
            assert_eq!(
                render_outline_json_with_errors(std::slice::from_ref(&doc), &[], &opts),
                seq_json,
                "json, max_tokens {max_tokens}"
            );
        }
    }

    // Exact-output budget-edge tests (#100).
    #[test]
    fn outline_text_budget_edge_exact_fit_one_token_less_and_below_notice() {
        let (doc, (s1, s2, s3)) = sample_doc();
        let opts0 = OutlineOptions::default();
        let full = render_outline_text(std::slice::from_ref(&doc), &opts0);
        assert_eq!(
            full,
            format!("a.rs [rust, 3 lines]\n  L1 {s1}\n  L2 {s2}\n  L3 {s3}\n")
        );
        let exact = full.len().div_ceil(4);
        let opts_exact = OutlineOptions {
            max_tokens: exact,
            ..OutlineOptions::default()
        };
        assert_eq!(
            render_outline_text(std::slice::from_ref(&doc), &opts_exact),
            full
        );
        // One token less: head is kept (header + first item), the cut
        // lands on a line end, and the outline notice survives.
        let opts_less = OutlineOptions {
            max_tokens: exact - 1,
            ..OutlineOptions::default()
        };
        let less = render_outline_text(std::slice::from_ref(&doc), &opts_less);
        assert_eq!(
            less,
            format!(
                "a.rs [rust, 3 lines]\n  L1 {s1}\n\
                 ... (+2 omitted items; narrow with --depth, --filter, or --max-tokens)\n"
            )
        );
        assert!(less.len() <= (exact - 1) * 4);
        // Budget smaller than the notice: the notice alone.
        let opts_tiny = OutlineOptions {
            max_tokens: 10,
            ..OutlineOptions::default()
        };
        // Updated for the Devin Review finding "Silent file omissions
        // in outlines": at this budget the doc itself is dropped after
        // its items, and the notice now discloses the dropped file
        // section alongside the omitted items (previously the bare
        // "+3 omitted items" wording).
        assert_eq!(
            render_outline_text(std::slice::from_ref(&doc), &opts_tiny),
            "... (+3 omitted items, +1 omitted files; narrow with --depth, --filter, or --max-tokens)\n"
        );
    }

    #[test]
    fn outline_batch_headers_do_not_crowd_out_first_file_symbols() {
        // Regression (Devin Review, "Later outline headers crowd out
        // symbols"): six files whose headers alone crowd the budget.
        // The old step could only drop items, so it stripped every
        // symbol — including the first file's, whose full outline
        // plus the notice fits easily. The text step now drops
        // trailing docs whole (header included) once their items are
        // gone, before earlier docs lose items.
        let docs: Vec<OutlineDoc> = (0..6)
            .map(|i| OutlineDoc {
                path: format!("a/very/long/path/to/file{i}.rs"),
                lang: "rust".to_owned(),
                total_lines: 1,
                imports: vec![],
                items: vec![OutlineItem {
                    kind: "function".to_owned(),
                    name: format!("symbol{i}"),
                    qualified_name: format!("symbol{i}"),
                    signature: format!("pub fn symbol{i}({})", "x".repeat(30)),
                    start_line: 1,
                    end_line: 1,
                    depth: 0,
                    children: vec![],
                }],
                warnings: vec![],
                raw_bytes: 0,
            })
            .collect();
        let opts = OutlineOptions {
            max_tokens: 50,
            ..OutlineOptions::default()
        };
        let out = render_outline_text(&docs, &opts);
        assert!(out.len() <= 50 * 4, "len {} vs budget: {out}", out.len());
        assert!(
            out.contains("pub fn symbol0"),
            "first file keeps its symbol: {out}"
        );
        assert!(
            !out.contains("file5.rs"),
            "trailing docs are dropped whole: {out}"
        );
        assert!(
            out.contains("omitted items"),
            "the notice discloses the trim: {out}"
        );
    }

    /// Regression (Devin Review, "Silent file omissions in
    /// outlines"): a batch where every file has zero matching items
    /// still discloses dropped file sections — the omitted-items
    /// count stays zero for such docs, so before the fix the
    /// sections vanished with no notice at all.
    #[test]
    fn outline_batch_with_no_matching_items_discloses_dropped_files() {
        let docs: Vec<OutlineDoc> = ["a.rs", "b.rs", "c.rs"]
            .iter()
            .map(|path| OutlineDoc {
                path: (*path).to_string(),
                lang: "rust".to_string(),
                total_lines: 1,
                items: vec![],
                imports: vec![],
                warnings: vec![],
                raw_bytes: 0,
            })
            .collect();
        let opts = OutlineOptions {
            max_tokens: 30,
            ..OutlineOptions::default()
        };
        let out = render_outline_text(&docs, &opts);
        assert!(out.len() <= 30 * 4 + 1, "over budget: {out:?}");
        assert!(out.contains("a.rs"), "first file kept: {out}");
        assert!(
            out.contains("omitted files"),
            "dropped file sections are disclosed: {out}"
        );
        assert!(
            !out.contains("c.rs"),
            "the trailing file was the one dropped: {out}"
        );
    }

    /// Regression (Devin Review, "Fitting file dropped from
    /// outline"): trailing files with no matching items are dropped
    /// first; the first item drop afterwards switches the notice
    /// from files-only to the longer combined wording, and emptying
    /// the first file swaps its item line for the placeholder — so
    /// rendered length is not monotone in the step count and the
    /// old bisect skipped the fitting state and returned only the
    /// notice. The first file's symbol fits and must survive.
    #[test]
    fn outline_fitting_first_file_survives_after_empty_files_drop() {
        let doc_with = |path: &str, items: Vec<OutlineItem>| OutlineDoc {
            path: path.to_string(),
            lang: "rust".to_string(),
            total_lines: 1,
            items,
            imports: vec![],
            warnings: vec![],
            raw_bytes: 0,
        };
        let docs = vec![
            doc_with(
                "a.rs",
                vec![OutlineItem {
                    kind: "function".to_string(),
                    name: "a".to_string(),
                    qualified_name: "a".to_string(),
                    signature: "fn a()".to_string(),
                    start_line: 1,
                    end_line: 1,
                    depth: 0,
                    children: vec![],
                }],
            ),
            doc_with("b.rs", vec![]),
            doc_with("c.rs", vec![]),
            doc_with("d.rs", vec![]),
        ];
        let opts = OutlineOptions {
            max_tokens: 27,
            ..OutlineOptions::default()
        };
        let out = render_outline_text(&docs, &opts);
        assert!(out.len() <= 27 * 4 + 1, "over budget: {out:?}");
        assert!(
            out.contains("fn a()"),
            "the fitting first file keeps its symbol: {out}"
        );
        assert!(
            out.contains("omitted files"),
            "the dropped files are disclosed: {out}"
        );
        // And it is exactly the sequential first-fit state.
        let filtered: Vec<OutlineDoc> = docs.iter().map(|d| filtered_doc(d, &opts)).collect();
        let mut seq_state = (filtered, 0usize, 0usize);
        crate::budget::trim_structured(
            &mut seq_state,
            27,
            |(docs, omitted, omitted_docs)| {
                render_outline_text_docs(docs, *omitted, *omitted_docs, &opts)
            },
            |(docs, omitted, omitted_docs)| outline_text_trim_step(docs, omitted, omitted_docs),
        );
        let (seq_docs, seq_omitted, seq_omitted_docs) = &seq_state;
        let seq_out = render_outline_text_docs(seq_docs, *seq_omitted, *seq_omitted_docs, &opts);
        let seq_out = crate::budget::finish_text(
            seq_out,
            27,
            crate::budget::KeepPolicy::Head,
            &outline_notice(*seq_omitted, *seq_omitted_docs),
        );
        assert_eq!(out, seq_out, "production trim == sequential first fit");
    }

    /// The length model behind trim_outline_text must mirror the
    /// real renderers exactly: notice lengths against
    /// [`outline_notice`], and the error tail against
    /// `budget::append_error_lines` over a sweep of document
    /// lengths (including the clipped-first-line branch).
    #[test]
    fn outline_length_model_mirrors_the_real_renderers() {
        for items in [0usize, 1, 9, 10, 99, 100, 12_345] {
            for docs in [0usize, 1, 9, 10, 250] {
                assert_eq!(
                    outline_notice_len(items, docs),
                    if items == 0 && docs == 0 {
                        0
                    } else {
                        outline_notice(items, docs).len() + 1
                    },
                    "notice len, items {items} docs {docs}"
                );
            }
        }
        let messages: Vec<String> = vec![
            "io error: no such file".to_string(),
            "parse failed near token 42 with a somewhat longer message".to_string(),
            "denied".to_string(),
        ];
        let single_message = vec!["single error with enough text to clip at tight budgets".to_string()];
        let many_messages: Vec<String> = (0..120)
            .map(|i| format!("err-{i:03}: failed near symbol {i}"))
            .collect();
        for group in [&messages, &single_message, &many_messages] {
            let model = ErrorTailModel::new(group);
            for max_tokens in [10usize, 27, 40, 100, 500] {
                for docs_len in (0..=400usize).step_by(7) {
                    let mut real = "x".repeat(docs_len);
                    crate::budget::append_error_lines(
                        &mut real,
                        group,
                        max_tokens,
                        lexer::normalize_signature,
                    );
                    assert_eq!(
                        model.tail_len(docs_len, max_tokens),
                        real.len() - docs_len,
                        "error tail, msgs {} max_tokens {max_tokens} docs_len {docs_len}",
                        group.len()
                    );
                }
            }
        }
        // Verify DocMeasure length parity with non-empty warnings and imports
        // (including multibyte UTF-8 warnings and >200-char normalized imports).
        let rich_doc = OutlineDoc {
            path: "src/rich.rs".to_string(),
            lang: "rust".to_string(),
            total_lines: 42,
            items: vec![
                OutlineItem {
                    kind: "function".to_string(),
                    name: "alpha".to_string(),
                    qualified_name: "alpha".to_string(),
                    signature: "pub fn alpha() -> i32".to_string(),
                    start_line: 10,
                    end_line: 15,
                    depth: 0,
                    children: vec![],
                },
                OutlineItem {
                    kind: "function".to_string(),
                    name: "beta".to_string(),
                    qualified_name: "beta".to_string(),
                    signature: "pub fn beta() -> i32".to_string(),
                    start_line: 20,
                    end_line: 20,
                    depth: 0,
                    children: vec![],
                },
            ],
            imports: (0..25).map(|i| format!("crate::module_{i}::Symbol_{i}")).collect(),
            warnings: vec![
                "partial parse: café — skipped block".to_string(),
                "fallback heuristic".to_string(),
            ],
            raw_bytes: 0,
        };
        for include_imports in [false, true] {
            let opts = OutlineOptions {
                include_imports,
                ..OutlineOptions::default()
            };
            let filtered = filtered_doc(&rich_doc, &opts);
            let measured = measure_doc(&filtered, 1, &opts);
            // At idx == 1, measure_doc includes the 1-byte inter-doc separator.
            let mut single_doc = filtered.clone();
            let full_rendered = render_outline_text_docs(std::slice::from_ref(&single_doc), 0, 0, &opts);
            assert_eq!(measured.full_len(), full_rendered.len() + 1);
            for drops in 1..=measured.item_count {
                assert!(drop_last_item(&mut single_doc.items));
                let partial_rendered =
                    render_outline_text_docs(std::slice::from_ref(&single_doc), 0, 0, &opts);
                assert_eq!(
                    measured.partial_len(drops),
                    partial_rendered.len() + 1,
                    "include_imports={include_imports} drops={drops}"
                );
            }
        }
    }

    /// Regression (Devin Review, "Quadratic slowdown for batch
    /// outlines"): a large batch (120 files × 25 items, some
    /// nested, plus an error tail) trimmed at several budgets must
    /// stay byte-identical to the sequential first-fit trim — the
    /// length-model search materializes the same state the
    /// sequential loop stops at, without rendering or cloning
    /// candidate states.
    #[test]
    fn outline_large_batch_trim_matches_sequential_byte_for_byte() {
        let make_item = |name: &str, line: usize, children: Vec<OutlineItem>| OutlineItem {
            kind: "function".to_string(),
            name: name.to_string(),
            qualified_name: name.to_string(),
            signature: format!("pub fn {name}(x: u32) -> u32"),
            start_line: line,
            end_line: line + 2,
            depth: 0,
            children,
        };
        let docs: Vec<OutlineDoc> = (0..120)
            .map(|f| {
                let items = (0..25)
                    .map(|i| {
                        let children = if i % 7 == 0 {
                            vec![make_item(&format!("inner{i}"), i + 100, vec![])]
                        } else {
                            vec![]
                        };
                        make_item(&format!("f{f}_{i}"), i + 1, children)
                    })
                    .collect();
                let imports = if f % 5 == 0 {
                    (0..20)
                        .map(|k| format!("crate::mod{f}::dep_{k}::TypeName"))
                        .collect()
                } else if f % 3 == 0 {
                    vec!["std::collections::HashMap".to_string()]
                } else {
                    vec![]
                };
                let warnings = if f % 4 == 0 {
                    vec![format!("partial parse in mod{f}: café")]
                } else {
                    vec![]
                };
                OutlineDoc {
                    path: format!("src/mod{f}/file.rs"),
                    lang: "rust".to_string(),
                    total_lines: 90,
                    items,
                    imports,
                    warnings,
                    raw_bytes: 0,
                }
            })
            .collect();
        let errors = vec![
            OutlineError {
                path: "gone.rs".to_string(),
                message: "io error: no such file".to_string(),
            },
            OutlineError {
                path: "bad.rs".to_string(),
                message: "parse failed near token 42".to_string(),
            },
        ];
        let messages: Vec<String> = errors.iter().map(|e| e.message.clone()).collect();
        for include_imports in [false, true] {
            for max_tokens in [2000usize, 300, 55, 27, 12] {
                let opts = OutlineOptions {
                    max_tokens,
                    include_imports,
                    ..OutlineOptions::default()
                };
                let production = render_outline_text_with_errors(&docs, &errors, &opts);
                // Sequential ground truth: the production pipeline with
                // the step-by-step trim.
                let filtered: Vec<OutlineDoc> = docs.iter().map(|d| filtered_doc(d, &opts)).collect();
                let mut seq_state = (filtered, 0usize, 0usize);
                crate::budget::trim_structured(
                    &mut seq_state,
                    max_tokens,
                    |(docs, omitted, omitted_docs)| {
                        let mut out = render_outline_text_docs(docs, *omitted, *omitted_docs, &opts);
                        crate::budget::append_error_lines(
                            &mut out,
                            &messages,
                            max_tokens,
                            lexer::normalize_signature,
                        );
                        out
                    },
                    |(docs, omitted, omitted_docs)| {
                        outline_text_trim_step(docs, omitted, omitted_docs)
                    },
                );
                let (seq_docs, seq_omitted, seq_omitted_docs) = &seq_state;
                let mut seq_out =
                    render_outline_text_docs(seq_docs, *seq_omitted, *seq_omitted_docs, &opts);
                crate::budget::append_error_lines(
                    &mut seq_out,
                    &messages,
                    max_tokens,
                    lexer::normalize_signature,
                );
                let seq_out = crate::budget::finish_text(
                    seq_out,
                    max_tokens,
                    crate::budget::KeepPolicy::Head,
                    &outline_notice(*seq_omitted, *seq_omitted_docs),
                );
                assert_eq!(
                    production, seq_out,
                    "include_imports {include_imports} max_tokens {max_tokens}"
                );
                // finish_text's contract: within budget, or the notice
                // alone when even the notice exceeds the budget.
                let notice_floor = outline_notice(*seq_omitted, *seq_omitted_docs).len() + 1;
                assert!(
                    production.len() <= (max_tokens * 4 + 1).max(notice_floor),
                    "over budget at {max_tokens}: {} bytes",
                    production.len()
                );
            }
        }
    }

    #[test]
    fn outline_json_budget_edge_exact_fit_one_token_less_and_below_smallest_valid() {
        let (doc, _) = sample_doc();
        let opts0 = OutlineOptions::default();
        let full = render_outline_json(std::slice::from_ref(&doc), &opts0);
        let exact = full.len().div_ceil(4);
        let opts_exact = OutlineOptions {
            max_tokens: exact,
            ..OutlineOptions::default()
        };
        assert_eq!(
            render_outline_json(std::slice::from_ref(&doc), &opts_exact),
            full
        );
        // One token less, measured against the JSON size: only the
        // last item is given up.
        let opts_less = OutlineOptions {
            max_tokens: exact - 1,
            ..OutlineOptions::default()
        };
        let less = render_outline_json(std::slice::from_ref(&doc), &opts_less);
        let parsed: serde_json::Value = serde_json::from_str(&less).unwrap();
        assert!(less.len() <= (exact - 1) * 4);
        assert_eq!(parsed["truncated"], serde_json::Value::Bool(true));
        assert_eq!(parsed["omitted_items"], serde_json::Value::from(1));
        let items = parsed["docs"][0]["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[1]["name"],
            serde_json::Value::String("beta".to_owned())
        );
        // Below the smallest valid document: validity wins.
        let opts_tiny = OutlineOptions {
            max_tokens: 1,
            ..OutlineOptions::default()
        };
        let tiny = render_outline_json(std::slice::from_ref(&doc), &opts_tiny);
        let parsed: serde_json::Value = serde_json::from_str(&tiny).unwrap();
        assert_eq!(parsed["docs"][0]["items"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["omitted_items"], serde_json::Value::from(3));
        assert_eq!(parsed["truncated"], serde_json::Value::Bool(true));
    }

    #[test]
    fn outline_json_error_list_is_capped_by_the_shared_routine() {
        let (doc, _) = sample_doc();
        let errors: Vec<OutlineError> = (0..12)
            .map(|i| OutlineError {
                path: format!("missing-{i}.rs"),
                message: format!("missing-{i}.rs: No such file or directory, really"),
            })
            .collect();
        let opts = OutlineOptions {
            max_tokens: 60,
            ..OutlineOptions::default()
        };
        let json = render_outline_json_with_errors(&[doc], &errors, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let errs = parsed["errors"].as_array().unwrap();
        assert!(errs.len() < 12, "error list must be capped: {}", errs.len());
        assert_eq!(
            errs.last().unwrap()["path"],
            serde_json::Value::String("...".to_owned())
        );
        assert!(
            errs.last().unwrap()["message"]
                .as_str()
                .unwrap()
                .contains("omitted errors"),
            "tail is the shared cap's summary entry: {errs:?}"
        );
    }

    #[test]
    fn render_outline_with_errors_includes_text_and_json_errors() {
        let doc = outline_source("a.rs", "pub fn alpha() {}\n", Lang::Rust, &OutlineOptions::default());
        let errors = vec![OutlineError {
            path: "missing.rs".to_owned(),
            message: "missing.rs: No such file or directory".to_owned(),
        }];
        let txt = render_outline_text_with_errors(std::slice::from_ref(&doc), &errors, &OutlineOptions::default());
        assert!(txt.contains("pub fn alpha()"), "{txt}");
        assert!(txt.contains("error: missing.rs: No such file or directory"), "{txt}");

        let json_str = render_outline_json_with_errors(&[doc], &errors, &OutlineOptions::default());
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["docs"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["errors"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["errors"][0]["path"], "missing.rs");
    }
}
