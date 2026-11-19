//! Structural code outline parsers for C#, Razor, Rust, Python, TS/JS, Go, and PowerShell.

use super::lexer::{
    find_matching_delim, normalize_signature, skip_string_or_comment, LexLang, LineIndex,
};
use super::{Lang, OutlineDoc, OutlineItem, OutlineOptions};

const MAX_SIG_CHARS: usize = 140;

pub fn parse_code(
    path: &str,
    src: &str,
    idx: &LineIndex,
    lang: Lang,
    opts: &OutlineOptions,
) -> OutlineDoc {
    let mut doc = OutlineDoc {
        path: path.to_owned(),
        lang: lang.as_str().to_owned(),
        total_lines: idx.total_lines(),
        imports: Vec::new(),
        items: Vec::new(),
        warnings: Vec::new(),
    };
    let start = skip_utf8_bom(src);
    match lang {
        Lang::CSharp => parse_csharp(src, start, src.len(), idx, opts, &mut doc),
        Lang::Razor => parse_razor(src, start, idx, opts, &mut doc),
        Lang::Rust => {
            doc.items = parse_rust_scope(
                src,
                start,
                src.len(),
                idx,
                0,
                "",
                opts.include_all,
                &mut doc.imports,
            );
        }
        Lang::Python => parse_python(src, start, idx, opts, &mut doc),
        Lang::TypeScript | Lang::JavaScript => {
            doc.items = parse_tsjs_scope(
                src,
                start,
                src.len(),
                idx,
                0,
                "",
                false,
                opts.include_all,
                &mut doc.imports,
            );
        }
        Lang::Go => parse_go(src, start, idx, opts, &mut doc),
        Lang::PowerShell => {
            doc.items = parse_ps_scope(
                src,
                start,
                src.len(),
                idx,
                0,
                "",
                false,
                &mut doc.imports,
            );
        }
        _ => {}
    }
    doc
}

fn skip_utf8_bom(src: &str) -> usize {
    if src.starts_with('\u{FEFF}') {
        3
    } else {
        0
    }
}

fn join_qualified(prefix: &str, sep: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}{sep}{name}")
    }
}

/// Skip spaces, tabs, newlines, and language comments starting at `pos`.
fn skip_ws_and_comments(bytes: &[u8], mut pos: usize, end: usize, lang: LexLang) -> usize {
    while pos < end {
        let b = bytes[pos];
        if b.is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        if b == b'/' && pos + 1 < end && (bytes[pos + 1] == b'/' || bytes[pos + 1] == b'*') {
            if let Some(next) = skip_string_or_comment(bytes, pos, lang) {
                pos = next.min(end);
                continue;
            }
        }
        if matches!(lang, LexLang::PowerShell)
            && (b == b'#' || (b == b'<' && pos + 1 < end && bytes[pos + 1] == b'#'))
        {
            if let Some(next) = skip_string_or_comment(bytes, pos, lang) {
                pos = next.min(end);
                continue;
            }
        }
        if matches!(lang, LexLang::CSharp) && b == b'#' {
            if let Some(next) = skip_string_or_comment(bytes, pos, lang) {
                pos = next.min(end);
                continue;
            }
        }
        break;
    }
    pos
}

/// Read an identifier (ASCII or UTF-8 non-ASCII letters) starting at `pos`.
fn read_ident(src: &str, pos: usize) -> Option<(&str, usize)> {
    let tail = src.get(pos..)?;
    let mut end = 0usize;
    for (i, ch) in tail.char_indices() {
        if i == 0 {
            if ch.is_alphabetic() || ch == '_' || ch == '$' {
                end = i + ch.len_utf8();
            } else {
                return None;
            }
        } else if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            end = i + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        None
    } else {
        Some((&tail[..end], pos + end))
    }
}

/// Strip comments/newlines cleanly from a raw header snippet so signatures are concise.
fn clean_header_text(src: &str, start: usize, end: usize, lang: LexLang) -> String {
    let bytes = src.as_bytes();
    let mut cleaned = String::with_capacity(end.saturating_sub(start));
    let mut i = start;
    while i < end {
        let b = bytes[i];
        if (b == b'/' && i + 1 < end && (bytes[i + 1] == b'/' || bytes[i + 1] == b'*'))
            || (matches!(lang, LexLang::PowerShell)
                && (b == b'#' || (b == b'<' && i + 1 < end && bytes[i + 1] == b'#')))
            || (matches!(lang, LexLang::CSharp) && b == b'#' && is_line_start(bytes, i))
        {
            if let Some(next) = skip_string_or_comment(bytes, i, lang) {
                cleaned.push(' ');
                i = next.min(end);
                continue;
            }
        }
        if let Some(ch) = src[i..end].chars().next() {
            cleaned.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    normalize_signature(&cleaned, MAX_SIG_CHARS)
}

fn is_line_start(bytes: &[u8], pos: usize) -> bool {
    let mut i = pos;
    while i > 0 && bytes[i - 1] != b'\n' {
        i -= 1;
        if !matches!(bytes[i], b' ' | b'\t') {
            return false;
        }
    }
    true
}

/// Tokenize words/punct outside parens/brackets/generics inside a header slice.
/// Returns `(tokens_at_top_level, first_eq_before_paren, has_fat_arrow, has_paren)`.
struct HeaderScan {
    words: Vec<(String, usize, usize)>,
    has_paren: bool,
    has_eq_before_paren: bool,
    has_fat_arrow: bool,
    first_paren_pos: Option<usize>,
}

fn scan_header(src: &str, start: usize, end: usize, lang: LexLang) -> HeaderScan {
    let bytes = src.as_bytes();
    let mut words = Vec::new();
    let mut has_paren = false;
    let mut has_eq_before_paren = false;
    let mut has_fat_arrow = false;
    let mut first_paren_pos = None;
    let mut angle_depth = 0usize;
    let mut i = start;

    while i < end {
        if let Some(next) = skip_string_or_comment(bytes, i, lang) {
            i = next.min(end);
            continue;
        }
        let b = bytes[i];
        if b == b'(' {
            if !has_paren {
                has_paren = true;
                first_paren_pos = Some(i);
            }
            if let Some(close) = find_matching_delim(bytes, i, b'(', b')', lang) {
                i = (close + 1).min(end);
                continue;
            }
        } else if b == b'[' {
            if let Some(close) = find_matching_delim(bytes, i, b'[', b']', lang) {
                i = (close + 1).min(end);
                continue;
            }
        } else if b == b'<' {
            // Avoid treating `<=` or `<<` or operator< as generic delimiter blindly, but track `<T>`
            if bytes.get(i + 1) != Some(&b'=') && bytes.get(i + 1) != Some(&b'<') {
                angle_depth += 1;
            }
        } else if b == b'>' {
            if i > 0 && bytes[i - 1] == b'=' {
                has_fat_arrow = true;
            } else {
                angle_depth = angle_depth.saturating_sub(1);
            }
        } else if b == b'=' {
            if bytes.get(i + 1) == Some(&b'>') {
                has_fat_arrow = true;
                i += 2;
                continue;
            }
            let prev = i.checked_sub(1).and_then(|p| bytes.get(p).copied());
            let next = bytes.get(i + 1).copied();
            if !has_paren
                && angle_depth == 0
                && !matches!(prev, Some(b'=' | b'!' | b'<' | b'>'))
                && next != Some(b'=')
            {
                has_eq_before_paren = true;
            }
        } else if angle_depth == 0 && (b.is_ascii_alphabetic() || b == b'_' || b == b'$' || b >= 0x80)
        {
            if let Some((_w, next)) = read_ident(src, i) {
                let capped = next.min(end);
                words.push((src[i..capped].to_owned(), i, capped));
                i = capped;
                continue;
            }
        }
        i += 1;
    }

    HeaderScan {
        words,
        has_paren,
        has_eq_before_paren,
        has_fat_arrow,
        first_paren_pos,
    }
}

/// Find the end of the next top-level statement in `scope_start..scope_end` ending in `;` or `{ ... }`.
/// Returns `(stmt_start, header_end, body_open_pos, body_close_pos, next_pos)`.
struct BraceStmt {
    header_start: usize,
    header_end: usize,
    body_open: Option<usize>,
    body_close: Option<usize>,
    next_pos: usize,
}

fn next_brace_stmt(
    bytes: &[u8],
    pos: usize,
    scope_end: usize,
    lang: LexLang,
) -> Option<BraceStmt> {
    let start = skip_ws_and_comments(bytes, pos, scope_end, lang);
    if start >= scope_end {
        return None;
    }
    let mut i = start;
    let mut seen_eq = false;
    while i < scope_end {
        if let Some(next) = skip_string_or_comment(bytes, i, lang) {
            i = next.min(scope_end);
            continue;
        }
        let b = bytes[i];
        match b {
            b'(' => {
                if let Some(close) = find_matching_delim(bytes, i, b'(', b')', lang) {
                    i = (close + 1).min(scope_end);
                    continue;
                }
            }
            b'[' => {
                if let Some(close) = find_matching_delim(bytes, i, b'[', b']', lang) {
                    i = (close + 1).min(scope_end);
                    continue;
                }
            }
            b'=' => {
                if bytes.get(i + 1) == Some(&b'>') {
                    i += 2;
                    continue;
                }
                let prev = i.checked_sub(1).and_then(|p| bytes.get(p).copied());
                let next = bytes.get(i + 1).copied();
                if !matches!(prev, Some(b'=' | b'!' | b'<' | b'>')) && next != Some(b'=') {
                    seen_eq = true;
                }
            }
            b';' => {
                return Some(BraceStmt {
                    header_start: start,
                    header_end: i,
                    body_open: None,
                    body_close: None,
                    next_pos: i + 1,
                });
            }
            b'{' => {
                let close = find_matching_delim(bytes, i, b'{', b'}', lang)
                    .map(|c| c.min(scope_end - 1))
                    .unwrap_or(scope_end - 1);
                // If an `=` appeared (like `const cfg = { ... };` or `static X = S { ... };`),
                // check if the construct is an expression initializer rather than a declaration body:
                // Caller inspects `seen_eq` or we consume trailing `;` if present right after `}`?
                // Actually let's check if trailing `;` belongs to expression initializers or properties:
                let mut after = close + 1;
                if seen_eq {
                    // Consume balanced rest of initializer until `;` if any (e.g. `= new Foo { ... };`)
                    let mut j = skip_ws_and_comments(bytes, after, scope_end, lang);
                    if j < scope_end && bytes[j] == b';' {
                        after = j + 1;
                    } else {
                        // Look ahead for `;` before next declaration if chained like `= new { a } ?? new { b };`
                        while j < scope_end {
                            if let Some(next) = skip_string_or_comment(bytes, j, lang) {
                                j = next.min(scope_end);
                                continue;
                            }
                            if bytes[j] == b';' {
                                after = j + 1;
                                break;
                            }
                            if bytes[j] == b'\n' || bytes[j] == b'{' {
                                break;
                            }
                            j += 1;
                        }
                    }
                }
                return Some(BraceStmt {
                    header_start: start,
                    header_end: i,
                    body_open: Some(i),
                    body_close: Some(close),
                    next_pos: after,
                });
            }
            _ => {}
        }
        i += 1;
    }
    Some(BraceStmt {
        header_start: start,
        header_end: scope_end,
        body_open: None,
        body_close: None,
        next_pos: scope_end,
    })
}

// ===========================================================================
// C# & Razor
// ===========================================================================

fn strip_csharp_attributes(
    src: &str,
    mut pos: usize,
    end: usize,
) -> (usize, Option<usize>, Vec<String>) {
    let bytes = src.as_bytes();
    let mut first_attr_start = None;
    let mut hints = Vec::new();
    loop {
        pos = skip_ws_and_comments(bytes, pos, end, LexLang::CSharp);
        if pos >= end || bytes[pos] != b'[' {
            break;
        }
        if first_attr_start.is_none() {
            first_attr_start = Some(pos);
        }
        if let Some(close) = find_matching_delim(bytes, pos, b'[', b']', LexLang::CSharp) {
            let close = close.min(end - 1);
            let raw = normalize_signature(&src[pos..=close], 48);
            if is_notable_csharp_attr(&raw) && hints.len() < 2 {
                hints.push(raw);
            }
            pos = close + 1;
        } else {
            break;
        }
    }
    (pos, first_attr_start, hints)
}

fn is_notable_csharp_attr(attr: &str) -> bool {
    let lower = attr.to_ascii_lowercase();
    lower.contains("fact")
        || lower.contains("theory")
        || lower.contains("test")
        || lower.contains("http")
        || lower.contains("route")
        || lower.contains("authorize")
}

fn csharp_type_keyword(words: &[(String, usize, usize)]) -> Option<(&'static str, usize)> {
    for (idx, (w, _, _)) in words.iter().enumerate() {
        match w.as_str() {
            "namespace" => return Some(("namespace", idx)),
            "class" => return Some(("class", idx)),
            "struct" => return Some(("struct", idx)),
            "interface" => return Some(("interface", idx)),
            "enum" => return Some(("enum", idx)),
            "delegate" => return Some(("delegate", idx)),
            "record" => {
                // Handle `record class Foo` / `record struct Foo`
                if let Some((next_w, _, _)) = words.get(idx + 1) {
                    if next_w == "class" || next_w == "struct" {
                        return Some(("record", idx + 1));
                    }
                }
                return Some(("record", idx));
            }
            _ => {}
        }
    }
    None
}

fn csharp_dotted_name(src: &str, start: usize, end: usize) -> String {
    let mut out = String::new();
    let bytes = src.as_bytes();
    let mut i = skip_ws_and_comments(bytes, start, end, LexLang::CSharp);
    while i < end {
        if let Some((ident, next)) = read_ident(src, i) {
            out.push_str(ident);
            i = skip_ws_and_comments(bytes, next, end, LexLang::CSharp);
            if i < end && bytes[i] == b'.' {
                out.push('.');
                i = skip_ws_and_comments(bytes, i + 1, end, LexLang::CSharp);
                continue;
            }
        }
        break;
    }
    out
}

fn parse_csharp(
    src: &str,
    start: usize,
    end: usize,
    idx: &LineIndex,
    opts: &OutlineOptions,
    doc: &mut OutlineDoc,
) {
    let (items, file_ns) = parse_csharp_scope(
        src,
        start,
        end,
        idx,
        0,
        "",
        None,
        opts.include_all,
        true,
        &mut doc.imports,
    );
    if let Some((ns_name, ns_start_line, ns_sig)) = file_ns {
        let end_line = items
            .last()
            .map(|it| it.end_line)
            .unwrap_or(idx.total_lines())
            .max(ns_start_line);
        let shifted: Vec<OutlineItem> = items.into_iter().map(shift_depth_plus_one).collect();
        doc.items.push(OutlineItem {
            kind: "namespace".to_owned(),
            name: ns_name.clone(),
            qualified_name: ns_name,
            signature: ns_sig,
            start_line: ns_start_line,
            end_line,
            depth: 0,
            children: shifted,
        });
    } else {
        doc.items = items;
    }
}

fn shift_depth_plus_one(mut item: OutlineItem) -> OutlineItem {
    item.depth += 1;
    item.children = item.children.into_iter().map(shift_depth_plus_one).collect();
    item
}

#[allow(clippy::too_many_arguments)]
fn parse_csharp_scope(
    src: &str,
    scope_start: usize,
    scope_end: usize,
    idx: &LineIndex,
    depth: usize,
    prefix: &str,
    enclosing_type: Option<&str>,
    include_all: bool,
    allow_file_ns: bool,
    imports: &mut Vec<String>,
) -> (Vec<OutlineItem>, Option<(String, usize, String)>) {
    let bytes = src.as_bytes();
    let mut pos = scope_start;
    let mut items = Vec::new();
    let mut active_prefix = prefix.to_owned();
    let mut file_ns: Option<(String, usize, String)> = None;

    while pos < scope_end {
        let (decl_pos, attr_start, attr_hints) = strip_csharp_attributes(src, pos, scope_end);
        let Some(stmt) = next_brace_stmt(bytes, decl_pos, scope_end, LexLang::CSharp) else {
            break;
        };
        let item_start = attr_start.unwrap_or(stmt.header_start);
        pos = stmt.next_pos;

        let hdr_raw = src[stmt.header_start..stmt.header_end].trim();
        if hdr_raw.is_empty() {
            continue;
        }
        let scan = scan_header(src, stmt.header_start, stmt.header_end, LexLang::CSharp);
        let first_word = scan.words.first().map(|w| w.0.as_str()).unwrap_or("");

        // Handle using directives
        if first_word == "using"
            || (first_word == "global"
                && scan.words.get(1).map(|w| w.0.as_str()) == Some("using"))
        {
            if stmt.body_open.is_none() {
                let imp = clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp);
                if !imp.is_empty() {
                    imports.push(imp);
                }
            }
            continue;
        }

        // Handle assembly/module attributes (`[assembly: ...]`)
        if hdr_raw.starts_with('[') && stmt.body_open.is_none() {
            continue;
        }

        let start_line = idx.line_of(item_start);
        let end_line = idx.line_of(stmt.body_close.unwrap_or(stmt.header_end));

        if let Some((kind, kw_idx)) = csharp_type_keyword(&scan.words) {
            if kind == "namespace" {
                let ns_after = scan.words[kw_idx].2;
                let ns_name = csharp_dotted_name(src, ns_after, stmt.header_end);
                if ns_name.is_empty() {
                    continue;
                }
                let sig = format!("namespace {ns_name}");
                if let (Some(bo), Some(bc)) = (stmt.body_open, stmt.body_close) {
                    let qname = join_qualified(&active_prefix, ".", &ns_name);
                    let (children, _) = parse_csharp_scope(
                        src,
                        bo + 1,
                        bc,
                        idx,
                        depth + 1,
                        &qname,
                        None,
                        include_all,
                        false,
                        imports,
                    );
                    items.push(OutlineItem {
                        kind: "namespace".to_owned(),
                        name: ns_name,
                        qualified_name: qname,
                        signature: sig,
                        start_line,
                        end_line,
                        depth,
                        children,
                    });
                } else if allow_file_ns && file_ns.is_none() {
                    active_prefix = join_qualified(&active_prefix, ".", &ns_name);
                    file_ns = Some((ns_name, start_line, sig));
                }
                continue;
            }

            if kind == "delegate" {
                let name = scan
                    .words
                    .iter()
                    .rev()
                    .find(|(_, s, _)| {
                        scan.first_paren_pos.map(|fp| *s < fp).unwrap_or(true)
                    })
                    .map(|(w, _, _)| w.clone())
                    .unwrap_or_default();
                if !name.is_empty() {
                    let qname = join_qualified(&active_prefix, ".", &name);
                    let sig = format_sig_with_attrs(
                        &attr_hints,
                        &clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp),
                    );
                    items.push(OutlineItem {
                        kind: "delegate".to_owned(),
                        name,
                        qualified_name: qname,
                        signature: sig,
                        start_line,
                        end_line,
                        depth,
                        children: Vec::new(),
                    });
                }
                continue;
            }

            let name = scan
                .words
                .get(kw_idx + 1)
                .map(|(w, _, _)| w.clone())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let qname = join_qualified(&active_prefix, ".", &name);
            let sig = format_sig_with_attrs(
                &attr_hints,
                &clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp),
            );
            let children = if kind != "enum" {
                if let (Some(bo), Some(bc)) = (stmt.body_open, stmt.body_close) {
                    let (ch, _) = parse_csharp_scope(
                        src,
                        bo + 1,
                        bc,
                        idx,
                        depth + 1,
                        &qname,
                        Some(&name),
                        include_all,
                        false,
                        imports,
                    );
                    ch
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            items.push(OutlineItem {
                kind: kind.to_owned(),
                name,
                qualified_name: qname,
                signature: sig,
                start_line,
                end_line,
                depth,
                children,
            });
            continue;
        }

        // Member declarations (inside a type or top-level statements/methods)
        let is_event = scan.words.iter().any(|(w, _, _)| w == "event");
        let is_operator = scan.words.iter().any(|(w, _, _)| w == "operator");
        let is_destructor = enclosing_type
            .map(|t| hdr_raw.contains(&format!("~{t}")))
            .unwrap_or(false);

        if is_event {
            let name = scan
                .words
                .last()
                .map(|(w, _, _)| w.clone())
                .unwrap_or_else(|| "event".to_owned());
            let qname = join_qualified(&active_prefix, ".", &name);
            let sig = format_sig_with_attrs(
                &attr_hints,
                &clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp),
            );
            items.push(OutlineItem {
                kind: "event".to_owned(),
                name,
                qualified_name: qname,
                signature: sig,
                start_line,
                end_line,
                depth,
                children: Vec::new(),
            });
            continue;
        }

        if is_operator || is_destructor {
            let name = if is_destructor {
                format!("~{}", enclosing_type.unwrap_or(""))
            } else {
                "operator".to_owned()
            };
            let qname = join_qualified(&active_prefix, ".", &name);
            let sig = clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp);
            items.push(OutlineItem {
                kind: "method".to_owned(),
                name,
                qualified_name: qname,
                signature: sig,
                start_line,
                end_line,
                depth,
                children: Vec::new(),
            });
            continue;
        }

        if scan.has_paren && !scan.has_eq_before_paren {
            // Constructor or method: find word immediately before first `(`
            let fp = scan.first_paren_pos.unwrap_or(stmt.header_end);
            let name = scan
                .words
                .iter()
                .rev()
                .find(|(_, _, e)| *e <= fp)
                .map(|(w, _, _)| w.clone())
                .unwrap_or_default();
            if name.is_empty()
                || matches!(
                    name.as_str(),
                    "if" | "for" | "foreach" | "while" | "switch" | "catch" | "lock" | "using"
                        | "return" | "throw" | "new"
                )
            {
                continue;
            }
            let kind = if enclosing_type == Some(name.as_str()) {
                "constructor"
            } else {
                "method"
            };
            let qname = join_qualified(&active_prefix, ".", &name);
            let mut raw_sig = clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp);
            if stmt.body_open.is_none() {
                if let Some(arrow_idx) = raw_sig.find("=>") {
                    raw_sig = raw_sig[..arrow_idx].trim_end().to_owned();
                }
            }
            let sig = format_sig_with_attrs(&attr_hints, &raw_sig);
            items.push(OutlineItem {
                kind: kind.to_owned(),
                name,
                qualified_name: qname,
                signature: sig,
                start_line,
                end_line,
                depth,
                children: Vec::new(),
            });
            continue;
        }

        // Property, indexer, or field
        let is_indexer = !scan.has_paren && hdr_raw.contains("this[");
        let is_block_prop = stmt.body_open.is_some() && !scan.has_eq_before_paren;
        let is_expr_prop = !scan.has_paren && scan.has_fat_arrow && !scan.has_eq_before_paren;
        if is_indexer || is_block_prop || is_expr_prop {
            let name = if is_indexer {
                "this[]".to_owned()
            } else {
                scan.words
                    .last()
                    .map(|(w, _, _)| w.clone())
                    .unwrap_or_default()
            };
            if name.is_empty() {
                continue;
            }
            let qname = join_qualified(&active_prefix, ".", &name);
            let mut raw_sig =
                clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp);
            if is_expr_prop {
                if let Some(arrow_idx) = raw_sig.find("=>") {
                    raw_sig = raw_sig[..arrow_idx].trim_end().to_owned();
                }
            } else if stmt.body_open.is_some() {
                raw_sig.push_str(" { ... }");
            }
            let sig = format_sig_with_attrs(&attr_hints, &raw_sig);
            items.push(OutlineItem {
                kind: "property".to_owned(),
                name,
                qualified_name: qname,
                signature: sig,
                start_line,
                end_line,
                depth,
                children: Vec::new(),
            });
            continue;
        }

        if include_all && enclosing_type.is_some() && !scan.words.is_empty() {
            // Field: identifier before `=` or last word
            let eq_pos = hdr_raw.find('=').map(|p| stmt.header_start + p);
            let name = scan
                .words
                .iter()
                .rev()
                .find(|(_, _, e)| eq_pos.map(|ep| *e <= ep).unwrap_or(true))
                .map(|(w, _, _)| w.clone())
                .unwrap_or_default();
            if !name.is_empty() {
                let qname = join_qualified(&active_prefix, ".", &name);
                let sig = format_sig_with_attrs(
                    &attr_hints,
                    &clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::CSharp),
                );
                items.push(OutlineItem {
                    kind: "field".to_owned(),
                    name,
                    qualified_name: qname,
                    signature: sig,
                    start_line,
                    end_line,
                    depth,
                    children: Vec::new(),
                });
            }
        }
    }

    (items, file_ns)
}

fn format_sig_with_attrs(attrs: &[String], sig: &str) -> String {
    if attrs.is_empty() {
        sig.to_owned()
    } else {
        normalize_signature(&format!("{} {sig}", attrs.join(" ")), MAX_SIG_CHARS)
    }
}

fn parse_razor(
    src: &str,
    start: usize,
    idx: &LineIndex,
    opts: &OutlineOptions,
    doc: &mut OutlineDoc,
) {
    let bytes = src.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        // Skip Razor comments `@* ... *@`
        if bytes[i] == b'@' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'@') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // Check directives at line start (leading whitespace + `@`)
        if bytes[i] == b'@' && is_line_start(bytes, i) {
            let line_no = idx.line_of(i);
            let line_end = idx.line_end(line_no);
            if let Some((dir, after_dir)) = read_ident(src, i + 1) {
                match dir {
                    "code" | "functions" => {
                        let open = skip_ws_and_comments(bytes, after_dir, bytes.len(), LexLang::CSharp);
                        if bytes.get(open) == Some(&b'{') {
                            let close = find_matching_delim(
                                bytes,
                                open,
                                b'{',
                                b'}',
                                LexLang::CSharp,
                            )
                            .unwrap_or(bytes.len() - 1);
                            let block_name = format!("@{dir}");
                            let (children, _) = parse_csharp_scope(
                                src,
                                open + 1,
                                close,
                                idx,
                                1,
                                &block_name,
                                None,
                                opts.include_all,
                                false,
                                &mut doc.imports,
                            );
                            doc.items.push(OutlineItem {
                                kind: "block".to_owned(),
                                name: block_name.clone(),
                                qualified_name: block_name.clone(),
                                signature: block_name,
                                start_line: line_no,
                                end_line: idx.line_of(close),
                                depth: 0,
                                children,
                            });
                            i = close + 1;
                            continue;
                        }
                    }
                    "using" => {
                        let imp = normalize_signature(&src[i + 1..line_end], MAX_SIG_CHARS);
                        doc.imports.push(imp);
                        i = line_end;
                        continue;
                    }
                    "page" | "inject" | "implements" | "inherits" | "typeparam" | "attribute"
                    | "model" | "layout" | "namespace" | "rendermode" => {
                        let sig = normalize_signature(&src[i..line_end], MAX_SIG_CHARS);
                        let item_name = if dir == "inject" {
                            sig.split_whitespace()
                                .last()
                                .unwrap_or("@inject")
                                .trim_end_matches(';')
                                .to_owned()
                        } else {
                            format!("@{dir}")
                        };
                        doc.items.push(OutlineItem {
                            kind: "directive".to_owned(),
                            name: item_name.clone(),
                            qualified_name: item_name,
                            signature: sig,
                            start_line: line_no,
                            end_line: line_no,
                            depth: 0,
                            children: Vec::new(),
                        });
                        i = line_end;
                        continue;
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }
}

// ===========================================================================
// Rust
// ===========================================================================

fn strip_rust_attributes(
    src: &str,
    mut pos: usize,
    end: usize,
) -> (usize, Option<usize>, Vec<String>) {
    let bytes = src.as_bytes();
    let mut first_attr_start = None;
    let mut hints = Vec::new();
    loop {
        pos = skip_ws_and_comments(bytes, pos, end, LexLang::Rust);
        if pos + 1 >= end || bytes[pos] != b'#' {
            break;
        }
        // Handle `#![...]` (inner attr) or `#[...]` (outer attr)
        let bracket = if bytes[pos + 1] == b'[' {
            pos + 1
        } else if bytes[pos + 1] == b'!' && bytes.get(pos + 2) == Some(&b'[') {
            pos + 2
        } else {
            break;
        };
        let is_inner = bracket == pos + 2;
        if let Some(close) = find_matching_delim(bytes, bracket, b'[', b']', LexLang::Rust) {
            let close = close.min(end - 1);
            if !is_inner {
                if first_attr_start.is_none() {
                    first_attr_start = Some(pos);
                }
                let raw = normalize_signature(&src[pos..=close], 48);
                if (raw.contains("test") || raw.contains("cfg(test)")) && hints.len() < 2 {
                    hints.push(raw);
                }
            }
            pos = close + 1;
        } else {
            break;
        }
    }
    (pos, first_attr_start, hints)
}

fn rust_item_keyword(words: &[(String, usize, usize)]) -> Option<(&'static str, usize)> {
    for (idx, (w, _, _)) in words.iter().enumerate() {
        match w.as_str() {
            "mod" => return Some(("module", idx)),
            "struct" => return Some(("struct", idx)),
            "enum" => return Some(("enum", idx)),
            "trait" => return Some(("trait", idx)),
            "impl" => return Some(("impl", idx)),
            "fn" => return Some(("function", idx)),
            "type" => return Some(("type", idx)),
            "const" => {
                // `const fn` / `const unsafe fn` must keep scanning for `fn`
                if matches!(
                    words.get(idx + 1).map(|x| x.0.as_str()),
                    Some("fn" | "unsafe" | "extern")
                ) {
                    continue;
                }
                return Some(("const", idx));
            }
            "static" => return Some(("static", idx)),
            "macro_rules" => return Some(("macro", idx)),
            _ => {}
        }
    }
    None
}

fn rust_impl_target(src: &str, impl_kw_end: usize, header_end: usize) -> (String, String) {
    // Parse `impl<T> Trait for Type<U>` or `impl<T> Type<T>` cleanly
    let header = clean_header_text(src, impl_kw_end, header_end, LexLang::Rust);
    let trimmed = header.trim();
    // Skip leading generic `<...>` if present
    let after_gen = if trimmed.starts_with('<') {
        skip_balanced_angles(trimmed).trim_start()
    } else {
        trimmed
    };
    let before_where = after_gen
        .split(" where ")
        .next()
        .unwrap_or(after_gen)
        .trim();
    let short_ident = |s: &str| -> String {
        let base = s.split('<').next().unwrap_or(s).trim();
        base.rsplit("::").next().unwrap_or(base).trim().to_owned()
    };
    if let Some((_trait_part, for_part)) = split_top_level_for(before_where) {
        let target = short_ident(for_part);
        (before_where.to_owned(), target)
    } else {
        let target = short_ident(before_where);
        (target.clone(), target)
    }
}

fn skip_balanced_angles(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'<' {
            depth += 1;
        } else if b == b'>' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return &s[i + 1..];
            }
        }
    }
    s
}

fn split_top_level_for(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut angle = 0usize;
    let mut paren = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => angle += 1,
            b'>' => angle = angle.saturating_sub(1),
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            _ => {}
        }
        if angle == 0 && paren == 0 && s[i..].starts_with(" for ") {
            return Some((&s[..i], &s[i + 5..]));
        }
        i += 1;
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn parse_rust_scope(
    src: &str,
    scope_start: usize,
    scope_end: usize,
    idx: &LineIndex,
    depth: usize,
    prefix: &str,
    include_all: bool,
    imports: &mut Vec<String>,
) -> Vec<OutlineItem> {
    let bytes = src.as_bytes();
    let mut pos = scope_start;
    let mut items = Vec::new();

    while pos < scope_end {
        let (decl_pos, attr_start, attr_hints) = strip_rust_attributes(src, pos, scope_end);
        let Some(stmt) = next_brace_stmt(bytes, decl_pos, scope_end, LexLang::Rust) else {
            break;
        };
        let item_start = attr_start.unwrap_or(stmt.header_start);
        pos = stmt.next_pos;

        let hdr_raw = src[stmt.header_start..stmt.header_end].trim();
        if hdr_raw.is_empty() {
            continue;
        }
        let scan = scan_header(src, stmt.header_start, stmt.header_end, LexLang::Rust);
        let first = scan.words.first().map(|w| w.0.as_str()).unwrap_or("");
        if first == "use" || (first == "pub" && scan.words.get(1).map(|w| w.0.as_str()) == Some("use"))
        {
            let imp = clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Rust);
            if !imp.is_empty() {
                imports.push(imp);
            }
            continue;
        }
        // Skip `extern crate` unless include_all
        if first == "extern" && scan.words.get(1).map(|w| w.0.as_str()) == Some("crate") {
            continue;
        }

        let start_line = idx.line_of(item_start);
        let end_line = idx.line_of(stmt.body_close.unwrap_or(stmt.header_end));

        let Some((kind, kw_idx)) = rust_item_keyword(&scan.words) else {
            continue;
        };

        if kind == "impl" {
            let (display_name, target_type) =
                rust_impl_target(src, scan.words[kw_idx].2, stmt.header_end);
            let child_prefix = if target_type.is_empty() {
                prefix.to_owned()
            } else {
                join_qualified(prefix, "::", &target_type)
            };
            let qname = join_qualified(prefix, "::", &display_name);
            let sig = format_sig_with_attrs(
                &attr_hints,
                &clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Rust),
            );
            let children = if let (Some(bo), Some(bc)) = (stmt.body_open, stmt.body_close) {
                parse_rust_scope(
                    src,
                    bo + 1,
                    bc,
                    idx,
                    depth + 1,
                    &child_prefix,
                    include_all,
                    imports,
                )
            } else {
                Vec::new()
            };
            items.push(OutlineItem {
                kind: "impl".to_owned(),
                name: display_name,
                qualified_name: qname,
                signature: sig,
                start_line,
                end_line,
                depth,
                children,
            });
            continue;
        }

        let Some((name, _)) = scan.words.get(kw_idx + 1).map(|(w, s, _)| (w.clone(), *s)) else {
            continue;
        };
        if matches!(kind, "const" | "static") && !include_all && first != "pub" && depth > 0 {
            continue;
        }

        let qname = join_qualified(prefix, "::", &name);
        let sig = format_sig_with_attrs(
            &attr_hints,
            &clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Rust),
        );
        let children = if matches!(kind, "module" | "trait") {
            if let (Some(bo), Some(bc)) = (stmt.body_open, stmt.body_close) {
                parse_rust_scope(src, bo + 1, bc, idx, depth + 1, &qname, include_all, imports)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        items.push(OutlineItem {
            kind: kind.to_owned(),
            name,
            qualified_name: qname,
            signature: sig,
            start_line,
            end_line,
            depth,
            children,
        });
    }

    items
}

// ===========================================================================
// Python
// ===========================================================================

fn leading_indent(line: &str) -> usize {
    let mut count = 0usize;
    for b in line.bytes() {
        match b {
            b' ' => count += 1,
            b'\t' => count += 4,
            _ => break,
        }
    }
    count
}

fn parse_python(
    src: &str,
    start: usize,
    idx: &LineIndex,
    opts: &OutlineOptions,
    doc: &mut OutlineDoc,
) {
    let total = idx.total_lines();
    if total == 0 {
        return;
    }
    let bytes = src.as_bytes();
    // Precompute byte ranges covered by strings/comments/parens so we only recognize
    // `def`/`class`/decorators at bracket_depth == 0 outside strings.
    let mut blocked_lines = vec![false; total + 1];
    let mut i = start;
    let mut paren_depth = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if paren_depth > 0 && (i == start || bytes[i - 1] == b'\n') {
            blocked_lines[idx.line_of(i)] = true;
        }
        if let Some(next) = skip_string_or_comment(bytes, i, LexLang::Python) {
            if b != b'#' {
                let l1 = idx.line_of(i);
                let l2 = idx.line_of(next.saturating_sub(1).max(i));
                // Lines AFTER the opening line of a multiline string cannot start a declaration.
                for slot in blocked_lines.iter_mut().take(l2 + 1).skip(l1 + 1) {
                    *slot = true;
                }
            }
            i = next;
            continue;
        }
        if matches!(b, b'(' | b'[' | b'{') {
            paren_depth += 1;
        } else if matches!(b, b')' | b']' | b'}') {
            paren_depth = paren_depth.saturating_sub(1);
        }
        i += 1;
    }

    struct PyFrame {
        indent: usize,
        kind: &'static str,
        item: OutlineItem,
    }

    let mut stack: Vec<PyFrame> = Vec::new();
    let mut pending_dec_line: Option<(usize, usize)> = None; // (indent, line_no)
    let mut last_content_line = 0usize;

    let close_to = |stack: &mut Vec<PyFrame>, target_indent: usize, end_line: usize, roots: &mut Vec<OutlineItem>| {
        while let Some(top) = stack.last() {
            if top.indent >= target_indent {
                let mut frame = stack.pop().unwrap();
                frame.item.end_line = end_line.max(frame.item.start_line);
                if let Some(parent) = stack.last_mut() {
                    parent.item.children.push(frame.item);
                } else {
                    roots.push(frame.item);
                }
            } else {
                break;
            }
        }
    };

    let mut line_no = 1usize;
    while line_no <= total {
        let raw_line = idx.line_slice(src, line_no);
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            line_no += 1;
            continue;
        }
        if blocked_lines[line_no] {
            last_content_line = line_no;
            line_no += 1;
            continue;
        }

        let indent = leading_indent(raw_line);
        if indent == 0
            && (trimmed.starts_with("import ") || trimmed.starts_with("from "))
            && stack.is_empty()
        {
            doc.imports.push(normalize_signature(trimmed, MAX_SIG_CHARS));
            pending_dec_line = None;
            last_content_line = line_no;
            line_no += 1;
            continue;
        }

        // Decorator line
        if trimmed.starts_with('@') {
            close_to(&mut stack, indent, last_content_line, &mut doc.items);
            if pending_dec_line.map(|(ind, _)| ind != indent).unwrap_or(true) {
                pending_dec_line = Some((indent, line_no));
            }
            // Skip multiline decorator args cleanly
            if let Some(at_pos) = raw_line.find('@') {
                let abs = idx.line_start(line_no) + at_pos;
                if let Some(paren_off) = find_first_unquoted_on_line(src, abs, idx.line_end(line_no), b'(', LexLang::Python) {
                    if let Some(close) = find_matching_delim(bytes, paren_off, b'(', b')', LexLang::Python) {
                        let close_line = idx.line_of(close);
                        last_content_line = close_line;
                        line_no = close_line + 1;
                        continue;
                    }
                }
            }
            last_content_line = line_no;
            line_no += 1;
            continue;
        }

        let decl_info: Option<(&'static str, usize)> = if trimmed.starts_with("class ") {
            Some(("class", 6))
        } else if trimmed.starts_with("async def ") {
            Some(("function", 10))
        } else if trimmed.starts_with("def ") {
            Some(("function", 4))
        } else {
            None
        };

        if let Some((raw_kind, kw_len)) = decl_info {
            close_to(&mut stack, indent, last_content_line, &mut doc.items);

            // Skip nested functions inside functions unless include_all
            let inside_func = stack.last().map(|f| f.kind == "function").unwrap_or(false);
            if inside_func && !opts.include_all {
                pending_dec_line = None;
                last_content_line = line_no;
                line_no += 1;
                continue;
            }

            let leading_ws_bytes = raw_line.len() - raw_line.trim_start().len();
            let decl_byte = idx.line_start(line_no) + leading_ws_bytes;
            let after_kw = decl_byte + kw_len;
            let name = read_ident(src, skip_ws_and_comments(bytes, after_kw, bytes.len(), LexLang::Python))
                .map(|(w, _)| w.to_owned())
                .unwrap_or_default();
            if name.is_empty() {
                pending_dec_line = None;
                last_content_line = line_no;
                line_no += 1;
                continue;
            }

            // Locate end of signature (`:` after matching `(...)`)
            let header_end = find_python_header_end(src, decl_byte, idx, line_no);
            let header_end_line = idx.line_of(header_end);
            let sig = normalize_signature(&src[decl_byte..header_end], MAX_SIG_CHARS);
            let start_line = match pending_dec_line.take() {
                Some((dec_ind, dec_ln)) if dec_ind == indent => dec_ln,
                _ => line_no,
            };

            let inside_class = stack.last().map(|f| f.kind == "class").unwrap_or(false);
            let kind = if raw_kind == "function" && inside_class {
                "method"
            } else {
                raw_kind
            };
            let prefix = stack
                .last()
                .map(|f| f.item.qualified_name.as_str())
                .unwrap_or("");
            let qname = join_qualified(prefix, ".", &name);
            let depth = stack.len();
            stack.push(PyFrame {
                indent,
                kind: raw_kind,
                item: OutlineItem {
                    kind: kind.to_owned(),
                    name,
                    qualified_name: qname,
                    signature: sig,
                    start_line,
                    end_line: header_end_line,
                    depth,
                    children: Vec::new(),
                },
            });
            last_content_line = header_end_line;
            line_no = header_end_line + 1;
            continue;
        }

        pending_dec_line = None;
        close_to(&mut stack, indent, last_content_line, &mut doc.items);
        last_content_line = line_no;
        line_no += 1;
    }

    close_to(&mut stack, 0, last_content_line, &mut doc.items);
}

fn find_first_unquoted_on_line(
    src: &str,
    start: usize,
    end: usize,
    target: u8,
    lang: LexLang,
) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut i = start;
    while i < end {
        if let Some(next) = skip_string_or_comment(bytes, i, lang) {
            i = next.min(end);
            continue;
        }
        if bytes[i] == target {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_python_header_end(src: &str, decl_start: usize, idx: &LineIndex, start_line: usize) -> usize {
    let bytes = src.as_bytes();
    let mut i = decl_start;
    while i < bytes.len() {
        if let Some(next) = skip_string_or_comment(bytes, i, LexLang::Python) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' => {
                if let Some(close) = find_matching_delim(bytes, i, b'(', b')', LexLang::Python) {
                    i = close + 1;
                    continue;
                }
            }
            b'[' => {
                if let Some(close) = find_matching_delim(bytes, i, b'[', b']', LexLang::Python) {
                    i = close + 1;
                    continue;
                }
            }
            b':' => return i,
            _ => {}
        }
        i += 1;
    }
    idx.line_end(start_line)
}

// ===========================================================================
// TypeScript / JavaScript (ASI-safe)
// ===========================================================================

/// Next statement in an ASI language (TS/JS/Go/PowerShell), splitting on `;`, `{ ... }`, or
/// terminating newlines at paren/bracket depth 0.
fn next_asi_stmt(
    bytes: &[u8],
    pos: usize,
    scope_end: usize,
    lang: LexLang,
    can_end_on_newline: impl Fn(&[u8], usize, usize) -> bool,
) -> Option<BraceStmt> {
    let start = skip_ws_and_comments(bytes, pos, scope_end, lang);
    if start >= scope_end {
        return None;
    }
    let mut i = start;
    let mut seen_eq = false;
    while i < scope_end {
        if let Some(next) = skip_string_or_comment(bytes, i, lang) {
            let skipped_comment = matches!(bytes[i], b'/' | b'#' | b'<');
            i = next.min(scope_end);
            if skipped_comment && bytes.get(i) == Some(&b'\n') && can_end_on_newline(bytes, start, i)
            {
                return Some(BraceStmt {
                    header_start: start,
                    header_end: i,
                    body_open: None,
                    body_close: None,
                    next_pos: i + 1,
                });
            }
            continue;
        }
        let b = bytes[i];
        match b {
            b'(' => {
                if let Some(close) = find_matching_delim(bytes, i, b'(', b')', lang) {
                    i = (close + 1).min(scope_end);
                    continue;
                }
            }
            b'[' => {
                if let Some(close) = find_matching_delim(bytes, i, b'[', b']', lang) {
                    i = (close + 1).min(scope_end);
                    continue;
                }
            }
            b'=' => {
                if bytes.get(i + 1) == Some(&b'>') {
                    i += 2;
                    continue;
                }
                let prev = i.checked_sub(1).and_then(|p| bytes.get(p).copied());
                let next = bytes.get(i + 1).copied();
                if !matches!(prev, Some(b'=' | b'!' | b'<' | b'>')) && next != Some(b'=') {
                    seen_eq = true;
                }
            }
            b';' => {
                return Some(BraceStmt {
                    header_start: start,
                    header_end: i,
                    body_open: None,
                    body_close: None,
                    next_pos: i + 1,
                });
            }
            b'{' => {
                let close = find_matching_delim(bytes, i, b'{', b'}', lang)
                    .map(|c| c.min(scope_end - 1))
                    .unwrap_or(scope_end - 1);
                let mut after = close + 1;
                if seen_eq {
                    let j = skip_ws_and_comments(bytes, after, scope_end, lang);
                    if j < scope_end && bytes[j] == b';' {
                        after = j + 1;
                    }
                }
                return Some(BraceStmt {
                    header_start: start,
                    header_end: i,
                    body_open: Some(i),
                    body_close: Some(close),
                    next_pos: after,
                });
            }
            b'\n' => {
                if can_end_on_newline(bytes, start, i) {
                    return Some(BraceStmt {
                        header_start: start,
                        header_end: i,
                        body_open: None,
                        body_close: None,
                        next_pos: i + 1,
                    });
                }
            }
            _ => {}
        }
        i += 1;
    }
    Some(BraceStmt {
        header_start: start,
        header_end: scope_end,
        body_open: None,
        body_close: None,
        next_pos: scope_end,
    })
}

fn tsjs_newline_terminates(bytes: &[u8], start: usize, nl_pos: usize) -> bool {
    let slice = &bytes[start..nl_pos];
    let trimmed_end = trim_ascii_end_comment(slice);
    let Some(&last) = trimmed_end.last() else {
        return false;
    };
    if matches!(
        last,
        b',' | b'=' | b':' | b'?' | b'|' | b'&' | b'.' | b'+' | b'-' | b'*' | b'/'
    ) {
        return false;
    }
    if trimmed_end.ends_with(b"=>") {
        return false;
    }
    // Keep scanning if next non-ws token starts with `{` (brace on next line) or `=>` or `.` or `implements`/`extends`
    let next = skip_ws_and_comments(bytes, nl_pos + 1, bytes.len(), LexLang::TsJs);
    if next < bytes.len() {
        let nb = bytes[next];
        if matches!(nb, b'{' | b'.' | b'|' | b'&' | b'?') {
            return false;
        }
        if bytes[next..].starts_with(b"=>")
            || bytes[next..].starts_with(b"extends")
            || bytes[next..].starts_with(b"implements")
        {
            return false;
        }
    }
    true
}

fn trim_ascii_end_comment(mut slice: &[u8]) -> &[u8] {
    while let Some(&b) = slice.last() {
        if b.is_ascii_whitespace() {
            slice = &slice[..slice.len() - 1];
        } else {
            break;
        }
    }
    slice
}

fn strip_ts_decorators(src: &str, mut pos: usize, end: usize) -> (usize, Option<usize>) {
    let bytes = src.as_bytes();
    let mut first = None;
    loop {
        pos = skip_ws_and_comments(bytes, pos, end, LexLang::TsJs);
        if pos >= end || bytes[pos] != b'@' {
            break;
        }
        if first.is_none() {
            first = Some(pos);
        }
        pos += 1;
        while pos < end {
            if let Some(next) = skip_string_or_comment(bytes, pos, LexLang::TsJs) {
                pos = next.min(end);
                continue;
            }
            if bytes[pos] == b'(' {
                if let Some(close) = find_matching_delim(bytes, pos, b'(', b')', LexLang::TsJs) {
                    pos = (close + 1).min(end);
                    break;
                }
            }
            if bytes[pos] == b'\n' || bytes[pos] == b';' {
                break;
            }
            pos += 1;
        }
    }
    (pos, first)
}

#[allow(clippy::too_many_arguments)]
fn parse_tsjs_scope(
    src: &str,
    scope_start: usize,
    scope_end: usize,
    idx: &LineIndex,
    depth: usize,
    prefix: &str,
    in_class: bool,
    include_all: bool,
    imports: &mut Vec<String>,
) -> Vec<OutlineItem> {
    let bytes = src.as_bytes();
    let mut pos = scope_start;
    let mut items = Vec::new();

    while pos < scope_end {
        let (decl_pos, dec_start) = strip_ts_decorators(src, pos, scope_end);
        let Some(stmt) = next_asi_stmt(
            bytes,
            decl_pos,
            scope_end,
            LexLang::TsJs,
            tsjs_newline_terminates,
        ) else {
            break;
        };
        let item_start = dec_start.unwrap_or(stmt.header_start);
        pos = stmt.next_pos;

        let hdr_raw = src[stmt.header_start..stmt.header_end].trim();
        if hdr_raw.is_empty() {
            continue;
        }
        let scan = scan_header(src, stmt.header_start, stmt.header_end, LexLang::TsJs);
        let first = scan.words.first().map(|w| w.0.as_str()).unwrap_or("");
        if first == "import" && stmt.body_open.is_none() {
            let imp = clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::TsJs);
            if !imp.is_empty() {
                imports.push(imp);
            }
            continue;
        }
        // `import { a, b } from './x'` has `{` in the middle of the import statement!
        if first == "import" && stmt.body_open.is_some() {
            // Advance past `from '...'` if present
            let rest_start = stmt.next_pos;
            if let Some(rest_stmt) = next_asi_stmt(
                bytes,
                rest_start,
                scope_end,
                LexLang::TsJs,
                tsjs_newline_terminates,
            ) {
                pos = rest_stmt.next_pos;
                let imp = clean_header_text(
                    src,
                    stmt.header_start,
                    rest_stmt.header_end,
                    LexLang::TsJs,
                );
                if !imp.is_empty() {
                    imports.push(imp);
                }
            }
            continue;
        }

        let start_line = idx.line_of(item_start);
        let end_line = idx.line_of(stmt.body_close.unwrap_or(stmt.header_end));

        if !in_class {
            if let Some((kind, kw_idx)) = tsjs_top_keyword(&scan.words) {
                if matches!(kind, "const" | "let" | "var") {
                    // Emit only if arrow/function expression or include_all
                    let after_eq = hdr_raw.split_once('=').map(|(_, rhs)| rhs.trim()).unwrap_or("");
                    let is_fn_expr = scan.has_fat_arrow
                        || after_eq.starts_with("function")
                        || after_eq.starts_with("async function")
                        || after_eq.starts_with("async (");
                    if !is_fn_expr && !include_all {
                        continue;
                    }
                    let name = scan
                        .words
                        .get(kw_idx + 1)
                        .map(|(w, _, _)| w.clone())
                        .unwrap_or_default();
                    if name.is_empty() {
                        continue;
                    }
                    let qname = join_qualified(prefix, ".", &name);
                    let sig = clean_header_text(
                        src,
                        stmt.header_start,
                        stmt.header_end,
                        LexLang::TsJs,
                    );
                    items.push(OutlineItem {
                        kind: if is_fn_expr { "function" } else { kind }.to_owned(),
                        name,
                        qualified_name: qname,
                        signature: sig,
                        start_line,
                        end_line,
                        depth,
                        children: Vec::new(),
                    });
                    continue;
                }

                let name = match scan.words.get(kw_idx + 1) {
                    Some((w, _, _)) => w.clone(),
                    None if kind == "namespace" => {
                        // `declare module "pkg-name" { ... }`
                        let after_kw = scan.words[kw_idx].2;
                        let tail = src[after_kw..stmt.header_end].trim();
                        if (tail.starts_with('"') || tail.starts_with('\'')) && tail.len() >= 2 {
                            tail[1..tail.len() - 1].to_owned()
                        } else {
                            String::new()
                        }
                    }
                    None if kind == "class"
                        && scan.words.iter().any(|(w, _, _)| w == "default") =>
                    {
                        "default".to_owned()
                    }
                    None => String::new(),
                };
                if name.is_empty() {
                    continue;
                }
                let qname = join_qualified(prefix, ".", &name);
                let sig =
                    clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::TsJs);
                let children = if matches!(kind, "class" | "namespace") {
                    if let (Some(bo), Some(bc)) = (stmt.body_open, stmt.body_close) {
                        parse_tsjs_scope(
                            src,
                            bo + 1,
                            bc,
                            idx,
                            depth + 1,
                            &qname,
                            kind == "class",
                            include_all,
                            imports,
                        )
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                items.push(OutlineItem {
                    kind: kind.to_owned(),
                    name,
                    qualified_name: qname,
                    signature: sig,
                    start_line,
                    end_line,
                    depth,
                    children,
                });
                continue;
            }
        } else {
            // Class member: constructor, method, getter/setter, or arrow field
            if scan.has_paren && (!scan.has_eq_before_paren || scan.has_fat_arrow) {
                let fp = scan.first_paren_pos.unwrap_or(stmt.header_end);
                let name = scan
                    .words
                    .iter()
                    .rev()
                    .find(|(_, _, e)| *e <= fp)
                    .map(|(w, _, _)| w.clone())
                    .unwrap_or_default();
                if name.is_empty() || matches!(name.as_str(), "if" | "for" | "while" | "switch") {
                    continue;
                }
                let kind = if name == "constructor" {
                    "constructor"
                } else {
                    "method"
                };
                let qname = join_qualified(prefix, ".", &name);
                let sig =
                    clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::TsJs);
                items.push(OutlineItem {
                    kind: kind.to_owned(),
                    name,
                    qualified_name: qname,
                    signature: sig,
                    start_line,
                    end_line,
                    depth,
                    children: Vec::new(),
                });
            } else if include_all && !scan.words.is_empty() {
                let name = scan.words[0].0.clone();
                let qname = join_qualified(prefix, ".", &name);
                let sig =
                    clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::TsJs);
                items.push(OutlineItem {
                    kind: "field".to_owned(),
                    name,
                    qualified_name: qname,
                    signature: sig,
                    start_line,
                    end_line,
                    depth,
                    children: Vec::new(),
                });
            }
        }
    }

    items
}

fn tsjs_top_keyword(words: &[(String, usize, usize)]) -> Option<(&'static str, usize)> {
    for (idx, (w, _, _)) in words.iter().enumerate() {
        match w.as_str() {
            "interface" => return Some(("interface", idx)),
            "type" => return Some(("type", idx)),
            "enum" => return Some(("enum", idx)),
            "namespace" | "module" => return Some(("namespace", idx)),
            "class" => return Some(("class", idx)),
            "function" => return Some(("function", idx)),
            "const" => return Some(("const", idx)),
            "let" => return Some(("let", idx)),
            "var" => return Some(("var", idx)),
            _ => {}
        }
    }
    None
}

// ===========================================================================
// Go
// ===========================================================================

fn go_newline_terminates(bytes: &[u8], start: usize, nl_pos: usize) -> bool {
    let trimmed = trim_ascii_end_comment(&bytes[start..nl_pos]);
    let Some(&last) = trimmed.last() else {
        return false;
    };
    !matches!(last, b',' | b'+' | b'-' | b'*' | b'/' | b'=' | b'(' | b'[')
}

fn parse_go(
    src: &str,
    start: usize,
    idx: &LineIndex,
    opts: &OutlineOptions,
    doc: &mut OutlineDoc,
) {
    let bytes = src.as_bytes();
    let mut pos = start;
    while pos < bytes.len() {
        let Some(stmt) = next_asi_stmt(
            bytes,
            pos,
            bytes.len(),
            LexLang::Go,
            go_newline_terminates,
        ) else {
            break;
        };
        pos = stmt.next_pos;
        let hdr_raw = src[stmt.header_start..stmt.header_end].trim();
        if hdr_raw.is_empty() {
            continue;
        }
        let scan = scan_header(src, stmt.header_start, stmt.header_end, LexLang::Go);
        let first = scan.words.first().map(|w| w.0.as_str()).unwrap_or("");
        let start_line = idx.line_of(stmt.header_start);
        let end_line = idx.line_of(stmt.body_close.unwrap_or(stmt.header_end));

        match first {
            "package" => continue,
            "import" => {
                let imp = clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Go);
                if !imp.is_empty() {
                    doc.imports.push(imp);
                }
            }
            "func" => {
                // Distinguish `func Name(...)` vs `func (r *Recv) Name(...)`
                let after_func = skip_ws_and_comments(bytes, scan.words[0].2, stmt.header_end, LexLang::Go);
                if bytes.get(after_func) == Some(&b'(') {
                    if let Some(recv_close) =
                        find_matching_delim(bytes, after_func, b'(', b')', LexLang::Go)
                    {
                        let recv_inner = &src[after_func + 1..recv_close];
                        let recv_type = recv_inner
                            .split_whitespace()
                            .last()
                            .unwrap_or("")
                            .trim_start_matches('*')
                            .split('[')
                            .next()
                            .unwrap_or("")
                            .to_owned();
                        let name_pos = skip_ws_and_comments(bytes, recv_close + 1, stmt.header_end, LexLang::Go);
                        if let Some((name, _)) = read_ident(src, name_pos) {
                            let qname = join_qualified(&recv_type, ".", name);
                            let sig = clean_header_text(
                                src,
                                stmt.header_start,
                                stmt.header_end,
                                LexLang::Go,
                            );
                            doc.items.push(OutlineItem {
                                kind: "method".to_owned(),
                                name: name.to_owned(),
                                qualified_name: qname,
                                signature: sig,
                                start_line,
                                end_line,
                                depth: 0,
                                children: Vec::new(),
                            });
                        }
                        continue;
                    }
                }
                if let Some((name, _, _)) = scan.words.get(1) {
                    let sig =
                        clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Go);
                    doc.items.push(OutlineItem {
                        kind: "function".to_owned(),
                        name: name.clone(),
                        qualified_name: name.clone(),
                        signature: sig,
                        start_line,
                        end_line,
                        depth: 0,
                        children: Vec::new(),
                    });
                }
            }
            "type" => {
                if let Some((name, _, _)) = scan.words.get(1) {
                    let kind = match scan.words.get(2).map(|w| w.0.as_str()) {
                        Some("struct") => "struct",
                        Some("interface") => "interface",
                        _ => "type",
                    };
                    let sig =
                        clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Go);
                    let children = if kind == "interface" {
                        if let (Some(bo), Some(bc)) = (stmt.body_open, stmt.body_close) {
                            parse_go_interface(src, bo + 1, bc, idx, name)
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    };
                    doc.items.push(OutlineItem {
                        kind: kind.to_owned(),
                        name: name.clone(),
                        qualified_name: name.clone(),
                        signature: sig,
                        start_line,
                        end_line,
                        depth: 0,
                        children,
                    });
                }
            }
            "const" | "var" => {
                let name = scan
                    .words
                    .get(1)
                    .map(|(w, _, _)| w.clone())
                    .unwrap_or_else(|| first.to_owned());
                if opts.include_all || hdr_raw.contains('(') || scan.words.len() >= 2 {
                    let sig =
                        clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Go);
                    doc.items.push(OutlineItem {
                        kind: first.to_owned(),
                        name: name.clone(),
                        qualified_name: name,
                        signature: sig,
                        start_line,
                        end_line,
                        depth: 0,
                        children: Vec::new(),
                    });
                }
            }
            _ => {}
        }
    }
}

fn parse_go_interface(
    src: &str,
    scope_start: usize,
    scope_end: usize,
    idx: &LineIndex,
    iface_name: &str,
) -> Vec<OutlineItem> {
    let bytes = src.as_bytes();
    let mut pos = scope_start;
    let mut out = Vec::new();
    while pos < scope_end {
        let Some(stmt) = next_asi_stmt(
            bytes,
            pos,
            scope_end,
            LexLang::Go,
            go_newline_terminates,
        ) else {
            break;
        };
        pos = stmt.next_pos;
        let line = clean_header_text(src, stmt.header_start, stmt.header_end, LexLang::Go);
        if line.is_empty() {
            continue;
        }
        let Some((name, _)) = read_ident(line.as_str(), 0) else {
            continue;
        };
        let ln = idx.line_of(stmt.header_start);
        out.push(OutlineItem {
            kind: "method".to_owned(),
            name: name.to_owned(),
            qualified_name: join_qualified(iface_name, ".", name),
            signature: line,
            start_line: ln,
            end_line: ln,
            depth: 1,
            children: Vec::new(),
        });
    }
    out
}

// ===========================================================================
// PowerShell
// ===========================================================================

fn ps_newline_terminates(bytes: &[u8], start: usize, nl_pos: usize) -> bool {
    let trimmed = trim_ascii_end_comment(&bytes[start..nl_pos]);
    let Some(&last) = trimmed.last() else {
        return false;
    };
    if last == b'`' || last == b',' || last == b'|' {
        return false;
    }
    let next = skip_ws_and_comments(bytes, nl_pos + 1, bytes.len(), LexLang::PowerShell);
    if next < bytes.len() && bytes[next] == b'{' {
        return false;
    }
    true
}

fn strip_ps_attributes(src: &str, mut pos: usize, end: usize) -> (usize, Option<usize>) {
    let bytes = src.as_bytes();
    let mut first = None;
    loop {
        pos = skip_ws_and_comments(bytes, pos, end, LexLang::PowerShell);
        if pos >= end || bytes[pos] != b'[' {
            break;
        }
        // Only treat `[Attr(...)]` as attribute if followed by newline or another `[` or declaration
        if let Some(close) = find_matching_delim(bytes, pos, b'[', b']', LexLang::PowerShell) {
            let after = skip_ws_and_comments(bytes, close + 1, end, LexLang::PowerShell);
            if first.is_none() {
                first = Some(pos);
            }
            pos = after;
        } else {
            break;
        }
    }
    (pos, first)
}

#[allow(clippy::too_many_arguments)]
fn parse_ps_scope(
    src: &str,
    scope_start: usize,
    scope_end: usize,
    idx: &LineIndex,
    depth: usize,
    prefix: &str,
    in_class: bool,
    imports: &mut Vec<String>,
) -> Vec<OutlineItem> {
    let bytes = src.as_bytes();
    let mut pos = scope_start;
    let mut items = Vec::new();

    while pos < scope_end {
        let (decl_pos, attr_start) = strip_ps_attributes(src, pos, scope_end);
        let Some(stmt) = next_asi_stmt(
            bytes,
            decl_pos,
            scope_end,
            LexLang::PowerShell,
            ps_newline_terminates,
        ) else {
            break;
        };
        let item_start = attr_start.unwrap_or(stmt.header_start);
        pos = stmt.next_pos;

        let hdr_raw = src[stmt.header_start..stmt.header_end].trim();
        if hdr_raw.is_empty() {
            continue;
        }
        let scan = scan_header(src, stmt.header_start, stmt.header_end, LexLang::PowerShell);
        let first_lower = scan
            .words
            .first()
            .map(|w| w.0.to_ascii_lowercase())
            .unwrap_or_default();
        let start_line = idx.line_of(item_start);
        let end_line = idx.line_of(stmt.body_close.unwrap_or(stmt.header_end));

        if !in_class {
            if first_lower == "using" || first_lower == "import" {
                let imp = clean_header_text(
                    src,
                    stmt.header_start,
                    stmt.header_end,
                    LexLang::PowerShell,
                );
                if !imp.is_empty() {
                    imports.push(imp);
                }
                continue;
            }
            if first_lower == "param" && scan.has_paren && stmt.body_open.is_none() {
                let sig = clean_header_text(
                    src,
                    stmt.header_start,
                    stmt.header_end,
                    LexLang::PowerShell,
                );
                items.push(OutlineItem {
                    kind: "param".to_owned(),
                    name: "param".to_owned(),
                    qualified_name: "param".to_owned(),
                    signature: sig,
                    start_line,
                    end_line,
                    depth,
                    children: Vec::new(),
                });
                continue;
            }
            if matches!(
                first_lower.as_str(),
                "class" | "enum" | "function" | "filter" | "workflow"
            ) {
                // PowerShell function names can include `-` and `scope:` (e.g. `Get-TokenReport`, `script:Init-Log`)
                let after_kw = skip_ws_and_comments(
                    bytes,
                    scan.words[0].2,
                    stmt.header_end,
                    LexLang::PowerShell,
                );
                let name = read_ps_name(src, after_kw, stmt.header_end);
                if name.is_empty() {
                    continue;
                }
                let kind = match first_lower.as_str() {
                    "class" => "class",
                    "enum" => "enum",
                    _ => "function",
                };
                let qname = join_qualified(prefix, ".", &name);
                let sig = clean_header_text(
                    src,
                    stmt.header_start,
                    stmt.header_end,
                    LexLang::PowerShell,
                );
                let children = if kind == "class" {
                    if let (Some(bo), Some(bc)) = (stmt.body_open, stmt.body_close) {
                        parse_ps_scope(
                            src,
                            bo + 1,
                            bc,
                            idx,
                            depth + 1,
                            &qname,
                            true,
                            imports,
                        )
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                items.push(OutlineItem {
                    kind: kind.to_owned(),
                    name,
                    qualified_name: qname,
                    signature: sig,
                    start_line,
                    end_line,
                    depth,
                    children,
                });
            }
        } else if scan.has_paren && stmt.body_open.is_some() {
            // PowerShell class method or constructor
            let fp = scan.first_paren_pos.unwrap_or(stmt.header_end);
            let name = scan
                .words
                .iter()
                .rev()
                .find(|(_, _, e)| *e <= fp)
                .map(|(w, _, _)| w.clone())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let kind = if prefix.rsplit('.').next() == Some(name.as_str()) {
                "constructor"
            } else {
                "method"
            };
            let qname = join_qualified(prefix, ".", &name);
            let sig = clean_header_text(
                src,
                stmt.header_start,
                stmt.header_end,
                LexLang::PowerShell,
            );
            items.push(OutlineItem {
                kind: kind.to_owned(),
                name,
                qualified_name: qname,
                signature: sig,
                start_line,
                end_line,
                depth,
                children: Vec::new(),
            });
        }
    }

    items
}

fn read_ps_name(src: &str, start: usize, end: usize) -> String {
    let bytes = src.as_bytes();
    let mut i = start;
    while i < end {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':') {
            i += 1;
        } else {
            break;
        }
    }
    src[start..i].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outline::{flatten_items, outline_source};

    #[test]
    fn csharp_file_scoped_ns_attributes_and_expression_members() {
        let src = r#"using System;
using System.Threading.Tasks;

namespace App.Services;

public class OrderService(ILogger log)
{
    private readonly int _x = new Random().Next();

    public string Name => "Order";

    public int Count { get; set; }

    [Fact]
    public async Task<int> ProcessAsync(string id)
    {
        var s = @"fake } method() {}";
        return 1;
    }

    public int Double(int x) => x * 2;
}
"#;
        let doc = outline_source("OrderService.cs", src, Lang::CSharp, &OutlineOptions::default());
        assert_eq!(doc.imports.len(), 2);
        assert_eq!(doc.items[0].kind, "namespace");
        assert_eq!(doc.items[0].name, "App.Services");
        let cls = &doc.items[0].children[0];
        assert_eq!(cls.kind, "class");
        assert_eq!(cls.name, "OrderService");
        assert_eq!(cls.qualified_name, "App.Services.OrderService");

        let members = &cls.children;
        assert_eq!(members.len(), 4);
        assert_eq!(members[0].kind, "property");
        assert_eq!(members[0].name, "Name");
        assert_eq!(members[1].kind, "property");
        assert_eq!(members[1].name, "Count");
        assert_eq!(members[2].kind, "method");
        assert_eq!(members[2].name, "ProcessAsync");
        assert_eq!(members[2].start_line, 14); // includes [Fact]
        assert_eq!(members[2].end_line, 19);
        assert!(members[2].signature.contains("[Fact]"));
        assert_eq!(members[3].kind, "method");
        assert_eq!(members[3].name, "Double");
    }

    #[test]
    fn razor_directives_and_code_block_preserve_line_numbers() {
        let src = "@page \"/tenants\"\n@inject ITenantApi Api\n\n<h1>Tenants</h1>\n\n@code {\n    private bool _loading;\n\n    public async Task ReloadAsync()\n    {\n        _loading = true;\n    }\n}\n";
        let doc = outline_source("Tenants.razor", src, Lang::Razor, &OutlineOptions::default());
        assert_eq!(doc.items.len(), 3);
        assert_eq!(doc.items[0].kind, "directive");
        assert_eq!(doc.items[0].start_line, 1);
        assert_eq!(doc.items[1].name, "Api");
        assert_eq!(doc.items[2].name, "@code");
        assert_eq!(doc.items[2].start_line, 6);
        assert_eq!(doc.items[2].end_line, 13);
        let m = &doc.items[2].children[0];
        assert_eq!(m.name, "ReloadAsync");
        assert_eq!(m.start_line, 9);
        assert_eq!(m.end_line, 12);
    }

    #[test]
    fn rust_generic_impl_lifetimes_and_tests() {
        let src = r#"use std::fmt;

pub struct Store<T> {
    val: T,
}

impl<T: fmt::Debug> Store<T> {
    pub fn get<'a>(&'a self) -> &'a T {
        let ch = '}';
        &self.val
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn works() {
        assert_eq!(1, 1);
    }
}
"#;
        let doc = outline_source("lib.rs", src, Lang::Rust, &OutlineOptions::default());
        assert_eq!(doc.imports, vec!["use std::fmt"]);
        let flat = flatten_items(&doc.items);
        let get_fn = flat.iter().find(|it| it.name == "get").unwrap();
        assert_eq!(get_fn.qualified_name, "Store::get");
        assert_eq!(get_fn.start_line, 8);
        assert_eq!(get_fn.end_line, 11);
        let test_fn = flat.iter().find(|it| it.name == "works").unwrap();
        assert_eq!(test_fn.qualified_name, "tests::works");
        assert_eq!(test_fn.start_line, 16); // includes #[test]
    }

    #[test]
    fn python_ignores_docstrings_and_handles_decorators() {
        let src = r#"import os

@dataclass
class Runner:
    """
    def fake_in_docstring():
        pass
    """
    @classmethod
    async def create(
        cls,
        name: str,
    ) -> "Runner":
        return cls()

def top():
    return 1
"#;
        let doc = outline_source("runner.py", src, Lang::Python, &OutlineOptions::default());
        assert_eq!(doc.imports, vec!["import os"]);
        assert_eq!(doc.items.len(), 2, "items: {:#?}", doc.items);
        let cls = &doc.items[0];
        assert_eq!(cls.name, "Runner");
        assert_eq!(cls.start_line, 3); // includes @dataclass
        assert_eq!(cls.end_line, 14);
        assert_eq!(cls.children.len(), 1);
        assert_eq!(cls.children[0].name, "create");
        assert_eq!(cls.children[0].kind, "method");
        assert_eq!(cls.children[0].start_line, 9); // includes @classmethod
        assert_eq!(cls.children[0].end_line, 14);
        assert_eq!(doc.items[1].name, "top");
        assert_eq!(doc.items[1].start_line, 16);
        assert_eq!(doc.items[1].end_line, 17);
    }

    #[test]
    fn ts_asi_destructuring_and_arrow_functions() {
        let src = r#"import { Request } from 'express'
import {
  User,
} from './types'

export class ApiClient {
  constructor(private readonly baseUrl: string) {}

  async fetchUser({ id }: { id: string }): Promise<User> {
    return await fetch(`${this.baseUrl}/${id}`)
  }
}

export const formatUser = (u: User) => {
  return u.name
}

export default class {
  ping() {}
}

declare module "ambient-pkg" {
  export function helper(): void;
}
"#;
        let doc = outline_source("api.ts", src, Lang::TypeScript, &OutlineOptions::default());
        assert_eq!(doc.imports.len(), 2);
        assert_eq!(doc.items.len(), 4);
        assert_eq!(doc.items[0].kind, "class");
        assert_eq!(doc.items[0].children.len(), 2);
        assert_eq!(doc.items[0].children[0].kind, "constructor");
        assert_eq!(doc.items[0].children[1].name, "fetchUser");
        assert_eq!(doc.items[1].kind, "function");
        assert_eq!(doc.items[1].name, "formatUser");
        assert_eq!(doc.items[2].kind, "class");
        assert_eq!(doc.items[2].name, "default");
        assert_eq!(doc.items[3].kind, "namespace");
        assert_eq!(doc.items[3].name, "ambient-pkg");
    }

    #[test]
    fn go_receivers_and_interfaces() {
        let src = r#"package svc

import (
    "context"
)

type Store interface {
    Get(ctx context.Context) error
}

type Server struct {
    addr string
}

func (s *Server) Start(ctx context.Context) error {
    return nil
}

func NewServer(addr string) *Server {
    return &Server{addr: addr}
}
"#;
        let doc = outline_source("server.go", src, Lang::Go, &OutlineOptions::default());
        assert_eq!(doc.imports.len(), 1);
        let flat = flatten_items(&doc.items);
        let start = flat.iter().find(|i| i.name == "Start").unwrap();
        assert_eq!(start.kind, "method");
        assert_eq!(start.qualified_name, "Server.Start");
        let get = flat.iter().find(|i| i.name == "Get").unwrap();
        assert_eq!(get.qualified_name, "Store.Get");
    }

    #[test]
    fn powershell_functions_classes_and_herestrings() {
        let src = r#"param(
    [string]$Env = "dev"
)

class Deployer {
    [string]$Target
    Deployer([string]$t) { $this.Target = $t }
    [void] Run() { Write-Host $this.Target }
}

function Invoke-Deploy {
    $help = @"
function Fake-In-HereString { }
"@
    Write-Output $help
}
"#;
        let doc = outline_source("deploy.ps1", src, Lang::PowerShell, &OutlineOptions::default());
        assert_eq!(doc.items.len(), 3);
        assert_eq!(doc.items[0].kind, "param");
        assert_eq!(doc.items[1].kind, "class");
        assert_eq!(doc.items[1].children.len(), 2);
        assert_eq!(doc.items[1].children[0].kind, "constructor");
        assert_eq!(doc.items[1].children[1].name, "Run");
        assert_eq!(doc.items[2].kind, "function");
        assert_eq!(doc.items[2].name, "Invoke-Deploy");
    }
}
