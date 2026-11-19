//! Structural parsers and selector resolvers for JSON/JSONC, JSONL, YAML, TOML, and Markdown.

use super::lexer::{normalize_signature, skip_string_or_comment, LexLang, LineIndex};
use super::{Lang, OutlineDoc, OutlineItem, OutlineOptions};
use std::collections::{BTreeSet, HashMap};

const MAX_SIG_CHARS: usize = 140;
const MAX_ARRAY_OUTLINE_CHILDREN: usize = 5;
const MAX_JSONL_SHAPES: usize = 60;

#[derive(Debug, Clone)]
pub struct ResolvedRange {
    pub label: String,
    pub start_line: usize,
    pub end_line: usize,
}

pub fn parse_structured(
    path: &str,
    src: &str,
    idx: &LineIndex,
    lang: Lang,
    _opts: &OutlineOptions,
) -> OutlineDoc {
    let mut doc = OutlineDoc {
        path: path.to_owned(),
        lang: lang.as_str().to_owned(),
        total_lines: idx.total_lines(),
        imports: Vec::new(),
        items: Vec::new(),
        warnings: Vec::new(),
    };
    let start = if src.starts_with('\u{FEFF}') { 3 } else { 0 };
    match lang {
        Lang::Json => match parse_json_tree(src, start, idx) {
            Ok(root) => doc.items = json_node_to_items(&root, "", 0),
            Err(err) => doc.warnings.push(err),
        },
        Lang::Jsonl => doc.items = parse_jsonl_outline(src, idx),
        Lang::Yaml => doc.items = yaml_nodes_to_items(&parse_yaml_tree(src, start, idx), "", 0),
        Lang::Toml => doc.items = parse_toml_outline(src, start, idx),
        Lang::Markdown => doc.items = parse_markdown_outline(src, start, idx),
        _ => {}
    }
    doc
}

pub fn resolve_structured_selector(
    src: &str,
    idx: &LineIndex,
    lang: Lang,
    selector: &str,
) -> Result<Vec<ResolvedRange>, String> {
    let start = if src.starts_with('\u{FEFF}') { 3 } else { 0 };
    match lang {
        Lang::Json => resolve_json_selector(src, start, idx, selector),
        Lang::Jsonl => resolve_jsonl_selector(src, idx, selector),
        Lang::Yaml => resolve_yaml_selector(src, start, idx, selector),
        Lang::Toml => resolve_toml_selector(src, start, idx, selector),
        Lang::Markdown => resolve_markdown_selector(src, start, idx, selector),
        _ => Err(format!("{} is not a structured format", lang.as_str())),
    }
}

// ===========================================================================
// Shared path token parser & suggestion helper
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSeg {
    Key(String),
    Index(usize),
}

/// Parse RFC 6901 JSON Pointer (`/a/b/0`) or dot/bracket path (`a.b[0]`, `$.a['b']`).
fn parse_data_path(raw: &str) -> Result<Vec<PathSeg>, String> {
    let s = raw.trim();
    if s.is_empty() || s == "/" || s == "$" {
        return Ok(Vec::new());
    }
    if let Some(rest) = s.strip_prefix('/') {
        let mut out = Vec::new();
        for part in rest.split('/') {
            let decoded = unescape_json_pointer(part);
            out.push(PathSeg::Key(decoded));
        }
        return Ok(out);
    }

    let s = s.strip_prefix("$.").or_else(|| s.strip_prefix('$')).unwrap_or(s);
    let mut segs = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '.' {
            i += 1;
            continue;
        }
        if chars[i] == '[' {
            i += 1;
            if i < chars.len() && (chars[i] == '\'' || chars[i] == '"') {
                let q = chars[i];
                i += 1;
                let mut key = String::new();
                while i < chars.len() && chars[i] != q {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                    }
                    key.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() || chars[i] != q {
                    return Err(format!("unclosed quote in path `{raw}`"));
                }
                i += 1; // quote
                if i >= chars.len() || chars[i] != ']' {
                    return Err(format!("expected `]` in path `{raw}`"));
                }
                i += 1;
                segs.push(PathSeg::Key(key));
            } else {
                let mut inner = String::new();
                while i < chars.len() && chars[i] != ']' {
                    inner.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() || chars[i] != ']' {
                    return Err(format!("unclosed `[` in path `{raw}`"));
                }
                i += 1;
                let trimmed = inner.trim();
                let idx = trimmed
                    .parse::<usize>()
                    .map_err(|_| format!("invalid array index `{trimmed}` in path `{raw}`"))?;
                segs.push(PathSeg::Index(idx));
            }
        } else if chars[i] == '"' || chars[i] == '\'' {
            let q = chars[i];
            i += 1;
            let mut key = String::new();
            while i < chars.len() && chars[i] != q {
                if q == '"' && chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                key.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() || chars[i] != q {
                return Err(format!("unclosed quote in path `{raw}`"));
            }
            i += 1;
            segs.push(PathSeg::Key(key));
        } else {
            let mut key = String::new();
            while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
                key.push(chars[i]);
                i += 1;
            }
            if !key.is_empty() {
                segs.push(PathSeg::Key(key));
            }
        }
    }
    Ok(segs)
}

fn unescape_json_pointer(raw: &str) -> String {
    raw.replace("~1", "/").replace("~0", "~")
}

fn is_subsequence(needle: &str, haystack: &str) -> bool {
    let mut n_chars = needle.chars();
    let Some(mut target) = n_chars.next() else {
        return false;
    };
    for ch in haystack.chars() {
        if ch == target {
            match n_chars.next() {
                Some(next) => target = next,
                None => return true,
            }
        }
    }
    false
}

pub fn suggest_candidates<'a>(
    query: &str,
    candidates: impl Iterator<Item = &'a str>,
    require_match: bool,
) -> Vec<String> {
    let q_lower = query.to_ascii_lowercase();
    let mut scored: Vec<(i32, &str)> = candidates
        .map(|cand| {
            let c_lower = cand.to_ascii_lowercase();
            let short = c_lower.rsplit(['.', ':']).next().unwrap_or(&c_lower);
            let score = if c_lower == q_lower {
                1000
            } else if c_lower.contains(&q_lower) || q_lower.contains(&c_lower) {
                500 - (cand.len() as i32)
            } else {
                // Token overlap or short-name subsequence match (e.g. `Rn` -> `Run`)
                let mut hits = 0i32;
                for tok in q_lower.split(|c: char| !c.is_alphanumeric()) {
                    if tok.len() >= 2 && c_lower.contains(tok) {
                        hits += 50;
                    }
                }
                if hits > 0 {
                    hits - (cand.len() as i32 / 8)
                } else if q_lower.len() >= 2 && is_subsequence(&q_lower, short) {
                    200 - (short.len() as i32)
                } else {
                    -(cand.len() as i32)
                }
            };
            (score, cand)
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    let mut out = Vec::new();
    for (score, c) in scored {
        if require_match && score <= 0 {
            continue;
        }
        if !out.iter().any(|x| x == c) {
            out.push(c.to_owned());
            if out.len() >= 5 {
                break;
            }
        }
    }
    out
}

// ===========================================================================
// JSON / JSONC
// ===========================================================================

#[derive(Debug, Clone)]
struct JsonNode {
    start_line: usize,
    end_line: usize,
    kind: JsonKind,
}

#[derive(Debug, Clone)]
enum JsonKind {
    Object(Vec<JsonMember>),
    Array(Vec<JsonNode>),
    Scalar(String),
}

#[derive(Debug, Clone)]
struct JsonMember {
    key: String,
    start_line: usize,
    end_line: usize,
    value: JsonNode,
}

fn skip_json_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() {
        let b = bytes[pos];
        if b.is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        if b == b'/' && pos + 1 < bytes.len() && (bytes[pos + 1] == b'/' || bytes[pos + 1] == b'*')
        {
            if let Some(next) = skip_string_or_comment(bytes, pos, LexLang::Json) {
                pos = next;
                continue;
            }
        }
        break;
    }
    pos
}

fn parse_json_string(src: &str, pos: usize) -> Result<(String, usize), String> {
    let bytes = src.as_bytes();
    if bytes.get(pos) != Some(&b'"') {
        return Err(format!("expected JSON string at byte {pos}"));
    }
    let end = skip_string_or_comment(bytes, pos, LexLang::Json)
        .ok_or_else(|| format!("unterminated JSON string at byte {pos}"))?;
    let raw = &src[pos..end];
    let decoded = serde_json::from_str::<String>(raw).unwrap_or_else(|_| {
        raw.trim_start_matches('"')
            .trim_end_matches('"')
            .to_owned()
    });
    Ok((decoded, end))
}

fn parse_json_tree(src: &str, start: usize, idx: &LineIndex) -> Result<JsonNode, String> {
    let pos = skip_json_ws(src.as_bytes(), start);
    if pos >= src.len() {
        return Err("empty JSON document".to_owned());
    }
    let (node, _) = parse_json_value(src, pos, idx, 0)?;
    Ok(node)
}

fn parse_json_value(
    src: &str,
    pos: usize,
    idx: &LineIndex,
    depth: usize,
) -> Result<(JsonNode, usize), String> {
    if depth > 256 {
        return Err("JSON nesting exceeds maximum depth (256)".to_owned());
    }
    let bytes = src.as_bytes();
    let pos = skip_json_ws(bytes, pos);
    let b = *bytes.get(pos).ok_or_else(|| "unexpected EOF in JSON".to_owned())?;
    let start_line = idx.line_of(pos);

    match b {
        b'{' => {
            let mut i = skip_json_ws(bytes, pos + 1);
            let mut members = Vec::new();
            while i < bytes.len() && bytes[i] != b'}' {
                if bytes[i] == b',' {
                    i = skip_json_ws(bytes, i + 1);
                    continue;
                }
                if bytes[i] != b'"' {
                    return Err(format!(
                        "expected JSON object key at line {}",
                        idx.line_of(i)
                    ));
                }
                let key_line = idx.line_of(i);
                let (key, after_key) = parse_json_string(src, i)?;
                i = skip_json_ws(bytes, after_key);
                if bytes.get(i) != Some(&b':') {
                    return Err(format!("expected `:` after key `{key}` at line {}", idx.line_of(i)));
                }
                let (val, after_val) = parse_json_value(src, i + 1, idx, depth + 1)?;
                let end_line = val.end_line;
                members.push(JsonMember {
                    key,
                    start_line: key_line,
                    end_line,
                    value: val,
                });
                i = skip_json_ws(bytes, after_val);
                if bytes.get(i) == Some(&b',') {
                    i = skip_json_ws(bytes, i + 1);
                }
            }
            if bytes.get(i) != Some(&b'}') {
                return Err(format!("unclosed JSON object opened at line {start_line}"));
            }
            let end_line = idx.line_of(i);
            Ok((
                JsonNode {
                    start_line,
                    end_line,
                    kind: JsonKind::Object(members),
                },
                i + 1,
            ))
        }
        b'[' => {
            let mut i = skip_json_ws(bytes, pos + 1);
            let mut elems = Vec::new();
            while i < bytes.len() && bytes[i] != b']' {
                if bytes[i] == b',' {
                    i = skip_json_ws(bytes, i + 1);
                    continue;
                }
                let (val, after_val) = parse_json_value(src, i, idx, depth + 1)?;
                elems.push(val);
                i = skip_json_ws(bytes, after_val);
                if bytes.get(i) == Some(&b',') {
                    i = skip_json_ws(bytes, i + 1);
                }
            }
            if bytes.get(i) != Some(&b']') {
                return Err(format!("unclosed JSON array opened at line {start_line}"));
            }
            let end_line = idx.line_of(i);
            Ok((
                JsonNode {
                    start_line,
                    end_line,
                    kind: JsonKind::Array(elems),
                },
                i + 1,
            ))
        }
        b'"' => {
            let (s, end) = parse_json_string(src, pos)?;
            let preview = format!("\"{}\"", normalize_signature(&s, 56));
            Ok((
                JsonNode {
                    start_line,
                    end_line: idx.line_of(end.saturating_sub(1)),
                    kind: JsonKind::Scalar(preview),
                },
                end,
            ))
        }
        _ => {
            let mut i = pos;
            while i < bytes.len()
                && !bytes[i].is_ascii_whitespace()
                && !matches!(bytes[i], b',' | b'}' | b']')
            {
                i += 1;
            }
            let raw = src[pos..i].trim().to_owned();
            if raw.is_empty() {
                return Err(format!("unexpected token at line {start_line}"));
            }
            Ok((
                JsonNode {
                    start_line,
                    end_line: idx.line_of(i.saturating_sub(1)),
                    kind: JsonKind::Scalar(normalize_signature(&raw, 60)),
                },
                i,
            ))
        }
    }
}

fn summarize_json_node(node: &JsonNode) -> String {
    match &node.kind {
        JsonKind::Object(members) => format!("{{object, {} keys}}", members.len()),
        JsonKind::Array(elems) => {
            let sample = elems.first().and_then(|first| match &first.kind {
                JsonKind::Object(m) if !m.is_empty() => {
                    let keys: Vec<&str> = m.iter().take(5).map(|x| x.key.as_str()).collect();
                    let suffix = if m.len() > 5 { ", ..." } else { "" };
                    Some(format!(", sample={{{}{}}}", keys.join(", "), suffix))
                }
                _ => None,
            });
            format!(
                "[array, {} items{}]",
                elems.len(),
                sample.unwrap_or_default()
            )
        }
        JsonKind::Scalar(s) => s.clone(),
    }
}

fn json_kind_label(node: &JsonNode) -> &'static str {
    match &node.kind {
        JsonKind::Object(_) => "object",
        JsonKind::Array(_) => "array",
        JsonKind::Scalar(_) => "key",
    }
}

fn json_node_to_items(node: &JsonNode, prefix: &str, depth: usize) -> Vec<OutlineItem> {
    match &node.kind {
        JsonKind::Object(members) => members
            .iter()
            .map(|m| {
                let qname = if prefix.is_empty() {
                    format!("/{}", escape_pointer(&m.key))
                } else {
                    format!("{prefix}/{}", escape_pointer(&m.key))
                };
                let summary = summarize_json_node(&m.value);
                let children = json_node_to_items(&m.value, &qname, depth + 1);
                OutlineItem {
                    kind: json_kind_label(&m.value).to_owned(),
                    name: m.key.clone(),
                    qualified_name: qname,
                    signature: format!("{}: {summary}", m.key),
                    start_line: m.start_line,
                    end_line: m.end_line,
                    depth,
                    children,
                }
            })
            .collect(),
        JsonKind::Array(elems) => elems
            .iter()
            .take(MAX_ARRAY_OUTLINE_CHILDREN)
            .enumerate()
            .filter(|(_, el)| !matches!(el.kind, JsonKind::Scalar(_)))
            .map(|(i, el)| {
                let name = format!("[{i}]");
                let qname = if prefix.is_empty() {
                    format!("/{i}")
                } else {
                    format!("{prefix}/{i}")
                };
                let summary = summarize_json_node(el);
                let children = json_node_to_items(el, &qname, depth + 1);
                OutlineItem {
                    kind: json_kind_label(el).to_owned(),
                    name: name.clone(),
                    qualified_name: qname,
                    signature: format!("{name}: {summary}"),
                    start_line: el.start_line,
                    end_line: el.end_line,
                    depth,
                    children,
                }
            })
            .collect(),
        JsonKind::Scalar(_) => Vec::new(),
    }
}

fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn resolve_json_selector(
    src: &str,
    start: usize,
    idx: &LineIndex,
    selector: &str,
) -> Result<Vec<ResolvedRange>, String> {
    let root = parse_json_tree(src, start, idx)?;
    let segs = parse_data_path(selector)?;
    let mut cur = &root;
    let mut start_line = root.start_line;
    let mut end_line = root.end_line;

    for seg in &segs {
        match (&cur.kind, seg) {
            (JsonKind::Object(members), PathSeg::Key(k)) => {
                if let Some(m) = members.iter().find(|m| m.key == *k) {
                    cur = &m.value;
                    start_line = m.start_line;
                    end_line = m.end_line;
                } else {
                    let keys = members.iter().map(|m| m.key.as_str());
                    let sugg = suggest_candidates(k, keys, false);
                    return Err(format!(
                        "JSON key `{k}` not found in selector `{selector}`; available: {}",
                        if sugg.is_empty() {
                            "<none>".to_owned()
                        } else {
                            sugg.join(", ")
                        }
                    ));
                }
            }
            (JsonKind::Array(elems), PathSeg::Index(i)) => {
                if let Some(el) = elems.get(*i) {
                    cur = el;
                    start_line = el.start_line;
                    end_line = el.end_line;
                } else {
                    return Err(format!(
                        "JSON array index [{i}] out of bounds (len {}) in `{selector}`",
                        elems.len()
                    ));
                }
            }
            (JsonKind::Array(elems), PathSeg::Key(k)) => {
                if let Ok(i) = k.parse::<usize>() {
                    if let Some(el) = elems.get(i) {
                        cur = el;
                        start_line = el.start_line;
                        end_line = el.end_line;
                        continue;
                    }
                    return Err(format!(
                        "JSON array index [{i}] out of bounds (len {}) in `{selector}`",
                        elems.len()
                    ));
                }
                return Err(format!(
                    "cannot select key `{k}` on JSON array in `{selector}` (use numeric index)"
                ));
            }
            (JsonKind::Object(_), PathSeg::Index(i)) => {
                return Err(format!(
                    "cannot index JSON object with [{i}] in `{selector}`"
                ));
            }
            (JsonKind::Scalar(_), _) => {
                return Err(format!(
                    "cannot traverse into JSON scalar in `{selector}`"
                ));
            }
        }
    }

    Ok(vec![ResolvedRange {
        label: selector.to_owned(),
        start_line,
        end_line,
    }])
}

// ===========================================================================
// JSONL / NDJSON
// ===========================================================================

fn jsonl_shape(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            if keys.len() > 10 {
                let head: Vec<&str> = keys.into_iter().take(10).collect();
                format!("{{{}, ... (+{} keys)}}", head.join(", "), map.len() - 10)
            } else {
                format!("{{{}}}", keys.join(", "))
            }
        }
        serde_json::Value::Array(arr) => format!("[array, {} items]", arr.len()),
        serde_json::Value::String(_) => "<string>".to_owned(),
        serde_json::Value::Number(_) => "<number>".to_owned(),
        serde_json::Value::Bool(_) => "<bool>".to_owned(),
        serde_json::Value::Null => "<null>".to_owned(),
    }
}

fn parse_jsonl_outline(src: &str, idx: &LineIndex) -> Vec<OutlineItem> {
    struct ShapeGroup {
        shape: String,
        count: usize,
        first_line: usize,
        last_line: usize,
    }
    let mut order: Vec<ShapeGroup> = Vec::new();
    let mut by_shape: HashMap<String, usize> = HashMap::new();

    for ln in 1..=idx.total_lines() {
        let trimmed = idx.line_slice(src, ln).trim();
        if trimmed.is_empty() {
            continue;
        }
        let shape = match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(v) => jsonl_shape(&v),
            Err(_) => "<invalid json>".to_owned(),
        };
        if let Some(&slot) = by_shape.get(&shape) {
            let g = &mut order[slot];
            g.count += 1;
            g.last_line = ln;
        } else {
            let slot = order.len();
            by_shape.insert(shape.clone(), slot);
            order.push(ShapeGroup {
                shape,
                count: 1,
                first_line: ln,
                last_line: ln,
            });
        }
    }

    order
        .into_iter()
        .take(MAX_JSONL_SHAPES)
        .map(|g| OutlineItem {
            kind: "shape".to_owned(),
            name: g.shape.clone(),
            qualified_name: g.shape.clone(),
            signature: format!("[{}x] {}", g.count, g.shape),
            start_line: g.first_line,
            end_line: g.last_line,
            depth: 0,
            children: Vec::new(),
        })
        .collect()
}

fn json_field_matches(val: &serde_json::Value, key_path: &str, expected: &str) -> bool {
    let mut cur = val;
    for part in key_path.split('.') {
        match cur {
            serde_json::Value::Object(map) => {
                let Some(next) = map.get(part) else {
                    return false;
                };
                cur = next;
            }
            serde_json::Value::Array(arr) => {
                let Ok(i) = part.parse::<usize>() else {
                    return false;
                };
                let Some(next) = arr.get(i) else {
                    return false;
                };
                cur = next;
            }
            _ => return false,
        }
    }
    let clean_expected = expected
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(expected);
    match cur {
        serde_json::Value::String(s) => s == clean_expected,
        serde_json::Value::Number(n) => n.to_string() == expected,
        serde_json::Value::Bool(b) => (if *b { "true" } else { "false" }) == expected,
        serde_json::Value::Null => expected == "null",
        other => serde_json::to_string(other).ok().as_deref() == Some(expected),
    }
}

fn resolve_jsonl_selector(
    src: &str,
    idx: &LineIndex,
    selector: &str,
) -> Result<Vec<ResolvedRange>, String> {
    let sel = selector.trim();
    if let Some((key, val)) = sel.split_once('=') {
        let key = key.trim();
        let val = val.trim();
        if key.is_empty() {
            return Err(format!("empty filter key in JSONL selector `{selector}`"));
        }
        let mut ranges = Vec::new();
        let mut seen_keys = BTreeSet::new();
        for ln in 1..=idx.total_lines() {
            let trimmed = idx.line_slice(src, ln).trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(obj) = parsed.as_object() {
                    for k in obj.keys().take(12) {
                        seen_keys.insert(k.clone());
                    }
                }
                if json_field_matches(&parsed, key, val) {
                    ranges.push(ResolvedRange {
                        label: sel.to_owned(),
                        start_line: ln,
                        end_line: ln,
                    });
                }
            }
        }
        if ranges.is_empty() {
            let sugg = suggest_candidates(key, seen_keys.iter().map(String::as_str), false);
            return Err(format!(
                "no JSONL lines matched `{sel}`; top keys: {}",
                if sugg.is_empty() {
                    "<none>".to_owned()
                } else {
                    sugg.join(", ")
                }
            ));
        }
        return Ok(ranges);
    }

    // `L<n>` or `<n>` or `L<a>-L<b>`
    let stripped = sel.strip_prefix('L').or_else(|| sel.strip_prefix('l')).unwrap_or(sel);
    if let Some((a, b)) = stripped.split_once('-') {
        let s = a
            .trim()
            .trim_start_matches(['L', 'l'])
            .parse::<usize>()
            .map_err(|_| format!("invalid JSONL selector `{selector}` (use L<n> or key=value)"))?;
        let e = b
            .trim()
            .trim_start_matches(['L', 'l'])
            .parse::<usize>()
            .map_err(|_| format!("invalid JSONL selector `{selector}` (use L<n> or key=value)"))?;
        if s == 0 || e < s || e > idx.total_lines() {
            return Err(format!(
                "JSONL line range {s}-{e} out of bounds (1..={})",
                idx.total_lines()
            ));
        }
        return Ok(vec![ResolvedRange {
            label: sel.to_owned(),
            start_line: s,
            end_line: e,
        }]);
    }
    if let Ok(ln) = stripped.parse::<usize>() {
        if ln == 0 || ln > idx.total_lines() {
            return Err(format!(
                "JSONL line {ln} out of bounds (1..={})",
                idx.total_lines()
            ));
        }
        return Ok(vec![ResolvedRange {
            label: format!("L{ln}"),
            start_line: ln,
            end_line: ln,
        }]);
    }
    Err(format!(
        "unsupported JSONL selector `{selector}` (use L<n>, L<a>-L<b>, or key=value)"
    ))
}

// ===========================================================================
// YAML
// ===========================================================================

#[derive(Debug, Clone)]
struct YamlNode {
    key: Option<String>, // None = sequence item
    summary: String,
    start_line: usize,
    end_line: usize,
    children: Vec<YamlNode>,
}

fn strip_yaml_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else if b == b'\'' {
            in_single = true;
        } else if b == b'"' {
            in_double = true;
        } else if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn split_yaml_mapping(trimmed: &str) -> Option<(String, &str)> {
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() || bytes[0] == b'-' {
        return None;
    }
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else if b == b'\'' {
            in_single = true;
        } else if b == b'"' {
            in_double = true;
        } else if b == b':' && (i + 1 == bytes.len() || bytes[i + 1].is_ascii_whitespace()) {
            let raw_key = trimmed[..i].trim();
            if raw_key.is_empty() {
                return None;
            }
            let key = raw_key
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| raw_key.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(raw_key)
                .to_owned();
            let val = trimmed[i + 1..].trim();
            return Some((key, val));
        }
        i += 1;
    }
    None
}

fn is_yaml_block_scalar(val: &str) -> bool {
    let v = val.trim();
    if v.is_empty() {
        return false;
    }
    let first = v.as_bytes()[0];
    if first != b'|' && first != b'>' {
        return false;
    }
    v[1..].chars().all(|c| c == '-' || c == '+' || c.is_ascii_digit())
}

fn unclosed_yaml_quote(val: &str) -> Option<u8> {
    let bytes = val.as_bytes();
    let mut i = 0usize;
    let mut in_quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match in_quote {
            Some(b'\'') => {
                if b == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        i += 2;
                        continue;
                    }
                    in_quote = None;
                }
            }
            Some(b'"') => {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    in_quote = None;
                }
            }
            None => {
                if b == b'\'' || b == b'"' {
                    in_quote = Some(b);
                } else if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    in_quote
}

fn yaml_quote_closes_on_line(line: &str, quote: u8) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut open = true;
    while i < bytes.len() {
        let b = bytes[i];
        if open {
            if quote == b'\'' && b == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                open = false;
            } else if quote == b'"' {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    open = false;
                }
            }
        } else if b == b'\'' || b == b'"' {
            // Another quote on same line reopens? Only check if same/other quote started unclosed
            return unclosed_yaml_quote(&line[i..]).is_none();
        } else if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            break;
        }
        i += 1;
    }
    !open
}

fn parse_yaml_tree(src: &str, start: usize, idx: &LineIndex) -> Vec<YamlNode> {
    struct Frame {
        indent: usize,
        node: YamlNode,
    }
    let start_line = if start > 0 { idx.line_of(start) } else { 1 };
    let mut roots = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut block_scalar_indent: Option<usize> = None;
    let mut in_quote: Option<u8> = None;
    let mut last_content_line = 0usize;

    let close_to = |stack: &mut Vec<Frame>, target_indent: usize, end_line: usize, roots: &mut Vec<YamlNode>| {
        while let Some(top) = stack.last() {
            if top.indent >= target_indent {
                let mut f = stack.pop().unwrap();
                f.node.end_line = end_line.max(f.node.start_line);
                if let Some(parent) = stack.last_mut() {
                    parent.node.children.push(f.node);
                } else {
                    roots.push(f.node);
                }
            } else {
                break;
            }
        }
    };

    for ln in start_line..=idx.total_lines() {
        let mut raw = idx.line_slice(src, ln);
        if ln == start_line && raw.starts_with('\u{FEFF}') {
            raw = &raw[3..];
        }
        let indent = raw.bytes().take_while(|&b| b == b' ').count();

        if let Some(q) = in_quote {
            last_content_line = ln;
            if yaml_quote_closes_on_line(raw, q) {
                in_quote = None;
            }
            continue;
        }

        if let Some(bs_indent) = block_scalar_indent {
            if raw.trim().is_empty() || indent > bs_indent {
                if !raw.trim().is_empty() {
                    last_content_line = ln;
                }
                continue;
            }
            block_scalar_indent = None;
        }

        let clean = strip_yaml_comment(raw).trim_end();
        let trimmed = clean.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "---" || trimmed == "..." || trimmed.starts_with("--- ") {
            close_to(&mut stack, 0, last_content_line, &mut roots);
            last_content_line = ln;
            continue;
        }

        close_to(&mut stack, indent, last_content_line, &mut roots);

        if trimmed == "-" || trimmed.starts_with("- ") {
            let after_dash = trimmed.strip_prefix("- ").unwrap_or("").trim();
            let seq_node = YamlNode {
                key: None,
                summary: normalize_signature(after_dash, 60),
                start_line: ln,
                end_line: ln,
                children: Vec::new(),
            };
            stack.push(Frame {
                indent,
                node: seq_node,
            });
            if is_yaml_block_scalar(after_dash) {
                block_scalar_indent = Some(indent);
            } else if let Some((k, v)) = split_yaml_mapping(after_dash) {
                let key_indent = indent + 2;
                let summary = if is_yaml_block_scalar(v) {
                    block_scalar_indent = Some(key_indent);
                    "<block scalar>".to_owned()
                } else {
                    in_quote = unclosed_yaml_quote(v);
                    normalize_signature(v, 60)
                };
                stack.push(Frame {
                    indent: key_indent,
                    node: YamlNode {
                        key: Some(k),
                        summary,
                        start_line: ln,
                        end_line: ln,
                        children: Vec::new(),
                    },
                });
            } else {
                in_quote = unclosed_yaml_quote(after_dash);
            }
            last_content_line = ln;
            continue;
        }

        if let Some((k, v)) = split_yaml_mapping(trimmed) {
            let summary = if is_yaml_block_scalar(v) {
                block_scalar_indent = Some(indent);
                "<block scalar>".to_owned()
            } else {
                in_quote = unclosed_yaml_quote(v);
                normalize_signature(v, 60)
            };
            stack.push(Frame {
                indent,
                node: YamlNode {
                    key: Some(k),
                    summary,
                    start_line: ln,
                    end_line: ln,
                    children: Vec::new(),
                },
            });
        } else {
            in_quote = unclosed_yaml_quote(trimmed);
        }
        last_content_line = ln;
    }

    close_to(&mut stack, 0, last_content_line, &mut roots);
    roots
}

fn yaml_nodes_to_items(nodes: &[YamlNode], prefix: &str, depth: usize) -> Vec<OutlineItem> {
    let mut out = Vec::new();
    let mut seq_nums = 0usize..;
    for n in nodes {
        let Some(k) = &n.key else {
            let seq_idx = seq_nums.next().unwrap_or(0);
            if seq_idx < MAX_ARRAY_OUTLINE_CHILDREN && !n.children.is_empty() {
                let name = format!("[{seq_idx}]");
                let qname = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                let children = yaml_nodes_to_items(&n.children, &qname, depth + 1);
                out.push(OutlineItem {
                    kind: "item".to_owned(),
                    name: name.clone(),
                    qualified_name: qname,
                    signature: name,
                    start_line: n.start_line,
                    end_line: n.end_line,
                    depth,
                    children,
                });
            }
            continue;
        };

        let qname = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        let is_seq = n.summary.is_empty() && n.children.iter().any(|c| c.key.is_none());
        let is_map = n.summary.is_empty() && n.children.iter().any(|c| c.key.is_some());
        let kind = if is_seq {
            "array"
        } else if is_map {
            "object"
        } else {
            "key"
        };
        let sig = if is_seq {
            format!("{k}: [seq, {} items]", n.children.len())
        } else if is_map {
            format!("{k}: {{map, {} keys}}", n.children.len())
        } else if n.summary.is_empty() {
            format!("{k}:")
        } else {
            format!("{k}: {}", n.summary)
        };
        let children = yaml_nodes_to_items(&n.children, &qname, depth + 1);
        out.push(OutlineItem {
            kind: kind.to_owned(),
            name: k.clone(),
            qualified_name: qname,
            signature: sig,
            start_line: n.start_line,
            end_line: n.end_line,
            depth,
            children,
        });
    }
    out
}

fn resolve_yaml_selector(
    src: &str,
    start: usize,
    idx: &LineIndex,
    selector: &str,
) -> Result<Vec<ResolvedRange>, String> {
    let roots = parse_yaml_tree(src, start, idx);
    let segs = parse_data_path(selector)?;
    if segs.is_empty() {
        return Ok(vec![ResolvedRange {
            label: selector.to_owned(),
            start_line: 1,
            end_line: idx.total_lines().max(1),
        }]);
    }
    let mut cur_list: &[YamlNode] = &roots;
    let mut matched: Option<&YamlNode> = None;

    for seg in &segs {
        match seg {
            PathSeg::Key(k) => {
                // Support numeric key on sequence items too (JSON Pointer `/steps/0`)
                if cur_list.iter().all(|n| n.key.is_none()) && !cur_list.is_empty() {
                    if let Ok(i) = k.parse::<usize>() {
                        let node = cur_list.get(i).ok_or_else(|| {
                            format!(
                                "YAML sequence index [{i}] out of bounds (len {}) in `{selector}`",
                                cur_list.len()
                            )
                        })?;
                        matched = Some(node);
                        cur_list = &node.children;
                        continue;
                    }
                }
                if let Some(node) = cur_list.iter().find(|n| n.key.as_deref() == Some(k.as_str())) {
                    matched = Some(node);
                    cur_list = &node.children;
                } else {
                    let keys = cur_list.iter().filter_map(|n| n.key.as_deref());
                    let sugg = suggest_candidates(k, keys, false);
                    return Err(format!(
                        "YAML key `{k}` not found in `{selector}`; available: {}",
                        if sugg.is_empty() {
                            "<none>".to_owned()
                        } else {
                            sugg.join(", ")
                        }
                    ));
                }
            }
            PathSeg::Index(i) => {
                let seq: Vec<&YamlNode> = cur_list.iter().filter(|n| n.key.is_none()).collect();
                let node = seq.get(*i).copied().ok_or_else(|| {
                    format!(
                        "YAML sequence index [{i}] out of bounds (len {}) in `{selector}`",
                        seq.len()
                    )
                })?;
                matched = Some(node);
                cur_list = &node.children;
            }
        }
    }

    let node = matched.ok_or_else(|| format!("selector `{selector}` matched nothing"))?;
    Ok(vec![ResolvedRange {
        label: selector.to_owned(),
        start_line: node.start_line,
        end_line: node.end_line,
    }])
}

// ===========================================================================
// TOML
// ===========================================================================

fn split_toml_key_paths(raw: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for ch in raw.chars() {
        if let Some(q) = in_quote {
            if q == '"' && !escaped && ch == '\\' {
                escaped = true;
                continue;
            }
            if !escaped && ch == q {
                in_quote = None;
            } else {
                cur.push(ch);
            }
            escaped = false;
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch == '.' {
            let trimmed = cur.trim().to_owned();
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    let trimmed = cur.trim().to_owned();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }
    parts
}

fn strip_toml_comment_outside_strings(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else if b == b'\'' {
            in_single = true;
        } else if b == b'"' {
            in_double = true;
        } else if b == b'#' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn parse_toml_outline(src: &str, start: usize, idx: &LineIndex) -> Vec<OutlineItem> {
    let total = idx.total_lines();
    if total == 0 {
        return Vec::new();
    }
    // Track multiline string/bracket state cleanly across lines
    let start_line = if start > 0 { idx.line_of(start) } else { 1 };
    let mut items: Vec<OutlineItem> = Vec::new();
    let mut current_table: Option<OutlineItem> = None;
    let mut array_counts: HashMap<String, usize> = HashMap::new();
    let mut in_multiline: Option<&'static str> = None;
    let mut bracket_depth = 0usize;
    let mut last_content_line = 0usize;

    let flush_table = |cur: &mut Option<OutlineItem>, end_line: usize, items: &mut Vec<OutlineItem>| {
        if let Some(mut tbl) = cur.take() {
            tbl.end_line = end_line.max(tbl.start_line);
            items.push(tbl);
        }
    };

    let mut ln = start_line;
    while ln <= total {
        let mut raw = idx.line_slice(src, ln);
        if ln == start_line && raw.starts_with('\u{FEFF}') {
            raw = &raw[3..];
        }

        if let Some(delim) = in_multiline {
            if let Some(item) = current_table
                .as_mut()
                .and_then(|t| t.children.last_mut())
                .or_else(|| items.last_mut())
            {
                item.end_line = ln;
            }
            last_content_line = ln;
            if let Some(pos) = find_toml_triple_close(raw, delim) {
                in_multiline = None;
                update_toml_brackets(
                    strip_toml_comment_outside_strings(&raw[pos + 3..]),
                    &mut bracket_depth,
                );
            }
            ln += 1;
            continue;
        }

        let code = strip_toml_comment_outside_strings(raw).trim();
        if code.is_empty() {
            ln += 1;
            continue;
        }

        if bracket_depth > 0 {
            update_toml_brackets(code, &mut bracket_depth);
            if let Some(last_item) = current_table
                .as_mut()
                .and_then(|t| t.children.last_mut())
                .or_else(|| items.last_mut())
            {
                last_item.end_line = ln;
            }
            last_content_line = ln;
            ln += 1;
            continue;
        }

        if code.starts_with("[[") && code.ends_with("]]") {
            flush_table(&mut current_table, last_content_line, &mut items);
            let name = code[2..code.len() - 2].trim();
            let qparts = split_toml_key_paths(name);
            let joined = qparts.join(".");
            let count = array_counts.entry(joined.clone()).or_insert(0);
            let qname = format!("{joined}[{}]", *count);
            *count += 1;
            current_table = Some(OutlineItem {
                kind: "array_table".to_owned(),
                name: joined,
                qualified_name: qname,
                signature: normalize_signature(code, MAX_SIG_CHARS),
                start_line: ln,
                end_line: ln,
                depth: 0,
                children: Vec::new(),
            });
            last_content_line = ln;
            ln += 1;
            continue;
        }

        if code.starts_with('[') && code.ends_with(']') {
            flush_table(&mut current_table, last_content_line, &mut items);
            let name = code[1..code.len() - 1].trim();
            let joined = split_toml_key_paths(name).join(".");
            current_table = Some(OutlineItem {
                kind: "table".to_owned(),
                name: joined.clone(),
                qualified_name: joined,
                signature: normalize_signature(code, MAX_SIG_CHARS),
                start_line: ln,
                end_line: ln,
                depth: 0,
                children: Vec::new(),
            });
            last_content_line = ln;
            ln += 1;
            continue;
        }

        if let Some((lhs, rhs)) = split_toml_kv(code) {
            let key_parts = split_toml_key_paths(lhs);
            let key_name = key_parts.join(".");
            let rhs_trim = rhs.trim();
            if rhs_trim.starts_with("\"\"\"")
                && find_toml_triple_close(&rhs_trim[3..], "\"\"\"").is_none()
            {
                in_multiline = Some("\"\"\"");
            } else if rhs_trim.starts_with("'''")
                && find_toml_triple_close(&rhs_trim[3..], "'''").is_none()
            {
                in_multiline = Some("'''");
            } else {
                update_toml_brackets(rhs_trim, &mut bracket_depth);
            }
            let prefix = current_table
                .as_ref()
                .map(|t| t.qualified_name.as_str())
                .unwrap_or("");
            let qname = if prefix.is_empty() {
                key_name.clone()
            } else {
                format!("{prefix}.{key_name}")
            };
            let item = OutlineItem {
                kind: "key".to_owned(),
                name: key_name.clone(),
                qualified_name: qname,
                signature: normalize_signature(&format!("{key_name} = {rhs_trim}"), MAX_SIG_CHARS),
                start_line: ln,
                end_line: ln,
                depth: if current_table.is_some() { 1 } else { 0 },
                children: Vec::new(),
            };
            if let Some(tbl) = current_table.as_mut() {
                tbl.children.push(item);
            } else {
                items.push(item);
            }
        }

        last_content_line = ln;
        ln += 1;
    }

    flush_table(&mut current_table, last_content_line, &mut items);
    items
}

fn find_toml_triple_close(s: &str, delim: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let delim_bytes = delim.as_bytes();
    let is_double = delim == "\"\"\"";
    let mut i = 0usize;
    while i < bytes.len() {
        if is_double && bytes[i] == b'\\' {
            i += 1;
            if let Some(ch) = s.get(i..).and_then(|rest| rest.chars().next()) {
                i += ch.len_utf8();
            } else {
                break;
            }
            continue;
        }
        if bytes[i..].starts_with(delim_bytes) {
            return Some(i);
        }
        if let Some(ch) = s.get(i..).and_then(|rest| rest.chars().next()) {
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }
    None
}

fn split_toml_kv(code: &str) -> Option<(&str, &str)> {
    let bytes = code.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else if b == b'\'' {
            in_single = true;
        } else if b == b'"' {
            in_double = true;
        } else if b == b'=' {
            return Some((code[..i].trim(), code[i + 1..].trim()));
        }
        i += 1;
    }
    None
}

fn update_toml_brackets(s: &str, depth: &mut usize) {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
        } else if b == b'\'' {
            in_single = true;
        } else if b == b'"' {
            in_double = true;
        } else if b == b'[' || b == b'{' {
            *depth += 1;
        } else if b == b']' || b == b'}' {
            *depth = depth.saturating_sub(1);
        }
        i += 1;
    }
}

fn resolve_toml_selector(
    src: &str,
    start: usize,
    idx: &LineIndex,
    selector: &str,
) -> Result<Vec<ResolvedRange>, String> {
    let items = parse_toml_outline(src, start, idx);
    let segs = parse_data_path(selector)?;
    let target = segs_to_toml_dotted(&segs);
    let flat = super::flatten_items(&items);

    let mut matches: Vec<ResolvedRange> = flat
        .iter()
        .filter(|it| it.qualified_name == target || it.name == target)
        .map(|it| ResolvedRange {
            label: it.qualified_name.clone(),
            start_line: it.start_line,
            end_line: it.end_line,
        })
        .collect();

    if matches.is_empty() {
        // Also try matching table prefix for nested tables like `[profile.release]` when asked `profile`
        let prefix_dot = format!("{target}.");
        matches = flat
            .iter()
            .filter(|it| {
                it.kind != "key" && it.qualified_name.starts_with(&prefix_dot)
            })
            .map(|it| ResolvedRange {
                label: it.qualified_name.clone(),
                start_line: it.start_line,
                end_line: it.end_line,
            })
            .collect();
    }

    if matches.is_empty() {
        let sugg = suggest_candidates(
            &target,
            flat.iter().map(|it| it.qualified_name.as_str()),
            false,
        );
        return Err(format!(
            "TOML selector `{selector}` not found; available: {}",
            if sugg.is_empty() {
                "<none>".to_owned()
            } else {
                sugg.join(", ")
            }
        ));
    }
    Ok(matches)
}

fn segs_to_toml_dotted(segs: &[PathSeg]) -> String {
    let mut out = String::new();
    for seg in segs {
        match seg {
            PathSeg::Key(k) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(k);
            }
            PathSeg::Index(i) => {
                out.push_str(&format!("[{i}]"));
            }
        }
    }
    out
}

// ===========================================================================
// Markdown
// ===========================================================================

fn markdown_slug(title: &str) -> String {
    let mut slug = String::new();
    let mut prev_dash = false;
    for ch in title.trim().chars() {
        if ch.is_alphanumeric() {
            for lc in ch.to_lowercase() {
                slug.push(lc);
            }
            prev_dash = false;
        } else if (ch == ' ' || ch == '-' || ch == '_') && !prev_dash && !slug.is_empty() {
            slug.push('-');
            prev_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

fn parse_atx_heading(line: &str) -> Option<(usize, String)> {
    let trimmed = line.trim_start_matches(' ');
    // ATX allows up to 3 leading spaces
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
    if !(1..=6).contains(&hashes) {
        return None;
    }
    let rest = &trimmed[hashes..];
    if !rest.is_empty() && !rest.starts_with(' ') && !rest.starts_with('\t') {
        return None;
    }
    let mut title = rest.trim();
    // Strip optional closing `#` sequence preceded by whitespace
    if let Some(stripped) = title.strip_suffix(|c: char| c == '#') {
        let candidate = stripped.trim_end_matches('#');
        if candidate.is_empty() || candidate.ends_with(' ') || candidate.ends_with('\t') {
            title = candidate.trim();
        }
    }
    if title.is_empty() {
        return None;
    }
    Some((hashes, title.to_owned()))
}

fn parse_fence_open(line: &str) -> Option<(u8, usize)> {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let first = *trimmed.as_bytes().first()?;
    if first != b'`' && first != b'~' {
        return None;
    }
    let count = trimmed.bytes().take_while(|&b| b == first).count();
    if count < 3 {
        return None;
    }
    if first == b'`' && trimmed[count..].contains('`') {
        return None; // inline code span, not a fenced block
    }
    Some((first, count))
}

fn is_fence_close(line: &str, ch: u8, min_len: usize) -> bool {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 {
        return false;
    }
    let count = trimmed.bytes().take_while(|&b| b == ch).count();
    count >= min_len && trimmed[count..].trim().is_empty()
}

fn is_setext_underline(line: &str) -> Option<usize> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.bytes().all(|b| b == b'=') {
        return Some(1);
    }
    if trimmed.len() >= 2 && trimmed.bytes().all(|b| b == b'-') {
        return Some(2);
    }
    None
}

fn parse_markdown_outline(src: &str, start: usize, idx: &LineIndex) -> Vec<OutlineItem> {
    let total = idx.total_lines();
    if total == 0 {
        return Vec::new();
    }
    let start_line = if start > 0 { idx.line_of(start) } else { 1 };
    let mut ln = start_line;

    // Skip optional YAML frontmatter on line 1
    if ln == 1 && idx.line_slice(src, 1).trim() == "---" {
        let mut probe = 2usize;
        while probe <= total {
            let t = idx.line_slice(src, probe).trim();
            if t == "---" || t == "..." {
                ln = probe + 1;
                break;
            }
            probe += 1;
        }
    }

    struct RawHeading {
        level: usize,
        title: String,
        line: usize,
    }
    let mut headings = Vec::new();
    let mut active_fence: Option<(u8, usize)> = None;
    let mut prev_plain_line: Option<(usize, String)> = None;

    while ln <= total {
        let raw = idx.line_slice(src, ln);
        if let Some((fch, flen)) = active_fence {
            if is_fence_close(raw, fch, flen) {
                active_fence = None;
            }
            prev_plain_line = None;
            ln += 1;
            continue;
        }
        if let Some(fence) = parse_fence_open(raw) {
            active_fence = Some(fence);
            prev_plain_line = None;
            ln += 1;
            continue;
        }
        if let Some((level, title)) = parse_atx_heading(raw) {
            headings.push(RawHeading {
                level,
                title,
                line: ln,
            });
            prev_plain_line = None;
            ln += 1;
            continue;
        }
        if let Some(level) = is_setext_underline(raw) {
            if let Some((title_ln, title)) = prev_plain_line.take() {
                headings.push(RawHeading {
                    level,
                    title,
                    line: title_ln,
                });
                ln += 1;
                continue;
            }
        }
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('>')
            || trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with("+ ")
        {
            prev_plain_line = None;
        } else {
            prev_plain_line = Some((ln, trimmed.to_owned()));
        }
        ln += 1;
    }

    // Build tree with exact section end_lines
    struct MdFrame {
        level: usize,
        item: OutlineItem,
    }
    let mut stack: Vec<MdFrame> = Vec::new();
    let mut roots: Vec<OutlineItem> = Vec::new();

    let close_for = |stack: &mut Vec<MdFrame>, level: usize, end_line: usize, roots: &mut Vec<OutlineItem>| {
        while let Some(top) = stack.last() {
            if top.level >= level {
                let mut f = stack.pop().unwrap();
                f.item.end_line = end_line.max(f.item.start_line);
                if let Some(parent) = stack.last_mut() {
                    parent.item.children.push(f.item);
                } else {
                    roots.push(f.item);
                }
            } else {
                break;
            }
        }
    };

    for h in headings {
        let section_close = h.line.saturating_sub(1);
        close_for(&mut stack, h.level, section_close, &mut roots);
        let qname = if let Some(parent) = stack.last() {
            format!("{} > {}", parent.item.qualified_name, h.title)
        } else {
            h.title.clone()
        };
        let depth = stack.len();
        let sig = format!("{} {}", "#".repeat(h.level), normalize_signature(&h.title, MAX_SIG_CHARS));
        stack.push(MdFrame {
            level: h.level,
            item: OutlineItem {
                kind: "heading".to_owned(),
                name: h.title,
                qualified_name: qname,
                signature: sig,
                start_line: h.line,
                end_line: total,
                depth,
                children: Vec::new(),
            },
        });
    }

    close_for(&mut stack, 0, total, &mut roots);
    roots
}

fn resolve_markdown_selector(
    src: &str,
    start: usize,
    idx: &LineIndex,
    selector: &str,
) -> Result<Vec<ResolvedRange>, String> {
    let items = parse_markdown_outline(src, start, idx);
    let flat = super::flatten_items(&items);
    let sel = selector.trim();
    let sel_no_hash = sel.trim_start_matches('#').trim();
    let norm_path = |s: &str| -> Vec<String> {
        s.split('>')
            .flat_map(|part| part.split('/'))
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    };

    // 1. Hierarchical exact or case-insensitive path (`Hosts > Verification` or `Hosts/Verification`)
    let wanted_parts = norm_path(sel_no_hash);
    if wanted_parts.len() > 1 {
        let mut exact = Vec::new();
        let mut ci = Vec::new();
        let mut slug = Vec::new();
        for it in &flat {
            let item_parts = norm_path(&it.qualified_name);
            if item_parts == wanted_parts {
                exact.push(*it);
            } else if item_parts.len() == wanted_parts.len()
                && item_parts
                    .iter()
                    .zip(&wanted_parts)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                ci.push(*it);
            } else if item_parts.len() == wanted_parts.len()
                && item_parts
                    .iter()
                    .zip(&wanted_parts)
                    .all(|(a, b)| markdown_slug(a) == markdown_slug(b))
            {
                slug.push(*it);
            }
        }
        let chosen = if !exact.is_empty() {
            exact
        } else if !ci.is_empty() {
            ci
        } else {
            slug
        };
        if !chosen.is_empty() {
            return Ok(chosen
                .into_iter()
                .map(|it| ResolvedRange {
                    label: it.qualified_name.clone(),
                    start_line: it.start_line,
                    end_line: it.end_line,
                })
                .collect());
        }
    }

    // 2. Exact title, case-insensitive title, or slug match
    let sel_slug = markdown_slug(sel_no_hash);
    let mut exact = Vec::new();
    let mut ci = Vec::new();
    let mut slug = Vec::new();
    for it in &flat {
        if it.name == sel_no_hash {
            exact.push(*it);
        } else if it.name.eq_ignore_ascii_case(sel_no_hash) {
            ci.push(*it);
        } else if !sel_slug.is_empty() && markdown_slug(&it.name) == sel_slug {
            slug.push(*it);
        }
    }
    let chosen = if !exact.is_empty() {
        exact
    } else if !ci.is_empty() {
        ci
    } else {
        slug
    };
    if !chosen.is_empty() {
        return Ok(chosen
            .into_iter()
            .map(|it| ResolvedRange {
                label: it.qualified_name.clone(),
                start_line: it.start_line,
                end_line: it.end_line,
            })
            .collect());
    }

    let sugg = suggest_candidates(
        sel_no_hash,
        flat.iter().map(|it| it.qualified_name.as_str()),
        false,
    );
    Err(format!(
        "Markdown heading `{selector}` not found; available: {}",
        if sugg.is_empty() {
            "<none>".to_owned()
        } else {
            sugg.join(", ")
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outline::outline_source;

    #[test]
    fn jsonc_outline_and_rfc6901_pointer_resolution() {
        let src = "{\n  // comment\n  \"a/b\": {\n    \"items\": [\n      {\"id\": 1, \"name~x\": \"ok\"},\n      {\"id\": 2, \"name~x\": \"two\"}\n    ]\n  }\n}\n";
        let idx = LineIndex::new(src);
        let doc = outline_source("cfg.jsonc", src, Lang::Json, &OutlineOptions::default());
        assert_eq!(doc.items[0].name, "a/b");
        assert_eq!(doc.items[0].start_line, 3);
        assert_eq!(doc.items[0].end_line, 8);
        assert!(doc.items[0].children[0].signature.contains("sample={id, name~x}"));

        let r1 = resolve_structured_selector(src, &idx, Lang::Json, "/a~1b/items/1/name~0x").unwrap();
        assert_eq!(r1[0].start_line, 6);
        assert_eq!(r1[0].end_line, 6);

        let r2 = resolve_structured_selector(src, &idx, Lang::Json, "$.a/b").unwrap();
        assert_eq!((r2[0].start_line, r2[0].end_line), (3, 8));
    }

    #[test]
    fn jsonl_groups_shapes_and_filters_by_key_value() {
        let src = "{\"type\":\"start\",\"id\":1}\n{\"type\":\"msg\",\"text\":\"hi\"}\n{\"type\":\"msg\",\"text\":\"bye\"}\n{\"type\":\"end\",\"ok\":true}\n";
        let idx = LineIndex::new(src);
        let doc = outline_source("s.jsonl", src, Lang::Jsonl, &OutlineOptions::default());
        assert_eq!(doc.items.len(), 3);
        assert_eq!(doc.items[1].signature, "[2x] {text, type}");
        assert_eq!((doc.items[1].start_line, doc.items[1].end_line), (2, 3));

        let matches = resolve_structured_selector(src, &idx, Lang::Jsonl, "type=msg").unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!((matches[0].start_line, matches[1].start_line), (2, 3));
    }

    #[test]
    fn yaml_ignores_block_scalars_and_resolves_paths() {
        let src = "name: check\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: test\n        run: |\n          echo \"fake_key: 123\"\n          # not a yaml key\n      - name: lint\n        run: echo ok\n";
        let idx = LineIndex::new(src);
        let doc = outline_source("ci.yml", src, Lang::Yaml, &OutlineOptions::default());
        let steps = &doc.items[1].children[0].children[1];
        assert_eq!(steps.name, "steps");
        assert_eq!(steps.children.len(), 2);

        let r = resolve_structured_selector(src, &idx, Lang::Yaml, "jobs.build.steps[0].run").unwrap();
        assert_eq!(r[0].start_line, 7);
        assert_eq!(r[0].end_line, 9);

        let quoted = "root:\n  msg: \"first line\n    fake_child: should_not_split\"\n  next: 1\n";
        let q_idx = LineIndex::new(quoted);
        let q_doc = outline_source("q.yml", quoted, Lang::Yaml, &OutlineOptions::default());
        assert_eq!(q_doc.items[0].children.len(), 2);
        assert_eq!(q_doc.items[0].children[0].name, "msg");
        assert_eq!(q_doc.items[0].children[1].name, "next");
        let qr = resolve_structured_selector(quoted, &q_idx, Lang::Yaml, "root.msg").unwrap();
        assert_eq!((qr[0].start_line, qr[0].end_line), (2, 3));
    }

    #[test]
    fn toml_tables_arrays_and_multiline_strings() {
        let src = "[package]\nname = \"demo\"\n\n[[bin]]\nname = \"a\"\n\n[[bin]]\nname = \"b\"\n\n[profile.release]\nopt-level = 3\ndesc = \"\"\"\n[fake.table]\n\"\"\"\n\n[\"quoted.key\"]\nz = '''\nline1\nline2\n'''\n";
        let idx = LineIndex::new(src);
        let doc = outline_source("Cargo.toml", src, Lang::Toml, &OutlineOptions::default());
        assert_eq!(doc.items.len(), 5);
        assert_eq!(doc.items[1].qualified_name, "bin[0]");
        assert_eq!(doc.items[2].qualified_name, "bin[1]");

        let r = resolve_structured_selector(src, &idx, Lang::Toml, "profile.release").unwrap();
        assert_eq!((r[0].start_line, r[0].end_line), (10, 14));

        let r_desc = resolve_structured_selector(src, &idx, Lang::Toml, "profile.release.desc").unwrap();
        assert_eq!((r_desc[0].start_line, r_desc[0].end_line), (12, 14));

        let r_quoted = resolve_structured_selector(src, &idx, Lang::Toml, "\"quoted.key\".z").unwrap();
        assert_eq!((r_quoted[0].start_line, r_quoted[0].end_line), (17, 20));
    }

    #[test]
    fn markdown_skips_frontmatter_and_code_fences() {
        let src = "---\ntitle: Ignored\n---\n# Top\nIntro\n```bash\n# fake heading inside code\n```\n## Sub One\nBody\n### Nested\nDetails\n## Sub Two\nEnd\n";
        let idx = LineIndex::new(src);
        let doc = outline_source("README.md", src, Lang::Markdown, &OutlineOptions::default());
        assert_eq!(doc.items.len(), 1);
        assert_eq!(doc.items[0].name, "Top");
        assert_eq!((doc.items[0].start_line, doc.items[0].end_line), (4, 14));
        assert_eq!(doc.items[0].children.len(), 2);
        assert_eq!((doc.items[0].children[0].start_line, doc.items[0].children[0].end_line), (9, 12));

        let r1 = resolve_structured_selector(src, &idx, Lang::Markdown, "sub-one").unwrap();
        assert_eq!((r1[0].start_line, r1[0].end_line), (9, 12));
        let r2 = resolve_structured_selector(src, &idx, Lang::Markdown, "Top > Sub One > Nested").unwrap();
        assert_eq!((r2[0].start_line, r2[0].end_line), (11, 12));
    }
}
