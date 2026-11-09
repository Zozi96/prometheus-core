//! Brief construction (spec #43, ticket #53): the Review brief document
//! and its Delta review package, assembled from the scan's facts, plus the
//! exclusion-list validation the hook runs before dispatch.
//!
//! The builder's inputs are the neutral package only — request, contract,
//! decisions, criteria, the changed rows with their hunk index, and the
//! open findings projected by the hook. There is no input field for the
//! gate record, its path, owner evidence, method choices, or self-rating:
//! withheld by construction. `validate_review_brief` is the second line of
//! defence over any assembled document, whatever produced it: no key
//! outside the document's allowlist, and no withheld string in its content.
//!
//! Both functions are pure document transforms, mirroring the Python
//! oracle in `runtime/sureforge_hook.py` field for field. No panics cross
//! the FFI boundary: the wrappers catch unwinds and report a structured
//! error, and the hook reruns the whole call on its Python route.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

/// The brief document schema this build speaks (`BRIEF_SCHEMA` 1). The
/// Python side negotiates it before delegating, exactly as for the store.
pub const BRIEF_SCHEMA: u32 = 1;

/// `_changed_lines`' over-cap sentinel (the hook's LIGHT_MAX_LINES + 1):
/// the line count a brief reports when a changed row is unmeasurable.
const LINES_OVER_CAP: i64 = 51;

// ---------------------------------------------------------------------------
// JSON: the small strict subset a document transform needs. Objects keep
// insertion order, numbers are integers (the hook's documents carry only
// counts and line numbers), and anything else is a parse failure the
// caller turns into its fallback route.

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries.iter().find(|(name, _)| name == key).map(|(_, value)| value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(value) => Some(*value),
            _ => None,
        }
    }

    fn as_list(&self) -> Option<&Vec<Json>> {
        match self {
            Json::List(items) => Some(items),
            _ => None,
        }
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn parse(text: &str) -> Result<Json, String> {
        let mut parser = Parser { chars: text.chars().collect(), pos: 0, depth: 0 };
        let value = parser.value()?;
        parser.skip_ws();
        if parser.pos != parser.chars.len() {
            return Err("trailing data".into());
        }
        Ok(value)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > 200 {
            return Err("too deep".into());
        }
        let result = self.value_inner();
        self.depth -= 1;
        result
    }

    fn value_inner(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek().ok_or("unexpected end")? {
            '{' => {
                self.pos += 1;
                let mut entries = Vec::new();
                self.skip_ws();
                if self.peek() == Some('}') {
                    self.pos += 1;
                    return Ok(Json::Object(entries));
                }
                loop {
                    self.skip_ws();
                    let key = match self.string()? {
                        Json::Str(text) => text,
                        _ => return Err("object key".into()),
                    };
                    self.skip_ws();
                    if self.peek() != Some(':') {
                        return Err("expected ':'".into());
                    }
                    self.pos += 1;
                    let item = self.value()?;
                    entries.push((key, item));
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => self.pos += 1,
                        Some('}') => {
                            self.pos += 1;
                            return Ok(Json::Object(entries));
                        }
                        _ => return Err("expected ',' or '}'".into()),
                    }
                }
            }
            '[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(']') {
                    self.pos += 1;
                    return Ok(Json::List(items));
                }
                loop {
                    items.push(self.value()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => self.pos += 1,
                        Some(']') => {
                            self.pos += 1;
                            return Ok(Json::List(items));
                        }
                        _ => return Err("expected ',' or ']'".into()),
                    }
                }
            }
            '"' => self.string(),
            't' => self.literal("true", Json::Bool(true)),
            'f' => self.literal("false", Json::Bool(false)),
            'n' => self.literal("null", Json::Null),
            '-' | '0'..='9' => self.number(),
            _ => Err("unexpected character".into()),
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        if self.chars[self.pos..].starts_with(&word.chars().collect::<Vec<_>>()[..]) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err("bad literal".into())
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some('0'..='9')) {
            self.pos += 1;
        }
        if matches!(self.peek(), Some('.' | 'e' | 'E')) {
            return Err("non-integer number".into());
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<i64>().map(Json::Int).map_err(|_| "bad number".to_string())
    }

    fn string(&mut self) -> Result<Json, String> {
        if self.peek() != Some('"') {
            return Err("expected string".into());
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match c {
                '"' => return Ok(Json::Str(out)),
                '\\' => {
                    let esc = self.peek().ok_or("unterminated escape")?;
                    self.pos += 1;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let unit = self.hex4()?;
                            if (0xD800..0xDC00).contains(&unit) {
                                if self.peek() == Some('\\') {
                                    self.pos += 1;
                                    if self.peek() == Some('u') {
                                        self.pos += 1;
                                        let low = self.hex4()?;
                                        let combined = 0x10000
                                            + (((unit - 0xD800) as u32) << 10)
                                            + (low as u32).saturating_sub(0xDC00);
                                        out.push(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                                        continue;
                                    }
                                    return Err("lone surrogate".into());
                                }
                                return Err("lone surrogate".into());
                            }
                            if (0xDC00..0xE000).contains(&unit) {
                                return Err("lone surrogate".into());
                            }
                            out.push(char::from_u32(unit as u32).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, String> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let c = self.peek().ok_or("bad \\u escape")?;
            let digit = c.to_digit(16).ok_or("bad \\u escape")?;
            value = value * 16 + digit as u16;
            self.pos += 1;
        }
        Ok(value)
    }
}

fn dump(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(number) => out.push_str(&number.to_string()),
        Json::Str(text) => esc(text, out),
        Json::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                dump(item, out);
            }
            out.push(']');
        }
        Json::Object(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                esc(key, out);
                out.push(':');
                dump(item, out);
            }
            out.push('}');
        }
    }
}

/// JSON string escaping, the same subset the scan emitter uses.
fn esc(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn obj(entries: Vec<(&str, Json)>) -> Json {
    Json::Object(entries.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
}

fn strings(value: Option<&Json>) -> Vec<String> {
    match value.and_then(Json::as_list) {
        Some(items) => items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect(),
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Assembly: the Python oracle's rules, statement for statement.

/// The brief's label for one hunk, on `_parse_diff_files`' range rule.
fn hunk_label(hunk: &Json) -> String {
    let (old_start, old_count) = (hunk.get("old_start").and_then(Json::as_int).unwrap_or(0),
                                  hunk.get("old_count").and_then(Json::as_int).unwrap_or(0));
    let (new_start, new_count) = (hunk.get("new_start").and_then(Json::as_int).unwrap_or(0),
                                  hunk.get("new_count").and_then(Json::as_int).unwrap_or(0));
    let (start, end) = if new_count > 0 {
        (new_start, new_start + new_count - 1)
    } else if old_count > 0 {
        (old_start, old_start + old_count - 1)
    } else {
        let point = if new_start != 0 { new_start } else { old_start };
        (point.max(1), point.max(1))
    };
    let header = hunk.get("header").and_then(Json::as_str).unwrap_or("");
    let collapsed = header.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        format!("lines {start}-{end}")
    } else {
        format!("lines {start}-{end}: {collapsed}")
    }
}

fn labelled_hunk(hunk: &Json) -> Json {
    let mut entries = match hunk {
        Json::Object(entries) => entries.clone(),
        _ => Vec::new(),
    };
    entries.push(("label".to_string(), Json::Str(hunk_label(hunk))));
    Json::Object(entries)
}

/// (path, first, last) for a finding location; line fields None for a
/// path-only anchor, None overall when there is no usable location.
fn finding_anchor(location: Option<&str>) -> Option<(String, Option<i64>, Option<i64>)> {
    let text = location?.trim();
    if text.is_empty() {
        return None;
    }
    if let Some((head, tail)) = text.rsplit_once(':') {
        if !head.is_empty() {
            let tail = tail.trim();
            let mut parts = tail.splitn(2, '-');
            let first = parts.next().unwrap_or("");
            if !first.is_empty() && first.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(first) = first.parse::<i64>() {
                    match parts.next() {
                        None => return Some((head.to_string(), Some(first), Some(first))),
                        Some(second) if !second.is_empty()
                            && second.chars().all(|c| c.is_ascii_digit()) =>
                        {
                            if let Ok(last) = second.parse::<i64>() {
                                return Some((head.to_string(), Some(first), Some(last)));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Some((text.to_string(), None, None))
}

/// Whether a repair hunk answers a finding: old-range first (findings
/// locate lines in the tree they were raised against); a pure insertion
/// answers the line it follows and the lines it adds.
fn hunk_answers(hunk: &Json, anchor: &(String, Option<i64>, Option<i64>)) -> bool {
    let (first, last) = match (anchor.1, anchor.2) {
        (Some(first), Some(last)) => (first, last),
        _ => return true,
    };
    let old_start = hunk.get("old_start").and_then(Json::as_int).unwrap_or(0);
    let old_count = hunk.get("old_count").and_then(Json::as_int).unwrap_or(0);
    if old_count > 0 {
        return first <= old_start + old_count - 1 && old_start <= last;
    }
    if first <= old_start && old_start <= last {
        return true;
    }
    let new_start = hunk.get("new_start").and_then(Json::as_int).unwrap_or(0);
    let new_count = hunk.get("new_count").and_then(Json::as_int).unwrap_or(0);
    first <= new_start + new_count.max(1) - 1 && new_start <= last
}

fn delta_package(delta: &Json, findings: &[Json]) -> Json {
    let anchors: Vec<(String, Option<(String, Option<i64>, Option<i64>)>)> = findings
        .iter()
        .map(|row| {
            let id = row.get("id").and_then(Json::as_str).unwrap_or("").to_string();
            let location = row.get("location").and_then(Json::as_str);
            (id, finding_anchor(location))
        })
        .collect();
    let mut answered: Vec<String> = Vec::new();
    let mut files = Vec::new();
    if let Some(entries) = delta.get("files").and_then(Json::as_list) {
        for entry in entries {
            let path = entry.get("path").and_then(Json::as_str).unwrap_or("");
            let mut hunks = Vec::new();
            if let Some(raw) = entry.get("hunks").and_then(Json::as_list) {
                for hunk in raw {
                    let mut answers = Vec::new();
                    for (fid, anchor) in &anchors {
                        if let Some(anchor) = anchor {
                            if anchor.0 == path && hunk_answers(hunk, anchor) {
                                answers.push(Json::Str(fid.clone()));
                                if !answered.contains(fid) {
                                    answered.push(fid.clone());
                                }
                            }
                        }
                    }
                    let mut labelled = match labelled_hunk(hunk) {
                        Json::Object(entries) => entries,
                        _ => Vec::new(),
                    };
                    labelled.push(("answers".to_string(), Json::List(answers)));
                    hunks.push(Json::Object(labelled));
                }
            }
            files.push(obj(vec![
                ("path", Json::Str(path.to_string())),
                ("added", entry.get("added").cloned().unwrap_or(Json::Null)),
                ("deleted", entry.get("deleted").cloned().unwrap_or(Json::Null)),
                ("hunks", Json::List(hunks)),
            ]));
    }
    }
    let unanswered = anchors
        .iter()
        .filter(|(fid, _)| !answered.contains(fid))
        .map(|(fid, _)| Json::Str(fid.clone()))
        .collect();
    obj(vec![
        ("from", delta.get("from").cloned().unwrap_or(Json::Null)),
        ("files", Json::List(files)),
        ("unanswered", Json::List(unanswered)),
    ])
}

fn build_impl(data: &str) -> Result<String, String> {
    let input = Parser::parse(data)?;
    if !matches!(input, Json::Object(_)) {
        return Err("brief-input: not an object".into());
    }
    let findings_in = input.get("findings").and_then(Json::as_list).cloned().unwrap_or_default();
    let findings = findings_in
        .iter()
        .map(|row| {
            let detail = row.get("detail").and_then(Json::as_str).unwrap_or("");
            obj(vec![
                ("id", row.get("id").cloned().unwrap_or(Json::Null)),
                ("classification", row.get("classification").cloned().unwrap_or(Json::Null)),
                ("detail", Json::Str(detail.split_whitespace().collect::<Vec<_>>().join(" "))),
            ])
        })
        .collect::<Vec<_>>();
    let (changed, files, lines) = match input.get("changed") {
        None | Some(Json::Null) => (Json::Null, Json::Null, Json::Null),
        Some(Json::List(rows)) => {
            let mut over = false;
            let mut total: i64 = 0;
            let mut out = Vec::new();
            for row in rows {
                let added = row.get("added").cloned().unwrap_or(Json::Null);
                let deleted = row.get("deleted").cloned().unwrap_or(Json::Null);
                match (added.as_int(), deleted.as_int()) {
                    (Some(a), Some(d)) => total += a + d,
                    _ => over = true,
                }
                let hunks = row
                    .get("hunks")
                    .and_then(Json::as_list)
                    .map(|list| list.iter().map(labelled_hunk).collect())
                    .unwrap_or_default();
                out.push(obj(vec![
                    ("path", row.get("path").cloned().unwrap_or(Json::Null)),
                    ("added", added),
                    ("deleted", deleted),
                    ("binary", row.get("binary").cloned().unwrap_or(Json::Null)),
                    ("hunks", Json::List(hunks)),
                ]));
            }
            let files = Json::Int(out.len() as i64);
            let lines = Json::Int(if over { LINES_OVER_CAP } else { total });
            (Json::List(out), files, lines)
        }
        Some(_) => return Err("brief-input: changed".into()),
    };
    let delta = match input.get("delta") {
        None | Some(Json::Null) => Json::Null,
        Some(delta) => delta_package(delta, &findings_in),
    };
    let doc = obj(vec![
        ("schema", Json::Int(BRIEF_SCHEMA as i64)),
        ("kind", Json::Str("review".into())),
        ("fingerprint", input.get("fingerprint").cloned().unwrap_or(Json::Null)),
        ("request", Json::List(strings(input.get("request")).into_iter().map(Json::Str).collect())),
        ("contract", input.get("contract").cloned().unwrap_or(Json::Null)),
        ("decisions", Json::List(strings(input.get("decisions")).into_iter().map(Json::Str).collect())),
        ("criteria", Json::List(strings(input.get("criteria")).into_iter().map(Json::Str).collect())),
        ("changed", changed),
        ("changed_unmeasurable", input.get("changed_unmeasurable").cloned().unwrap_or(Json::Null)),
        ("files", files),
        ("lines", lines),
        ("findings", Json::List(findings)),
        ("delta", delta),
    ]);
    let mut out = String::new();
    dump(&doc, &mut out);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Validation: the exclusion list, mirroring `_validate_brief`.

const BRIEF_KEYS: &[&str] = &[
    "schema", "kind", "fingerprint", "request", "contract", "decisions",
    "criteria", "changed", "changed_unmeasurable", "files", "lines",
    "findings", "delta",
];
const ROW_KEYS: &[&str] = &["path", "added", "deleted", "binary", "hunks"];
const HUNK_KEYS: &[&str] = &["old_start", "old_count", "new_start", "new_count", "header", "label"];
const FINDING_KEYS: &[&str] = &["id", "classification", "detail"];
const DELTA_KEYS: &[&str] = &["from", "files", "unanswered"];
const DELTA_FILE_KEYS: &[&str] = &["path", "added", "deleted", "hunks"];
const DELTA_HUNK_KEYS: &[&str] = &[
    "old_start", "old_count", "new_start", "new_count", "header", "label", "answers",
];
const WITHHELD_KEYS: &[&str] = &[
    "gate_record", "gate_path", "record", "record_path", "owner_evidence",
    "owner_methods", "methods", "self_rating", "self_review", "satisfied",
    "reviewer", "verdict", "predicted_verdict", "snapshot", "tier", "phase",
    "round_number", "units", "authorized", "decisions_resolved",
];

fn check_keys(obj: &Json, allowed: &[&str], violations: &mut Vec<String>) {
    if let Json::Object(entries) = obj {
        for (key, _) in entries {
            if !allowed.contains(&key.as_str()) {
                if WITHHELD_KEYS.contains(&key.as_str()) {
                    violations.push(format!("withheld-key:{key}"));
                } else {
                    violations.push(format!("unexpected-key:{key}"));
                }
            }
        }
    }
}

fn collect_strings(value: &Json, out: &mut Vec<String>) {
    match value {
        Json::Str(text) => out.push(text.clone()),
        Json::List(items) => items.iter().for_each(|item| collect_strings(item, out)),
        Json::Object(entries) => entries.iter().for_each(|(_, item)| collect_strings(item, out)),
        _ => {}
    }
}

fn validate_impl(doc_text: &str, tokens_text: &str) -> String {
    let malformed = || {
        "{\"ok\":false,\"violations\":[\"malformed-brief\"]}".to_string()
    };
    let doc = match Parser::parse(doc_text) {
        Ok(doc) => doc,
        Err(_) => return malformed(),
    };
    let schema_ok = doc.get("schema").and_then(Json::as_int) == Some(BRIEF_SCHEMA as i64);
    let kind_ok = doc.get("kind").and_then(Json::as_str) == Some("review");
    let fingerprint = doc.get("fingerprint").and_then(Json::as_str).unwrap_or("");
    let fingerprint_ok = fingerprint.is_empty()
        || ((40..=64).contains(&fingerprint.chars().count())
            && fingerprint.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    if !schema_ok || !kind_ok || !matches!(doc, Json::Object(_)) || !fingerprint_ok {
        return malformed();
    }
    let mut violations: Vec<String> = Vec::new();
    check_keys(&doc, BRIEF_KEYS, &mut violations);
    if let Some(rows) = doc.get("changed").and_then(Json::as_list) {
        for row in rows {
            check_keys(row, ROW_KEYS, &mut violations);
            if let Some(hunks) = row.get("hunks").and_then(Json::as_list) {
                for hunk in hunks {
                    check_keys(hunk, HUNK_KEYS, &mut violations);
                }
            }
        }
    }
    if let Some(rows) = doc.get("findings").and_then(Json::as_list) {
        for row in rows {
            check_keys(row, FINDING_KEYS, &mut violations);
        }
    }
    if let Some(delta) = doc.get("delta") {
        if matches!(delta, Json::Object(_)) {
            check_keys(delta, DELTA_KEYS, &mut violations);
            if let Some(files) = delta.get("files").and_then(Json::as_list) {
                for entry in files {
                    check_keys(entry, DELTA_FILE_KEYS, &mut violations);
                    if let Some(hunks) = entry.get("hunks").and_then(Json::as_list) {
                        for hunk in hunks {
                            check_keys(hunk, DELTA_HUNK_KEYS, &mut violations);
                        }
                    }
                }
            }
        }
    }
    let mut strings = Vec::new();
    collect_strings(&doc, &mut strings);
    let tokens = Parser::parse(tokens_text).ok().and_then(|parsed| {
        parsed.as_list().map(|items| {
            items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect::<Vec<_>>()
        })
    }).unwrap_or_default();
    for (index, token) in tokens.iter().enumerate() {
        if token.chars().count() >= 8 && strings.iter().any(|text| text.contains(token.as_str())) {
            violations.push(format!("withheld-content:{index}"));
        }
    }
    let result = obj(vec![
        ("ok", Json::Bool(violations.is_empty())),
        ("violations", Json::List(violations.into_iter().map(Json::Str).collect())),
    ]);
    let mut out = String::new();
    dump(&result, &mut out);
    out
}

// ---------------------------------------------------------------------------

/// Assemble the Review brief document (JSON, schema 1) from the neutral
/// inputs. Raises on a malformed input: the hook reruns on its Python route.
#[pyfunction]
fn build_review_brief(data: &str) -> PyResult<String> {
    match std::panic::catch_unwind(|| build_impl(data)) {
        Ok(Ok(doc)) => Ok(doc),
        Ok(Err(code)) => Err(PyRuntimeError::new_err(code)),
        Err(_) => Err(PyRuntimeError::new_err("brief-panic")),
    }
}

/// Validate a brief document against the exclusion list; returns
/// `{"ok": bool, "violations": [...]}` and never raises.
#[pyfunction]
fn validate_review_brief(doc: &str, tokens: &str) -> String {
    match std::panic::catch_unwind(|| validate_impl(doc, tokens)) {
        Ok(result) => result,
        Err(_) => "{\"ok\":false,\"violations\":[\"malformed-brief\"]}".to_string(),
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("BRIEF_SCHEMA", BRIEF_SCHEMA)?;
    m.add_function(wrap_pyfunction!(build_review_brief, m)?)?;
    m.add_function(wrap_pyfunction!(validate_review_brief, m)?)?;
    Ok(())
}
