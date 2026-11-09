//! Change classification (spec #43, ticket #48): the machinery behind the
//! scan document's change class, manifest signatures, and risk flags.
//!
//! Everything here is a port of a Python oracle in the gate runtime
//! (`runtime/sureforge_hook.py`, plus `secret_read.py` for secret paths):
//! the differential parity suite compares the engine document against the
//! Python route field for field, so these functions mirror the Python
//! semantics exactly — including where the Python side fails closed. Any
//! doubt classifies upward (ADR-0002): an input a lexer or parser cannot
//! see through is "unparseable" / unreadable, never a lower class.
//!
//! No new dependencies: the JSON, TOML, XML, and Python-AST machinery the
//! manifest signatures need is hand-written against the Python semantics
//! (stdlib json / tomllib / ElementTree / ast), std only.

use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Text helpers mirroring Python str behaviour.

/// Python whitespace for strip/split/`\s`: Unicode White_Space plus the
/// file-separator controls Python's `str.isspace` also accepts.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()` with Python's whitespace set.
fn py_trim(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

/// `str.rstrip()` with Python's whitespace set.
fn py_rtrim(text: &str) -> &str {
    text.trim_end_matches(is_py_space)
}

/// `" ".join(text.split())`: whitespace runs collapse to single spaces.
fn py_ws_normalize(text: &str) -> String {
    text.split(is_py_space).filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ")
}

/// `str.splitlines()`: boundaries are \n, \r, \r\n, \v, \f, \x1c-\x1e,
/// \x85, \u2028, \u2029; a trailing boundary leaves no empty final line.
fn py_split_lines(text: &str) -> Vec<&str> {
    fn is_boundary(c: char) -> bool {
        matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}'
            | '\u{85}' | '\u{2028}' | '\u{2029}')
    }
    let mut lines = Vec::new();
    let mut start = 0;
    let mut iter = text.char_indices().peekable();
    while let Some((index, c)) = iter.next() {
        if is_boundary(c) {
            lines.push(&text[start..index]);
            start = index + c.len_utf8();
            if c == '\r' && iter.peek().map(|(_, next)| *next) == Some('\n') {
                iter.next();
                start += 1;
            }
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `str.casefold()` for the keys and names the gate folds: full lowercase
/// plus the ß expansion; the gate's folded vocabularies are ASCII.
fn casefold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == 'ß' || c == 'ẞ' {
            out.push_str("ss");
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// The folded final segment of a path, `\` normalized to `/` first (the
/// rule `_comment_style` and the comment lexers use).
fn folded_basename(path: &str) -> String {
    casefold(path.replace('\\', "/").rsplit('/').next().unwrap_or(""))
}

/// `_suffix`: the final `.` extension of a name, or "" (a leading dot is
/// not an extension).
fn suffix_of(name: &str) -> &str {
    match name.rfind('.') {
        Some(dot) if dot > 0 => &name[dot..],
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// Path classification: doc paths, test paths, comment styles.

const DOC_EXTS: [&str; 3] = [".md", ".rst", ".txt"];
const DATA_DIRS: [&str; 16] = [
    "test", "tests", "spec", "specs", "__tests__", "testdata", "test_data",
    "fixture", "fixtures", "golden", "goldens", "snapshots", "__snapshots__",
    "data", "resources", "assets",
];

/// `(?:requirements|constraints)(?:[-_.][^/]*)?\.txt$|^cmakelists\.txt$|^robots\.txt$`
/// searched in a folded basename.
fn doc_config_match(folded: &str) -> bool {
    if folded == "cmakelists.txt" || folded == "robots.txt" {
        return true;
    }
    for word in ["requirements", "constraints"] {
        let mut from = 0;
        while let Some(found) = folded[from..].find(word) {
            let rest = &folded[from + found + word.len()..];
            if rest == ".txt" {
                return true;
            }
            if let Some(first) = rest.chars().next() {
                if matches!(first, '-' | '_' | '.') && rest[first.len_utf8()..].ends_with(".txt") {
                    return true;
                }
            }
            from += found + 1;
        }
    }
    false
}

/// `_is_doc_path`: a .md/.rst/.txt file that is neither build/dependency
/// config nor test or resource data.
pub fn is_doc_path(name: &str) -> bool {
    let parts: Vec<String> = name
        .replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty())
        .map(|part| casefold(part))
        .collect();
    let Some(folded) = parts.last() else { return false };
    if parts[..parts.len() - 1].iter().any(|part| DATA_DIRS.contains(&part.as_str())) {
        return false;
    }
    DOC_EXTS.iter().any(|ext| folded.ends_with(ext)) && !doc_config_match(folded)
}

fn is_test_py(base: &str) -> bool {
    let folded = casefold(base);
    folded.ends_with(".py") && (folded.starts_with("test_") || folded.ends_with("_test.py"))
}

/// The `(?i)(^test_.+|.*_test\.[^.]+|.*\.test\.[^.]+|.*\.spec\.[^.]+)$`
/// test-name pattern over a folded basename.
fn test_file_match(folded: &str) -> bool {
    if folded.starts_with("test_") && folded.chars().count() > 5 {
        return true;
    }
    for needle in ["_test.", ".test.", ".spec."] {
        let mut from = 0;
        while let Some(found) = folded[from..].find(needle) {
            let rest = &folded[from + found + needle.len()..];
            if !rest.is_empty() && !rest.contains('.') {
                return true;
            }
            from += found + 1;
        }
    }
    false
}

const SOURCE_EXTS: [&str; 29] = [
    ".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".cs", ".go",
    ".java", ".kt", ".kts", ".rb", ".php", ".rs", ".scala", ".swift", ".c",
    ".h", ".cc", ".cpp", ".hpp", ".m", ".mm", ".vue", ".svelte", ".dart", ".lua",
];
const TEXT_EXTS: [&str; 4] = [".md", ".rst", ".txt", ".adoc"];
const JS_EXTS: [&str; 8] = ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];

/// `_source_test` over a folded basename.
fn source_test(folded: &str) -> bool {
    SOURCE_EXTS.contains(&suffix_of(folded)) && test_file_match(folded)
}

/// `_is_test_path`: a test file by each runner's naming convention.
pub fn is_test_path(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|part| !part.is_empty()).collect();
    let Some(base) = parts.last() else { return false };
    let folded = casefold(base);
    if is_test_py(base) || folded == "conftest.py" {
        return true;
    }
    if JS_EXTS.iter().any(|ext| folded.ends_with(&format!("test.{ext}")) || folded.ends_with(&format!("spec.{ext}"))) {
        return true;
    }
    if ["Test.cs", "Tests.cs", "Test.java", "Tests.java"].iter().any(|end| base.ends_with(end)) {
        return true;
    }
    if folded.ends_with("_test.go") || folded.ends_with("_test.rs")
        || (folded.starts_with("test_") && folded.ends_with(".rs"))
    {
        return true;
    }
    if parts.len() > 1 {
        let parent = casefold(parts[parts.len() - 2]);
        if parent == "__tests__" && JS_EXTS.iter().any(|ext| folded.ends_with(&format!(".{ext}"))) {
            return true;
        }
        if parent == "tests" && folded.ends_with(".rs") {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Style {
    Python,
    Hash,
    Slash,
}

const HASH_COMMENT_EXTS: [&str; 5] = [".py", ".pyi", ".sh", ".bash", ".rb"];
const SLASH_COMMENT_EXTS: &[&str] = &[
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".go", ".rs",
    ".java", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".kt", ".kts", ".swift",
    ".scala", ".php",
];

/// `_comment_style`: Python, Hash, Slash, or None when the file has no
/// comment syntax the gate lexes.
pub fn comment_style(name: &str) -> Option<Style> {
    let folded = folded_basename(name);
    if folded.ends_with(".py") || folded.ends_with(".pyi") {
        return Some(Style::Python);
    }
    if HASH_COMMENT_EXTS.iter().any(|ext| folded.ends_with(ext)) {
        return Some(Style::Hash);
    }
    if SLASH_COMMENT_EXTS.iter().any(|ext| folded.ends_with(ext)) {
        return Some(Style::Slash);
    }
    None
}

// ---------------------------------------------------------------------------
// Comment-only verdicts. Unparseable is the fail-closed bucket: source a
// lexer cannot see through is never safely comment-only.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    CommentOnly,
    Differs,
    Unparseable,
}

pub fn comment_verdict(style: Style, old: &str, new: &str, name: &str) -> Verdict {
    match style {
        Style::Python => python_verdict(old, new),
        Style::Hash => {
            let ruby = folded_basename(name).ends_with(".rb");
            match (hash_code_parts(old, ruby), hash_code_parts(new, ruby)) {
                (Some(left), Some(right)) => {
                    if left == right { Verdict::CommentOnly } else { Verdict::Differs }
                }
                _ => Verdict::Unparseable,
            }
        }
        Style::Slash => slash_verdict(old, new, name),
    }
}

/// `_hash_code_parts`: ordered non-comment code parts of one `#`-comment
/// file, or None when a `#` could be data (heredoc, open quote, command or
/// string interpolation, Ruby literals).
fn hash_code_parts(text: &str, ruby: bool) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    for line in py_split_lines(text) {
        let chars: Vec<char> = line.chars().collect();
        // A `$(`, `#{`, or a `#` inside `${...}` hides structure.
        for index in 0..chars.len() {
            if chars[index] == '$' && chars.get(index + 1) == Some(&'(') {
                return None;
            }
            if chars[index] == '#' && chars.get(index + 1) == Some(&'{') {
                return None;
            }
            if chars[index] == '$' && chars.get(index + 1) == Some(&'{') {
                let mut depth = index + 2;
                let mut hidden = false;
                while depth < chars.len() && chars[depth] != '}' {
                    if chars[depth] == '#' {
                        hidden = true;
                        break;
                    }
                    depth += 1;
                }
                if hidden {
                    return None;
                }
            }
        }
        if ruby && py_rtrim(line) == "__END__" {
            return None;
        }
        let mut quote: Option<char> = None;
        let mut index = 0;
        let mut end = chars.len();
        while index < chars.len() {
            let char = chars[index];
            if quote.is_some() {
                if char == '\\' {
                    index += 2;
                    continue;
                }
                if Some(char) == quote {
                    quote = None;
                }
            } else if char == '\\' {
                index += 2;
                continue;
            } else if char == '"' || char == '\'' {
                quote = Some(char);
            } else if char == '#' && (index == 0 || chars[index - 1] == ' ' || chars[index - 1] == '\t') {
                end = index;
                break;
            } else if char == '<' && chars.get(index + 1) == Some(&'<') {
                return None;
            } else if ruby && (char == '/' || (char == '%' && ruby_percent_literal(&chars, index))) {
                return None;
            }
            index += 1;
        }
        if quote.is_some() {
            return None;
        }
        let part: String = chars[..end].iter().collect();
        let part = py_trim(&part);
        if !part.is_empty() {
            parts.push(part.to_string());
        }
    }
    Some(parts)
}

/// The `%[qQwWiIrsx]?[^\w\s]` opener of a Ruby %-literal at `index`.
fn ruby_percent_literal(chars: &[char], index: usize) -> bool {
    let mut at = index + 1;
    if at < chars.len() && "qQwWiIrsx".contains(chars[at]) {
        at += 1;
    }
    match chars.get(at) {
        Some(c) => !(c.is_alphanumeric() || *c == '_' || is_py_space(*c)),
        None => false,
    }
}

const REGEX_KEYWORDS: [&str; 14] = [
    "return", "throw", "typeof", "yield", "await", "case", "in", "of", "new",
    "delete", "void", "instanceof", "do", "else",
];

/// `_slash_code_stream`: code text with comments blanked, or None when
/// unsafe to classify. Mirrors the Python scanner rule for rule.
fn slash_code_stream(text: &str, markup: bool, raw_backtick: bool, rust: bool) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let size = chars.len();
    let mut out: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut index = 0;
    while index < size {
        let char = chars[index];
        if let Some(open) = quote {
            out.push(char);
            if char == '\\' && !(raw_backtick && open == '`') {
                if chars.get(index + 1) == Some(&'(') {
                    return None;
                }
                if index + 1 < size {
                    out.push(chars[index + 1]);
                }
                index += 2;
                continue;
            }
            if char == open {
                quote = None;
            } else if (char == '$' || char == '#') && chars.get(index + 1) == Some(&'{') {
                return None;
            }
            index += 1;
            continue;
        }
        if char == '"' || char == '\'' || char == '`' {
            if rust && char == '\'' && !valid_rust_char_literal(&chars, index) {
                return None;
            }
            let previous = out.iter().rev().find(|c| !is_py_space(**c)).copied().unwrap_or('\0');
            if char != '`' && matches!(previous, 'R' | 'r' | '$' | '@' | '#') {
                return None;
            }
            if char == '"' && chars.get(index + 1) == Some(&'"') && chars.get(index + 2) == Some(&'"') {
                return None;
            }
            quote = Some(char);
            out.push(char);
        } else if char == '/' && chars.get(index + 1) == Some(&'/') {
            if index > 0 && chars[index - 1] == ':' {
                out.push('/');
                out.push('/');
                index += 2;
                continue;
            }
            while index < size && chars[index] != '\n' {
                index += 1;
            }
            out.push(' ');
            continue;
        } else if char == '/' && chars.get(index + 1) == Some(&'*') {
            let mut end = index + 2;
            let mut closed = None;
            while end + 1 < size {
                if chars[end] == '*' && chars[end + 1] == '/' {
                    closed = Some(end);
                    break;
                }
                end += 1;
            }
            let end = closed?;
            let newlines = chars[index..end].iter().filter(|c| **c == '\n').count();
            out.push(' ');
            for _ in 0..newlines {
                out.push('\n');
            }
            index = end + 2;
            continue;
        } else if char == '/' {
            let previous = out.iter().rev().find(|c| !is_py_space(**c)).copied().unwrap_or('\0');
            if previous == '\0' || "=({[,;:!&|?^~<>+-*%".contains(previous) {
                return None;
            }
            if previous == ')' || previous == '}' {
                return None;
            }
            if let Some(word) = trailing_identifier(&out) {
                if REGEX_KEYWORDS.contains(&word.as_str()) {
                    return None;
                }
            }
            out.push(char);
        } else if char == '<' && chars.get(index + 1) == Some(&'<') && chars.get(index + 2) == Some(&'<') {
            return None;
        } else if char == '<' && markup
            && chars.get(index + 1).is_some_and(|next| next.is_ascii_alphabetic())
        {
            return None;
        } else {
            out.push(char);
        }
        index += 1;
    }
    if quote.is_some() {
        return None;
    }
    Some(out.iter().collect())
}

/// The `[A-Za-z_$][\w$]*` word the output stream ends with, if any.
fn trailing_identifier(out: &[char]) -> Option<String> {
    let mut end = out.len();
    while end > 0 && is_py_space(out[end - 1]) {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && (out[start - 1].is_alphanumeric() || out[start - 1] == '_' || out[start - 1] == '$') {
        start -= 1;
    }
    // The regex can start after leading digits of the run (`1abc` -> `abc`).
    while start < end && !(out[start].is_ascii_alphabetic() || out[start] == '_' || out[start] == '$') {
        start += 1;
    }
    if start >= end {
        return None;
    }
    Some(out[start..end].iter().collect())
}

/// `'(?:\\u\{[0-9A-Fa-f]+\}|\\[^\n]|[^\\'\n])'` at `index`: a Rust char
/// literal rather than a lifetime or label.
fn valid_rust_char_literal(chars: &[char], index: usize) -> bool {
    let mut at = index + 1;
    match chars.get(at) {
        Some('\\') => {
            at += 1;
            if chars.get(at) == Some(&'u') && chars.get(at + 1) == Some(&'{') {
                at += 2;
                let digits = at;
                while at < chars.len() && chars[at].is_ascii_hexdigit() {
                    at += 1;
                }
                if at == digits || chars.get(at) != Some(&'}') {
                    return false;
                }
                at += 1;
            } else if chars.get(at).is_some_and(|c| *c != '\n') {
                at += 1;
            } else {
                return false;
            }
        }
        Some(c) if *c != '\'' && *c != '\n' => {
            at += 1;
        }
        _ => return false,
    }
    chars.get(at) == Some(&'\'')
}

fn slash_verdict(old: &str, new: &str, name: &str) -> Verdict {
    let folded = folded_basename(name);
    if folded.ends_with(".php")
        && [old, new].iter().any(|text| !text.starts_with("<?php") || text.contains("?>"))
    {
        return Verdict::Unparseable;
    }
    let markup = folded.ends_with(".jsx") || folded.ends_with(".tsx");
    let raw = folded.ends_with(".go");
    let rust = folded.ends_with(".rs");
    let pick = |stream: &str| -> Vec<String> {
        py_split_lines(stream)
            .iter()
            .map(|line| py_trim(line).to_string())
            .filter(|line| !line.is_empty())
            .collect()
    };
    match (slash_code_stream(old, markup, raw, rust), slash_code_stream(new, markup, raw, rust)) {
        (Some(left), Some(right)) => {
            if pick(&left) == pick(&right) { Verdict::CommentOnly } else { Verdict::Differs }
        }
        _ => Verdict::Unparseable,
    }
}

// ---------------------------------------------------------------------------
// The Python lexer: CPython's tokenize (3.12) reduced to the token stream
// `_python_comment_only` compares — semantic tokens with comments and
// layout dropped, NEWLINE normalized — plus conservative structural
// checks for the failures only compile() would catch (return/yield/await
// outside their scope, break/continue outside a loop, star imports inside
// a scope, indentation a header does not open). A stream that fails
// either is Unparseable: the file is never safely comment-only.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TokKind {
    Name,
    Number,
    Str,
    Op,
    Newline,
    Indent,
    Dedent,
    FStringStart,
    FStringMiddle,
    FStringEnd,
}

#[derive(Clone, PartialEq)]
struct Tok {
    kind: TokKind,
    text: String,
}

fn tok(kind: TokKind, text: impl Into<String>) -> Tok {
    Tok { kind, text: text.into() }
}

struct PyLexer {
    chars: Vec<char>,
    pos: usize,
    toks: Vec<Tok>,
    brackets: Vec<char>,
    indents: Vec<(i32, i32)>,
    fresh_line: bool,
    line_has_code: bool,
    continued: bool,
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || ((c as u32) >= 0x80 && !c.is_whitespace())
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || ((c as u32) >= 0x80 && !c.is_whitespace())
}

fn string_prefix(run: &str) -> Option<(bool, bool)> {
    // (raw, fstring) for a valid string prefix, case-insensitive.
    let lower = run.to_ascii_lowercase();
    match lower.as_str() {
        "r" => Some((true, false)),
        "b" | "u" => Some((false, false)),
        "f" => Some((false, true)),
        "rb" | "br" => Some((true, false)),
        "rf" | "fr" => Some((true, true)),
        _ => None,
    }
}

impl PyLexer {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn text_range(&self, start: usize, end: usize) -> String {
        self.chars[start..end].iter().collect()
    }

    fn run(&mut self) -> Result<(), ()> {
        while self.pos < self.chars.len() {
            if self.fresh_line && self.brackets.is_empty() {
                self.lex_line_start()?;
                if self.fresh_line {
                    continue; // a blank or comment-only line was consumed
                }
            }
            let c = self.chars[self.pos];
            match c {
                '\n' => {
                    self.pos += 1;
                    if self.brackets.is_empty() && self.line_has_code {
                        self.toks.push(tok(TokKind::Newline, "\n"));
                        self.line_has_code = false;
                    }
                    self.fresh_line = true;
                }
                '\r' | ' ' | '\t' | '\u{c}' => {
                    self.pos += 1;
                }
                '#' => self.skip_comment(),
                '\\' => {
                    if self.peek_at(1) == Some('\n') {
                        self.pos += 2;
                        self.continued = true;
                        self.fresh_line = true;
                    } else if self.peek_at(1) == Some('\r') && self.peek_at(2) == Some('\n') {
                        self.pos += 3;
                        self.continued = true;
                        self.fresh_line = true;
                    } else {
                        return Err(());
                    }
                }
                _ => {
                    self.lex_atom()?;
                    self.line_has_code = true;
                    self.fresh_line = false;
                }
            }
        }
        if self.continued || !self.brackets.is_empty() {
            return Err(());
        }
        if self.line_has_code {
            self.toks.push(tok(TokKind::Newline, "\n"));
        }
        while self.indents.len() > 1 {
            self.indents.pop();
            self.toks.push(tok(TokKind::Dedent, ""));
        }
        Ok(())
    }

    /// Indentation bookkeeping at a physical line start (bracket depth 0).
    /// Leaves `fresh_line` set when the whole line was blank or a comment.
    fn lex_line_start(&mut self) -> Result<(), ()> {
        if self.continued {
            self.continued = false;
            while matches!(self.peek(), Some(' ' | '\t' | '\u{c}' | '\r')) {
                self.pos += 1;
            }
            if self.peek() == Some('\n') {
                // A blank line after a continuation ends the logical line.
                self.pos += 1;
                if self.line_has_code {
                    self.toks.push(tok(TokKind::Newline, "\n"));
                    self.line_has_code = false;
                }
                return Ok(());
            }
            if self.peek() == Some('#') {
                self.skip_comment();
                if self.peek() == Some('\n') {
                    self.pos += 1;
                    if self.line_has_code {
                        self.toks.push(tok(TokKind::Newline, "\n"));
                        self.line_has_code = false;
                    }
                }
                return Ok(());
            }
            self.fresh_line = false;
            return Ok(());
        }
        let start = self.pos;
        while matches!(self.peek(), Some(' ' | '\t' | '\u{c}')) {
            self.pos += 1;
        }
        match self.peek() {
            None => {
                self.fresh_line = false;
                Ok(())
            }
            Some('\n') => {
                self.pos += 1;
                Ok(())
            }
            Some('#') => {
                self.skip_comment();
                if self.peek() == Some('\n') {
                    self.pos += 1;
                }
                Ok(())
            }
            Some(_) => {
                let (mut col, mut alt) = (0i32, 0i32);
                for c in &self.chars[start..self.pos] {
                    match c {
                        ' ' => {
                            col += 1;
                            alt += 1;
                        }
                        '\t' => {
                            col = (col / 8 + 1) * 8;
                            alt += 1;
                        }
                        '\u{c}' => {
                            col = 0;
                            alt = 0;
                        }
                        _ => {}
                    }
                }
                let (top_col, top_alt) = *self.indents.last().ok_or(())?;
                if col > top_col {
                    self.toks.push(tok(TokKind::Indent, self.text_range(start, self.pos)));
                    self.indents.push((col, alt));
                } else if col == top_col {
                    if alt != top_alt {
                        return Err(()); // TabError
                    }
                } else {
                    while self.indents.last().map(|(c, _)| *c) > Some(col) {
                        self.indents.pop();
                        self.toks.push(tok(TokKind::Dedent, ""));
                    }
                    let (now_col, now_alt) = *self.indents.last().ok_or(())?;
                    if now_col != col || now_alt != alt {
                        return Err(()); // unindent matches no outer level
                    }
                }
                self.fresh_line = false;
                Ok(())
            }
        }
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.pos += 1;
        }
    }

    /// One token (or, for an f-string, its token sequence) at the cursor.
    fn lex_atom(&mut self) -> Result<(), ()> {
        let c = self.chars[self.pos];
        if c == '"' || c == '\'' {
            return self.lex_string(0, self.pos);
        }
        if c.is_ascii_digit() || (c == '.' && self.peek_at(1).is_some_and(|n| n.is_ascii_digit())) {
            return self.lex_number();
        }
        if is_name_start(c) {
            let start = self.pos;
            while self.peek().is_some_and(is_name_char) {
                self.pos += 1;
            }
            let run = self.text_range(start, self.pos);
            if matches!(self.peek(), Some('"') | Some('\'')) {
                if let Some(prefix) = string_prefix(&run) {
                    let _ = prefix;
                    return self.lex_string(run.chars().count(), start);
                }
                if run.chars().all(|c| "rRbBuUfF".contains(c)) {
                    return Err(()); // a malformed string prefix (ur, rr, ...)
                }
                self.toks.push(tok(TokKind::Name, run));
                return self.lex_string(0, self.pos);
            }
            self.toks.push(tok(TokKind::Name, run));
            return Ok(());
        }
        // Operators and brackets: longest match first.
        let three = self.text_range(self.pos, (self.pos + 3).min(self.chars.len()));
        let two = self.text_range(self.pos, (self.pos + 2).min(self.chars.len()));
        for (text, len) in [
            (three.as_str(), 3usize),
            (two.as_str(), 2),
        ] {
            if matches!(text, "**=" | "//=" | "<<=" | ">>=" | "..." | "**" | "//" | "<<" | ">>"
                | "<=" | ">=" | "==" | "!=" | "->" | ":=" | "+=" | "-=" | "*=" | "/=" | "%="
                | "&=" | "|=" | "^=") && text.chars().count() == len {
                self.pos += len;
                self.push_op(text);
                return Ok(());
            }
        }
        if c.is_ascii_punctuation() {
            self.pos += 1;
            self.push_op(&c.to_string());
            return Ok(());
        }
        Err(())
    }

    fn push_op(&mut self, text: &str) {
        match text {
            "(" | "[" | "{" => self.brackets.push(text.chars().next().unwrap_or('(')),
            ")" | "]" | "}" => {
                // CPython's tokenizer pops any opener on any closer; a
                // mismatch is the parser's (compile's) error, not lexing's.
                self.brackets.pop();
            }
            _ => {}
        }
        self.toks.push(tok(TokKind::Op, text));
    }

    fn lex_number(&mut self) -> Result<(), ()> {
        let start = self.pos;
        if self.peek() == Some('0') && matches!(self.peek_at(1), Some('x' | 'X' | 'o' | 'O' | 'b' | 'B')) {
            let radix = self.peek_at(1).unwrap_or('x');
            self.pos += 2;
            while self.peek().is_some_and(|c| {
                c == '_' || match radix {
                    'x' | 'X' => c.is_ascii_hexdigit(),
                    'o' | 'O' => ('0'..='7').contains(&c),
                    _ => c == '0' || c == '1',
                }
            }) {
                self.pos += 1;
            }
        } else {
            while self.peek().is_some_and(|c| c.is_ascii_digit() || c == '_') {
                self.pos += 1;
            }
            if self.peek() == Some('.') {
                self.pos += 1;
                while self.peek().is_some_and(|c| c.is_ascii_digit() || c == '_') {
                    self.pos += 1;
                }
            }
            if matches!(self.peek(), Some('e' | 'E')) {
                let save = self.pos;
                self.pos += 1;
                if matches!(self.peek(), Some('+' | '-')) {
                    self.pos += 1;
                }
                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    while self.peek().is_some_and(|c| c.is_ascii_digit() || c == '_') {
                        self.pos += 1;
                    }
                } else {
                    self.pos = save;
                }
            }
            if matches!(self.peek(), Some('j' | 'J')) {
                self.pos += 1;
            }
        }
        let text = self.text_range(start, self.pos);
        self.toks.push(tok(TokKind::Number, text));
        Ok(())
    }

    /// A string literal at the cursor; `prefix_len` chars precede the quote
    /// and `start` is where the whole literal began.
    fn lex_string(&mut self, prefix_len: usize, start: usize) -> Result<(), ()> {
        let quote_pos = start + prefix_len;
        let raw = prefix_len > 0 && self.chars[start..quote_pos]
            .iter()
            .any(|c| *c == 'r' || *c == 'R');
        let fstring = prefix_len > 0 && self.chars[start..quote_pos]
            .iter()
            .any(|c| *c == 'f' || *c == 'F');
        let quote = self.chars[quote_pos];
        let triple = self.chars.get(quote_pos + 1) == Some(&quote)
            && self.chars.get(quote_pos + 2) == Some(&quote);
        let body = quote_pos + if triple { 3 } else { 1 };
        if fstring {
            self.pos = body;
            let head = self.text_range(start, body);
            self.toks.push(tok(TokKind::FStringStart, head));
            return self.lex_fstring(quote, triple);
        }
        let mut index = body;
        loop {
            let c = *self.chars.get(index).ok_or(())?;
            if c == '\\' {
                index += 2;
                continue;
            }
            if triple {
                if c == quote
                    && self.chars.get(index + 1) == Some(&quote)
                    && self.chars.get(index + 2) == Some(&quote)
                {
                    index += 3;
                    break;
                }
            } else {
                if c == quote {
                    index += 1;
                    break;
                }
                if c == '\n' {
                    return Err(());
                }
            }
            index += 1;
        }
        if raw {
            // A raw string's tokenizer behaviour is identical here.
        }
        self.pos = index;
        let text = self.text_range(start, index);
        self.toks.push(tok(TokKind::Str, text));
        Ok(())
    }

    /// The body of an f-string, after its FStringStart token.
    fn lex_fstring(&mut self, quote: char, triple: bool) -> Result<(), ()> {
        loop {
            let (text, stop) = self.fstring_middle(quote, triple, false)?;
            match stop {
                MiddleStop::Field => {
                    if !text.is_empty() {
                        self.toks.push(tok(TokKind::FStringMiddle, text));
                    }
                    self.fstring_field(quote, triple)?;
                }
                MiddleStop::End(end) => {
                    if !text.is_empty() {
                        self.toks.push(tok(TokKind::FStringMiddle, text));
                    }
                    self.toks.push(tok(TokKind::FStringEnd, end));
                    return Ok(());
                }
                MiddleStop::Close => return Err(()),
            }
        }
    }

    /// Literal f-string text up to the next field, close, or end quote.
    /// In a format spec the caller emits the text even when empty.
    fn fstring_middle(&mut self, quote: char, triple: bool, spec: bool)
        -> Result<(String, MiddleStop), ()>
    {
        let mut text = String::new();
        loop {
            let c = *self.chars.get(self.pos).ok_or(())?;
            if c == '\\' {
                text.push(c);
                if let Some(next) = self.chars.get(self.pos + 1) {
                    text.push(*next);
                    self.pos += 2;
                } else {
                    return Err(());
                }
                continue;
            }
            if c == quote {
                if triple {
                    if self.chars.get(self.pos + 1) == Some(&quote)
                        && self.chars.get(self.pos + 2) == Some(&quote)
                    {
                        let end = self.text_range(self.pos, self.pos + 3);
                        self.pos += 3;
                        return Ok((text, MiddleStop::End(end)));
                    }
                    text.push(c);
                    self.pos += 1;
                    continue;
                }
                let end = quote.to_string();
                self.pos += 1;
                return Ok((text, MiddleStop::End(end)));
            }
            if c == '{' {
                if self.chars.get(self.pos + 1) == Some(&'{') {
                    text.push('{');
                    text.push('{');
                    self.pos += 2;
                    continue;
                }
                return Ok((text, MiddleStop::Field));
            }
            if c == '}' {
                if self.chars.get(self.pos + 1) == Some(&'}') {
                    text.push('}');
                    text.push('}');
                    self.pos += 2;
                    continue;
                }
                if spec {
                    return Ok((text, MiddleStop::Close));
                }
                return Err(());
            }
            if c == '\n' && !triple {
                return Err(());
            }
            text.push(c);
            self.pos += 1;
        }
    }

    /// One `{...}` replacement field; the cursor is at its `{`.
    fn fstring_field(&mut self, quote: char, triple: bool) -> Result<(), ()> {
        self.pos += 1;
        self.toks.push(tok(TokKind::Op, "{"));
        let base = self.brackets.len();
        self.brackets.push('{');
        loop {
            let c = *self.chars.get(self.pos).ok_or(())?;
            if c == ' ' || c == '\t' || c == '\u{c}' || c == '\r' || c == '\n' {
                self.pos += 1;
                continue;
            }
            if c == '#' {
                self.skip_comment();
                continue;
            }
            if self.brackets.len() == base + 1 {
                if c == '}' {
                    self.pos += 1;
                    self.brackets.pop();
                    self.toks.push(tok(TokKind::Op, "}"));
                    return Ok(());
                }
                if c == ':' {
                    self.pos += 1;
                    self.toks.push(tok(TokKind::Op, ":"));
                    return self.fstring_spec(quote, triple, base);
                }
                if c == '!' && self.peek_at(1).is_some_and(is_name_start) {
                    self.pos += 1;
                    self.toks.push(tok(TokKind::Op, "!"));
                    let start = self.pos;
                    while self.peek().is_some_and(is_name_char) {
                        self.pos += 1;
                    }
                    let run = self.text_range(start, self.pos);
                    self.toks.push(tok(TokKind::Name, run));
                    continue;
                }
            }
            if c == '{' {
                self.pos += 1;
                self.brackets.push('{');
                self.toks.push(tok(TokKind::Op, "{"));
                continue;
            }
            if c == '}' {
                self.pos += 1;
                self.brackets.pop();
                self.toks.push(tok(TokKind::Op, "}"));
                continue;
            }
            self.lex_atom()?;
        }
    }

    /// A format spec: middles (emitted even when empty) and nested fields,
    /// up to the `}` that closes the outer field.
    fn fstring_spec(&mut self, quote: char, triple: bool, base: usize) -> Result<(), ()> {
        loop {
            let (text, stop) = self.fstring_middle(quote, triple, true)?;
            self.toks.push(tok(TokKind::FStringMiddle, text));
            match stop {
                MiddleStop::Field => self.fstring_field(quote, triple)?,
                MiddleStop::Close => {
                    if self.brackets.len() != base + 1 {
                        return Err(());
                    }
                    self.pos += 1;
                    self.brackets.pop();
                    self.toks.push(tok(TokKind::Op, "}"));
                    return Ok(());
                }
                MiddleStop::End(_) => return Err(()),
            }
        }
    }
}

enum MiddleStop {
    Field,
    Close,
    End(String),
}

fn py_tokenize(text: &str) -> Result<Vec<Tok>, ()> {
    let mut lexer = PyLexer {
        chars: text.chars().collect(),
        pos: 0,
        toks: Vec::new(),
        brackets: Vec::new(),
        indents: vec![(0, 0)],
        fresh_line: true,
        line_has_code: false,
        continued: false,
    };
    lexer.run()?;
    Ok(lexer.toks)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    Func,
    AsyncFunc,
    Class,
    Loop,
    Other,
}

/// The block a compound header opens, from its first segment's tokens.
fn classify_header(segment: &[Tok]) -> Option<Block> {
    let first = segment.first()?;
    if first.kind != TokKind::Name {
        return None;
    }
    match first.text.as_str() {
        "def" => Some(Block::Func),
        "class" => Some(Block::Class),
        "for" | "while" => Some(Block::Loop),
        "if" | "elif" | "else" | "with" | "try" | "except" | "finally" | "match" | "case" => {
            Some(Block::Other)
        }
        "async" => match segment.get(1) {
            Some(second) if second.kind == TokKind::Name && second.text == "def" => {
                Some(Block::AsyncFunc)
            }
            Some(second) if second.kind == TokKind::Name && second.text == "for" => Some(Block::Loop),
            Some(second) if second.kind == TokKind::Name && second.text == "with" => Some(Block::Other),
            _ => None,
        },
        _ => None,
    }
}

fn is_async_header(segment: &[Tok]) -> bool {
    segment.first().map(|t| t.kind == TokKind::Name && t.text == "async") == Some(true)
        && matches!(segment.get(1), Some(second) if second.kind == TokKind::Name
            && (second.text == "for" || second.text == "with"))
}

/// The structural checks compile() would add over a token stream.
fn py_validate(toks: &[Tok]) -> bool {
    fn scope(stack: &[Block], line: &[Block]) -> Vec<Block> {
        stack.iter().chain(line.iter()).copied().collect()
    }
    fn return_ok(stack: &[Block]) -> bool {
        for block in stack.iter().rev() {
            match block {
                Block::Func | Block::AsyncFunc => return true,
                Block::Class => return false,
                _ => {}
            }
        }
        false
    }
    fn await_ok(stack: &[Block]) -> bool {
        for block in stack.iter().rev() {
            match block {
                Block::AsyncFunc => return true,
                Block::Func | Block::Class => return false,
                _ => {}
            }
        }
        false
    }
    fn loop_ok(stack: &[Block]) -> bool {
        for block in stack.iter().rev() {
            match block {
                Block::Loop => return true,
                Block::Func | Block::AsyncFunc | Block::Class => return false,
                _ => {}
            }
        }
        false
    }

    let mut blocks: Vec<Block> = Vec::new();
    let mut line: Vec<Tok> = Vec::new();
    let mut line_blocks: Vec<Block> = Vec::new();
    let mut line_depth: i32 = 0;
    let mut segment_start = 0usize;
    let mut prev_line: Vec<Tok> = Vec::new();
    // A header line (def/if/for/...) whose ':' closed the line must be
    // followed by an Indent; anything else is the IndentationError
    // compile() reports. A ':' with tokens after it is a one-line suite.
    let mut header_pending = false;
    let mut line_colon = false;
    let mut line_header_candidate = false;
    let mut line_suite_content = false;
    // Operand juxtaposition (`changed 2 123`): tokenize accepts it,
    // compile() does not. Track whether the previous content token
    // ended an operand.
    let mut after_operand = false;
    let mut prev_was_string = false;
    for token in toks {
        match token.kind {
            TokKind::Indent => {
                header_pending = false;
                after_operand = false;
                prev_was_string = false;
                if prev_line.is_empty() {
                    return false;
                }
                let last = prev_line.last();
                if last.map(|t| t.kind == TokKind::Op && t.text == ":") != Some(true) {
                    return false;
                }
                let segment: Vec<Tok> = segment_of(&prev_line);
                match classify_header(&segment) {
                    Some(block) => {
                        if is_async_header(&segment) && !await_ok(&scope(&blocks, &line_blocks)) {
                            return false;
                        }
                        blocks.push(block);
                    }
                    None => return false,
                }
            }
            TokKind::Dedent => {
                if header_pending {
                    return false;
                }
                after_operand = false;
                prev_was_string = false;
                if blocks.pop().is_none() {
                    return false;
                }
            }
            TokKind::Newline => {
                header_pending = line_header_candidate && !line_suite_content;
                line_colon = false;
                line_header_candidate = false;
                line_suite_content = false;
                after_operand = false;
                prev_was_string = false;
                prev_line = std::mem::take(&mut line);
                line_blocks.clear();
                line_depth = 0;
                segment_start = 0;
            }
            _ => {
                if header_pending {
                    return false; // a header line with no indented suite
                }
                if line_colon {
                    line_suite_content = true;
                }
                // Operand juxtaposition check (see the state above).
                let is_keyword = token.kind == TokKind::Name
                    && is_py_keyword(&token.text)
                    && !matches!(token.text.as_str(), "True" | "False" | "None");
                let operand_start = !is_keyword
                    && matches!(token.kind, TokKind::Name | TokKind::Number
                        | TokKind::Str | TokKind::FStringStart)
                    || (token.kind == TokKind::Op && token.text == "...");
                if after_operand && operand_start {
                    let string_concat = prev_was_string
                        && matches!(token.kind, TokKind::Str | TokKind::FStringStart);
                    if !string_concat {
                        return false;
                    }
                }
                let operand_end = !is_keyword
                    && matches!(token.kind, TokKind::Name | TokKind::Number
                        | TokKind::Str | TokKind::FStringEnd)
                    || (token.kind == TokKind::Op
                        && matches!(token.text.as_str(), ")" | "]" | "}" | "..."));
                after_operand = operand_end;
                prev_was_string = matches!(token.kind, TokKind::Str | TokKind::FStringEnd);
                if token.kind == TokKind::Op {
                    match token.text.as_str() {
                        "(" | "[" | "{" => line_depth += 1,
                        ")" | "]" | "}" => line_depth = (line_depth - 1).max(0),
                        ":" if line_depth == 0 => {
                            let segment: Vec<Tok> = line[segment_start..].to_vec();
                            line_colon = true;
                            line_header_candidate = false;
                            if let Some(block) = classify_header(&segment) {
                                line_header_candidate = true;
                                if is_async_header(&segment)
                                    && !await_ok(&scope(&blocks, &line_blocks))
                                {
                                    return false;
                                }
                                line_blocks.push(block);
                            }
                            segment_start = line.len() + 1;
                        }
                        _ => {}
                    }
                }
                if token.kind == TokKind::Name {
                    let combined = scope(&blocks, &line_blocks);
                    match token.text.as_str() {
                        "return" | "yield" => {
                            if !return_ok(&combined) {
                                return false;
                            }
                        }
                        "await" => {
                            if !await_ok(&combined) {
                                return false;
                            }
                        }
                        "break" | "continue" => {
                            if !loop_ok(&combined) {
                                return false;
                            }
                        }
                        "async" => {
                            let at_segment_head = line.len() == segment_start;
                            if at_segment_head && !await_ok(&combined) {
                                // Only a for/with header is checked, and only
                                // when its shape follows; decided at the ':'.
                            }
                        }
                        _ => {}
                    }
                }
                if token.kind == TokKind::Op && token.text == "*" {
                    if line.first().map(|t| t.kind == TokKind::Name && t.text == "from") == Some(true)
                        && line.iter().any(|t| t.kind == TokKind::Name && t.text == "import")
                        && (!blocks.is_empty() || !line_blocks.is_empty())
                    {
                        return false; // import * is module-level only
                    }
                }
                line.push(token.clone());
            }
        }
    }
    if header_pending || (line_header_candidate && !line_suite_content) {
        return false; // the file ends on a header line with no suite
    }
    true
}

/// Python's hard keywords (match/case are soft and stay identifiers).
fn is_py_keyword(text: &str) -> bool {
    matches!(
        text,
        "False" | "None" | "True" | "and" | "as" | "assert" | "async" | "await"
            | "break" | "class" | "continue" | "def" | "del" | "elif" | "else"
            | "except" | "finally" | "for" | "from" | "global" | "if" | "import"
            | "in" | "is" | "lambda" | "nonlocal" | "not" | "or" | "pass"
            | "raise" | "return" | "try" | "while" | "with" | "yield"
    )
}

/// The first segment of a logical line: its tokens up to the first
/// depth-0 `:`.
fn segment_of(line: &[Tok]) -> Vec<Tok> {
    let mut depth = 0i32;
    let mut out = Vec::new();
    for token in line {
        if token.kind == TokKind::Op {
            match token.text.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => depth = (depth - 1).max(0),
                ":" if depth == 0 => break,
                _ => {}
            }
        }
        out.push(token.clone());
    }
    out
}

fn python_verdict(old: &str, new: &str) -> Verdict {
    match (py_tokenize(old), py_tokenize(new)) {
        (Ok(left), Ok(right)) => {
            if !py_validate(&left) || !py_validate(&right) {
                Verdict::Unparseable
            } else if left == right {
                Verdict::CommentOnly
            } else {
                Verdict::Differs
            }
        }
        _ => Verdict::Unparseable,
    }
}

// ---------------------------------------------------------------------------
// Risk flags: `_risk_matches` (pure) and the manifest half of `_risk_paths`.

const RISK_TOKENS: &[&str] = &[
    "auth", "authn", "authz", "oauth", "oidc", "saml", "login", "logout",
    "signin", "signup", "password", "passwd", "jwt", "rbac", "acl",
    "permission", "permissions", "secret", "secrets", "credential",
    "credentials", "crypto", "cryptography", "encryption", "migration",
    "migrations",
];
const RISK_SUFFIXES: [&str; 3] = [".pem", ".key", ".sql"];
const RISK_NAMES: [&str; 17] = [
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "poetry.lock", "Pipfile.lock", "uv.lock", "go.sum", "Cargo.lock",
    "Gemfile.lock", "gradle.lockfile", "packages.lock.json", "composer.lock",
    ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml",
];
const RISK_CONDITIONAL_NAMES: [&str; 14] = [
    "package.json", "composer.json", "pyproject.toml", "pipfile", "setup.py",
    "setup.cfg", "go.mod", "cargo.toml", "gemfile", "pom.xml", "build.gradle",
    "build.gradle.kts", "packages.config", "directory.packages.props",
];
const RISK_GLOBS: [&str; 2] = ["requirements*.txt", "azure-pipelines*.yml"];
const RISK_DIRS: [&str; 2] = ["/.github/workflows/", "/.circleci/"];
const MIGRATION_DIRS: [&str; 2] = ["migration", "migrations"];
const HELM_DIRS: [&str; 1] = ["charts"];

const SECRET_SUFFIXES: [&str; 4] = [".example", ".sample", ".template", ".dist"];
const SECRET_EXTENSIONS: [&str; 6] = [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"];
const SECRET_BASENAMES: &[&str] = &[
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".netrc", ".npmrc",
    ".pypirc", ".htpasswd", "auth.json", "credentials", "credentials.json",
    "secrets.json", "secrets.yml", "secrets.yaml",
];
const SECRET_DIRS: [&str; 3] = [".ssh", ".aws", ".gnupg"];

/// `secret_path_denied` (secret_read.py) as a boolean.
fn secret_path_denied(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let Some(base) = parts.last() else { return false };
    let base = casefold(base);
    if SECRET_SUFFIXES.iter().any(|suffix| base.ends_with(suffix)) {
        return false;
    }
    if base.starts_with(".env")
        || SECRET_EXTENSIONS.iter().any(|ext| base.ends_with(ext))
        || SECRET_BASENAMES.contains(&base.as_str())
        || base.starts_with("credentials")
        || base.starts_with("secrets.")
        || (base.starts_with("id_") && !base.ends_with(".pub"))
    {
        return true;
    }
    parts.iter().any(|part| SECRET_DIRS.contains(&casefold(part).as_str()))
}

/// `_structural_risk`: CI, migrations, SQL, infra, YAML, Helm, and secret
/// paths. These win over exemptions.
fn structural_risk(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
    let Some(last) = parts.last() else { return false };
    let name = casefold(last);
    let parents: Vec<String> = parts[..parts.len() - 1].iter().map(|part| casefold(part)).collect();
    let directory = if parents.is_empty() {
        "/".to_string()
    } else {
        format!("/{}/", parents.join("/"))
    };
    if RISK_DIRS.iter().any(|prefix| directory.contains(prefix)) {
        return true;
    }
    if RISK_NAMES.contains(&name.as_str()) {
        return true;
    }
    if parents.iter().any(|part| MIGRATION_DIRS.contains(&part.as_str())) {
        return true;
    }
    if RISK_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
        || [".yml", ".yaml", ".tf", ".dockerfile", ".tpl"].iter().any(|suffix| name.ends_with(suffix))
    {
        return true;
    }
    if name.starts_with("dockerfile") || name.starts_with("docker-compose") || name == "chart.yaml" {
        return true;
    }
    if parents.iter().any(|part| HELM_DIRS.contains(&part.as_str())) {
        return true;
    }
    if RISK_GLOBS.iter().any(|glob| fnmatch_case(&name, glob)) {
        return true;
    }
    secret_path_denied(path)
}

/// `_docs_text`: text anywhere under a docs/ directory segment.
fn docs_text(parts: &[&str], folded_name: &str) -> bool {
    TEXT_EXTS.contains(&suffix_of(folded_name))
        && parts[..parts.len() - 1].iter().any(|part| casefold(part) == "docs")
}

/// `_risk_exempt`: a source test file, or text under docs/. Structural
/// risk is never exempt.
fn risk_exempt(path: &str) -> bool {
    if structural_risk(path) {
        return false;
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
    let Some(last) = parts.last() else { return false };
    let name = casefold(last);
    source_test(&name) || docs_text(&parts, &name)
}

/// `_conditional_manifest`: manifests that count only when their
/// dependency or script content changes. Uses the raw `/` split, like the
/// Python side.
pub fn conditional_manifest(path: &str) -> bool {
    let name = casefold(path.rsplit('/').next().unwrap_or(""));
    name.ends_with(".csproj") || RISK_CONDITIONAL_NAMES.contains(&name.as_str())
}

/// `_path_tokens`: word runs of one path segment, split on case and
/// letter/digit boundaries, folded, with singular stems of risk tokens.
fn path_tokens(segment: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let chars: Vec<char> = segment.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if !chars[index].is_alphanumeric() {
            index += 1;
            continue;
        }
        let start = index;
        while index < chars.len() && chars[index].is_alphanumeric() {
            index += 1;
        }
        let run = &chars[start..index];
        // Case/digit breaks inside the run.
        let mut piece_start = 0;
        let mut pieces: Vec<String> = Vec::new();
        for at in 1..run.len() {
            let prev = run[at - 1];
            let cur = run[at];
            let brk = (prev.is_ascii_lowercase() && cur.is_ascii_uppercase())
                || (prev.is_ascii_uppercase() && cur.is_ascii_uppercase()
                    && run.get(at + 1).is_some_and(|c| c.is_ascii_lowercase())
                    && run.get(at + 2).is_some_and(|c| c.is_ascii_lowercase()))
                || (prev.is_ascii_alphabetic() && cur.is_ascii_digit())
                || (prev.is_ascii_digit() && cur.is_ascii_alphabetic());
            if brk {
                pieces.push(run[piece_start..at].iter().collect());
                piece_start = at;
            }
        }
        pieces.push(run[piece_start..].iter().collect());
        for piece in pieces {
            let folded = casefold(&piece);
            let stem = &folded[..folded.len().saturating_sub(1)];
            if folded.len() > 1 && folded.ends_with('s') && RISK_TOKENS.contains(&stem) {
                found.insert(stem.to_string());
            }
            found.insert(folded);
        }
    }
    found
}

/// One path's membership in `_risk_matches` (the set form is a pure
/// per-path predicate; the rows of a scan are judged one by one).
pub fn risk_match_one(path: &str) -> bool {
    if structural_risk(path) {
        return true;
    }
    if conditional_manifest(path) || risk_exempt(path) {
        return false;
    }
    let mut tokens = BTreeSet::new();
    for segment in path.split('/') {
        if !segment.is_empty() && segment != "." {
            tokens.extend(path_tokens(segment));
        }
    }
    tokens.iter().any(|token| RISK_TOKENS.contains(&token.as_str()))
}

/// `_risk_matches`: sorted unique paths matching a risk pattern. Pure.
pub fn risk_matches(paths: &[String]) -> Vec<String> {
    let mut matches = BTreeSet::new();
    for path in paths {
        if risk_match_one(path) {
            matches.insert(path.clone());
        }
    }
    matches.into_iter().collect()
}

/// `fnmatch.fnmatchcase` for the gate's two globs (and the general shape:
/// `*`, `?`, and `[...]` classes, matched over the whole string).
fn fnmatch_case(name: &str, pattern: &str) -> bool {
    fn inner(name: &[char], pattern: &[char]) -> bool {
        if pattern.is_empty() {
            return name.is_empty();
        }
        match pattern[0] {
            '*' => {
                for skip in 0..=name.len() {
                    if inner(&name[skip..], &pattern[1..]) {
                        return true;
                    }
                }
                false
            }
            '?' => !name.is_empty() && inner(&name[1..], &pattern[1..]),
            '[' => {
                if name.is_empty() {
                    return false;
                }
                let mut at = 1;
                let negate = pattern.get(at) == Some(&'!');
                if negate {
                    at += 1;
                }
                let mut matched = false;
                let mut first = true;
                while at < pattern.len() && (pattern[at] != ']' || first) {
                    first = false;
                    if at + 2 < pattern.len() && pattern[at + 1] == '-' && pattern[at + 2] != ']' {
                        if pattern[at] <= name[0] && name[0] <= pattern[at + 2] {
                            matched = true;
                        }
                        at += 3;
                    } else {
                        if pattern[at] == name[0] {
                            matched = true;
                        }
                        at += 1;
                    }
                }
                if at >= pattern.len() {
                    // No closing bracket: '[' is a literal.
                    return name[0] == '[' && inner(&name[1..], &pattern[1..]);
                }
                if matched != negate {
                    inner(&name[1..], &pattern[at + 1..])
                } else {
                    false
                }
            }
            c => !name.is_empty() && name[0] == c && inner(&name[1..], &pattern[1..]),
        }
    }
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    inner(&name, &pattern)
}

// ---------------------------------------------------------------------------
// Manifest signatures. A signature is the metadata-stripped manifest,
// dumped the way Python's json.dumps dumps the stripped structure; two
// signatures compare as strings. None is unreadable — fail closed, the
// file counts as a dependency change. Only equality is ever consumed,
// plus the current tree's signature string itself.

#[derive(Clone, PartialEq, Debug)]
enum Value {
    Null,
    Bool(bool),
    /// A JSON/TOML integer as its normalized decimal string (arbitrary
    /// precision, like a Python int).
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Dict(Vec<(String, Value)>),
    /// A TOML date/time: json.dumps cannot serialize it, so any that
    /// survives metadata stripping voids the signature, like Python's.
    DateTime,
}

const METADATA_KEYS: [&str; 8] = [
    "name", "version", "description", "license", "authors", "keywords",
    "homepage", "repository",
];
const KEEP_TABLES: &[&str] = &[
    "dependencies", "devdependencies", "optionaldependencies",
    "peerdependencies", "bundledependencies", "bundleddependencies",
    "dev-dependencies", "optional-dependencies", "peer-dependencies",
    "scripts", "overrides", "resolutions", "require", "require-dev",
    "install_requires", "setup_requires", "tests_require", "extras_require",
    "dev-packages",
];

fn keep_table(folded_key: &str) -> bool {
    KEEP_TABLES.contains(&folded_key) || folded_key.contains("dependenc")
}

/// `_strip_metadata`: drop metadata keys except inside a dependency or
/// script table; drop containers the stripping emptied.
fn strip_metadata(value: Value, keep: bool) -> Value {
    match value {
        Value::Dict(entries) => {
            let mut out = Vec::new();
            for (key, item) in entries {
                let folded = casefold(&key);
                if !keep && METADATA_KEYS.contains(&folded.as_str()) {
                    continue;
                }
                let child = strip_metadata(item, keep || keep_table(&folded));
                if matches!(&child, Value::Dict(items) if items.is_empty())
                    || matches!(&child, Value::List(items) if items.is_empty())
                {
                    continue;
                }
                out.push((key, child));
            }
            Value::Dict(out)
        }
        Value::List(items) => {
            let mut out = Vec::new();
            for item in items {
                let child = strip_metadata(item, keep);
                if matches!(&child, Value::Dict(entries) if entries.is_empty())
                    || matches!(&child, Value::List(entries) if entries.is_empty())
                {
                    continue;
                }
                out.push(child);
            }
            Value::List(out)
        }
        other => other,
    }
}

/// Python's float repr (as json.dumps and repr both use; the caller picks
/// the spelling of infinity/NaN).
fn py_float_repr(value: f64, json_words: bool) -> String {
    if value.is_nan() {
        return if json_words { "NaN".into() } else { "nan".into() };
    }
    if value.is_infinite() {
        return match (value > 0.0, json_words) {
            (true, true) => "Infinity".into(),
            (false, true) => "-Infinity".into(),
            (true, false) => "inf".into(),
            (false, false) => "-inf".into(),
        };
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("float exponent");
    let exponent: i32 = exponent.parse().expect("float exponent value");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let mut out = String::new();
    if value < 0.0 {
        out.push('-');
    }
    if (-4..16).contains(&exponent) {
        let point = exponent + 1;
        if point <= 0 {
            out.push_str("0.");
            for _ in 0..(-point) {
                out.push('0');
            }
            out.push_str(&digits);
        } else if point as usize >= digits.len() {
            out.push_str(&digits);
            for _ in 0..(point as usize - digits.len()) {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            out.push_str(&digits[..point as usize]);
            out.push('.');
            out.push_str(&digits[point as usize..]);
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push_str(&format!("{exponent:+03}"));
    }
    out
}

/// json.dumps string escaping with ensure_ascii (the default).
fn json_escape(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if ('\u{20}'..='\u{7e}').contains(&c) => out.push(c),
            c if (c as u32) <= 0xFFFF => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => {
                let n = c as u32 - 0x10000;
                out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xD800 + (n >> 10), 0xDC00 + (n & 0x3FF)));
            }
        }
    }
    out.push('"');
}

/// json.dumps of a stripped value; Err when a DateTime survives (Python's
/// dumps raises TypeError there, which `_dump_signature` turns into None).
fn dump_json(value: &Value, compact: bool, out: &mut String) -> Result<(), ()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(text) => out.push_str(text),
        Value::Float(number) => out.push_str(&py_float_repr(*number, true)),
        Value::Str(text) => json_escape(text, out),
        Value::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(if compact { "," } else { ", " });
                }
                dump_json(item, compact, out)?;
            }
            out.push(']');
        }
        Value::Dict(entries) => {
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (index, (key, item)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push_str(if compact { "," } else { ", " });
                }
                json_escape(key, out);
                out.push_str(if compact { ":" } else { ": " });
                dump_json(item, compact, out)?;
            }
            out.push('}');
        }
        Value::DateTime => return Err(()),
    }
    Ok(())
}

/// `_dump_signature`: "" for a non-dict or emptied structure, the dump
/// otherwise, None when the dump fails.
fn dump_signature(value: &Value) -> Option<String> {
    match value {
        Value::Dict(entries) if !entries.is_empty() => {
            let mut out = String::new();
            dump_json(value, true, &mut out).ok()?;
            Some(out)
        }
        _ => Some(String::new()),
    }
}

// ---------------------------------------------------------------------------
// JSON (Python's json.loads, including its NaN/Infinity extensions and
// last-duplicate-key rule; a lone surrogate escape is unreadable here —
// Python keeps it, so this fails closed where Python would sign).

struct JsonParser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl JsonParser {
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn value(&mut self) -> Option<Value> {
        self.depth += 1;
        if self.depth > 200 {
            return None;
        }
        let result = self.value_inner();
        self.depth -= 1;
        result
    }

    fn value_inner(&mut self) -> Option<Value> {
        self.skip_ws();
        match self.peek()? {
            '{' => {
                self.pos += 1;
                let mut entries: Vec<(String, Value)> = Vec::new();
                self.skip_ws();
                if self.peek() == Some('}') {
                    self.pos += 1;
                    return Some(Value::Dict(entries));
                }
                loop {
                    self.skip_ws();
                    let key = match self.string()? {
                        Value::Str(text) => text,
                        _ => return None,
                    };
                    self.skip_ws();
                    if self.peek() != Some(':') {
                        return None;
                    }
                    self.pos += 1;
                    let item = self.value()?;
                    if let Some(slot) = entries.iter_mut().find(|(name, _)| *name == key) {
                        slot.1 = item;
                    } else {
                        entries.push((key, item));
                    }
                    self.skip_ws();
                    match self.peek()? {
                        ',' => {
                            self.pos += 1;
                        }
                        '}' => {
                            self.pos += 1;
                            return Some(Value::Dict(entries));
                        }
                        _ => return None,
                    }
                }
            }
            '[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(']') {
                    self.pos += 1;
                    return Some(Value::List(items));
                }
                loop {
                    items.push(self.value()?);
                    self.skip_ws();
                    match self.peek()? {
                        ',' => {
                            self.pos += 1;
                        }
                        ']' => {
                            self.pos += 1;
                            return Some(Value::List(items));
                        }
                        _ => return None,
                    }
                }
            }
            '"' => self.string(),
            't' => self.literal("true", Value::Bool(true)),
            'f' => self.literal("false", Value::Bool(false)),
            'n' => self.literal("null", Value::Null),
            'N' => self.literal("NaN", Value::Float(f64::NAN)),
            'I' => self.literal("Infinity", Value::Float(f64::INFINITY)),
            '-' => {
                if self.chars[self.pos..].iter().collect::<String>().starts_with("-Infinity") {
                    self.pos += 9;
                    Some(Value::Float(f64::NEG_INFINITY))
                } else {
                    self.number()
                }
            }
            c if c.is_ascii_digit() => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Option<Value> {
        if self.chars[self.pos..].iter().collect::<String>().starts_with(word) {
            self.pos += word.chars().count();
            Some(value)
        } else {
            None
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        match self.peek()? {
            '0' => {
                self.pos += 1;
            }
            c if c.is_ascii_digit() => {
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return None,
        }
        let mut is_float = false;
        if self.peek() == Some('.') {
            is_float = true;
            self.pos += 1;
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return None;
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return None;
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let lexeme: String = self.chars[start..self.pos].iter().collect();
        if is_float {
            lexeme.parse::<f64>().ok().map(Value::Float)
        } else if lexeme == "-0" {
            Some(Value::Int("0".into()))
        } else {
            Some(Value::Int(lexeme))
        }
    }

    fn string(&mut self) -> Option<Value> {
        if self.peek() != Some('"') {
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.pos += 1;
            match c {
                '"' => return Some(Value::Str(out)),
                '\\' => {
                    let esc = self.peek()?;
                    self.pos += 1;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let first = self.hex4()?;
                            if (0xD800..0xDC00).contains(&first) {
                                if self.peek() == Some('\\') && self.chars.get(self.pos + 1) == Some(&'u') {
                                    self.pos += 2;
                                    let second = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&second) {
                                        let n = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                                        out.push(char::from_u32(n)?);
                                    } else {
                                        return None; // a lone surrogate fails closed
                                    }
                                } else {
                                    return None;
                                }
                            } else if (0xDC00..0xE000).contains(&first) {
                                return None;
                            } else {
                                out.push(char::from_u32(first)?);
                            }
                        }
                        _ => return None,
                    }
                }
                c if (c as u32) < 0x20 => return None,
                c => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self.peek()?;
            self.pos += 1;
            value = value * 16 + c.to_digit(16)?;
        }
        Some(value)
    }
}

fn json_signature(text: &str) -> Option<String> {
    let mut parser = JsonParser { chars: text.chars().collect(), pos: 0, depth: 0 };
    let data = parser.value()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return None;
    }
    if !matches!(data, Value::Dict(_)) {
        return None;
    }
    dump_signature(&strip_metadata(data, false))
}

// ---------------------------------------------------------------------------
// TOML (tomllib): the manifest subset — keyvals, [table] and [[array]]
// headers, dotted keys, strings (basic/literal, single/multi-line),
// integers, floats, booleans, dates (a DateTime marker: the JSON dump of
// a surviving one fails, exactly like Python's), arrays, inline tables.
// Redefinition rules follow TOML: a key or table defined twice, or a
// dotted-key table later opened by a header, is unreadable.

#[derive(Clone, Copy, PartialEq)]
enum TKind {
    Root,
    Explicit,
    Implicit,
    Dotted,
}

enum TNode {
    Leaf(Value),
    Table(TTable),
    ArrTab(Vec<TTable>),
}

struct TTable {
    entries: Vec<(String, TNode)>,
    kind: TKind,
}

impl TTable {
    fn new(kind: TKind) -> Self {
        TTable { entries: Vec::new(), kind }
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut TNode> {
        self.entries.iter_mut().find(|(name, _)| name == key).map(|(_, node)| node)
    }

    /// Descend into the table at `key` for a keyval's dotted path,
    /// creating a Dotted table when absent.
    fn descend_keyval(&mut self, key: &str) -> Option<&mut TTable> {
        if self.get_mut(key).is_none() {
            self.entries.push((key.to_string(), TNode::Table(TTable::new(TKind::Dotted))));
        }
        match self.get_mut(key)? {
            TNode::Table(table) => Some(table),
            TNode::ArrTab(items) => items.last_mut(),
            TNode::Leaf(_) => None,
        }
    }

    fn into_value(self) -> Value {
        let mut out = Vec::new();
        for (key, node) in self.entries {
            let value = match node {
                TNode::Leaf(value) => value,
                TNode::Table(table) => table.into_value(),
                TNode::ArrTab(items) => {
                    Value::List(items.into_iter().map(|table| table.into_value()).collect())
                }
            };
            out.push((key, value));
        }
        Value::Dict(out)
    }
}

struct TomlParser {
    chars: Vec<char>,
    pos: usize,
}

impl TomlParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn skip_inline_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.pos += 1;
        }
    }

    /// Whitespace, comments, and newlines between statements / in arrays.
    fn skip_filler(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\n' | '\r') => {
                    self.pos += 1;
                }
                Some('#') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn end_of_statement(&mut self) -> Option<()> {
        self.skip_inline_ws();
        match self.peek() {
            None => Some(()),
            Some('\n') => {
                self.pos += 1;
                Some(())
            }
            Some('\r') if self.peek_at(1) == Some('\n') => {
                self.pos += 2;
                Some(())
            }
            Some('#') => {
                while let Some(c) = self.peek() {
                    if c == '\n' {
                        break;
                    }
                    self.pos += 1;
                }
                self.end_of_statement()
            }
            _ => None,
        }
    }

    fn document(&mut self) -> Option<TTable> {
        let mut root = TTable::new(TKind::Root);
        let mut current: Vec<String> = Vec::new();
        loop {
            self.skip_filler();
            match self.peek() {
                None => return Some(root),
                Some('[') => {
                    let array = self.peek_at(1) == Some('[');
                    self.pos += if array { 2 } else { 1 };
                    let key = self.dotted_key()?;
                    self.skip_inline_ws();
                    if array {
                        if !(self.peek() == Some(']') && self.peek_at(1) == Some(']')) {
                            return None;
                        }
                        self.pos += 2;
                        apply_header(&mut root, &key, true)?;
                    } else {
                        if self.peek() != Some(']') {
                            return None;
                        }
                        self.pos += 1;
                        apply_header(&mut root, &key, false)?;
                    }
                    current = key;
                    self.end_of_statement()?;
                }
                Some(_) => {
                    let key = self.dotted_key()?;
                    self.skip_inline_ws();
                    if self.peek() != Some('=') {
                        return None;
                    }
                    self.pos += 1;
                    self.skip_inline_ws();
                    let value = self.value(false)?;
                    let table = resolve_table(&mut root, &current)?;
                    apply_keyval(table, &key, value)?;
                    self.end_of_statement()?;
                }
            }
        }
    }

    /// A dotted key: bare or quoted parts separated by `.`.
    fn dotted_key(&mut self) -> Option<Vec<String>> {
        let mut parts = Vec::new();
        loop {
            self.skip_inline_ws();
            let part = match self.peek()? {
                '"' => match self.basic_string()? {
                    Value::Str(text) => text,
                    _ => return None,
                },
                '\'' => self.literal_string(false)?,
                _ => {
                    let start = self.pos;
                    while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                        self.pos += 1;
                    }
                    if self.pos == start {
                        return None;
                    }
                    self.chars[start..self.pos].iter().collect()
                }
            };
            parts.push(part);
            self.skip_inline_ws();
            if self.peek() == Some('.') {
                self.pos += 1;
            } else {
                return Some(parts);
            }
        }
    }

    fn value(&mut self, inline: bool) -> Option<Value> {
        match self.peek()? {
            '"' => self.basic_string(),
            '\'' => self.literal_string(true).map(Value::Str),
            '[' => self.array(inline),
            '{' => self.inline_table(),
            _ => self.bare_value(),
        }
    }

    fn basic_string(&mut self) -> Option<Value> {
        // chars[pos] == '"'
        let triple = self.peek_at(1) == Some('"') && self.peek_at(2) == Some('"');
        let mut out = String::new();
        if triple {
            self.pos += 3;
            if self.peek() == Some('\n') {
                self.pos += 1;
            } else if self.peek() == Some('\r') && self.peek_at(1) == Some('\n') {
                self.pos += 2;
            }
            loop {
                let c = self.peek()?;
                if c == '"' && self.peek_at(1) == Some('"') && self.peek_at(2) == Some('"') {
                    self.pos += 3;
                    // Up to two more quotes belong to the content.
                    for _ in 0..2 {
                        if self.peek() == Some('"') {
                            out.push('"');
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    return Some(Value::Str(out));
                }
                if c == '\\' {
                    // A line-ending backslash trims all whitespace up to
                    // the next content character.
                    let mut scan = self.pos + 1;
                    let mut probe = scan;
                    while matches!(self.chars.get(probe), Some(' ' | '\t' | '\n' | '\r')) {
                        probe += 1;
                    }
                    if probe > scan && self.chars[scan..probe].iter().any(|c| *c == '\n' || *c == '\r') {
                        self.pos = probe;
                        continue;
                    }
                    scan += 1;
                    self.pos = scan;
                    out.push(self.escape()?);
                    continue;
                }
                out.push(c);
                self.pos += 1;
            }
        }
        self.pos += 1;
        loop {
            let c = self.peek()?;
            if c == '"' {
                self.pos += 1;
                return Some(Value::Str(out));
            }
            if c == '\n' || c == '\r' {
                return None;
            }
            if c == '\\' {
                self.pos += 1;
                out.push(self.escape()?);
                continue;
            }
            out.push(c);
            self.pos += 1;
        }
    }

    fn escape(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        match c {
            'b' => Some('\u{8}'),
            't' => Some('\t'),
            'n' => Some('\n'),
            'f' => Some('\u{c}'),
            'r' => Some('\r'),
            '"' => Some('"'),
            '\\' => Some('\\'),
            'u' => {
                let n = self.hex(4)?;
                char::from_u32(n)
            }
            'U' => {
                let n = self.hex(8)?;
                char::from_u32(n)
            }
            _ => None,
        }
    }

    fn hex(&mut self, digits: usize) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..digits {
            let c = self.peek()?;
            self.pos += 1;
            value = value.checked_mul(16)?.checked_add(c.to_digit(16)?)?;
        }
        Some(value)
    }

    fn literal_string(&mut self, as_value: bool) -> Option<String> {
        let _ = as_value;
        let triple = self.peek_at(1) == Some('\'') && self.peek_at(2) == Some('\'');
        let mut out = String::new();
        if triple {
            self.pos += 3;
            if self.peek() == Some('\n') {
                self.pos += 1;
            } else if self.peek() == Some('\r') && self.peek_at(1) == Some('\n') {
                self.pos += 2;
            }
            loop {
                let c = self.peek()?;
                if c == '\'' && self.peek_at(1) == Some('\'') && self.peek_at(2) == Some('\'') {
                    self.pos += 3;
                    for _ in 0..2 {
                        if self.peek() == Some('\'') {
                            out.push('\'');
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    return Some(out);
                }
                out.push(c);
                self.pos += 1;
            }
        }
        self.pos += 1;
        loop {
            let c = self.peek()?;
            if c == '\'' {
                self.pos += 1;
                return Some(out);
            }
            if c == '\n' || c == '\r' {
                return None;
            }
            out.push(c);
            self.pos += 1;
        }
    }

    fn array(&mut self, inline: bool) -> Option<Value> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        loop {
            if inline {
                self.skip_inline_ws();
                if self.peek() == Some('\n') || self.peek() == Some('#') {
                    return None;
                }
            } else {
                self.skip_filler();
            }
            if self.peek() == Some(']') {
                self.pos += 1;
                return Some(Value::List(items));
            }
            items.push(self.value(inline)?);
            if inline {
                self.skip_inline_ws();
            } else {
                self.skip_filler();
            }
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some(']') => {
                    self.pos += 1;
                    return Some(Value::List(items));
                }
                _ => return None,
            }
        }
    }

    fn inline_table(&mut self) -> Option<Value> {
        self.pos += 1; // '{'
        let mut table = TTable::new(TKind::Dotted);
        self.skip_inline_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Some(table.into_value());
        }
        loop {
            let key = self.dotted_key()?;
            self.skip_inline_ws();
            if self.peek() != Some('=') {
                return None;
            }
            self.pos += 1;
            self.skip_inline_ws();
            let value = self.value(true)?;
            apply_keyval(&mut table, &key, value)?;
            self.skip_inline_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                    self.skip_inline_ws();
                }
                Some('}') => {
                    self.pos += 1;
                    return Some(table.into_value());
                }
                _ => return None,
            }
        }
    }

    fn bare_value(&mut self) -> Option<Value> {
        let rest: String = self.chars[self.pos..].iter().collect();
        for (word, value) in [("true", Value::Bool(true)), ("false", Value::Bool(false))] {
            if rest.starts_with(word)
                && rest[word.len()..].chars().next().is_none_or(|c| " \t\n\r,]}#".contains(c))
            {
                self.pos += word.len();
                return Some(value);
            }
        }
        // Dates and times keep their shape in one token (a space may
        // separate a date from its time).
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | ':' | '.')) {
            self.pos += 1;
        }
        let mut token: String = self.chars[start..self.pos].iter().collect();
        if is_date_token(&token) {
            if matches!(self.peek(), Some('T' | 't')) {
                self.pos += 1;
                let at = self.pos;
                while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '+' | '-' | 'Z' | 'z')) {
                    self.pos += 1;
                }
                token.push('T');
                token.extend(&self.chars[at..self.pos]);
            } else if self.peek() == Some(' ')
                && self.peek_at(1).is_some_and(|c| c.is_ascii_digit())
                && self.peek_at(3) == Some(':')
            {
                self.pos += 1;
                let at = self.pos;
                while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '+' | '-' | 'Z' | 'z')) {
                    self.pos += 1;
                }
                token.push(' ');
                token.extend(&self.chars[at..self.pos]);
            }
            return Some(Value::DateTime);
        }
        if is_time_token(&token) {
            return Some(Value::DateTime);
        }
        number_value(&token)
    }
}

fn is_date_token(token: &str) -> bool {
    let b: Vec<char> = token.chars().collect();
    b.len() == 10
        && b[4] == '-'
        && b[7] == '-'
        && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

fn is_time_token(token: &str) -> bool {
    let b: Vec<char> = token.chars().collect();
    b.len() >= 8
        && b[2] == ':'
        && b[5] == ':'
        && [0usize, 1, 3, 4, 6, 7].iter().all(|i| b[*i].is_ascii_digit())
}

/// A TOML number (sign, base prefixes, underscores) as an Int decimal
/// string or a Float, with tomllib's validity rules on the shape.
fn number_value(token: &str) -> Option<Value> {
    if token.is_empty() {
        return None;
    }
    match token {
        "inf" | "+inf" => return Some(Value::Float(f64::INFINITY)),
        "-inf" => return Some(Value::Float(f64::NEG_INFINITY)),
        "nan" | "+nan" | "-nan" => return Some(Value::Float(f64::NAN)),
        _ => {}
    }
    // Underscores must sit between digits (or hex digits).
    let chars: Vec<char> = token.chars().collect();
    for (index, c) in chars.iter().enumerate() {
        if *c == '_' {
            let prev = chars.get(index.wrapping_sub(1));
            let next = chars.get(index + 1);
            if !prev.is_some_and(|p| p.is_ascii_alphanumeric()) || !next.is_some_and(|n| n.is_ascii_alphanumeric()) {
                return None;
            }
        }
    }
    let cleaned: String = token.chars().filter(|c| *c != '_').collect();
    let (sign, body) = match cleaned.strip_prefix('-') {
        Some(rest) => (-1i128, rest),
        None => (1i128, cleaned.strip_prefix('+').unwrap_or(&cleaned)),
    };
    for (prefix, radix) in [("0x", 16u32), ("0o", 8), ("0b", 2)] {
        if let Some(digits) = body.strip_prefix(prefix) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            let magnitude = i128::from_str_radix(digits, radix).ok()?;
            let value = sign * magnitude;
            if value < i64::MIN as i128 || value > i64::MAX as i128 {
                return None;
            }
            return Some(Value::Int(value.to_string()));
        }
    }
    let is_float = body.contains('.') || body.contains('e') || body.contains('E');
    if is_float {
        if body.ends_with('.') || body.contains(".e") || body.contains(".E") {
            return None;
        }
        let int_part = body.split(['.', 'e', 'E']).next().unwrap_or("");
        if int_part.len() > 1 && int_part.starts_with('0') {
            return None;
        }
        return cleaned.parse::<f64>().ok().map(Value::Float);
    }
    if body.len() > 1 && body.starts_with('0') {
        return None; // leading zeros are invalid TOML
    }
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let magnitude: i128 = body.parse().ok()?;
    let value = sign * magnitude;
    if value < i64::MIN as i128 || value > i64::MAX as i128 {
        return None;
    }
    Some(Value::Int(value.to_string()))
}

/// Resolve the table a path names, following arrays of tables into their
/// last element.
fn resolve_table<'a>(table: &'a mut TTable, path: &[String]) -> Option<&'a mut TTable> {
    let mut current = table;
    for part in path {
        if current.get_mut(part).is_none() {
            return None;
        }
        current = match current.get_mut(part)? {
            TNode::Table(inner) => inner,
            TNode::ArrTab(items) => items.last_mut()?,
            TNode::Leaf(_) => return None,
        };
    }
    Some(current)
}

fn apply_keyval(table: &mut TTable, key: &[String], value: Value) -> Option<()> {
    let mut current = table;
    for part in &key[..key.len() - 1] {
        current = current.descend_keyval(part)?;
    }
    let last = &key[key.len() - 1];
    if current.get_mut(last).is_some() {
        return None; // a key defined twice
    }
    current.entries.push((last.clone(), TNode::Leaf(value)));
    Some(())
}

fn apply_header(root: &mut TTable, key: &[String], array: bool) -> Option<()> {
    let mut current = root;
    for part in &key[..key.len() - 1] {
        if current.get_mut(part).is_none() {
            current.entries.push((part.clone(), TNode::Table(TTable::new(TKind::Implicit))));
        }
        current = match current.get_mut(part)? {
            TNode::Table(inner) => {
                if inner.kind == TKind::Dotted {
                    return None; // a dotted-key table cannot be reopened
                }
                inner
            }
            TNode::ArrTab(items) => items.last_mut()?,
            TNode::Leaf(_) => return None,
        };
    }
    let last = &key[key.len() - 1];
    if array {
        if current.get_mut(last).is_none() {
            current.entries.push((last.clone(), TNode::ArrTab(vec![TTable::new(TKind::Explicit)])));
            return Some(());
        }
        return match current.get_mut(last)? {
            TNode::ArrTab(items) => {
                items.push(TTable::new(TKind::Explicit));
                Some(())
            }
            _ => None,
        };
    }
    if current.get_mut(last).is_none() {
        current.entries.push((last.clone(), TNode::Table(TTable::new(TKind::Explicit))));
        return Some(());
    }
    match current.get_mut(last)? {
        TNode::Table(inner) if inner.kind == TKind::Implicit => {
            inner.kind = TKind::Explicit;
            Some(())
        }
        _ => None,
    }
}

fn toml_signature(text: &str) -> Option<String> {
    let mut parser = TomlParser { chars: text.chars().collect(), pos: 0 };
    let root = parser.document()?;
    parser.skip_filler();
    if parser.pos != parser.chars.len() {
        return None;
    }
    dump_signature(&strip_metadata(root.into_value(), false))
}

// ---------------------------------------------------------------------------
// XML (ElementTree subset): elements, attributes, text before the first
// child (tails are ignored, like the Python port reads them), comments /
// PIs dropped, CDATA as text, entity and character references, and
// namespace resolution for tags/attributes (xmlns declarations are not
// attributes). Kept-tree shape follows _xml_kept / _xml_full exactly:
// local tag names, casefolded reference/metadata matching, sorted local
// attribute pairs, and empty elements dropped.

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

#[derive(Clone)]
struct XmlElem {
    tag: String,
    attrib: Vec<(String, String)>,
    text: String,
    children: Vec<XmlElem>,
}

#[derive(Clone)]
struct NsScope {
    map: Vec<(String, String)>, // prefix -> uri; "" is the default namespace
}

impl NsScope {
    fn lookup(&self, prefix: &str) -> Option<&str> {
        self.map.iter().rev().find(|(p, _)| p == prefix).map(|(_, uri)| uri.as_str())
    }
}

fn xml_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == ':' || (c as u32) >= 0x80
}

fn xml_name_char(c: char) -> bool {
    xml_name_start(c) || c.is_ascii_digit() || c == '-' || c == '.'
}

fn xml_char_ok(code: u32) -> bool {
    matches!(code, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

struct XmlParser {
    chars: Vec<char>,
    pos: usize,
}

impl XmlParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn starts_with(&self, text: &str) -> bool {
        text.chars().enumerate().all(|(i, c)| self.chars.get(self.pos + i) == Some(&c))
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn skip_comment(&mut self) -> Option<()> {
        // At "<!--": content may not contain "--".
        self.pos += 4;
        loop {
            if self.peek().is_none() {
                return None;
            }
            if self.starts_with("-->") {
                self.pos += 3;
                return Some(());
            }
            if self.starts_with("--") {
                return None;
            }
            self.pos += 1;
        }
    }

    fn skip_pi(&mut self) -> Option<()> {
        // At "<?": runs to "?>". "<?xml" is only the declaration at pos 0.
        if self.starts_with("<?xml") && self.pos != 0 {
            return None;
        }
        self.pos += 2;
        loop {
            if self.peek().is_none() {
                return None;
            }
            if self.starts_with("?>") {
                self.pos += 2;
                return Some(());
            }
            self.pos += 1;
        }
    }

    fn skip_doctype(&mut self) -> Option<()> {
        // At "<!DOCTYPE": runs to '>' outside any [ ] internal subset.
        self.pos += 9;
        let mut depth = 0i32;
        loop {
            match self.peek()? {
                '[' => depth += 1,
                ']' => depth -= 1,
                '>' if depth <= 0 => {
                    self.pos += 1;
                    return Some(());
                }
                _ => {}
            }
            self.pos += 1;
        }
    }

    /// Whitespace, comments, PIs and the DOCTYPE around the root element.
    fn skip_misc(&mut self) -> Option<()> {
        loop {
            self.skip_ws();
            if self.starts_with("<!--") {
                self.skip_comment()?;
            } else if self.starts_with("<?") {
                self.skip_pi()?;
            } else if self.starts_with("<!DOCTYPE") {
                self.skip_doctype()?;
            } else {
                return Some(());
            }
        }
    }

    fn name(&mut self) -> Option<String> {
        let first = self.peek()?;
        if !xml_name_start(first) {
            return None;
        }
        let start = self.pos;
        self.pos += 1;
        while self.peek().is_some_and(xml_name_char) {
            self.pos += 1;
        }
        Some(self.chars[start..self.pos].iter().collect())
    }

    /// An entity or character reference at '&', decoded.
    fn reference(&mut self) -> Option<char> {
        self.pos += 1; // '&'
        if self.peek() == Some('#') {
            self.pos += 1;
            let (digits, radix) = if matches!(self.peek(), Some('x' | 'X')) {
                self.pos += 1;
                let start = self.pos;
                while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                    self.pos += 1;
                }
                (self.chars[start..self.pos].iter().collect::<String>(), 16)
            } else {
                let start = self.pos;
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.pos += 1;
                }
                (self.chars[start..self.pos].iter().collect::<String>(), 10)
            };
            if digits.is_empty() || self.peek() != Some(';') {
                return None;
            }
            self.pos += 1;
            let code = u32::from_str_radix(&digits, radix).ok()?;
            if !xml_char_ok(code) {
                return None;
            }
            return char::from_u32(code);
        }
        let name = self.name()?;
        if self.peek() != Some(';') {
            return None;
        }
        self.pos += 1;
        match name.as_str() {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "apos" => Some('\''),
            "quot" => Some('"'),
            _ => None, // undeclared entity
        }
    }

    /// Text content until the next '<' (references decoded).
    fn text_run(&mut self) -> Option<String> {
        let mut out = String::new();
        loop {
            match self.peek()? {
                '<' => return Some(out),
                '&' => out.push(self.reference()?),
                c => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn attr_value(&mut self) -> Option<String> {
        let quote = self.peek()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.peek()? {
                c if c == quote => {
                    self.pos += 1;
                    return Some(out);
                }
                '<' => return None,
                '&' => out.push(self.reference()?),
                // Literal whitespace in attribute values normalizes to
                // spaces (tab/newline), per the XML specification.
                '\t' | '\n' => {
                    out.push(' ');
                    self.pos += 1;
                }
                '\r' => {
                    out.push(' ');
                    self.pos += 1;
                    if self.peek() == Some('\n') {
                        self.pos += 1;
                    }
                }
                c => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn resolve(scope: &NsScope, raw: &str, is_attr: bool) -> Option<String> {
        if let Some((prefix, local)) = raw.split_once(':') {
            if prefix == "xmlns" || local.contains(':') {
                return None;
            }
            if prefix == "xml" {
                return Some(format!("{{{XML_NS}}}{local}"));
            }
            let uri = scope.lookup(prefix)?;
            Some(format!("{{{uri}}}{local}"))
        } else if is_attr {
            Some(raw.to_string()) // unprefixed attributes have no namespace
        } else {
            match scope.lookup("") {
                Some(uri) if !uri.is_empty() => Some(format!("{{{uri}}}{raw}")),
                _ => Some(raw.to_string()),
            }
        }
    }

    fn element(&mut self, parent: &NsScope) -> Option<XmlElem> {
        if self.peek() != Some('<') {
            return None;
        }
        self.pos += 1;
        let raw_tag = self.name()?;
        let mut raw_attrs: Vec<(String, String)> = Vec::new();
        let empty = loop {
            self.skip_ws();
            match self.peek()? {
                '/' => {
                    self.pos += 1;
                    if self.peek() != Some('>') {
                        return None;
                    }
                    self.pos += 1;
                    break true;
                }
                '>' => {
                    self.pos += 1;
                    break false;
                }
                _ => {
                    let name = self.name()?;
                    self.skip_ws();
                    if self.peek() != Some('=') {
                        return None;
                    }
                    self.pos += 1;
                    self.skip_ws();
                    let value = self.attr_value()?;
                    if raw_attrs.iter().any(|(n, _)| n == &name) {
                        return None; // duplicate attribute
                    }
                    raw_attrs.push((name, value));
                }
            }
        };
        // This element's own namespace declarations apply to itself.
        let mut scope = parent.clone();
        for (name, value) in &raw_attrs {
            if name == "xmlns" {
                scope.map.push((String::new(), value.clone()));
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                scope.map.push((prefix.to_string(), value.clone()));
            }
        }
        let tag = Self::resolve(&scope, &raw_tag, false)?;
        let mut attrib = Vec::new();
        for (name, value) in &raw_attrs {
            if name == "xmlns" || name.starts_with("xmlns:") {
                continue;
            }
            attrib.push((Self::resolve(&scope, name, true)?, value.clone()));
        }
        if empty {
            return Some(XmlElem { tag, attrib, text: String::new(), children: Vec::new() });
        }
        let mut elem = XmlElem { tag, attrib, text: String::new(), children: Vec::new() };
        let mut seen_child = false;
        loop {
            if self.peek().is_none() {
                return None;
            }
            if self.starts_with("</") {
                self.pos += 2;
                let close = self.name()?;
                self.skip_ws();
                if self.peek() != Some('>') || close != raw_tag {
                    return None;
                }
                self.pos += 1;
                return Some(elem);
            }
            if self.starts_with("<!--") {
                self.skip_comment()?;
                continue;
            }
            if self.starts_with("<![CDATA[") {
                self.pos += 9;
                let start = self.pos;
                loop {
                    if self.peek().is_none() {
                        return None;
                    }
                    if self.starts_with("]]>") {
                        break;
                    }
                    self.pos += 1;
                }
                if !seen_child {
                    elem.text.extend(&self.chars[start..self.pos]);
                }
                self.pos += 3;
                continue;
            }
            if self.starts_with("<?") {
                self.skip_pi()?;
                continue;
            }
            if self.peek() == Some('<') {
                let child = self.element(&scope)?;
                elem.children.push(child);
                seen_child = true;
                continue;
            }
            let text = self.text_run()?;
            if !seen_child {
                elem.text.push_str(&text);
            }
        }
    }
}

const XML_REF_FOLDED: [&str; 10] = [
    "packagereference", "projectreference", "reference", "packageversion",
    "import", "exec", "prebuildevent", "postbuildevent", "dependency",
    "package",
];
const XML_METADATA_FOLDED: [&str; 13] = [
    "name", "version", "description", "license", "authors", "keywords",
    "homepage", "repository", "author", "packagelicenseexpression",
    "packageid", "repositoryurl", "packageprojecturl",
];

fn xml_local(tag: &str) -> &str {
    tag.rsplit('}').next().unwrap_or(tag)
}

/// _xml_attrs: (local name, value) pairs, sorted, as a JSON array.
fn xml_attrs(elem: &XmlElem) -> Value {
    let mut pairs: Vec<(String, String)> = elem
        .attrib
        .iter()
        .map(|(key, value)| (xml_local(key).to_string(), value.clone()))
        .collect();
    pairs.sort();
    Value::List(
        pairs
            .into_iter()
            .map(|(key, value)| Value::List(vec![Value::Str(key), Value::Str(value)]))
            .collect(),
    )
}

fn xml_full(elem: &XmlElem) -> Value {
    Value::List(vec![
        Value::Str(xml_local(&elem.tag).to_string()),
        xml_attrs(elem),
        Value::Str(py_ws_normalize(&elem.text)),
        Value::List(elem.children.iter().map(xml_full).collect()),
    ])
}

fn xml_kept(elem: &XmlElem) -> Option<Value> {
    let local = xml_local(&elem.tag);
    let folded = casefold(local);
    if XML_REF_FOLDED.contains(&folded.as_str()) {
        return Some(xml_full(elem));
    }
    if XML_METADATA_FOLDED.contains(&folded.as_str()) {
        return None;
    }
    let children: Vec<Value> = elem.children.iter().filter_map(xml_kept).collect();
    let text = py_ws_normalize(&elem.text);
    let attrs = xml_attrs(elem);
    let attrs_empty = matches!(&attrs, Value::List(items) if items.is_empty());
    if children.is_empty() && text.is_empty() && attrs_empty {
        return None; // an element with nothing kept disappears entirely
    }
    Some(Value::List(vec![
        Value::Str(local.to_string()),
        attrs,
        Value::Str(text),
        Value::List(children),
    ]))
}

fn xml_signature(text: &str) -> Option<String> {
    let mut parser = XmlParser { chars: text.chars().collect(), pos: 0 };
    parser.skip_misc()?;
    let scope = NsScope { map: Vec::new() };
    let root = parser.element(&scope)?;
    parser.skip_misc()?;
    if parser.pos != parser.chars.len() {
        return None;
    }
    match xml_kept(&root) {
        Some(node) => {
            let mut out = String::new();
            dump_json(&node, false, &mut out).ok()?;
            Some(out)
        }
        None => Some(String::new()), // a fully-metadata root signs as absent
    }
}

// ---------------------------------------------------------------------------
// Line signature (setup.cfg / go.mod / Gemfile fall-back form).

fn metadata_line(line: &str) -> bool {
    const KEYS: [&str; 8] = [
        "name", "version", "description", "license", "authors", "keywords",
        "homepage", "repository",
    ];
    let folded: Vec<char> = line.chars().collect();
    for key in KEYS {
        let kchars: Vec<char> = key.chars().collect();
        if folded.len() > kchars.len()
            && folded[..kchars.len()].iter().zip(&kchars).all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            let mut index = kchars.len();
            while folded.get(index).is_some_and(|c| is_py_space(*c)) {
                index += 1;
            }
            if folded.get(index) != Some(&'=') {
                continue;
            }
            index += 1;
            while folded.get(index).is_some_and(|c| is_py_space(*c)) {
                index += 1;
            }
            if folded.get(index).is_some_and(|c| !is_py_space(*c)) {
                return true;
            }
        }
    }
    false
}

fn line_signature(text: &str) -> String {
    py_split_lines(text)
        .iter()
        .map(|line| py_trim(line))
        .filter(|line| !line.is_empty() && !metadata_line(line))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// setup.py: a Python-subset AST builder over the Part 2 token stream,
// rendered exactly like ast.dump. Anything outside the subset fails
// (None) — the signature is then unreadable, which the gate treats as a
// dependency change: wider, never narrower.

use std::fmt::Write as _;

#[derive(Clone, PartialEq)]
enum FVal {
    Null,                                 // an omitted optional field
    Raw(String),                          // pre-rendered text (Constant values, ints)
    Str(String),                          // a plain string field (repr'd)
    List(Vec<FVal>),
    Node(&'static str, Vec<(&'static str, FVal)>),
    Paren(Box<FVal>), // parenthesized expression (transparent, marks AnnAssign)
}

fn fnode(name: &'static str, fields: Vec<(&'static str, FVal)>) -> FVal {
    FVal::Node(name, fields)
}

fn fconst(raw: String) -> FVal {
    fnode("Constant", vec![("value", FVal::Raw(raw))])
}

fn fconst_str(decoded: &str) -> FVal {
    fconst(py_str_repr(decoded))
}

fn fname(id: &str, ctx: &'static str) -> FVal {
    fnode("Name", vec![("id", FVal::Str(id.to_string())), ("ctx", fnode(ctx, vec![]))])
}

fn render_fval(value: &FVal, out: &mut String) {
    match value {
        FVal::Null => out.push_str("None"),
        FVal::Raw(text) => out.push_str(text),
        FVal::Str(text) => out.push_str(&py_str_repr(text)),
        FVal::Paren(inner) => render_fval(inner, out),
        FVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                render_fval(item, out);
            }
            out.push(']');
        }
        FVal::Node(name, fields) => {
            let _ = write!(out, "{name}(");
            let mut first = true;
            for (field, field_value) in fields {
                if *field_value == FVal::Null {
                    continue;
                }
                if !first {
                    out.push_str(", ");
                }
                first = false;
                let _ = write!(out, "{field}=");
                render_fval(field_value, out);
            }
            out.push(')');
        }
    }
}

/// Python repr() of a str: quote choice and escape set.
fn py_str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if py_printable(c) => out.push(c),
            c => {
                let code = c as u32;
                if code < 0x100 {
                    let _ = write!(out, "\\x{code:02x}");
                } else if code < 0x10000 {
                    let _ = write!(out, "\\u{code:04x}");
                } else {
                    let _ = write!(out, "\\U{code:08x}");
                }
            }
        }
    }
    out.push(quote);
    out
}

/// Approximation of str.isprintable: Python counts a character
/// printable when its Unicode category is a letter, mark, number,
/// punctuation, or symbol (space is the only printable separator).
fn py_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    let code = c as u32;
    if c.is_control() {
        return false; // Cc
    }
    if matches!(code, 0x00ad | 0x0600..=0x0605 | 0x061c | 0x06dd | 0x070f | 0x180e
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f
        | 0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x13438
        | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f) {
        return false; // Cf format controls
    }
    if matches!(code, 0x2028 | 0x2029) {
        return false; // Zl / Zp
    }
    if matches!(code, 0x00a0 | 0x1680 | 0x2000..=0x200a | 0x202f | 0x205f | 0x3000) {
        return false; // Zs beyond the plain space
    }
    if matches!(code, 0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x100000..=0x10fffd) {
        return false; // Co private use
    }
    true
}

/// Python repr() of a bytes object.
fn bytes_repr(bytes: &[u8]) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') { b'"' } else { b'\'' };
    let mut out = String::from("b");
    out.push(quote as char);
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b if b == quote => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7e => out.push(byte as char),
            b => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push(quote as char);
    out
}

/// One escape sequence after a backslash in a (non-raw) string body;
/// returns the decoded text and the new cursor.
fn py_escape(chars: &[char], mut index: usize, bytes_mode: bool) -> Option<(String, usize)> {
    let c = *chars.get(index)?;
    index += 1;
    let simple = match c {
        'n' => Some("\n"),
        't' => Some("\t"),
        'r' => Some("\r"),
        'a' => Some("\u{7}"),
        'b' => Some("\u{8}"),
        'f' => Some("\u{c}"),
        'v' => Some("\u{b}"),
        '\\' => Some("\\"),
        '\'' => Some("'"),
        '"' => Some("\""),
        '\n' => Some(""),
        _ => None,
    };
    if let Some(text) = simple {
        return Some((text.to_string(), index));
    }
    if ('0'..='7').contains(&c) {
        let mut value: u32 = c.to_digit(8)?;
        for _ in 0..2 {
            match chars.get(index) {
                Some(d @ '0'..='7') => {
                    value = value * 8 + d.to_digit(8)?;
                    index += 1;
                }
                _ => break,
            }
        }
        if bytes_mode {
            let wrapped = ((value & 0xff) as u8) as char;
            return Some((wrapped.to_string(), index));
        }
        return Some((char::from_u32(value)?.to_string(), index));
    }
    match c {
        'x' => {
            let hi = chars.get(index)?.to_digit(16)?;
            let lo = chars.get(index + 1)?.to_digit(16)?;
            let value = hi * 16 + lo;
            if bytes_mode {
                let wrapped = ((value & 0xff) as u8) as char;
                Some((wrapped.to_string(), index + 2))
            } else {
                Some((char::from_u32(value)?.to_string(), index + 2))
            }
        }
        'u' if !bytes_mode => {
            let mut value = 0u32;
            for offset in 0..4 {
                value = value * 16 + chars.get(index + offset)?.to_digit(16)?;
            }
            Some((char::from_u32(value)?.to_string(), index + 4))
        }
        'U' if !bytes_mode => {
            let mut value = 0u32;
            for offset in 0..8 {
                value = value * 16 + chars.get(index + offset)?.to_digit(16)?;
            }
            if value >= 0x110000 {
                return None;
            }
            Some((char::from_u32(value)?.to_string(), index + 8))
        }
        'N' => None, // named escapes need the Unicode database: fail closed
        _ => Some((format!("\\{c}"), index)), // unknown escapes are kept literally
    }
}

/// Decode a plain string literal body (between the quotes).
fn decode_str_body(body: &[char], raw: bool, bytes_mode: bool) -> Option<Vec<char>> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < body.len() {
        let c = body[index];
        if c == '\\' && !raw {
            let (text, next) = py_escape(body, index + 1, bytes_mode)?;
            for ch in text.chars() {
                out.push(ch);
            }
            index = next;
        } else {
            if bytes_mode && (c as u32) > 0x7f {
                return None; // bytes literals are ASCII only
            }
            out.push(c);
            index += 1;
        }
    }
    Some(out)
}

/// The result of reading one string token: its kind and content.
enum LitValue {
    Str(String),
    Bytes(Vec<u8>),
    FStr, // handled from the token stream, never a single token
}

/// Parse one TokKind::Str token into its decoded value.
fn literal_value(token: &str) -> Option<LitValue> {
    let chars: Vec<char> = token.chars().collect();
    let mut index = 0;
    let mut raw = false;
    let mut bytes_mode = false;
    let mut fstring = false;
    let mut is_u = false;
    while index < chars.len() {
        match chars[index].to_ascii_lowercase() {
            'r' => raw = true,
            'b' => bytes_mode = true,
            'f' => fstring = true,
            'u' => is_u = true,
            _ => break,
        }
        index += 1;
    }
    if is_u && (raw || bytes_mode || fstring) {
        return None;
    }
    if fstring {
        return Some(LitValue::FStr);
    }
    let quote = *chars.get(index)?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let triple = chars.get(index + 1) == Some(&quote) && chars.get(index + 2) == Some(&quote);
    let body_start = index + if triple { 3 } else { 1 };
    let body_end = chars.len().checked_sub(if triple { 3 } else { 1 })?;
    if body_end < body_start {
        return None;
    }
    let decoded = decode_str_body(&chars[body_start..body_end], raw, bytes_mode)?;
    if bytes_mode {
        let mut bytes = Vec::new();
        for c in decoded {
            let code = c as u32;
            if code > 0xff {
                return None;
            }
            bytes.push(code as u8);
        }
        Some(LitValue::Bytes(bytes))
    } else {
        Some(LitValue::Str(decoded.into_iter().collect()))
    }
}

/// Decode raw f-string middle text: brace pairs collapse, escapes run.
fn decode_fstring_middle(raw_text: &str) -> Option<String> {
    let chars: Vec<char> = raw_text.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '{' if chars.get(index + 1) == Some(&'{') => {
                out.push('{');
                index += 2;
            }
            '}' if chars.get(index + 1) == Some(&'}') => {
                out.push('}');
                index += 2;
            }
            '\\' => {
                let (text, next) = py_escape(&chars, index + 1, false)?;
                out.push_str(&text);
                index = next;
            }
            c => {
                out.push(c);
                index += 1;
            }
        }
    }
    Some(out)
}

/// A NUMBER token as its ast Constant rendering (decimal text for ints,
/// repr for floats, `...j` for complex).
fn number_constant(token: &str) -> Option<String> {
    let cleaned: String = token.chars().filter(|c| *c != '_').collect();
    // Underscore placement: single, between digits.
    let raw: Vec<char> = token.chars().collect();
    for (i, c) in raw.iter().enumerate() {
        if *c == '_' {
            let ok = i > 0
                && raw[i - 1].is_ascii_alphanumeric()
                && raw.get(i + 1).is_some_and(|n| n.is_ascii_alphanumeric());
            if !ok {
                return None;
            }
        }
    }
    if let Some(rest) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        return Some(radix_decimal(rest, 16)?);
    }
    if let Some(rest) = cleaned.strip_prefix("0o").or_else(|| cleaned.strip_prefix("0O")) {
        return Some(radix_decimal(rest, 8)?);
    }
    if let Some(rest) = cleaned.strip_prefix("0b").or_else(|| cleaned.strip_prefix("0B")) {
        return Some(radix_decimal(rest, 2)?);
    }
    if let Some(imag) = cleaned.strip_suffix('j').or_else(|| cleaned.strip_suffix('J')) {
        let value: f64 = imag.parse().ok()?;
        return Some(format!("{}j", py_float_repr(value, true)));
    }
    if cleaned.contains(['.', 'e', 'E']) {
        // Float literals tolerate leading zeros (00.5); parse covers rest.
        let value: f64 = cleaned.parse().ok()?;
        return Some(py_float_repr(value, true));
    }
    // Plain decimal integer: leading zeros are a SyntaxError in Python.
    if cleaned.len() > 1 && cleaned.starts_with('0') {
        return None;
    }
    if cleaned.is_empty() || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let trimmed = cleaned.trim_start_matches('0');
    Some(if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() })
}

fn radix_decimal(digits: &str, radix: u32) -> Option<String> {
    if digits.is_empty() {
        return None;
    }
    let mut value: u128 = 0;
    for c in digits.chars() {
        value = value.checked_mul(radix as u128)?.checked_add(c.to_digit(radix)? as u128)?;
    }
    Some(value.to_string())
}

// ---------------------------------------------------------------------------
// The setup.py subset parser proper.

struct AstParser {
    toks: Vec<Tok>,
    pos: usize,
}

fn ctx_load() -> FVal {
    fnode("Load", vec![])
}

fn binop_node(left: FVal, op: &'static str, right: FVal) -> FVal {
    fnode("BinOp", vec![("left", left), ("op", fnode(op, vec![])), ("right", right)])
}

impl AstParser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_at(&self, offset: usize) -> Option<&Tok> {
        self.toks.get(self.pos + offset)
    }

    fn at_op(&self, text: &str) -> bool {
        matches!(self.peek(), Some(Tok { kind: TokKind::Op, text: t }) if t == text)
    }

    fn at_op_at(&self, offset: usize, text: &str) -> bool {
        matches!(self.peek_at(offset), Some(Tok { kind: TokKind::Op, text: t }) if t == text)
    }

    fn at_name(&self, text: &str) -> bool {
        matches!(self.peek(), Some(Tok { kind: TokKind::Name, text: t }) if t == text)
    }

    fn at_kind(&self, kind: &TokKind) -> bool {
        matches!(self.peek(), Some(tok) if &tok.kind == kind)
    }

    fn eat_op(&mut self, text: &str) -> bool {
        if self.at_op(text) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_name(&mut self, text: &str) -> bool {
        if self.at_name(text) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_op(&mut self, text: &str) -> Option<()> {
        if self.eat_op(text) {
            Some(())
        } else {
            None
        }
    }

    fn expect_name(&mut self, text: &str) -> Option<()> {
        if self.eat_name(text) {
            Some(())
        } else {
            None
        }
    }

    /// The next token's text when it is a Name.
    fn name_text(&mut self) -> Option<String> {
        if let Some(Tok { kind: TokKind::Name, text }) = self.peek() {
            let text = text.clone();
            self.pos += 1;
            Some(text)
        } else {
            None
        }
    }

    fn end_of_line(&mut self) {
        if self.at_kind(&TokKind::Newline) {
            self.pos += 1;
        }
    }

    // -- expressions -----------------------------------------------------

    fn parse_expr(&mut self) -> Option<FVal> {
        // Assignment expression: NAME ':=' expr.
        if matches!(self.peek(), Some(Tok { kind: TokKind::Name, .. })) && self.at_op_at(1, ":=") {
            let target = fname(&self.peek()?.text.clone(), "Store");
            self.pos += 2;
            let value = self.parse_expr()?;
            return Some(fnode("NamedExpr", vec![("target", target), ("value", value)]));
        }
        let first = self.parse_or_test()?;
        if self.eat_name("if") {
            let test = self.parse_or_test()?;
            self.expect_name("else")?;
            let orelse = self.parse_expr()?;
            return Some(fnode(
                "IfExp",
                vec![("test", test), ("body", unparen(first)), ("orelse", orelse)],
            ));
        }
        Some(first)
    }

    fn parse_bool_chain(
        &mut self,
        keyword: &str,
        op_name: &'static str,
        next: fn(&mut Self) -> Option<FVal>,
    ) -> Option<FVal> {
        let first = next(self)?;
        if !self.at_name(keyword) {
            return Some(first);
        }
        let mut values = vec![unparen(first)];
        while self.eat_name(keyword) {
            values.push(unparen(next(self)?));
        }
        Some(fnode("BoolOp", vec![("op", fnode(op_name, vec![])), ("values", FVal::List(values))]))
    }

    fn parse_or_test(&mut self) -> Option<FVal> {
        self.parse_bool_chain("or", "Or", Self::parse_and_test)
    }

    fn parse_and_test(&mut self) -> Option<FVal> {
        self.parse_bool_chain("and", "And", Self::parse_not_test)
    }

    fn parse_not_test(&mut self) -> Option<FVal> {
        if self.eat_name("not") {
            let operand = self.parse_not_test()?;
            return Some(fnode("UnaryOp", vec![("op", fnode("Not", vec![])), ("operand", unparen(operand))]));
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Option<FVal> {
        let left = self.parse_bitor()?;
        let mut ops: Vec<FVal> = Vec::new();
        let mut comparators: Vec<FVal> = Vec::new();
        loop {
            let op_name: &'static str = if self.eat_op("<") {
                "Lt"
            } else if self.eat_op(">") {
                "Gt"
            } else if self.eat_op("==") {
                "Eq"
            } else if self.eat_op("!=") {
                "NotEq"
            } else if self.eat_op("<=") {
                "LtE"
            } else if self.eat_op(">=") {
                "GtE"
            } else if self.at_name("not") && matches!(self.peek_at(1), Some(Tok { kind: TokKind::Name, text }) if text == "in") {
                self.pos += 2;
                "NotIn"
            } else if self.eat_name("in") {
                "In"
            } else if self.at_name("is") {
                self.pos += 1;
                if self.eat_name("not") {
                    "IsNot"
                } else {
                    "Is"
                }
            } else {
                break;
            };
            ops.push(fnode(op_name, vec![]));
            comparators.push(unparen(self.parse_bitor()?));
        }
        if ops.is_empty() {
            return Some(left);
        }
        Some(fnode(
            "Compare",
            vec![
                ("left", unparen(left)),
                ("ops", FVal::List(ops)),
                ("comparators", FVal::List(comparators)),
            ],
        ))
    }

    fn parse_bin_chain(
        &mut self,
        ops: &[(&str, &'static str)],
        next: fn(&mut Self) -> Option<FVal>,
    ) -> Option<FVal> {
        let mut left = next(self)?;
        loop {
            let mut matched: Option<&'static str> = None;
            for (text, name) in ops {
                if self.at_op(text) {
                    self.pos += 1;
                    matched = Some(name);
                    break;
                }
            }
            let Some(op_name) = matched else { return Some(left) };
            let right = next(self)?;
            left = binop_node(unparen(left), op_name, unparen(right));
        }
    }

    fn parse_bitor(&mut self) -> Option<FVal> {
        self.parse_bin_chain(&[("|", "BitOr")], Self::parse_bitxor)
    }

    fn parse_bitxor(&mut self) -> Option<FVal> {
        self.parse_bin_chain(&[("^", "BitXor")], Self::parse_bitand)
    }

    fn parse_bitand(&mut self) -> Option<FVal> {
        self.parse_bin_chain(&[("&", "BitAnd")], Self::parse_shift)
    }

    fn parse_shift(&mut self) -> Option<FVal> {
        self.parse_bin_chain(&[("<<", "LShift"), (">>", "RShift")], Self::parse_arith)
    }

    fn parse_arith(&mut self) -> Option<FVal> {
        self.parse_bin_chain(&[("+", "Add"), ("-", "Sub")], Self::parse_term)
    }

    fn parse_term(&mut self) -> Option<FVal> {
        self.parse_bin_chain(
            &[("*", "Mult"), ("@", "MatMult"), ("/", "Div"), ("//", "FloorDiv"), ("%", "Mod")],
            Self::parse_factor,
        )
    }

    fn parse_factor(&mut self) -> Option<FVal> {
        for (text, name) in [("+", "UAdd"), ("-", "USub"), ("~", "Invert")] {
            if self.at_op(text) {
                self.pos += 1;
                let operand = self.parse_factor()?;
                return Some(fnode("UnaryOp", vec![("op", fnode(name, vec![])), ("operand", unparen(operand))]));
            }
        }
        self.parse_power()
    }

    fn parse_power(&mut self) -> Option<FVal> {
        let base = self.parse_atom_expr()?;
        if self.eat_op("**") {
            let exponent = self.parse_factor()?;
            return Some(binop_node(unparen(base), "Pow", unparen(exponent)));
        }
        Some(base)
    }

    fn parse_atom_expr(&mut self) -> Option<FVal> {
        let awaited = self.eat_name("await");
        let mut expr = self.parse_atom()?;
        loop {
            if self.eat_op(".") {
                let attr = self.name_text()?;
                expr = fnode(
                    "Attribute",
                    vec![("value", unparen(expr)), ("attr", FVal::Str(attr)), ("ctx", ctx_load())],
                );
            } else if self.at_op("(") {
                expr = self.parse_call(expr)?;
            } else if self.at_op("[") {
                self.pos += 1;
                let slice = self.parse_subscript_list()?;
                self.expect_op("]")?;
                expr = fnode(
                    "Subscript",
                    vec![("value", unparen(expr)), ("slice", slice), ("ctx", ctx_load())],
                );
            } else {
                break;
            }
        }
        if awaited {
            expr = fnode("Await", vec![("value", unparen(expr))]);
        }
        Some(expr)
    }

    fn parse_subscript_list(&mut self) -> Option<FVal> {
        let mut items = vec![self.parse_slice_item()?];
        let mut tuple = false;
        while self.eat_op(",") {
            tuple = true;
            if self.at_op("]") {
                break;
            }
            items.push(self.parse_slice_item()?);
        }
        if tuple {
            Some(fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())]))
        } else {
            items.into_iter().next()
        }
    }

    fn parse_slice_item(&mut self) -> Option<FVal> {
        let lower = if self.at_op(":") { None } else { Some(self.parse_expr()?) };
        if !self.eat_op(":") {
            return lower;
        }
        let upper = if self.at_op(":") || self.at_op("]") || self.at_op(",") {
            None
        } else {
            Some(self.parse_expr()?)
        };
        let step = if self.eat_op(":") {
            if self.at_op("]") || self.at_op(",") {
                None
            } else {
                Some(self.parse_expr()?)
            }
        } else {
            None
        };
        Some(fnode(
            "Slice",
            vec![
                ("lower", lower.map(unparen).unwrap_or(FVal::Null)),
                ("upper", upper.map(unparen).unwrap_or(FVal::Null)),
                ("step", step.map(unparen).unwrap_or(FVal::Null)),
            ],
        ))
    }

    /// Call arguments; the cursor is at '('. Consumes through ')'.
    fn parse_call(&mut self, func: FVal) -> Option<FVal> {
        self.expect_op("(")?;
        let mut args: Vec<FVal> = Vec::new();
        let mut keywords: Vec<FVal> = Vec::new();
        if self.eat_op(")") {
            return Some(fnode("Call", vec![("func", unparen(func)), ("args", FVal::List(args)), ("keywords", FVal::List(keywords))]));
        }
        loop {
            if self.eat_op("**") {
                let value = self.parse_expr()?;
                keywords.push(fnode("keyword", vec![("arg", FVal::Null), ("value", unparen(value))]));
            } else if self.eat_op("*") {
                let value = self.parse_expr()?;
                args.push(fnode("Starred", vec![("value", unparen(value)), ("ctx", ctx_load())]));
            } else if matches!(self.peek(), Some(Tok { kind: TokKind::Name, .. })) && self.at_op_at(1, "=") {
                let name = self.name_text()?;
                self.pos += 1; // '='
                let value = self.parse_expr()?;
                keywords.push(fnode("keyword", vec![("arg", FVal::Str(name)), ("value", unparen(value))]));
            } else {
                let value = self.parse_expr()?;
                if self.at_name("for")
                    || (self.at_name("async") && matches!(self.peek_at(1), Some(Tok { kind: TokKind::Name, text }) if text == "for"))
                {
                    let generators = self.parse_comprehensions()?;
                    let genexp = fnode("GeneratorExp", vec![("elt", unparen(value)), ("generators", FVal::List(generators))]);
                    args.push(genexp);
                    self.expect_op(")")?;
                    return Some(fnode(
                        "Call",
                        vec![("func", unparen(func)), ("args", FVal::List(args)), ("keywords", FVal::List(keywords))],
                    ));
                }
                args.push(unparen(value));
            }
            if self.eat_op(",") {
                if self.eat_op(")") {
                    break;
                }
                continue;
            }
            self.expect_op(")")?;
            break;
        }
        Some(fnode("Call", vec![("func", unparen(func)), ("args", FVal::List(args)), ("keywords", FVal::List(keywords))]))
    }

    fn parse_comprehensions(&mut self) -> Option<Vec<FVal>> {
        let mut generators = Vec::new();
        loop {
            let is_async = if self.eat_name("async") {
                self.expect_name("for")?;
                1
            } else if self.eat_name("for") {
                0
            } else {
                return None;
            };
            let target = self.parse_target_list(true)?;
            self.expect_name("in")?;
            let iter = self.parse_or_test()?;
            let mut ifs = Vec::new();
            while self.eat_name("if") {
                ifs.push(unparen(self.parse_or_test()?));
            }
            generators.push(fnode(
                "comprehension",
                vec![
                    ("target", target),
                    ("iter", unparen(iter)),
                    ("ifs", FVal::List(ifs)),
                    ("is_async", FVal::Raw(is_async.to_string())),
                ],
            ));
            if !(self.at_name("for") || self.at_name("async")) {
                return Some(generators);
            }
        }
    }

    /// An expression list in target position (for / with / del targets).
    /// With join_commas=false a single (possibly parenthesized) target.
    fn parse_target_list(&mut self, join_commas: bool) -> Option<FVal> {
        let mut items = vec![self.parse_expr()?];
        let mut tuple = false;
        while join_commas && self.eat_op(",") {
            tuple = true;
            if self.at_op("in") || self.at_op(")") || self.at_op("]") || self.at_name("in") {
                break;
            }
            if matches!(self.peek(), Some(Tok { kind: TokKind::Op, text }) if text == "=" || text == ":")
                || self.at_kind(&TokKind::Newline)
            {
                break;
            }
            items.push(self.parse_expr()?);
        }
        let node = if tuple || items.len() > 1 {
            fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())])
        } else {
            items.into_iter().next()?
        };
        to_target(&node, "Store")
    }

    fn parse_atom(&mut self) -> Option<FVal> {
        let tok = self.peek()?.clone();
        match tok.kind {
            TokKind::Number => {
                self.pos += 1;
                Some(fconst(number_constant(&tok.text)?))
            }
            TokKind::Str | TokKind::FStringStart => self.parse_string_group(),
            TokKind::Name => match tok.text.as_str() {
                "True" => {
                    self.pos += 1;
                    Some(fconst("True".to_string()))
                }
                "False" => {
                    self.pos += 1;
                    Some(fconst("False".to_string()))
                }
                "None" => {
                    self.pos += 1;
                    Some(fconst("None".to_string()))
                }
                "lambda" => {
                    self.pos += 1;
                    self.parse_lambda()
                }
                _ => {
                    self.pos += 1;
                    Some(fname(&tok.text, "Load"))
                }
            },
            TokKind::Op => match tok.text.as_str() {
                "(" => self.parse_group(),
                "[" => self.parse_list_display(),
                "{" => self.parse_dict_display(),
                "..." => {
                    self.pos += 1;
                    Some(fconst("...".to_string()))
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn parse_group(&mut self) -> Option<FVal> {
        self.expect_op("(")?;
        if self.eat_op(")") {
            return Some(fnode("Tuple", vec![("elts", FVal::List(vec![])), ("ctx", ctx_load())]));
        }
        if self.at_name("yield") {
            let value = self.parse_yield()?;
            self.expect_op(")")?;
            return Some(value);
        }
        let first = self.parse_starred_or_expr()?;
        if self.at_name("for")
            || (self.at_name("async") && matches!(self.peek_at(1), Some(Tok { kind: TokKind::Name, text }) if text == "for"))
        {
            let generators = self.parse_comprehensions()?;
            self.expect_op(")")?;
            return Some(fnode("GeneratorExp", vec![("elt", unparen(first)), ("generators", FVal::List(generators))]));
        }
        if self.at_op(",") {
            let mut items = vec![first];
            while self.eat_op(",") {
                if self.at_op(")") {
                    break;
                }
                items.push(self.parse_starred_or_expr()?);
            }
            self.expect_op(")")?;
            return Some(fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())]));
        }
        self.expect_op(")")?;
        Some(FVal::Paren(Box::new(first)))
    }

    fn parse_starred_or_expr(&mut self) -> Option<FVal> {
        if self.eat_op("*") {
            let value = self.parse_expr()?;
            return Some(fnode("Starred", vec![("value", unparen(value)), ("ctx", ctx_load())]));
        }
        self.parse_expr()
    }

    fn parse_yield(&mut self) -> Option<FVal> {
        self.expect_name("yield")?;
        if self.eat_name("from") {
            let value = self.parse_expr()?;
            return Some(fnode("YieldFrom", vec![("value", unparen(value))]));
        }
        let starts_expr = matches!(self.peek(), Some(Tok { kind, .. })
            if matches!(kind, TokKind::Name | TokKind::Number | TokKind::Str | TokKind::FStringStart)
                || (matches!(kind, TokKind::Op)));
        let stops = matches!(self.peek(), Some(Tok { kind: TokKind::Newline | TokKind::Dedent, .. }))
            || self.peek().is_none()
            || self.at_op(")")
            || self.at_op("]")
            || self.at_op(";")
            || self.at_op(",");
        if !starts_expr || stops {
            return Some(fnode("Yield", vec![("value", FVal::Null)]));
        }
        let mut items = vec![self.parse_starred_or_expr()?];
        while self.eat_op(",") {
            if matches!(self.peek(), Some(Tok { kind: TokKind::Newline | TokKind::Dedent, .. }))
                || self.at_op(")")
                || self.at_op(";")
            {
                break;
            }
            items.push(self.parse_starred_or_expr()?);
        }
        let value = if items.len() == 1 {
            unparen(items.into_iter().next()?)
        } else {
            fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())])
        };
        Some(fnode("Yield", vec![("value", value)]))
    }

    fn parse_list_display(&mut self) -> Option<FVal> {
        self.expect_op("[")?;
        if self.eat_op("]") {
            return Some(fnode("List", vec![("elts", FVal::List(vec![])), ("ctx", ctx_load())]));
        }
        let first = self.parse_starred_or_expr()?;
        if self.at_name("for")
            || (self.at_name("async") && matches!(self.peek_at(1), Some(Tok { kind: TokKind::Name, text }) if text == "for"))
        {
            let generators = self.parse_comprehensions()?;
            self.expect_op("]")?;
            return Some(fnode("ListComp", vec![("elt", unparen(first)), ("generators", FVal::List(generators))]));
        }
        let mut items = vec![first];
        while self.eat_op(",") {
            if self.at_op("]") {
                break;
            }
            items.push(self.parse_starred_or_expr()?);
        }
        self.expect_op("]")?;
        Some(fnode("List", vec![("elts", FVal::List(items)), ("ctx", ctx_load())]))
    }

    fn parse_dict_display(&mut self) -> Option<FVal> {
        self.expect_op("{")?;
        if self.eat_op("}") {
            return Some(fnode("Dict", vec![("keys", FVal::List(vec![])), ("values", FVal::List(vec![]))]));
        }
        let mut keys: Vec<FVal> = Vec::new();
        let mut values: Vec<FVal> = Vec::new();
        let mut is_dict: Option<bool> = None;
        loop {
            if self.eat_op("**") {
                if is_dict == Some(false) {
                    return None;
                }
                is_dict = Some(true);
                keys.push(FVal::Null);
                values.push(unparen(self.parse_expr()?));
            } else {
                let first = self.parse_expr()?;
                if self.eat_op(":") {
                    if is_dict == Some(false) {
                        return None;
                    }
                    is_dict = Some(true);
                    let value = self.parse_expr()?;
                    if self.at_name("for")
                        || (self.at_name("async")
                            && matches!(self.peek_at(1), Some(Tok { kind: TokKind::Name, text }) if text == "for"))
                    {
                        let generators = self.parse_comprehensions()?;
                        self.expect_op("}")?;
                        return Some(fnode(
                            "DictComp",
                            vec![
                                ("key", unparen(first)),
                                ("value", unparen(value)),
                                ("generators", FVal::List(generators)),
                            ],
                        ));
                    }
                    keys.push(unparen(first));
                    values.push(unparen(value));
                } else {
                    if is_dict == Some(true) {
                        return None;
                    }
                    is_dict = Some(false);
                    if self.at_name("for")
                        || (self.at_name("async")
                            && matches!(self.peek_at(1), Some(Tok { kind: TokKind::Name, text }) if text == "for"))
                    {
                        let generators = self.parse_comprehensions()?;
                        self.expect_op("}")?;
                        return Some(fnode(
                            "SetComp",
                            vec![("elt", unparen(first)), ("generators", FVal::List(generators))],
                        ));
                    }
                    values.push(unparen(first));
                }
            }
            if self.eat_op(",") {
                if self.at_op("}") {
                    break;
                }
                continue;
            }
            break;
        }
        self.expect_op("}")?;
        if is_dict == Some(true) {
            Some(fnode("Dict", vec![("keys", FVal::List(keys)), ("values", FVal::List(values))]))
        } else {
            Some(fnode("Set", vec![("elts", FVal::List(values))]))
        }
    }

    /// A run of adjacent string / f-string literals.
    fn parse_string_group(&mut self) -> Option<FVal> {
        enum Piece {
            Plain(String),
            Bytes(Vec<u8>),
            Joined(Vec<FVal>),
        }
        let mut pieces: Vec<Piece> = Vec::new();
        loop {
            if self.at_kind(&TokKind::Str) {
                let text = self.peek()?.text.clone();
                self.pos += 1;
                match literal_value(&text)? {
                    LitValue::Str(decoded) => pieces.push(Piece::Plain(decoded)),
                    LitValue::Bytes(bytes) => pieces.push(Piece::Bytes(bytes)),
                    LitValue::FStr => return None,
                }
            } else if self.at_kind(&TokKind::FStringStart) {
                pieces.push(Piece::Joined(self.parse_fstring()?));
            } else {
                break;
            }
        }
        let has_joined = pieces.iter().any(|piece| matches!(piece, Piece::Joined(_)));
        if !has_joined {
            let mut text = String::new();
            let mut bytes: Vec<u8> = Vec::new();
            let mut saw_bytes = false;
            let mut saw_str = false;
            for piece in pieces {
                match piece {
                    Piece::Plain(part) => {
                        saw_str = true;
                        text.push_str(&part);
                    }
                    Piece::Bytes(part) => {
                        saw_bytes = true;
                        bytes.extend(part);
                    }
                    Piece::Joined(_) => return None,
                }
            }
            if saw_bytes && saw_str {
                return None;
            }
            return Some(if saw_bytes { fconst(bytes_repr(&bytes)) } else { fconst_str(&text) });
        }
        let mut values: Vec<FVal> = Vec::new();
        for piece in pieces {
            match piece {
                Piece::Plain(part) => push_constant_text(&mut values, &part),
                Piece::Bytes(_) => return None,
                Piece::Joined(inner) => {
                    for value in inner {
                        if let FVal::Node("Constant", fields) = &value {
                            if let Some((_, FVal::Raw(raw))) = fields.first() {
                                if let Some(text) = repr_unquote(raw) {
                                    push_constant_text(&mut values, &text);
                                    continue;
                                }
                            }
                        }
                        values.push(value);
                    }
                }
            }
        }
        Some(fnode("JoinedStr", vec![("values", FVal::List(values))]))
    }

    /// One f-string; the cursor is at its FStringStart token.
    fn parse_fstring(&mut self) -> Option<Vec<FVal>> {
        self.pos += 1; // FStringStart
        let mut values: Vec<FVal> = Vec::new();
        let mut pending = String::new();
        loop {
            if self.at_kind(&TokKind::FStringMiddle) {
                let raw = self.peek()?.text.clone();
                self.pos += 1;
                pending.push_str(&decode_fstring_middle(&raw)?);
            } else if self.at_op("{") {
                self.pos += 1;
                let field = self.parse_fstring_field()?;
                if !pending.is_empty() {
                    values.push(fconst_str(&pending));
                    pending.clear();
                }
                values.push(field);
            } else if self.at_kind(&TokKind::FStringEnd) {
                self.pos += 1;
                break;
            } else {
                return None;
            }
        }
        if !pending.is_empty() {
            values.push(fconst_str(&pending));
        }
        Some(values)
    }

    /// One `{...}` field (cursor just past '{'); consumes through '}'.
    fn parse_fstring_field(&mut self) -> Option<FVal> {
        if self.at_op("=") {
            return None; // debug fields: outside the subset (fail closed)
        }
        let value = self.parse_expr()?;
        if self.at_op("=") {
            return None; // debug field (f"{x=}")
        }
        let mut conversion = -1i32;
        if self.eat_op("!") {
            let name = self.name_text()?;
            if name.len() != 1 {
                return None;
            }
            conversion = match name.as_str() {
                "s" => 115,
                "r" => 114,
                "a" => 97,
                _ => return None,
            };
        }
        let mut format_spec = FVal::Null;
        if self.eat_op(":") {
            format_spec = self.parse_fstring_spec()?;
        }
        self.expect_op("}")?;
        Some(fnode(
            "FormattedValue",
            vec![
                ("value", unparen(value)),
                ("conversion", FVal::Raw(conversion.to_string())),
                ("format_spec", format_spec),
            ],
        ))
    }

    /// A format spec: middles and nested fields up to the field's '}'.
    fn parse_fstring_spec(&mut self) -> Option<FVal> {
        let mut values: Vec<FVal> = Vec::new();
        let mut pending = String::new();
        loop {
            if self.at_kind(&TokKind::FStringMiddle) {
                let raw = self.peek()?.text.clone();
                self.pos += 1;
                pending.push_str(&decode_fstring_middle(&raw)?);
            } else if self.at_op("{") {
                self.pos += 1;
                let field = self.parse_fstring_field()?;
                if !pending.is_empty() {
                    values.push(fconst_str(&pending));
                    pending.clear();
                }
                values.push(field);
            } else if self.at_op("}") {
                break;
            } else {
                return None;
            }
        }
        if !pending.is_empty() {
            values.push(fconst_str(&pending));
        } else if matches!(values.last(), Some(FVal::Node(name, _)) if *name == "FormattedValue") {
            values.push(fconst_str(""));
        }
        Some(fnode("JoinedStr", vec![("values", FVal::List(values))]))
    }

    fn parse_lambda(&mut self) -> Option<FVal> {
        let args = self.parse_params(false)?;
        self.expect_op(":")?;
        let body = self.parse_expr()?;
        Some(fnode("Lambda", vec![("args", args), ("body", unparen(body))]))
    }

    /// def/lambda parameters. With parens=true the cursor is before '('
    /// and annotations are allowed; lambda form ends at ':'.
    fn parse_params(&mut self, parens: bool) -> Option<FVal> {
        if parens {
            self.expect_op("(")?;
        }
        struct Param {
            name: String,
            annotation: FVal,
            default: Option<FVal>,
        }
        let mut positional: Vec<Param> = Vec::new();
        let mut slash_at: Option<usize> = None;
        let mut vararg: Option<Param> = None;
        let mut kwonly: Vec<Param> = Vec::new();
        let mut kwarg: Option<Param> = None;
        let mut star_seen = false;
        loop {
            if parens && self.at_op(")") {
                self.pos += 1;
                break;
            }
            if !parens && self.at_op(":") {
                break;
            }
            if self.eat_op("/") {
                if slash_at.is_some() || star_seen {
                    return None;
                }
                slash_at = Some(positional.len());
            } else if self.eat_op("**") {
                let name = self.name_text()?;
                let annotation = if parens && self.eat_op(":") {
                    self.parse_expr()?
                } else {
                    FVal::Null
                };
                kwarg = Some(Param { name, annotation, default: None });
                if parens {
                    self.eat_op(",");
                    self.expect_op(")")?;
                }
                break;
            } else if self.at_op("*") && !star_seen {
                self.pos += 1;
                star_seen = true;
                if matches!(self.peek(), Some(Tok { kind: TokKind::Name, .. })) {
                    let name = self.name_text()?;
                    let annotation = if parens && self.eat_op(":") {
                        self.parse_expr()?
                    } else {
                        FVal::Null
                    };
                    vararg = Some(Param { name, annotation, default: None });
                }
            } else {
                let name = self.name_text()?;
                let annotation = if parens && self.eat_op(":") {
                    self.parse_expr()?
                } else {
                    FVal::Null
                };
                let default = if self.eat_op("=") {
                    Some(self.parse_expr()?)
                } else {
                    None
                };
                let param = Param { name, annotation, default };
                if star_seen {
                    kwonly.push(param);
                } else {
                    positional.push(param);
                }
            }
            if parens {
                if self.eat_op(",") {
                    continue;
                }
                self.expect_op(")")?;
                break;
            }
            if !self.eat_op(",") {
                break;
            }
        }
        let make_arg = |param: &Param| {
            fnode(
                "arg",
                vec![
                    ("arg", FVal::Str(param.name.clone())),
                    ("annotation", param.annotation.clone()),
                    ("type_comment", FVal::Null),
                ],
            )
        };
        let (posonly, regular) = match slash_at {
            Some(index) => positional.split_at(index),
            None => (&[][..], &positional[..]),
        };
        let (posonly, regular) = if slash_at.is_some() {
            (posonly, regular)
        } else {
            (&[][..], &positional[..])
        };
        let mut defaults: Vec<FVal> = Vec::new();
        let mut posonly_args: Vec<FVal> = Vec::new();
        let mut regular_args: Vec<FVal> = Vec::new();
        for param in posonly {
            posonly_args.push(make_arg(param));
            if let Some(default) = &param.default {
                defaults.push(default.clone());
            }
        }
        for param in regular {
            regular_args.push(make_arg(param));
            if let Some(default) = &param.default {
                defaults.push(default.clone());
            }
        }
        let mut kw_defaults: Vec<FVal> = Vec::new();
        let mut kwonly_args: Vec<FVal> = Vec::new();
        for param in &kwonly {
            kwonly_args.push(make_arg(param));
            kw_defaults.push(param.default.clone().unwrap_or(FVal::Null));
        }
        Some(fnode(
            "arguments",
            vec![
                ("posonlyargs", FVal::List(posonly_args)),
                ("args", FVal::List(regular_args)),
                ("vararg", vararg.as_ref().map(make_arg).unwrap_or(FVal::Null)),
                ("kwonlyargs", FVal::List(kwonly_args)),
                ("kw_defaults", FVal::List(kw_defaults)),
                ("kwarg", kwarg.as_ref().map(make_arg).unwrap_or(FVal::Null)),
                ("defaults", FVal::List(defaults)),
            ],
        ))
    }
}

fn unparen(value: FVal) -> FVal {
    match value {
        FVal::Paren(inner) => *inner,
        other => other,
    }
}

/// Append decoded text as a Constant, merging with a trailing Constant.
fn push_constant_text(values: &mut Vec<FVal>, text: &str) {
    if let Some(FVal::Node(name, fields)) = values.last_mut() {
        if *name == "Constant" {
            if let Some((_, FVal::Raw(raw))) = fields.first_mut() {
                if let Some(existing) = repr_unquote(raw) {
                    *raw = py_str_repr(&format!("{existing}{text}"));
                    return;
                }
            }
        }
    }
    values.push(fconst_str(text));
}

/// Recover the string inside a rendered '...' repr (for merging).
fn repr_unquote(raw: &str) -> Option<String> {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() < 2 {
        return None;
    }
    // Reuse the literal decoder by feeding the repr back as a token.
    match literal_value(raw)? {
        LitValue::Str(text) => Some(text),
        _ => None,
    }
}

/// Rewrite an expression tree into target (Store/Del) shape.
fn to_target(value: &FVal, ctx: &'static str) -> Option<FVal> {
    match value {
        FVal::Paren(inner) => to_target(inner, ctx),
        FVal::Node("Name", fields) => {
            let id = match fields.first() {
                Some((_, FVal::Str(text))) => text.clone(),
                _ => return None,
            };
            Some(fname(&id, ctx))
        }
        FVal::Node("Attribute", fields) => Some(fnode(
            "Attribute",
            vec![
                ("value", fields[0].1.clone()),
                ("attr", fields[1].1.clone()),
                ("ctx", fnode(ctx, vec![])),
            ],
        )),
        FVal::Node("Subscript", fields) => Some(fnode(
            "Subscript",
            vec![
                ("value", fields[0].1.clone()),
                ("slice", fields[1].1.clone()),
                ("ctx", fnode(ctx, vec![])),
            ],
        )),
        FVal::Node(kind @ ("Tuple" | "List"), fields) => {
            let elts = match &fields[0].1 {
                FVal::List(items) => items
                    .iter()
                    .map(|item| to_target(item, ctx))
                    .collect::<Option<Vec<_>>>()?,
                _ => return None,
            };
            Some(fnode(
                if *kind == "Tuple" { "Tuple" } else { "List" },
                vec![("elts", FVal::List(elts)), ("ctx", fnode(ctx, vec![]))],
            ))
        }
        FVal::Node("Starred", fields) => Some(fnode(
            "Starred",
            vec![("value", to_target(&fields[0].1, ctx)?), ("ctx", fnode(ctx, vec![]))],
        )),
        _ => None,
    }
}

impl AstParser {
    // -- statements --------------------------------------------------------

    fn parse_module(&mut self) -> Option<FVal> {
        let mut body = Vec::new();
        loop {
            while self.at_kind(&TokKind::Newline) {
                self.pos += 1;
            }
            if self.peek().is_none() {
                break;
            }
            body.extend(self.parse_statement()?);
        }
        Some(fnode(
            "Module",
            vec![("body", FVal::List(body)), ("type_ignores", FVal::List(vec![]))],
        ))
    }

    fn parse_block(&mut self) -> Option<Vec<FVal>> {
        if self.at_kind(&TokKind::Newline) {
            self.pos += 1;
            if !self.at_kind(&TokKind::Indent) {
                return None;
            }
            self.pos += 1;
            let mut body = Vec::new();
            loop {
                while self.at_kind(&TokKind::Newline) {
                    self.pos += 1;
                }
                if self.at_kind(&TokKind::Dedent) {
                    self.pos += 1;
                    return Some(body);
                }
                if self.peek().is_none() {
                    return None;
                }
                body.extend(self.parse_statement()?);
            }
        }
        // One-line suite: simple statements separated by ';'.
        let mut body = vec![self.parse_small_stmt()?];
        while self.eat_op(";") {
            if self.at_kind(&TokKind::Newline) || self.peek().is_none() {
                break;
            }
            body.push(self.parse_small_stmt()?);
        }
        self.end_of_line();
        Some(body)
    }

    /// One statement position: a compound statement (one node), or a
    /// line of small statements separated by ';' (several nodes).
    fn parse_statement(&mut self) -> Option<Vec<FVal>> {
        let compound = self.parse_compound()?;
        if let Some(node) = compound {
            return Some(vec![node]);
        }
        let mut body = vec![self.parse_small_stmt()?];
        while self.eat_op(";") {
            if self.at_kind(&TokKind::Newline) || self.peek().is_none() {
                break;
            }
            body.push(self.parse_small_stmt()?);
        }
        self.end_of_line();
        Some(body)
    }

    /// Compound statements and decorators; Ok(None) for a simple line.
    fn parse_compound(&mut self) -> Option<Option<FVal>> {
        // Decorators.
        if self.at_op("@") {
            let mut decorators = Vec::new();
            while self.eat_op("@") {
                decorators.push(unparen(self.parse_expr()?));
                if !self.at_kind(&TokKind::Newline) {
                    return None;
                }
                self.pos += 1;
            }
            if self.at_name("def") {
                return self.parse_function(decorators, false).map(Some);
            }
            if self.at_name("class") {
                return self.parse_class(decorators).map(Some);
            }
            if self.at_name("async")
                && matches!(self.peek_at(1), Some(Tok { kind: TokKind::Name, text }) if text == "def")
            {
                self.pos += 1;
                return self.parse_function(decorators, true).map(Some);
            }
            return None;
        }
        if self.at_name("def") {
            return self.parse_function(Vec::new(), false).map(Some);
        }
        if self.at_name("class") {
            return self.parse_class(Vec::new()).map(Some);
        }
        if self.at_name("async") {
            match self.peek_at(1) {
                Some(Tok { kind: TokKind::Name, text }) if text == "def" => {
                    self.pos += 1;
                    return self.parse_function(Vec::new(), true).map(Some);
                }
                Some(Tok { kind: TokKind::Name, text }) if text == "for" => {
                    self.pos += 1;
                    return self.parse_for(true).map(Some);
                }
                Some(Tok { kind: TokKind::Name, text }) if text == "with" => {
                    self.pos += 1;
                    return self.parse_with(true).map(Some);
                }
                _ => return None,
            }
        }
        if self.at_name("if") {
            return self.parse_if().map(Some);
        }
        if self.at_name("while") {
            return self.parse_while().map(Some);
        }
        if self.at_name("for") {
            return self.parse_for(false).map(Some);
        }
        if self.at_name("with") {
            return self.parse_with(false).map(Some);
        }
        if self.at_name("try") {
            return self.parse_try().map(Some);
        }
        if self.at_name("match") {
            let saved = self.pos;
            if let Some(node) = self.parse_match() {
                return Some(Some(node));
            }
            self.pos = saved;
        }
        Some(None)
    }

    fn parse_function(&mut self, decorators: Vec<FVal>, is_async: bool) -> Option<FVal> {
        self.expect_name("def")?;
        let name = self.name_text()?;
        let type_params = if self.at_op("[") { self.parse_type_params()? } else { Vec::new() };
        let args = self.parse_params(true)?;
        let returns = if self.eat_op("->") { self.parse_expr()? } else { FVal::Null };
        self.expect_op(":")?;
        let body = self.parse_block()?;
        Some(fnode(
            if is_async { "AsyncFunctionDef" } else { "FunctionDef" },
            vec![
                ("name", FVal::Str(name)),
                ("args", args),
                ("body", FVal::List(body)),
                ("decorator_list", FVal::List(decorators)),
                ("returns", returns),
                ("type_comment", FVal::Null),
                ("type_params", FVal::List(type_params)),
            ],
        ))
    }

    fn parse_type_params(&mut self) -> Option<Vec<FVal>> {
        self.expect_op("[")?;
        let mut params = Vec::new();
        loop {
            if self.eat_op("**") {
                let name = self.name_text()?;
                params.push(fnode("ParamSpec", vec![("name", FVal::Str(name))]));
            } else if self.eat_op("*") {
                let name = self.name_text()?;
                params.push(fnode("TypeVarTuple", vec![("name", FVal::Str(name))]));
            } else {
                let name = self.name_text()?;
                let bound = if self.eat_op(":") { self.parse_expr()? } else { FVal::Null };
                params.push(fnode(
                    "TypeVar",
                    vec![("name", FVal::Str(name)), ("bound", bound)],
                ));
            }
            if !self.eat_op(",") {
                break;
            }
            if self.at_op("]") {
                break;
            }
        }
        self.expect_op("]")?;
        Some(params)
    }

    fn parse_class(&mut self, decorators: Vec<FVal>) -> Option<FVal> {
        self.expect_name("class")?;
        let name = self.name_text()?;
        let type_params = if self.at_op("[") { self.parse_type_params()? } else { Vec::new() };
        let mut bases: Vec<FVal> = Vec::new();
        let mut keywords: Vec<FVal> = Vec::new();
        if self.at_op("(") {
            // Reuse the call machinery by folding the result back apart.
            let probe = fname("C", "Load");
            let call = self.parse_call(probe)?;
            if let FVal::Node("Call", fields) = call {
                bases = match &fields[1].1 {
                    FVal::List(items) => items.clone(),
                    _ => return None,
                };
                keywords = match &fields[2].1 {
                    FVal::List(items) => items.clone(),
                    _ => return None,
                };
            } else {
                return None;
            }
        }
        self.expect_op(":")?;
        let body = self.parse_block()?;
        Some(fnode(
            "ClassDef",
            vec![
                ("name", FVal::Str(name)),
                ("bases", FVal::List(bases)),
                ("keywords", FVal::List(keywords)),
                ("body", FVal::List(body)),
                ("decorator_list", FVal::List(decorators)),
                ("type_params", FVal::List(type_params)),
            ],
        ))
    }

    fn parse_if(&mut self) -> Option<FVal> {
        self.expect_name("if")?;
        self.parse_if_tail()
    }

    /// After 'if'/'elif': test, suite, and the else/elif tail. An elif
    /// becomes a nested If in orelse, exactly like CPython's dump.
    fn parse_if_tail(&mut self) -> Option<FVal> {
        let test = self.parse_expr()?;
        self.expect_op(":")?;
        let body = self.parse_block()?;
        let mut orelse = Vec::new();
        if self.at_name("elif") {
            self.pos += 1;
            orelse = vec![self.parse_if_tail()?];
        } else if self.eat_name("else") {
            self.expect_op(":")?;
            orelse = self.parse_block()?;
        }
        Some(fnode(
            "If",
            vec![("test", unparen(test)), ("body", FVal::List(body)), ("orelse", FVal::List(orelse))],
        ))
    }

    fn parse_while(&mut self) -> Option<FVal> {
        self.expect_name("while")?;
        let test = self.parse_expr()?;
        self.expect_op(":")?;
        let body = self.parse_block()?;
        let mut orelse = Vec::new();
        if self.eat_name("else") {
            self.expect_op(":")?;
            orelse = self.parse_block()?;
        }
        Some(fnode(
            "While",
            vec![("test", unparen(test)), ("body", FVal::List(body)), ("orelse", FVal::List(orelse))],
        ))
    }

    fn parse_for(&mut self, is_async: bool) -> Option<FVal> {
        self.expect_name("for")?;
        let target = self.parse_target_list(true)?;
        self.expect_name("in")?;
        let mut items = vec![self.parse_starred_or_expr()?];
        while self.eat_op(",") {
            if self.at_op(":") {
                break;
            }
            items.push(self.parse_starred_or_expr()?);
        }
        let iter = if items.len() == 1 {
            unparen(items.into_iter().next()?)
        } else {
            fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())])
        };
        self.expect_op(":")?;
        let body = self.parse_block()?;
        let mut orelse = Vec::new();
        if self.eat_name("else") {
            self.expect_op(":")?;
            orelse = self.parse_block()?;
        }
        Some(fnode(
            if is_async { "AsyncFor" } else { "For" },
            vec![
                ("target", target),
                ("iter", iter),
                ("body", FVal::List(body)),
                ("orelse", FVal::List(orelse)),
                ("type_comment", FVal::Null),
            ],
        ))
    }

    fn parse_with(&mut self, is_async: bool) -> Option<FVal> {
        self.expect_name("with")?;
        let mut items = Vec::new();
        loop {
            let context = self.parse_expr()?;
            let optional = if self.eat_name("as") {
                self.parse_target_list(false)?
            } else {
                FVal::Null
            };
            items.push(fnode(
                "withitem",
                vec![("context_expr", unparen(context)), ("optional_vars", optional)],
            ));
            if !self.eat_op(",") {
                break;
            }
            if self.at_op(":") {
                break;
            }
        }
        self.expect_op(":")?;
        let body = self.parse_block()?;
        Some(fnode(
            if is_async { "AsyncWith" } else { "With" },
            vec![
                ("items", FVal::List(items)),
                ("body", FVal::List(body)),
                ("type_comment", FVal::Null),
            ],
        ))
    }

    fn parse_try(&mut self) -> Option<FVal> {
        self.expect_name("try")?;
        self.expect_op(":")?;
        let body = self.parse_block()?;
        let mut star: Option<bool> = None;
        let mut handlers = Vec::new();
        while self.at_name("except") {
            self.pos += 1;
            let this_star = self.eat_op("*");
            match star {
                None => star = Some(this_star),
                Some(previous) if previous != this_star => return None,
                _ => {}
            }
            let (ty, name) = if self.eat_op(":") {
                (FVal::Null, FVal::Null)
            } else {
                let ty = self.parse_expr()?;
                let name = if self.eat_name("as") {
                    FVal::Str(self.name_text()?)
                } else {
                    FVal::Null
                };
                self.expect_op(":")?;
                (ty, name)
            };
            let handler_body = self.parse_block()?;
            handlers.push(fnode(
                "ExceptHandler",
                vec![("type", ty), ("name", name), ("body", FVal::List(handler_body))],
            ));
        }
        let mut orelse = Vec::new();
        if self.eat_name("else") {
            self.expect_op(":")?;
            orelse = self.parse_block()?;
        }
        let mut finalbody = Vec::new();
        if self.eat_name("finally") {
            self.expect_op(":")?;
            finalbody = self.parse_block()?;
        }
        if handlers.is_empty() && finalbody.is_empty() {
            return None;
        }
        Some(fnode(
            if star == Some(true) { "TryStar" } else { "Try" },
            vec![
                ("body", FVal::List(body)),
                ("handlers", FVal::List(handlers)),
                ("orelse", FVal::List(orelse)),
                ("finalbody", FVal::List(finalbody)),
            ],
        ))
    }

    fn parse_match(&mut self) -> Option<FVal> {
        self.expect_name("match")?;
        let mut items = vec![self.parse_starred_or_expr()?];
        while self.eat_op(",") {
            if self.at_op(":") {
                break;
            }
            items.push(self.parse_starred_or_expr()?);
        }
        let subject = if items.len() == 1 {
            unparen(items.into_iter().next()?)
        } else {
            fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())])
        };
        self.expect_op(":")?;
        if !self.at_kind(&TokKind::Newline) {
            return None;
        }
        self.pos += 1;
        if !self.at_kind(&TokKind::Indent) {
            return None;
        }
        self.pos += 1;
        let mut cases = Vec::new();
        loop {
            while self.at_kind(&TokKind::Newline) {
                self.pos += 1;
            }
            if self.at_kind(&TokKind::Dedent) {
                self.pos += 1;
                break;
            }
            if !self.at_name("case") {
                return None;
            }
            self.pos += 1;
            let pattern = self.parse_pattern()?;
            let guard = if self.eat_name("if") {
                self.parse_expr()?
            } else {
                FVal::Null
            };
            self.expect_op(":")?;
            let body = self.parse_block()?;
            cases.push(fnode(
                "match_case",
                vec![("pattern", pattern), ("guard", guard), ("body", FVal::List(body))],
            ));
        }
        if cases.is_empty() {
            return None;
        }
        Some(fnode("Match", vec![("subject", subject), ("cases", FVal::List(cases))]))
    }

    // -- patterns ----------------------------------------------------------

    fn parse_pattern(&mut self) -> Option<FVal> {
        let first = self.parse_pattern_alt()?;
        if !self.at_op("|") {
            return Some(first);
        }
        let mut patterns = vec![first];
        while self.eat_op("|") {
            patterns.push(self.parse_pattern_alt()?);
        }
        Some(fnode("MatchOr", vec![("patterns", FVal::List(patterns))]))
    }

    fn parse_pattern_alt(&mut self) -> Option<FVal> {
        let base = self.parse_pattern_atom()?;
        if self.eat_name("as") {
            let name = self.name_text()?;
            return Some(fnode(
                "MatchAs",
                vec![("pattern", base), ("name", FVal::Str(name))],
            ));
        }
        Some(base)
    }

    fn parse_pattern_atom(&mut self) -> Option<FVal> {
        let tok = self.peek()?.clone();
        match tok.kind {
            TokKind::Str | TokKind::FStringStart => {
                let value = self.parse_string_group()?;
                if matches!(value, FVal::Node("JoinedStr", _)) {
                    return None;
                }
                Some(fnode("MatchValue", vec![("value", value)]))
            }
            TokKind::Number => {
                self.pos += 1;
                Some(fnode("MatchValue", vec![("value", fconst(number_constant(&tok.text)?))]))
            }
            TokKind::Op => match tok.text.as_str() {
                "-" | "+" => {
                    self.pos += 1;
                    let number = match self.peek()?.clone() {
                        Tok { kind: TokKind::Number, text } => {
                            self.pos += 1;
                            fconst(number_constant(&text)?)
                        }
                        _ => return None,
                    };
                    if tok.text == "-" {
                        Some(fnode(
                            "MatchValue",
                            vec![("value", fnode(
                                "UnaryOp",
                                vec![("op", fnode("USub", vec![])), ("operand", number)],
                            ))],
                        ))
                    } else {
                        Some(fnode("MatchValue", vec![("value", number)]))
                    }
                }
                "[" => {
                    self.pos += 1;
                    let mut patterns = Vec::new();
                    if !self.at_op("]") {
                        loop {
                            patterns.push(self.parse_pattern_item()?);
                            if !self.eat_op(",") {
                                break;
                            }
                            if self.at_op("]") {
                                break;
                            }
                        }
                    }
                    self.expect_op("]")?;
                    Some(fnode("MatchSequence", vec![("patterns", FVal::List(patterns))]))
                }
                "(" => {
                    self.pos += 1;
                    if self.eat_op(")") {
                        return Some(fnode("MatchSequence", vec![("patterns", FVal::List(vec![]))]));
                    }
                    let first = self.parse_pattern_item()?;
                    if self.eat_op(",") {
                        let mut patterns = vec![first];
                        while !self.at_op(")") {
                            patterns.push(self.parse_pattern_item()?);
                            if !self.eat_op(",") {
                                break;
                            }
                        }
                        self.expect_op(")")?;
                        return Some(fnode("MatchSequence", vec![("patterns", FVal::List(patterns))]));
                    }
                    self.expect_op(")")?;
                    Some(first)
                }
                "{" => {
                    self.pos += 1;
                    let mut keys = Vec::new();
                    let mut patterns = Vec::new();
                    let mut rest = FVal::Null;
                    if !self.at_op("}") {
                        loop {
                            if self.eat_op("**") {
                                rest = FVal::Str(self.name_text()?);
                            } else {
                                let key = self.parse_pattern_key()?;
                                self.expect_op(":")?;
                                keys.push(key);
                                patterns.push(self.parse_pattern()?);
                            }
                            if !self.eat_op(",") {
                                break;
                            }
                            if self.at_op("}") {
                                break;
                            }
                        }
                    }
                    self.expect_op("}")?;
                    Some(fnode(
                        "MatchMapping",
                        vec![
                            ("keys", FVal::List(keys)),
                            ("patterns", FVal::List(patterns)),
                            ("rest", rest),
                        ],
                    ))
                }
                _ => None,
            },
            TokKind::Name => {
                if tok.text == "_" {
                    self.pos += 1;
                    return Some(fnode(
                        "MatchAs",
                        vec![("pattern", FVal::Null), ("name", FVal::Null)],
                    ));
                }
                if matches!(tok.text.as_str(), "None" | "True" | "False") {
                    self.pos += 1;
                    return Some(fnode(
                        "MatchSingleton",
                        vec![("value", FVal::Raw(tok.text.clone()))],
                    ));
                }
                // Dotted name or bare capture / class pattern.
                self.pos += 1;
                let mut expr = fname(&tok.text, "Load");
                let mut dotted = false;
                while self.eat_op(".") {
                    dotted = true;
                    let attr = self.name_text()?;
                    expr = fnode(
                        "Attribute",
                        vec![("value", expr), ("attr", FVal::Str(attr)), ("ctx", ctx_load())],
                    );
                }
                if self.at_op("(") {
                    return self.parse_class_pattern(expr);
                }
                if dotted {
                    return Some(fnode("MatchValue", vec![("value", expr)]));
                }
                Some(fnode(
                    "MatchAs",
                    vec![("pattern", FVal::Null), ("name", FVal::Str(tok.text.clone()))],
                ))
            }
            _ => None,
        }
    }

    fn parse_pattern_item(&mut self) -> Option<FVal> {
        if self.eat_op("*") {
            let name = if self.at_name("_") {
                self.pos += 1;
                FVal::Null
            } else {
                FVal::Str(self.name_text()?)
            };
            return Some(fnode("MatchStar", vec![("name", name)]));
        }
        self.parse_pattern()
    }

    fn parse_pattern_key(&mut self) -> Option<FVal> {
        // Mapping keys are literals or dotted names.
        let tok = self.peek()?.clone();
        match tok.kind {
            TokKind::Str | TokKind::FStringStart => {
                let value = self.parse_string_group()?;
                if matches!(value, FVal::Node("JoinedStr", _)) {
                    return None;
                }
                Some(value)
            }
            TokKind::Number => {
                self.pos += 1;
                Some(fconst(number_constant(&tok.text)?))
            }
            TokKind::Op if tok.text == "-" || tok.text == "+" => {
                self.pos += 1;
                let number = match self.peek()?.clone() {
                    Tok { kind: TokKind::Number, text } => {
                        self.pos += 1;
                        fconst(number_constant(&text)?)
                    }
                    _ => return None,
                };
                if tok.text == "-" {
                    Some(fnode(
                        "UnaryOp",
                        vec![("op", fnode("USub", vec![])), ("operand", number)],
                    ))
                } else {
                    Some(number)
                }
            }
            TokKind::Name => {
                if matches!(tok.text.as_str(), "None" | "True" | "False") {
                    self.pos += 1;
                    return Some(fconst(tok.text.clone()));
                }
                self.pos += 1;
                let mut expr = fname(&tok.text, "Load");
                let mut dotted = false;
                while self.eat_op(".") {
                    dotted = true;
                    let attr = self.name_text()?;
                    expr = fnode(
                        "Attribute",
                        vec![("value", expr), ("attr", FVal::Str(attr)), ("ctx", ctx_load())],
                    );
                }
                if !dotted {
                    return None; // a bare name is not a valid mapping key
                }
                Some(expr)
            }
            _ => None,
        }
    }

    fn parse_class_pattern(&mut self, cls: FVal) -> Option<FVal> {
        self.expect_op("(")?;
        let mut patterns = Vec::new();
        let mut kwd_attrs: Vec<FVal> = Vec::new();
        let mut kwd_patterns = Vec::new();
        if !self.at_op(")") {
            loop {
                if matches!(self.peek(), Some(Tok { kind: TokKind::Name, .. })) && self.at_op_at(1, "=") {
                    let attr = self.name_text()?;
                    self.pos += 1; // '='
                    kwd_attrs.push(FVal::Str(attr));
                    kwd_patterns.push(self.parse_pattern()?);
                } else {
                    if !kwd_attrs.is_empty() {
                        return None;
                    }
                    patterns.push(self.parse_pattern()?);
                }
                if !self.eat_op(",") {
                    break;
                }
                if self.at_op(")") {
                    break;
                }
            }
        }
        self.expect_op(")")?;
        Some(fnode(
            "MatchClass",
            vec![
                ("cls", cls),
                ("patterns", FVal::List(patterns)),
                ("kwd_attrs", FVal::List(kwd_attrs)),
                ("kwd_patterns", FVal::List(kwd_patterns)),
            ],
        ))
    }

    // -- small statements ----------------------------------------------------

    fn parse_small_stmt(&mut self) -> Option<FVal> {
        if self.at_name("import") {
            return self.parse_import();
        }
        if self.at_name("from") {
            return self.parse_from_import();
        }
        if self.eat_name("return") {
            let value = if self.at_kind(&TokKind::Newline) || self.at_op(";") || self.peek().is_none() {
                FVal::Null
            } else if self.at_name("yield") {
                self.parse_yield()?
            } else {
                let items = self.parse_expr_items()?;
                if items.len() == 1 {
                    unparen(items.into_iter().next()?)
                } else {
                    fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())])
                }
            };
            return Some(fnode("Return", vec![("value", value)]));
        }
        if self.eat_name("del") {
            let items = self.parse_expr_items()?;
            let mut targets = Vec::new();
            for item in &items {
                targets.push(to_target(item, "Del")?);
            }
            return Some(fnode("Delete", vec![("targets", FVal::List(targets))]));
        }
        if self.eat_name("assert") {
            let test = self.parse_expr()?;
            let msg = if self.eat_op(",") {
                self.parse_expr()?
            } else {
                FVal::Null
            };
            return Some(fnode("Assert", vec![("test", unparen(test)), ("msg", msg)]));
        }
        if self.eat_name("raise") {
            let (exc, cause) = if self.at_kind(&TokKind::Newline) || self.at_op(";") || self.peek().is_none() {
                (FVal::Null, FVal::Null)
            } else {
                let exc = self.parse_expr()?;
                let cause = if self.eat_name("from") {
                    self.parse_expr()?
                } else {
                    FVal::Null
                };
                (unparen(exc), cause)
            };
            return Some(fnode("Raise", vec![("exc", exc), ("cause", cause)]));
        }
        if self.at_name("global") || self.at_name("nonlocal") {
            let kind = if self.at_name("global") { "Global" } else { "Nonlocal" };
            self.pos += 1;
            let mut names = vec![FVal::Str(self.name_text()?)];
            while self.eat_op(",") {
                names.push(FVal::Str(self.name_text()?));
            }
            return Some(fnode(kind, vec![("names", FVal::List(names))]));
        }
        if self.eat_name("pass") {
            return Some(fnode("Pass", vec![]));
        }
        if self.eat_name("break") {
            return Some(fnode("Break", vec![]));
        }
        if self.eat_name("continue") {
            return Some(fnode("Continue", vec![]));
        }
        self.parse_expr_stmt()
    }

    fn parse_import(&mut self) -> Option<FVal> {
        self.expect_name("import")?;
        let mut names = Vec::new();
        loop {
            let mut module = self.name_text()?;
            while self.eat_op(".") {
                module.push('.');
                module.push_str(&self.name_text()?);
            }
            let asname = if self.eat_name("as") {
                FVal::Str(self.name_text()?)
            } else {
                FVal::Null
            };
            names.push(fnode(
                "alias",
                vec![("name", FVal::Str(module)), ("asname", asname)],
            ));
            if !self.eat_op(",") {
                break;
            }
        }
        Some(fnode("Import", vec![("names", FVal::List(names))]))
    }

    fn parse_from_import(&mut self) -> Option<FVal> {
        self.expect_name("from")?;
        let mut level = 0usize;
        loop {
            if self.at_op("...") {
                self.pos += 1;
                level += 3;
            } else if self.at_op(".") {
                self.pos += 1;
                level += 1;
            } else {
                break;
            }
        }
        let mut module = FVal::Null;
        if !self.at_name("import") {
            let mut name = self.name_text()?;
            while self.eat_op(".") {
                name.push('.');
                name.push_str(&self.name_text()?);
            }
            module = FVal::Str(name);
        }
        self.expect_name("import")?;
        let mut names = Vec::new();
        if self.eat_op("*") {
            names.push(fnode(
                "alias",
                vec![("name", FVal::Str("*".to_string())), ("asname", FVal::Null)],
            ));
        } else {
            let parens = self.eat_op("(");
            loop {
                let name = self.name_text()?;
                let asname = if self.eat_name("as") {
                    FVal::Str(self.name_text()?)
                } else {
                    FVal::Null
                };
                names.push(fnode(
                    "alias",
                    vec![("name", FVal::Str(name)), ("asname", asname)],
                ));
                if !self.eat_op(",") {
                    break;
                }
                if parens && self.at_op(")") {
                    break;
                }
            }
            if parens {
                self.expect_op(")")?;
            }
        }
        Some(fnode(
            "ImportFrom",
            vec![
                ("module", module),
                ("names", FVal::List(names)),
                ("level", FVal::Raw(level.to_string())),
            ],
        ))
    }

    /// Comma-separated expressions (statement lists), no trailing node.
    fn parse_expr_items(&mut self) -> Option<Vec<FVal>> {
        let mut items = vec![self.parse_starred_or_expr()?];
        while self.eat_op(",") {
            if self.at_kind(&TokKind::Newline)
                || self.at_op(";")
                || self.at_op(":")
                || self.at_op(")")
                || self.peek().is_none()
            {
                break;
            }
            items.push(self.parse_starred_or_expr()?);
        }
        Some(items)
    }

    fn parse_expr_stmt(&mut self) -> Option<FVal> {
        if self.at_name("yield") {
            let value = self.parse_yield()?;
            return Some(fnode("Expr", vec![("value", value)]));
        }
        let first = self.parse_expr()?;
        // AnnAssign: a single target followed by ':'.
        if self.at_op(":") {
            let parenthesized = matches!(first, FVal::Paren(_));
            let target = to_target(&first, "Store")?;
            self.pos += 1;
            let annotation = self.parse_expr()?;
            let value = if self.eat_op("=") {
                self.parse_assign_value()?
            } else {
                FVal::Null
            };
            let simple = if parenthesized { "0" } else { "1" };
            return Some(fnode(
                "AnnAssign",
                vec![
                    ("target", target),
                    ("annotation", unparen(annotation)),
                    ("value", value),
                    ("simple", FVal::Raw(simple.to_string())),
                ],
            ));
        }
        let mut items = vec![first];
        let mut saw_comma = false;
        while self.eat_op(",") {
            saw_comma = true;
            if self.at_kind(&TokKind::Newline)
                || self.at_op(";")
                || self.at_op("=")
                || self.peek().is_none()
                || self.at_aug_op()
            {
                break;
            }
            items.push(self.parse_starred_or_expr()?);
        }
        // Augmented assignment.
        if items.len() == 1 {
            if let Some(op_name) = self.aug_op_name() {
                let target = to_target(&items[0], "Store")?;
                let value = self.parse_assign_value()?;
                return Some(fnode(
                    "AugAssign",
                    vec![("target", target), ("op", fnode(op_name, vec![])), ("value", value)],
                ));
            }
        }
        if self.at_op("=") {
            let mut targets = Vec::new();
            let first_node = if saw_comma || items.len() > 1 {
                fnode("Tuple", vec![("elts", FVal::List(items.clone())), ("ctx", ctx_load())])
            } else {
                items[0].clone()
            };
            targets.push(to_target(&first_node, "Store")?);
            let value = loop {
                self.pos += 1; // '='
                if self.at_name("yield") {
                    break self.parse_yield()?;
                }
                let rhs_items = self.parse_expr_items()?;
                let rhs = if rhs_items.len() == 1 {
                    rhs_items.into_iter().next()?
                } else {
                    fnode("Tuple", vec![("elts", FVal::List(rhs_items)), ("ctx", ctx_load())])
                };
                if self.at_op("=") {
                    targets.push(to_target(&rhs, "Store")?);
                    continue;
                }
                break rhs;
            };
            let value = match value {
                FVal::Node("Yield", _) | FVal::Node("YieldFrom", _) => value,
                other => unparen(other),
            };
            return Some(fnode(
                "Assign",
                vec![("targets", FVal::List(targets)), ("value", value)],
            ));
        }
        let value = if saw_comma || items.len() > 1 {
            fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())])
        } else {
            items.into_iter().next()?
        };
        Some(fnode("Expr", vec![("value", unparen(value))]))
    }

    fn at_aug_op(&self) -> bool {
        self.aug_op_peek().is_some()
    }

    fn aug_op_peek(&self) -> Option<&'static str> {
        let text = match self.peek() {
            Some(Tok { kind: TokKind::Op, text }) => text.as_str(),
            _ => return None,
        };
        Some(match text {
            "+=" => "Add",
            "-=" => "Sub",
            "*=" => "Mult",
            "@=" => "MatMult",
            "/=" => "Div",
            "//=" => "FloorDiv",
            "%=" => "Mod",
            "**=" => "Pow",
            "<<=" => "LShift",
            ">>=" => "RShift",
            "&=" => "BitAnd",
            "|=" => "BitOr",
            "^=" => "BitXor",
            _ => return None,
        })
    }

    fn aug_op_name(&mut self) -> Option<&'static str> {
        let name = self.aug_op_peek()?;
        self.pos += 1;
        Some(name)
    }

    fn parse_assign_value(&mut self) -> Option<FVal> {
        if self.at_name("yield") {
            return self.parse_yield();
        }
        let items = self.parse_expr_items()?;
        if items.len() == 1 {
            items.into_iter().next()
        } else {
            Some(fnode("Tuple", vec![("elts", FVal::List(items)), ("ctx", ctx_load())]))
        }
    }
}

// ---------------------------------------------------------------------------
// The setup() metadata drop and the signature dispatch.

/// `_setup_py_signature`'s is_setup: a bare `setup(...)` call, or an
/// attribute chain rooted at the name `setuptools` ending in `.setup`.
fn is_setup_call(func: &FVal) -> bool {
    match func {
        FVal::Node("Name", fields) => {
            matches!(fields.first(), Some((_, FVal::Str(id))) if id == "setup")
        }
        FVal::Node("Attribute", fields) => {
            let attr_is_setup =
                matches!(fields.get(1), Some((_, FVal::Str(attr))) if attr == "setup");
            if !attr_is_setup {
                return false;
            }
            let mut current = &fields[0].1;
            loop {
                match current {
                    FVal::Node("Attribute", inner) => current = &inner[0].1,
                    FVal::Node("Name", inner) => {
                        return matches!(inner.first(), Some((_, FVal::Str(id))) if id == "setuptools");
                    }
                    FVal::Paren(inner) => current = inner,
                    _ => return false,
                }
            }
        }
        FVal::Paren(inner) => is_setup_call(inner),
        _ => false,
    }
}

/// The NodeTransformer drop: metadata keywords leave setup() calls.
fn strip_setup_calls(value: &mut FVal) {
    match value {
        FVal::Node(name, fields) => {
            for (_, field_value) in fields.iter_mut() {
                strip_setup_calls(field_value);
            }
            if *name == "Call" {
                let is_setup = fields
                    .first()
                    .map(|(_, func)| is_setup_call(func))
                    .unwrap_or(false);
                if is_setup {
                    if let Some((_, FVal::List(keywords))) = fields.get_mut(2) {
                        keywords.retain(|keyword| {
                            if let FVal::Node("keyword", kw_fields) = keyword {
                                if let Some((_, FVal::Str(arg))) = kw_fields.first() {
                                    return !METADATA_KEYS.contains(&arg.as_str());
                                }
                            }
                            true // **kwargs (arg is None) stay
                        });
                    }
                }
            }
        }
        FVal::List(items) => {
            for item in items {
                strip_setup_calls(item);
            }
        }
        FVal::Paren(inner) => strip_setup_calls(inner),
        _ => {}
    }
}

fn setup_signature(text: &str) -> Option<String> {
    let toks = py_tokenize(text).ok()?;
    let mut parser = AstParser { toks, pos: 0 };
    let mut module = parser.parse_module()?;
    if parser.pos != parser.toks.len() {
        return None;
    }
    strip_setup_calls(&mut module);
    let mut out = String::new();
    render_fval(&module, &mut out);
    Some(out)
}

/// One manifest side's read state, mirroring `_manifest_signature`:
/// the git lookup itself failed (Unknown), the file is not in the tree
/// (Absent), or its decoded text.
#[derive(Clone, Copy)]
pub enum SigSide<'a> {
    Unknown,
    Absent,
    Text(&'a str),
}

/// The outcome of one manifest signature computation.
pub enum ManSig {
    /// The path is not a conditional manifest.
    NotManifest,
    /// A manifest whose signature cannot be computed (fail closed).
    Unknown,
    /// The signature ("" for an absent file).
    Sig(String),
}

/// `_manifest_signature` + `_conditional_signature` for one tree side.
/// The dispatch folds the basename, like Python's casefold comparison.
pub fn manifest_signature(path: &str, side: SigSide<'_>) -> ManSig {
    if !conditional_manifest(path) {
        return ManSig::NotManifest;
    }
    let text = match side {
        SigSide::Unknown => return ManSig::Unknown,
        SigSide::Absent => return ManSig::Sig(String::new()),
        SigSide::Text(text) => text,
    };
    let name = folded_basename(path);
    let folded = casefold(&name);
    let inner = if folded == "package.json" || folded == "composer.json" {
        json_signature(text)
    } else if folded.ends_with(".csproj")
        || folded == "directory.packages.props"
        || folded == "packages.config"
        || folded == "pom.xml"
    {
        xml_signature(text)
    } else if folded == "setup.py" {
        setup_signature(text)
    } else if folded.ends_with(".toml") || folded == "pipfile" {
        toml_signature(text)
    } else {
        Some(line_signature(text))
    };
    match inner {
        Some(signature) => ManSig::Sig(signature),
        None => ManSig::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Row-level classification: the scan.rs seam (mirrors _scan_row_class,
// _scan_row_manifest and _scan_classify in the hook).

/// One side of a changed row, as the scan loop sees it.
pub enum RowSide<'a> {
    /// Not in this tree (added/deleted side).
    Absent,
    /// Present but the blob could not be read as text.
    Unavailable,
    /// Present; decoded text and whether the content is binary.
    Text(&'a str, bool),
}

pub struct RowInput<'a> {
    pub path: &'a str,
    pub status: char,
    pub old: RowSide<'a>,
    pub new: RowSide<'a>,
    pub mode_changed: bool,
}

pub struct RowOutput {
    /// docs-only | comment-only | tests-only | logic
    pub class: &'static str,
    pub class_reason: Option<&'static str>,
    pub risk: bool,
    /// (current-tree signature, deps_changed) for a manifest row; the
    /// signature itself is None when unmeasurable (deps_changed is then
    /// true, fail closed, like `_scan_row_manifest`).
    pub manifest: Option<(Option<String>, bool)>,
}

fn fallback_class(path: &str) -> &'static str {
    if is_test_path(path) {
        "tests-only"
    } else {
        "logic"
    }
}

fn side_binary(side: &RowSide<'_>) -> bool {
    matches!(side, RowSide::Text(_, true))
}

fn side_text<'a>(side: &RowSide<'a>) -> Option<&'a str> {
    match side {
        RowSide::Text(text, _) => Some(text),
        _ => None,
    }
}

fn sig_side<'a>(side: &RowSide<'a>) -> SigSide<'a> {
    match side {
        RowSide::Absent => SigSide::Absent,
        RowSide::Unavailable => SigSide::Unknown,
        RowSide::Text(text, _) => SigSide::Text(text),
    }
}

/// Classify one changed row and compute its manifest facts.
pub fn classify_row(input: &RowInput<'_>) -> RowOutput {
    let path = input.path;
    // Manifest facts first (independent of the class computation).
    // A manifest row always carries an entry; an unmeasurable signature
    // is null inside it and counts as a dependency change.
    let is_manifest = conditional_manifest(path);
    let manifest = if is_manifest {
        let sig = |side: SigSide<'_>| match manifest_signature(path, side) {
            ManSig::Sig(signature) => Some(signature),
            _ => None,
        };
        let before = sig(sig_side(&input.old));
        let after = sig(sig_side(&input.new));
        let deps_changed = before.is_none() || after.is_none() || before != after;
        Some((after, deps_changed))
    } else {
        None
    };
    let deps_changed = manifest.as_ref().map(|(_, changed)| *changed).unwrap_or(false);
    let risk = risk_match_one(path) || (deps_changed && !risk_exempt(path));

    if is_doc_path(path) {
        return RowOutput { class: "docs-only", class_reason: None, risk, manifest };
    }
    let fallback = fallback_class(path);
    let (class, reason): (&'static str, Option<&'static str>) = match input.status {
        'A' | 'D' => (fallback, None),
        'T' => (fallback, Some("typechange")),
        _ => {
            if side_binary(&input.old) || side_binary(&input.new) {
                (fallback, Some("binary-content"))
            } else if input.mode_changed {
                (fallback, Some("mode-change"))
            } else {
                match comment_style(path) {
                    None => (fallback, None),
                    Some(style) => {
                        match (side_text(&input.old), side_text(&input.new)) {
                            (Some(old), Some(new)) => {
                                match comment_verdict(style, old, new, path) {
                                    Verdict::CommentOnly => ("comment-only", None),
                                    Verdict::Differs => (fallback, None),
                                    Verdict::Unparseable => {
                                        (fallback, Some("unparseable-source"))
                                    }
                                }
                            }
                            _ => (fallback, Some("content-unavailable")),
                        }
                    }
                }
            }
        }
    };
    RowOutput { class, class_reason: reason, risk, manifest }
}

/// The overall class over all rows (mirrors `_scan_classify`): returns
/// (class, reason, unmeasurable). Rows arrive with their test-path flag.
pub fn overall_class(rows: &[(bool, &RowOutput)]) -> (Option<&'static str>, Option<&'static str>, bool) {
    let active: Vec<&(bool, &RowOutput)> =
        rows.iter().filter(|(_, row)| row.class != "docs-only").collect();
    if !active.is_empty() {
        if active.iter().all(|(_, row)| row.class == "comment-only") {
            return (Some("comment-only"), None, false);
        }
        let class = if active.iter().all(|(is_test, _)| *is_test) {
            "tests-only"
        } else {
            "logic"
        };
        let reason = active
            .iter()
            .filter_map(|(_, row)| row.class_reason)
            .next();
        return (Some(class), reason, false);
    }
    if !rows.is_empty() {
        return (Some("docs-only"), None, false);
    }
    // No rows at all (baseline == current): still docs-only, like the
    // oracle's empty-active branch.
    (Some("docs-only"), None, false)
}

