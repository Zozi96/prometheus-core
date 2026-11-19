//! Shared line-indexing and language-aware lexical helpers for `outline` and `slice`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexLang {
    CSharp,
    Rust,
    TsJs,
    Go,
    PowerShell,
    Python,
    Json,
}

/// Byte spans `(start, end)` for every 1-based line in a UTF-8 buffer (excluding `\r?\n`).
#[derive(Debug, Clone)]
pub struct LineIndex {
    spans: Vec<(usize, usize)>,
}

impl LineIndex {
    pub fn new(src: &str) -> Self {
        let bytes = src.as_bytes();
        let mut spans = Vec::new();
        let mut start = 0usize;
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'\n' {
                let end = if i > start && bytes[i - 1] == b'\r' {
                    i - 1
                } else {
                    i
                };
                spans.push((start, end));
                start = i + 1;
            }
            i += 1;
        }
        if start < bytes.len() {
            let end = if bytes[bytes.len() - 1] == b'\r' {
                bytes.len() - 1
            } else {
                bytes.len()
            };
            spans.push((start, end));
        }
        Self { spans }
    }

    pub fn total_lines(&self) -> usize {
        self.spans.len()
    }

    /// 1-based line number containing `byte_offset` (clamped to `1..=total_lines`, or `1` when empty).
    pub fn line_of(&self, byte_offset: usize) -> usize {
        if self.spans.is_empty() {
            return 1;
        }
        let idx = self.spans.partition_point(|&(start, _)| start <= byte_offset);
        idx.clamp(1, self.spans.len())
    }

    pub fn line_span(&self, line_1based: usize) -> Option<(usize, usize)> {
        if line_1based == 0 || line_1based > self.spans.len() {
            return None;
        }
        Some(self.spans[line_1based - 1])
    }

    pub fn line_slice<'a>(&self, src: &'a str, line_1based: usize) -> &'a str {
        match self.line_span(line_1based) {
            Some((s, e)) => &src[s..e],
            None => "",
        }
    }

    pub fn line_start(&self, line_1based: usize) -> usize {
        self.line_span(line_1based).map(|(s, _)| s).unwrap_or(0)
    }

    pub fn line_end(&self, line_1based: usize) -> usize {
        self.line_span(line_1based).map(|(_, e)| e).unwrap_or(0)
    }
}

/// Collapse runs of whitespace/newlines into single spaces and truncate cleanly.
pub fn normalize_signature(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars.saturating_add(4)));
    let mut prev_space = true; // trim leading whitespace
    for ch in raw.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    if max_chars > 0 && out.chars().count() > max_chars {
        let keep = max_chars.saturating_sub(3);
        let truncated: String = out.chars().take(keep).collect();
        format!("{}...", truncated.trim_end())
    } else {
        out
    }
}

pub fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_line_comment(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], pos: usize, nested: bool) -> usize {
    let mut i = pos + 2;
    let mut depth = 1usize;
    while i + 1 < bytes.len() {
        if nested && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
            continue;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_escaped_string(bytes: &[u8], pos: usize, quote: u8, escape: u8, stop_at_newline: bool) -> usize {
    let mut i = pos + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == escape {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if b == quote {
            return i + 1;
        }
        if stop_at_newline && b == b'\n' {
            return i;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_backtick_raw(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos + 1;
    while i < bytes.len() {
        if bytes[i] == b'`' {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_csharp_verbatim(bytes: &[u8], quote_pos: usize) -> usize {
    let mut i = quote_pos + 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if bytes.get(i + 1) == Some(&b'"') {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_csharp_interpolated(bytes: &[u8], quote_pos: usize, verbatim: bool) -> usize {
    let mut i = quote_pos + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if verbatim {
            if b == b'"' {
                if bytes.get(i + 1) == Some(&b'"') {
                    i += 2;
                    continue;
                }
                return i + 1;
            }
        } else {
            if b == b'\\' {
                i = (i + 2).min(bytes.len());
                continue;
            }
            if b == b'"' {
                return i + 1;
            }
            if b == b'\n' {
                return i;
            }
        }
        if b == b'{' {
            if bytes.get(i + 1) == Some(&b'{') {
                i += 2;
                continue;
            }
            if let Some(close) = find_matching_delim(bytes, i, b'{', b'}', LexLang::CSharp) {
                i = close + 1;
                continue;
            }
            return bytes.len();
        }
        i += 1;
    }
    bytes.len()
}

fn skip_csharp_raw_string(bytes: &[u8], quote_start: usize) -> usize {
    let mut quotes = 0usize;
    while quote_start + quotes < bytes.len() && bytes[quote_start + quotes] == b'"' {
        quotes += 1;
    }
    let mut i = quote_start + quotes;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut run = 0usize;
            while i + run < bytes.len() && bytes[i + run] == b'"' {
                run += 1;
            }
            if run >= quotes {
                return i + quotes;
            }
            i += run;
            continue;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_rust_raw_string(bytes: &[u8], pos: usize) -> Option<usize> {
    if pos > 0 && is_ident_byte(bytes[pos - 1]) {
        return None;
    }
    let mut i = pos;
    match bytes.get(i) {
        Some(b'r') => i += 1,
        Some(b'b') | Some(b'c') if bytes.get(i + 1) == Some(&b'r') => i += 2,
        _ => return None,
    }
    let mut hashes = 0usize;
    while bytes.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut matched = 0usize;
            while matched < hashes && bytes.get(i + 1 + matched) == Some(&b'#') {
                matched += 1;
            }
            if matched == hashes {
                return Some(i + 1 + hashes);
            }
        }
        i += 1;
    }
    Some(bytes.len())
}

fn skip_rust_char(bytes: &[u8], pos: usize) -> Option<usize> {
    // Either `'...'` or `b'...'`
    let quote_pos = if bytes.get(pos) == Some(&b'b')
        && bytes.get(pos + 1) == Some(&b'\'')
        && (pos == 0 || !is_ident_byte(bytes[pos - 1]))
    {
        pos + 1
    } else if bytes.get(pos) == Some(&b'\'') {
        pos
    } else {
        return None;
    };

    let next = quote_pos + 1;
    if next >= bytes.len() {
        return None;
    }
    if bytes[next] == b'\\' {
        let mut i = next + 1;
        if i >= bytes.len() {
            return None;
        }
        i += 1;
        let limit = (quote_pos + 14).min(bytes.len());
        while i < limit {
            if bytes[i] == b'\'' {
                return Some(i + 1);
            }
            if bytes[i] == b'\n' {
                return None;
            }
            i += 1;
        }
        return None;
    }
    // Single UTF-8 scalar followed immediately by `'`, never `\n` or `'`
    let b0 = bytes[next];
    if b0 == b'\'' || b0 == b'\n' || b0 == b'\r' {
        return None;
    }
    let char_len = if b0 < 0x80 {
        1
    } else if b0 >> 5 == 0b110 {
        2
    } else if b0 >> 4 == 0b1110 {
        3
    } else {
        4
    };
    if next + char_len < bytes.len() && bytes[next + char_len] == b'\'' {
        return Some(next + char_len + 1);
    }
    None
}

fn skip_ts_template(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if b == b'`' {
            return i + 1;
        }
        if b == b'$' && bytes.get(i + 1) == Some(&b'{') {
            if let Some(close) = find_matching_delim(bytes, i + 1, b'{', b'}', LexLang::TsJs) {
                i = close + 1;
                continue;
            }
            return bytes.len();
        }
        i += 1;
    }
    bytes.len()
}

fn looks_like_js_regex(bytes: &[u8], pos: usize) -> bool {
    // Never treat `</tag>` as regex; check previous non-whitespace byte.
    let mut i = pos;
    while i > 0 {
        i -= 1;
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'<' || b == b')' || b == b']' || b == b'"' || b == b'\'' || b == b'`' {
            return false;
        }
        if is_ident_byte(b) {
            // Check keyword prefixes like `return /re/`, `case /re/`, `throw /re/`, `typeof /re/`
            let mut start = i;
            while start > 0 && is_ident_byte(bytes[start - 1]) {
                start -= 1;
            }
            let word = &bytes[start..=i];
            return matches!(
                word,
                b"return" | b"case" | b"throw" | b"typeof" | b"await" | b"yield" | b"in" | b"of"
            );
        }
        return matches!(
            b,
            b'=' | b'(' | b',' | b'[' | b'!' | b'&' | b'|' | b'?' | b':' | b';' | b'{' | b'}' | b'~'
                | b'+' | b'-' | b'*' | b'%' | b'^' | b'>'
        );
    }
    true
}

fn skip_js_regex(bytes: &[u8], pos: usize) -> Option<usize> {
    if !looks_like_js_regex(bytes, pos) {
        return None;
    }
    let mut i = pos + 1;
    let mut in_class = false;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' || b == b'\r' {
            return None;
        }
        if b == b'\\' {
            if i + 1 < bytes.len() && bytes[i + 1] != b'\n' {
                i += 2;
                continue;
            }
            return None;
        }
        if b == b'[' {
            in_class = true;
        } else if b == b']' {
            in_class = false;
        } else if b == b'/' && !in_class {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

fn skip_powershell_block_comment(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos + 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b'#' && bytes[i + 1] == b'>' {
            return i + 2;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_powershell_herestring(bytes: &[u8], pos: usize, quote: u8) -> Option<usize> {
    // `@"` or `@'` followed by optional spaces/tabs then `\r?\n`
    let mut i = pos + 2;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if bytes.get(i) == Some(&b'\r') {
        i += 1;
    }
    if bytes.get(i) != Some(&b'\n') {
        return None;
    }
    i += 1;
    while i < bytes.len() {
        if bytes.get(i) == Some(&quote) && bytes.get(i + 1) == Some(&b'@') {
            return Some(i + 2);
        }
        while i < bytes.len() && bytes[i] != b'\n' {
            i += 1;
        }
        if i < bytes.len() {
            i += 1;
        }
    }
    Some(bytes.len())
}

fn skip_powershell_double_string(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'`' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if b == b'"' {
            return i + 1;
        }
        if b == b'$' && bytes.get(i + 1) == Some(&b'(') {
            if let Some(close) = find_matching_delim(bytes, i + 1, b'(', b')', LexLang::PowerShell) {
                i = close + 1;
                continue;
            }
            return bytes.len();
        }
        i += 1;
    }
    bytes.len()
}

fn skip_powershell_single_string(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos + 1;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if bytes.get(i + 1) == Some(&b'\'') {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_python_string(bytes: &[u8], pos: usize) -> Option<usize> {
    let mut i = pos;
    let mut prefix_len = 0usize;
    if i > 0 && is_ident_byte(bytes[i - 1]) {
        // Only treat prefix + quote if prefix is not attached to an earlier identifier.
        // We check when caller sits at start of prefix or at quote itself.
        return None;
    }
    while prefix_len < 2 && i < bytes.len() {
        let b = bytes[i].to_ascii_lowercase();
        if matches!(b, b'r' | b'b' | b'f' | b'u') {
            i += 1;
            prefix_len += 1;
        } else {
            break;
        }
    }
    let quote = *bytes.get(i)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let is_triple = bytes.get(i + 1) == Some(&quote) && bytes.get(i + 2) == Some(&quote);
    if is_triple {
        i += 3;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i = (i + 2).min(bytes.len());
                continue;
            }
            if bytes[i] == quote
                && bytes.get(i + 1) == Some(&quote)
                && bytes.get(i + 2) == Some(&quote)
            {
                return Some(i + 3);
            }
            i += 1;
        }
        Some(bytes.len())
    } else {
        Some(skip_escaped_string(bytes, i, quote, b'\\', true))
    }
}

/// If `bytes[pos]` begins a comment or string/char/regex literal in `lang`,
/// returns `Some(next_pos)` immediately past the construct; otherwise `None`.
pub fn skip_string_or_comment(bytes: &[u8], pos: usize, lang: LexLang) -> Option<usize> {
    let b = *bytes.get(pos)?;
    match lang {
        LexLang::CSharp => {
            if b == b'/' && bytes.get(pos + 1) == Some(&b'/') {
                return Some(skip_line_comment(bytes, pos));
            }
            if b == b'/' && bytes.get(pos + 1) == Some(&b'*') {
                return Some(skip_block_comment(bytes, pos, false));
            }
            if b == b'#' {
                // Skip C# preprocessor lines (`#region`, `#if`, etc.) when `#` starts a line.
                let mut back = pos;
                let mut line_start = true;
                while back > 0 && bytes[back - 1] != b'\n' {
                    back -= 1;
                    if !matches!(bytes[back], b' ' | b'\t') {
                        line_start = false;
                        break;
                    }
                }
                if line_start {
                    return Some(skip_line_comment(bytes, pos));
                }
            }
            if b == b'$' {
                let mut j = pos;
                while bytes.get(j) == Some(&b'$') {
                    j += 1;
                }
                if bytes.get(j) == Some(&b'"') {
                    if bytes.get(j + 1) == Some(&b'"') && bytes.get(j + 2) == Some(&b'"') {
                        return Some(skip_csharp_raw_string(bytes, j));
                    }
                    return Some(skip_csharp_interpolated(bytes, j, false));
                }
                if bytes.get(j) == Some(&b'@') && bytes.get(j + 1) == Some(&b'"') {
                    return Some(skip_csharp_interpolated(bytes, j + 1, true));
                }
            }
            if b == b'@' {
                if bytes.get(pos + 1) == Some(&b'"') {
                    return Some(skip_csharp_verbatim(bytes, pos + 1));
                }
                if bytes.get(pos + 1) == Some(&b'$') && bytes.get(pos + 2) == Some(&b'"') {
                    return Some(skip_csharp_interpolated(bytes, pos + 2, true));
                }
            }
            if b == b'"' {
                if bytes.get(pos + 1) == Some(&b'"') && bytes.get(pos + 2) == Some(&b'"') {
                    return Some(skip_csharp_raw_string(bytes, pos));
                }
                return Some(skip_escaped_string(bytes, pos, b'"', b'\\', true));
            }
            if b == b'\'' {
                return Some(skip_escaped_string(bytes, pos, b'\'', b'\\', true));
            }
            None
        }
        LexLang::Rust => {
            if b == b'/' && bytes.get(pos + 1) == Some(&b'/') {
                return Some(skip_line_comment(bytes, pos));
            }
            if b == b'/' && bytes.get(pos + 1) == Some(&b'*') {
                return Some(skip_block_comment(bytes, pos, true));
            }
            if let Some(end) = skip_rust_raw_string(bytes, pos) {
                return Some(end);
            }
            if (b == b'b' || b == b'c')
                && bytes.get(pos + 1) == Some(&b'"')
                && (pos == 0 || !is_ident_byte(bytes[pos - 1]))
            {
                return Some(skip_escaped_string(bytes, pos + 1, b'"', b'\\', false));
            }
            if b == b'"' {
                return Some(skip_escaped_string(bytes, pos, b'"', b'\\', false));
            }
            if b == b'\'' || b == b'b' {
                return skip_rust_char(bytes, pos);
            }
            None
        }
        LexLang::TsJs => {
            if b == b'/' && bytes.get(pos + 1) == Some(&b'/') {
                return Some(skip_line_comment(bytes, pos));
            }
            if b == b'/' && bytes.get(pos + 1) == Some(&b'*') {
                return Some(skip_block_comment(bytes, pos, false));
            }
            if b == b'/' {
                if let Some(end) = skip_js_regex(bytes, pos) {
                    return Some(end);
                }
            }
            if b == b'"' {
                return Some(skip_escaped_string(bytes, pos, b'"', b'\\', true));
            }
            if b == b'\'' {
                return Some(skip_escaped_string(bytes, pos, b'\'', b'\\', true));
            }
            if b == b'`' {
                return Some(skip_ts_template(bytes, pos));
            }
            None
        }
        LexLang::Go => {
            if b == b'/' && bytes.get(pos + 1) == Some(&b'/') {
                return Some(skip_line_comment(bytes, pos));
            }
            if b == b'/' && bytes.get(pos + 1) == Some(&b'*') {
                return Some(skip_block_comment(bytes, pos, false));
            }
            if b == b'"' {
                return Some(skip_escaped_string(bytes, pos, b'"', b'\\', true));
            }
            if b == b'\'' {
                return Some(skip_escaped_string(bytes, pos, b'\'', b'\\', true));
            }
            if b == b'`' {
                return Some(skip_backtick_raw(bytes, pos));
            }
            None
        }
        LexLang::PowerShell => {
            if b == b'<' && bytes.get(pos + 1) == Some(&b'#') {
                return Some(skip_powershell_block_comment(bytes, pos));
            }
            if b == b'#' {
                return Some(skip_line_comment(bytes, pos));
            }
            if b == b'@' && matches!(bytes.get(pos + 1), Some(b'"') | Some(b'\'')) {
                if let Some(end) = skip_powershell_herestring(bytes, pos, bytes[pos + 1]) {
                    return Some(end);
                }
            }
            if b == b'"' {
                return Some(skip_powershell_double_string(bytes, pos));
            }
            if b == b'\'' {
                return Some(skip_powershell_single_string(bytes, pos));
            }
            None
        }
        LexLang::Python => {
            if b == b'#' {
                return Some(skip_line_comment(bytes, pos));
            }
            skip_python_string(bytes, pos)
        }
        LexLang::Json => {
            if b == b'/' && bytes.get(pos + 1) == Some(&b'/') {
                return Some(skip_line_comment(bytes, pos));
            }
            if b == b'/' && bytes.get(pos + 1) == Some(&b'*') {
                return Some(skip_block_comment(bytes, pos, false));
            }
            if b == b'"' {
                return Some(skip_escaped_string(bytes, pos, b'"', b'\\', false));
            }
            None
        }
    }
}

/// Find the byte index of the matching `close_ch` for `bytes[open_pos] == open_ch`.
pub fn find_matching_delim(
    bytes: &[u8],
    open_pos: usize,
    open_ch: u8,
    close_ch: u8,
    lang: LexLang,
) -> Option<usize> {
    if bytes.get(open_pos) != Some(&open_ch) {
        return None;
    }
    let mut i = open_pos + 1;
    let mut depth = 1usize;
    while i < bytes.len() {
        if let Some(next) = skip_string_or_comment(bytes, i, lang) {
            i = next;
            continue;
        }
        if bytes[i] == open_ch {
            depth += 1;
        } else if bytes[i] == close_ch {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_handles_crlf_and_trailing_newline() {
        let src = "first\r\nsecond\r\nthird\n";
        let idx = LineIndex::new(src);
        assert_eq!(idx.total_lines(), 3);
        assert_eq!(idx.line_slice(src, 1), "first");
        assert_eq!(idx.line_slice(src, 2), "second");
        assert_eq!(idx.line_slice(src, 3), "third");
        assert_eq!(idx.line_of(0), 1);
        assert_eq!(idx.line_of(7), 2);
        assert_eq!(idx.line_of(15), 3);
        assert_eq!(idx.line_of(src.len()), 3);
    }

    #[test]
    fn csharp_verbatim_interpolated_and_raw_strings_keep_braces_balanced() {
        let src = r#"{
            var a = @"brace } "" { here";
            var b = $"value: {dict["key"]} and }}";
            var c = """
                unclosed } { inside raw
            """;
            #region Don't break { on apostrophe
            var d = $$"""nested {{x}} }""";
        }"#;
        let close = find_matching_delim(src.as_bytes(), 0, b'{', b'}', LexLang::CSharp);
        assert_eq!(close, Some(src.len() - 1));
    }

    #[test]
    fn rust_lifetimes_chars_raw_strings_and_nested_comments() {
        let src = r##"{
            /* outer /* inner } */ still comment { */
            let s: &'a str = r#"raw } " quote"#;
            let ch = '}';
            let q = '\'';
            let u = '\u{7d}';
            let b = b'}';
            fn helper<'a, 'static_like>(x: &'a str) {}
        }"##;
        let close = find_matching_delim(src.as_bytes(), 0, b'{', b'}', LexLang::Rust);
        assert_eq!(close, Some(src.len() - 1));
    }

    #[test]
    fn ts_template_nesting_and_regex() {
        let src = r#"{ const x = `a ${fn({ k: `}` })} b`; const re = /["{}]/g; return <div>{x}</div>; }"#;
        let close = find_matching_delim(src.as_bytes(), 0, b'{', b'}', LexLang::TsJs);
        assert_eq!(close, Some(src.len() - 1));
    }

    #[test]
    fn powershell_herestrings_and_subexpressions() {
        let src = "{\n$a = @\"\n} { fake brace\n\"@\n$b = \"val $($x[\"}\"])\"\n$c = 'don''t } break'\n<# } #>\n}";
        let close = find_matching_delim(src.as_bytes(), 0, b'{', b'}', LexLang::PowerShell);
        assert_eq!(close, Some(src.len() - 1));
    }

    #[test]
    fn python_triple_quotes_and_escaped_raw_quotes() {
        let src = "(\n  \"\"\"def fake():\n  )\"\"\",\n  r\"\\\"\",\n)";
        let close = find_matching_delim(src.as_bytes(), 0, b'(', b')', LexLang::Python);
        assert_eq!(close, Some(src.len() - 1));
    }

    #[test]
    fn normalize_signature_collapses_and_truncates() {
        assert_eq!(
            normalize_signature("  public   async\n  Task<int>\tRunAsync()  ", 140),
            "public async Task<int> RunAsync()"
        );
        assert_eq!(normalize_signature("abcdef", 5), "ab...");
    }
}
