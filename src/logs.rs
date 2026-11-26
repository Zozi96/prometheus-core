//! Test-log parsing: streaming parsers that turn check output into a
//! typed result — counts or a named error, failing lines, and failed-test
//! selectors.
//!
//! One deep operation at the engine seam: `parse_log` takes the log text
//! and returns a [`ParsedLog`]. Inside, the parse is line-incremental:
//! each family keeps only the small state its summary needs, so a log's
//! size costs time, not memory. The golden corpus under
//! `tests/fixtures/log_corpus/` is the parser's oracle. Malformed input is
//! data, never a crash: every failure is a named `error` code in the
//! result, and a parser panic yields the `no-summary` error instead of
//! reaching the caller.

use std::collections::{HashMap, HashSet};

const FAILING_LINE_LIMIT: usize = 50;
const SELECTOR_LIMIT: usize = 50;

#[derive(Clone, Copy, Default)]
struct Counts {
    passed: i128,
    failed: i128,
    skipped: i128,
    total: i128,
}

impl Counts {
    fn add(&mut self, other: &Counts) {
        self.passed += other.passed;
        self.failed += other.failed;
        self.skipped += other.skipped;
        self.total += other.total;
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// Preprocessing: ANSI escapes out, line endings to `\n`.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            let mut j = i + 2;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b';') {
                j += 1;
            }
            if j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                i = j + 1;
                continue;
            }
        }
        // ESC and '[' are ASCII, so the escape scan never splits a char.
        let ch_len = utf8_len(bytes[i]);
        out.push_str(&text[i..i + ch_len]);
        i += ch_len;
    }
    out.replace("\r\n", "\n").replace('\r', "\n")
}

/// Split lines on the boundary set a log can contain
/// (`\n`, `\r`, `\r\n`, `\x0b`, `\x0c`).
fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' || b == b'\r' || b == 0x0b || b == 0x0c {
            lines.push(&text[start..i]);
            if b == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 1;
            }
            i += 1;
            start = i;
        } else {
            i += utf8_len(b);
        }
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// An integer for the strings these parsers feed it: surrounding
/// whitespace, an optional sign, then ASCII digits. Anything else is not a
/// count and reports `bad-count` instead.
fn parse_int(raw: &str) -> Option<i128> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    let (sign, digits) = match text.strip_prefix('-') {
        Some(rest) => (-1i128, rest),
        None => (1i128, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: i128 = 0;
    for b in digits.bytes() {
        value = value.checked_mul(10)?.checked_add((b - b'0') as i128)?;
    }
    Some(sign * value)
}

/// A strict count field: ASCII digits only.
fn is_count(raw: &str) -> Option<i128> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    parse_int(raw)
}

fn strip_suffix_ci<'a>(text: &'a str, suffix: &str) -> Option<&'a str> {
    if text.len() < suffix.len() {
        return None;
    }
    let head = &text[..text.len() - suffix.len()];
    let tail = &text[text.len() - suffix.len()..];
    tail.bytes()
        .zip(suffix.bytes())
        .all(|(a, b)| a.to_ascii_lowercase() == b)
        .then_some(head)
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    if text.len() < prefix.len() {
        return None;
    }
    let head = &text[..prefix.len()];
    head.bytes()
        .zip(prefix.bytes())
        .all(|(a, b)| a.to_ascii_lowercase() == b)
        .then_some(&text[prefix.len()..])
}

fn rfind_ci(text: &str, needle: &str) -> Option<usize> {
    if needle.len() > text.len() {
        return None;
    }
    (0..=text.len() - needle.len())
        .rev()
        .find(|&at| strip_prefix_ci(&text[at..], needle).is_some())
}

fn take_digits(text: &str) -> Option<(i128, &str)> {
    let digits = text.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    Some((parse_int(&text[..digits])?, &text[digits..]))
}

// ---------------------------------------------------------------------------
// Failing lines (raw text, first 50).

fn is_failing_line(line: &str) -> bool {
    if line.starts_with("FAIL:") || line.starts_with("ERROR:") || line.starts_with("failures:") {
        return true;
    }
    for head in ["FAILED", "ERROR"] {
        if let Some(rest) = line.strip_prefix(head) {
            if rest.starts_with([' ', '\t', '\u{a0}']) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Failure selectors: one per failing test, in log order, in a shape the
// Write brief's `_repair_command` turns into a targeted rerun.

fn unittest_selector(name: &str, qualifier: &str) -> String {
    // Python 3.12+ prints the full id, the trailing component included —
    // also for a failed import, whose qualifier is
    // `unittest.loader._FailedTest.<module>`. Strip the trailing component
    // BEFORE the _FailedTest special case, or it never matches and the
    // selector names the loader instead of the broken module.
    let qualifier = qualifier
        .strip_suffix(&format!(".{name}"))
        .unwrap_or(qualifier);
    if qualifier == "unittest.loader._FailedTest" {
        return format!("{}.py", name.replace('.', "/"));
    }
    let mut parts: Vec<&str> = qualifier.split('.').collect();
    match name {
        "setUpModule" | "tearDownModule" => format!("{}.py", parts.join("/")),
        "setUpClass" | "tearDownClass" => {
            let module = if parts.len() > 1 { &parts[..parts.len() - 1] } else { &parts[..] };
            format!("{}.py", module.join("/"))
        }
        _ => {
            if parts.len() > 1 && parts[parts.len() - 1] == name {
                parts.pop(); // Python 3.12+ prints the full id, method included.
            }
            if parts.len() == 1 {
                format!("{}.{}", parts[0], name)
            } else {
                format!(
                    "{}.py:{}.{}",
                    parts[..parts.len() - 1].join("/"),
                    parts[parts.len() - 1],
                    name
                )
            }
        }
    }
}

/// `^(?:FAIL|ERROR): (\S+) \(([^)]+)\)`
fn unittest_failure(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("FAIL: ").or_else(|| line.strip_prefix("ERROR: "))?;
    let open = rest.find(" (")?;
    let name = &rest[..open];
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    let inner_start = open + 2;
    let close = rest[inner_start..].find(')')?;
    if close == 0 {
        return None;
    }
    Some((name, &rest[inner_start..inner_start + close]))
}

/// The pytest short-summary lines (`FAILED ...`, `ERROR ...`): the nodeid
/// is the text before the " - " detail separator, kept only when it is
/// nodeid-shaped (a `::` path, or a bare `.py` file with no spaces).
fn pytest_failure(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("FAILED ").or_else(|| line.strip_prefix("ERROR "))?;
    let nodeid = rest.split(" - ").next()?.trim();
    if nodeid.contains("::") || (nodeid.ends_with(".py") && !nodeid.contains(' ')) {
        Some(nodeid)
    } else {
        None
    }
}

/// `^test (\S+) \.\.\. FAILED[ \t]*$` (doc tests, whose names are paths, skip).
fn cargo_failure(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("test ")?.trim_end_matches([' ', '\t']);
    let name = rest.strip_suffix(" ... FAILED")?;
    if name.is_empty()
        || name.contains(char::is_whitespace)
        || name.contains('/')
        || name.ends_with(".rs")
    {
        return None;
    }
    Some(name)
}

/// `^[ \t]+Failed (\S+) \[[^\]]*\]` — the VSTest per-test failure line.
fn vstest_failure(line: &str) -> Option<&str> {
    let rest = line.trim_start_matches([' ', '\t']).strip_prefix("Failed ")?;
    let end = rest.find(" [")?;
    if !rest[end + 2..].contains(']') {
        return None;
    }
    let name = &rest[..end];
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some(name)
}

/// `^[ \t]+failed (\S+) \([^()]*\)[ \t]*$` — the MTP per-test failure line.
/// The name must look like a fully qualified test name, never an assembly
/// path or a count field.
fn mtp_failure(line: &str) -> Option<&str> {
    let trimmed = line.trim_end_matches([' ', '\t']);
    let rest = trimmed.trim_start_matches([' ', '\t']).strip_prefix("failed ")?;
    let open = rest.find(" (")?;
    let name = &rest[..open];
    let inner = rest[open + 2..].strip_suffix(')')?;
    if inner.contains(['(', ')'])
        || name.is_empty()
        || name.contains(char::is_whitespace)
        || name.contains('/')
        || !name.contains('.')
        || name.ends_with(".dll")
    {
        return None;
    }
    Some(name)
}

// ---------------------------------------------------------------------------
// unittest summaries.

/// `^Ran (\d+) tests? in `
fn unittest_ran(line: &str) -> Option<i128> {
    let rest = line.strip_prefix("Ran ")?;
    let digits = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let tail = &rest[digits..];
    if tail.starts_with(" tests in ") || tail.starts_with(" test in ") {
        parse_int(&rest[..digits])
    } else {
        None
    }
}

/// `^(?:OK|FAILED)(?: \(([^)]*)\))?[ \t]*$` → the parenthesised parts, if any.
fn unittest_end(line: &str) -> Option<Option<&str>> {
    let trimmed = line.trim_end_matches([' ', '\t']);
    for head in ["OK", "FAILED"] {
        if trimmed == head {
            return Some(None);
        }
        if let Some(rest) = trimmed.strip_prefix(head) {
            let inner = rest.strip_prefix(" (")?.strip_suffix(')')?;
            if !inner.contains(')') {
                return Some(Some(inner));
            }
            return None;
        }
    }
    None
}

fn is_no_tests_ran(line: &str) -> bool {
    match line.strip_prefix("NO TESTS RAN") {
        Some(rest) => rest.chars().all(|ch| matches!(ch, ' ' | '\t' | '\u{b}' | '\u{c}')),
        None => false,
    }
}

fn unittest_part(parts: &HashMap<String, String>, key: &str) -> Result<i128, &'static str> {
    match parts.get(key) {
        None => Ok(0),
        Some(raw) => parse_int(raw).ok_or("bad-count"),
    }
}

fn resolve_unittest(
    rans: &[(usize, i128)],
    ends: &[(usize, Option<String>)],
    no_tests_ran: &[usize],
) -> Result<(Counts, bool), &'static str> {
    let mut counts = Counts::default();
    let mut found = false;
    for (index, total) in rans {
        let end = ends.iter().find(|(at, _)| at > index);
        match end {
            None => {
                if no_tests_ran.iter().any(|at| at > index) {
                    counts.passed += total;
                    counts.total += total;
                    found = true;
                } else {
                    return Err("unittest-no-end");
                }
            }
            Some((_, parts_raw)) => {
                let mut parts: HashMap<String, String> = HashMap::new();
                if let Some(raw) = parts_raw {
                    for part in raw.split(',') {
                        if part.contains('=') {
                            let stripped = part.trim();
                            if let Some(eq) = stripped.find('=') {
                                parts.insert(
                                    stripped[..eq].to_string(),
                                    stripped[eq + 1..].to_string(),
                                );
                            }
                        }
                    }
                }
                let failed = unittest_part(&parts, "failures")?
                    + unittest_part(&parts, "errors")?
                    + unittest_part(&parts, "unexpected successes")?;
                let skipped = unittest_part(&parts, "skipped")?;
                counts.failed += failed;
                counts.skipped += skipped;
                counts.passed += total - failed - skipped;
                counts.total += total;
                found = true;
            }
        }
    }
    Ok((counts, found))
}

// ---------------------------------------------------------------------------
// pytest summaries.

/// ` in [\d.]+s\b.*` — the summary's tail after the items group.
fn pytest_tail(tail: &str) -> bool {
    let Some(rest) = tail.strip_prefix(" in ") else { return false };
    let digits = rest.bytes().take_while(|b| b.is_ascii_digit() || *b == b'.').count();
    if digits == 0 {
        return false;
    }
    let after = &rest[digits..];
    if !after.starts_with('s') {
        return false;
    }
    match after[1..].chars().next() {
        None => true,
        Some(ch) => !(ch.is_alphanumeric() || ch == '_'),
    }
}

/// The group of `^=*[ \t]*((?:\d+ [a-z]+(?:, )?)+|no tests ran) in [\d.]+s\b`:
/// the items span (or the literal), when the line is a pytest summary.
fn pytest_group(line: &str) -> Option<&str> {
    let rest = line.trim_start_matches('=').trim_start_matches([' ', '\t']);
    let bytes = rest.as_bytes();
    // Item boundaries: the end offset after each `\d+ [a-z]+` item. Items
    // are separated by ", ", or by nothing (the summary grammar allows the
    // separator group to match empty, gluing the counts together).
    let mut ends: Vec<usize> = Vec::new();
    let mut pos = 0;
    loop {
        let digits = bytes[pos..].iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 || bytes.get(pos + digits) != Some(&b' ') {
            break;
        }
        let word_start = pos + digits + 1;
        let word = bytes[word_start..]
            .iter()
            .take_while(|b| b.is_ascii_lowercase())
            .count();
        if word == 0 {
            break;
        }
        pos = word_start + word;
        ends.push(pos);
        if rest[pos..].starts_with(", ") {
            pos += 2;
        } else if bytes.get(pos).is_some_and(|b| b.is_ascii_digit()) {
            // Adjacent item with no separator: keep scanning.
        } else {
            break;
        }
    }
    for end in ends.iter().rev() {
        if pytest_tail(&rest[*end..]) {
            return Some(&rest[..*end]);
        }
    }
    if let Some(tail) = rest.strip_prefix("no tests ran") {
        if pytest_tail(tail) {
            return Some("no tests ran");
        }
    }
    None
}

fn pytest_counts(group: &str) -> Counts {
    let mut words: HashMap<&str, i128> = HashMap::new();
    for part in group.split(", ") {
        let Some((number, word)) = part.split_once(' ') else { continue };
        if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
            if let Some(value) = parse_int(number) {
                *words.entry(word).or_insert(0) += value;
            }
        }
    }
    let get = |key: &str| words.get(key).copied().unwrap_or(0);
    let mut counts = Counts::default();
    counts.failed = get("failed") + get("error") + get("errors");
    counts.skipped = get("skipped") + get("xfailed");
    counts.passed = get("passed") + get("xpassed");
    counts.total = counts.passed + counts.failed + counts.skipped;
    counts
}

// ---------------------------------------------------------------------------
// cargo summaries.

/// `^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;`
fn cargo_counts(line: &str) -> Option<Counts> {
    let rest = line.strip_prefix("test result: ")?;
    let word: usize = rest
        .chars()
        .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
        .map(char::len_utf8)
        .sum();
    if word == 0 {
        return None;
    }
    let mut tail = rest[word..].strip_prefix(". ")?;
    fn take(tail: &mut &str, literal: &str) -> Option<i128> {
        let digits = tail.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        let value = parse_int(&tail[..digits])?;
        *tail = tail[digits..].strip_prefix(literal)?;
        Some(value)
    }
    let passed = take(&mut tail, " passed; ")?;
    let failed = take(&mut tail, " failed; ")?;
    let ignored = take(&mut tail, " ignored;")?;
    Some(Counts {
        passed,
        failed,
        skipped: ignored,
        total: passed + failed + ignored,
    })
}

// ---------------------------------------------------------------------------
// .NET summaries (MTP and VSTest).

#[derive(Clone, Copy, PartialEq)]
enum Verdict {
    Passed,
    Failed,
    Zero,
    Skipped,
}

struct DotnetValues {
    total: i128,
    failed: i128,
    succeeded: i128,
    skipped: i128,
}

/// `[ \t]*-` plus a project: the shared summary project suffix. Returns the
/// project text (unstripped) when `rest` is exactly that suffix.
fn project_suffix(rest: &str) -> Option<&str> {
    let after = rest.trim_start_matches([' ', '\t']).strip_prefix('-')?;
    if after.is_empty() {
        return None;
    }
    Some(after)
}

/// Fullmatch of `(Passed|Failed)!` or a zero verdict, each with an optional
/// ` - project` suffix → (verdict, project).
fn mtp_status(status: &str) -> Option<(Verdict, Option<String>)> {
    for (head, verdict) in [("Passed!", Verdict::Passed), ("Failed!", Verdict::Failed)] {
        if let Some(rest) = status.strip_prefix(head) {
            if rest.is_empty() {
                return Some((verdict, None));
            }
            return project_suffix(rest).map(|project| (verdict, Some(project.trim().to_string())));
        }
    }
    for head in ["Zero tests ran!", "Zero tests ran", "No tests ran."] {
        if let Some(rest) = status.strip_prefix(head) {
            if rest.is_empty() {
                return Some((Verdict::Zero, None));
            }
            return project_suffix(rest)
                .map(|project| (Verdict::Zero, Some(project.trim().to_string())));
        }
    }
    None
}

const MTP_FIELD_NAMES: [&str; 6] = ["total", "failed", "succeeded", "skipped", "error", "duration"];

/// `^[ \t]+(name):[ \t]*(value)[ \t]*$` for the MTP field names.
fn mtp_field(line: &str) -> Option<(&str, &str)> {
    if !line.starts_with([' ', '\t']) {
        return None;
    }
    let trimmed = line.trim_end_matches([' ', '\t']);
    let body = trimmed.trim_start_matches([' ', '\t']);
    for name in MTP_FIELD_NAMES {
        if let Some(rest) = body.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix(':') {
                return Some((name, value.trim_start_matches([' ', '\t'])));
            }
        }
    }
    None
}

/// The verdict phrase at the end of an MTP assembly line's head zone,
/// returning what precedes it. Phrases (ASCII case-insensitive):
/// `passed`, `skipped`, `zero tests ran`, `failed`,
/// `failed with N error(s)`, optionally `and M warning(s)`, or
/// `failed with N warning(s)`.
fn assembly_head(zone: &str) -> Option<&str> {
    for phrase in [" passed", " skipped", " zero tests ran", " failed"] {
        if let Some(head) = strip_suffix_ci(zone, phrase) {
            return Some(head);
        }
    }
    let at = rfind_ci(zone, " failed with ")?;
    let rest = &zone[at + " failed with ".len()..];
    let (_, rest) = take_digits(rest)?;
    if let Some(after) = strip_prefix_ci(rest, " error(s)") {
        if after.is_empty() {
            return Some(&zone[..at]);
        }
        let after = strip_prefix_ci(after, " and ")?;
        let (_, after) = take_digits(after)?;
        if strip_prefix_ci(after, " warning(s)") == Some("") {
            return Some(&zone[..at]);
        }
        return None;
    }
    if let Some(after) = strip_prefix_ci(rest, " warning(s)") {
        if after.is_empty() {
            return Some(&zone[..at]);
        }
    }
    None
}

/// The MTP assembly line: ` <text> (<tfm>) <verdict> (<duration>)`.
fn mtp_assembly(line: &str) -> bool {
    if !line.starts_with([' ', '\t']) {
        return false;
    }
    let trimmed = line.trim_end_matches([' ', '\t']);
    if !trimmed.ends_with(')') {
        return false;
    }
    let Some(open2) = trimmed.rfind('(') else { return false };
    let inner2 = &trimmed[open2 + 1..trimmed.len() - 1];
    if inner2.contains(['(', ')']) {
        return false;
    }
    let Some(zone) = trimmed[..open2].strip_suffix(' ') else { return false };
    let Some(head) = assembly_head(zone) else { return false };
    if !head.ends_with(')') {
        return false;
    }
    let Some(open1) = head.rfind('(') else { return false };
    let inner1 = &head[open1 + 1..head.len() - 1];
    if inner1.contains(['(', ')']) {
        return false;
    }
    // `.+ \(`: at least one character before the space preceding '('.
    open1 >= 2 && head.as_bytes()[open1 - 1] == b' '
}

/// One MTP block as collected: the raw status text and its field lines.
struct MtpBlock {
    status: String,
    fields: Vec<(String, String)>,
}

/// `^[ \t]*Test run summary:[ \t]*(status)[ \t]*$` → the status text.
fn mtp_header(line: &str) -> Option<&str> {
    let rest = line.trim_start_matches([' ', '\t']).strip_prefix("Test run summary:")?;
    Some(rest.trim_matches([' ', '\t']))
}

/// `^(?:Passed|Failed|Skipped)![ \t]+-` — a VSTest summary line candidate.
fn vstest_candidate(line: &str) -> bool {
    for head in ["Passed!", "Failed!", "Skipped!"] {
        if let Some(rest) = line.strip_prefix(head) {
            let spaces = rest.bytes().take_while(|b| *b == b' ' || *b == b'\t').count();
            if spaces > 0 && rest[spaces..].starts_with('-') {
                return true;
            }
        }
    }
    false
}

fn take_count(tail: &mut &str, literal: &str) -> Option<i128> {
    let after_label = tail.strip_prefix(literal)?;
    let spaced = after_label.trim_start_matches([' ', '\t']);
    let digits = spaced.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let value = parse_int(&spaced[..digits])?;
    *tail = &spaced[digits..];
    Some(value)
}

/// The VSTest full line → (verdict, values, project).
fn vstest_parse(line: &str) -> Option<(Verdict, DotnetValues, String)> {
    let (mut tail, verdict) = if let Some(rest) = line.strip_prefix("Passed!") {
        (rest, Verdict::Passed)
    } else if let Some(rest) = line.strip_prefix("Failed!") {
        (rest, Verdict::Failed)
    } else {
        (line.strip_prefix("Skipped!")?, Verdict::Skipped)
    };
    let spaces = tail.bytes().take_while(|b| *b == b' ' || *b == b'\t').count();
    if spaces == 0 {
        return None;
    }
    tail = tail[spaces..].strip_prefix('-')?;
    let spaces = tail.bytes().take_while(|b| *b == b' ' || *b == b'\t').count();
    if spaces == 0 {
        return None;
    }
    tail = &tail[spaces..];
    let failed = take_count(&mut tail, "Failed:")?;
    tail = tail.strip_prefix(',')?.trim_start_matches([' ', '\t']);
    let passed = take_count(&mut tail, "Passed:")?;
    tail = tail.strip_prefix(',')?.trim_start_matches([' ', '\t']);
    let skipped = take_count(&mut tail, "Skipped:")?;
    tail = tail.strip_prefix(',')?.trim_start_matches([' ', '\t']);
    let total = take_count(&mut tail, "Total:")?;
    tail = tail.strip_prefix(',')?.trim_start_matches([' ', '\t']);
    let duration = tail.strip_prefix("Duration:")?;
    // Duration is lazy: the first [ \t]+-[ \t]*
    // split whose project side is non-blank wins.
    let bytes = duration.as_bytes();
    let mut i = 0;
    let mut project = None;
    while i < bytes.len() {
        if bytes[i] == b' ' || bytes[i] == b'\t' {
            let mut j = i;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'-' {
                let candidate = duration[j + 1..]
                    .trim_start_matches([' ', '\t'])
                    .trim_end_matches([' ', '\t']);
                if !candidate.is_empty() {
                    project = Some(candidate.trim().to_string());
                    break;
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    let project = project?;
    Some((
        verdict,
        DotnetValues { total, failed, succeeded: passed, skipped },
        project,
    ))
}

/// Normal/detailed VSTest reports run totals, omitting zero outcome fields.
fn vstest_detailed_parse(lines: &[&str], known_failure: bool) -> Result<DotnetValues, &'static str> {
    let success = match lines[0].trim_matches([' ', '\t']) {
        "Test Run Successful." => true,
        "Test Run Failed." => false,
        _ => return Err("vstest-incomplete-run"),
    };
    let count = |raw: &str| {
        is_count(raw.trim())
            .filter(|&value| value <= i64::MAX as i128)
            .ok_or("dotnet-not-a-count")
    };
    let total = lines
        .get(1)
        .and_then(|line| line.trim_start_matches([' ', '\t']).strip_prefix("Total tests:"))
        .ok_or("dotnet-missing-field")
        .and_then(count)?;
    let (mut passed, mut failed, mut skipped) = (None, None, None);
    for line in &lines[2..] {
        let line = line.trim_start_matches([' ', '\t']);
        let (field, raw) = if let Some(raw) = line.strip_prefix("Passed:") {
            (&mut passed, raw)
        } else if let Some(raw) = line.strip_prefix("Failed:") {
            (&mut failed, raw)
        } else if let Some(raw) = line.strip_prefix("Skipped:") {
            (&mut skipped, raw)
        } else {
            break;
        };
        if field.replace(count(raw)?).is_some() {
            return Err("dotnet-duplicate-field");
        }
    }
    let (succeeded, failed, skipped) = (passed.unwrap_or(0), failed.unwrap_or(0), skipped.unwrap_or(0));
    if failed + succeeded + skipped != total {
        return Err("dotnet-counts-mismatch");
    }
    if success && failed != 0 {
        return Err("vstest-passed-contradiction");
    }
    if !success && failed == 0 && !known_failure {
        return Err("vstest-failed-contradiction");
    }
    Ok(DotnetValues { total, failed, succeeded, skipped })
}

fn resolve_dotnet(
    blocks: &[MtpBlock],
    vstest_lines: &[&str],
    detailed_lines: &[&str],
    detailed_starts: &[usize],
    known_failure: bool,
) -> Result<(Counts, bool), &'static str> {
    let mut details: Vec<(String, DotnetValues)> = Vec::new();
    let mut aggregate: Option<DotnetValues> = None;
    for block in blocks {
        let (verdict, project) = match mtp_status(&block.status) {
            Some(parsed) => parsed,
            None => return Err("dotnet-unknown-verdict"),
        };
        let mut fields: HashMap<&str, &str> = HashMap::new();
        for (name, value) in &block.fields {
            if fields.insert(name.as_str(), value.as_str()).is_some() {
                return Err("dotnet-duplicate-field");
            }
        }
        for name in ["total", "failed", "succeeded", "skipped"] {
            if !fields.contains_key(name) {
                return Err("dotnet-missing-field");
            }
        }
        let read = |fields: &HashMap<&str, &str>, name: &str| -> Result<i128, &'static str> {
            is_count(fields[name]).ok_or("dotnet-not-a-count")
        };
        let values = DotnetValues {
            total: read(&fields, "total")?,
            failed: read(&fields, "failed")?,
            succeeded: read(&fields, "succeeded")?,
            skipped: read(&fields, "skipped")?,
        };
        let error = match fields.get("error") {
            None => 0,
            Some(raw) => is_count(raw).ok_or("dotnet-error-not-a-count")?,
        };
        if values.failed + values.succeeded + values.skipped != values.total {
            return Err("dotnet-counts-mismatch");
        }
        if verdict == Verdict::Zero && (values.failed != 0 || values.succeeded != 0) {
            return Err("dotnet-zero-has-run-tests");
        }
        if error != 0 && values.total > 0 && !known_failure {
            return Err("dotnet-errors-with-tests");
        }
        if verdict == Verdict::Passed && (values.failed != 0 || values.total == 0) {
            return Err("dotnet-passed-contradiction");
        }
        if verdict == Verdict::Failed && values.failed == 0 && !known_failure {
            return Err("dotnet-failed-contradiction");
        }
        match project {
            None => {
                if aggregate.is_some() {
                    return Err("dotnet-duplicate-aggregate");
                }
                aggregate = Some(values);
            }
            Some(name) => details.push((name, values)),
        }
    }
    for line in vstest_lines {
        let (verdict, values, project) = match vstest_parse(line) {
            Some(parsed) => parsed,
            None => return Err("vstest-malformed-line"),
        };
        if values.failed + values.succeeded + values.skipped != values.total {
            return Err("dotnet-counts-mismatch");
        }
        if verdict == Verdict::Skipped && (values.failed != 0 || values.succeeded != 0) {
            return Err("vstest-skipped-has-run-tests");
        }
        if verdict == Verdict::Passed && values.failed != 0 {
            return Err("vstest-passed-contradiction");
        }
        if verdict == Verdict::Failed && values.failed == 0 && !known_failure {
            return Err("dotnet-failed-contradiction");
        }
        details.push((project, values));
    }
    let mut detailed_values: Vec<DotnetValues> = Vec::new();
    for &start in detailed_starts {
        detailed_values.push(vstest_detailed_parse(
            &detailed_lines[start..],
            known_failure,
        )?);
    }
    if detailed_values.len() == 1 {
        if aggregate.replace(detailed_values.pop().unwrap()).is_some() {
            return Err("dotnet-duplicate-aggregate");
        }
    } else if detailed_values.len() > 1 {
        if aggregate.is_some() || details.is_empty() || detailed_values.len() != details.len() {
            return Err("dotnet-duplicate-aggregate");
        }
        let tuple = |v: &DotnetValues| (v.total, v.failed, v.succeeded, v.skipped);
        let mut detailed_sorted: Vec<_> = detailed_values.iter().map(tuple).collect();
        let mut details_sorted: Vec<_> = details.iter().map(|(_, v)| tuple(v)).collect();
        detailed_sorted.sort_unstable();
        details_sorted.sort_unstable();
        if detailed_sorted != details_sorted {
            return Err("dotnet-aggregate-disagrees");
        }
    }
    let mut counts = Counts::default();
    let mut found = false;
    let mut projects: HashMap<&str, &DotnetValues> = HashMap::new();
    for (name, values) in &details {
        if projects.insert(name.as_str(), values).is_some() {
            return Err("dotnet-duplicate-project");
        }
    }
    fn add(values: &DotnetValues, counts: &mut Counts) {
        counts.passed += values.succeeded;
        counts.failed += values.failed;
        counts.skipped += values.skipped;
        counts.total += values.total;
    }
    if !projects.is_empty() {
        if let Some(total) = &aggregate {
            for name in ["total", "failed", "succeeded", "skipped"] {
                let pick = |values: &DotnetValues| match name {
                    "total" => values.total,
                    "failed" => values.failed,
                    "succeeded" => values.succeeded,
                    _ => values.skipped,
                };
                let summed: i128 = details.iter().map(|(_, values)| pick(values)).sum();
                if summed != pick(total) {
                    return Err("dotnet-aggregate-disagrees");
                }
            }
            add(total, &mut counts);
        } else {
            for (_, values) in &details {
                add(values, &mut counts);
            }
        }
        found = true;
    } else if let Some(total) = &aggregate {
        add(total, &mut counts);
        found = true;
    }
    Ok((counts, found))
}

// ---------------------------------------------------------------------------
// The typed result.

/// One structured failure: the test identity, its re-runnable selector,
/// and the concise runner error line when the log carries one. These
/// details are the typed input shared by Check and compact rendering.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FailureDetail {
    pub test: String,
    pub selector: String,
    pub message: String,
}

/// The typed result of parsing a test log (ticket #94): counts or a
/// named error, the failing lines, and the failed-test selectors.
/// Serializes as `{counts, error, failing_lines, failed_tests,
/// failure_details}` — the shape the golden corpus compares.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ParsedLog {
    pub counts: Option<crate::check::Counts>,
    pub error: Option<String>,
    pub failing_lines: Vec<String>,
    pub failed_tests: Vec<String>,
    pub failure_details: Vec<FailureDetail>,
}

impl ParsedLog {
    fn no_summary() -> Self {
        ParsedLog {
            counts: None,
            error: Some("no-summary".to_string()),
            failing_lines: Vec::new(),
            failed_tests: Vec::new(),
            failure_details: Vec::new(),
        }
    }
}

fn detail_test_name(selector: &str) -> String {
    if let Some(name) = selector.strip_prefix("cargo test -- --exact ") {
        return name.to_string();
    }
    if let Some(name) = selector.strip_prefix("dotnet test --filter FullyQualifiedName=") {
        return name.to_string();
    }
    selector.to_string()
}

fn push_detail(
    details: &mut HashMap<String, FailureDetail>,
    test: &str,
    selector: String,
    message: &str,
) {
    let message = message.trim();
    if test.is_empty() || message.is_empty() {
        return;
    }
    if details.len() >= SELECTOR_LIMIT && !details.contains_key(&selector) {
        return;
    }
    let message: String = message.chars().take(160).collect();
    details.entry(selector.clone()).or_insert_with(|| FailureDetail {
        test: test.to_string(),
        selector,
        message,
    });
}

fn line_is_old_panic_format(line: &str) -> bool {
    line.contains(" panicked at '")
}

/// Extract concise per-test failure details from the runner-specific
/// shapes the selectors already recognize. This pass is deliberately
/// independent of count resolution: a malformed summary never discards
/// failure identity, and an unrecognized shape simply yields no detail.
fn extract_failure_details(lines: &[&str]) -> HashMap<String, FailureDetail> {
    let mut details = HashMap::new();

    // pytest's short summary already carries `nodeid - concise error`.
    for line in lines {
        if let Some(nodeid) = pytest_failure(line) {
            let message = line
                .split_once(" - ")
                .map(|(_, message)| message)
                .unwrap_or("failed");
            push_detail(&mut details, nodeid, nodeid.to_string(), message);
        }
    }

    // cargo prints captured failure output in `---- <test> stdout ----`
    // blocks. Scan the whole block in O(1) memory: stdout noise before the
    // panic must not push the panic payload out of a fixed-size window.
    let mut cargo_name: Option<String> = None;
    let mut cargo_fallback: Option<String> = None;
    let mut cargo_message: Option<String> = None;
    let mut cargo_waiting_payload = false;
    fn finish_cargo(
        details: &mut HashMap<String, FailureDetail>,
        cargo_name: &mut Option<String>,
        cargo_fallback: &mut Option<String>,
        cargo_message: &mut Option<String>,
        cargo_waiting_payload: &mut bool,
    ) {
        if let Some(name) = cargo_name.take() {
            let message = cargo_message
                .take()
                .or_else(|| cargo_fallback.take())
                .unwrap_or_default();
            push_detail(
                details,
                &name,
                format!("cargo test -- --exact {name}"),
                &message,
            );
        }
        cargo_fallback.take();
        cargo_message.take();
        *cargo_waiting_payload = false;
    }
    for line in lines {
        if let Some(rest) = line.strip_prefix("---- ") {
            if let Some(name) = rest.strip_suffix(" stdout ----") {
                finish_cargo(
                    &mut details,
                    &mut cargo_name,
                    &mut cargo_fallback,
                    &mut cargo_message,
                    &mut cargo_waiting_payload,
                );
                cargo_name = Some(name.to_string());
                continue;
            }
        }
        if cargo_name.is_some() {
            if line.starts_with("test result:") || *line == "failures:" {
                finish_cargo(
                    &mut details,
                    &mut cargo_name,
                    &mut cargo_fallback,
                    &mut cargo_message,
                    &mut cargo_waiting_payload,
                );
            } else {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let bounded: String = trimmed.chars().take(260).collect();
                if cargo_fallback.is_none() {
                    cargo_fallback = Some(bounded.clone());
                }
                if cargo_waiting_payload {
                    cargo_message = Some(bounded);
                    cargo_waiting_payload = false;
                } else if cargo_message.is_none()
                    && trimmed.starts_with("thread '")
                    && trimmed.contains(" panicked at ")
                {
                    if line_is_old_panic_format(trimmed) {
                        cargo_message = Some(bounded);
                    } else {
                        cargo_waiting_payload = true;
                    }
                }
            }
        }
    }
    finish_cargo(
        &mut details,
        &mut cargo_name,
        &mut cargo_fallback,
        &mut cargo_message,
        &mut cargo_waiting_payload,
    );

    // unittest failure sections end at the next section or the run
    // summary; their concise error is the last column-zero exception line.
    let mut unit_selector: Option<String> = None;
    let mut unit_message: Option<String> = None;
    fn finish_unit(
        details: &mut HashMap<String, FailureDetail>,
        unit_selector: &mut Option<String>,
        unit_message: &mut Option<String>,
    ) {
        if let (Some(selector), Some(message)) = (unit_selector.take(), unit_message.take()) {
            let test = detail_test_name(&selector);
            push_detail(details, &test, selector, &message);
        }
        unit_message.take();
    }
    for line in lines {
        if let Some((name, qualifier)) = unittest_failure(line) {
            finish_unit(&mut details, &mut unit_selector, &mut unit_message);
            unit_selector = Some(unittest_selector(name, qualifier));
            continue;
        }
        if unit_selector.is_some() {
            if unittest_ran(line).is_some() || unittest_end(line).is_some() {
                finish_unit(&mut details, &mut unit_selector, &mut unit_message);
                continue;
            }
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.bytes().all(|b| b == b'-')
                || trimmed.bytes().all(|b| b == b'=')
                || line.starts_with(char::is_whitespace)
                || trimmed.starts_with("Traceback ")
            {
                continue;
            }
            unit_message = Some(trimmed.to_string());
        }
    }
    finish_unit(&mut details, &mut unit_selector, &mut unit_message);

    // VSTest puts the message on the indented line after `Error Message:`;
    // MTP indents the concise message directly below the failed test.
    let mut dotnet_name: Option<String> = None;
    let mut dotnet_ready = false;
    fn finish_dotnet(
        details: &mut HashMap<String, FailureDetail>,
        dotnet_name: &mut Option<String>,
        message: Option<&str>,
    ) {
        if let (Some(name), Some(message)) = (dotnet_name.take(), message) {
            push_detail(
                details,
                &name,
                format!("dotnet test --filter FullyQualifiedName={name}"),
                message,
            );
        }
    }
    for line in lines {
        if let Some(name) = vstest_failure(line).or_else(|| mtp_failure(line)) {
            finish_dotnet(&mut details, &mut dotnet_name, None);
            dotnet_name = Some(name.to_string());
            dotnet_ready = mtp_failure(line).is_some();
            continue;
        }
        if dotnet_name.is_some() {
            let trimmed = line.trim();
            if let Some(inline) = trimmed.strip_prefix("Error Message:") {
                let inline = inline.trim();
                if inline.is_empty() {
                    dotnet_ready = true;
                } else {
                    finish_dotnet(&mut details, &mut dotnet_name, Some(inline));
                    dotnet_ready = false;
                }
            } else if dotnet_ready && !trimmed.is_empty() && line.starts_with(char::is_whitespace) {
                finish_dotnet(&mut details, &mut dotnet_name, Some(trimmed));
                dotnet_ready = false;
            } else if !trimmed.is_empty()
                && !line.starts_with(char::is_whitespace)
                && !trimmed.starts_with("Stack Trace:")
            {
                finish_dotnet(&mut details, &mut dotnet_name, None);
                dotnet_ready = false;
            }
        }
    }
    finish_dotnet(&mut details, &mut dotnet_name, None);

    details
}

fn to_check_counts(counts: &Counts) -> Option<crate::check::Counts> {
    Some(crate::check::Counts {
        passed: i64::try_from(counts.passed).ok()?,
        failed: i64::try_from(counts.failed).ok()?,
        skipped: i64::try_from(counts.skipped).ok()?,
        total: i64::try_from(counts.total).ok()?,
    })
}

// ---------------------------------------------------------------------------
// Framework adapters (ticket #95).
//
// One adapter per framework family behind one interface: an adapter
// receives every (normalized) line and, at the end, gives counts or a
// named error, plus its failed-test selectors. VSTest and MTP share the
// dotnet adapter because they share one resolution step.
//
// Combination is fixed: the first error in registry order wins (unittest
// before dotnet; pytest and cargo never error); otherwise the counts of
// every family that found a summary are summed; when no family found one,
// the result is `no-summary`. The combining step holds no
// framework-specific state.

struct AdapterOutcome {
    result: Result<(Counts, bool), &'static str>,
    selectors: Vec<(usize, String)>,
}

trait LogAdapter {
    fn feed(&mut self, line: &str);
    fn finish(self: Box<Self>, known_failure: bool) -> AdapterOutcome;
}

/// The single place a framework is registered. Registry order is also the
/// error precedence order and the selector precedence order for lines
/// several families could claim. Adding a framework takes one new adapter
/// and one entry here, with no edit to the combining step.
fn adapter_registry() -> Vec<Box<dyn LogAdapter>> {
    vec![
        Box::new(UnittestAdapter::default()),
        Box::new(PytestAdapter::default()),
        Box::new(CargoAdapter::default()),
        Box::new(DotnetAdapter::default()),
    ]
}

#[derive(Default)]
struct UnittestAdapter {
    line_no: usize,
    rans: Vec<(usize, i128)>,
    ends: Vec<(usize, Option<String>)>,
    no_tests_ran: Vec<usize>,
    selectors: Vec<(usize, String)>,
}

impl LogAdapter for UnittestAdapter {
    fn feed(&mut self, line: &str) {
        let index = self.line_no;
        self.line_no += 1;
        if let Some((name, qualifier)) = unittest_failure(line) {
            self.selectors
                .push((index, unittest_selector(name, qualifier)));
        }
        if let Some(total) = unittest_ran(line) {
            self.rans.push((index, total));
        }
        if let Some(parts) = unittest_end(line) {
            self.ends.push((index, parts.map(str::to_string)));
        }
        if is_no_tests_ran(line) {
            self.no_tests_ran.push(index);
        }
    }

    fn finish(self: Box<Self>, _known_failure: bool) -> AdapterOutcome {
        AdapterOutcome {
            result: resolve_unittest(&self.rans, &self.ends, &self.no_tests_ran),
            selectors: self.selectors,
        }
    }
}

#[derive(Default)]
struct PytestAdapter {
    line_no: usize,
    counts: Counts,
    found: bool,
    selectors: Vec<(usize, String)>,
}

impl LogAdapter for PytestAdapter {
    fn feed(&mut self, line: &str) {
        let index = self.line_no;
        self.line_no += 1;
        if line.starts_with("FAILED ") || line.starts_with("ERROR ") {
            if let Some(nodeid) = pytest_failure(line) {
                self.selectors.push((index, nodeid.to_string()));
            }
        }
        if let Some(group) = pytest_group(line) {
            self.counts.add(&pytest_counts(group));
            self.found = true;
        }
    }

    fn finish(self: Box<Self>, _known_failure: bool) -> AdapterOutcome {
        AdapterOutcome {
            result: Ok((self.counts, self.found)),
            selectors: self.selectors,
        }
    }
}

#[derive(Default)]
struct CargoAdapter {
    line_no: usize,
    counts: Counts,
    found: bool,
    selectors: Vec<(usize, String)>,
}

impl LogAdapter for CargoAdapter {
    fn feed(&mut self, line: &str) {
        let index = self.line_no;
        self.line_no += 1;
        if let Some(name) = cargo_failure(line) {
            self.selectors
                .push((index, format!("cargo test -- --exact {name}")));
        }
        if let Some(found) = cargo_counts(line) {
            self.counts.add(&found);
            self.found = true;
        }
    }

    fn finish(self: Box<Self>, _known_failure: bool) -> AdapterOutcome {
        AdapterOutcome {
            result: Ok((self.counts, self.found)),
            selectors: self.selectors,
        }
    }
}

#[derive(Default)]
struct DotnetAdapter {
    line_no: usize,
    blocks: Vec<MtpBlock>,
    collecting: Option<usize>,
    vstest_lines: Vec<String>,
    /// Detailed VSTest groups, stored without per-line cloning: an
    /// open group runs to the end of the log, so a group is fully
    /// described by the index of its header line in `detailed_lines`,
    /// the one shared store every later line is appended to exactly
    /// once. (Previously each open group cloned every later line,
    /// giving O(projects × lines) copies on detailed .NET logs.)
    detailed_lines: Vec<String>,
    detailed_starts: Vec<usize>,
    selectors: Vec<(usize, String)>,
}

impl LogAdapter for DotnetAdapter {
    fn feed(&mut self, line: &str) {
        let index = self.line_no;
        self.line_no += 1;
        if let Some(name) = vstest_failure(line).or_else(|| mtp_failure(line)) {
            self.selectors.push((
                index,
                format!("dotnet test --filter FullyQualifiedName={name}"),
            ));
        }
        // An open detailed group runs to the end of the log: store
        // the line once, here — before the MTP block below can
        // return early — and record a new group's start when this
        // line is a detailed header. Every open group is the suffix
        // of the shared store from its start, so it sees this line
        // (and the header line starts its own group) with no cloning.
        {
            let trimmed = line.trim_matches([' ', '\t']);
            let is_detailed_header = matches!(
                trimmed,
                "Test Run Successful."
                    | "Test Run Failed."
                    | "Test Run Aborted."
                    | "Test Run Canceled."
            ) || trimmed.starts_with("Test Run Aborted with error ");
            if is_detailed_header || !self.detailed_starts.is_empty() {
                if is_detailed_header {
                    self.detailed_starts.push(self.detailed_lines.len());
                }
                self.detailed_lines.push(line.to_string());
            }
        }
        // An open MTP block consumes field, assembly, and blank lines; any
        // other line closes it and is processed on its own merits. (The
        // families' scans are independent, and a consumed line matches no
        // other family's pattern: each is anchored at column 0 or carries
        // the block's own shape.)
        if let Some(open) = self.collecting {
            if let Some((name, value)) = mtp_field(line) {
                self.blocks[open]
                    .fields
                    .push((name.to_string(), value.to_string()));
                if name == "duration" {
                    self.collecting = None;
                }
                return;
            }
            if line.trim().is_empty() || mtp_assembly(line) {
                return;
            }
            self.collecting = None;
        }
        if let Some(status) = mtp_header(line) {
            self.blocks.push(MtpBlock {
                status: status.to_string(),
                fields: Vec::new(),
            });
            self.collecting = Some(self.blocks.len() - 1);
        }
        if vstest_candidate(line) {
            self.vstest_lines.push(line.to_string());
        }
    }

    fn finish(self: Box<Self>, known_failure: bool) -> AdapterOutcome {
        let vstest_lines: Vec<&str> = self.vstest_lines.iter().map(String::as_str).collect();
        let detailed_lines: Vec<&str> = self.detailed_lines.iter().map(String::as_str).collect();
        AdapterOutcome {
            result: resolve_dotnet(
                &self.blocks,
                &vstest_lines,
                &detailed_lines,
                &self.detailed_starts,
                known_failure,
            ),
            selectors: self.selectors,
        }
    }
}

fn parse_impl(text: &str, exit_code: Option<i64>) -> ParsedLog {
    let known_failure = exit_code.is_some_and(|code| code != 0);
    let failing_lines: Vec<String> = split_lines(text)
        .into_iter()
        .filter(|line| is_failing_line(line))
        .take(FAILING_LINE_LIMIT)
        .map(str::to_string)
        .collect();
    let normalized = normalize(text);
    let lines: Vec<&str> = normalized.split('\n').collect();

    let mut adapters = adapter_registry();
    for line in &lines {
        for adapter in &mut adapters {
            adapter.feed(line);
        }
    }
    let outcomes: Vec<AdapterOutcome> = adapters
        .into_iter()
        .map(|adapter| adapter.finish(known_failure))
        .collect();

    // Selectors merge back into log order (stable, so registry order breaks
    // ties on a shared line), deduplicated, capped like the families' own.
    let mut all_selectors: Vec<(usize, String)> = outcomes
        .iter()
        .flat_map(|o| o.selectors.iter().cloned())
        .collect();
    all_selectors.sort_by_key(|(index, _)| *index);
    let mut failed_tests: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (_, selector) in all_selectors {
        if failed_tests.len() < SELECTOR_LIMIT && seen.insert(selector.clone()) {
            failed_tests.push(selector);
        }
    }

    // Fixed combination: first error in registry order wins; otherwise sum
    // the counts of every family that found a summary; none found is
    // `no-summary`.
    let mut total = Counts::default();
    let mut any_found = false;
    let mut error: Option<&'static str> = None;
    for outcome in &outcomes {
        match &outcome.result {
            Err(code) => {
                error = Some(code);
                break;
            }
            Ok((counts, found)) => {
                if *found {
                    total.add(counts);
                    any_found = true;
                }
            }
        }
    }
    let (counts, error) = if let Some(code) = error {
        (None, Some(code))
    } else if any_found {
        (Some(total), None)
    } else {
        (None, Some("no-summary"))
    };
    let extracted_details = extract_failure_details(&lines);
    let failure_details = failed_tests
        .iter()
        .map(|selector| {
            extracted_details
                .get(selector)
                .cloned()
                .unwrap_or_else(|| FailureDetail {
                    test: detail_test_name(selector),
                    selector: selector.clone(),
                    message: String::new(),
                })
        })
        .collect();
    ParsedLog {
        counts: counts.as_ref().and_then(to_check_counts),
        error: error.map(str::to_string),
        failing_lines,
        failed_tests,
        failure_details,
    }
}

/// Parse a test log into its typed result. A parser panic still yields
/// the `no-summary` error instead of reaching the caller.
pub fn parse_log(text: &str, exit_code: Option<i64>) -> ParsedLog {
    match std::panic::catch_unwind(|| parse_impl(text, exit_code)) {
        Ok(parsed) => parsed,
        Err(_) => ParsedLog::no_summary(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_log;
    use crate::check::Counts;

    // The two VSTest detailed unit tests that used to live here
    // (`vstest_detailed_counts`,
    // `vstest_detailed_rejects_ambiguous_or_invalid_summary`) are replaced
    // by the golden-corpus cases vstest-detailed-pass, vstest-terse-pass-63,
    // vstest-detailed-and-terse-pass, vstest-detailed-indented,
    // vstest-detailed-two-projects, vstest-detailed-failed,
    // vstest-detailed-skipped-only, vstest-detailed-no-header,
    // vstest-detailed-missing-total, vstest-detailed-counts-mismatch,
    // vstest-detailed-duplicate-field, vstest-detailed-not-a-count,
    // vstest-detailed-passed-contradiction,
    // vstest-detailed-failed-contradiction, vstest-detailed-aborted,
    // vstest-detailed-duplicate-aggregate, vstest-detailed-aggregate-disagrees
    // and vstest-detailed-aggregate-disagrees-multi in
    // tests/fixtures/log_corpus/ (walked by tests/log_corpus.rs).

    #[test]
    fn typed_result_carries_counts_error_and_selectors() {
        let parsed = parse_log("Ran 2 tests in 0.1s\n\nOK\n", Some(0));
        assert_eq!(
            parsed.counts,
            Some(Counts { passed: 2, failed: 0, skipped: 0, total: 2 })
        );
        assert_eq!(parsed.error, None);
        assert!(parsed.failing_lines.is_empty());
        assert!(parsed.failed_tests.is_empty());

        let parsed = parse_log("nothing recognizable\n", Some(0));
        assert_eq!(parsed.counts, None);
        assert_eq!(parsed.error.as_deref(), Some("no-summary"));
    }
}
