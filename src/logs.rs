//! Test-log parsing (spec #43, ticket #50): streaming parsers that turn
//! check output into the normalized receipt, failure selectors included.
//!
//! One deep operation at the engine seam: `parse_check_log` takes the log
//! text (the gate runtime already holds it) and returns the receipt
//! document as JSON — `{schema, counts, error, failing_lines, failed_tests}`.
//! Inside, the parse is line-incremental: each family keeps only the small
//! state its summary needs, so a log's size costs time, not memory. The
//! Python parser in `sureforge_hook` is the parity oracle (ADR-0007 D5):
//! counts, strictness, and error identity mirror `parse_test_log` and
//! `_failing_lines`; the failure selectors are the shapes `_repair_command`
//! turns into a targeted rerun for the next repair round's Write brief
//! (ADR-0003). Malformed input is data, never a crash: every failure is a
//! named `error` code in the document.

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;

const SCHEMA: u32 = 1;
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

/// The Python oracle's preprocessing: ANSI escapes out, line endings to `\n`.
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

/// Python's `str.splitlines` for the boundary set a log can contain
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

/// Python's `int()` for the strings these parsers feed it: surrounding
/// whitespace, an optional sign, then ASCII digits. Anything else is not a
/// count (the oracle raises there; the receipt reports `bad-count` instead).
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

/// A strict count field: ASCII digits only, as the oracle's
/// `value.isascii() and value.isdigit()` requires.
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
// Failing lines: `_failing_lines` on the oracle side (raw text, first 50).

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

fn failed_selectors(lines: &[&str]) -> Vec<String> {
    let mut selectors: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in lines {
        let selector = if let Some((name, qualifier)) = unittest_failure(line) {
            Some(unittest_selector(name, qualifier))
        } else if line.starts_with("FAILED ") || line.starts_with("ERROR ") {
            pytest_failure(line).map(str::to_string)
        } else if let Some(name) = cargo_failure(line) {
            Some(format!("cargo test -- --exact {name}"))
        } else if let Some(name) = vstest_failure(line).or_else(|| mtp_failure(line)) {
            Some(format!("dotnet test --filter FullyQualifiedName={name}"))
        } else {
            None
        };
        if let Some(selector) = selector {
            if selectors.len() < SELECTOR_LIMIT && seen.insert(selector.clone()) {
                selectors.push(selector);
            }
        }
    }
    selectors
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
    // are separated by ", ", or by nothing (the oracle's regex allows the
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
        } else if bytes.get(pos).map_or(false, |b| b.is_ascii_digit()) {
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
/// returning what precedes it. Phrases (ASCII case-insensitive, as the
/// oracle's pattern is): `passed`, `skipped`, `zero tests ran`, `failed`,
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
    } else if let Some(rest) = line.strip_prefix("Skipped!") {
        (rest, Verdict::Skipped)
    } else {
        return None;
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
    // Duration is lazy in the oracle's pattern: the first [ \t]+-[ \t]*
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

fn resolve_dotnet(
    blocks: &[MtpBlock],
    vstest_lines: &[&str],
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
// The receipt document.

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn json_string_list(items: &[String]) -> String {
    let parts: Vec<String> =
        items.iter().map(|item| format!("\"{}\"", json_escape(item))).collect();
    format!("[{}]", parts.join(", "))
}

fn receipt_json(
    counts: Option<&Counts>,
    error: Option<&str>,
    failing_lines: &[String],
    failed_tests: &[String],
) -> String {
    let counts_json = match counts {
        Some(c) => format!(
            "{{\"passed\": {}, \"failed\": {}, \"skipped\": {}, \"total\": {}}}",
            c.passed, c.failed, c.skipped, c.total
        ),
        None => "null".to_string(),
    };
    let error_json = match error {
        Some(code) => format!("\"{}\"", json_escape(code)),
        None => "null".to_string(),
    };
    format!(
        "{{\"schema\": {SCHEMA}, \"counts\": {counts_json}, \"error\": {error_json}, \
         \"failing_lines\": {}, \"failed_tests\": {}}}",
        json_string_list(failing_lines),
        json_string_list(failed_tests)
    )
}

fn parse_impl(text: &str, exit_code: Option<i64>) -> String {
    let known_failure = exit_code.map_or(false, |code| code != 0);
    let failing_lines: Vec<String> = split_lines(text)
        .into_iter()
        .filter(|line| is_failing_line(line))
        .take(FAILING_LINE_LIMIT)
        .map(str::to_string)
        .collect();
    let normalized = normalize(text);
    let lines: Vec<&str> = normalized.split('\n').collect();
    let failed_tests = failed_selectors(&lines);

    let mut rans: Vec<(usize, i128)> = Vec::new();
    let mut ends: Vec<(usize, Option<String>)> = Vec::new();
    let mut no_tests_ran: Vec<usize> = Vec::new();
    let mut pytest = Counts::default();
    let mut pytest_found = false;
    let mut cargo = Counts::default();
    let mut cargo_found = false;
    let mut blocks: Vec<MtpBlock> = Vec::new();
    let mut collecting: Option<usize> = None;
    let mut vstest_lines: Vec<&str> = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        // An open MTP block consumes field, assembly, and blank lines; any
        // other line closes it and is processed on its own merits. (The
        // oracle's scans are independent, and a consumed line matches no
        // other family's pattern: each is anchored at column 0 or carries
        // the block's own shape.)
        if let Some(open) = collecting {
            if let Some((name, value)) = mtp_field(line) {
                blocks[open].fields.push((name.to_string(), value.to_string()));
                if name == "duration" {
                    collecting = None;
                }
                continue;
            }
            if line.trim().is_empty() || mtp_assembly(line) {
                continue;
            }
            collecting = None;
        }
        if let Some(status) = mtp_header(line) {
            blocks.push(MtpBlock { status: status.to_string(), fields: Vec::new() });
            collecting = Some(blocks.len() - 1);
        }
        if let Some(total) = unittest_ran(line) {
            rans.push((index, total));
        }
        if let Some(parts) = unittest_end(line) {
            ends.push((index, parts.map(str::to_string)));
        }
        if is_no_tests_ran(line) {
            no_tests_ran.push(index);
        }
        if let Some(group) = pytest_group(line) {
            pytest.add(&pytest_counts(group));
            pytest_found = true;
        }
        if let Some(found) = cargo_counts(line) {
            cargo.add(&found);
            cargo_found = true;
        }
        if vstest_candidate(line) {
            vstest_lines.push(line);
        }
    }

    let (counts, error) = match resolve_unittest(&rans, &ends, &no_tests_ran) {
        Err(code) => (None, Some(code)),
        Ok((unittest, unittest_found)) => {
            match resolve_dotnet(&blocks, &vstest_lines, known_failure) {
                Err(code) => (None, Some(code)),
                Ok((dotnet, dotnet_found)) => {
                    if unittest_found || pytest_found || cargo_found || dotnet_found {
                        let mut total = unittest;
                        total.add(&pytest);
                        total.add(&cargo);
                        total.add(&dotnet);
                        (Some(total), None)
                    } else {
                        (None, Some("no-summary"))
                    }
                }
            }
        }
    };
    receipt_json(counts.as_ref(), error, &failing_lines, &failed_tests)
}

/// Parse check output into the normalized receipt document (JSON, schema 1).
/// Never raises: a parse failure is the document's `error` code, and any
/// internal failure degrades to the `no-summary` document — the caller
/// still holds the Python route as its fallback.
#[pyfunction]
#[pyo3(signature = (text, exit_code=None))]
fn parse_check_log(text: &str, exit_code: Option<i64>) -> String {
    match std::panic::catch_unwind(|| parse_impl(text, exit_code)) {
        Ok(document) => document,
        Err(_) => receipt_json(None, Some("no-summary"), &[], &[]),
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_check_log, m)?)?;
    Ok(())
}
