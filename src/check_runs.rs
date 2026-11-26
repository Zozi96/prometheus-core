//! Bounded cross-repo record of Check run outcomes.
//!
//! One JSONL file at `<home>/.agents/prometheus/metrics/check-runs.jsonl`
//! holds fixed-vocabulary rows: timestamp, outcome, selection facts, and
//! resource counters only — never repository paths, file names, commands, or
//! log content. Widening reasons are path-scrubbed before they are written.
//! Every write failure is silent; telemetry must never change a Check run.

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 1024 * 1024;
const SCHEMA: u8 = 2;
const STORE_FILE: &str = "check-runs.jsonl";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OutcomeKind {
    ExecutedPass,
    ExecutedFail,
    ReusedGreenReceipt,
    ValidationPending,
}

/// One outcome the runner records. `widen` is still scrubbed here rather
/// than trusted to be path-free at the call site.
#[derive(Debug)]
pub(crate) struct RunMetric {
    pub outcome: OutcomeKind,
    pub selection: String,
    pub widen: Vec<String>,
    pub change_class: String,
    pub wall_ms: u64,
    pub cpu_ms: u64,
    pub peak_memory_kb: u64,
    pub slot_wait_ms: u64,
}

#[derive(Serialize)]
struct Row {
    schema: u8,
    timestamp: u64,
    outcome: OutcomeKind,
    selection: String,
    widen: Vec<String>,
    class: String,
    wall_ms: u64,
    cpu_ms: u64,
    peak_memory_kb: u64,
    slot_wait_ms: u64,
}

/// Metrics writes are on unless compiled as a unit test or
/// `PROMETHEUS_KIT_NO_METRICS` is present (empty value still disables).
pub(crate) fn enabled() -> bool {
    !cfg!(test) && std::env::var_os("PROMETHEUS_KIT_NO_METRICS").is_none()
}

pub(crate) fn record(metric: RunMetric) {
    if enabled() {
        let _ = append(row_from(metric));
    }
}

fn row_from(metric: RunMetric) -> Row {
    Row {
        schema: SCHEMA,
        timestamp: unix_now(),
        outcome: metric.outcome,
        selection: fixed_selection(&metric.selection).to_owned(),
        widen: metric
            .widen
            .iter()
            .map(|reason| sanitize_reason(reason))
            .collect(),
        class: fixed_class(&metric.change_class).to_owned(),
        wall_ms: metric.wall_ms,
        cpu_ms: metric.cpu_ms,
        peak_memory_kb: metric.peak_memory_kb,
        slot_wait_ms: metric.slot_wait_ms,
    }
}

fn fixed_selection(selection: &str) -> &str {
    match selection {
        "targeted" | "module" | "full" => selection,
        _ => "unknown",
    }
}

fn fixed_class(class: &str) -> &str {
    match class {
        "" | "none" | "docs-only" | "tests-only" | "logic" => class,
        _ => "",
    }
}

fn named_reason_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(resolved conflict: |consumers: | in )[^;]+").unwrap())
}

fn path_token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^\s,;:()]*(?:[/\\]|\w\.\w)[^\s,;:()]*").unwrap())
}

/// The legacy metrics rule: named path lists after fixed prefixes are
/// replaced wholesale, then any token shaped like a path or a file name with
/// an extension becomes `<path>`. Bounded at 160 chars.
fn base_ref_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(base )[^ ;]+( could not be resolved)").unwrap())
}

fn merge_base_ref_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(between HEAD and )[^ ;]+").unwrap())
}

fn sanitize_reason(text: &str) -> String {
    let refs = base_ref_regex().replace_all(text, "${1}<ref>${2}");
    let refs = merge_base_ref_regex().replace_all(&refs, "${1}<ref>");
    let named = named_reason_regex().replace_all(&refs, "${1}<path>");
    let scrubbed = path_token_regex().replace_all(&named, "<path>");
    scrubbed.chars().take(160).collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn append(row: Row) -> Option<()> {
    let mut line = serde_json::to_vec(&row).ok()?;
    line.push(b'\n');
    let mut file = open_store(true)?;
    file.try_lock().ok()?;
    let len = file.metadata().ok()?.len();
    if len.saturating_add(line.len() as u64) > MAX_BYTES {
        return None;
    }
    if write_appended(&mut file, &line).is_err() {
        let _ = file.set_len(len);
        return None;
    }
    Some(())
}

#[cfg(not(windows))]
fn write_appended(file: &mut File, line: &[u8]) -> std::io::Result<()> {
    file.write_all(line)
}

// Windows `try_lock` cannot guard an append-only handle, so the writer opens
// read/write and seeks to EOF under the lock instead of relying on O_APPEND.
#[cfg(windows)]
fn write_appended(file: &mut File, line: &[u8]) -> std::io::Result<()> {
    use std::io::Seek;
    file.seek(std::io::SeekFrom::End(0))?;
    file.write_all(line)
}

/// Open the check-run ledger. `PROMETHEUS_METRICS_DIR` names an explicit
/// metrics directory for tests and fixtures; otherwise the ledger shares the
/// fixed private metrics store route with `savings.jsonl`.
fn open_store(write: bool) -> Option<File> {
    if let Some(dir) = std::env::var_os("PROMETHEUS_METRICS_DIR") {
        if dir.is_empty() {
            return None;
        }
        crate::metrics::open_private_file_in_dir(Path::new(&dir), write, STORE_FILE)
    } else {
        crate::metrics::open_metrics_named(write, STORE_FILE)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FactOutcome {
    ExecutedPass,
    ExecutedFail,
    Reused,
    Pending,
}

struct RowFacts {
    timestamp: u64,
    outcome: FactOutcome,
    selection: String,
    widen: Vec<String>,
    wall_ms: u64,
}

#[derive(Default, Serialize)]
struct WallTotal {
    runs: u64,
    wall_ms: u64,
}

#[derive(Default, Serialize)]
struct Summary {
    total_runs: u64,
    executed: u64,
    reused: u64,
    validation_pending: u64,
    by_selection: BTreeMap<String, WallTotal>,
    full_suite_by_reason: BTreeMap<String, WallTotal>,
}

fn value_u64(value: &serde_json::Value) -> Option<u64> {
    value.as_u64()
}

fn value_string_array(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(sanitize_reason))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_schema_two(row: &serde_json::Value) -> Option<RowFacts> {
    Some(RowFacts {
        timestamp: value_u64(row.get("timestamp")?)?,
        outcome: match row.get("outcome")?.as_str()? {
            "executed-pass" => FactOutcome::ExecutedPass,
            "executed-fail" => FactOutcome::ExecutedFail,
            "reused-green-receipt" => FactOutcome::Reused,
            "validation-pending" => FactOutcome::Pending,
            _ => return None,
        },
        selection: row
            .get("selection")?
            .as_str()
            .unwrap_or("unknown")
            .to_owned(),
        widen: row.get("widen").map(value_string_array).unwrap_or_default(),
        wall_ms: row.get("wall_ms").and_then(value_u64).unwrap_or(0),
    })
}

fn parse_legacy(row: &serde_json::Value) -> Option<RowFacts> {
    let day = row.get("day")?.as_str()?;
    let outcome = match row.get("kind")?.as_str()? {
        "check" => {
            if row.get("exit").and_then(|exit| exit.as_i64()) == Some(0) {
                FactOutcome::ExecutedPass
            } else {
                FactOutcome::ExecutedFail
            }
        }
        "reuse" => FactOutcome::Reused,
        _ => return None,
    };
    Some(RowFacts {
        timestamp: parse_date_epoch(day)?,
        outcome,
        selection: row
            .get("selection")?
            .as_str()
            .unwrap_or("unknown")
            .to_owned(),
        widen: row.get("widen").map(value_string_array).unwrap_or_default(),
        wall_ms: row.get("wall_ms").and_then(value_u64).unwrap_or(0),
    })
}

fn parse_facts(line: &[u8]) -> Option<RowFacts> {
    let row: serde_json::Value = serde_json::from_slice(line).ok()?;
    match row.get("schema").and_then(value_u64) {
        Some(1) => parse_legacy(&row),
        Some(2) => parse_schema_two(&row),
        _ => None,
    }
}

fn summarize_read(reader: impl BufRead, since: u64) -> Summary {
    let mut summary = Summary::default();
    for line in reader.split(b'\n') {
        let Ok(bytes) = line else { break };
        if bytes.is_empty() {
            continue;
        }
        let Some(facts) = parse_facts(&bytes) else {
            continue;
        };
        if facts.timestamp < since {
            continue;
        }
        summary.total_runs = summary.total_runs.saturating_add(1);
        match facts.outcome {
            FactOutcome::ExecutedPass | FactOutcome::ExecutedFail => {
                summary.executed = summary.executed.saturating_add(1);
            }
            FactOutcome::Reused => summary.reused = summary.reused.saturating_add(1),
            FactOutcome::Pending => {
                summary.validation_pending = summary.validation_pending.saturating_add(1)
            }
        }
        let selection = if facts.selection.is_empty() {
            "unknown".to_owned()
        } else {
            facts.selection
        };
        let total = summary.by_selection.entry(selection.clone()).or_default();
        total.runs = total.runs.saturating_add(1);
        total.wall_ms = total.wall_ms.saturating_add(facts.wall_ms);

        if selection == "full"
            && matches!(
                facts.outcome,
                FactOutcome::ExecutedPass | FactOutcome::ExecutedFail
            )
        {
            let reached: Vec<&String> = facts
                .widen
                .iter()
                .filter(|reason| reason.contains("full suite"))
                .collect();
            let reason = reached
                .last()
                .copied()
                .or_else(|| facts.widen.last())
                .map(String::as_str)
                .unwrap_or("requested")
                .to_owned();
            let total = summary.full_suite_by_reason.entry(reason).or_default();
            total.runs = total.runs.saturating_add(1);
            total.wall_ms = total.wall_ms.saturating_add(facts.wall_ms);
        }
    }
    summary
}

fn load_summary(since: Option<u64>) -> Summary {
    let cutoff = since.unwrap_or(0);
    let Some(file) = open_store(false) else {
        return Summary::default();
    };
    if file.try_lock_shared().is_err() {
        return Summary::default();
    }
    summarize_read(std::io::BufReader::new(file.take(MAX_BYTES)), cutoff)
}

/// The report as JSON; empty or unreadable stores summarize as zero rows.
pub fn selection_report_json(since: Option<u64>) -> String {
    serde_json::to_string(&load_summary(since)).unwrap_or_else(|_| "{}".to_owned())
}

/// The report as deterministic text; empty sections are explicit.
pub fn selection_report_text(since: Option<u64>) -> String {
    let summary = load_summary(since);
    let mut out = format!(
        "total runs {}\nexecuted {}\nreused green receipts {}\nvalidation pending {}\n\nwall by selection:\n",
        summary.total_runs, summary.executed, summary.reused, summary.validation_pending
    );
    if summary.by_selection.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (selection, total) in &summary.by_selection {
            out.push_str(&format!(
                "  {selection}: runs {} wall_ms {}\n",
                total.runs, total.wall_ms
            ));
        }
    }
    out.push_str("\nfull-suite wall by widening reason:\n");
    if summary.full_suite_by_reason.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (reason, total) in &summary.full_suite_by_reason {
            out.push_str(&format!(
                "  {reason}: runs {} wall_ms {}\n",
                total.runs, total.wall_ms
            ));
        }
    }
    out
}

fn leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn month_days(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from the Unix epoch for a validated civil date (Howard Hinnant's
/// civil-calendar conversion), avoiding a date/time dependency for one CLI.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year as i64;
    era * 146097 + day_of_era - 719468
}

fn parse_date_epoch(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| {
        if range.clone().all(|index| bytes[index].is_ascii_digit()) {
            text[range].parse::<u32>().ok()
        } else {
            None
        }
    };
    let year = digits(0..4)? as i64;
    let month = digits(5..7)?;
    let day = digits(8..10)?;
    if month == 0 || month > 12 || day == 0 || day > month_days(year, month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    u64::try_from(days.checked_mul(86_400)?).ok()
}

/// Parse `--since` as either a UTC date (`YYYY-MM-DD`) or a duration with a
/// `s`, `m`, `h`, `d`, or `w` suffix, relative to `now` in epoch seconds.
pub fn parse_since(text: &str, now: u64) -> Option<u64> {
    if let Some(date) = parse_date_epoch(text) {
        return Some(date);
    }
    let (digits, multiplier) = match text.as_bytes().last() {
        Some(b's') => (&text[..text.len() - 1], 1_u64),
        Some(b'm') => (&text[..text.len() - 1], 60),
        Some(b'h') => (&text[..text.len() - 1], 3_600),
        Some(b'd') => (&text[..text.len() - 1], 86_400),
        Some(b'w') => (&text[..text.len() - 1], 604_800),
        _ => return None,
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let amount = digits.parse::<u64>().ok()?.checked_mul(multiplier)?;
    Some(now.saturating_sub(amount))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!(
                "prometheus-check-runs-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn widening_reasons_are_path_scrubbed() {
        assert_eq!(
            "coverage uncertain: dynamic import in <path>; widened to the full suite",
            sanitize_reason(
                "coverage uncertain: dynamic import in src/app/main.py; widened to the full suite"
            )
        );
        assert_eq!(
            "resolved conflict: <path>; consumers: <path>",
            sanitize_reason("resolved conflict: a.py, Makefile; consumers: tests/t.py")
        );
        assert_eq!(
            "deleted test <path>, <path>; widened to the full suite",
            sanitize_reason(
                "deleted test tests/a_test.py, tests/b_test.py; widened to the full suite"
            )
        );
        assert_eq!(
            "integration delta unavailable: base <ref> could not be resolved; widened to the full suite",
            sanitize_reason("integration delta unavailable: base acme-customer-fix could not be resolved; widened to the full suite")
        );
        assert_eq!(
            "integration delta unavailable: no merge base between HEAD and <ref>; widened to the full suite",
            sanitize_reason("integration delta unavailable: no merge base between HEAD and main; widened to the full suite")
        );
    }

    #[test]
    fn row_shape_is_fixed_and_path_free() {
        let row = row_from(RunMetric {
            outcome: OutcomeKind::ExecutedPass,
            selection: "targeted".to_owned(),
            widen: vec!["deleted test tests/a_test.py; widened to the full suite".to_owned()],
            change_class: "logic".to_owned(),
            wall_ms: 10,
            cpu_ms: 8,
            peak_memory_kb: 2048,
            slot_wait_ms: 3,
        });
        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&row).unwrap()).unwrap();
        assert_eq!(
            [
                "schema",
                "timestamp",
                "outcome",
                "selection",
                "widen",
                "class",
                "wall_ms",
                "cpu_ms",
                "peak_memory_kb",
                "slot_wait_ms",
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect()
        );
        let text = value.to_string();
        assert!(!text.contains("tests/a_test.py"), "{text}");
        assert!(text.contains("<path>"), "{text}");
        assert_eq!("executed-pass", value["outcome"]);
        assert_eq!(8, value["cpu_ms"]);
    }

    fn schema_two_row(
        timestamp: u64,
        outcome: &str,
        selection: &str,
        wall: u64,
        widen: &[&str],
    ) -> String {
        let widen = widen
            .iter()
            .map(|reason| format!("\"{reason}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema\":2,\"timestamp\":{timestamp},\"outcome\":\"{outcome}\",\"selection\":\"{selection}\",\"widen\":[{widen}],\"class\":\"logic\",\"wall_ms\":{wall},\"cpu_ms\":1,\"peak_memory_kb\":2,\"slot_wait_ms\":3}}\n"
        )
    }

    #[test]
    fn report_aggregates_new_and_legacy_rows_and_ignores_malformed_rows() {
        let reached = "module boundary uncertain; widened to the full suite";
        let mut text = String::new();
        text.push_str(&schema_two_row(
            1_000,
            "executed-pass",
            "full",
            900,
            &["affected selection empty; widened to the module", reached],
        ));
        text.push_str(&schema_two_row(1_100, "executed-fail", "targeted", 10, &[]));
        text.push_str(&schema_two_row(
            1_200,
            "reused-green-receipt",
            "targeted",
            0,
            &[],
        ));
        text.push_str(&schema_two_row(
            1_300,
            "validation-pending",
            "full",
            20,
            &[],
        ));
        text.push_str("{\"schema\":1,\"day\":\"1970-01-02\",\"kind\":\"check\",\"selection\":\"full\",\"widen\":[],\"wall_ms\":100,\"exit\":0}\n");
        text.push_str("{\"schema\":99,\"kind\":\"check\",\"selection\":\"full\",\"wall_ms\":5}\n");
        text.push_str("not json\n");
        let summary = summarize_read(std::io::Cursor::new(text), 0);
        assert_eq!(
            (5, 3, 1, 1),
            (
                summary.total_runs,
                summary.executed,
                summary.reused,
                summary.validation_pending
            )
        );
        assert_eq!(2, summary.by_selection["targeted"].runs);
        assert_eq!(1020, summary.by_selection["full"].wall_ms);
        assert_eq!(900, summary.full_suite_by_reason[reached].wall_ms);
        assert_eq!(100, summary.full_suite_by_reason["requested"].wall_ms);
    }

    #[test]
    fn since_parses_dates_durations_and_boundaries() {
        let now = parse_date_epoch("2026-01-08").unwrap();
        assert_eq!(
            Some(parse_date_epoch("2026-01-02").unwrap()),
            parse_since("2026-01-02", now)
        );
        assert_eq!(Some(now - 6 * 86_400), parse_since("6d", now));
        assert_eq!(Some(now - 2 * 3_600), parse_since("2h", now));
        assert_eq!(None, parse_since("soon", now));
        assert_eq!(None, parse_since("2026-02-29", now));
        let boundary = schema_two_row(now, "executed-pass", "targeted", 1, &[]);
        let summary = summarize_read(std::io::Cursor::new(boundary), now);
        assert_eq!(1, summary.total_runs);
    }

    #[cfg(unix)]
    #[test]
    fn override_store_refuses_symlinks_foreign_modes_and_loose_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = TempDir::new("private");
        let dir = temp.0.join("store");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(crate::metrics::open_private_file_in_dir(&dir, true, STORE_FILE).is_some());

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(crate::metrics::open_private_file_in_dir(&dir, true, STORE_FILE).is_none());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let file = dir.join(STORE_FILE);
        std::fs::write(&file, "{}\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(crate::metrics::open_private_file_in_dir(&dir, true, STORE_FILE).is_none());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(crate::metrics::open_private_file_in_dir(&dir, true, STORE_FILE).is_some());
        assert_eq!(0, std::fs::metadata(&file).unwrap().mode() & 0o077);

        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/tmp/elsewhere", &file).unwrap();
        assert!(crate::metrics::open_private_file_in_dir(&dir, true, STORE_FILE).is_none());
        std::fs::remove_file(&file).unwrap();

        let real = temp.0.join("real");
        let link = temp.0.join("link");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(crate::metrics::open_private_file_in_dir(&link, true, STORE_FILE).is_none());
    }
}
