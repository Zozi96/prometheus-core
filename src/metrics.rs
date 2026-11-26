//! Bounded local record of hook-rule outcomes.
//!
//! One JSONL file at `<home>/.agents/prometheus/metrics/savings.jsonl` holds
//! fixed-vocabulary rows: epoch seconds, host, rule id, and byte counts only —
//! never session ids, paths, commands, or content. Every failure is silent;
//! metrics must never change a hook reply.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::ffi::CStr;

const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Host {
    Antigravity,
    Claude,
    Cursor,
    Devin,
    Droid,
    Grok,
    Muse,
    Omp,
    Opencode,
    Standalone,
}

impl Host {
    pub fn name(self) -> &'static str {
        match self {
            Self::Antigravity => "antigravity",
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Devin => "devin",
            Self::Droid => "droid",
            Self::Grok => "grok",
            Self::Muse => "muse",
            Self::Omp => "omp",
            Self::Opencode => "opencode",
            Self::Standalone => "standalone",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "antigravity" => Some(Self::Antigravity),
            "claude" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "devin" => Some(Self::Devin),
            "droid" => Some(Self::Droid),
            "grok" => Some(Self::Grok),
            "muse" => Some(Self::Muse),
            "omp" => Some(Self::Omp),
            "opencode" => Some(Self::Opencode),
            "standalone" => Some(Self::Standalone),
            _ => None,
        }
    }
}

/// Host for CLI (non-hook) metric rows, detected only from fixed, known
/// nonempty environment markers. Marker values are never read beyond
/// emptiness and never serialized; zero or multiple distinct markers are
/// ambiguous and yield `Standalone`.
pub fn command_host() -> Host {
    let mut found: Option<Host> = None;
    for (var, host) in [
        ("ANTIGRAVITY_CONVERSATION_ID", Host::Antigravity),
        ("CURSOR_PROJECT_DIR", Host::Cursor),
        ("DEVIN_PROJECT_DIR", Host::Devin),
        ("CLAUDECODE", Host::Claude),
        ("FACTORY_DROID_SESSION_ID", Host::Droid),
        ("FACTORY_SESSION_ID", Host::Droid),
        ("GROK_SESSION_ID", Host::Grok),
        ("MUSE_SESSION_ID", Host::Muse),
        ("PI_SESSION_ID", Host::Omp),
        ("OPENCODE_SESSION_ID", Host::Opencode),
    ] {
        if std::env::var_os(var).is_some_and(|v| !v.is_empty()) {
            match found {
                None => found = Some(host),
                Some(prev) if prev == host => {}
                Some(_) => return Host::Standalone,
            }
        }
    }
    found.unwrap_or(Host::Standalone)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Rule {
    ShellRewrite,
    ShellDenial,
    InlineDumpDenial,
    LargeReadAdvisory,
    FirstReadDenial,
    RereadWarning,
    RereadDenial,
    AllowedRetry,
    UseTimeHint,
    Outline,
    Slice,
    Search,
    Diff,
    Map,
    Compact,
}

impl Rule {
    pub fn name(self) -> &'static str {
        match self {
            Self::ShellRewrite => "shell-rewrite",
            Self::ShellDenial => "shell-denial",
            Self::InlineDumpDenial => "inline-dump-denial",
            Self::LargeReadAdvisory => "large-read-advisory",
            Self::FirstReadDenial => "first-read-denial",
            Self::RereadWarning => "reread-warning",
            Self::RereadDenial => "reread-denial",
            Self::AllowedRetry => "allowed-retry",
            Self::UseTimeHint => "use-time-hint",
            Self::Outline => "outline",
            Self::Slice => "slice",
            Self::Search => "search",
            Self::Diff => "diff",
            Self::Map => "map",
            Self::Compact => "compact",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "shell-rewrite" => Some(Self::ShellRewrite),
            "shell-denial" => Some(Self::ShellDenial),
            "inline-dump-denial" => Some(Self::InlineDumpDenial),
            "large-read-advisory" => Some(Self::LargeReadAdvisory),
            "first-read-denial" => Some(Self::FirstReadDenial),
            "reread-warning" => Some(Self::RereadWarning),
            "reread-denial" => Some(Self::RereadDenial),
            "allowed-retry" => Some(Self::AllowedRetry),
            "use-time-hint" => Some(Self::UseTimeHint),
            "outline" => Some(Self::Outline),
            "slice" => Some(Self::Slice),
            "search" => Some(Self::Search),
            "diff" => Some(Self::Diff),
            "map" => Some(Self::Map),
            "compact" => Some(Self::Compact),
            _ => None,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    timestamp: u64,
    host: Host,
    rule_id: Rule,
    raw_bytes: usize,
    emitted_bytes: usize,
}

#[derive(Default, Serialize)]
struct Total {
    count: u64,
    raw_bytes: u64,
    emitted_bytes: u64,
    net_bytes: i64,
}

#[derive(Serialize)]
struct Totals {
    by_host: BTreeMap<Host, Total>,
    by_rule: BTreeMap<Rule, Total>,
    by_host_rule: BTreeMap<Host, BTreeMap<Rule, Total>>,
}

/// One hook-rule outcome, carried as data from the hook decision to the
/// single recording site at the entry point (ADR-0017, #103).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricRecord {
    pub rule: Rule,
    pub raw_bytes: usize,
    pub emitted_bytes: usize,
}

/// Record one metric carried as data from a hook decision.
pub fn record_metric(host: Host, metric: MetricRecord) {
    record(host, metric.rule, metric.raw_bytes, metric.emitted_bytes);
}

/// Metrics writes are on unless compiled as a unit test or
/// `PROMETHEUS_KIT_NO_METRICS` is present (empty value still disables).
pub fn enabled() -> bool {
    !cfg!(test) && std::env::var_os("PROMETHEUS_KIT_NO_METRICS").is_none()
}

/// Append one row; all failures are silent by contract.
pub fn record(host: Host, rule_id: Rule, raw_bytes: usize, emitted_bytes: usize) {
    if enabled() {
        let _ = append(Row {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            host,
            rule_id,
            raw_bytes,
            emitted_bytes,
        });
    }
}

fn append(row: Row) -> Option<()> {
    let mut line = serde_json::to_vec(&row).ok()?;
    line.push(b'\n');
    let mut file = open_metrics(true)?;
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

/// Aggregated totals as compact JSON; empty maps when the file is absent or
/// refused. Never creates the file. `since` is an inclusive epoch-second lower
/// bound.
pub fn totals_json(since: Option<u64>) -> String {
    serde_json::to_string(&aggregate(since)).unwrap_or_else(|_| "{}".to_string())
}

/// Backward-compatible library accessor for unwindowed JSON totals.
pub fn totals() -> String {
    totals_json(None)
}

/// Human-readable deterministic totals. Keys sort through `BTreeMap` and no
/// wall-clock or fixture-identifying data is rendered.
pub fn totals_text(since: Option<u64>) -> String {
    let totals = aggregate(since);
    let mut out = String::from("prometheus-kit metrics\nby_host:\n");
    render_totals(
        &mut out,
        totals
            .by_host
            .iter()
            .map(|(host, total)| (host.name(), total)),
    );
    out.push_str("by_rule:\n");
    render_totals(
        &mut out,
        totals
            .by_rule
            .iter()
            .map(|(rule, total)| (rule.name(), total)),
    );
    out.push_str("by_host_rule:\n");
    let mut any = false;
    for (host, rules) in &totals.by_host_rule {
        for (rule, total) in rules {
            any = true;
            render_total(&mut out, &format!("{}/{}", host.name(), rule.name()), total);
        }
    }
    if !any {
        out.push_str("  (none)\n");
    }
    out
}

fn render_totals<'a>(out: &mut String, rows: impl Iterator<Item = (&'a str, &'a Total)>) {
    let mut any = false;
    for (name, total) in rows {
        any = true;
        render_total(out, name, total);
    }
    if !any {
        out.push_str("  (none)\n");
    }
}

fn render_total(out: &mut String, name: &str, total: &Total) {
    out.push_str(&format!(
        "  {name} count={} raw_bytes={} emitted_bytes={} net_bytes={}\n",
        total.count, total.raw_bytes, total.emitted_bytes, total.net_bytes
    ));
}

fn aggregate(since: Option<u64>) -> Totals {
    let mut by_host: BTreeMap<Host, Total> = BTreeMap::new();
    let mut by_rule: BTreeMap<Rule, Total> = BTreeMap::new();
    let mut by_host_rule: BTreeMap<Host, BTreeMap<Rule, Total>> = BTreeMap::new();
    if let Some(file) = open_metrics(false) {
        if file.try_lock_shared().is_ok() {
            let reader = std::io::BufReader::new(file.take(MAX_BYTES));
            for line in reader.split(b'\n') {
                let Ok(bytes) = line else { break };
                let Ok(row) = serde_json::from_slice::<Row>(&bytes) else {
                    continue;
                };
                if since.is_some_and(|since| row.timestamp < since) {
                    continue;
                }
                accumulate(&mut by_host, row.host, &row);
                accumulate(&mut by_rule, row.rule_id, &row);
                accumulate(by_host_rule.entry(row.host).or_default(), row.rule_id, &row);
            }
        }
    }
    Totals {
        by_host,
        by_rule,
        by_host_rule,
    }
}

fn accumulate<K: Ord>(map: &mut BTreeMap<K, Total>, key: K, row: &Row) {
    let total = map.entry(key).or_default();
    total.count = total.count.saturating_add(1);
    total.raw_bytes = total.raw_bytes.saturating_add(row.raw_bytes as u64);
    total.emitted_bytes = total.emitted_bytes.saturating_add(row.emitted_bytes as u64);
    let raw = i64::try_from(row.raw_bytes).unwrap_or(i64::MAX);
    let emitted = i64::try_from(row.emitted_bytes).unwrap_or(i64::MAX);
    total.net_bytes = total.net_bytes.saturating_add(raw.saturating_sub(emitted));
}

/// Parse a `--since` window: `<n>s|m|h|d|w` relative to `now`, or a UTC
/// `YYYY-MM-DD` date at midnight. The returned boundary is inclusive.
pub fn parse_since(value: &str, now: u64) -> Option<u64> {
    if let Some(days) = parse_utc_date(value) {
        return Some(days.saturating_mul(86_400));
    }
    let (digits, multiplier) = [
        ("s", 1u64),
        ("m", 60),
        ("h", 3_600),
        ("d", 86_400),
        ("w", 604_800),
    ]
    .iter()
    .find_map(|(suffix, multiplier)| {
        value
            .strip_suffix(suffix)
            .map(|digits| (digits, *multiplier))
    })?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let amount: u64 = digits.parse().ok()?;
    Some(now.saturating_sub(amount.saturating_mul(multiplier)))
}

fn parse_utc_date(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: i64 = value[0..4].parse().ok()?;
    let month: u32 = value[5..7].parse().ok()?;
    let day: u32 = value[8..10].parse().ok()?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    u64::try_from(days).ok()
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a validated proleptic Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Open `savings.jsonl` under `<home>/.agents/prometheus/metrics`, walking each
/// component by fd so no path component can be swapped mid-walk. `write` may
/// create missing directories (0o700) and the file (0o600); read-only never
/// creates. Unsafe owners, symlinks, or loose permissions refuse the whole
/// route rather than repairing it.
#[cfg(unix)]
fn open_metrics(write: bool) -> Option<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let home = crate::droid_mode::default_home().ok()?;
    if !home.is_absolute() {
        return None;
    }
    let home_dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(home)
        .ok()?;
    if home_dir.metadata().ok()?.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    let agents = child_dir(&home_dir, c".agents", write, false)?;
    let prometheus = child_dir(&agents, c"prometheus", write, false)?;
    let metrics = child_dir(&prometheus, c"metrics", write, true)?;
    open_metrics_file(&metrics, write)
}

/// Open or (write mode only) create `name` under `parent`, refusing
/// non-directories, foreign owners, symlinks, and — when `private` — any
/// group/other permission bits. A concurrent creator is accepted only after
/// the reopened directory passes the same checks.
#[cfg(unix)]
fn child_dir(parent: &File, name: &CStr, write: bool, private: bool) -> Option<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 && write && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    }
    if fd < 0 {
        return None;
    }
    let dir = unsafe { File::from_raw_fd(fd) };
    let meta = dir.metadata().ok()?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    if private && meta.mode() & 0o077 != 0 {
        return None;
    }
    Some(dir)
}

/// Open `savings.jsonl` under the pinned metrics dir; the file must be a
/// regular, single-link file owned by the effective uid with no group/other
/// bits. The writer opens `O_WRONLY|O_APPEND|O_CREAT` (mode 0o600); the
/// reader opens `O_RDONLY` and never creates.
#[cfg(unix)]
fn open_metrics_file(dir: &File, write: bool) -> Option<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    let access = if write {
        libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT
    } else {
        libc::O_RDONLY
    };
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | access;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c"savings.jsonl".as_ptr(), flags, 0o600) };
    if fd < 0 {
        return None;
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().ok()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
    {
        return None;
    }
    Some(file)
}

#[cfg(windows)]
pub(crate) mod windows;

#[cfg(windows)]
fn open_metrics(write: bool) -> Option<File> {
    windows::open_metrics(write)
}

#[cfg(not(any(unix, windows)))]
fn open_metrics(_write: bool) -> Option<File> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A metrics log written by the current release still reads (#106):
    /// every rule id in the current format — including the retired ones
    /// (ADR-0016) — parses, so older logs keep aggregating.

    #[test]
    fn parse_since_accepts_durations_and_utc_dates() {
        let now = 1_700_000_000;
        assert_eq!(parse_since("30s", now), Some(now - 30));
        assert_eq!(parse_since("15m", now), Some(now - 900));
        assert_eq!(parse_since("2h", now), Some(now - 7_200));
        assert_eq!(parse_since("7d", now), Some(now - 604_800));
        assert_eq!(parse_since("1w", now), Some(now - 604_800));
        assert_eq!(parse_since("2023-10-02", now), Some(1_696_204_800));
        assert_eq!(parse_since("1970-01-01", now), Some(0));
        for invalid in [
            "",
            "1",
            "x",
            "1y",
            "-1d",
            "2023-02-29",
            "2024-02-30",
            "1969-12-31",
            "2023-10-02T00:00:00Z",
            "1µ",
        ] {
            assert_eq!(parse_since(invalid, now), None, "{invalid}");
        }
    }

    #[test]
    fn fixed_host_and_rule_names_round_trip() {
        for host in [
            Host::Antigravity,
            Host::Claude,
            Host::Cursor,
            Host::Devin,
            Host::Droid,
            Host::Grok,
            Host::Muse,
            Host::Omp,
            Host::Opencode,
            Host::Standalone,
        ] {
            assert_eq!(Host::parse(host.name()), Some(host));
        }
        for rule in [
            Rule::ShellRewrite,
            Rule::ShellDenial,
            Rule::InlineDumpDenial,
            Rule::LargeReadAdvisory,
            Rule::FirstReadDenial,
            Rule::RereadWarning,
            Rule::RereadDenial,
            Rule::AllowedRetry,
            Rule::UseTimeHint,
            Rule::Outline,
            Rule::Slice,
            Rule::Search,
            Rule::Diff,
            Rule::Map,
            Rule::Compact,
        ] {
            assert_eq!(Rule::parse(rule.name()), Some(rule));
        }
    }

    #[test]
    fn current_release_metrics_log_format_still_parses_including_retired_rules() {
        for rule in [
            "shell-rewrite",
            "shell-denial",
            "inline-dump-denial",
            "large-read-advisory",
            "first-read-denial",
            "reread-warning",
            "reread-denial",
            "allowed-retry",
            "use-time-hint",
            "outline",
            "slice",
            "search",
            "diff",
            "map",
            "compact",
        ] {
            let line = format!(
                r#"{{"timestamp":1760000000,"host":"claude","rule_id":"{rule}","raw_bytes":10,"emitted_bytes":4}}"#
            );
            let row: Row = serde_json::from_slice(line.as_bytes())
                .unwrap_or_else(|e| panic!("rule {rule} no longer parses: {e}"));
            assert_eq!(10, row.raw_bytes);
            assert_eq!(4, row.emitted_bytes);
        }
    }
}
