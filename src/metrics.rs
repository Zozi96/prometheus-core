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
    Standalone,
}

impl Host {
    /// Map a `prometheus-kit hook` host name; other hosts have no metrics identity.
    pub fn from_hook(host: &str) -> Option<Self> {
        match host {
            "antigravity" => Some(Self::Antigravity),
            "claude" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "devin" => Some(Self::Devin),
            "droid" => Some(Self::Droid),
            "grok" => Some(Self::Grok),
            "muse" => Some(Self::Muse),
            "omp" => Some(Self::Omp),
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
        ("GROK_SESSION_ID", Host::Grok),
        ("MUSE_SESSION_ID", Host::Muse),
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
}

#[derive(Serialize)]
struct Totals {
    by_host: BTreeMap<Host, Total>,
    by_rule: BTreeMap<Rule, Total>,
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

/// Aggregated totals as `{"by_host": {...}, "by_rule": {...}}`; empty maps when
/// the file is absent or refused. Never creates the file.
pub fn totals() -> String {
    let mut by_host: BTreeMap<Host, Total> = BTreeMap::new();
    let mut by_rule: BTreeMap<Rule, Total> = BTreeMap::new();
    if let Some(file) = open_metrics(false) {
        if file.try_lock_shared().is_ok() {
            let reader = std::io::BufReader::new(file.take(MAX_BYTES));
            for line in reader.split(b'\n') {
                let Ok(bytes) = line else { break };
                let Ok(row) = serde_json::from_slice::<Row>(&bytes) else {
                    continue;
                };
                accumulate(&mut by_host, row.host, &row);
                accumulate(&mut by_rule, row.rule_id, &row);
            }
        }
    }
    serde_json::to_string(&Totals { by_host, by_rule }).unwrap_or_else(|_| "{}".to_string())
}

fn accumulate<K: Ord>(map: &mut BTreeMap<K, Total>, key: K, row: &Row) {
    let total = map.entry(key).or_default();
    total.count = total.count.saturating_add(1);
    total.raw_bytes = total.raw_bytes.saturating_add(row.raw_bytes as u64);
    total.emitted_bytes = total.emitted_bytes.saturating_add(row.emitted_bytes as u64);
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
