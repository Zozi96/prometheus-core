//! The receipt store (spec #43, ticket #57): one store behind the engine for
//! Green receipt lookup, the host-wide Check slot, and receipt/closure
//! aggregation, shared by the hook, writer leaves, and the parent.
//!
//! The store's on-disk format is the session layout the Python runtime
//! already writes — `receipts.jsonl` and `usage.jsonl` rows per session
//! directory, plus `check-slot.lock` / `check-slot.json` beside them — at
//! `STORE_SCHEMA` 1. The Python side negotiates the schema before delegating
//! (exactly as it negotiates `ENGINE_API`); a mismatch, a missing function,
//! or any engine failure reruns the whole call on the Python route, which
//! stays the behavioural oracle. The store caches and serves facts (receipt
//! rows, usage rows, the slot holder) — never verdicts (ADR-0005): a Green
//! receipt is served only on exact Tree fingerprint and logical-command
//! equality (ADR-0001, ADR-0004), and the Python side still applies its
//! provenance checks (script binding, runner origin) to the candidates this
//! module returns.
//!
//! Rows are parsed with Python's own `json` module, in process, so a line
//! the Python route would skip (unparseable, not an object) is skipped here
//! too, and returned rows are the very objects that parser produced.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt, PyList};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The store format this build reads. The gate runtime delegates only when
/// this equals the schema it was written against; any other value keeps the
/// runtime on its own route.
pub const STORE_SCHEMA: u32 = 1;

const SLOT_POLL: Duration = Duration::from_millis(20);
const PROMPT_EVENTS: [&str; 2] = ["userpromptsubmit", "beforesubmitprompt"];

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

// ---------------------------------------------------------------------------
// Row reading. The Python oracle (`_receipts`, closure `_rows`) reads the
// whole file as UTF-8 text: a read failure is an empty row set, and — for
// receipts — so is undecodable text, because `_read` swallows UnicodeError.
// Usage rows differ: `closure_report._rows` catches only OSError, so a
// decode failure must surface here as an error and let the Python route
// reproduce its own behaviour.

enum TextRead {
    Text(String),
    Absent,
    Undecodable,
}

fn read_text(path: &Path) -> TextRead {
    match std::fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => TextRead::Text(text),
            Err(_) => TextRead::Undecodable,
        },
        Err(_) => TextRead::Absent,
    }
}

fn parse_jsonl(py: Python<'_>, text: &str) -> PyResult<Vec<Py<PyDict>>> {
    let loads = py.import("json")?.getattr("loads")?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Ok(value) = loads.call1((line,)) {
            if let Ok(dict) = value.cast::<PyDict>() {
                rows.push(dict.clone().unbind());
            }
        }
    }
    Ok(rows)
}

fn receipt_rows(py: Python<'_>, path: &Path) -> PyResult<Vec<Py<PyDict>>> {
    match read_text(path) {
        TextRead::Text(text) => parse_jsonl(py, &text),
        _ => Ok(Vec::new()),
    }
}

fn usage_rows(py: Python<'_>, session_dir: &Path) -> PyResult<Vec<Py<PyDict>>> {
    match read_text(&session_dir.join("usage.jsonl")) {
        TextRead::Text(text) => parse_jsonl(py, &text),
        TextRead::Absent => Ok(Vec::new()),
        TextRead::Undecodable => Err(err("usage.jsonl is not valid UTF-8")),
    }
}

// ---------------------------------------------------------------------------
// Value helpers with Python semantics (identity for `is True`, truthiness
// for `or`, the `int()` builtin for conversion).

fn get<'py>(row: &Bound<'py, PyDict>, key: &str) -> Option<Bound<'py, PyAny>> {
    row.get_item(key).ok().flatten()
}

fn as_str(value: &Bound<'_, PyAny>) -> Option<String> {
    value.extract::<String>().ok()
}

fn str_field_is(row: &Bound<'_, PyDict>, key: &str, want: &str) -> bool {
    get(row, key).and_then(|value| as_str(&value)).as_deref() == Some(want)
}

fn is_true(value: &Bound<'_, PyAny>) -> bool {
    // `value is True`: identity, so 1 and "yes" do not count.
    value.is_instance_of::<PyBool>() && value.extract::<bool>().unwrap_or(false)
}

fn is_exact_int(value: &Bound<'_, PyAny>) -> bool {
    // `type(value) is int`: bool is a subclass and does not count.
    value.is_exact_instance_of::<PyInt>()
}

fn truthy(value: &Bound<'_, PyAny>) -> bool {
    value.is_truthy().unwrap_or(false)
}

/// `int(value or 0)`, through the builtin so float truncation and string
/// errors behave exactly as the Python route's.
fn int_or_zero(py: Python<'_>, value: Option<Bound<'_, PyAny>>) -> PyResult<i64> {
    match value {
        Some(value) if truthy(&value) => Ok(py
            .get_type::<PyInt>()
            .call1((value,))?
            .extract::<i64>()?),
        _ => Ok(0),
    }
}

// ---------------------------------------------------------------------------
// SHA-256 (std has none; the engine's only crypto dependency, gix, is
// SHA-1). Verified against hashlib by the parity suite and against the
// FIPS 180-4 vectors in this module's tests.

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(bytes: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut block = bytes.to_vec();
    block.push(0x80);
    while block.len() % 64 != 56 {
        block.push(0);
    }
    block.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in block.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

fn file_sha256_hex(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
}

// ---------------------------------------------------------------------------
// Green receipt lookup. Returns every receipt row (in file order) that the
// content half of the Python scan accepts: exact command, exact fingerprint,
// exact selection, parsed counts with total > 0 and no failures, exit 0, and
// a recorded log that still hashes to the recorded digest at its recorded
// path. The Python side applies its provenance checks (script binding,
// runner origin) to these candidates and takes the latest that passes —
// exactly the rows, in exactly the order, its own scan would visit.

#[pyfunction]
fn store_green_candidates(
    py: Python<'_>,
    receipts_path: String,
    command: Bound<'_, PyList>,
    fingerprint: String,
    selection: String,
    min_index: Option<usize>,
) -> PyResult<Py<PyList>> {
    let rows = receipt_rows(py, Path::new(&receipts_path))?;
    let out = PyList::empty(py);
    for (index, row) in rows.iter().enumerate() {
        if min_index.is_some_and(|min| index < min) {
            continue;
        }
        let row = row.bind(py);
        if !str_field_is(&row, "fingerprint", &fingerprint) {
            continue;
        }
        match get(&row, "command") {
            Some(found) if found.eq(&command)? => {}
            _ => continue,
        }
        let selection_ok = match row.get_item("selection")? {
            Some(found) => found.eq(selection.as_str())?,
            None => selection == "full",
        };
        if !selection_ok {
            continue;
        }
        if get(&row, "unparsed").is_some_and(|value| is_true(&value)) {
            continue;
        }
        let counts = match get(&row, "counts") {
            Some(value) => match value.cast::<PyDict>() {
                Ok(dict) => dict.clone(),
                Err(_) => continue,
            },
            None => continue,
        };
        if !get(&counts, "total").is_some_and(|value| truthy(&value)) {
            continue;
        }
        if get(&counts, "failed").is_some_and(|value| truthy(&value)) {
            continue;
        }
        match get(&row, "exit") {
            Some(value) if is_exact_int(&value) && value.extract::<i64>()? == 0 => {}
            _ => continue,
        }
        let log = match get(&row, "log").and_then(|value| as_str(&value)) {
            Some(log) => log,
            None => continue,
        };
        let digest = match get(&row, "log_sha256").and_then(|value| as_str(&value)) {
            Some(digest) if !digest.is_empty() => digest,
            _ => continue,
        };
        if file_sha256_hex(Path::new(&log)).as_deref() != Some(digest.as_str()) {
            continue;
        }
        out.append(row)?;
    }
    Ok(out.unbind())
}

// ---------------------------------------------------------------------------
// Log lookup for matching_receipt: every row (in file order) whose
// fingerprint equals the tree, whose recorded digest equals the target
// log's current digest, and whose recorded log path resolves to the target.
// Returns None when the target log cannot be read at all — the Python route
// reports no match then, definitively. The caller still applies the
// recognized-command / exit-only filter and takes the latest.

#[pyfunction]
fn store_log_candidates(
    py: Python<'_>,
    receipts_path: String,
    log_path: String,
    fingerprint: String,
) -> PyResult<Option<Py<PyList>>> {
    let target = match std::fs::canonicalize(&log_path) {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    let digest = match file_sha256_hex(&target) {
        Some(digest) => digest,
        None => return Ok(None),
    };
    let rows = receipt_rows(py, Path::new(&receipts_path))?;
    let out = PyList::empty(py);
    for row in &rows {
        let row = row.bind(py);
        if !str_field_is(&row, "fingerprint", &fingerprint) {
            continue;
        }
        if !str_field_is(&row, "log_sha256", &digest) {
            continue;
        }
        let logged = match get(&row, "log").and_then(|value| as_str(&value)) {
            Some(logged) => logged,
            None => continue,
        };
        match std::fs::canonicalize(&logged) {
            Ok(resolved) if resolved == target => {}
            _ => continue,
        }
        out.append(row)?;
    }
    Ok(Some(out.unbind()))
}

// ---------------------------------------------------------------------------
// Receipt aggregation: receipt_report over the rows of any number of
// session receipt files, in one call, instead of a re-scan per process.

#[pyfunction]
fn store_receipt_report(py: Python<'_>, paths: Vec<String>) -> PyResult<Py<PyDict>> {
    let mut native: i64 = 0;
    let mut fixture: i64 = 0;
    let mut avoided: i64 = 0;
    let mut full: i64 = 0;
    let mut reuse: i64 = 0;
    let mut wall: i64 = 0;
    let mut cpu: i64 = 0;
    let mut slot: i64 = 0;
    let mut peak: i64 = 0;
    for path in &paths {
        for row in receipt_rows(py, Path::new(path))? {
            let row = row.bind(py);
            native += int_or_zero(py, get(&row, "native_invocations"))?;
            fixture += int_or_zero(py, get(&row, "fixture_invocations"))?;
            let avoided_duplicate = get(&row, "avoided_duplicate").is_some_and(|v| is_true(&v));
            if avoided_duplicate {
                avoided += 1;
            }
            if str_field_is(&row, "kind", "check") && str_field_is(&row, "selection", "full") {
                full += 1;
            }
            if get(&row, "reused").is_some_and(|v| is_true(&v)) || str_field_is(&row, "kind", "reuse") {
                reuse += 1;
            }
            let kind = get(&row, "kind").and_then(|value| as_str(&value));
            if avoided_duplicate
                || matches!(kind.as_deref(), Some("reuse" | "selection" | "invalidation" | "validation"))
            {
                continue;
            }
            if get(&row, "fixture_invocations").is_some_and(|v| truthy(&v)) {
                continue;
            }
            if row.get_item("wall_ms")?.is_none() {
                continue;
            }
            wall += int_or_zero(py, get(&row, "wall_ms"))?;
            cpu += int_or_zero(py, get(&row, "cpu_ms"))?;
            slot += int_or_zero(py, get(&row, "slot_wait_ms"))?;
            peak = peak.max(int_or_zero(py, get(&row, "peak_memory_kb"))?);
        }
    }
    let report = PyDict::new(py);
    report.set_item("native_build_invocations", native)?;
    report.set_item("fixture_build_invocations", fixture)?;
    report.set_item("avoided_duplicate_pending_builds", avoided)?;
    report.set_item("full_suite_executions", full)?;
    report.set_item("receipt_reuse", reuse)?;
    report.set_item("wall_ms", wall)?;
    report.set_item("cpu_ms", cpu)?;
    report.set_item("peak_memory_kb", peak)?;
    report.set_item("slot_wait_ms", slot)?;
    Ok(report.unbind())
}

// ---------------------------------------------------------------------------
// Closure aggregation: evals/closure_report.aggregate over the usage rows
// of any number of session directories, in one call. A closure is a turn
// segment's last Stop row; segments end at prompt-submit rows, and a final
// synthetic prompt row closes the trailing segment, as in the oracle.

struct ClosureAgg {
    by_tier_class: BTreeMap<String, i64>,
    attempts_sum: i64,
    attempts_count: i64,
    closes_sum: i64,
    standard: i64,
    standard_not_ready: i64,
}

impl ClosureAgg {
    fn flush(&mut self, py: Python<'_>, segment: &[Py<PyDict>]) {
        let segment: Vec<Bound<'_, PyDict>> = segment.iter().map(|row| row.bind(py).clone()).collect();
        let stops: Vec<&Bound<'_, PyDict>> = segment
            .iter()
            .filter(|row| str_field_is(row, "event", "stop"))
            .collect();
        let Some(closure) = stops.last() else {
            return;
        };
        let tier = get(closure, "tier").and_then(|v| as_str(&v)).unwrap_or_else(|| "unknown".into());
        let class = get(closure, "class").and_then(|v| as_str(&v)).unwrap_or_else(|| "unknown".into());
        *self.by_tier_class.entry(format!("{tier}/{class}")).or_insert(0) += 1;
        self.attempts_sum += stops.len() as i64;
        self.attempts_count += 1;
        self.closes_sum += segment.iter().filter(|row| str_field_is(row, "event", "close")).count() as i64;
        if tier == "standard" {
            self.standard += 1;
            let ready = matches!(
                get(closure, "verdict").and_then(|v| as_str(&v)).as_deref(),
                Some("READY" | "pass")
            );
            if !ready {
                self.standard_not_ready += 1;
            }
        }
    }
}

#[pyfunction]
fn store_closure_report(py: Python<'_>, session_dirs: Vec<String>) -> PyResult<Py<PyDict>> {
    let mut agg = ClosureAgg {
        by_tier_class: BTreeMap::new(),
        attempts_sum: 0,
        attempts_count: 0,
        closes_sum: 0,
        standard: 0,
        standard_not_ready: 0,
    };
    for dir in &session_dirs {
        let rows = usage_rows(py, Path::new(dir))?;
        let mut segment: Vec<Py<PyDict>> = Vec::new();
        for row in &rows {
            let bound = row.bind(py);
            let event = get(&bound, "event").and_then(|v| as_str(&v));
            if PROMPT_EVENTS.contains(&event.as_deref().unwrap_or("")) {
                agg.flush(py, &segment);
                segment.clear();
            } else {
                segment.push(row.clone_ref(py));
            }
        }
        agg.flush(py, &segment);
    }
    let total: i64 = agg.by_tier_class.values().sum();
    let by = PyDict::new(py);
    for (key, count) in &agg.by_tier_class {
        by.set_item(key, count)?;
    }
    let report = PyDict::new(py);
    report.set_item("closures", total)?;
    report.set_item("by_tier_class", by)?;
    report.set_item(
        "mean_stop_attempts",
        if total > 0 { agg.attempts_sum as f64 / total as f64 } else { 0.0 },
    )?;
    report.set_item(
        "mean_close_calls",
        if total > 0 { agg.closes_sum as f64 / total as f64 } else { 0.0 },
    )?;
    report.set_item("standard_closures", agg.standard)?;
    report.set_item("standard_not_ready", agg.standard_not_ready)?;
    match if agg.standard > 0 {
        Some(agg.standard_not_ready as f64 / agg.standard as f64)
    } else {
        None
    } {
        Some(fraction) => report.set_item("standard_not_ready_fraction", fraction)?,
        None => report.set_item("standard_not_ready_fraction", py.None())?,
    }
    Ok(report.unbind())
}

// ---------------------------------------------------------------------------
// The host-wide Check slot. One slot per machine: an OS file lock on
// check-slot.lock (the kernel drops it when the holder dies, so a crash
// cannot wedge the next run), with the holder's metadata in
// check-slot.json. The locked File lives in this registry until release;
// the acquiring process owns it, exactly as the Python route owns its fd.
// Poll and timeout semantics are the Python route's: try at once, poll
// every 20 ms, and on timeout report the holder the metadata names.

static SLOT_COUNTER: AtomicU64 = AtomicU64::new(1);
static SLOTS: Mutex<Option<HashMap<u64, File>>> = Mutex::new(None);

enum SlotOutcome {
    Acquired(u64, f64),
    Timeout(f64, Vec<u8>),
    Unavailable,
}

fn slots() -> std::sync::MutexGuard<'static, Option<HashMap<u64, File>>> {
    SLOTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Python's `json.dumps` string escaping (ensure_ascii), so the metadata
/// file parses to the same values whichever route wrote it.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch if (ch as u32) < 0x7f => out.push(ch),
            ch => {
                let cp = ch as u32;
                if cp < 0x10000 {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let rest = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (rest >> 10), 0xdc00 + (rest & 0x3ff)));
                }
            }
        }
    }
    out.push('"');
    out
}

fn slot_meta_json(session_id: &str, host: &str, command: &[String]) -> String {
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let command_json = command
        .iter()
        .map(|part| json_escape(part))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\"command\": [{}], \"host\": {}, \"pid\": {}, \"session_id\": {}, \"started_at\": {:?}}}\n",
        command_json,
        json_escape(host),
        std::process::id(),
        json_escape(session_id),
        started_at,
    )
}

fn slot_acquire_impl(
    lock_path: &Path,
    meta_path: &Path,
    session_id: &str,
    host: &str,
    command: &[String],
    timeout_s: f64,
) -> SlotOutcome {
    if let Some(parent) = lock_path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let _ = std::fs::DirBuilder::new().mode(0o700).create(parent);
        }
        #[cfg(not(unix))]
        let _ = std::fs::create_dir_all(parent);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(lock_path) {
        Ok(file) => file,
        Err(_) => return SlotOutcome::Unavailable,
    };
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(_) => {
                // WouldBlock and a lock error alike: the Python route's
                // nonblocking attempt returns False for both and polls on.
                let waited = started.elapsed().as_secs_f64();
                if waited >= timeout_s {
                    let meta = std::fs::read(meta_path).unwrap_or_default();
                    return SlotOutcome::Timeout(waited, meta);
                }
                std::thread::sleep(SLOT_POLL);
            }
        }
    }
    let waited = started.elapsed().as_secs_f64();
    // A contender that times out names what it can: a failed metadata
    // write never loses the slot.
    let _ = std::fs::write(meta_path, slot_meta_json(session_id, host, command));
    let token = SLOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    slots()
        .get_or_insert_with(HashMap::new)
        .insert(token, file);
    SlotOutcome::Acquired(token, waited)
}

fn parse_holder(py: Python<'_>, meta: &[u8]) -> Py<PyAny> {
    let empty = || PyDict::new(py).unbind().into_any();
    let text = match std::str::from_utf8(meta) {
        Ok(text) => text,
        Err(_) => return empty(),
    };
    let loads = match py.import("json").and_then(|json| json.getattr("loads")) {
        Ok(loads) => loads,
        Err(_) => return empty(),
    };
    match loads.call1((text,)) {
        Ok(value) if value.is_instance_of::<PyDict>() => value.unbind(),
        _ => empty(),
    }
}

#[pyfunction]
fn store_slot_acquire(
    py: Python<'_>,
    lock_path: String,
    meta_path: String,
    session_id: String,
    host: String,
    command: Vec<String>,
    timeout_s: f64,
) -> PyResult<Py<PyDict>> {
    let outcome = py.detach(move || {
        slot_acquire_impl(
            &PathBuf::from(lock_path),
            &PathBuf::from(meta_path),
            &session_id,
            &host,
            &command,
            timeout_s,
        )
    });
    let result = PyDict::new(py);
    match outcome {
        SlotOutcome::Acquired(token, waited) => {
            result.set_item("status", "acquired")?;
            result.set_item("token", token)?;
            result.set_item("waited", waited)?;
        }
        SlotOutcome::Timeout(waited, meta) => {
            result.set_item("status", "timeout")?;
            result.set_item("waited", waited)?;
            result.set_item("holder", parse_holder(py, &meta))?;
        }
        SlotOutcome::Unavailable => {
            result.set_item("status", "unavailable")?;
        }
    }
    Ok(result.unbind())
}

#[pyfunction]
fn store_slot_release(token: u64) -> bool {
    let file = slots().as_mut().and_then(|map| map.remove(&token));
    match file {
        Some(file) => {
            let _ = file.unlock();
            true
        }
        None => false,
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("STORE_SCHEMA", STORE_SCHEMA)?;
    m.add_function(wrap_pyfunction!(store_green_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(store_log_candidates, m)?)?;
    m.add_function(wrap_pyfunction!(store_receipt_report, m)?)?;
    m.add_function(wrap_pyfunction!(store_closure_report, m)?)?;
    m.add_function(wrap_pyfunction!(store_slot_acquire, m)?)?;
    m.add_function(wrap_pyfunction!(store_slot_release, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{json_escape, sha256_hex};

    #[test]
    fn sha256_fips_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn json_escape_matches_python_dumps() {
        assert_eq!(json_escape("plain"), "\"plain\"");
        assert_eq!(json_escape("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(json_escape("á"), "\"\\u00e1\"");
        assert_eq!(json_escape("\u{1f600}"), "\"\\ud83d\\ude00\"");
        assert_eq!(json_escape("\u{01}\u{7f}"), "\"\\u0001\\u007f\"");
    }
}
