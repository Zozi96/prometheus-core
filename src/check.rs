//! The standalone check runner's mechanics (ADR-0010, ticket #60):
//! `.prometheus.json` config, compiled-command bounding (ADR-0004), the
//! Iteration profile (ADR-0008), the host-wide Check slot, Green receipts
//! (ADR-0001), and the Scan cache. Pure functions and small file stores so
//! the `prometheus-check` binary stays a thin orchestration shell and every
//! rule is unit-testable without spawning a process.
//!
//! Vocabulary follows GLOSSARY.md: Check slot, Check footprint, Green
//! receipt, Tree fingerprint, Iteration profile, Behavioral pass, Widening,
//! Scan cache. This module never imports or invokes the Python gate
//! runtime; receipts written here are the runner's own store, keyed by
//! Tree fingerprint and logical command exactly as ADR-0001 requires.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Repository config (.prometheus.json)

/// The slice of `.prometheus.json` the runner reads. Unknown keys are the
/// repository's business; a malformed file yields the defaults, and the
/// caller reports that the config could not be read.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// `test_command`: a string (split on whitespace) or an argv list.
    pub test_command: Option<Vec<String>>,
    /// `parallelism`: the Check footprint cap for compiled runs.
    pub parallelism: Option<usize>,
    /// `iteration_profile`: MSBuild properties for iterative runs only.
    pub iteration_profile: BTreeMap<String, String>,
}

pub fn load_config(root: &Path) -> Config {
    let Ok(text) = std::fs::read_to_string(root.join(".prometheus.json")) else {
        return Config::default();
    };
    parse_config(&text).unwrap_or_default()
}

pub fn parse_config(text: &str) -> Option<Config> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let test_command = match object.get("test_command") {
        Some(serde_json::Value::String(text)) => {
            let parts: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
            if parts.is_empty() { None } else { Some(parts) }
        }
        Some(serde_json::Value::Array(items)) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect();
            if parts.len() == items.len() && !parts.is_empty() { Some(parts) } else { None }
        }
        _ => None,
    };
    let parallelism = object
        .get("parallelism")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value as usize)
        .filter(|value| *value > 0);
    let iteration_profile = match object.get("iteration_profile") {
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .filter_map(|(key, value)| match value {
                serde_json::Value::String(text) => Some((key.clone(), text.clone())),
                serde_json::Value::Bool(flag) => {
                    Some((key.clone(), if *flag { "true" } else { "false" }.to_owned()))
                }
                serde_json::Value::Number(number) => Some((key.clone(), number.to_string())),
                _ => None,
            })
            .collect(),
        _ => BTreeMap::new(),
    };
    Some(Config { test_command, parallelism, iteration_profile })
}

/// The Iteration profile tokens for an MSBuild run: `-p:Key=Value`, sorted
/// by key, exactly the gate's `_profile_flags` shape. The full suite never
/// carries the profile, and neither does a `--no-profile` run; the caller
/// decides both before asking here.
pub fn profile_args(config: &Config) -> Vec<String> {
    config
        .iteration_profile
        .iter()
        .map(|(key, value)| format!("-p:{key}={value}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Compiled commands and bounded Check footprint (ADR-0004)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compiled {
    MsBuild,
    Cargo,
}

fn program_name(command: &[String]) -> String {
    let Some(first) = command.first() else { return String::new() };
    let base = first.rsplit(['/', '\\']).next().unwrap_or(first);
    base.to_ascii_lowercase()
        .trim_end_matches(".exe")
        .trim_end_matches(".cmd")
        .trim_end_matches(".bat")
        .to_owned()
}

/// `Compiled` for `dotnet build|test|msbuild`, `msbuild`, and
/// `cargo build|test`; `None` for interpreted runners, which take no
/// Check slot and no footprint caps.
pub fn compiled_kind(command: &[String]) -> Option<Compiled> {
    let runner = program_name(command);
    let rest: Vec<String> = command.iter().skip(1).map(|part| part.to_ascii_lowercase()).collect();
    match runner.as_str() {
        "msbuild" => Some(Compiled::MsBuild),
        "dotnet" => match rest.first().map(String::as_str) {
            Some("build" | "test" | "msbuild") => Some(Compiled::MsBuild),
            _ => None,
        },
        "cargo" => {
            // Skip a `+toolchain` prefix and leading global flags.
            let sub = rest
                .iter()
                .find(|part| !part.starts_with('+') && !part.starts_with('-'))
                .map(String::as_str);
            match sub {
                Some("build" | "test") => Some(Compiled::Cargo),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Half the host's cores, at least one: the ADR-0004 default cap when the
/// repository does not declare `parallelism`.
pub fn default_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|count| (count.get() / 2).max(1))
        .unwrap_or(1)
}

fn profile_key(flag: &str) -> Option<String> {
    let folded = flag.to_ascii_lowercase();
    for prefix in ["-p:", "/p:", "--property:", "-property:"] {
        if let Some(rest) = folded.strip_prefix(prefix) {
            return Some(rest.split('=').next().unwrap_or(rest).to_owned());
        }
    }
    None
}

/// The argv a compiled run actually executes: parallelism caps and the
/// Iteration profile injected before any `--`, never duplicating a cap or
/// a property the caller's logical command already sets. The Green
/// receipt keeps the logical command; this argv is only the process.
pub fn bound_argv(command: &[String], jobs: usize, profile: &[String]) -> Vec<String> {
    let Some(kind) = compiled_kind(command) else {
        return command.to_vec();
    };
    let split = command.iter().position(|part| part == "--").unwrap_or(command.len());
    let (head, tail) = command.split_at(split);
    let mut out: Vec<String> = head.to_vec();
    match kind {
        Compiled::MsBuild => {
            let has_m = head.iter().any(|part| {
                let folded = part.to_ascii_lowercase();
                folded == "-m" || folded.starts_with("-m:") || folded.starts_with("--maxcpucount")
            });
            if !has_m {
                out.push(format!("-m:{jobs}"));
            }
            let has_nr = head.iter().any(|part| {
                part.to_ascii_lowercase().starts_with("-nodereuse")
                    || part.to_ascii_lowercase().starts_with("/nodereuse")
            });
            if !has_nr {
                out.push("-nodeReuse:false".to_owned());
            }
        }
        Compiled::Cargo => {
            let has_j = head.iter().any(|part| {
                part == "-j" || part.starts_with("--jobs") || part.starts_with("-j")
            });
            if !has_j {
                out.push("-j".to_owned());
                out.push(jobs.to_string());
            }
        }
    }
    let set: Vec<String> = head.iter().filter_map(|part| profile_key(part)).collect();
    for flag in profile {
        match profile_key(flag) {
            Some(key) if set.contains(&key) => {}
            _ => out.push(flag.clone()),
        }
    }
    out.extend_from_slice(tail);
    out
}

/// The native build a compiled test run is preceded by (ADR-0002):
/// `dotnet test` runs `dotnet build` first with the caller's build flags
/// (the `--filter` selection stays off it), and `cargo test` runs
/// `cargo test --no-run`. Build and plain run commands get no prefix.
pub fn build_before(command: &[String]) -> Option<Vec<String>> {
    let kind = compiled_kind(command)?;
    let runner = program_name(command);
    let subcommand = command
        .iter()
        .skip(1)
        .find(|part| !part.starts_with('+') && !part.starts_with('-'))
        .map(|part| part.to_ascii_lowercase());
    if subcommand.as_deref() != Some("test") {
        return None;
    }
    match kind {
        Compiled::Cargo => {
            let mut out: Vec<String> = command.to_vec();
            out.push("--no-run".to_owned());
            Some(out)
        }
        Compiled::MsBuild if runner == "dotnet" => {
            let mut out = vec![command[0].clone(), "build".to_owned()];
            let mut index = 2;
            while index < command.len() {
                let part = &command[index];
                if part == "--" {
                    break;
                }
                let folded = part.to_ascii_lowercase();
                if folded == "--filter" {
                    index += 2;
                    continue;
                }
                if folded.starts_with("--filter") {
                    index += 1;
                    continue;
                }
                out.push(part.clone());
                index += 1;
            }
            Some(out)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Counts and the Behavioral pass (ADR-0008)

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub passed: i64,
    pub failed: i64,
    pub skipped: i64,
    pub total: i64,
}

/// Counts from the engine's parsed check-log document, or `None` when the
/// output carried no recognizable test summary.
pub fn counts_of(document: &str) -> Option<Counts> {
    let value: serde_json::Value = serde_json::from_str(document).ok()?;
    let counts = value.get("counts")?;
    if counts.is_null() {
        return None;
    }
    serde_json::from_value(counts.clone()).ok()
}

/// A Behavioral pass: at least one executed test, at least one passing,
/// none failing, exit 0. A lint, type, or build result and an empty
/// selection are not one (GLOSSARY, ADR-0008).
pub fn behavioral_pass(counts: Option<Counts>, exit: i32) -> bool {
    exit == 0
        && counts.map(|counts| counts.total > 0 && counts.passed >= 1 && counts.failed == 0)
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Green receipts (ADR-0001, ADR-0008)

/// One row of the runner's receipt store (`receipts.jsonl` in the store
/// directory). Only facts: what ran, on which Tree fingerprint, with what
/// outcome. A receipt is Green when `exit == 0` and it records a
/// Behavioral pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub kind: String,
    pub command: Vec<String>,
    pub fingerprint: String,
    pub exit: i32,
    #[serde(default)]
    pub counts: Option<Counts>,
    #[serde(default)]
    pub behavioral: bool,
    /// The Iteration profile tokens this run carried; empty means the
    /// run built with the repository's defaults.
    #[serde(default)]
    pub profile: Vec<String>,
    #[serde(default)]
    pub selection: String,
    #[serde(default)]
    pub widen: Vec<String>,
    #[serde(default)]
    pub log: String,
    #[serde(default)]
    pub wall_ms: u128,
    #[serde(default)]
    pub slot_wait_ms: u128,
}

pub fn read_receipts(path: &Path) -> Vec<Receipt> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    text.lines()
        .filter_map(|line| serde_json::from_str::<Receipt>(line).ok())
        .filter(|row| row.kind == "check")
        .collect()
}

/// The latest Green receipt an identical run may reuse, or `None`.
/// Reuse requires the exact Tree fingerprint and the exact logical
/// command (ADR-0001). A profiled receipt is never reused by a
/// `--no-profile` run (`plain`); a run that accepts the profile may
/// reuse a receipt built without it (ADR-0008).
pub fn find_green(
    receipts: &[Receipt],
    fingerprint: &str,
    logical: &[String],
    plain: bool,
) -> Option<Receipt> {
    receipts
        .iter()
        .rev()
        .find(|row| {
            row.fingerprint == fingerprint
                && row.command == logical
                && row.exit == 0
                && row.behavioral
                && !(plain && !row.profile.is_empty())
        })
        .cloned()
}

pub fn append_receipt(path: &Path, receipt: &Receipt) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", serde_json::to_string(receipt).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Scan cache (GLOSSARY): tree scans keyed by the Tree fingerprint of the
// tree each entry describes; a fingerprint change alone invalidates it.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEntry {
    pub fingerprint: String,
    pub task_delta: Vec<String>,
    pub integration_delta: Vec<String>,
    pub impact: serde_json::Value,
}

pub fn scan_cache_read(path: &Path, fingerprint: &str) -> Option<ScanEntry> {
    let text = std::fs::read_to_string(path).ok()?;
    let entry: ScanEntry = serde_json::from_str(&text).ok()?;
    (entry.fingerprint == fingerprint).then_some(entry)
}

pub fn scan_cache_write(path: &Path, entry: &ScanEntry) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string(entry).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// The Check slot (ADR-0004): one host-wide turn for compiled check runs.
// An OS file lock on `check-slot.lock` beside `check-slot.json` holder
// metadata — the same on-disk shape the core receipt store uses — so a
// holder that dies releases the slot with its process.

pub struct Slot {
    _file: File,
    pub waited: Duration,
}

#[derive(Debug)]
pub struct SlotTimeout {
    pub waited: Duration,
    pub holder: String,
}

pub fn acquire_slot(
    dir: &Path,
    command: &[String],
    timeout: Duration,
) -> Result<Slot, SlotTimeout> {
    let _ = std::fs::create_dir_all(dir);
    let lock_path = dir.join("check-slot.lock");
    let meta_path = dir.join("check-slot.json");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|_| SlotTimeout { waited: Duration::ZERO, holder: String::new() })?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(_) => {
                let waited = started.elapsed();
                if waited >= timeout {
                    let holder = std::fs::read_to_string(&meta_path).unwrap_or_default();
                    return Err(SlotTimeout { waited, holder: holder.trim().to_owned() });
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let meta = serde_json::json!({
        "command": command,
        "host": "prometheus-check",
        "pid": std::process::id(),
        "session_id": "",
        "started_at": started_at,
    });
    let _ = std::fs::write(&meta_path, format!("{meta}\n"));
    Ok(Slot { _file: file, waited: started.elapsed() })
}

// ---------------------------------------------------------------------------
// Change class (GLOSSARY), over path names only: docs-only and tests-only
// are name-decidable; anything else is a Logic change. Comment-only needs
// line content and is the scan's call, not this one's.

pub fn change_class(changed: &[String]) -> &'static str {
    if changed.is_empty() {
        return "none";
    }
    let docs = |name: &str| {
        let folded = name.to_ascii_lowercase();
        folded.ends_with(".md")
            || folded.ends_with(".rst")
            || folded.ends_with(".txt")
            || folded.starts_with("docs/")
    };
    if changed.iter().all(|name| docs(name)) {
        return "docs-only";
    }
    if changed.iter().all(|name| crate::classify::is_test_path(name)) {
        return "tests-only";
    }
    "logic"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    #[test]
    fn config_parses_command_parallelism_and_profile() {
        let config = parse_config(
            r#"{"test_command": ["pytest", "-q"], "parallelism": 3,
                "iteration_profile": {"RunAnalyzers": "false", "TreatWarningsAsErrors": true}}"#,
        )
        .unwrap();
        assert_eq!(config.test_command, Some(argv(&["pytest", "-q"])));
        assert_eq!(config.parallelism, Some(3));
        assert_eq!(
            profile_args(&config),
            argv(&["-p:RunAnalyzers=false", "-p:TreatWarningsAsErrors=true"])
        );
        let stringy = parse_config(r#"{"test_command": "cargo test --workspace"}"#).unwrap();
        assert_eq!(stringy.test_command, Some(argv(&["cargo", "test", "--workspace"])));
        assert!(parse_config("not json").is_none());
    }

    #[test]
    fn compiled_kind_recognizes_only_compiled_checks() {
        assert_eq!(compiled_kind(&argv(&["dotnet", "test", "a.csproj"])), Some(Compiled::MsBuild));
        assert_eq!(compiled_kind(&argv(&["cargo", "test"])), Some(Compiled::Cargo));
        assert_eq!(compiled_kind(&argv(&["cargo", "+stable", "test"])), Some(Compiled::Cargo));
        assert_eq!(compiled_kind(&argv(&["dotnet", "run"])), None);
        assert_eq!(compiled_kind(&argv(&["pytest", "-q"])), None);
        assert_eq!(compiled_kind(&argv(&[])), None);
    }

    #[test]
    fn bound_argv_caps_without_duplicating() {
        let bounded = bound_argv(&argv(&["cargo", "test", "--workspace"]), 4, &[]);
        assert_eq!(bounded, argv(&["cargo", "test", "--workspace", "-j", "4"]));
        let already = bound_argv(&argv(&["cargo", "test", "-j", "2"]), 4, &[]);
        assert_eq!(already, argv(&["cargo", "test", "-j", "2"]));
        let dotnet = bound_argv(
            &argv(&["dotnet", "test", "--", "--filter", "X"]),
            2,
            &argv(&["-p:RunAnalyzers=false"]),
        );
        assert_eq!(
            dotnet,
            argv(&[
                "dotnet", "test", "-m:2", "-nodeReuse:false", "-p:RunAnalyzers=false", "--",
                "--filter", "X"
            ])
        );
        let own_property = bound_argv(
            &argv(&["dotnet", "test", "-p:RunAnalyzers=true"]),
            2,
            &argv(&["-p:RunAnalyzers=false"]),
        );
        assert!(!own_property.iter().any(|part| part == "-p:RunAnalyzers=false"));
        assert_eq!(bound_argv(&argv(&["pytest", "-q"]), 4, &[]), argv(&["pytest", "-q"]));
    }

    #[test]
    fn build_before_pairs_the_native_build() {
        assert_eq!(
            build_before(&argv(&["cargo", "test", "-p", "core"])),
            Some(argv(&["cargo", "test", "-p", "core", "--no-run"]))
        );
        assert_eq!(
            build_before(&argv(&["dotnet", "test", "a.csproj", "--filter", "FullyQualifiedName~X", "-c", "Release"])),
            Some(argv(&["dotnet", "build", "a.csproj", "-c", "Release"]))
        );
        assert_eq!(build_before(&argv(&["dotnet", "build"])), None);
        assert_eq!(build_before(&argv(&["cargo", "build"])), None);
        assert_eq!(build_before(&argv(&["pytest", "-q"])), None);
    }

    #[test]
    fn behavioral_pass_needs_an_executed_passing_test() {
        let counts = Counts { passed: 3, failed: 0, skipped: 1, total: 4 };
        assert!(behavioral_pass(Some(counts), 0));
        assert!(!behavioral_pass(Some(Counts { passed: 0, failed: 0, skipped: 0, total: 0 }), 0));
        assert!(!behavioral_pass(Some(Counts { passed: 0, failed: 0, skipped: 2, total: 2 }), 0));
        assert!(!behavioral_pass(Some(Counts { passed: 3, failed: 1, skipped: 0, total: 4 }), 0));
        assert!(!behavioral_pass(Some(counts), 1));
        assert!(!behavioral_pass(None, 0));
    }

    #[test]
    fn counts_parse_from_the_engine_document() {
        let doc = r#"{"schema": 1, "counts": {"passed": 5, "failed": 0, "skipped": 1, "total": 6}, "error": null, "failing_lines": [], "failed_tests": []}"#;
        assert_eq!(counts_of(doc), Some(Counts { passed: 5, failed: 0, skipped: 1, total: 6 }));
        assert_eq!(counts_of(r#"{"counts": null}"#), None);
    }

    #[test]
    fn green_reuse_needs_fingerprint_command_and_unprofiled_for_plain() {
        let base = Receipt {
            kind: "check".into(),
            command: argv(&["pytest", "-q"]),
            fingerprint: "abc".into(),
            exit: 0,
            counts: Some(Counts { passed: 1, failed: 0, skipped: 0, total: 1 }),
            behavioral: true,
            profile: vec![],
            selection: String::new(),
            widen: vec![],
            log: String::new(),
            wall_ms: 0,
            slot_wait_ms: 0,
        };
        assert!(find_green(&[base.clone()], "abc", &argv(&["pytest", "-q"]), true).is_some());
        assert!(find_green(&[base.clone()], "xyz", &argv(&["pytest", "-q"]), true).is_none());
        assert!(find_green(&[base.clone()], "abc", &argv(&["pytest"]), true).is_none());
        let mut profiled = base.clone();
        profiled.profile = argv(&["-p:RunAnalyzers=false"]);
        assert!(find_green(&[profiled.clone()], "abc", &argv(&["pytest", "-q"]), true).is_none());
        assert!(find_green(&[profiled], "abc", &argv(&["pytest", "-q"]), false).is_some());
        let mut failed = base.clone();
        failed.behavioral = false;
        assert!(find_green(&[failed], "abc", &argv(&["pytest", "-q"]), false).is_none());
    }

    #[test]
    fn scan_cache_is_keyed_by_fingerprint() {
        let dir = std::env::temp_dir().join(format!("prometheus-check-test-{}", std::process::id()));
        let path = dir.join("scan-cache.json");
        let entry = ScanEntry {
            fingerprint: "abc".into(),
            task_delta: argv(&["a.py"]),
            integration_delta: vec![],
            impact: serde_json::json!({"selection": {"level": "targeted"}}),
        };
        scan_cache_write(&path, &entry).unwrap();
        assert!(scan_cache_read(&path, "abc").is_some());
        assert!(scan_cache_read(&path, "other").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn slot_is_exclusive_until_released() {
        let dir = std::env::temp_dir().join(format!("prometheus-check-slot-{}", std::process::id()));
        let first = acquire_slot(&dir, &argv(&["cargo", "test"]), Duration::from_secs(5)).unwrap();
        let blocked = acquire_slot(&dir, &argv(&["cargo", "test"]), Duration::from_millis(60));
        assert!(blocked.is_err());
        drop(first);
        assert!(acquire_slot(&dir, &argv(&["cargo", "test"]), Duration::from_secs(5)).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn change_class_names_docs_and_tests() {
        assert_eq!(change_class(&argv(&["README.md", "docs/x.md"])), "docs-only");
        assert_eq!(change_class(&argv(&["tests/test_a.py"])), "tests-only");
        assert_eq!(change_class(&argv(&["src/a.py"])), "logic");
        assert_eq!(change_class(&argv(&[])), "none");
    }
}
