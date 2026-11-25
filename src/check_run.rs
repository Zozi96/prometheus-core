//! A Check run as a library module (ADR-0017, ticket #98).
//!
//! The whole Check run — Green receipt reuse, the Check slot wait, the
//! launch, test-log parsing, the receipt, and the summary facts — lives
//! behind one interface: a [`CheckRunRequest`] in, a [`CheckOutcome`]
//! out. The binary parses arguments, reads Ambient facts (including
//! the default Check slot directory), calls [`run_check`], and prints
//! and exits from the outcome in one place each.
//!
//! Two dependencies are injected, each with a real adapter and a test
//! adapter: the process launcher ([`RealLauncher`]) and the Tree
//! fingerprint ([`RealFingerprint`]). The store and the Check slot stay
//! real, over a temporary directory in tests. There is no clock
//! adapter and no other single-adapter indirection: durations (wall
//! time and Check-slot wait) are measured here and go to the Green
//! receipt only, never to the outcome the binary prints (ADR-0017 D3).
//! `--timeout` bounds only the Check-slot wait (ADR-0004); the launched
//! command has no duration limit (ADR-0002).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::check::{
    acquire_slot_in, after_build, append_receipt, behavioral_pass, bound_argv, build_before,
    compiled_kind, default_parallelism, find_green, profile_args, read_receipts, receipt_kept,
    Compiled, Config, Counts, Receipt,
};
use crate::logs::ParsedLog;
use crate::selection::Level;

// ---------------------------------------------------------------------------
// Injected dependencies: the process launcher and the Tree fingerprint.

/// What one launch of a process did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchOutcome {
    Exited(i32),
    /// The program could not be found: the runner is unavailable.
    NotFound,
    /// The process could not be started at all.
    Failed(String),
}

/// The process launcher: run one argv in `root`, with its output
/// appended to the Check run log.
pub trait ProcessLauncher {
    fn launch(&self, argv: &[String], root: &Path, log: &mut File) -> LaunchOutcome;
}

/// The real launcher: spawn the process, inheriting nothing but the
/// log for stdout and stderr, and wait for it — with no duration
/// limit (ADR-0002).
pub struct RealLauncher;

impl ProcessLauncher for RealLauncher {
    fn launch(&self, argv: &[String], root: &Path, log: &mut File) -> LaunchOutcome {
        let (Ok(stdout), Ok(stderr)) = (log.try_clone(), log.try_clone()) else {
            return LaunchOutcome::Failed("could not clone the log file".to_owned());
        };
        let mut child = match Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
        {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return LaunchOutcome::NotFound;
            }
            Err(error) => return LaunchOutcome::Failed(error.to_string()),
        };
        LaunchOutcome::Exited(
            child
                .wait()
                .ok()
                .and_then(|status| status.code())
                .unwrap_or(1),
        )
    }
}

/// The Tree fingerprint source: the identity of the working tree's
/// content at a moment.
pub trait TreeFingerprintSource {
    fn fingerprint(&self, root: &Path, store: &Path) -> Option<String>;
}

/// The real fingerprint: the worktree fingerprint over the runner's
/// object store.
pub struct RealFingerprint;

impl TreeFingerprintSource for RealFingerprint {
    fn fingerprint(&self, root: &Path, store: &Path) -> Option<String> {
        crate::gather::tree_fingerprint(root, store)
    }
}

// ---------------------------------------------------------------------------
// The request and the outcome.

/// One Check run request. `logical: None` is how "no test command is
/// known" reaches the interface: it is a Validation pending outcome,
/// not a process exit decided by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRunRequest {
    pub root: PathBuf,
    pub store: PathBuf,
    /// The Check slot directory, resolved by the binary (its default
    /// is an Ambient fact read at the edge).
    pub slot_dir: PathBuf,
    /// An explicit log path, used as given; otherwise the log is
    /// created under the store and named from Declared inputs
    /// (ADR-0017 D4).
    pub log: Option<PathBuf>,
    pub force: bool,
    pub no_profile: bool,
    /// Bounds only the Check-slot wait (ADR-0004).
    pub timeout: Duration,
    pub logical: Option<Vec<String>>,
    pub level: Level,
    pub widen: Vec<String>,
    /// For the no-test-command outcome only: print the Widening
    /// reasons before the pending line (the runner's standing shape
    /// for a multi-family selection with no declared command).
    pub pending_prints_reasons: bool,
    pub config: Config,
    /// The Tree fingerprint that drove gathering and Selection, when
    /// the command was selected from a Tree scan (the `--changed`
    /// path). The run re-fingerprints at its own edge; if that fresh
    /// value differs from this one, the tree changed between selection
    /// and launch, so the run executes but no Green receipt is kept or
    /// reused under the newer fingerprint for a selection made from
    /// the older tree. `None` when no scan drove the selection (an
    /// explicit command): the run's own fingerprint governs.
    pub expected_fingerprint: Option<String>,
}

/// A run that executed its command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedRun {
    pub exit_code: i32,
    /// The typed parse result of the run's log (ticket #94).
    pub parsed: ParsedLog,
    pub receipt_kept: bool,
    pub tree_changed: bool,
    pub log_path: PathBuf,
    /// The log's last lines, for the no-summary report.
    pub log_tail: Vec<String>,
    pub log_inside_tree: bool,
}

/// A run covered by an existing Green receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusedRun {
    pub exit_code: i32,
    pub counts: Counts,
    pub log: String,
}

/// Why a Check run could not execute its command: Validation pending
/// (GLOSSARY). It is neither a pass nor a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReason {
    NoTestCommandKnown { widened: Vec<String> },
    SlotHeld { holder: String },
    SlotUnavailable { why: String },
    RunnerUnavailable { program: String },
    SpawnFailed { message: String },
}

/// What a Check run returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Executed(ExecutedRun),
    Reused(ReusedRun),
    ValidationPending(PendingReason),
}

/// A failure of the run's own machinery (no fingerprint, no log file):
/// the binary prints the message and exits with this code, exactly as
/// it did when the run lived in `main`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRunError {
    pub exit_code: i32,
    pub message: String,
}

// ---------------------------------------------------------------------------
// The run.

fn launch_sequence(
    launcher: &dyn ProcessLauncher,
    launched: &[String],
    root: &Path,
    log_file: &mut File,
) -> Result<i32, PendingReason> {
    let launch = |argv: &[String], log_file: &mut File| -> Result<i32, PendingReason> {
        match launcher.launch(argv, root, log_file) {
            LaunchOutcome::Exited(code) => Ok(code),
            LaunchOutcome::NotFound => Err(PendingReason::RunnerUnavailable {
                program: argv[0].clone(),
            }),
            LaunchOutcome::Failed(message) => Err(PendingReason::SpawnFailed { message }),
        }
    };
    match build_before(launched) {
        Some(build) => {
            let built = launch(&build, log_file)?;
            if built != 0 {
                return Ok(built);
            }
            launch(&after_build(launched), log_file)
        }
        None => launch(launched, log_file),
    }
}

/// Run one Check run end to end and return its outcome.
pub fn run_check(
    request: &CheckRunRequest,
    launcher: &dyn ProcessLauncher,
    fingerprints: &dyn TreeFingerprintSource,
) -> Result<CheckOutcome, CheckRunError> {
    let Some(logical) = &request.logical else {
        return Ok(CheckOutcome::ValidationPending(
            PendingReason::NoTestCommandKnown {
                widened: if request.pending_prints_reasons {
                    request.widen.clone()
                } else {
                    Vec::new()
                },
            },
        ));
    };
    let root = &request.root;
    let store = &request.store;
    let Some(before) = fingerprints.fingerprint(root, store) else {
        return Err(CheckRunError {
            exit_code: 1,
            message: "tree fingerprint unavailable; checks cannot be recorded".to_owned(),
        });
    };

    // A selection made from an older tree must never be reused
    // against, or recorded under, a newer fingerprint: if the tree
    // changed between gather/select and this run, behave exactly like
    // a tree that changes during the run — execute, keep no receipt.
    let stale_selection = request
        .expected_fingerprint
        .as_deref()
        .is_some_and(|expected| expected != before);

    let receipts_path = store.join("receipts.jsonl");
    if !request.force && !stale_selection {
        let receipts = read_receipts(&receipts_path);
        if let Some(prior) = find_green(&receipts, &before, logical, request.no_profile) {
            return Ok(CheckOutcome::Reused(ReusedRun {
                exit_code: prior.exit,
                counts: prior.counts.unwrap_or_default(),
                log: prior.log,
            }));
        }
    }

    let kind = compiled_kind(logical);
    let jobs = request
        .config
        .parallelism
        .unwrap_or_else(default_parallelism);
    let profile: Vec<String> =
        if request.no_profile || request.level == Level::Full || kind != Some(Compiled::MsBuild) {
            Vec::new()
        } else {
            profile_args(&request.config)
        };
    let launched = bound_argv(logical, jobs, &profile);

    // ADR-0017 D4: a created log is named from declared inputs — the
    // Tree fingerprint and the launched command — plus the first free
    // ordinal, claimed by exclusive create. An explicit log path is
    // used as given.
    let (log_path, mut log_file) = match &request.log {
        Some(path) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match File::create(path) {
                Ok(file) => (path.clone(), file),
                Err(error) => {
                    return Err(CheckRunError {
                        exit_code: 2,
                        message: error.to_string(),
                    });
                }
            }
        }
        None => {
            let logs_dir = store.join("logs");
            let _ = std::fs::create_dir_all(&logs_dir);
            let mut parts: Vec<&[u8]> = vec![before.as_bytes()];
            parts.extend(launched.iter().map(|arg| arg.as_bytes()));
            let hash = crate::kit_util::declared_inputs_hash(&parts);
            match crate::kit_util::claim_created_log(&logs_dir, "check", &hash) {
                Some(claimed) => claimed,
                None => {
                    return Err(CheckRunError {
                        exit_code: 2,
                        message: format!("could not claim a log file in {}", logs_dir.display()),
                    });
                }
            }
        }
    };
    let log_inside_tree = log_path.starts_with(root) && !log_path.starts_with(store);

    let started = Instant::now();
    let (code, slot_wait) = if kind.is_some() {
        match acquire_slot_in(&request.slot_dir, logical, request.timeout) {
            Ok(slot) => {
                let waited = slot.waited;
                let code = match launch_sequence(launcher, &launched, root, &mut log_file) {
                    Ok(code) => code,
                    Err(pending) => return Ok(CheckOutcome::ValidationPending(pending)),
                };
                (code, waited)
            }
            Err(timeout) => {
                return Ok(CheckOutcome::ValidationPending(match timeout.unavailable {
                    Some(why) => PendingReason::SlotUnavailable { why },
                    None => PendingReason::SlotHeld {
                        holder: timeout.holder,
                    },
                }));
            }
        }
    } else {
        let code = match launch_sequence(launcher, &launched, root, &mut log_file) {
            Ok(code) => code,
            Err(pending) => return Ok(CheckOutcome::ValidationPending(pending)),
        };
        (code, Duration::ZERO)
    };
    let wall = started.elapsed();
    let _ = log_file.flush();

    let text = std::fs::read_to_string(&log_path).unwrap_or_default();
    let parsed = crate::logs::parse_log(&text, Some(code as i64));
    let counts = parsed.counts;
    let behavioral = behavioral_pass(counts, code);

    let after = fingerprints.fingerprint(root, store).unwrap_or_default();
    let tree_changed = stale_selection || after != before;
    let kept = receipt_kept(code, counts, !tree_changed);
    if kept {
        let receipt = Receipt {
            kind: "check".into(),
            command: logical.clone(),
            fingerprint: before.clone(),
            exit: code,
            counts,
            behavioral,
            profile: profile.clone(),
            selection: request.level.as_str().to_owned(),
            widen: request.widen.clone(),
            log: log_path.to_string_lossy().to_string(),
            // Durations live on the receipt only (ADR-0017 D3).
            wall_ms: wall.as_millis(),
            slot_wait_ms: slot_wait.as_millis(),
        };
        let _ = append_receipt(&receipts_path, &receipt);
    }

    let lines: Vec<&str> = text.lines().collect();
    let log_tail = lines[lines.len().saturating_sub(20)..]
        .iter()
        .map(|line| line.to_string())
        .collect();
    Ok(CheckOutcome::Executed(ExecutedRun {
        exit_code: code,
        parsed,
        receipt_kept: kept,
        tree_changed,
        log_path,
        log_tail,
        log_inside_tree,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!(
                "prometheus-check-run-{name}-{}-{}",
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

    /// The test launcher: scripted outcome, scripted log content, an
    /// optional pause, and a record of every argv it was asked to run.
    struct TestLauncher {
        log_text: String,
        outcome: LaunchOutcome,
        sleep: Duration,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl TestLauncher {
        fn exiting(log_text: &str, code: i32) -> TestLauncher {
            TestLauncher {
                log_text: log_text.to_owned(),
                outcome: LaunchOutcome::Exited(code),
                sleep: Duration::ZERO,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProcessLauncher for TestLauncher {
        fn launch(&self, argv: &[String], _root: &Path, log: &mut File) -> LaunchOutcome {
            self.calls.borrow_mut().push(argv.to_vec());
            if !self.sleep.is_zero() {
                std::thread::sleep(self.sleep);
            }
            if let LaunchOutcome::Exited(_) = self.outcome {
                let _ = log.write_all(self.log_text.as_bytes());
                let _ = log.flush();
            }
            self.outcome.clone()
        }
    }

    /// The test Tree fingerprint: a scripted sequence; the last value
    /// repeats when the script runs out.
    struct TestFingerprint {
        values: RefCell<VecDeque<Option<String>>>,
        last: RefCell<Option<String>>,
    }

    impl TestFingerprint {
        fn fixed(value: &str) -> TestFingerprint {
            TestFingerprint::sequence(&[value, value])
        }
        fn sequence(values: &[&str]) -> TestFingerprint {
            TestFingerprint {
                values: RefCell::new(values.iter().map(|value| Some(value.to_string())).collect()),
                last: RefCell::new(None),
            }
        }
    }

    impl TreeFingerprintSource for TestFingerprint {
        fn fingerprint(&self, _root: &Path, _store: &Path) -> Option<String> {
            if let Some(value) = self.values.borrow_mut().pop_front() {
                *self.last.borrow_mut() = value.clone();
                value
            } else {
                self.last.borrow().clone()
            }
        }
    }

    const PASS_LOG: &str = "Ran 2 tests in 0.1s\n\nOK\n";

    fn request(temp: &TempDir, logical: Option<Vec<String>>) -> CheckRunRequest {
        CheckRunRequest {
            root: temp.0.clone(),
            store: temp.0.join("store"),
            slot_dir: temp.0.join("slot"),
            log: None,
            force: false,
            no_profile: false,
            timeout: Duration::from_secs(5),
            logical,
            level: Level::Targeted,
            widen: Vec::new(),
            pending_prints_reasons: false,
            config: Config::default(),
            expected_fingerprint: None,
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    fn executed(outcome: CheckOutcome) -> ExecutedRun {
        match outcome {
            CheckOutcome::Executed(run) => run,
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn pass_keeps_a_green_receipt_with_durations_on_it() {
        let temp = TempDir::new("pass");
        let req = request(&temp, Some(argv(&["pytest", "-q"])));
        let launcher = TestLauncher::exiting(PASS_LOG, 0);
        let run = executed(run_check(&req, &launcher, &TestFingerprint::fixed("fp")).unwrap());
        assert_eq!(run.exit_code, 0);
        assert_eq!(run.parsed.counts.map(|counts| counts.total), Some(2));
        assert!(run.receipt_kept);
        assert!(!run.tree_changed);
        let receipts = std::fs::read_to_string(temp.0.join("store/receipts.jsonl")).unwrap();
        assert!(receipts.contains("\"wall_ms\""), "{receipts}");
        assert!(receipts.contains("\"slot_wait_ms\""), "{receipts}");
        assert!(receipts.contains("\"fingerprint\":\"fp\""), "{receipts}");
    }

    #[test]
    fn failure_keeps_no_receipt() {
        let temp = TempDir::new("fail");
        let req = request(&temp, Some(argv(&["pytest", "-q"])));
        let launcher = TestLauncher::exiting(
            "FAIL: test_x (tests.test_a.T)\nRan 2 tests in 0.1s\n\nFAILED (failures=1)\n",
            1,
        );
        let run = executed(run_check(&req, &launcher, &TestFingerprint::fixed("fp")).unwrap());
        assert_eq!(run.exit_code, 1);
        assert!(!run.receipt_kept);
        assert!(!temp.0.join("store/receipts.jsonl").exists());
    }

    #[test]
    fn green_receipt_is_reused_and_force_reruns() {
        let temp = TempDir::new("reuse");
        let req = request(&temp, Some(argv(&["pytest", "-q"])));
        let launcher = TestLauncher::exiting(PASS_LOG, 0);
        let fingerprints = TestFingerprint::fixed("fp");
        let first = run_check(&req, &launcher, &fingerprints).unwrap();
        assert!(matches!(first, CheckOutcome::Executed(_)));
        let second = run_check(&req, &launcher, &fingerprints).unwrap();
        match second {
            CheckOutcome::Reused(reused) => {
                assert_eq!(reused.exit_code, 0);
                assert_eq!(reused.counts.total, 2);
            }
            other => panic!("expected Reused, got {other:?}"),
        }
        assert_eq!(
            launcher.calls.borrow().len(),
            1,
            "reuse must not launch again"
        );

        let mut forced = req.clone();
        forced.force = true;
        let third = run_check(&forced, &launcher, &fingerprints).unwrap();
        assert!(matches!(third, CheckOutcome::Executed(_)));
        assert_eq!(
            launcher.calls.borrow().len(),
            2,
            "a forced run launches again"
        );
    }

    #[test]
    fn tree_changing_during_the_run_keeps_no_receipt() {
        let temp = TempDir::new("changed");
        let req = request(&temp, Some(argv(&["pytest", "-q"])));
        let launcher = TestLauncher::exiting(PASS_LOG, 0);
        let fingerprints = TestFingerprint::sequence(&["before", "after"]);
        let run = executed(run_check(&req, &launcher, &fingerprints).unwrap());
        assert!(run.tree_changed);
        assert!(!run.receipt_kept);
        assert!(!temp.0.join("store/receipts.jsonl").exists());
    }

    #[test]
    fn fingerprint_changing_between_selection_and_launch_keeps_no_receipt() {
        // Regression (Devin Review BUG_..._0001): the command was
        // selected from the scan of "fp-selected", but by launch the
        // tree fingerprints as "fp-current" (and stays there). The run
        // executes, but no Green receipt may be kept under the newer
        // fingerprint for the older tree's selection.
        let temp = TempDir::new("stale-selection");
        let mut req = request(&temp, Some(argv(&["pytest", "-q"])));
        req.expected_fingerprint = Some("fp-selected".to_owned());
        let launcher = TestLauncher::exiting(PASS_LOG, 0);
        let run =
            executed(run_check(&req, &launcher, &TestFingerprint::fixed("fp-current")).unwrap());
        assert_eq!(run.exit_code, 0);
        assert!(run.tree_changed);
        assert!(!run.receipt_kept);
        assert!(!temp.0.join("store/receipts.jsonl").exists());
    }

    #[test]
    fn stale_selection_does_not_reuse_a_receipt_for_the_newer_tree() {
        // Seed a Green receipt under "fp-current" with a matching
        // selection, then submit the same command with a selection
        // made from "fp-selected": it must execute, not reuse.
        let temp = TempDir::new("stale-reuse");
        let fingerprints = TestFingerprint::fixed("fp-current");
        let launcher = TestLauncher::exiting(PASS_LOG, 0);
        let mut seeded = request(&temp, Some(argv(&["pytest", "-q"])));
        seeded.expected_fingerprint = Some("fp-current".to_owned());
        let first = run_check(&seeded, &launcher, &fingerprints).unwrap();
        assert!(matches!(first, CheckOutcome::Executed(_)));
        assert_eq!(launcher.calls.borrow().len(), 1);

        let mut stale = seeded.clone();
        stale.expected_fingerprint = Some("fp-selected".to_owned());
        let second = run_check(&stale, &launcher, &fingerprints).unwrap();
        assert!(matches!(second, CheckOutcome::Executed(_)));
        assert_eq!(
            launcher.calls.borrow().len(),
            2,
            "a stale selection must launch, not reuse the newer receipt"
        );
    }

    #[test]
    fn log_with_no_summary_is_executed_with_no_counts() {
        let temp = TempDir::new("nosummary");
        let req = request(&temp, Some(argv(&["pytest", "-q"])));
        let launcher = TestLauncher::exiting("compiling things\n", 0);
        let run = executed(run_check(&req, &launcher, &TestFingerprint::fixed("fp")).unwrap());
        assert_eq!(run.parsed.counts, None);
        assert_eq!(run.parsed.error.as_deref(), Some("no-summary"));
        assert_eq!(run.log_tail, vec!["compiling things".to_owned()]);
    }

    #[test]
    fn zero_tests_run_is_executed_and_keeps_no_receipt() {
        let temp = TempDir::new("zero");
        let req = request(&temp, Some(argv(&["pytest", "-q"])));
        let launcher = TestLauncher::exiting("Ran 0 tests in 0.0s\n\nOK\n", 0);
        let run = executed(run_check(&req, &launcher, &TestFingerprint::fixed("fp")).unwrap());
        assert_eq!(run.exit_code, 0);
        assert_eq!(run.parsed.counts.map(|counts| counts.total), Some(0));
        assert!(
            !run.receipt_kept,
            "an empty selection is not behavioral evidence"
        );
    }

    #[test]
    fn each_validation_pending_cause() {
        // No test command is known.
        let temp = TempDir::new("pending-command");
        let outcome = run_check(
            &request(&temp, None),
            &TestLauncher::exiting(PASS_LOG, 0),
            &TestFingerprint::fixed("fp"),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            CheckOutcome::ValidationPending(PendingReason::NoTestCommandKnown { .. })
        ));

        // The runner is unavailable.
        let temp = TempDir::new("pending-runner");
        let mut launcher = TestLauncher::exiting(PASS_LOG, 0);
        launcher.outcome = LaunchOutcome::NotFound;
        let outcome = run_check(
            &request(&temp, Some(argv(&["pytest", "-q"]))),
            &launcher,
            &TestFingerprint::fixed("fp"),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            CheckOutcome::ValidationPending(PendingReason::RunnerUnavailable { .. })
        ));

        // The Check slot wait times out: hold the slot for real.
        let temp = TempDir::new("pending-slot");
        let mut req = request(&temp, Some(argv(&["cargo", "test", "--workspace"])));
        req.timeout = Duration::from_millis(60);
        let held = crate::check::acquire_slot_in(
            &req.slot_dir,
            &argv(&["cargo", "test"]),
            Duration::from_secs(5),
        )
        .unwrap();
        let launcher = TestLauncher::exiting(PASS_LOG, 0);
        let outcome = run_check(&req, &launcher, &TestFingerprint::fixed("fp")).unwrap();
        assert!(matches!(
            outcome,
            CheckOutcome::ValidationPending(PendingReason::SlotHeld { .. })
        ));
        assert!(
            launcher.calls.borrow().is_empty(),
            "a timed-out run never launches"
        );
        drop(held);

        // The Check slot is unavailable: its directory is a file.
        let temp = TempDir::new("pending-unavailable");
        let req = request(&temp, Some(argv(&["cargo", "test", "--workspace"])));
        std::fs::write(&req.slot_dir, "not a directory").unwrap();
        let outcome = run_check(
            &req,
            &TestLauncher::exiting(PASS_LOG, 0),
            &TestFingerprint::fixed("fp"),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            CheckOutcome::ValidationPending(PendingReason::SlotUnavailable { .. })
        ));
    }

    #[test]
    fn same_request_against_same_store_state_gives_equal_outcome() {
        let temp = TempDir::new("twice");
        let mut req = request(&temp, Some(argv(&["pytest", "-q"])));
        req.force = true;
        let run_once = || {
            let launcher = TestLauncher::exiting(PASS_LOG, 0);
            run_check(&req, &launcher, &TestFingerprint::fixed("fp")).unwrap()
        };
        let first = run_once();
        // The second run starts from the same store state (ADR-0017:
        // the created log's ordinal depends on store state).
        let _ = std::fs::remove_dir_all(temp.0.join("store"));
        let second = run_once();
        assert_eq!(first, second);
    }

    #[test]
    fn timeout_bounds_only_the_slot_wait_never_the_launched_command() {
        // A launched command that runs far past `--timeout` still
        // completes: the timeout is the slot wait's, and the slot is
        // free here.
        let temp = TempDir::new("slow");
        let mut req = request(&temp, Some(argv(&["cargo", "test", "--workspace"])));
        req.timeout = Duration::from_millis(50);
        let mut launcher = TestLauncher::exiting(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            0,
        );
        launcher.sleep = Duration::from_millis(300);
        let run = executed(run_check(&req, &launcher, &TestFingerprint::fixed("fp")).unwrap());
        assert_eq!(run.exit_code, 0);
        assert!(run.receipt_kept);
        // The slot-wait timeout half is covered by
        // `each_validation_pending_cause` (SlotHeld): the wait ended
        // at the timeout while the holder still held the slot.
    }
}
