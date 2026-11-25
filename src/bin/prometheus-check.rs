//! prometheus-check: the standalone check runner over Prometheus core
//! (ADR-0010, ticket #60).
//!
//! Usage:
//!   prometheus-check [--root <dir>] [--log <path>] [--force]
//!                    [--no-profile] -- <command...>
//!   prometheus-check [--root <dir>] [--base <ref>] [--force]
//!                    [--no-profile] --changed
//!
//! An explicit command runs as given: compiled runs (`dotnet`/`cargo`)
//! take the single host-wide Check slot with bounded Check footprint and
//! their native build first (ADR-0002, ADR-0004); a Green receipt on the
//! same Tree fingerprint and logical command is reused instead of
//! re-executing (ADR-0001). `--changed` computes the Tree scan (backed by
//! the Scan cache) over the Task delta and the Integration delta, selects
//! a Targeted check from the syntactic impact graph, and widens
//! fail-closed with recorded reasons on uncertainty. `--no-profile` drops
//! the Iteration profile and never reuses a profiled Green receipt
//! (ADR-0008). No gate record, no `--gate` flag, and no Python gate
//! import exists here: this binary is the whole runner.
//!
//! The runner's store lives in `<git-dir>/prometheus-check/` (receipts,
//! scan cache, fingerprint object store, logs); the Check slot lives in
//! the OS temp dir so every session and agent host on this machine
//! serializes on the same slot.

use prometheus_core::check::{
    git_text, host_slot_dir, is_full_command, load_config, parse_timeout, private_store_dir,
    timeout_from_env, MAX_TIMEOUT_SECS,
};
use prometheus_core::selection::{select, NoChecksOwed, SelectionOutcome};
use std::path::{Path, PathBuf};
use std::time::Duration;

const USAGE: &str = "usage: prometheus-check [--root <dir>] [--store <dir>] [--slot-dir <dir>] \
[--log <path>] [--base <ref>] [--timeout <seconds>] [--force] [--no-profile] \
(-- <command...> | --changed)";

struct Args {
    root: PathBuf,
    store: Option<PathBuf>,
    slot_dir: Option<PathBuf>,
    log: Option<PathBuf>,
    base: Option<String>,
    timeout: f64,
    force: bool,
    no_profile: bool,
    changed: bool,
    command: Vec<String>,
}

fn timeout_error(source: &str) -> String {
    format!("{source} must be a number of seconds from 0 to {MAX_TIMEOUT_SECS:.0}")
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args {
        root: std::env::current_dir().map_err(|e| e.to_string())?,
        store: None,
        slot_dir: None,
        log: None,
        base: None,
        timeout: timeout_from_env(std::env::var("PROMETHEUS_CHECK_TIMEOUT").ok().as_deref()),
        force: false,
        no_profile: false,
        changed: false,
        command: Vec::new(),
    };
    let mut index = 0;
    while index < raw.len() {
        let part = raw[index].as_str();
        let value = |index: &mut usize| -> Result<String, String> {
            *index += 1;
            raw.get(*index).cloned().ok_or_else(|| USAGE.to_string())
        };
        match part {
            "--" => {
                args.command = raw[index + 1..].to_vec();
                break;
            }
            "--root" => args.root = PathBuf::from(value(&mut index)?),
            "--store" => args.store = Some(PathBuf::from(value(&mut index)?)),
            "--slot-dir" => args.slot_dir = Some(PathBuf::from(value(&mut index)?)),
            "--log" => args.log = Some(PathBuf::from(value(&mut index)?)),
            "--base" => args.base = Some(value(&mut index)?),
            "--timeout" => {
                args.timeout = parse_timeout(&value(&mut index)?).ok_or_else(|| timeout_error("--timeout"))?
            }
            "--force" => args.force = true,
            "--no-profile" => args.no_profile = true,
            "--changed" => args.changed = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                println!("standalone check runner over Prometheus core (ADR-0010)");
                std::process::exit(0);
            }
            "--version" => {
                println!("prometheus-check {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => return Err(USAGE.to_string()),
        }
        index += 1;
    }
    if args.changed != args.command.is_empty() {
        return Err(USAGE.to_string());
    }
    Ok(args)
}

/// The runner's store: inside the git dir when there is one, so the store
/// never enters the Tree fingerprint it keys on. A tree with no git dir
/// gets a private per-user directory under the host slot directory.
fn default_store(root: &Path, base: &Path) -> Result<PathBuf, String> {
    match git_text(root, &["rev-parse", "--absolute-git-dir"]) {
        Some(git_dir) => Ok(PathBuf::from(git_dir).join("prometheus-check")),
        None => private_store_dir(base, root),
    }
}

/// Print a Check run outcome and give the process exit code: the one
/// place the binary prints from an outcome and the one place it turns
/// one into an exit code (ticket #98). Wording and codes are the
/// runner's standing ones, including a pass that selected zero tests.
fn print_outcome(outcome: &prometheus_core::check_run::CheckOutcome) -> i32 {
    use prometheus_core::check_run::{CheckOutcome, PendingReason};
    match outcome {
        CheckOutcome::Reused(reused) => {
            let counts = reused.counts;
            println!(
                "passed {} failed {} skipped {} total {} exit {}",
                counts.passed, counts.failed, counts.skipped, counts.total, reused.exit_code
            );
            println!(
                "reused green receipt; log: {} (pass --force to re-execute)",
                reused.log
            );
            reused.exit_code
        }
        CheckOutcome::ValidationPending(reason) => {
            match reason {
                PendingReason::NoTestCommandKnown { widened } => {
                    for reason in widened {
                        println!("widened: {reason}");
                    }
                    println!("validation pending: ask for the test_command");
                }
                PendingReason::SlotHeld { holder } => {
                    println!(
                        "prometheus-check: validation pending (check slot held by {})",
                        if holder.is_empty() {
                            "another check run"
                        } else {
                            holder
                        }
                    );
                }
                PendingReason::SlotUnavailable { why } => {
                    println!(
                        "prometheus-check: validation pending (check slot unavailable: {why})"
                    );
                }
                PendingReason::RunnerUnavailable { program } => {
                    println!("runner not available: {program}");
                    println!("validation pending: ask for the test_command");
                }
                PendingReason::SpawnFailed { message } => {
                    eprintln!("prometheus-check: {message}");
                }
            }
            1
        }
        CheckOutcome::Executed(run) => {
            if run.log_inside_tree {
                eprintln!(
                    "prometheus-check: the log is inside the working tree; write it outside the repo \
                     so it does not change the fingerprint"
                );
            }
            if run.tree_changed && !run.receipt_kept {
                eprintln!(
                    "prometheus-check: the tree changed during the command; no receipt was kept"
                );
            }
            match run.parsed.counts {
                Some(counts) => {
                    println!(
                        "passed {} failed {} skipped {} total {} exit {}",
                        counts.passed, counts.failed, counts.skipped, counts.total, run.exit_code
                    );
                    for line in &run.parsed.failing_lines {
                        println!("{line}");
                    }
                }
                None => {
                    for line in &run.log_tail {
                        println!("{line}");
                    }
                    println!("exit {}", run.exit_code);
                    println!("no test summary was found; this run is not behavioral evidence");
                }
            }
            println!("log: {}", run.log_path.display());
            if run
                .parsed
                .counts
                .map(|counts| counts.total == 0)
                .unwrap_or(false)
            {
                println!("zero tests selected; this run is not behavioral success");
                if run.exit_code == 0 {
                    return 1;
                }
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
            run.exit_code
        }
    }
}

/// Run the library Check run for one request and exit from its
/// outcome, in one place.
fn run_and_exit(request: prometheus_core::check_run::CheckRunRequest) -> ! {
    use prometheus_core::check_run::{run_check, RealFingerprint, RealLauncher};
    match run_check(&request, &RealLauncher, &RealFingerprint) {
        Ok(outcome) => std::process::exit(print_outcome(&outcome)),
        Err(error) => {
            eprintln!("prometheus-check: {}", error.message);
            std::process::exit(error.exit_code);
        }
    }
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    let root = args.root.canonicalize().unwrap_or_else(|_| args.root.clone());
    let store = match &args.store {
        Some(store) => store.clone(),
        None => {
            let base = args.slot_dir.clone().unwrap_or_else(host_slot_dir);
            match default_store(&root, &base) {
                Ok(store) => store,
                Err(error) => {
                    eprintln!("prometheus-check: {error}");
                    std::process::exit(2);
                }
            }
        }
    };
    let _ = std::fs::create_dir_all(&store);
    let config = load_config(&root);

    // The Check run request the binary builds at its edge: arguments
    // parsed, Ambient facts read (the default Check slot directory
    // here; the virtual environment in the `--changed` branch below),
    // and the library run called through `run_and_exit`, which prints
    // and exits in one place each.
    let make_request = |logical: Option<Vec<String>>,
                        level: prometheus_core::selection::Level,
                        widen: Vec<String>,
                        pending_prints_reasons: bool,
                        expected_fingerprint: Option<String>|
     -> prometheus_core::check_run::CheckRunRequest {
        prometheus_core::check_run::CheckRunRequest {
            root: root.clone(),
            store: store.clone(),
            slot_dir: args.slot_dir.clone().unwrap_or_else(host_slot_dir),
            log: args.log.clone(),
            force: args.force,
            no_profile: args.no_profile,
            timeout: Duration::from_secs_f64(args.timeout),
            logical,
            level,
            widen,
            pending_prints_reasons,
            config: config.clone(),
            expected_fingerprint,
        }
    };

    if !args.changed {
        let level = if is_full_command(&args.command, &config) {
            prometheus_core::selection::Level::Full
        } else {
            prometheus_core::selection::Level::Targeted
        };
        run_and_exit(make_request(
            Some(args.command.clone()),
            level,
            Vec::new(),
            false,
            None,
        ));
    }

    let Some(before) = prometheus_core::gather::tree_fingerprint(&root, &store) else {
        eprintln!("prometheus-check: tree fingerprint unavailable; checks cannot be recorded");
        std::process::exit(1);
    };

    // --changed: gather, then select, then run. Gathering is the
    // library step in `prometheus_core::gather` (ticket #97): it does
    // the base revision fallback, the Scan cache read and write, the
    // impact computation, the cargo graph, and the Python runtime
    // lookup, and returns typed facts. The one Ambient fact it needs —
    // the active virtual environment — is read here, at the binary's
    // edge, and passed in (ADR-0017 D2).
    let gathered = prometheus_core::gather::gather_scan(&prometheus_core::gather::GatherRequest {
        root: root.clone(),
        store: store.clone(),
        fingerprint: before.clone(),
        base: args.base.clone(),
        ambient: prometheus_core::gather::AmbientFacts {
            virtual_env: std::env::var_os("VIRTUAL_ENV").map(PathBuf::from),
            python_no_user_site: std::env::var_os("PYTHONNOUSERSITE")
                .is_some_and(|v| !v.is_empty()),
        },
    });
    let deltas = &gathered.deltas;
    let facts = gathered.scan_facts();
    println!(
        "change class {}: {} task file(s), {} integration file(s)",
        facts.change_class,
        deltas.task.len(),
        deltas.integration.len()
    );
    let selection = match select(&facts) {
        SelectionOutcome::Selected(selection) => selection,
        SelectionOutcome::NoChecksOwed(NoChecksOwed::NoChanges) => {
            println!("no changes against the base; no checks owed");
            std::process::exit(0);
        }
        SelectionOutcome::NoChecksOwed(NoChecksOwed::DocsOnly) => {
            println!("change class docs-only: no checks owed");
            std::process::exit(0);
        }
        SelectionOutcome::NoCommandKnown {
            reasons,
            print_reasons,
        } => {
            // No test command is known: a Validation pending outcome
            // of the library Check run, printed like every outcome.
            run_and_exit(make_request(
                None,
                prometheus_core::selection::Level::Full,
                reasons,
                print_reasons,
                Some(before.clone()),
            ));
        }
    };
    for reason in &selection.reasons {
        println!("widened: {reason}");
    }
    println!(
        "selection {}: {}",
        selection.level.as_str(),
        selection.command.join(" ")
    );
    run_and_exit(make_request(
        Some(selection.command),
        selection.level,
        selection.reasons,
        false,
        // The fingerprint that drove gathering and Selection: if the
        // tree changes before the run re-fingerprints, the run must
        // not keep or reuse a Green receipt under the newer tree.
        Some(before),
    ));
}
