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
    acquire_slot, append_receipt, behavioral_pass, bound_argv, build_before, change_class,
    compiled_kind, counts_of, default_parallelism, find_green, load_config, profile_args,
    read_receipts, scan_cache_read, scan_cache_write, Compiled, Config, Receipt, ScanEntry,
};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args {
        root: std::env::current_dir().map_err(|e| e.to_string())?,
        store: None,
        slot_dir: None,
        log: None,
        base: None,
        timeout: std::env::var("PROMETHEUS_CHECK_TIMEOUT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(600.0),
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
                args.timeout = value(&mut index)?.parse().map_err(|_| USAGE.to_string())?
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

fn git(root: &Path, parts: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(root).args(parts).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn git_lines(root: &Path, parts: &[&str]) -> Vec<String> {
    // No whole-output trim: porcelain lines carry meaning in their first
    // columns, and the first line would lose one.
    let out = Command::new("git").arg("-C").arg(root).args(parts).output();
    let Ok(out) = out else { return Vec::new() };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| line.trim_end().to_owned())
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// The runner's store: inside the git dir when there is one, so the store
/// never enters the Tree fingerprint it keys on.
fn default_store(root: &Path) -> PathBuf {
    if let Some(git_dir) = git(root, &["rev-parse", "--absolute-git-dir"]) {
        return PathBuf::from(git_dir).join("prometheus-check");
    }
    std::env::temp_dir().join("prometheus-check-store")
}

fn fingerprint(root: &Path, store: &Path) -> Option<String> {
    let objects = store.join("objects");
    let _ = std::fs::create_dir_all(&objects);
    prometheus_core::fingerprint::worktree_fingerprint(
        &root.to_string_lossy(),
        &objects.to_string_lossy(),
    )
}

/// Working-tree changes against HEAD: the Task delta, from git's status
/// plumbing (the Tree fingerprint and the impact graph are the engine's;
/// enumerating dirty paths is not). Renames report their new path.
fn task_delta(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = git_lines(root, &["status", "--porcelain", "--untracked-files=all"])
        .iter()
        .map(|line| {
            let path = line.chars().skip(3).collect::<String>();
            let path = path.rsplit(" -> ").next().unwrap_or(&path);
            path.trim().trim_matches('"').to_owned()
        })
        .filter(|line| !line.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Changes the base update brought in: the Integration delta, from the
/// merge-base of HEAD and the base ref to HEAD itself. `None` when the
/// base cannot be resolved — an uncertainty the caller widens on.
fn integration_delta(root: &Path, base: &str) -> Option<Vec<String>> {
    let merge_base = git(root, &["merge-base", "HEAD", base])?;
    Some(git_lines(root, &["diff", "--name-only", &merge_base, "HEAD"]))
}

fn is_test_file(name: &str) -> bool {
    if prometheus_core::classify::is_test_path(name) {
        return true;
    }
    let base = name.rsplit('/').next().unwrap_or(name);
    (base.starts_with("test_") && base.ends_with(".py"))
        || base.ends_with("_test.py")
        || base.ends_with("_test.go")
        || base.ends_with(".test.ts")
        || base.ends_with(".test.js")
        || base.ends_with("Test.cs")
        || base.ends_with("Tests.cs")
}

/// The discovered test files under `root`, skipping build output and
/// vendored trees. `None` when the walk itself fails: selection then
/// widens fail-closed instead of trusting a partial listing.
fn discover_tests(root: &Path) -> Option<Vec<String>> {
    let skip = [".git", "target", "node_modules", ".venv", "venv", "__pycache__", ".tox", "bin", "obj"];
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !skip.contains(&name.as_str()) {
                    stack.push(path);
                }
            } else if let Ok(rel) = path.strip_prefix(root) {
                let rel = rel.to_string_lossy().replace('\\', "/");
                if is_test_file(&rel) {
                    out.push(rel);
                }
            }
        }
    }
    out.sort();
    Some(out)
}

/// The cargo workspace graph in the impact document's input shape
/// (`[{name, dir, deps}]`, dirs root-relative), or "" when there is no
/// readable workspace.
fn cargo_graph_json(root: &Path) -> String {
    if !root.join("Cargo.toml").is_file() {
        return String::new();
    }
    let out = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--offline")
        .current_dir(root)
        .output();
    let Ok(out) = out else { return String::new() };
    if !out.status.success() {
        return String::new();
    }
    let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return String::new();
    };
    let members: Vec<String> = meta
        .get("workspace_members")
        .and_then(|value| value.as_array())
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let rel = |path: &str| -> String {
        Path::new(path)
            .strip_prefix(root)
            .map(|rel| rel.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| path.to_owned())
    };
    let mut packages = Vec::new();
    if let Some(all) = meta.get("packages").and_then(|value| value.as_array()) {
        for package in all {
            let id = package.get("id").and_then(|value| value.as_str()).unwrap_or("");
            if !members.iter().any(|member| member == id) {
                continue;
            }
            let manifest = package.get("manifest_path").and_then(|value| value.as_str()).unwrap_or("");
            let dir = rel(Path::new(manifest).parent().map(|p| p.to_string_lossy().to_string()).as_deref().unwrap_or(""));
            let deps: Vec<String> = package
                .get("dependencies")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|dep| dep.get("path").and_then(|value| value.as_str()).map(|path| rel(path)))
                        .collect()
                })
                .unwrap_or_default();
            packages.push(serde_json::json!({
                "name": package.get("name").and_then(|value| value.as_str()).unwrap_or(""),
                "dir": dir,
                "deps": deps,
            }));
        }
    }
    serde_json::to_string(&packages).unwrap_or_default()
}

/// The full-suite command for this repository: the declared
/// `test_command` first, then one detected from the project layout.
fn full_command(root: &Path, config: &Config) -> Option<Vec<String>> {
    if let Some(command) = &config.test_command {
        return Some(command.clone());
    }
    if root.join("Cargo.toml").is_file() {
        return Some(vec!["cargo".into(), "test".into(), "--workspace".into()]);
    }
    let has_dotnet = std::fs::read_dir(root)
        .map(|entries| {
            entries.flatten().any(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.ends_with(".sln") || name.ends_with(".csproj")
            })
        })
        .unwrap_or(false);
    if has_dotnet {
        return Some(vec!["dotnet".into(), "test".into()]);
    }
    if root.join("pyproject.toml").is_file() || root.join("tests").is_dir() {
        if pytest_available() {
            return Some(vec!["python3".into(), "-m".into(), "pytest".into(), "-q".into()]);
        }
        let start = if root.join("tests").is_dir() { "tests" } else { "." };
        return Some(vec![
            "python3".into(), "-m".into(), "unittest".into(), "discover".into(),
            "-s".into(), start.into(),
        ]);
    }
    if root.join("package.json").is_file() {
        return Some(vec!["npm".into(), "test".into()]);
    }
    None
}

fn pytest_available() -> bool {
    Command::new("python3")
        .args(["-c", "import pytest"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The targeted Python command for a set of test files: pytest when it is
/// installed, otherwise unittest over the files' module names — the same
/// runner-agnostic posture as ADR-0001's targeted selection.
fn python_targeted_command(tests: &[String]) -> Vec<String> {
    if pytest_available() {
        let mut command = vec!["python3".to_owned(), "-m".to_owned(), "pytest".to_owned(), "-q".to_owned()];
        command.extend(tests.iter().cloned());
        return command;
    }
    let mut command = vec!["python3".to_owned(), "-m".to_owned(), "unittest".to_owned()];
    for test in tests {
        let module = test
            .trim_end_matches(".py")
            .replace('/', ".")
            .trim_end_matches(".__init__")
            .to_owned();
        command.push(module);
    }
    command
}

fn is_full_command(command: &[String]) -> bool {
    command.iter().any(|part| part == "--workspace")
}

/// Run one logical command end to end: Green receipt reuse, the Check
/// slot and bounded footprint for compiled runs, the native build first,
/// the log, the counts, and the Green receipt this run earns.
#[allow(clippy::too_many_arguments)]
fn run_command(
    args: &Args,
    root: &Path,
    store: &Path,
    config: &Config,
    logical: Vec<String>,
    selection: &str,
    widen: Vec<String>,
    before: &str,
) -> i32 {
    let receipts_path = store.join("receipts.jsonl");
    if !args.force {
        let receipts = read_receipts(&receipts_path);
        if let Some(prior) = find_green(&receipts, before, &logical, args.no_profile) {
            let counts = prior.counts.unwrap_or_default();
            println!(
                "passed {} failed {} skipped {} total {} exit {}",
                counts.passed, counts.failed, counts.skipped, counts.total, prior.exit
            );
            println!("reused green receipt; log: {} (pass --force to re-execute)", prior.log);
            return prior.exit;
        }
    }
    let kind = compiled_kind(&logical);
    let jobs = config.parallelism.unwrap_or_else(default_parallelism);
    let profile: Vec<String> = if args.no_profile || selection == "full" || kind != Some(Compiled::MsBuild) {
        Vec::new()
    } else {
        profile_args(config)
    };
    let launched = bound_argv(&logical, jobs, &profile);

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let log_path = args.log.clone().unwrap_or_else(|| store.join("logs").join(format!("check-{stamp}.log")));
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if log_path.starts_with(root) && !log_path.starts_with(store) {
        eprintln!(
            "prometheus-check: the log is inside the working tree; write it outside the repo \
             so it does not change the fingerprint"
        );
    }
    let mut log_file = match std::fs::File::create(&log_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("prometheus-check: {error}");
            return 2;
        }
    };

    let slot_dir = args.slot_dir.clone().unwrap_or_else(|| std::env::temp_dir().join("prometheus-check-slot"));
    let started = Instant::now();
    let execute = |launched: &[String], log_file: &mut File| -> Option<i32> {
        let mut child = match Command::new(&launched[0])
            .args(&launched[1..])
            .current_dir(root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdout(Stdio::from(log_file.try_clone().ok()?))
            .stderr(Stdio::from(log_file.try_clone().ok()?))
            .spawn()
        {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("runner not available: {}", launched[0]);
                println!("validation pending: ask for the test_command");
                return None;
            }
            Err(error) => {
                eprintln!("prometheus-check: {error}");
                return None;
            }
        };
        child.wait().ok().and_then(|status| status.code()).or(Some(1))
    };

    let (code, slot_wait) = if kind.is_some() {
        match acquire_slot(&slot_dir, &logical, Duration::from_secs_f64(args.timeout)) {
            Ok(slot) => {
                let waited = slot.waited;
                let code = run_under_slot(&launched, &mut log_file, execute);
                (code, waited)
            }
            Err(timeout) => {
                println!(
                    "prometheus-check: validation pending (check slot held by {})",
                    if timeout.holder.is_empty() { "another check run".to_owned() } else { timeout.holder }
                );
                return 1;
            }
        }
    } else {
        (run_under_slot(&launched, &mut log_file, execute), Duration::ZERO)
    };
    let Some(code) = code else { return 1 };
    let wall = started.elapsed();

    let text = std::fs::read_to_string(&log_path).unwrap_or_default();
    let document = prometheus_core::logs::parse_document(&text, Some(code as i64));
    let counts = counts_of(&document);
    let behavioral = behavioral_pass(counts, code);

    let after = fingerprint(root, store).unwrap_or_default();
    if after == before && code == 0 {
        let receipt = Receipt {
            kind: "check".into(),
            command: logical.clone(),
            fingerprint: before.to_owned(),
            exit: code,
            counts,
            behavioral,
            profile: profile.clone(),
            selection: selection.to_owned(),
            widen: widen.clone(),
            log: log_path.to_string_lossy().to_string(),
            wall_ms: wall.as_millis(),
            slot_wait_ms: slot_wait.as_millis(),
        };
        let _ = append_receipt(&receipts_path, &receipt);
    } else if after != before {
        eprintln!("prometheus-check: the tree changed during the command; no receipt was kept");
    }

    match counts {
        Some(counts) => {
            println!(
                "passed {} failed {} skipped {} total {} exit {}",
                counts.passed, counts.failed, counts.skipped, counts.total, code
            );
            let parsed: serde_json::Value = serde_json::from_str(&document).unwrap_or_default();
            if let Some(lines) = parsed.get("failing_lines").and_then(|value| value.as_array()) {
                for line in lines.iter().filter_map(|value| value.as_str()) {
                    println!("{line}");
                }
            }
        }
        None => {
            let lines: Vec<&str> = text.lines().collect();
            for line in &lines[lines.len().saturating_sub(20)..] {
                println!("{line}");
            }
            println!("exit {code}");
            println!("no test summary was found; this run is not behavioral evidence");
        }
    }
    println!("log: {}", log_path.display());
    if counts.map(|counts| counts.total == 0).unwrap_or(false) {
        println!("zero tests selected; this run is not behavioral success");
        if code == 0 {
            return 1;
        }
    }
    let _ = std::io::stdout().flush();
    code
}

fn run_under_slot(
    launched: &[String],
    log_file: &mut File,
    execute: impl Fn(&[String], &mut File) -> Option<i32>,
) -> Option<i32> {
    if let Some(build) = build_before(launched) {
        let built = execute(&build, log_file)?;
        if built != 0 {
            return Some(built);
        }
    }
    execute(launched, log_file)
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
    let store = args.store.clone().unwrap_or_else(|| default_store(&root));
    let _ = std::fs::create_dir_all(&store);
    let config = load_config(&root);

    let Some(before) = fingerprint(&root, &store) else {
        eprintln!("prometheus-check: tree fingerprint unavailable; checks cannot be recorded");
        std::process::exit(1);
    };

    if !args.changed {
        let selection = if is_full_command(&args.command) { "full" } else { "targeted" };
        std::process::exit(run_command(
            &args,
            &root,
            &store,
            &config,
            args.command.clone(),
            selection,
            Vec::new(),
            &before,
        ));
    }

    // --changed: the Tree scan over both deltas, backed by the Scan cache.
    let cache_path = store.join("scan-cache.json");
    let (task, integration, impact_doc) = match scan_cache_read(&cache_path, &before) {
        Some(entry) => (entry.task_delta, entry.integration_delta, entry.impact),
        None => {
            let task = task_delta(&root);
            let base = args
                .base
                .clone()
                .or_else(|| {
                    ["origin/main", "origin/master", "main", "master"]
                        .iter()
                        .find(|refname| git(&root, &["rev-parse", "--verify", &format!("{refname}^{{commit}}")]).is_some())
                        .map(|refname| refname.to_string())
                })
                .unwrap_or_else(|| "HEAD".to_owned());
            let integration = integration_delta(&root, &base).unwrap_or_default();
            let mut changed = task.clone();
            changed.extend(integration.iter().cloned());
            changed.sort();
            changed.dedup();
            let tests = discover_tests(&root);
            let cargo_json = cargo_graph_json(&root);
            let document = prometheus_core::impact::impact_document(
                &root.to_string_lossy(),
                &changed,
                tests,
                &cargo_json,
            )
            .unwrap_or_else(|| "{\"selection\":{\"level\":\"full\",\"tests\":[],\"packages\":[],\"projects\":[],\"module\":null,\"reasons\":[\"impact unavailable; widened to the full suite\"]}}".to_owned());
            let impact_doc: serde_json::Value =
                serde_json::from_str(&document).unwrap_or(serde_json::Value::Null);
            let _ = scan_cache_write(
                &cache_path,
                &ScanEntry {
                    fingerprint: before.clone(),
                    task_delta: task.clone(),
                    integration_delta: integration.clone(),
                    impact: impact_doc.clone(),
                },
            );
            (task, integration, impact_doc)
        }
    };

    let mut changed = task.clone();
    changed.extend(integration.iter().cloned());
    changed.sort();
    changed.dedup();

    let klass = change_class(&changed);
    println!("change class {klass}: {} task file(s), {} integration file(s)", task.len(), integration.len());
    if changed.is_empty() {
        println!("no changes against the base; no checks owed");
        std::process::exit(0);
    }
    if klass == "docs-only" {
        println!("change class docs-only: no checks owed");
        std::process::exit(0);
    }

    let selection = impact_doc.get("selection").cloned().unwrap_or(serde_json::Value::Null);
    let level = selection.get("level").and_then(|value| value.as_str()).unwrap_or("full").to_owned();
    let mut reasons: Vec<String> = selection
        .get("reasons")
        .and_then(|value| value.as_array())
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let str_list = |key: &str| -> Vec<String> {
        selection
            .get(key)
            .and_then(|value| value.as_array())
            .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect())
            .unwrap_or_default()
    };

    let (command, effective_level): (Vec<String>, String) = match level.as_str() {
        "targeted" => {
            let tests = str_list("tests");
            let packages = str_list("packages");
            let projects = str_list("projects");
            if !packages.is_empty() {
                let mut command = vec!["cargo".to_owned(), "test".to_owned()];
                for package in &packages {
                    command.push("-p".to_owned());
                    command.push(package.clone());
                }
                (command, "targeted".to_owned())
            } else if !projects.is_empty() {
                (vec!["dotnet".to_owned(), "test".to_owned(), projects[0].clone()], "targeted".to_owned())
            } else if !tests.is_empty() && tests.iter().all(|test| test.ends_with(".py")) {
                (python_targeted_command(&tests), "targeted".to_owned())
            } else if let Some(module) = selection.get("module").and_then(|value| value.as_str()) {
                (
                    vec!["python3".to_owned(), "-m".to_owned(), "pytest".to_owned(), "-q".to_owned(), module.to_owned()],
                    "targeted".to_owned(),
                )
            } else {
                reasons.push("targeted selection has no runnable command; widened to the full suite".to_owned());
                match full_command(&root, &config) {
                    Some(command) => (command, "full".to_owned()),
                    None => {
                        println!("validation pending: ask for the test_command");
                        std::process::exit(1);
                    }
                }
            }
        }
        "module" => {
            if let Some(module) = selection.get("module").and_then(|value| value.as_str()) {
                (
                    vec!["python3".to_owned(), "-m".to_owned(), "pytest".to_owned(), "-q".to_owned(), module.to_owned()],
                    "module".to_owned(),
                )
            } else {
                match full_command(&root, &config) {
                    Some(command) => (command, "full".to_owned()),
                    None => {
                        println!("validation pending: ask for the test_command");
                        std::process::exit(1);
                    }
                }
            }
        }
        _ => match full_command(&root, &config) {
            Some(command) => (command, "full".to_owned()),
            None => {
                println!("validation pending: ask for the test_command");
                std::process::exit(1);
            }
        },
    };
    for reason in &reasons {
        println!("widened: {reason}");
    }
    println!("selection {effective_level}: {}", command.join(" "));
    std::process::exit(run_command(
        &args,
        &root,
        &store,
        &config,
        command,
        &effective_level,
        reasons,
        &before,
    ));
}
