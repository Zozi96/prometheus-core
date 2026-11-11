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
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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

// ---------------------------------------------------------------------------
// The native build a compiled test run is preceded by (ADR-0002).

/// Longest accepted `--timeout`: one year, in seconds.
pub const MAX_TIMEOUT_SECS: f64 = 31_536_000.0;

/// A timeout in seconds, or `None` when it is not a finite number in
/// `0..=MAX_TIMEOUT_SECS`; `Duration::from_secs_f64` panics on the rest.
pub fn parse_timeout(text: &str) -> Option<f64> {
    let value: f64 = text.trim().parse().ok()?;
    (value.is_finite() && (0.0..=MAX_TIMEOUT_SECS).contains(&value)).then_some(value)
}

/// The `PROMETHEUS_CHECK_TIMEOUT` value, or the 600 s default when it is
/// unset or invalid; only the CLI flag is strict.
pub fn timeout_from_env(value: Option<&str>) -> f64 {
    value.and_then(parse_timeout).unwrap_or(600.0)
}

/// Whether a finished run earns a receipt: the tree stayed put, the exit
/// was 0, and the run did not select zero tests.
pub fn receipt_kept(exit: i32, counts: Option<Counts>, tree_stable: bool) -> bool {
    tree_stable && exit == 0 && counts.map(|counts| counts.total != 0).unwrap_or(true)
}

// `dotnet build` shares these value flags with `dotnet test`.
const DOTNET_BUILD_VALUE_FLAGS: [&str; 9] =
    ["-c", "--configuration", "-f", "--framework", "-r", "--runtime", "-a", "--arch", "--os"];
// Test-only value flags: they stay off the build and select no other binaries.
const DOTNET_TEST_VALUE_FLAGS: [&str; 17] = [
    "--filter", "--filter-class", "--filter-method", "--filter-trait", "--logger", "-l", "--diag", "-d",
    "--settings", "-s",
    "--results-directory", "--verbosity", "-v", "--collect", "--max-threads",
    "--blame-crash-dump-type", "--blame-hang-timeout",
];
const DOTNET_TEST_SWITCHES: [&str; 10] = [
    "--blame", "--blame-crash", "--blame-hang", "--nologo", "-n", "--no-launch-profile",
    "--no-progress", "--interactive", "--list-tests", "-t",
];
const DOTNET_TARGETS: [&str; 5] = [".csproj", ".fsproj", ".vbproj", ".sln", ".slnx"];

fn is_dotnet_target(arg: &str) -> bool {
    let folded = arg.to_ascii_lowercase();
    if arg.starts_with('-') || !DOTNET_TARGETS.iter().any(|ext| folded.ends_with(ext)) {
        return false;
    }
    // A leading slash is an MSBuild flag (`/p:Name=value`) unless a path
    // separator comes before any `:` or `=`: `/tmp/x.csproj` is a target.
    match arg.strip_prefix('/') {
        Some(rest) => rest.find('/').is_some_and(|slash| rest.find([':', '=']).map_or(true, |end| slash < end)),
        None => true,
    }
}

fn is_msbuild_cap(folded: &str) -> bool {
    folded == "-m"
        || folded == "/m"
        || ["-m:", "/m:", "-maxcpucount", "/maxcpucount", "--maxcpucount", "-nodereuse", "/nodereuse", "-nr:", "/nr:"]
            .iter()
            .any(|prefix| folded.starts_with(prefix))
}

/// The `dotnet build` argv for a `dotnet test` command and whether that
/// build covers every flag. The build takes the project or solution,
/// build-only flags, MSBuild properties and parallelism caps; test-only
/// flags and their values stay off it. An unrecognized flag is never
/// guessed at: the split is then not covered and `dotnet test` must do its
/// own build. `None` for anything but `dotnet test` without `--no-build`.
fn dotnet_build_plan(command: &[String]) -> Option<(Vec<String>, bool)> {
    if program_name(command) != "dotnet" || !command.get(1)?.eq_ignore_ascii_case("test") {
        return None;
    }
    let args = &command[2..];
    let before_separator = args.iter().take_while(|arg| *arg != "--");
    if before_separator.clone().any(|arg| arg.to_ascii_lowercase().split('=').next() == Some("--no-build")) {
        return None;
    }
    let mut build = vec![command[0].clone(), "build".to_owned()];
    let mut covered = true;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let folded = arg.to_ascii_lowercase();
        if folded == "--" {
            break;
        }
        let head = folded.split('=').next().unwrap_or(&folded).to_owned();
        let next = args.get(index + 1);
        if ["-p:", "/p:", "--property:", "-property:"].iter().any(|prefix| folded.starts_with(prefix))
            || is_msbuild_cap(&folded)
        {
            build.push(arg.clone());
            index += 1;
        } else if ["-p", "/p", "--property", "-property"].contains(&head.as_str()) {
            if arg.contains('=') {
                build.push(arg.clone());
                index += 1;
            } else if let Some(value) = next.filter(|value| value.contains('=')) {
                build.push(arg.clone());
                build.push(value.clone());
                index += 2;
            } else {
                covered = false;
                index += 1;
            }
        } else if DOTNET_BUILD_VALUE_FLAGS.contains(&head.as_str())
            || DOTNET_TEST_VALUE_FLAGS.contains(&head.as_str())
        {
            let take = if arg.contains('=') {
                1
            } else if next.is_some_and(|value| !value.starts_with('-')) {
                2
            } else {
                covered = false;
                1
            };
            if DOTNET_BUILD_VALUE_FLAGS.contains(&head.as_str()) && covered {
                build.extend(args[index..index + take].iter().cloned());
            }
            index += take;
        } else if head == "--no-restore" {
            build.push(arg.clone());
            index += 1;
        } else if DOTNET_TEST_SWITCHES.contains(&head.as_str()) {
            index += 1;
        } else if head == "--project" && next.is_some_and(|value| !value.starts_with('-')) {
            build.push(args[index + 1].clone());
            index += 2;
        } else if is_dotnet_target(arg) {
            build.push(arg.clone());
            index += 1;
        } else {
            covered = false;
            index += 1;
            if next.is_some_and(|value| !value.starts_with('-') && !is_dotnet_target(value)) {
                index += 1;
            }
        }
    }
    Some((build, covered))
}

fn cargo_subcommand_index(command: &[String]) -> Option<usize> {
    command
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, part)| !part.starts_with('+') && !part.starts_with('-'))
        .map(|(index, _)| index)
}

/// `cargo test` with `--no-run` placed before any `--` separator and the
/// harness arguments left off; `None` when the command is compile-only
/// already.
fn cargo_prebuild(command: &[String]) -> Option<Vec<String>> {
    let sub = cargo_subcommand_index(command)?;
    if !command[sub].eq_ignore_ascii_case("test") {
        return None;
    }
    let split = command.iter().position(|part| part == "--").unwrap_or(command.len());
    let head = &command[..split];
    // `--doc` cannot be paired with `--no-run`; the doctests build as they run.
    if head.iter().any(|part| part == "--no-run" || part == "--doc") {
        return None;
    }
    let mut out = head.to_vec();
    out.push("--no-run".to_owned());
    Some(out)
}

/// The native build a compiled test run is preceded by: `dotnet test`
/// gets `dotnet build` with the covered build flags (`--filter` and the
/// other test flags stay off it), and `cargo test` gets `cargo test
/// --no-run`. Build, compile-only, and uncovered commands get no prefix.
pub fn build_before(command: &[String]) -> Option<Vec<String>> {
    match compiled_kind(command)? {
        Compiled::Cargo => cargo_prebuild(command),
        Compiled::MsBuild => dotnet_build_plan(command).and_then(|(build, covered)| covered.then_some(build)),
    }
}

/// The command to run once `build_before` succeeded: `dotnet test` gains
/// `--no-build` only when the build provably covered every argument.
pub fn after_build(command: &[String]) -> Vec<String> {
    match dotnet_build_plan(command) {
        Some((_, true)) => {
            let mut out = command.to_vec();
            out.insert(2, "--no-build".to_owned());
            out
        }
        _ => command.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Full versus Targeted: which explicit commands are the full suite.

const CARGO_NARROWING_FLAGS: [&str; 13] = [
    "-p", "--package", "--exclude", "--test", "--bin", "--example", "--bench", "--lib", "--bins",
    "--tests", "--examples", "--benches", "--doc",
];
const CARGO_VALUE_FLAGS: [&str; 11] = [
    "-j", "--jobs", "--features", "-F", "--target", "--profile", "--color", "--target-dir",
    "--manifest-path", "--message-format", "--config",
];
const HARNESS_VALUE_FLAGS: [&str; 7] = [
    "--test-threads", "--format", "--color", "--logfile", "--report-time", "--shuffle-seed",
    "--ensure-time",
];

/// `--workspace` or `--all` before any `--`: the one explicit way a bare
/// cargo command names the whole workspace. A plain `cargo test` depends on
/// the manifest at hand and is not guessed to be it.
fn cargo_workspace_wide(command: &[String]) -> bool {
    command.iter().take_while(|part| *part != "--").any(|part| part == "--workspace" || part == "--all")
}

fn cargo_narrowed(command: &[String]) -> bool {
    let Some(sub) = cargo_subcommand_index(command) else { return false };
    let split = command.iter().position(|part| part == "--").unwrap_or(command.len());
    let mut index = sub + 1;
    while index < split {
        let part = command[index].as_str();
        let head = part.split('=').next().unwrap_or(part);
        if CARGO_NARROWING_FLAGS.contains(&head) || (part.starts_with("-p") && !part.starts_with("--")) {
            return true;
        }
        if CARGO_VALUE_FLAGS.contains(&part) || part == "-Z" {
            index += 1;
        } else if !part.starts_with('-') {
            return true;
        }
        index += 1;
    }
    let mut index = split + 1;
    while index < command.len() {
        let part = command[index].as_str();
        if part == "--skip" || part == "--ignored" {
            return true;
        }
        if HARNESS_VALUE_FLAGS.contains(&part) || part == "-Z" {
            index += 1;
        } else if !part.starts_with('-') {
            return true;
        }
        index += 1;
    }
    false
}

fn dotnet_full(command: &[String]) -> bool {
    !command.iter().skip(1).any(|part| {
        let folded = part.to_ascii_lowercase();
        let head = folded.split('=').next().unwrap_or(&folded);
        head.starts_with("--filter")
            || head == "--project"
            || (is_dotnet_target(part) && !folded.ends_with(".sln") && !folded.ends_with(".slnx"))
    })
}

/// Whether an explicit command is the Full suite rather than a Targeted
/// check: the declared `test_command`, or a compiled run that names the
/// whole workspace or solution and that no project, package, target or
/// name filter narrows. The full suite never carries
/// the Iteration profile (ADR-0008), so this decides the profile.
pub fn is_full_command(command: &[String], config: &Config) -> bool {
    if config.test_command.as_deref() == Some(command) {
        return true;
    }
    match compiled_kind(command) {
        Some(Compiled::Cargo) => cargo_workspace_wide(command) && !cargo_narrowed(command),
        Some(Compiled::MsBuild) if program_name(command) == "dotnet" => dotnet_full(command),
        Some(Compiled::MsBuild) => command.iter().any(|part| is_dotnet_target(part) && {
            let folded = part.to_ascii_lowercase();
            folded.ends_with(".sln") || folded.ends_with(".slnx")
        }),
        None => false,
    }
}

/// How several affected .NET projects run: a lone project directly, a
/// single root solution as a widening, or a widening to the full suite
/// when no single solution can stand for all of them.
pub enum DotnetPick {
    Project(Vec<String>),
    Solution(Vec<String>, String),
    Widen(String),
}

pub fn dotnet_pick(projects: &[String], root_solutions: &[String]) -> DotnetPick {
    let test = |target: &String| vec!["dotnet".to_owned(), "test".to_owned(), target.clone()];
    match (projects, root_solutions) {
        ([project], _) => DotnetPick::Project(test(project)),
        (_, [solution]) => DotnetPick::Solution(
            test(solution),
            format!("{} projects affected; widened to {solution}", projects.len()),
        ),
        _ => DotnetPick::Widen(format!(
            "{} projects affected and no single root solution; widened to the full suite",
            projects.len()
        )),
    }
}

/// The discovered test files under `root`, skipping build output and
/// vendored trees. `None` when the walk itself fails: selection then
/// widens fail-closed instead of trusting a partial listing.
pub fn discover_tests(root: &Path) -> Option<Vec<String>> {
    let skip = [".git", "target", "node_modules", ".venv", "venv", "__pycache__", ".tox"];
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries {
            let entry = entry.ok()?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            // `file_type` does not follow symlinks: a directory link is
            // never walked, so a cycle or a link out of the tree cannot
            // make the listing endless or foreign.
            let kind = entry.file_type().ok()?;
            if kind.is_dir() {
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

// ---------------------------------------------------------------------------
// Mixed runner families: a selection must never drop an affected family.

/// The distinct runner families an impact selection touches. A `.cs` test
/// belongs to its project's family, not a family of its own.
pub fn selection_families(
    tests: &[String],
    packages: &[String],
    projects: &[String],
    module: Option<&str>,
) -> Vec<&'static str> {
    let mut out: BTreeSet<&'static str> = BTreeSet::new();
    if !packages.is_empty() {
        out.insert("cargo");
    }
    if !projects.is_empty() {
        out.insert("dotnet");
    }
    if module.is_some() {
        out.insert("python");
    }
    for test in tests {
        let folded = test.to_ascii_lowercase();
        let ext = folded.rsplit('.').next().unwrap_or("");
        out.insert(match ext {
            "rs" => "cargo",
            "cs" | "fs" | "vb" => "dotnet",
            "py" => "python",
            "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts" => "node",
            _ => "other",
        });
    }
    out.into_iter().collect()
}

/// What to run when a selection spans several families.
pub enum MixedPlan {
    /// One family: plan it as usual.
    Single,
    /// The declared `test_command` covers them, with the reason.
    Declared(Vec<String>, String),
    /// No declared command can cover them: validation is pending.
    Pending(String),
}

pub fn mixed_plan(families: &[&str], config: &Config) -> MixedPlan {
    if families.len() < 2 {
        return MixedPlan::Single;
    }
    let names = families.join(", ");
    match &config.test_command {
        Some(command) => MixedPlan::Declared(
            command.clone(),
            format!("selection spans several runner families ({names}); widened to the declared test_command"),
        ),
        None => MixedPlan::Pending(format!(
            "selection spans several runner families ({names}) and no test_command is declared"
        )),
    }
}

// ---------------------------------------------------------------------------
// Python runner resolution

/// Interpreters to try, best first: the active or repository virtualenv,
/// then `python3`, then `python`.
pub fn python_candidates(root: &Path) -> Vec<String> {
    let mut envs: Vec<PathBuf> = Vec::new();
    if let Some(active) = std::env::var_os("VIRTUAL_ENV") {
        envs.push(PathBuf::from(active));
    }
    envs.push(root.join(".venv"));
    envs.push(root.join("venv"));
    let mut out: Vec<String> = Vec::new();
    for env in envs {
        for rel in ["bin/python", "Scripts/python.exe"] {
            let path = env.join(rel);
            if path.is_file() {
                out.push(path.to_string_lossy().into_owned());
            }
        }
    }
    out.push("python3".to_owned());
    out.push("python".to_owned());
    out
}

fn python_run(python: &str, pytest: bool) -> Vec<String> {
    let runner = if pytest { vec!["pytest", "-q"] } else { vec!["unittest"] };
    ["-m"].into_iter().chain(runner).fold(vec![python.to_owned()], |mut out, part| {
        out.push(part.to_owned());
        out
    })
}

/// The full-suite command for a Python project.
pub fn python_full(python: &str, pytest: bool, has_tests_dir: bool) -> Vec<String> {
    let mut command = python_run(python, pytest);
    if !pytest {
        command.extend(["discover", "-s", if has_tests_dir { "tests" } else { "." }].map(str::to_owned));
    }
    command
}

/// A module selection: pytest over the module directory, or unittest
/// discovery there when pytest is not installed.
pub fn python_module(python: &str, pytest: bool, module: &str) -> Vec<String> {
    let mut command = python_run(python, pytest);
    if !pytest {
        command.extend(["discover", "-s"].map(str::to_owned));
    }
    command.push(module.to_owned());
    command
}

/// The targeted command for test files: pytest when installed, else
/// unittest over the files' module names (ADR-0001's runner-agnostic
/// posture).
pub fn python_targeted(python: &str, pytest: bool, tests: &[String]) -> Vec<String> {
    let mut command = python_run(python, pytest);
    for test in tests {
        command.push(if pytest {
            test.clone()
        } else {
            test.trim_end_matches(".py").replace('/', ".").trim_end_matches(".__init__").to_owned()
        });
    }
    command
}

// ---------------------------------------------------------------------------
// Non-git store (ADR-0010): per user, per root, private.

/// `<base>/check-stores/<sha256 of root>` for a tree with no git dir,
/// created owner-only. Every directory on the path must be a real
/// directory owned by this user with no group or world access; a symlink
/// or a shared directory is refused rather than trusted.
pub fn private_store_dir(base: &Path, root: &Path) -> Result<PathBuf, String> {
    let digest = crate::store::sha256_hex(root.to_string_lossy().as_bytes());
    let stores = base.join("check-stores");
    let store = stores.join(digest);
    for dir in [base, stores.as_path(), store.as_path()] {
        crate::store::ensure_private_dir(dir)?;
    }
    Ok(store)
}

// ---------------------------------------------------------------------------
// Task delta and Integration delta (GLOSSARY), inferred statelessly from
// git: the working tree and the branch's own commits are the Task delta;
// what an identifiable merge of the base brought in is the Integration
// delta. Base commits the branch has not merged are drift, not
// integration. Anything the history cannot attribute widens.

fn git_out(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git").arg("-C").arg(root).args(args).output().ok()?;
    out.status.success().then_some(out.stdout)
}

/// Trimmed stdout of a successful git command.
pub fn git_text(root: &Path, args: &[&str]) -> Option<String> {
    git_out(root, args).map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEntry {
    pub x: char,
    pub y: char,
    pub path: String,
    /// The old path of a rename or copy.
    pub from: Option<String>,
}

/// `git status --porcelain=v1 -z`: `XY path\0`, and `XY new\0old\0` for a
/// rename or copy. NUL-separated, so spaces, quotes and non-ASCII names
/// arrive verbatim.
pub fn parse_status_z(raw: &[u8]) -> Vec<StatusEntry> {
    let mut fields = raw.split(|byte| *byte == 0).filter(|field| !field.is_empty());
    let mut out = Vec::new();
    while let Some(field) = fields.next() {
        if field.len() < 4 {
            continue;
        }
        let (x, y) = (field[0] as char, field[1] as char);
        let from = if matches!(x, 'R' | 'C') || matches!(y, 'R' | 'C') {
            fields.next().map(lossy)
        } else {
            None
        };
        out.push(StatusEntry { x, y, path: lossy(&field[3..]), from });
    }
    out
}

fn is_unmerged(entry: &StatusEntry) -> bool {
    entry.x == 'U' || entry.y == 'U' || (entry.x, entry.y) == ('A', 'A') || (entry.x, entry.y) == ('D', 'D')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChange {
    pub status: char,
    pub path: String,
    pub from: Option<String>,
}

/// `git diff --name-status -z`: `S\0path\0`, and `Rnn\0old\0new\0` for a
/// rename or copy.
pub fn parse_name_status_z(raw: &[u8]) -> Vec<PathChange> {
    let mut fields = raw.split(|byte| *byte == 0).filter(|field| !field.is_empty());
    let mut out = Vec::new();
    while let Some(status) = fields.next() {
        let letter = status[0] as char;
        if matches!(letter, 'R' | 'C') {
            let (Some(old), Some(new)) = (fields.next(), fields.next()) else { break };
            out.push(PathChange { status: letter, path: lossy(new), from: Some(lossy(old)) });
        } else {
            let Some(path) = fields.next() else { break };
            out.push(PathChange { status: letter, path: lossy(path), from: None });
        }
    }
    out
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Deltas {
    pub task: Vec<String>,
    pub integration: Vec<String>,
    /// Paths either delta removed from the tree.
    pub deleted: Vec<String>,
    /// Why the selection must widen to the full suite; empty when the
    /// attribution is certain.
    pub widen: Vec<String>,
    /// The immutable state the attribution depends on: resolved base
    /// commit, fork point, and HEAD. `None` when it could not be resolved.
    pub key: Option<String>,
}

const MERGE_CAP: usize = 32;
const PROVENANCE_MARKERS: [&str; 5] =
    ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"];

fn absorb(raw: Option<Vec<u8>>, into: &mut BTreeSet<String>, deleted: &mut BTreeSet<String>) -> bool {
    let Some(raw) = raw else { return false };
    for change in parse_name_status_z(&raw) {
        into.extend(change.from);
        if change.status == 'D' {
            deleted.insert(change.path.clone());
        }
        into.insert(change.path);
    }
    true
}

fn is_ancestor(root: &Path, commit: &str, of: &str) -> Option<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["merge-base", "--is-ancestor", commit, of])
        .output()
        .ok()?
        .status
        .code()?;
    match status {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

pub fn compute_deltas(root: &Path, base: Option<&str>) -> Deltas {
    let mut task = BTreeSet::new();
    let mut integration = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    let mut widen: Vec<String> = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();

    match git_out(root, &["status", "--porcelain=v1", "-z", "--untracked-files=all"]) {
        Some(raw) => {
            for entry in parse_status_z(&raw) {
                if is_unmerged(&entry) {
                    conflicts.push(entry.path.clone());
                } else if entry.x == 'D' || entry.y == 'D' {
                    deleted.insert(entry.path.clone());
                }
                task.extend(entry.from);
                task.insert(entry.path);
            }
        }
        None => widen.push("working-tree status unavailable; widened to the full suite".to_owned()),
    }
    if !conflicts.is_empty() {
        widen.push(format!("unresolved conflicts in {}; widened to the full suite", conflicts.join(", ")));
    }
    if let Some(git_dir) = git_text(root, &["rev-parse", "--absolute-git-dir"]) {
        for marker in PROVENANCE_MARKERS {
            if Path::new(&git_dir).join(marker).exists() {
                widen.push(format!("{marker} present: a merge, rebase, or pick is in progress; widened to the full suite"));
            }
        }
    }

    let mut key = None;
    match base {
        None => widen.push("integration delta unavailable: no base ref could be resolved; widened to the full suite".to_owned()),
        Some(name) => {
            let unavailable = |why: String| format!("integration delta unavailable: {why}; widened to the full suite");
            let resolve = |spec: String| git_text(root, &["rev-parse", "--verify", "--quiet", &spec]);
            let base_sha = resolve(format!("{name}^{{commit}}"));
            let head_sha = resolve("HEAD^{commit}".to_owned());
            match (base_sha, head_sha) {
                (None, _) => widen.push(unavailable(format!("base {name} could not be resolved"))),
                (_, None) => widen.push(unavailable("HEAD could not be resolved".to_owned())),
                (Some(base_sha), Some(head_sha)) => {
                    match git_text(root, &["merge-base", &head_sha, &base_sha]) {
                        None => widen.push(unavailable(format!("no merge base between HEAD and {name}"))),
                        Some(fork) => {
                            key = Some(format!("{name}={base_sha};fork={fork};head={head_sha}"));
                            let committed = git_out(
                                root,
                                &["diff", "--name-status", "-z", "--find-renames", "--no-ext-diff", &fork, &head_sha],
                            );
                            if !absorb(committed, &mut task, &mut deleted) {
                                widen.push(unavailable("the branch's commits could not be listed".to_owned()));
                            }
                            attribute_base_merges(
                                root,
                                &base_sha,
                                &head_sha,
                                &mut integration,
                                &mut deleted,
                                &mut widen,
                            );
                        }
                    }
                }
            }
        }
    }
    deleted.retain(|path| !root.join(path).exists());
    for path in &task {
        integration.remove(path);
    }
    Deltas {
        task: task.into_iter().collect(),
        integration: integration.into_iter().collect(),
        deleted: deleted.into_iter().collect(),
        widen,
        key,
    }
}

/// The Integration delta: for each merge the branch holds whose second
/// parent the base already contains, what that parent changed since it
/// forked from the branch side. Edits made while resolving the merge are
/// already in the branch-versus-fork diff, so they stay Task delta.
fn attribute_base_merges(
    root: &Path,
    base: &str,
    head: &str,
    integration: &mut BTreeSet<String>,
    deleted: &mut BTreeSet<String>,
    widen: &mut Vec<String>,
) {
    let uncertain = |why: String| format!("integration delta unavailable: {why}; widened to the full suite");
    let Some(listing) = git_text(root, &["rev-list", "--merges", "--parents", &format!("{base}..{head}")]) else {
        widen.push(uncertain("the branch's merges could not be listed".to_owned()));
        return;
    };
    let merges: Vec<Vec<&str>> = listing.lines().map(|line| line.split(' ').collect()).collect();
    if merges.len() > MERGE_CAP {
        widen.push(uncertain(format!("{} merges are too many to attribute", merges.len())));
        return;
    }
    for merge in merges {
        let short = &merge[0][..merge[0].len().min(12)];
        let [_, first, second] = merge[..] else {
            widen.push(uncertain(format!("merge {short} has an unsupported parent count")));
            continue;
        };
        match is_ancestor(root, second, base) {
            Some(true) => {}
            Some(false) => continue,
            None => {
                widen.push(uncertain(format!("merge {short} could not be attributed")));
                continue;
            }
        }
        let incoming = git_text(root, &["merge-base", first, second]).and_then(|fork| {
            git_out(
                root,
                &["diff", "--name-status", "-z", "--find-renames", "--no-ext-diff", &fork, second],
            )
        });
        if !absorb(incoming, integration, deleted) {
            widen.push(uncertain(format!("merge {short} could not be attributed")));
        }
    }
}

impl Deltas {
    /// Deleted paths that are test files: a removed test cannot be
    /// selected, so the check widens to the full suite.
    pub fn deleted_tests(&self) -> Vec<&String> {
        self.deleted.iter().filter(|path| is_test_file(path)).collect()
    }
}

/// A test file by the shared classifier or a runner's extra naming rule.
pub fn is_test_file(name: &str) -> bool {
    if crate::classify::is_test_path(name) {
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
    /// The base ref the Integration delta was computed against; a cache
    /// entry is only valid for the base it names.
    #[serde(default)]
    pub base: String,
    pub task_delta: Vec<String>,
    pub integration_delta: Vec<String>,
    pub impact: serde_json::Value,
}

pub fn scan_cache_read(path: &Path, fingerprint: &str, base: &str) -> Option<ScanEntry> {
    let text = std::fs::read_to_string(path).ok()?;
    let entry: ScanEntry = serde_json::from_str(&text).ok()?;
    (entry.fingerprint == fingerprint && entry.base == base).then_some(entry)
}

pub fn scan_cache_write(path: &Path, entry: &ScanEntry) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string(entry).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// The Check slot (ADR-0004): one host-wide turn for compiled check runs.
// This is the core receipt store's slot itself — same lock file, same
// holder metadata, same poll and timeout — acquired through
// `store::acquire_slot`, so a gate compiled run and a `prometheus-check`
// compiled run wait for each other (GLOSSARY: Check slot). The default
// directory is the gate's: beside every session directory, resolved
// exactly as the Python runtime's `record_path` resolves it.

/// The directory holding the host-wide Check slot: `$XDG_RUNTIME_DIR/
/// prometheus` when that dir is absolute, a directory, and owned by this
/// user; else `<temp>/prometheus-<uid>` on POSIX, `<temp>/prometheus`
/// elsewhere — the Python runtime's rule, so both routes name one slot.
pub fn host_slot_dir() -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            let path = PathBuf::from(&runtime);
            if path.is_absolute() {
                if let Ok(meta) = std::fs::metadata(&path) {
                    if meta.is_dir() && meta.uid() == unsafe { libc::getuid() } {
                        return path.join("prometheus");
                    }
                }
            }
        }
        let uid = unsafe { libc::getuid() };
        return std::env::temp_dir().join(format!("prometheus-{uid}"));
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("prometheus")
    }
}

pub struct Slot {
    token: u64,
    pub waited: Duration,
}

impl Drop for Slot {
    fn drop(&mut self) {
        crate::store::release_slot(self.token);
    }
}

#[derive(Debug)]
pub struct SlotTimeout {
    pub waited: Duration,
    pub holder: String,
    /// Set when the slot could not be used at all (unsafe or unwritable
    /// directory, bad lock file) as opposed to being held by another run.
    pub unavailable: Option<String>,
}

/// Acquire the Check slot in `dir` (the gate's directory, or an explicit
/// override a test or embedder names).
pub fn acquire_slot_in(
    dir: &Path,
    command: &[String],
    timeout: Duration,
) -> Result<Slot, SlotTimeout> {
    let lock_path = dir.join("check-slot.lock");
    let meta_path = dir.join("check-slot.json");
    match crate::store::acquire_slot(
        &lock_path,
        &meta_path,
        "",
        "prometheus-check",
        command,
        timeout.as_secs_f64(),
    ) {
        crate::store::SlotOutcome::Acquired(token, waited) => {
            Ok(Slot { token, waited: Duration::from_secs_f64(waited) })
        }
        crate::store::SlotOutcome::Timeout(waited, meta) => Err(SlotTimeout {
            waited: Duration::from_secs_f64(waited),
            holder: String::from_utf8_lossy(&meta).trim().to_owned(),
            unavailable: None,
        }),
        crate::store::SlotOutcome::Unavailable(why) => Err(SlotTimeout {
            waited: Duration::ZERO,
            holder: String::new(),
            unavailable: Some(why),
        }),
    }
}

// ---------------------------------------------------------------------------
// Change class (GLOSSARY), over path names only: docs-only and tests-only
// are name-decidable; anything else is a Logic change. Comment-only needs
// line content and is the scan's call, not this one's.

const DOC_DIRS: [&str; 3] = ["docs", "doc", "documentation"];
const DOC_STEMS: [&str; 12] = [
    "readme", "notes", "changelog", "changes", "history", "license", "authors", "contributing",
    "notice", "todo", "install", "news",
];

/// The shared classifier's verdict, narrowed for `.txt`: a text file can
/// be runtime data (`include_str!`), so it is documentation only inside a
/// docs folder or under a recognized documentation name.
fn is_docs_only_name(name: &str) -> bool {
    if !crate::classify::is_doc_path(name) {
        return false;
    }
    let folded = name.replace('\\', "/").to_ascii_lowercase();
    let Some(stem) = folded.rsplit('/').next().and_then(|base| base.strip_suffix(".txt")) else {
        return true;
    };
    let mut dirs = folded.split('/').collect::<Vec<_>>();
    dirs.pop();
    dirs.iter().any(|dir| DOC_DIRS.contains(dir)) || DOC_STEMS.contains(&stem)
}

pub fn change_class(changed: &[String]) -> &'static str {
    if changed.is_empty() {
        return "none";
    }
    if changed.iter().all(|name| is_docs_only_name(name)) {
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
    fn cargo_prebuild_stops_before_the_harness_separator() {
        assert_eq!(
            build_before(&argv(&["cargo", "test", "-p", "core", "--", "--nocapture", "name"])),
            Some(argv(&["cargo", "test", "-p", "core", "--no-run"]))
        );
        assert_eq!(build_before(&argv(&["cargo", "test", "--no-run"])), None);
        assert_eq!(build_before(&argv(&["cargo", "test", "--no-run", "--", "x"])), None);
    }

    #[test]
    fn dotnet_prebuild_forwards_build_flags_and_fails_closed() {
        assert_eq!(build_before(&argv(&["dotnet", "test", "--no-build"])), None);
        assert_eq!(
            build_before(&argv(&[
                "dotnet", "test", "a.sln", "-l", "trx", "-v", "q", "--blame", "--filter=X",
                "-p:A=1", "-c", "Release", "--no-restore"
            ])),
            Some(argv(&["dotnet", "build", "a.sln", "-p:A=1", "-c", "Release", "--no-restore"]))
        );
        assert_eq!(build_before(&argv(&["dotnet", "test", "a.csproj", "--surprise", "x"])), None);
        assert_eq!(build_before(&argv(&["dotnet", "test", "a.csproj", "-p", "A"])), None);
    }

    #[test]
    fn no_build_follows_only_a_covered_split() {
        assert_eq!(
            after_build(&argv(&["dotnet", "test", "a.csproj", "--filter", "X"])),
            argv(&["dotnet", "test", "--no-build", "a.csproj", "--filter", "X"])
        );
        let unknown = argv(&["dotnet", "test", "a.csproj", "--surprise"]);
        assert_eq!(after_build(&unknown), unknown);
        let cargo = argv(&["cargo", "test"]);
        assert_eq!(after_build(&cargo), cargo);
    }

    #[test]
    fn timeouts_are_finite_and_bounded() {
        assert_eq!(parse_timeout("600"), Some(600.0));
        assert_eq!(parse_timeout("0"), Some(0.0));
        assert_eq!(parse_timeout("31536000"), Some(31_536_000.0));
        for bad in ["-1", "nan", "inf", "-inf", "1e999", "31536001", "abc", ""] {
            assert_eq!(parse_timeout(bad), None, "{bad}");
        }
    }

    #[test]
    fn zero_test_success_keeps_no_receipt() {
        let zero = Some(Counts { passed: 0, failed: 0, skipped: 0, total: 0 });
        let one = Some(Counts { passed: 1, failed: 0, skipped: 0, total: 1 });
        assert!(!receipt_kept(0, zero, true));
        assert!(receipt_kept(0, one, true));
        assert!(!receipt_kept(0, one, false));
        assert!(!receipt_kept(1, one, true));
        assert!(receipt_kept(0, None, true));
    }

    #[test]
    fn full_command_is_not_claimed_for_narrowed_runs() {
        let none = Config::default();
        let full = |parts: &[&str]| is_full_command(&argv(parts), &none);
        assert!(full(&["cargo", "test", "--workspace"]));
        assert!(full(&["cargo", "test", "--workspace", "--", "--nocapture"]));
        assert!(!full(&["cargo", "test", "--workspace", "-p", "core"]));
        assert!(!full(&["cargo", "test", "--workspace", "--lib"]));
        assert!(!full(&["cargo", "test", "name_filter"]));
        assert!(!full(&["cargo", "test", "--", "name_filter"]));
        assert!(full(&["cargo", "test", "--all", "-j", "4", "--features", "x"]));
        assert!(!full(&["cargo", "test"]));
        assert!(!full(&["cargo", "test", "-j", "4", "--features", "x"]));
        assert!(full(&["dotnet", "test", "a.sln"]));
        assert!(!full(&["dotnet", "test", "a.sln", "--filter", "X"]));
        assert!(!full(&["dotnet", "test", "a.sln", "--filter=X"]));
        assert!(!full(&["dotnet", "test", "a.csproj"]));
        assert!(full(&["dotnet", "test"]));
        let declared = Config { test_command: Some(argv(&["pytest", "-q"])), ..Config::default() };
        assert!(is_full_command(&argv(&["pytest", "-q"]), &declared));
        assert!(!is_full_command(&argv(&["pytest", "-q", "tests/a.py"]), &declared));
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
            base: "main".into(),
            task_delta: argv(&["a.py"]),
            integration_delta: vec![],
            impact: serde_json::json!({"selection": {"level": "targeted"}}),
        };
        scan_cache_write(&path, &entry).unwrap();
        assert!(scan_cache_read(&path, "abc", "main").is_some());
        assert!(scan_cache_read(&path, "other", "main").is_none());
        assert!(scan_cache_read(&path, "abc", "develop").is_none(),
                "a cache entry is only valid for the base it names");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn slot_is_exclusive_until_released() {
        let dir = std::env::temp_dir().join(format!("prometheus-check-slot-{}", std::process::id()));
        let first = acquire_slot_in(&dir, &argv(&["cargo", "test"]), Duration::from_secs(5)).unwrap();
        let blocked = acquire_slot_in(&dir, &argv(&["cargo", "test"]), Duration::from_millis(60));
        assert!(blocked.is_err());
        drop(first);
        assert!(acquire_slot_in(&dir, &argv(&["cargo", "test"]), Duration::from_secs(5)).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn change_class_names_docs_and_tests() {
        assert_eq!(change_class(&argv(&["README.md", "docs/x.md"])), "docs-only");
        assert_eq!(change_class(&argv(&["tests/test_a.py"])), "tests-only");
        assert_eq!(change_class(&argv(&["src/a.py"])), "logic");
        assert_eq!(change_class(&argv(&[])), "none");
        for logic in [
            "requirements.txt",
            "CMakeLists.txt",
            "docs/conf.py",
            "tests/fixtures/data.txt",
            "docs/Makefile",
        ] {
            assert_ne!(change_class(&argv(&[logic])), "docs-only", "{logic}");
        }
        assert_eq!(change_class(&argv(&["docs/guide.rst", "NOTES.txt"])), "docs-only");
    }

    // -- deltas, against real throwaway repositories --------------------------

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir = std::env::temp_dir()
                .join(format!("prometheus-check-{name}-{}-{}", std::process::id(), name.len()));
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

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .args(["-c", "core.autocrlf=false", "-c", "init.defaultBranch=main"])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn write(dir: &Path, name: &str, text: &str) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn commit(dir: &Path, name: &str, text: &str) {
        write(dir, name, text);
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-qm", name]);
    }

    fn repo(name: &str) -> TempDir {
        let temp = TempDir::new(name);
        git(&temp.0, &["init", "-q", "-b", "main"]);
        commit(&temp.0, "a.py", "a = 1\n");
        commit(&temp.0, "b.py", "b = 1\n");
        commit(&temp.0, "tests/test_a.py", "x = 1\n");
        temp
    }

    #[test]
    fn status_and_diff_parsers_keep_both_rename_paths() {
        let status = parse_status_z(b"R  new name \xc3\xb1.py\0old name.py\0 M a.py\0?? \"q\".py\0");
        assert_eq!(status.len(), 3);
        assert_eq!(status[0].path, "new name \u{f1}.py");
        assert_eq!(status[0].from.as_deref(), Some("old name.py"));
        assert_eq!(status[2].path, "\"q\".py");
        let diff = parse_name_status_z(b"R087\0old.py\0new.py\0D\0gone.py\0M\0m.py\0");
        assert_eq!(diff.len(), 3);
        assert_eq!(diff[0].from.as_deref(), Some("old.py"));
        assert_eq!(diff[1].status, 'D');
    }

    #[test]
    fn dirty_renames_with_spaces_and_non_ascii_keep_old_and_new() {
        let temp = repo("dirty");
        let dir = &temp.0;
        commit(dir, "src/old name.py", "o = 1\n");
        git(dir, &["mv", "src/old name.py", "src/nuevo \u{f1}.py"]);
        write(dir, "docs/\u{e9}.md", "new\n");
        let deltas = compute_deltas(dir, Some("main"));
        assert!(deltas.widen.is_empty(), "{:?}", deltas.widen);
        for path in ["src/old name.py", "src/nuevo \u{f1}.py", "docs/\u{e9}.md"] {
            assert!(deltas.task.iter().any(|name| name == path), "{path}: {:?}", deltas.task);
        }
        assert!(deltas.integration.is_empty());
    }

    #[test]
    fn committed_branch_work_is_task_not_integration() {
        let temp = repo("branch");
        let dir = &temp.0;
        git(dir, &["checkout", "-q", "-b", "feat"]);
        commit(dir, "feat.py", "f = 1\n");
        git(dir, &["mv", "a.py", "a2.py"]);
        git(dir, &["commit", "-qam", "rename"]);
        let deltas = compute_deltas(dir, Some("main"));
        assert_eq!(deltas.task, vec!["a.py", "a2.py", "feat.py"]);
        assert!(deltas.integration.is_empty());
        assert!(deltas.widen.is_empty(), "{:?}", deltas.widen);
    }

    #[test]
    fn base_merge_is_integration_and_unmerged_drift_is_not() {
        let temp = repo("merge");
        let dir = &temp.0;
        git(dir, &["checkout", "-q", "-b", "feat"]);
        commit(dir, "feat.py", "f = 1\n");
        git(dir, &["checkout", "-q", "main"]);
        commit(dir, "m.py", "m = 1\n");
        commit(dir, "b.py", "b = 2\n");
        git(dir, &["checkout", "-q", "feat"]);
        git(dir, &["merge", "-q", "--no-edit", "main"]);
        let merged = compute_deltas(dir, Some("main"));
        assert!(merged.widen.is_empty(), "{:?}", merged.widen);
        assert_eq!(merged.task, vec!["feat.py"]);
        assert_eq!(merged.integration, vec!["b.py", "m.py"]);
        git(dir, &["checkout", "-q", "main"]);
        commit(dir, "drift.py", "d = 1\n");
        git(dir, &["checkout", "-q", "feat"]);
        let drifted = compute_deltas(dir, Some("main"));
        assert_eq!(drifted.integration, vec!["b.py", "m.py"], "unmerged drift is not integration");
        assert_eq!(drifted.task, vec!["feat.py"]);
        assert_ne!(merged.key, drifted.key, "a moved base must invalidate the cache key");
        assert!(merged.key.is_some());
    }

    #[test]
    fn merge_resolution_edits_stay_task_work() {
        let temp = repo("resolve");
        let dir = &temp.0;
        git(dir, &["checkout", "-q", "-b", "feat"]);
        commit(dir, "a.py", "a = 'feat'\n");
        git(dir, &["checkout", "-q", "main"]);
        commit(dir, "a.py", "a = 'main'\n");
        commit(dir, "m.py", "m = 1\n");
        git(dir, &["checkout", "-q", "feat"]);
        git(dir, &["merge", "-q", "main"]);
        let conflicted = compute_deltas(dir, Some("main"));
        assert!(conflicted.widen.iter().any(|reason| reason.contains("unresolved conflicts")));
        assert!(conflicted.widen.iter().any(|reason| reason.contains("MERGE_HEAD")));
        commit(dir, "a.py", "a = 'both'\n");
        let resolved = compute_deltas(dir, Some("main"));
        assert!(resolved.widen.is_empty(), "{:?}", resolved.widen);
        assert_eq!(resolved.task, vec!["a.py"]);
        assert_eq!(resolved.integration, vec!["m.py"]);
    }

    #[test]
    fn deleted_tests_are_reported_for_widening() {
        let temp = repo("deleted");
        let dir = &temp.0;
        git(dir, &["checkout", "-q", "-b", "feat"]);
        git(dir, &["rm", "-q", "tests/test_a.py"]);
        git(dir, &["commit", "-qm", "drop test"]);
        git(dir, &["rm", "-q", "-f", "a.py"]);
        let deltas = compute_deltas(dir, Some("main"));
        assert_eq!(deltas.deleted, vec!["a.py", "tests/test_a.py"]);
        assert_eq!(deltas.deleted_tests(), vec!["tests/test_a.py"]);
    }

    #[test]
    fn unresolved_base_widens_without_a_cache_key() {
        let temp = repo("nobase");
        let missing = compute_deltas(&temp.0, Some("nope"));
        assert!(missing.widen.iter().any(|reason| reason.contains("integration delta unavailable")));
        assert!(missing.key.is_none());
        let none = compute_deltas(&temp.0, None);
        assert!(none.widen.iter().any(|reason| reason.contains("no base ref")));
    }

    #[test]
    fn scan_cache_key_includes_base_state() {
        let dir = TempDir::new("cachekey");
        let path = dir.0.join("scan-cache.json");
        let entry = ScanEntry {
            fingerprint: "abc".into(),
            base: "main=1;fork=2;head=3".into(),
            task_delta: vec![],
            integration_delta: vec![],
            impact: serde_json::Value::Null,
        };
        scan_cache_write(&path, &entry).unwrap();
        assert!(scan_cache_read(&path, "abc", "main=1;fork=2;head=3").is_some());
        assert!(scan_cache_read(&path, "abc", "main=9;fork=2;head=3").is_none());
    }

    #[test]
    fn dotnet_projects_use_one_solution_or_widen() {
        let one = argv(&["a.csproj"]);
        let two = argv(&["a.csproj", "b.csproj"]);
        assert!(matches!(dotnet_pick(&one, &[]), DotnetPick::Project(cmd) if cmd == argv(&["dotnet", "test", "a.csproj"])));
        assert!(matches!(dotnet_pick(&two, &argv(&["all.sln"])), DotnetPick::Solution(cmd, _) if cmd == argv(&["dotnet", "test", "all.sln"])));
        assert!(matches!(dotnet_pick(&two, &argv(&["x.sln", "y.sln"])), DotnetPick::Widen(_)));
        assert!(matches!(dotnet_pick(&two, &[]), DotnetPick::Widen(_)));
    }

    #[test]
    fn python_commands_fall_back_to_unittest() {
        assert_eq!(
            python_module("py", true, "tests/pkg"),
            argv(&["py", "-m", "pytest", "-q", "tests/pkg"])
        );
        assert_eq!(
            python_module("py", false, "tests/pkg"),
            argv(&["py", "-m", "unittest", "discover", "-s", "tests/pkg"])
        );
        assert_eq!(
            python_targeted("py", false, &argv(&["tests/test_a.py"])),
            argv(&["py", "-m", "unittest", "tests.test_a"])
        );
        assert_eq!(python_full("py", false, true), argv(&["py", "-m", "unittest", "discover", "-s", "tests"]));
        let dir = TempDir::new("venv");
        write(&dir.0, ".venv/bin/python", "");
        let found = python_candidates(&dir.0);
        // Candidates are built by joining path components, so on Windows
        // the same file is spelled with '\\' where this expectation uses
        // '/': compare separator-normalized, as the filesystem does.
        let norm = |name: &str| name.replace('\\', "/");
        let venv = norm(&dir.0.join(".venv/bin/python").to_string_lossy());
        let at = found
            .iter()
            .position(|name| norm(name) == venv)
            .expect("venv interpreter listed");
        assert!(at < found.iter().position(|name| name == "python3").unwrap());
        assert_eq!(found.last().map(String::as_str), Some("python"));
    }

    #[cfg(unix)]
    #[test]
    fn non_git_store_is_private_and_refuses_symlinks_and_shared_dirs() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let temp = TempDir::new("store");
        let base = temp.0.join("prometheus-test");
        let root = temp.0.join("tree");
        let store = private_store_dir(&base, &root).unwrap();
        assert!(store.starts_with(base.join("check-stores")));
        assert_eq!(std::fs::metadata(&store).unwrap().mode() & 0o777, 0o700);
        assert_eq!(private_store_dir(&base, &root).unwrap(), store);
        assert_ne!(private_store_dir(&base, &temp.0.join("other")).unwrap(), store);

        let shared = temp.0.join("shared");
        std::fs::create_dir(&shared).unwrap();
        let linked = temp.0.join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&shared, linked.join("check-stores")).unwrap();
        assert!(private_store_dir(&linked, &root).unwrap_err().contains("symlink"));

        let open = temp.0.join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_store_dir(&open, &root).unwrap_err().contains("accessible"));
    }

    #[test]
    fn an_invalid_timeout_env_falls_back_to_the_default() {
        assert_eq!(timeout_from_env(None), 600.0);
        assert_eq!(timeout_from_env(Some("30")), 30.0);
        for bad in ["-1", "NaN", "inf", "1e100", "abc"] {
            assert_eq!(timeout_from_env(Some(bad)), 600.0, "{bad}");
        }
    }

    #[test]
    fn dotnet_absolute_targets_are_not_slash_flags() {
        assert_eq!(
            build_before(&argv(&["dotnet", "test", "/tmp/x.csproj", "/p:A=1", "/m:2"])),
            Some(argv(&["dotnet", "build", "/tmp/x.csproj", "/p:A=1", "/m:2"]))
        );
        assert_eq!(build_before(&argv(&["dotnet", "test", "/p:Project=/a/b.csproj"])), Some(argv(&["dotnet", "build", "/p:Project=/a/b.csproj"])));
        let none = Config::default();
        assert!(!is_full_command(&argv(&["dotnet", "test", "/tmp/x.csproj"]), &none));
        assert!(is_full_command(&argv(&["dotnet", "test", "/tmp/x.sln"]), &none));
    }

    #[test]
    fn dotnet_settings_diag_alias_and_property_spellings() {
        assert_eq!(
            build_before(&argv(&[
                "dotnet", "test", "a.csproj", "--settings", "r.runsettings", "-s", "r2", "-d", "log.txt",
                "-property:A=1"
            ])),
            Some(argv(&["dotnet", "build", "a.csproj", "-property:A=1"]))
        );
        assert_eq!(
            build_before(&argv(&["dotnet", "test", "a.csproj", "-property", "A=1"])),
            Some(argv(&["dotnet", "build", "a.csproj", "-property", "A=1"]))
        );
    }

    #[test]
    fn no_build_is_looked_for_only_before_the_separator() {
        let command = argv(&["dotnet", "test", "a.csproj", "--", "RunConfiguration.X=1", "--no-build", "--bogus"]);
        assert_eq!(build_before(&command), Some(argv(&["dotnet", "build", "a.csproj"])));
        assert_eq!(
            after_build(&command),
            argv(&["dotnet", "test", "--no-build", "a.csproj", "--", "RunConfiguration.X=1", "--no-build", "--bogus"])
        );
        assert_eq!(build_before(&argv(&["dotnet", "test", "--no-build", "a.csproj"])), None);
    }

    #[test]
    fn cargo_doctests_get_no_prebuild() {
        assert_eq!(build_before(&argv(&["cargo", "test", "--doc"])), None);
        assert_eq!(build_before(&argv(&["cargo", "test", "-p", "core", "--doc", "--", "name"])), None);
        assert_eq!(
            build_before(&argv(&["cargo", "test", "--", "--doc"])),
            Some(argv(&["cargo", "test", "--no-run"]))
        );
    }

    #[test]
    fn txt_is_docs_only_just_in_docs_or_named_docs() {
        for docs in ["docs/guide.txt", "README.txt", "docs/a/notes.txt", "CHANGELOG.txt", "pkg/NOTES.txt"] {
            assert_eq!(change_class(&argv(&[docs])), "docs-only", "{docs}");
        }
        for runtime in ["src/wordlist.txt", "customfolder/fixture.txt", "data.txt", "requirements.txt"] {
            assert_ne!(change_class(&argv(&[runtime])), "docs-only", "{runtime}");
        }
        assert_eq!(change_class(&argv(&["docs/a.md", "src/wordlist.txt"])), "logic");
    }

    #[test]
    fn discovery_skips_symlinked_dirs_and_keeps_bin_obj_tests() {
        let temp = TempDir::new("discover");
        let root = &temp.0;
        write(root, "tests/bin/test_x.py", "");
        write(root, "src/obj/test_y.py", "");
        write(root, "node_modules/test_skip.py", "");
        let outside = TempDir::new("discover-outside");
        write(&outside.0, "test_out.py", "");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root, root.join("loop")).unwrap();
            std::os::unix::fs::symlink(&outside.0, root.join("tests/link")).unwrap();
        }
        assert_eq!(
            discover_tests(root),
            Some(vec!["src/obj/test_y.py".to_owned(), "tests/bin/test_x.py".to_owned()])
        );
        assert_eq!(discover_tests(&root.join("missing")), None);
    }

    #[test]
    fn selection_families_do_not_double_count_dotnet_tests() {
        let none: Vec<String> = vec![];
        assert_eq!(selection_families(&argv(&["T.cs"]), &none, &argv(&["a.csproj"]), None), vec!["dotnet"]);
        assert_eq!(
            selection_families(&argv(&["tests/test_a.py"]), &argv(&["core"]), &argv(&["a.csproj"]), None),
            vec!["cargo", "dotnet", "python"]
        );
        assert_eq!(selection_families(&none, &none, &none, Some("tests/pkg")), vec!["python"]);
        assert_eq!(selection_families(&argv(&["a.go", "t.py"]), &none, &none, None), vec!["other", "python"]);
    }

    #[test]
    fn mixed_families_use_the_declared_command_or_stay_pending() {
        let declared = Config { test_command: Some(argv(&["make", "test"])), ..Config::default() };
        assert!(matches!(mixed_plan(&["python"], &declared), MixedPlan::Single));
        assert!(matches!(
            mixed_plan(&["cargo", "python"], &declared),
            MixedPlan::Declared(command, reason) if command == argv(&["make", "test"]) && reason.contains("cargo, python")
        ));
        assert!(matches!(mixed_plan(&["cargo", "dotnet"], &Config::default()), MixedPlan::Pending(_)));
    }

    #[cfg(unix)]
    #[test]
    fn slot_refuses_unsafe_directories_and_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = TempDir::new("slotsafety");
        let t = &temp.0;
        let dir = |name: &str, mode: u32| {
            let path = t.join(name);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        let cmd = argv(&["cargo", "test"]);
        let refused = |dir: &Path| match acquire_slot_in(dir, &cmd, Duration::from_millis(50)) {
            Ok(_) => panic!("{} was accepted", dir.display()),
            Err(failure) => failure.unavailable.unwrap_or_else(|| panic!("{} read as contention", dir.display())),
        };
        assert!(refused(&dir("shared", 0o777)).contains("accessible"));
        let real = dir("real", 0o700);
        symlink(&real, t.join("linked")).unwrap();
        assert!(refused(&t.join("linked")).contains("symlink"));

        let victim = t.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let locked = dir("locked", 0o700);
        symlink(&victim, locked.join("check-slot.lock")).unwrap();
        refused(&locked);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");

        let loose = dir("loose", 0o700);
        std::fs::write(loose.join("check-slot.lock"), "").unwrap();
        std::fs::set_permissions(loose.join("check-slot.lock"), std::fs::Permissions::from_mode(0o666)).unwrap();
        refused(&loose);

        let meta = dir("meta", 0o700);
        symlink(&victim, meta.join("check-slot.json")).unwrap();
        let slot = acquire_slot_in(&meta, &cmd, Duration::from_secs(2)).ok().expect("slot acquired");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep", "metadata must not follow the symlink");
        drop(slot);
    }

    #[cfg(unix)]
    #[test]
    fn slot_dir_is_created_private_and_contention_is_not_unavailable() {
        use std::os::unix::fs::MetadataExt;
        let temp = TempDir::new("slotprivate");
        let dir = temp.0.join("fresh");
        let first = acquire_slot_in(&dir, &argv(&["cargo", "test"]), Duration::from_secs(2)).ok().unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        let Err(blocked) = acquire_slot_in(&dir, &argv(&["cargo", "test"]), Duration::from_millis(60)) else {
            panic!("a held slot was acquired twice")
        };
        assert!(blocked.unavailable.is_none());
        assert!(blocked.holder.contains("prometheus-check"));
        drop(first);
    }
}
