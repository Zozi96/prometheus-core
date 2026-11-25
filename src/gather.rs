//! Tree scan gathering as a library step (ADR-0017, ticket #97).
//!
//! After the Selection ticket (#96), the binary's `main` still gathered
//! the facts Selection needs: the base revision fallback, the Scan
//! cache read and write, the impact computation, the cargo graph, and
//! the Python runtime lookup — reading the environment along the way.
//! That gathering lives here now, so a Check run started with
//! `--changed` reads as gather, then select, then run.
//!
//! Gathering does the real I/O (git, the build graph, the interpreter
//! lookup, the Scan cache) and returns typed facts. A failure is
//! returned as a typed value — Widening reasons on the deltas,
//! [`ImpactFacts::Unavailable`], a missing Python runtime — never
//! turned into a process exit. Ambient facts (ADR-0017 D2) are read
//! once at the binary's edge and passed in through [`GatherRequest`]:
//! nothing in this module reads an environment variable or the working
//! directory. The interpreter path stays part of a Green receipt's
//! identity because it is part of the launched command Selection
//! builds from these facts. Tree scans stay cached by Tree fingerprint
//! (ADR-0007 D3), and the fingerprint itself is a Declared input the
//! caller resolves through [`tree_fingerprint`].

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::check::{
    change_class, compute_deltas, discover_tests, git_text, load_config, python_candidates,
    scan_cache_read, scan_cache_write, Config, Deltas, ScanEntry,
};
use crate::selection::{ImpactFacts, ImpactSelection, LayoutFacts, PythonRuntime, TreeScanFacts};

/// Ambient facts (ADR-0017 D2), read once at the binary's edge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmbientFacts {
    /// The active virtual environment (`VIRTUAL_ENV`), if any. It
    /// changes the launched command, and so a Green receipt's identity.
    pub virtual_env: Option<PathBuf>,
    /// Whether the caller disabled user site-packages (`PYTHONNOUSERSITE`).
    /// Isolated probes (`-I`) ignore env vars, so this must be passed
    /// explicitly so the user-site fallback mirrors normal launches.
    pub python_no_user_site: bool,
}

/// Everything gathering is a function of: the tree, the runner's store,
/// the Tree fingerprint the Scan cache is keyed by, an optional
/// explicit base ref, and the Ambient facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatherRequest {
    pub root: PathBuf,
    pub store: PathBuf,
    pub fingerprint: String,
    pub base: Option<String>,
    pub ambient: AmbientFacts,
}

/// The typed facts one gathering produces: everything Selection needs,
/// plus the scan's own record (config and deltas) for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatheredScan {
    pub fingerprint: String,
    pub config: Config,
    pub deltas: Deltas,
    /// The sorted union of the Task delta and the Integration delta.
    pub changed: Vec<String>,
    pub impact: ImpactFacts,
    pub python: Option<PythonRuntime>,
    pub root_solutions: Vec<String>,
    pub layout: LayoutFacts,
}

impl GatheredScan {
    /// The Tree scan facts Selection is a pure function of.
    pub fn scan_facts(&self) -> TreeScanFacts {
        TreeScanFacts {
            changed: self.changed.clone(),
            change_class: change_class(&self.changed).to_owned(),
            certain: self.deltas.widen.is_empty(),
            widen_reasons: self.deltas.widen.clone(),
            deleted_tests: self.deltas.deleted_tests().into_iter().cloned().collect(),
            impact: self.impact.clone(),
            declared_test_command: self.config.test_command.clone(),
            python: self.python.clone(),
            root_solutions: self.root_solutions.clone(),
            layout: self.layout.clone(),
        }
    }
}

/// The Tree fingerprint of `root`, with the fingerprint object store
/// under the runner's store. `None` when the tree cannot be
/// fingerprinted.
pub fn tree_fingerprint(root: &Path, store: &Path) -> Option<String> {
    let objects = store.join("objects");
    let _ = std::fs::create_dir_all(&objects);
    crate::fingerprint::worktree_fingerprint(&root.to_string_lossy(), &objects.to_string_lossy())
}

/// The base revision: the explicit ref when given, else the first of
/// the conventional base refs that resolves.
fn resolve_base(root: &Path, explicit: Option<String>) -> Option<String> {
    explicit.or_else(|| {
        ["origin/main", "origin/master", "main", "master"]
            .iter()
            .find(|refname| {
                git_text(
                    root,
                    &[
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        &format!("{refname}^{{commit}}"),
                    ],
                )
                .is_some()
            })
            .map(|refname| refname.to_string())
    })
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
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
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
            let id = package
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            if !members.iter().any(|member| member == id) {
                continue;
            }
            let manifest = package
                .get("manifest_path")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let dir = rel(Path::new(manifest)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .as_deref()
                .unwrap_or(""));
            let deps: Vec<String> = package
                .get("dependencies")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|dep| dep.get("path").and_then(|value| value.as_str()).map(rel))
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

/// The Python interpreter to run tests with and whether pytest is
/// installed there: the first candidate (virtualenv first, then
/// `python3`, then `python`) that starts.
///
/// The probe runs the interpreter ISOLATED from the checkout
/// (`-I` + `PYTHONSAFEPATH=1`): for `python -c`, `sys.path[0]` is
/// normally the working directory, so an unisolated probe would
/// import — and execute — repository-controlled modules (a
/// `pytest.py` or `sitecustomize.py` in the tree) with the caller's
/// permissions, even for a change no test run will ever follow
/// (Devin Review security finding, parent PR #108). Isolation keeps
/// the answers accurate: `import pytest` now reports the
/// interpreter's installed pytest, not a same-named file in the
/// tree. Venv candidates are absolute paths and keep working.
fn python_runtime(
    root: &Path,
    virtual_env: Option<&Path>,
    python_no_user_site: bool,
) -> Option<PythonRuntime> {
    let works = |program: &str, code: &str| {
        Command::new(program)
            .args(["-I", "-c", code])
            .env("PYTHONSAFEPATH", "1")
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    };
    let program = python_candidates(root, virtual_env)
        .into_iter()
        .find(|program| works(program, "import sys"))?;
    // The isolated import covers venv and system site-packages but
    // hides the user site (`pip install --user`); fall back to a
    // presence check there (Devin Review, "User-installed pytest
    // tests skipped") unless `PYTHONNOUSERSITE` disables user site.
    let pytest = works(&program, "import pytest")
        || (!python_no_user_site && pytest_in_user_site(&program, root));
    Some(PythonRuntime { program, pytest })
}

/// Whether `dir` directly contains an importable pytest package or
/// module, judged by presence on disk — never by importing it.
fn pytest_direct_in(dir: &Path) -> bool {
    dir.join("pytest").is_dir() || dir.join("pytest.py").is_file()
}

/// Extract the finder module stem from a PEP 660 editable `.pth`
/// import line (`import __editable___pytest_8_0_0_finder; ...`).
fn pep660_pytest_finder_present(dir: &Path, file_name: &str, line: &str) -> bool {
    if !(file_name.starts_with("__editable__.pytest-")
        || file_name.starts_with("__editable__.pytest."))
    {
        return false;
    }
    let Some(rest) = line
        .strip_prefix("import ")
        .or_else(|| line.strip_prefix("import\t"))
    else {
        return false;
    };
    let ident = rest
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .next()
        .unwrap_or("");
    !ident.is_empty()
        && !ident.contains('/')
        && !ident.contains('\\')
        && dir.join(format!("{ident}.py")).is_file()
}

/// Whether `dir` exposes pytest either directly or through an editable
/// `.pth` / `.egg-link` entry, judged purely on disk — never by
/// executing `.pth` `import` code.
fn pytest_present_in(dir: &Path) -> bool {
    if pytest_direct_in(dir) {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if ext == "pth" {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for raw_line in content.lines() {
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.starts_with("import ") || line.starts_with("import\t") {
                    if pep660_pytest_finder_present(dir, file_name, line) {
                        return true;
                    }
                    continue;
                }
                let candidate = Path::new(line);
                let target = if candidate.is_absolute() {
                    candidate.to_path_buf()
                } else {
                    dir.join(candidate)
                };
                if pytest_direct_in(&target) {
                    return true;
                }
            }
        } else if ext == "egg-link" {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(line) = content
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with('#'))
            {
                let candidate = Path::new(line);
                let target = if candidate.is_absolute() {
                    candidate.to_path_buf()
                } else {
                    dir.join(candidate)
                };
                if pytest_direct_in(&target) {
                    return true;
                }
            }
        }
    }
    false
}

/// Detect pytest installed only in the interpreter's user site
/// WITHOUT importing anything from it: an isolated interpreter
/// reports the user-site paths it would normally enable (pure path
/// computation — no repository code runs), and the package's
/// presence is checked on disk. Skipped inside a virtual
/// environment, whose launches exclude the user site anyway.
fn pytest_in_user_site(program: &str, root: &Path) -> bool {
    let code = "import site, sys\n\
                print(1 if sys.prefix != sys.base_prefix else 0)\n\
                us = site.getusersitepackages()\n\
                if isinstance(us, str): us = [us]\n\
                for p in us: print(p)";
    let out = Command::new(program)
        .args(["-I", "-c", code])
        .env("PYTHONSAFEPATH", "1")
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success());
    let Some(out) = out else { return false };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("0") {
        return false; // venv interpreter (or unparseable): no user site
    }
    lines
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(|line| pytest_present_in(Path::new(line)))
}

fn root_files(root: &Path, suffixes: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(root)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .filter(|name| suffixes.iter().any(|suffix| name.ends_with(suffix)))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Gather the Tree scan facts for one `--changed` Check run.
pub fn gather_scan(request: &GatherRequest) -> GatheredScan {
    let root = &request.root;
    let config = load_config(root);
    let base = resolve_base(root, request.base.clone());
    let deltas = compute_deltas(root, base.as_deref());

    let mut changed = deltas.task.clone();
    changed.extend(deltas.integration.iter().cloned());
    changed.sort();
    changed.dedup();

    // The Scan cache, keyed by Tree fingerprint and delta key. An
    // entry whose impact does not deserialize into the typed facts is
    // a miss in `scan_cache_read`, and the scan runs again here.
    let cache_path = request.store.join("scan-cache.json");
    let cached = deltas
        .key
        .as_deref()
        .and_then(|key| scan_cache_read(&cache_path, &request.fingerprint, key));
    let impact = match cached {
        // `scan_cache_read` only returns entries whose impact deserializes
        // into the typed facts, so `None` here should be unreachable; if
        // that invariant ever breaks, widen instead of panicking.
        Some(entry) => match ImpactSelection::from_document(&entry.impact) {
            Some(selection) => ImpactFacts::Available(selection),
            None => ImpactFacts::Unavailable,
        },
        None => {
            let document = crate::impact::impact_document(
                &root.to_string_lossy(),
                &changed,
                discover_tests(root),
                &cargo_graph_json(root),
            );
            let parsed = document
                .as_deref()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
                .and_then(|value| {
                    ImpactSelection::from_document(&value).map(|selection| (value, selection))
                });
            match parsed {
                Some((impact_doc, selection)) => {
                    if let Some(key) = &deltas.key {
                        let _ = scan_cache_write(
                            &cache_path,
                            &ScanEntry {
                                fingerprint: request.fingerprint.clone(),
                                base: key.clone(),
                                task_delta: deltas.task.clone(),
                                integration_delta: deltas.integration.clone(),
                                impact: impact_doc,
                            },
                        );
                    }
                    ImpactFacts::Available(selection)
                }
                None => ImpactFacts::Unavailable,
            }
        }
    };

    // Selection owes no checks — and the gathered Python runtime is
    // never consulted — when the change is certainly empty or
    // docs-only (the same conditions as Selection's NoChecksOwed
    // outcomes). Do not even PROBE an interpreter in that case:
    // starting Python inside the checkout can execute
    // repository-controlled code, which is unjustifiable for a run
    // that will launch nothing (Devin Review security finding,
    // parent PR #108). The probe itself is additionally isolated;
    // see `python_runtime`.
    let certain = deltas.widen.is_empty();
    let owes_no_checks = certain && (changed.is_empty() || change_class(&changed) == "docs-only");
    let python = if owes_no_checks {
        None
    } else {
        python_runtime(
            root,
            request.ambient.virtual_env.as_deref(),
            request.ambient.python_no_user_site,
        )
    };

    GatheredScan {
        fingerprint: request.fingerprint.clone(),
        config,
        deltas,
        changed,
        impact,
        python,
        root_solutions: root_files(root, &[".sln", ".slnx"]),
        layout: LayoutFacts {
            cargo_toml: root.join("Cargo.toml").is_file(),
            csproj: !root_files(root, &[".csproj"]).is_empty(),
            pyproject: root.join("pyproject.toml").is_file(),
            tests_dir: root.join("tests").is_dir(),
            package_json: root.join("package.json").is_file(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::{select, SelectionOutcome};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!(
                "prometheus-gather-{name}-{}-{}",
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

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(["-c", "core.autocrlf=false", "-c", "init.defaultBranch=main"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
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

    /// A real temporary git repository: `calc.py` and a test importing
    /// it committed on `main`, then `calc.py` modified in the worktree.
    fn repo(name: &str) -> TempDir {
        let temp = TempDir::new(name);
        git(&temp.0, &["init", "-q", "-b", "main"]);
        commit(&temp.0, "calc.py", "def add(a, b):\n    return a + b\n");
        commit(&temp.0, "tests/test_calc.py", "import calc\n");
        write(&temp.0, "calc.py", "def add(a, b):\n    return a + b + 0\n");
        temp
    }

    fn request(
        root: &Path,
        store: &Path,
        base: Option<&str>,
        venv: Option<PathBuf>,
    ) -> GatherRequest {
        GatherRequest {
            root: root.to_path_buf(),
            store: store.to_path_buf(),
            fingerprint: tree_fingerprint(root, store).expect("test repo fingerprints"),
            base: base.map(str::to_owned),
            ambient: AmbientFacts {
                virtual_env: venv,
                python_no_user_site: false,
            },
        }
    }

    #[test]
    fn gathers_typed_facts_over_a_real_repo_and_gathers_twice_equal() {
        let temp = repo("basic");
        let store = temp.0.join(".git/prometheus-check");
        let req = request(&temp.0, &store, Some("main"), None);
        let first = gather_scan(&req);
        assert!(
            first.changed.iter().any(|path| path == "calc.py"),
            "{:?}",
            first.changed
        );
        assert!(
            matches!(first.impact, ImpactFacts::Available(_)),
            "{:?}",
            first.impact
        );
        assert!(first.deltas.key.is_some());
        let second = gather_scan(&req);
        assert_eq!(
            first, second,
            "gathering twice over the same inputs gives equal facts"
        );
    }

    #[test]
    fn scan_cache_miss_computes_and_hit_reuses() {
        let temp = repo("cache");
        let store = temp.0.join(".git/prometheus-check");
        let req = request(&temp.0, &store, Some("main"), None);
        let cache_path = store.join("scan-cache.json");
        assert!(!cache_path.exists());
        let computed = gather_scan(&req);
        assert!(cache_path.exists(), "a miss computes and writes the cache");

        // Rewrite the cached impact with a marker Selection: a hit
        // returns it verbatim instead of recomputing.
        let mut entry: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cache_path).unwrap()).unwrap();
        entry["impact"] = serde_json::json!({
            "selection": {"level": "full", "tests": [], "packages": [], "projects": [],
                          "module": null, "reasons": ["cached marker"]}
        });
        std::fs::write(&cache_path, serde_json::to_string(&entry).unwrap()).unwrap();
        let hit = gather_scan(&req);
        match &hit.impact {
            ImpactFacts::Available(selection) => {
                assert_eq!(selection.reasons, vec!["cached marker".to_owned()]);
            }
            other => panic!("expected the cached facts, got {other:?}"),
        }
        assert_ne!(hit.impact, computed.impact);
    }

    #[test]
    fn scan_cache_entry_that_does_not_deserialize_is_a_miss() {
        let temp = repo("badcache");
        let store = temp.0.join(".git/prometheus-check");
        let req = request(&temp.0, &store, Some("main"), None);
        let computed = gather_scan(&req);
        let cache_path = store.join("scan-cache.json");
        let mut entry: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cache_path).unwrap()).unwrap();
        entry["impact"] = serde_json::json!({"selection": {"level": "everything"}});
        std::fs::write(&cache_path, serde_json::to_string(&entry).unwrap()).unwrap();
        let rescanned = gather_scan(&req);
        assert_eq!(
            rescanned.impact, computed.impact,
            "a non-deserializing entry reruns the scan"
        );
        // And the rewritten cache entry deserializes again.
        assert!(scan_cache_read(
            &cache_path,
            &req.fingerprint,
            rescanned.deltas.key.as_deref().unwrap()
        )
        .is_some());
    }

    #[test]
    fn missing_base_revision_widens_with_no_cache_key() {
        let temp = repo("nobase");
        let store = temp.0.join(".git/prometheus-check");
        let gathered = gather_scan(&request(&temp.0, &store, Some("nope"), None));
        assert!(gathered.deltas.key.is_none());
        assert!(
            gathered
                .deltas
                .widen
                .iter()
                .any(|reason| reason.contains("base nope could not be resolved")),
            "{:?}",
            gathered.deltas.widen
        );
    }

    #[test]
    fn unavailable_impact_facts_are_a_typed_value() {
        // No git repository at all: the impact computation cannot run,
        // and gathering reports that as a value, not an exit.
        let temp = TempDir::new("nogit");
        write(&temp.0, "calc.py", "x = 1\n");
        let req = GatherRequest {
            root: temp.0.clone(),
            store: temp.0.join("store"),
            fingerprint: "declared-test-fingerprint".to_owned(),
            base: None,
            ambient: AmbientFacts {
                virtual_env: None,
                python_no_user_site: false,
            },
        };
        let gathered = gather_scan(&req);
        assert_eq!(gathered.impact, ImpactFacts::Unavailable);
        assert!(!gathered.deltas.widen.is_empty());
    }

    #[test]
    fn two_virtual_environments_give_two_commands_and_receipt_identities() {
        let temp = repo("venv");
        write(&temp.0, "pyproject.toml", "[project]\nname = \"x\"\n");
        let make_venv = |name: &str| -> PathBuf {
            let venv = temp.0.join(name);
            // The fake venv's interpreter must genuinely start:
            // `python_runtime` runs `<candidate> -c "import sys"`.
            // On Unix a shell script that exits 0 does that; on
            // Windows `bin/python` is not an executable path, so the
            // candidate list falls through to `python3` — build the
            // platform-correct `Scripts/python.exe` instead, as a copy
            // of a real Python executable plus the `pyvenv.cfg` a real
            // venv carries (its `home` line points the copy at the
            // real installation's standard library).
            #[cfg(windows)]
            {
                let real = ["python", "python3", "py"]
                    .into_iter()
                    .find_map(|program| {
                        std::process::Command::new(program)
                            .args(["-c", "import sys; print(sys.executable)"])
                            .output()
                            .ok()
                            .filter(|output| output.status.success())
                            .and_then(|output| {
                                String::from_utf8(output.stdout)
                                    .ok()
                                    .map(|text| PathBuf::from(text.trim()))
                            })
                            .filter(|path| path.is_file())
                    })
                    .expect("a real Python executable on PATH for the fake venv");
                let scripts = venv.join("Scripts");
                std::fs::create_dir_all(&scripts).unwrap();
                std::fs::copy(&real, scripts.join("python.exe")).unwrap();
                let home = real.parent().unwrap();
                std::fs::write(
                    venv.join("pyvenv.cfg"),
                    format!("home = {}\n", home.display()),
                )
                .unwrap();
            }
            #[cfg(not(windows))]
            {
                write(&venv, "bin/python", "#!/bin/sh\nexit 0\n");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        venv.join("bin/python"),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .unwrap();
                }
            }
            venv
        };
        let venv_a = make_venv("venv-a");
        let venv_b = make_venv("venv-b");
        let gathered_a = gather_scan(&request(
            &temp.0,
            &temp.0.join(".git/prometheus-check-a"),
            Some("main"),
            Some(venv_a),
        ));
        let gathered_b = gather_scan(&request(
            &temp.0,
            &temp.0.join(".git/prometheus-check-b"),
            Some("main"),
            Some(venv_b),
        ));
        let program_a = gathered_a.python.as_ref().unwrap().program.clone();
        let program_b = gathered_b.python.as_ref().unwrap().program.clone();
        assert!(program_a.contains("venv-a"), "{program_a}");
        assert!(program_b.contains("venv-b"), "{program_b}");

        let command_of = |gathered: &GatheredScan| match select(&gathered.scan_facts()) {
            SelectionOutcome::Selected(selection) => selection.command,
            other => panic!("expected a selection, got {other:?}"),
        };
        let command_a = command_of(&gathered_a);
        let command_b = command_of(&gathered_b);
        assert_ne!(
            command_a, command_b,
            "different venvs launch different commands"
        );
        // A Green receipt's identity is fingerprint + logical command.
        assert_ne!(
            (gathered_a.fingerprint.clone(), command_a),
            (gathered_b.fingerprint.clone(), command_b)
        );
    }

    /// A `pytest.py` sitting in the checkout that records its own
    /// import: if any interpreter probe imports it, the marker file
    /// appears in the tree root (the probe's working directory).
    const CANARY_PY: &str = "import pathlib\n\
        pathlib.Path('prometheus_canary_marker').write_text('imported')\n";

    #[test]
    fn docs_only_change_never_probes_python() {
        // Regression (Devin Review security finding, parent PR
        // #108): gathering used to start Python in the checkout
        // before Selection decided a docs-only change owes no
        // checks, so the probe's `import pytest` executed the
        // repo-controlled `pytest.py` with the caller's permissions.
        let temp = TempDir::new("canary-docs");
        git(&temp.0, &["init", "-q", "-b", "main"]);
        commit(&temp.0, "calc.py", "def add(a, b):\n    return a + b\n");
        commit(&temp.0, "pytest.py", CANARY_PY);
        commit(&temp.0, "README.md", "# docs\n");
        write(&temp.0, "README.md", "# docs, edited\n");
        let store = temp.0.join(".git/prometheus-check");
        let gathered = gather_scan(&request(&temp.0, &store, Some("main"), None));
        assert_eq!(gathered.changed, vec!["README.md".to_owned()]);
        assert!(
            gathered.python.is_none(),
            "no interpreter is probed when no checks are owed"
        );
        assert!(
            !temp.0.join("prometheus_canary_marker").exists(),
            "the repo-controlled module must never be imported"
        );
        assert!(matches!(
            select(&gathered.scan_facts()),
            SelectionOutcome::NoChecksOwed(crate::selection::NoChecksOwed::DocsOnly)
        ));
    }

    #[test]
    fn python_probe_is_isolated_from_checkout_modules() {
        // Companion regression: on a LOGIC change the probe does
        // run, but isolated (`-I` + PYTHONSAFEPATH), so the
        // checkout's own `pytest.py` is not imported — the detected
        // runtime is the real interpreter, and `pytest` reflects the
        // installed environment, not the tree's shadow module.
        let temp = TempDir::new("canary-logic");
        git(&temp.0, &["init", "-q", "-b", "main"]);
        commit(&temp.0, "calc.py", "def add(a, b):\n    return a + b\n");
        commit(&temp.0, "pytest.py", CANARY_PY);
        write(&temp.0, "calc.py", "def add(a, b):\n    return a + b + 0\n");
        let store = temp.0.join(".git/prometheus-check");
        let gathered = gather_scan(&request(&temp.0, &store, Some("main"), None));
        assert!(
            gathered.python.is_some(),
            "a logic change still gets its runtime detected"
        );
        assert!(
            !temp.0.join("prometheus_canary_marker").exists(),
            "the isolated probe must not import checkout modules"
        );
    }

    #[test]
    fn pytest_present_in_detects_package_dir_and_module_file() {
        use std::fs;
        let temp = TempDir::new("pytest-present");
        assert!(!pytest_present_in(&temp.0));
        fs::create_dir_all(temp.0.join("pytest")).unwrap();
        assert!(pytest_present_in(&temp.0));
        let temp2 = TempDir::new("pytest-present-mod");
        write(&temp2.0, "pytest.py", "# fake\n");
        assert!(pytest_present_in(&temp2.0));
    }

    /// Regression (Devin Review, "User-installed pytest tests
    /// skipped"): a fake interpreter whose isolated import cannot
    /// see pytest, but whose reported user site contains the
    /// package, must be detected as pytest-capable — by presence on
    /// disk, never by importing from the user site or the checkout.
    #[cfg(unix)]
    #[test]
    fn pytest_detected_when_only_in_user_site() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new("usersite");
        let root = temp.0.clone();
        let user_site = root.join("user-site");
        fs::create_dir_all(user_site.join("pytest")).unwrap();
        let venv = root.join("venv");
        let bin = venv.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let script = format!(
            "#!/bin/sh\ncase \"$3\" in\n\"import sys\") exit 0;;\n\"import pytest\") exit 1;;\n*getusersitepackages*) printf '0\\n{}\\n'; exit 0;;\nesac\nexit 1\n",
            user_site.display()
        );
        let program = bin.join("python");
        fs::write(&program, script).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        let runtime = python_runtime(&root, Some(&venv), false).expect("runtime detected");
        assert!(runtime.pytest, "user-site-only pytest is detected");
        fs::remove_dir_all(user_site.join("pytest")).unwrap();
        let runtime = python_runtime(&root, Some(&venv), false).expect("runtime detected");
        assert!(!runtime.pytest, "no pytest anywhere: not detected");
    }

    #[test]
    fn pytest_present_in_detects_pth_and_egg_link_editable_installs() {
        use std::fs;
        // 1. Absolute .pth pointing to editable src dir with pytest/.
        let temp = TempDir::new("pth-abs");
        let site = temp.0.join("site");
        let src = temp.0.join("editable-src");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(src.join("pytest")).unwrap();
        write(
            &site,
            "editable.pth",
            &format!("# comment\nimport os; os.abort()\n{}\n", src.display()),
        );
        assert!(pytest_present_in(&site));

        // 2. Relative .pth path + arbitrary import line does not match.
        let temp_rel = TempDir::new("pth-rel");
        let site_rel = temp_rel.0.join("site");
        let rel_src = temp_rel.0.join("rel-src");
        fs::create_dir_all(&site_rel).unwrap();
        fs::create_dir_all(rel_src.join("pytest")).unwrap();
        write(&site_rel, "other.pth", "import sys\n");
        assert!(!pytest_present_in(&site_rel));
        write(&site_rel, "rel.pth", "../rel-src\n");
        assert!(pytest_present_in(&site_rel));

        // 3. .egg-link pointing to editable checkout.
        let temp_egg = TempDir::new("egg-link");
        let site_egg = temp_egg.0.join("site");
        let egg_src = temp_egg.0.join("egg-src");
        fs::create_dir_all(&site_egg).unwrap();
        write(&egg_src, "pytest.py", "# editable\n");
        write(&site_egg, "pytest.egg-link", &format!("{}\n.\n", egg_src.display()));
        assert!(pytest_present_in(&site_egg));

        // 4. PEP 660 __editable__.pytest-*.pth with static finder module check.
        let temp_pep660 = TempDir::new("pep660");
        let site_660 = temp_pep660.0.join("site");
        fs::create_dir_all(&site_660).unwrap();
        write(
            &site_660,
            "__editable__.pytest-8.0.0.pth",
            "import __editable___pytest_8_0_0_finder; __editable___pytest_8_0_0_finder.install()\n",
        );
        assert!(
            !pytest_present_in(&site_660),
            "missing finder module must not match"
        );
        write(&site_660, "__editable___pytest_8_0_0_finder.py", "# finder\n");
        assert!(pytest_present_in(&site_660));
    }

    #[cfg(unix)]
    #[test]
    fn pytest_user_site_honors_python_no_user_site_and_pth_editable() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new("usersite-flags");
        let root = temp.0.clone();
        let user_site = root.join("user-site");
        let editable_src = root.join("pytest-checkout");
        fs::create_dir_all(&user_site).unwrap();
        fs::create_dir_all(editable_src.join("pytest")).unwrap();
        write(
            &user_site,
            "pytest.pth",
            &format!("{}\n", editable_src.display()),
        );
        let venv = root.join("venv");
        let bin = venv.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let script = format!(
            "#!/bin/sh\ncase \"$3\" in\n\"import sys\") exit 0;;\n\"import pytest\") exit 1;;\n*getusersitepackages*) printf '0\\n{}\\n'; exit 0;;\nesac\nexit 1\n",
            user_site.display()
        );
        let program = bin.join("python");
        fs::write(&program, script).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();

        let runtime = python_runtime(&root, Some(&venv), false).expect("runtime detected");
        assert!(runtime.pytest, "editable .pth in user-site is detected");

        fs::create_dir_all(user_site.join("pytest")).unwrap();
        let runtime_disabled =
            python_runtime(&root, Some(&venv), true).expect("runtime detected");
        assert!(
            !runtime_disabled.pytest,
            "PYTHONNOUSERSITE disables user-site fallback"
        );
    }
}
