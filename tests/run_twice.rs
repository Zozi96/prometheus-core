//! ADR-0017 run-twice proof (ticket #92): equal declared inputs, each run
//! starting from the same store state, give byte-identical stdout and the
//! same exit code for both binaries, and created log names carry no clock
//! value or process id.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "prom_run_twice_{tag}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn check_bin() -> &'static str {
    env!("CARGO_BIN_EXE_prometheus-check")
}

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_prometheus-kit")
}

fn log_path(stdout: &[u8]) -> PathBuf {
    let text = String::from_utf8_lossy(stdout);
    let path = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("log: ").or_else(|| {
                line.rsplit(" | log: ")
                    .next()
                    .filter(|_| line.contains(" | log: "))
            })
        })
        .unwrap_or_else(|| panic!("no log line in {text}"))
        .trim()
        .to_string();
    PathBuf::from(path)
}

fn log_name(stdout: &[u8]) -> String {
    log_path(stdout)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string()
}

fn assert_hash_ordinal_name(name: &str, prefix: &str) {
    let rest = name
        .strip_prefix(&format!("{prefix}-"))
        .unwrap_or_else(|| panic!("{name} lacks {prefix}-"));
    let (hash, ordinal) = rest.strip_suffix(".log").unwrap().rsplit_once('-').unwrap();
    assert_eq!(hash.len(), 64, "{name}: hash is not a sha256 hex digest");
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
    assert!(
        ordinal.bytes().all(|b| b.is_ascii_digit()),
        "{name}: ordinal is not numeric"
    );
}

#[test]
fn check_runs_twice_byte_identical_and_repeat_gets_next_ordinal() {
    let tmp = TempDir::new("check");
    let root = tmp.0.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("a.txt"), "hello\n").unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&root)
        .status()
        .unwrap()
        .success());
    let store = tmp.0.join("store");

    let run = || -> Output {
        Command::new(check_bin())
            .args([
                "--root",
                root.to_str().unwrap(),
                "--store",
                store.to_str().unwrap(),
                "--",
            ])
            .args(["sh", "-c", "printf 'Ran 1 test in 0.0s\\n\\nOK\\n'"])
            .output()
            .unwrap()
    };

    let first = run();
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let name = log_name(&first.stdout);
    assert_hash_ordinal_name(&name, "check");
    assert!(name.ends_with("-0.log"), "{name}");
    let logs_dir = store.join("logs");
    let first_log = logs_dir.join(&name);
    let first_contents = fs::read(&first_log).unwrap();

    // A repeat against the store that already holds the earlier log gets
    // the next ordinal and leaves the earlier log untouched. (--force so
    // the Green receipt is not reused instead of re-executing.)
    let repeat = Command::new(check_bin())
        .args([
            "--root",
            root.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--force",
            "--",
        ])
        .args(["sh", "-c", "printf 'Ran 1 test in 0.0s\\n\\nOK\\n'"])
        .output()
        .unwrap();
    assert_eq!(repeat.status.code(), Some(0));
    let repeat_name = log_name(&repeat.stdout);
    assert!(repeat_name.ends_with("-1.log"), "{repeat_name}");
    assert_eq!(fs::read(&first_log).unwrap(), first_contents);

    // From the same store state again, output is byte-identical.
    let _ = fs::remove_dir_all(&store);
    let second = run();
    assert_eq!(second.status.code(), first.status.code());
    assert_eq!(second.stdout, first.stdout);
}

#[test]
fn compact_spillover_runs_twice_byte_identical() {
    let tmp = TempDir::new("compact");
    let runtime = tmp.0.join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    let mut input = String::new();
    for i in 0..600 {
        input.push_str(&format!(
            "line {i} some verbose output that will be compacted away\n"
        ));
    }
    let file = tmp.0.join("input.log");
    fs::write(&file, &input).unwrap();

    let run = || -> Output {
        Command::new(kit_bin())
            .args(["compact", file.to_str().unwrap()])
            .env("PROMETHEUS_KIT_NO_METRICS", "1")
            .env("XDG_RUNTIME_DIR", &runtime)
            .current_dir(&tmp.0)
            .output()
            .unwrap()
    };

    // Establish the starting spillover state before the first run
    // (the acceptance shape: each run starts from the same directory
    // state). The spillover slot is shared — on Windows it is the
    // temp dir's `prometheus` directory, where real CLI spillover
    // logs live and an earlier test-binary invocation in the same
    // job (the default-features run) can leave a same-hash `-0` log
    // behind. This test must never delete files it did not create
    // (Devin Review, "Windows test deletes shared logs": a previous
    // version removed the whole slot directory). The test's content
    // is fixed, so its log names are known exactly —
    // `compact-<sha256 of the content>-<ordinal>.log` — and only
    // files with that exact stem are reset: leftovers of earlier
    // invocations of this same test.
    #[cfg(windows)]
    let slot = std::env::temp_dir().join("prometheus");
    #[cfg(not(windows))]
    let slot = runtime.join("prometheus");
    let kit_logs = slot.join("kit-logs");
    let stem = format!(
        "compact-{}-",
        prometheus_core::store::sha256_hex(input.as_bytes())
    );
    let reset_own_logs = || {
        if let Ok(entries) = fs::read_dir(&kit_logs) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(&stem) && name.ends_with(".log") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    };
    reset_own_logs();

    let first = run();
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let name = log_name(&first.stdout);
    assert_hash_ordinal_name(&name, "compact");
    assert!(name.ends_with("-0.log"), "{name}");
    let first_log = log_path(&first.stdout);

    // Reset the spillover state between runs: remove only the log
    // the first run created (its path is printed in its stdout), so
    // the second run starts from the same spillover state and must
    // print byte-identical output.
    fs::remove_file(&first_log).unwrap();
    let second = run();
    assert_eq!(second.status.code(), first.status.code());
    assert_eq!(second.stdout, first.stdout);
    // The second run's log is this test's own file too; remove it so
    // no invocation leaves state behind for the next one.
    let _ = fs::remove_file(log_path(&second.stdout));
}

#[test]
fn hook_runs_twice_byte_identical_for_each_of_the_nine_hosts_through_the_binary() {
    let tmp = TempDir::new("hook");
    let home = tmp.0.join("home");
    fs::create_dir_all(&home).unwrap();
    let cwd = tmp.0.to_string_lossy().replace('\\', "\\\\");
    let events: [(&str, String); 9] = [
        (
            "claude",
            format!(
                r#"{{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":".env"}},"cwd":"{cwd}","session_id":"s-twice"}}"#
            ),
        ),
        (
            "muse",
            format!(
                r#"{{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":".env"}},"cwd":"{cwd}","session_id":"s-twice"}}"#
            ),
        ),
        (
            "droid",
            format!(
                r#"{{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":".env"}},"cwd":"{cwd}","session_id":"s-twice"}}"#
            ),
        ),
        (
            "devin",
            format!(
                r#"{{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":".env"}},"cwd":"{cwd}","session_id":"s-twice"}}"#
            ),
        ),
        (
            "cursor",
            format!(
                r#"{{"hook_event_name":"preToolUse","tool_name":"Read","tool_input":{{"file_path":".env"}},"workspace_roots":["{cwd}"],"conversation_id":"s-twice"}}"#
            ),
        ),
        (
            "omp",
            format!(
                r#"{{"tool_name":"read","input":{{"path":".env"}},"cwd":"{cwd}","sessionId":"s-twice"}}"#
            ),
        ),
        (
            "opencode",
            format!(
                r#"{{"event_name":"pretooluse","tool_name":"read","tool_input":{{"path":".env"}},"cwd":"{cwd}","session_id":"s-twice"}}"#
            ),
        ),
        (
            "antigravity",
            format!(
                r#"{{"hookEventName":"PreToolUse","conversationId":"s-twice","workspacePaths":["{cwd}"],"toolCall":{{"name":"view_file","args":{{"AbsolutePath":".env"}}}}}}"#
            ),
        ),
        (
            "grok",
            format!(
                r#"{{"hookEventName":"PreToolUse","sessionId":"s-twice","workspaceRoot":"{cwd}","toolName":"read_file","toolInput":{{"file_path":".env"}}}}"#
            ),
        ),
    ];
    for (host, event) in events {
        let run = || -> Output {
            let mut cmd = Command::new(kit_bin());
            cmd.args(["hook", host])
                .env("HOME", &home)
                .env("XDG_RUNTIME_DIR", &tmp.0)
                .env("PROMETHEUS_KIT_RTK_COEXIST", "0")
                .env("PROMETHEUS_KIT_NO_METRICS", "1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(event.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        };
        let first = run();
        let second = run();
        assert_eq!(Some(0), first.status.code(), "{host}");
        assert_ne!(
            b"{}\n",
            first.stdout.as_slice(),
            "{host} secret guard must fire"
        );
        assert_eq!(
            first.stdout, second.stdout,
            "{host} replies must be byte-identical"
        );
    }
}

#[test]
fn kit_subcommands_outline_slice_search_diff_map_run_twice_byte_identical_text_and_json() {
    let tmp = TempDir::new("kit_five");
    let repo = tmp.0.join("repo");
    let src = repo.join("src");
    fs::create_dir_all(&src).unwrap();

    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .unwrap()
        .success());

    fs::write(
        src.join("lib.rs"),
        "pub struct Widget {\n    pub count: usize,\n}\n\nimpl Widget {\n    pub fn compute(&self) -> usize {\n        let needle_val = self.count + 1;\n        needle_val\n    }\n}\n",
    )
    .unwrap();
    fs::write(
        src.join("extra.rs"),
        "pub fn helper_fn(x: usize) -> usize {\n    x * 2\n}\n",
    )
    .unwrap();

    assert!(Command::new("git")
        .args(["add", "."])
        .current_dir(&repo)
        .status()
        .unwrap()
        .success());

    // Unstaged modification for deterministic diff output against the index.
    fs::write(
        src.join("lib.rs"),
        "pub struct Widget {\n    pub count: usize,\n}\n\nimpl Widget {\n    pub fn compute(&self) -> usize {\n        let needle_val = self.count + 42;\n        needle_val\n    }\n}\n",
    )
    .unwrap();

    let run_twice = |args: &[&str]| -> String {
        let exec = || {
            Command::new(kit_bin())
                .args(args)
                .current_dir(&repo)
                .env("PROMETHEUS_KIT_NO_METRICS", "1")
                .output()
                .unwrap()
        };
        let first = exec();
        let second = exec();
        assert_eq!(
            first.status.code(),
            Some(0),
            "{args:?}: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(second.status.code(), first.status.code(), "{args:?}");
        assert_eq!(first.stdout, second.stdout, "{args:?} stdout must repeat byte-identical");
        assert_eq!(first.stderr, second.stderr, "{args:?} stderr must repeat byte-identical");
        String::from_utf8(first.stdout).unwrap()
    };

    // 1. outline (text + JSON)
    let out_txt = run_twice(&["outline", "src/lib.rs"]);
    assert!(out_txt.contains("Widget"), "{out_txt}");
    assert!(out_txt.contains("compute"), "{out_txt}");
    let out_json_s = run_twice(&["outline", "--json", "src/lib.rs"]);
    let out_json: serde_json::Value = serde_json::from_str(&out_json_s).unwrap();
    assert!(!out_json["docs"][0]["items"].as_array().unwrap().is_empty());

    // 2. slice (text + JSON)
    let sl_txt = run_twice(&["slice", "src/lib.rs::Widget::compute"]);
    assert!(sl_txt.contains("needle_val"), "{sl_txt}");
    let sl_json_s = run_twice(&["slice", "--json", "src/lib.rs::Widget::compute"]);
    let sl_json: serde_json::Value = serde_json::from_str(&sl_json_s).unwrap();
    assert!(!sl_json["slices"][0]["lines"].as_array().unwrap().is_empty());
    assert!(sl_json_s.contains("needle_val"), "{sl_json_s}");

    // 3. search (text + JSON)
    let sr_txt = run_twice(&["search", "--symbols", "needle_val", "."]);
    assert!(sr_txt.contains("src/lib.rs"), "{sr_txt}");
    assert!(sr_txt.contains("2 examined, 1 matched"), "{sr_txt}");
    let sr_json_s = run_twice(&["search", "--symbols", "--json", "needle_val", "."]);
    let sr_json: serde_json::Value = serde_json::from_str(&sr_json_s).unwrap();
    assert_eq!(sr_json["examined_files"], 2);
    assert_eq!(sr_json["total_files"], 1);

    // 4. diff (text + JSON)
    let df_txt = run_twice(&["diff", "--root", "."]);
    assert!(df_txt.contains("src/lib.rs"), "{df_txt}");
    assert!(df_txt.contains("self.count + 42"), "{df_txt}");
    let df_json_s = run_twice(&["diff", "--json", "--root", "."]);
    let df_json: serde_json::Value = serde_json::from_str(&df_json_s).unwrap();
    assert_eq!(df_json["files"][0]["path"], "src/lib.rs");

    // 5. map (text + JSON)
    let mp_txt = run_twice(&["map", "--symbols", "."]);
    assert!(mp_txt.contains("lib.rs"), "{mp_txt}");
    assert!(mp_txt.contains("Widget"), "{mp_txt}");
    let mp_json_s = run_twice(&["map", "--symbols", "--json", "."]);
    let mp_json: serde_json::Value = serde_json::from_str(&mp_json_s).unwrap();
    assert_eq!(mp_json["total_files"], 2);
    assert!(mp_json_s.contains("Widget"), "{mp_json_s}");
}

#[test]
fn check_unavailable_known_runner_reports_guidance_without_asking_for_command() {
    let tmp = TempDir::new("check_runner_missing");
    let root = tmp.0.join("root");
    let store = tmp.0.join("store");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("a.txt"), "hello\n").unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&root)
        .status()
        .unwrap()
        .success());

    let missing = Command::new(check_bin())
        .args([
            "--root",
            root.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--",
            "nonexistent-runner-xyz",
        ])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    let missing_out = String::from_utf8_lossy(&missing.stdout);
    assert!(
        missing_out.contains("runner not available: nonexistent-runner-xyz"),
        "{missing_out}"
    );
    assert!(missing_out.contains("verify the configured executable path"), "{missing_out}");
    assert!(!missing_out.contains("install"), "{missing_out}");
    assert!(
        !missing_out.contains("ask for the test_command"),
        "{missing_out}"
    );

    // Unknown command still asks for test_command.
    let unknown = Command::new(check_bin())
        .args([
            "--root",
            root.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--changed",
        ])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(1));
    let unknown_out = String::from_utf8_lossy(&unknown.stdout);
    assert!(
        unknown_out.contains("validation pending: ask for the test_command"),
        "{unknown_out}"
    );
}
