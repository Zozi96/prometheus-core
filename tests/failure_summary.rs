//! #112: one typed failure summary across Check and compact.

use prometheus_core::compact::{
    compact_text, render_compact_json, render_compact_text, CompactMode, CompactOptions,
};
use prometheus_core::failure_summary::{render_failure_summary, FAILURE_SUMMARY_MAX_LINES};
use prometheus_core::logs::parse_log;
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
            "prom_failure_summary_{tag}_{}_{nanos}",
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

fn fixture(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/log_corpus")
            .join(name),
    )
    .unwrap()
}

fn cases() -> [(&'static str, &'static str, &'static str, &'static str); 5] {
    [
        (
            "cargo-failed.log",
            "tests::test_sub",
            "assertion failed",
            "cargo test -- --exact tests::test_sub",
        ),
        (
            "pytest-failed.log",
            "tests/test_x.py::T::test_a",
            "AssertionError: boom",
            "tests/test_x.py::T::test_a",
        ),
        (
            "unittest-failed.log",
            "tests/test_app.py:T.test_value",
            "AssertionError: 1 != 2",
            "tests/test_app.py:T.test_value",
        ),
        (
            "vstest-failed-line.log",
            "Foo.Tests.UnitTest1.TestMethod1",
            "Assert.AreEqual failed.",
            "dotnet test --filter FullyQualifiedName=Foo.Tests.UnitTest1.TestMethod1",
        ),
        (
            "mtp-failed-line.log",
            "Foo.Tests.UnitTest1.TestMethod1",
            "Assert.AreEqual failed.",
            "dotnet test --filter FullyQualifiedName=Foo.Tests.UnitTest1.TestMethod1",
        ),
    ]
}

#[test]
fn typed_failure_details_cover_all_five_families() {
    for (file, test, message, selector) in cases() {
        let parsed = parse_log(&fixture(file), Some(1));
        assert!(!parsed.failed_tests.is_empty(), "{file}");
        let detail = parsed
            .failure_details
            .iter()
            .find(|detail| detail.test == test)
            .unwrap_or_else(|| panic!("{file}: missing {test}: {:?}", parsed.failure_details));
        assert_eq!(selector, detail.selector, "{file}");
        assert!(detail.message.contains(message), "{file}: {detail:?}");
        let rendered = render_failure_summary(&parsed, Some("/tmp/saved.log"));
        let text = rendered.join("\n");
        assert!(text.contains(test), "{file}: {text}");
        assert!(text.contains(message), "{file}: {text}");
        assert!(
            text.contains(&format!("rerun: {selector}")),
            "{file}: {text}"
        );
    }

    let inline_vstest = "  Failed Foo.Tests.Inline [1 ms]\n  Error Message: Assert failed inline.\nFailed!  - Failed:     1, Passed:     0, Skipped:     0, Total:     1, Duration: 1 ms - Foo.dll\n";
    let parsed = parse_log(inline_vstest, Some(1));
    assert_eq!("Assert failed inline.", parsed.failure_details[0].message);
}

#[test]
fn compact_test_mode_uses_typed_summary_with_positive_savings() {
    for (file, test, message, selector) in cases() {
        let opts = CompactOptions {
            mode: CompactMode::Test,
            allow_spillover: false,
            ..CompactOptions::default()
        };
        let result = compact_text(&fixture(file), Some(1), &opts);
        assert!(result.saved_pct > 0.0, "{file}: {}%", result.saved_pct);
        assert!(result.lines.is_empty(), "{file}: raw tail leaked");
        let rendered = render_compact_text(&result, 0);
        assert!(
            rendered.len() < fixture(file).len(),
            "{file}: {} output bytes must beat {} raw bytes",
            rendered.len(),
            fixture(file).len()
        );
        assert!(rendered.contains(test), "{file}: {rendered}");
        assert!(rendered.contains(message), "{file}: {rendered}");
        assert!(
            rendered.contains(&format!("rerun: {selector}")),
            "{file}: {rendered}"
        );

        let unbudgeted_json = render_compact_json(&result, 0);
        let json: serde_json::Value = serde_json::from_str(&unbudgeted_json).unwrap();
        assert!(
            json.get("failure_details").is_some(),
            "{file}: {unbudgeted_json}"
        );
        let budgeted_json = render_compact_json(&result, 100);
        serde_json::from_str::<serde_json::Value>(&budgeted_json).unwrap();
        assert!(render_compact_text(&result, 60).len() <= 100 * 4, "{file}");
    }
}

fn large_cargo_log(count: usize) -> String {
    let mut raw = format!("running {count} tests\n");
    for index in 0..count {
        raw.push_str(&format!("test tests::case_{index} ... FAILED\n"));
    }
    raw.push_str("\nfailures:\n");
    for index in 0..count {
        raw.push_str(&format!(
            "---- tests::case_{index} stdout ----\nthread 'tests::case_{index}' panicked at src/lib.rs:1:1:\nassertion failed {index}\n\n"
        ));
    }
    raw.push_str("failures:\n");
    for index in 0..count {
        raw.push_str(&format!("    tests::case_{index}\n"));
    }
    raw.push_str(&format!(
        "test result: FAILED. 0 passed; {count} failed; 0 ignored; 0 measured; 0 filtered out\n"
    ));
    raw
}

fn cargo_log_without_counts(count: usize) -> String {
    let mut raw = format!("running {count} tests\n");
    for index in 0..count {
        raw.push_str(&format!("test tests::case_{index} ... FAILED\n"));
    }
    raw.push_str("\nfailures:\n");
    for index in 0..count {
        raw.push_str(&format!(
            "---- tests::case_{index} stdout ----\nthread 'tests::case_{index}' panicked at src/lib.rs:1:1:\nassertion failed {index}\n\n"
        ));
    }
    raw.push_str("failures:\n");
    for index in 0..count {
        raw.push_str(&format!("    tests::case_{index}\n"));
    }
    raw
}

fn small_pytest_log(count: usize) -> String {
    let mut raw = String::new();
    for index in 0..count {
        raw.push_str(&format!("t.py::t{index} FAILED [ {index}%]\n"));
    }
    raw.push_str("=== short test summary info ===\n");
    for index in 0..count {
        raw.push_str(&format!("FAILED t.py::t{index} - E{index}\n"));
    }
    raw.push_str(&format!("=== {count} failed in 0.12s ===\n"));
    raw
}

#[test]
fn large_typed_failure_sets_are_capped_and_byte_identical() {
    let raw = large_cargo_log(40);

    let parsed = parse_log(&raw, Some(1));
    assert_eq!(40, parsed.failure_details.len());
    let first = render_failure_summary(&parsed, Some("/tmp/saved.log"));
    let second = render_failure_summary(&parsed, Some("/tmp/saved.log"));
    assert_eq!(first, second);
    assert!(first.len() <= FAILURE_SUMMARY_MAX_LINES);
    assert_eq!(
        first.last().unwrap(),
        &format!(
            "... ({} failures omitted; see full log: /tmp/saved.log)",
            40 - (first.len() - 2) / 2
        )
    );
}

#[test]
fn compact_cap_notice_points_to_the_saved_log() {
    let tmp = TempDir::new("saved_log_notice");
    let saved = tmp.0.join("saved.log");
    let raw = large_cargo_log(60);
    let opts = CompactOptions {
        mode: CompactMode::Test,
        save_log: Some(saved.clone()),
        allow_spillover: false,
        ..CompactOptions::default()
    };
    let result = compact_text(&raw, Some(1), &opts);
    assert_eq!(fs::read_to_string(&saved).unwrap(), raw);
    let rendered = render_compact_text(&result, 0);
    assert!(
        rendered.contains(&format!(
            "failures omitted; see full log: {}",
            saved.display()
        )),
        "{rendered}"
    );
    assert!(rendered.contains("log: "), "{rendered}");
}

#[test]
fn unknown_logs_keep_the_bounded_fallback() {
    let raw = (0..100)
        .map(|index| format!("unknown runner line {index}\n"))
        .collect::<String>();
    let opts = CompactOptions {
        mode: CompactMode::Test,
        allow_spillover: false,
        tail_lines: 7,
        ..CompactOptions::default()
    };
    let result = compact_text(&raw, Some(1), &opts);
    assert_eq!(Some(1), result.exit_code);
    assert!(result.failure_details.is_empty());
    assert!(
        result.lines.len() <= 8,
        "bounded fallback: {:?}",
        result.lines
    );
    let rendered = render_compact_text(&result, 0);
    assert!(rendered.contains("exit 1"), "{rendered}");
    assert!(rendered.contains("unknown runner line 99"), "{rendered}");
}

#[cfg(unix)]
fn run_kit_compact(
    tmp: &TempDir,
    fixture_path: Option<&PathBuf>,
    script: &str,
    extra: &[&str],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_prometheus-kit"));
    command
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .env("XDG_RUNTIME_DIR", tmp.0.join("runtime"))
        .arg("compact")
        .arg("--mode")
        .arg("test")
        .args(extra);
    if let Some(path) = fixture_path {
        command.arg(path);
    } else {
        command.args(["--", "sh", "-c", script]);
    }
    command.output().unwrap()
}

#[cfg(unix)]
#[test]
fn compact_cli_preserves_exit_and_log_pointer_for_typed_and_unknown_failures() {
    let tmp = TempDir::new("compact_cli");
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/log_corpus/pytest-failed.log");
    let typed = run_kit_compact(
        &tmp,
        None,
        &format!("cat '{}'; exit 1", fixture_path.display()),
        &[],
    );
    assert_eq!(Some(1), typed.status.code());
    let stdout = String::from_utf8_lossy(&typed.stdout);
    assert!(stdout.contains("tests/test_x.py::T::test_a"), "{stdout}");
    assert!(stdout.contains("AssertionError: boom"), "{stdout}");
    assert!(
        stdout.contains("rerun: tests/test_x.py::T::test_a"),
        "{stdout}"
    );
    assert!(!stdout.contains("log: "), "{stdout}");
    assert!(
        stdout.len() < fixture_path.metadata().unwrap().len() as usize,
        "{stdout}"
    );

    let json = run_kit_compact(
        &tmp,
        None,
        &format!("cat '{}'; exit 1", fixture_path.display()),
        &["--json", "--max-tokens", "300"],
    );
    assert_eq!(Some(1), json.status.code());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(value["failure_details"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty()));
    assert!(value.get("log_path").is_none(), "{value}");

    let large_path = tmp.0.join("large-cargo.log");
    fs::write(&large_path, large_cargo_log(60)).unwrap();
    let capped = run_kit_compact(
        &tmp,
        None,
        &format!("cat '{}'; exit 1", large_path.display()),
        &[],
    );
    assert_eq!(Some(1), capped.status.code());
    let stdout = String::from_utf8_lossy(&capped.stdout);
    assert!(
        stdout.contains("failures omitted; see full log: "),
        "{stdout}"
    );
    assert!(stdout.contains("log: "), "{stdout}");

    let unknown = run_kit_compact(
        &tmp,
        None,
        "printf 'unknown runner failure\\n'; exit 7",
        &[],
    );
    assert_eq!(Some(7), unknown.status.code());
    let stdout = String::from_utf8_lossy(&unknown.stdout);
    assert!(stdout.contains("exit 7"), "{stdout}");
    assert!(stdout.contains("unknown runner failure"), "{stdout}");
    assert!(stdout.contains("log: "), "{stdout}");
}

#[test]
fn cargo_panic_after_stdout_noise_is_still_extracted() {
    let mut raw = String::from("running 1 test\ntest tests::noisy ... FAILED\n\nfailures:\n\n---- tests::noisy stdout ----\n");
    for index in 0..20 {
        raw.push_str(&format!("noise line {index}\n"));
    }
    raw.push_str("thread 'tests::noisy' panicked at src/lib.rs:1:1:\nassertion failed after noise\n\nfailures:\n    tests::noisy\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n");
    let parsed = parse_log(&raw, Some(1));
    assert_eq!(
        "assertion failed after noise",
        parsed.failure_details[0].message
    );
}

#[test]
fn budget_trim_has_one_coherent_failure_notice_and_no_verbose_footer() {
    let fixture = fixture("pytest-failed.log");
    let saved = TempDir::new("budget_trim");
    let log = saved.0.join("saved.log");
    let opts = CompactOptions {
        mode: CompactMode::Test,
        max_tokens: 60,
        save_log: Some(log.clone()),
        allow_spillover: false,
        ..CompactOptions::default()
    };
    let result = compact_text(&fixture, Some(1), &opts);
    let rendered = render_compact_text(&result, 60);
    assert_eq!(
        1,
        rendered.matches("failures omitted").count(),
        "{rendered}"
    );
    assert!(rendered.contains(&log.display().to_string()), "{rendered}");
    assert!(!rendered.contains("% saved"), "{rendered}");
}

#[cfg(unix)]
#[test]
fn large_and_budget_trimmed_typed_logs_still_spill_losslessly() {
    let tmp = TempDir::new("typed_spill");
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/log_corpus/pytest-failed.log");
    let budgeted = run_kit_compact(
        &tmp,
        None,
        &format!("cat '{}'; exit 1", fixture_path.display()),
        &["--max-tokens", "60"],
    );
    assert_eq!(Some(1), budgeted.status.code());
    let stdout = String::from_utf8_lossy(&budgeted.stdout);
    assert!(stdout.contains("see full log: "), "{stdout}");

    let noisy = tmp.0.join("noisy-pytest.log");
    let mut raw = fixture("pytest-failed.log");
    for index in 0..200 {
        raw.push_str(&format!("noise noise noise noise noise {index}\n"));
    }
    fs::write(&noisy, &raw).unwrap();
    let large = run_kit_compact(
        &tmp,
        None,
        &format!("cat '{}'; exit 1", noisy.display()),
        &[],
    );
    assert_eq!(Some(1), large.status.code());
    let stdout = String::from_utf8_lossy(&large.stdout);
    assert!(stdout.contains("log: "), "{stdout}");
}

#[cfg(unix)]
#[test]
fn keep_log_threads_path_into_omission_without_duplicate_footer() {
    let tmp = TempDir::new("keep_log_path");
    let large_path = tmp.0.join("large-cargo.log");
    fs::write(&large_path, large_cargo_log(60)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_prometheus-kit"))
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .env("XDG_RUNTIME_DIR", tmp.0.join("runtime"))
        .args(["compact", "--mode", "test", "--keep-log", "--", "sh", "-c"])
        .arg(format!("cat '{}'; exit 1", large_path.display()))
        .output()
        .unwrap();
    assert_eq!(Some(1), out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap();
    let path = first.strip_prefix("log: ").unwrap();
    assert!(
        stdout.contains(&format!("see full log: {path}")),
        "{stdout}"
    );
    assert_eq!(1, stdout.lines().filter(|line| line.starts_with("log: ")).count(), "{stdout}");
    assert!(!stdout.contains("full log unavailable"), "{stdout}");
}

#[test]
fn untyped_counts_do_not_emit_typed_notices_or_inflate_json() {
    let raw = concat!(
        "running 2 tests\n",
        "test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out\n",
    );
    let opts = CompactOptions {
        mode: CompactMode::Test,
        allow_spillover: false,
        ..CompactOptions::default()
    };
    let result = compact_text(raw, Some(1), &opts);
    assert!(result.failure_details.is_empty());
    assert_eq!(0, result.failure_total);

    let text = render_compact_text(&result, 0);
    assert!(!text.contains("failures omitted"), "{text}");
    assert!(text.contains("% saved"), "{text}");

    let json = render_compact_json(&result, 100);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(false, value["truncated"].as_bool().unwrap(), "{json}");
    assert_eq!(0, value["omitted_items"].as_u64().unwrap(), "{json}");
}

#[test]
fn counts_none_partial_trim_keeps_total_and_one_failure_notice() {
    let opts = CompactOptions {
        mode: CompactMode::Test,
        allow_spillover: false,
        ..CompactOptions::default()
    };
    let result = compact_text(&cargo_log_without_counts(3), Some(1), &opts);
    assert!(result.test_counts.is_none());
    assert_eq!(3, result.failure_details.len());

    let mut chosen = None;
    for max_tokens in 1..200 {
        let rendered = render_compact_text(&result, max_tokens);
        let shown = rendered.matches("rerun: cargo test -- --exact tests::case_").count();
        if shown == 2 {
            chosen = Some(rendered);
            break;
        }
    }
    let rendered = chosen.expect("no budget kept exactly two typed failures");
    assert!(rendered.contains("failures (3):"), "{rendered}");
    assert_eq!(1, rendered.matches("failures omitted").count(), "{rendered}");
    assert!(
        !rendered.contains("omitted lines/diagnostics"),
        "{rendered}"
    );
}

#[test]
fn ultra_tight_finish_text_preserves_the_failure_log_notice() {
    let tmp = TempDir::new("ultra_tight_failure_notice");
    let log = tmp.0.join("saved.log");
    let opts = CompactOptions {
        mode: CompactMode::Test,
        save_log: Some(log.clone()),
        allow_spillover: false,
        ..CompactOptions::default()
    };
    let result = compact_text(&small_pytest_log(12), None, &opts);

    let rendered = render_compact_text(&result, 5);
    assert_eq!(1, rendered.matches("failures omitted").count(), "{rendered}");
    assert!(
        rendered.contains(&format!("see full log: {}", log.display())),
        "{rendered}"
    );
    assert!(!rendered.contains("omitted lines/diagnostics"), "{rendered}");
    assert!(
        !rendered.contains("truncated; see full log or --max-tokens"),
        "{rendered}"
    );
}

#[test]
fn json_exact_budget_edge_counts_only_budget_popped_failures() {
    let raw = concat!(
        "t.py::t0 FAILED [ 0%]\n",
        "=== short test summary info ===\n",
        "FAILED t.py::t0 - E0\n",
        "=== 12 failed in 0.12s ===\n",
    );
    let opts = CompactOptions {
        mode: CompactMode::Test,
        allow_spillover: false,
        ..CompactOptions::default()
    };
    let result = compact_text(raw, Some(1), &opts);
    assert_eq!(1, result.failure_details.len());
    assert_eq!(12, result.failure_total);

    let full = render_compact_json(&result, 0);
    let exact = full.len().div_ceil(4);
    assert_eq!(full, render_compact_json(&result, exact));

    let less = render_compact_json(&result, exact - 1);
    assert!(less.len() <= (exact - 1) * 4, "{less}");
    let value: serde_json::Value = serde_json::from_str(&less).unwrap();
    assert_eq!(true, value["truncated"].as_bool().unwrap(), "{less}");
    assert_eq!(1, value["omitted_items"].as_u64().unwrap(), "{less}");
    assert_eq!(
        0,
        value["failure_details"].as_array().map_or(0, Vec::len),
        "{less}"
    );
}

#[cfg(unix)]
#[test]
fn file_input_with_capped_typed_failures_spills_the_full_log() {
    let tmp = TempDir::new("file_capped_spill");
    let path = tmp.0.join("capped-pytest.log");
    fs::write(&path, small_pytest_log(12)).unwrap();
    let out = run_kit_compact(&tmp, Some(&path), "", &[]);
    assert_eq!(Some(0), out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("failures omitted; see full log: "), "{stdout}");
    assert!(!stdout.contains("full log unavailable"), "{stdout}");
    assert!(stdout.contains("log: "), "{stdout}");
}

fn run_check(root: &PathBuf, store: &PathBuf, fixture_path: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prometheus-check"))
        .env("PROMETHEUS_KIT_NO_METRICS", "1")
        .env("PROMETHEUS_METRICS_DIR", root.join("metrics"))
        .args([
            "--root",
            root.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--",
            "sh",
            "-c",
        ])
        .arg(format!("cat '{}'; exit 1", fixture_path.display()))
        .output()
        .unwrap()
}

#[test]
fn red_check_prints_the_shared_summary_for_all_five_families() {
    let tmp = TempDir::new("check");
    let root = tmp.0.join("repo");
    let store = tmp.0.join("store");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("a.txt"), "hello\n").unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&root)
        .status()
        .unwrap()
        .success());

    for (file, test, message, selector) in cases() {
        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/log_corpus")
            .join(file);
        let output = run_check(&root, &store, &fixture_path);
        assert_eq!(
            Some(1),
            output.status.code(),
            "{file}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("failures ("), "{file}: {stdout}");
        assert!(stdout.contains(test), "{file}: {stdout}");
        assert!(stdout.contains(message), "{file}: {stdout}");
        assert!(
            stdout.contains(&format!("rerun: {selector}")),
            "{file}: {stdout}"
        );
        assert!(stdout.contains("log: "), "{file}: {stdout}");
    }
}
