//! Golden corpus for test-log parsing (ticket #93): the recovered
//! 33-fixture parity corpus plus the unittest import-error case, as files
//! under `tests/fixtures/log_corpus/`. One test walks the corpus in sorted
//! order and compares the parser's result with each expected result,
//! naming the fixture on failure. There is no regenerate mode: a mismatch
//! is reported, never re-baselined here.

use std::fs;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/log_corpus")
}

#[derive(serde::Deserialize)]
struct Expected {
    exit: Option<i64>,
    counts: Option<serde_json::Value>,
    error: Option<String>,
    failing_lines: Vec<String>,
    failed_tests: Vec<String>,
}

#[test]
fn golden_corpus_matches_parser_output() {
    let dir = corpus_dir();
    let mut logs: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
        .collect();
    logs.sort();
    assert_eq!(
        logs.len(),
        52,
        "corpus: 33 recovered cases + the import-error case + 18 vstest-detailed cases"
    );
    for log_path in logs {
        let name = log_path.file_stem().unwrap().to_string_lossy().to_string();
        let expected: Expected = serde_json::from_str(
            &fs::read_to_string(dir.join(format!("{name}.expected.json"))).unwrap(),
        )
        .unwrap_or_else(|err| panic!("fixture {name}: bad expected file: {err}"));
        // Bytes, not lines: CRLF and ANSI fixtures must reach the parser
        // exactly as stored.
        let text = String::from_utf8(fs::read(&log_path).unwrap())
            .unwrap_or_else(|err| panic!("fixture {name}: log is not UTF-8: {err}"));
        // The corpus compares the typed result in serialized form.
        let doc = serde_json::to_value(prometheus_core::logs::parse_log(&text, expected.exit))
            .unwrap_or_else(|err| panic!("fixture {name}: typed result did not serialize: {err}"));
        let want = serde_json::json!({
            "counts": expected.counts,
            "error": expected.error,
            "failing_lines": expected.failing_lines,
            "failed_tests": expected.failed_tests,
        });
        assert_eq!(doc, want, "fixture {name}");
    }
}
