//! Deterministic `--failed` rerun selection from a typed red test log.

use crate::check::Config;
use crate::logs::parse_log;
use std::path::{Path, PathBuf};

const CARGO_SELECTOR: &str = "cargo test -- --exact ";
const DOTNET_SELECTOR: &str = "dotnet test --filter FullyQualifiedName=";

fn program_base(program: &str) -> String {
    program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase()
}

fn python_base(config: &Config, pytest: bool) -> Vec<String> {
    if let Some(command) = &config.test_command {
        if let Some(program) = command.first() {
            let base = program_base(program);
            if pytest && base == "pytest" {
                return vec![program.clone(), "-q".to_owned()];
            }
            if base.starts_with("python") && command.get(1).map(String::as_str) == Some("-m") {
                let runner = if pytest { "pytest" } else { "unittest" };
                let mut out = vec![program.clone(), "-m".to_owned(), runner.to_owned()];
                if pytest {
                    out.push("-q".to_owned());
                }
                return out;
            }
        }
    }
    let runner = if pytest { "pytest" } else { "unittest" };
    let mut out = vec!["python3".to_owned(), "-m".to_owned(), runner.to_owned()];
    if pytest {
        out.push("-q".to_owned());
    }
    out
}

fn pytest_nodeid(text: &str) -> bool {
    text.contains("::") || (text.ends_with(".py") && !text.contains(char::is_whitespace))
}

fn pytest_summary_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("FAILED ").or_else(|| line.strip_prefix("ERROR ")) else {
        return false;
    };
    pytest_nodeid(rest.split_whitespace().next().unwrap_or_default())
}

fn looks_like_pytest_log(text: &str) -> bool {
    text.contains("short test summary info") || text.lines().any(pytest_summary_line)
}

fn unittest_target(selector: &str) -> String {
    let dotted_path = |path: &str| {
        path.trim_start_matches("./")
            .trim_end_matches(".py")
            .replace('/', ".")
    };
    if let Some((path, rest)) = selector.split_once(".py:") {
        format!("{}.{}", dotted_path(path), rest)
    } else if selector.ends_with(".py") {
        dotted_path(selector)
    } else {
        selector.to_owned()
    }
}

/// Construct the narrowed rerun command for the typed failing selectors in
/// one red log. Python runner executables come from a declared Python
/// `test_command` when one is present; otherwise `python3 -m ...` is used.
pub fn failed_rerun_command(log_text: &str, config: &Config) -> Result<Vec<String>, String> {
    let parsed = parse_log(log_text, None);
    if parsed.failed_tests.is_empty() {
        return Err("no parseable failing selectors".to_owned());
    }

    let mut cargo = Vec::new();
    let mut dotnet = Vec::new();
    let mut python = Vec::new();
    for selector in &parsed.failed_tests {
        if let Some(name) = selector.strip_prefix(CARGO_SELECTOR) {
            cargo.push(name.to_owned());
        } else if let Some(name) = selector.strip_prefix(DOTNET_SELECTOR) {
            dotnet.push(name.to_owned());
        } else {
            python.push(selector.clone());
        }
    }
    let families = usize::from(!cargo.is_empty()) + usize::from(!dotnet.is_empty()) + usize::from(!python.is_empty());
    if families != 1 {
        return Err("failing selectors span multiple test runners".to_owned());
    }

    if !cargo.is_empty() {
        let mut command = vec!["cargo".to_owned(), "test".to_owned(), "--".to_owned(), "--exact".to_owned()];
        command.extend(cargo);
        return Ok(command);
    }
    if !dotnet.is_empty() {
        return Ok(vec![
            "dotnet".to_owned(),
            "test".to_owned(),
            "--filter".to_owned(),
            dotnet
                .iter()
                .map(|name| format!("FullyQualifiedName={name}"))
                .collect::<Vec<_>>()
                .join("|"),
        ]);
    }

    if looks_like_pytest_log(log_text) && python.iter().all(|selector| pytest_nodeid(selector)) {
        let mut command = python_base(config, true);
        command.extend(python);
        Ok(command)
    } else {
        let mut command = python_base(config, false);
        command.extend(python.iter().map(|selector| unittest_target(selector)));
        Ok(command)
    }
}

fn is_red_log(text: &str) -> bool {
    let parsed = parse_log(text, None);
    !parsed.failed_tests.is_empty() || parsed.counts.is_some_and(|counts| counts.failed > 0)
}

/// Newest red-looking `.log` in a Check store log directory. Red means the
/// typed parse saw failing tests or a nonzero failed count; a red log with
/// no selectors is still red, so the caller fails closed on it rather than
/// silently reaching for an older log.
pub fn latest_red_log(logs_dir: &Path) -> Option<PathBuf> {
    let mut logs: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(logs_dir)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("log") {
                return None;
            }
            let modified = entry.metadata().and_then(|meta| meta.modified()).ok()?;
            Some((modified, path))
        })
        .collect();
    logs.sort();
    for (_, path) in logs.into_iter().rev() {
        if std::fs::read_to_string(&path).ok().is_some_and(|text| is_red_log(&text)) {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(command: &[&str]) -> Config {
        Config {
            test_command: Some(command.iter().map(|part| part.to_string()).collect()),
            ..Config::default()
        }
    }

    #[test]
    fn cargo_selectors_combine_into_one_exact_targeted_rerun() {
        let log = "test tests::a ... FAILED\ntest tests::b ... FAILED\ntest result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out\n";
        assert_eq!(
            failed_rerun_command(log, &Config::default()).unwrap(),
            vec!["cargo", "test", "--", "--exact", "tests::a", "tests::b"]
        );
    }

    #[test]
    fn dotnet_selectors_combine_with_an_or_filter() {
        let log = "  Failed A.One [1 ms]\n  Failed A.Two [1 ms]\nFailed!  - Failed:     2, Passed:     0, Skipped:     0, Total:     2, Duration: 1 ms - A.dll\n";
        assert_eq!(
            failed_rerun_command(log, &Config::default()).unwrap(),
            vec!["dotnet", "test", "--filter", "FullyQualifiedName=A.One|FullyQualifiedName=A.Two"]
        );
    }

    #[test]
    fn pytest_nodeids_use_the_declared_python_command() {
        let log = "=== short test summary info ===\nFAILED tests/test_x.py::test_a - AssertionError\nFAILED tests/test_x.py::test_b - AssertionError\n=== 2 failed in 0.1s ===\n";
        assert_eq!(
            failed_rerun_command(log, &config(&["python3.12", "-m", "pytest", "-q"])).unwrap(),
            vec!["python3.12", "-m", "pytest", "-q", "tests/test_x.py::test_a", "tests/test_x.py::test_b"]
        );
    }

    #[test]
    fn unittest_file_class_selectors_become_dotted_unittest_names() {
        let log = "FAIL: test_value (tests.test_app.T)\n\nRan 1 test in 0.1s\n\nFAILED (failures=1)\n";
        assert_eq!(
            failed_rerun_command(log, &config(&["python3.12", "-m", "unittest", "discover"])).unwrap(),
            vec!["python3.12", "-m", "unittest", "tests.test_app.T.test_value"]
        );
    }

    #[test]
    fn empty_and_mixed_selector_sets_fail_closed() {
        assert!(failed_rerun_command("not a test log", &Config::default()).is_err());
        let mixed = "test tests::a ... FAILED\n=== short test summary info ===\nFAILED tests/test_x.py::test_a - AssertionError\n";
        assert!(failed_rerun_command(mixed, &Config::default()).is_err());
    }
}
