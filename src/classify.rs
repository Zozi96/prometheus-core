//! Documentation and test path classification for `prometheus-check`.

/// `str.casefold()` for the keys and names the gate folds: full lowercase
/// plus the ß expansion; the gate's folded vocabularies are ASCII.
fn casefold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == 'ß' || c == 'ẞ' {
            out.push_str("ss");
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

const DOC_EXTS: [&str; 3] = [".md", ".rst", ".txt"];
const DATA_DIRS: [&str; 16] = [
    "test", "tests", "spec", "specs", "__tests__", "testdata", "test_data",
    "fixture", "fixtures", "golden", "goldens", "snapshots", "__snapshots__",
    "data", "resources", "assets",
];

/// `(?:requirements|constraints)(?:[-_.][^/]*)?\.txt$|^cmakelists\.txt$|^robots\.txt$`
/// searched in a folded basename.
fn doc_config_match(folded: &str) -> bool {
    if folded == "cmakelists.txt" || folded == "robots.txt" {
        return true;
    }
    for word in ["requirements", "constraints"] {
        let mut from = 0;
        while let Some(found) = folded[from..].find(word) {
            let rest = &folded[from + found + word.len()..];
            if rest == ".txt" {
                return true;
            }
            if let Some(first) = rest.chars().next() {
                if matches!(first, '-' | '_' | '.') && rest[first.len_utf8()..].ends_with(".txt") {
                    return true;
                }
            }
            from += found + 1;
        }
    }
    false
}

/// `_is_doc_path`: a .md/.rst/.txt file that is neither build/dependency
/// config nor test or resource data.
pub fn is_doc_path(name: &str) -> bool {
    let parts: Vec<String> = name
        .replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty())
        .map(casefold)
        .collect();
    let Some(folded) = parts.last() else { return false };
    if parts[..parts.len() - 1].iter().any(|part| DATA_DIRS.contains(&part.as_str())) {
        return false;
    }
    DOC_EXTS.iter().any(|ext| folded.ends_with(ext)) && !doc_config_match(folded)
}

fn is_test_py(base: &str) -> bool {
    let folded = casefold(base);
    folded.ends_with(".py") && (folded.starts_with("test_") || folded.ends_with("_test.py"))
}

const JS_EXTS: [&str; 8] = ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];

/// `_is_test_path`: a test file by each runner's naming convention.
pub fn is_test_path(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|part| !part.is_empty()).collect();
    let Some(base) = parts.last() else { return false };
    let folded = casefold(base);
    if is_test_py(base) || folded == "conftest.py" {
        return true;
    }
    if JS_EXTS.iter().any(|ext| folded.ends_with(&format!("test.{ext}")) || folded.ends_with(&format!("spec.{ext}"))) {
        return true;
    }
    if ["Test.cs", "Tests.cs", "Test.java", "Tests.java"].iter().any(|end| base.ends_with(end)) {
        return true;
    }
    if folded.ends_with("_test.go") || folded.ends_with("_test.rs")
        || (folded.starts_with("test_") && folded.ends_with(".rs"))
    {
        return true;
    }
    if parts.len() > 1 {
        let parent = casefold(parts[parts.len() - 2]);
        if parent == "__tests__" && JS_EXTS.iter().any(|ext| folded.ends_with(&format!(".{ext}"))) {
            return true;
        }
        if parent == "tests" && folded.ends_with(".rs") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{casefold, is_doc_path, is_test_path};

    #[test]
    fn documentation_paths() {
        for path in ["README.md", "docs/guide.rst", "docs/notes.TXT", "Straße.MD", r"docs\guide.md"] {
            assert!(is_doc_path(path), "{path}");
        }
        assert_eq!(casefold("ẞtraße"), "sstrasse");
        for path in [
            "", "README", "src/main.rs", "requirements.txt", "requirements-dev.txt",
            "dev_requirements.txt", "constraints.txt", "constraints.lock.txt", "CMakeLists.txt",
            "robots.txt", "tests/readme.md", r"FIXTURES\readme.txt", "testdata/a.rst",
            "snapshots/a.txt", "data/a.md", "assets/a.md", "test/a.md", "spec/a.md",
            "specs/a.md", "__tests__/a.md", "test_data/a.md", "fixture/a.md",
            "golden/a.md", "goldens/a.md", "__snapshots__/a.md", "resources/a.md",
        ] {
            assert!(!is_doc_path(path), "{path}");
        }
    }

    #[test]
    fn test_paths() {
        for path in [
            "test_foo.py", "foo_test.py", "conftest.py", "test_.py", "FooTest.cs",
            "FooTests.cs", "FooTest.java", "FooTests.java", "foo_test.go", "foo_test.rs",
            "test_foo.rs", "tests/integration.rs", r"tests\integration.rs", r"__tests__\app.ts",
        ] {
            assert!(is_test_path(path), "{path}");
        }
        for ext in ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"] {
            for path in [format!("app.test.{ext}"), format!("app.spec.{ext}"), format!("__tests__/app.{ext}")] {
                assert!(is_test_path(&path), "{path}");
            }
        }
        for path in ["", "test_", "test_.txt", "src/main.rs", "tests/helper.txt", "FooTest.py", "app.ts"] {
            assert!(!is_test_path(path), "{path}");
        }
    }
}
