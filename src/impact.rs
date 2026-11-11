//! Syntactic impact graph and Targeted check selection (spec #43,
//! ticket #52): one deep operation that returns the versioned impact
//! document — the affected behaviour for a change set, its direct and
//! shared consumers, the callers of each changed unit, the preserved
//! interfaces and target seam a Write brief otherwise asks the parent to
//! map in prose, and the Targeted selection with a reason for every
//! widening step (target, module, Full suite).
//!
//! The graph is syntactic — Python imports, .NET project references,
//! Cargo workspace path dependencies — and says so: dynamic dispatch,
//! reflection, and dependency injection in the changed files or their
//! direct consumers mark coverage `uncertain` by construction, and
//! uncertainty widens the selection instead of trusting a graph that
//! cannot see. Facts only: the document never carries a verdict.
//!
//! The caller resolves the two listings the Python route owns — the
//! discovered test files and the `cargo metadata` workspace graph —
//! exactly as the scan's trees are resolved by the caller; everything
//! else is computed here from the work tree. Any failure raises, and
//! the caller reruns the whole computation on the Python route.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use pyo3::prelude::*;

use crate::classify::is_test_path;
use crate::fingerprint::{err, open, status_impl, text, Res};

const SCHEMA: u32 = 1;

fn bx(e: impl std::fmt::Display) -> Box<dyn std::error::Error + Send + Sync> {
    e.to_string().into()
}

// ---------------------------------------------------------------------------
// Small helpers

fn esc(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn str_list(items: &[String], out: &mut String) {
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        esc(item, out);
    }
    out.push(']');
}

fn parent_dir(name: &str) -> &str {
    match name.rfind('/') {
        Some(index) => &name[..index],
        None => ".",
    }
}

/// `_module_names`: the dotted names a Python source file answers to.
fn module_names(source: &str) -> BTreeSet<String> {
    let stem = match source.rfind('.') {
        Some(index) if index > source.rfind('/').map(|i| i + 1).unwrap_or(0) => &source[..index],
        _ => source,
    };
    let parts: Vec<&str> = stem.split('/').collect();
    let mut names = BTreeSet::new();
    if parts.is_empty() {
        return names;
    }
    let last = parts[parts.len() - 1];
    names.insert(last.to_string());
    names.insert(parts.join("."));
    if last == "__init__" && parts.len() > 1 {
        names.insert(parts[parts.len() - 2].to_string());
        names.insert(parts[..parts.len() - 1].join("."));
    }
    names
}

/// Python's `os.path.normpath` for the forward-slash paths references use.
fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().map(|last| *last != "..").unwrap_or(false) {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
            }
            part => out.push(part),
        }
    }
    let joined = out.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

fn read_text(root: &Path, name: &str) -> String {
    match std::fs::read(root.join(name)) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
}

// ---------------------------------------------------------------------------
// The work-tree listing: index entries plus untracked files git does not
// ignore — `git ls-files -c -o --exclude-standard`, via the fingerprint's
// own walks.

fn listing(root: &str) -> Res<BTreeSet<String>> {
    let repo = open(root)?;
    let index = repo.index_or_empty().map_err(bx)?;
    let mut files = BTreeSet::new();
    for entry in index.entries() {
        files.insert(text(entry.path(&index))?);
    }
    let (_changed, untracked, _submodules) = status_impl(root, None)?;
    for path in untracked {
        if !path.ends_with('/') {
            files.insert(path);
        }
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// Python imports, line by line — the hook's `_impact_imports`, which shares
// `_imports`' line rules and keeps the line each name arrives on.

fn import_lines(text: &str) -> Vec<(usize, BTreeSet<String>)> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut names = BTreeSet::new();
        if let Some(rest) = line.strip_prefix("import ") {
            for item in rest.split(',') {
                let name = item.trim().split(" as ").next().unwrap_or("").trim();
                if !name.is_empty() {
                    names.insert(name.to_string());
                }
            }
        } else if line.starts_with("from ") && line.contains(" import ") {
            let body = &line[5..];
            if let Some(split) = body.find(" import ") {
                let package = body[..split].trim();
                names.insert(package.to_string());
                let imported = body[split + 8..].trim().trim_matches(|c| c == '(' || c == ')');
                for item in imported.split(',') {
                    let name = item.trim().split(" as ").next().unwrap_or("").trim();
                    if !name.is_empty() && name != "*" {
                        names.insert(name.to_string());
                        names.insert(format!("{package}.{name}"));
                    }
                }
            }
        }
        if !names.is_empty() {
            out.push((index + 1, names));
        }
    }
    out
}

fn import_names(text: &str) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    for (_line, names) in import_lines(text) {
        all.extend(names);
    }
    all
}

/// Public top-level defs and classes of one Python file, in file order —
/// the hook's `_impact_symbols` line rule.
fn public_symbols(text: &str) -> Vec<String> {
    let mut symbols: Vec<String> = Vec::new();
    for line in text.lines() {
        let rest = if let Some(rest) = strip_keyword(line, "async") {
            match strip_keyword(rest, "def") {
                Some(rest) => Some(rest),
                None => continue,
            }
        } else if let Some(rest) = strip_keyword(line, "def") {
            Some(rest)
        } else if let Some(rest) = strip_keyword(line, "class") {
            Some(rest)
        } else {
            None
        };
        let rest = match rest {
            Some(rest) => rest,
            None => continue,
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let first = match name.chars().next() {
            Some(first) => first,
            None => continue,
        };
        if !(first.is_ascii_alphabetic() || first == '_') || first == '_' {
            continue;
        }
        if !symbols.contains(&name) {
            symbols.push(name);
        }
    }
    symbols
}

/// `keyword` at the start of `line`, followed by whitespace; the remainder.
fn strip_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    if rest.starts_with(|c: char| c.is_whitespace()) {
        Some(rest.trim_start())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Coverage markers: syntactic constructs that hide graph edges.

fn marker_table(name: &str) -> Option<&'static [(&'static str, &'static [&'static str])]> {
    const PY: &[(&str, &[&str])] = &[
        ("dynamic import", &["importlib", "__import__", "pkgutil", "entry_points"]),
        ("dynamic dispatch", &["getattr(", "eval(", "exec(", "globals(", "locals(", "vars("]),
    ];
    const CS: &[(&str, &[&str])] = &[
        ("reflection", &["Assembly.Load", "Activator.CreateInstance", "Type.GetType", "MethodInfo", ".Invoke("]),
        ("dynamic dispatch", &["dynamic "]),
        ("dependency injection", &["AddScoped", "AddTransient", "AddSingleton"]),
    ];
    const JS: &[(&str, &[&str])] = &[
        ("dynamic import", &["import("]),
        ("dynamic dispatch", &["eval("]),
    ];
    const GO: &[(&str, &[&str])] = &[("reflection", &["reflect."])];
    if name.ends_with(".py") {
        Some(PY)
    } else if name.ends_with(".cs") {
        Some(CS)
    } else if name.ends_with(".js") || name.ends_with(".ts") {
        Some(JS)
    } else if name.ends_with(".go") {
        Some(GO)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// .NET: project scan, owner rule, references, and the gate's command — the
// hook's `_impact_dotnet_projects`, `_impact_dotnet_owner`,
// `_dotnet_references`, and `_dotnet_command`, computed over the work tree.

struct Project {
    relative: String,
    is_test: bool,
    text: String,
}

fn scan_projects(root: &Path) -> Vec<Project> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(_) => continue,
            };
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() && path.extension().map(|e| e == "csproj").unwrap_or(false) {
                if let Ok(relative) = path.strip_prefix(root) {
                    let relative = relative.to_string_lossy().replace('\\', "/");
                    if relative.split('/').any(|part| {
                        matches!(part, ".git" | "bin" | "obj" | "node_modules")
                    }) {
                        continue;
                    }
                    let text = read_text(root, &relative);
                    let folded = text.to_lowercase();
                    let is_test = ["test.sdk", "xunit", "nunit", "mstest"]
                        .iter()
                        .any(|marker| folded.contains(marker));
                    found.push(Project { relative, is_test, text });
                }
            }
        }
    }
    found.sort_by(|a, b| a.relative.cmp(&b.relative));
    found
}

/// Every `ProjectReference Include="..."` target named by one project file.
fn project_references(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let bytes = text.as_bytes();
    let mut at = 0;
    while let Some(found) = text[at..].find("ProjectReference") {
        let mut pos = at + found + "ProjectReference".len();
        let rest = &text[pos..];
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            at = pos;
            continue;
        }
        while pos < bytes.len() && (bytes[pos] as char).is_whitespace() {
            pos += 1;
        }
        if !text[pos..].starts_with("Include") {
            at = pos;
            continue;
        }
        pos += "Include".len();
        while pos < bytes.len() && (bytes[pos] as char).is_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() || bytes[pos] != b'=' {
            at = pos;
            continue;
        }
        pos += 1;
        while pos < bytes.len() && (bytes[pos] as char).is_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() || bytes[pos] != b'"' {
            at = pos;
            continue;
        }
        let start = pos + 1;
        match text[start..].find('"') {
            Some(end) => {
                targets.push(text[start..start + end].to_string());
                at = start + end + 1;
            }
            None => break,
        }
    }
    targets
}

/// `_dotnet_references`: the projects in `projects` that `from` references.
fn references_of(from: &Project, projects: &[Project]) -> BTreeSet<String> {
    let base = parent_dir(&from.relative);
    let mut refs = BTreeSet::new();
    for target in project_references(&from.text) {
        let target = target.replace('\\', "/");
        let joined = if base == "." { target } else { format!("{base}/{target}") };
        let normalized = normpath(&joined);
        if projects.iter().any(|pkg| pkg.relative == normalized) {
            refs.insert(normalized);
        }
    }
    refs
}

fn dotnet_owner(projects: &[Project], name: &str) -> Option<String> {
    let directory = parent_dir(name);
    let mut owners: Vec<String> = Vec::new();
    let mut depth: i64 = -1;
    for project in projects {
        let base = parent_dir(&project.relative);
        if base != "." && directory != base && !directory.starts_with(&format!("{base}/")) {
            continue;
        }
        let length = if base == "." { 0 } else { base.len() as i64 };
        if length > depth {
            owners = vec![project.relative.clone()];
            depth = length;
        } else if length == depth {
            owners.push(project.relative.clone());
        }
    }
    if owners.len() == 1 {
        Some(owners.pop().unwrap())
    } else {
        None
    }
}

enum DotnetCommand {
    Test(Vec<String>),
    Build,
    None,
}

/// `_dotnet_command`'s decision, as (kind, test targets in command order).
fn dotnet_command(projects: &[Project], files: &[String], solutions: &[String]) -> DotnetCommand {
    if projects.is_empty() {
        return DotnetCommand::None;
    }
    let mut targets: BTreeSet<String> = BTreeSet::new();
    let mut builds: Vec<String> = Vec::new();
    for name in files {
        let owner = match dotnet_owner(projects, name) {
            Some(owner) => owner,
            None => return DotnetCommand::None,
        };
        let project = projects.iter().find(|pkg| pkg.relative == owner).unwrap();
        if project.is_test {
            targets.insert(owner);
            continue;
        }
        let refs: Vec<String> = projects
            .iter()
            .filter(|pkg| pkg.is_test && references_of(pkg, projects).contains(&owner))
            .map(|pkg| pkg.relative.clone())
            .collect();
        if refs.is_empty() {
            builds.push(owner);
            continue;
        }
        for relative in refs {
            targets.insert(relative);
        }
    }
    if targets.len() == 1 {
        return DotnetCommand::Test(vec![targets.iter().next().unwrap().clone()]);
    }
    if solutions.len() == 1 && !targets.is_empty() {
        return DotnetCommand::Test(vec![solutions[0].clone()]);
    }
    if targets.is_empty() && builds.len() == 1 {
        return DotnetCommand::Build;
    }
    if targets.is_empty() && solutions.len() == 1 {
        return DotnetCommand::Build;
    }
    DotnetCommand::None
}

fn solution_names(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".sln") || name.ends_with(".slnx") {
                names.push(name);
            }
        }
    }
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Cargo: the serialized workspace graph the caller resolved from
// `cargo metadata` — owners and the path-dependency closure, the hook's
// `_impact_cargo` over root-relative directories.

#[derive(Clone)]
struct CargoPkg {
    name: String,
    dir: String,
    deps: Vec<String>,
}

fn parts_len(dir: &str) -> usize {
    if dir == "." {
        0
    } else {
        dir.matches('/').count() + 1
    }
}

fn cargo_owner(cargo: &[CargoPkg], directory: &str) -> String {
    let mut best: Option<&CargoPkg> = None;
    for pkg in cargo {
        let base = &pkg.dir;
        let inside = base == "." || directory == base || directory.starts_with(&format!("{base}/"));
        if inside
            && (best.is_none() || parts_len(base) > parts_len(&best.unwrap().dir))
        {
            best = Some(pkg);
        }
    }
    best.map(|pkg| pkg.name.clone()).unwrap_or_default()
}

struct CargoDoc {
    owners: Vec<String>,
    direct: Vec<String>,
    shared: Vec<String>,
    reliable: bool,
    unmapped: Vec<String>,
}

fn cargo_doc(cargo: &Option<Vec<CargoPkg>>, changed: &[String]) -> CargoDoc {
    let rust: Vec<&String> = changed.iter().filter(|name| name.ends_with(".rs")).collect();
    let cargo = match cargo {
        Some(cargo) => cargo,
        None => {
            return CargoDoc {
                owners: vec![],
                direct: vec![],
                shared: vec![],
                reliable: rust.is_empty(),
                unmapped: vec![],
            }
        }
    };
    let by_dir: HashMap<&str, &str> = cargo
        .iter()
        .map(|pkg| (pkg.dir.as_str(), pkg.name.as_str()))
        .collect();
    let mut owners = BTreeSet::new();
    let mut reliable = true;
    let mut unmapped = Vec::new();
    for name in &rust {
        let package = cargo_owner(cargo, parent_dir(name));
        if package.is_empty() {
            reliable = false;
            unmapped.push((*name).clone());
        } else {
            owners.insert(package);
        }
    }
    let mut selected: BTreeSet<String> = owners.clone();
    loop {
        let mut grew = false;
        for pkg in cargo {
            if selected.contains(&pkg.name) {
                continue;
            }
            if pkg.deps.iter().any(|dep| {
                by_dir.get(dep.as_str()).map(|name| selected.contains(*name)).unwrap_or(false)
            }) {
                selected.insert(pkg.name.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    let direct: Vec<String> = cargo
        .iter()
        .filter(|pkg| {
            !owners.contains(&pkg.name)
                && pkg.deps.iter().any(|dep| {
                    by_dir.get(dep.as_str()).map(|name| owners.contains(*name)).unwrap_or(false)
                })
        })
        .map(|pkg| pkg.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let shared: Vec<String> = selected
        .difference(&owners)
        .filter(|name| !direct.contains(name))
        .cloned()
        .collect();
    CargoDoc {
        owners: owners.into_iter().collect(),
        direct,
        shared,
        reliable,
        unmapped,
    }
}

// A minimal JSON reader for the caller's serialized cargo graph: an array
// of objects with string and string-list values, machine-generated by
// `json.dumps` on the Python side.
enum Json {
    Str(String),
    List(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

struct JsonParser<'a> {
    chars: Vec<char>,
    pos: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl JsonParser<'_> {
    fn parse(text: &str) -> Option<Json> {
        let mut parser = JsonParser { chars: text.chars().collect(), pos: 0, _marker: std::marker::PhantomData };
        let value = parser.value()?;
        parser.skip_ws();
        if parser.pos == parser.chars.len() {
            Some(value)
        } else {
            None
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn value(&mut self) -> Option<Json> {
        self.skip_ws();
        match self.peek()? {
            '[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(']') {
                    self.pos += 1;
                    return Some(Json::List(items));
                }
                loop {
                    items.push(self.value()?);
                    self.skip_ws();
                    match self.peek()? {
                        ',' => self.pos += 1,
                        ']' => {
                            self.pos += 1;
                            return Some(Json::List(items));
                        }
                        _ => return None,
                    }
                }
            }
            '{' => {
                self.pos += 1;
                let mut entries = Vec::new();
                self.skip_ws();
                if self.peek() == Some('}') {
                    self.pos += 1;
                    return Some(Json::Obj(entries));
                }
                loop {
                    self.skip_ws();
                    let key = match self.value()? {
                        Json::Str(key) => key,
                        _ => return None,
                    };
                    self.skip_ws();
                    if self.peek() != Some(':') {
                        return None;
                    }
                    self.pos += 1;
                    let item = self.value()?;
                    entries.push((key, item));
                    self.skip_ws();
                    match self.peek()? {
                        ',' => self.pos += 1,
                        '}' => {
                            self.pos += 1;
                            return Some(Json::Obj(entries));
                        }
                        _ => return None,
                    }
                }
            }
            '"' => self.string().map(Json::Str),
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.peek() != Some('"') {
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.pos += 1;
            match c {
                '"' => return Some(out),
                '\\' => {
                    let escaped = self.peek()?;
                    self.pos += 1;
                    match escaped {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let first = self.hex4()?;
                            if (0xD800..0xDC00).contains(&first) {
                                if self.peek() == Some('\\') {
                                    self.pos += 1;
                                    if self.peek() == Some('u') {
                                        self.pos += 1;
                                        let second = self.hex4()?;
                                        let combined = 0x10000
                                            + ((first - 0xD800) << 10)
                                            + (second - 0xDC00);
                                        out.push(char::from_u32(combined)?);
                                        continue;
                                    }
                                    return None;
                                }
                                return None;
                            }
                            out.push(char::from_u32(first)?);
                        }
                        _ => return None,
                    }
                }
                c => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self.peek()?;
            self.pos += 1;
            value = value * 16 + c.to_digit(16)?;
        }
        Some(value)
    }
}

fn parse_cargo(json: &str) -> Option<Vec<CargoPkg>> {
    if json.is_empty() {
        return None;
    }
    let parsed = JsonParser::parse(json)?;
    let items = match parsed {
        Json::List(items) => items,
        _ => return None,
    };
    let mut cargo = Vec::new();
    for item in items {
        let entries = match item {
            Json::Obj(entries) => entries,
            _ => return None,
        };
        let mut name = String::new();
        let mut dir = String::new();
        let mut deps = Vec::new();
        for (key, value) in entries {
            match (key.as_str(), value) {
                ("name", Json::Str(value)) => name = value,
                ("dir", Json::Str(value)) => dir = value,
                ("deps", Json::List(values)) => {
                    for value in values {
                        match value {
                            Json::Str(value) => deps.push(value),
                            _ => return None,
                        }
                    }
                }
                _ => {}
            }
        }
        cargo.push(CargoPkg { name, dir, deps });
    }
    Some(cargo)
}

// ---------------------------------------------------------------------------
// The document.

struct Caller {
    path: String,
    line: usize,
    references: String,
}

fn impact_impl(
    root: &str,
    changed_in: &[String],
    tests: &Option<Vec<String>>,
    cargo_json: &str,
) -> Res<String> {
    let root_path = Path::new(root);
    let changed: Vec<String> = changed_in.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let changed_set: HashSet<&str> = changed.iter().map(|name| name.as_str()).collect();
    let files = listing(root)?;
    let cargo = parse_cargo(cargo_json);

    let mut texts: HashMap<String, String> = HashMap::new();
    fn text_of(texts: &mut HashMap<String, String>, root: &Path, name: &str) -> String {
        texts
            .entry(name.to_string())
            .or_insert_with(|| read_text(root, name))
            .clone()
    }

    // Affected behaviour: the gate's `_changed_tests` over the given list.
    let sources: Vec<&String> = changed.iter().filter(|name| name.ends_with(".py")).collect();
    let units: HashMap<&str, BTreeSet<String>> = sources
        .iter()
        .map(|name| (name.as_str(), module_names(name)))
        .collect();
    let affected: Option<Vec<String>> = tests.as_ref().map(|tests| {
        let mut selected = Vec::new();
        for test in tests {
            if changed_set.contains(test.as_str()) {
                selected.push(test.clone());
                continue;
            }
            let imports = import_names(&text_of(&mut texts, root_path, test));
            if sources
                .iter()
                .any(|source| !units[source.as_str()].is_disjoint(&imports))
            {
                selected.push(test.clone());
            }
        }
        selected
    });

    // Callers: every Python file whose imports name a changed unit.
    let mut callers: Vec<Caller> = Vec::new();
    for name in &files {
        if !name.ends_with(".py") || changed_set.contains(name.as_str()) {
            continue;
        }
        let lines = import_lines(&text_of(&mut texts, root_path, name));
        for source in &sources {
            for (number, names) in &lines {
                if !units[source.as_str()].is_disjoint(names) {
                    callers.push(Caller {
                        path: name.clone(),
                        line: *number,
                        references: (*source).clone(),
                    });
                    break;
                }
            }
        }
    }
    callers.sort_by(|a, b| (a.path.clone(), a.references.clone()).cmp(&(b.path.clone(), b.references.clone())));
    let caller_paths: HashSet<&str> = callers.iter().map(|entry| entry.path.as_str()).collect();
    let mut caller_modules: BTreeSet<String> = BTreeSet::new();
    for entry in &callers {
        caller_modules.extend(module_names(&entry.path));
    }
    let mut shared: BTreeSet<String> = BTreeSet::new();
    for name in &files {
        if !name.ends_with(".py") || changed_set.contains(name.as_str())
            || caller_paths.contains(name.as_str())
        {
            continue;
        }
        let imports = import_names(&text_of(&mut texts, root_path, name));
        if !caller_modules.is_disjoint(&imports) {
            shared.insert(name.clone());
        }
    }
    if let Some(affected) = &affected {
        for name in affected {
            shared.remove(name);
        }
    }

    // .NET consumers.
    let projects = scan_projects(root_path);
    let sharp: Vec<String> = changed.iter().filter(|name| name.ends_with(".cs")).cloned().collect();
    let (dotnet_consumers, dotnet_shared, dotnet_targets, dotnet_reliable, dotnet_reason) =
        if sharp.is_empty() {
            (Vec::new(), Vec::new(), Vec::new(), true, None)
        } else {
            let mut owners = BTreeSet::new();
            for name in &sharp {
                if let Some(owner) = dotnet_owner(&projects, name) {
                    owners.insert(owner);
                }
            }
            let refs: HashMap<String, BTreeSet<String>> = projects
                .iter()
                .map(|pkg| (pkg.relative.clone(), references_of(pkg, &projects)))
                .collect();
            let reaches = |start: &str, refs: &HashMap<String, BTreeSet<String>>| -> bool {
                let mut seen = HashSet::new();
                let mut stack: Vec<String> = refs.get(start).cloned().unwrap_or_default().into_iter().collect();
                while let Some(current) = stack.pop() {
                    if owners.contains(&current) {
                        return true;
                    }
                    if !seen.insert(current.clone()) {
                        continue;
                    }
                    if let Some(next) = refs.get(&current) {
                        stack.extend(next.iter().cloned());
                    }
                }
                false
            };
            let direct: Vec<String> = projects
                .iter()
                .filter(|pkg| {
                    pkg.is_test && !owners.is_disjoint(&refs[pkg.relative.as_str()])
                })
                .map(|pkg| pkg.relative.clone())
                .collect();
            let shared_list: Vec<String> = projects
                .iter()
                .filter(|pkg| {
                    pkg.is_test && !direct.contains(&pkg.relative) && reaches(&pkg.relative, &refs)
                })
                .map(|pkg| pkg.relative.clone())
                .collect();
            let solutions = solution_names(root_path);
            match dotnet_command(&projects, &sharp, &solutions) {
                DotnetCommand::Test(targets) => {
                    let mut sorted = targets;
                    sorted.sort();
                    (direct, shared_list, sorted, true, None)
                }
                DotnetCommand::Build => (
                    direct,
                    shared_list,
                    Vec::new(),
                    false,
                    Some("impact uncertain: no test project references the changed project"),
                ),
                DotnetCommand::None => (
                    direct,
                    shared_list,
                    Vec::new(),
                    false,
                    Some("impact uncertain: dotnet consumer mapping unavailable"),
                ),
            }
        };

    let cargo = cargo_doc(&cargo, &changed);

    let mut direct_consumers: BTreeSet<String> = BTreeSet::new();
    if let Some(affected) = &affected {
        direct_consumers.extend(affected.iter().cloned());
    }
    direct_consumers.extend(dotnet_consumers.iter().cloned());
    let mut shared_consumers: BTreeSet<String> = shared.clone();
    shared_consumers.extend(dotnet_shared.iter().cloned());

    // Interfaces and the target seam.
    let mut interfaces: Vec<(String, Vec<String>)> = Vec::new();
    let mut seam: Option<String> = None;
    for name in &sources {
        if is_test_path(name) {
            continue;
        }
        let symbols = public_symbols(&text_of(&mut texts, root_path, name));
        if !symbols.is_empty() {
            if seam.is_none() {
                seam = Some(format!("{name}:{}", symbols[0]));
            }
            let mut sorted = symbols.clone();
            sorted.sort();
            interfaces.push(((*name).clone(), sorted));
        }
    }

    // Reliability, mirroring `_impact_of` over the three mappings.
    let mut reliable = true;
    let mut reliability_reasons: Vec<String> = Vec::new();
    let py_sources: Vec<&String> = sources
        .iter()
        .filter(|name| !is_test_path(name))
        .cloned()
        .collect();
    if tests.is_none() {
        reliable = false;
    } else if !py_sources.is_empty() && affected.as_ref().map(|list| list.is_empty()).unwrap_or(false) {
        reliable = false;
        for name in &py_sources {
            reliability_reasons.push(format!(
                "impact uncertain: changed source has no consumer test ({name})"
            ));
        }
    }
    if !dotnet_reliable {
        reliable = false;
        reliability_reasons.push(dotnet_reason.unwrap().to_string());
    }
    if !cargo.reliable {
        reliable = false;
        if cargo_json.is_empty() {
            reliability_reasons.push("impact uncertain: cargo workspace unavailable".to_string());
        } else {
            for name in &cargo.unmapped {
                reliability_reasons.push(format!(
                    "impact uncertain: file maps to no workspace member ({name})"
                ));
            }
        }
    }

    // Coverage: markers in the changed files, their callers, and the
    // affected tests mark the graph uncertain by construction.
    let mut marked: BTreeSet<String> = changed_set.iter().map(|name| name.to_string()).collect();
    for entry in &callers {
        marked.insert(entry.path.clone());
    }
    if let Some(affected) = &affected {
        marked.extend(affected.iter().cloned());
    }
    let mut coverage_reasons: Vec<String> = Vec::new();
    for name in &marked {
        if let Some(table) = marker_table(name) {
            let text = text_of(&mut texts, root_path, name);
            for (kind, markers) in table {
                if markers.iter().any(|marker| text.contains(marker)) {
                    coverage_reasons.push(format!("coverage uncertain: {kind} in {name}"));
                }
            }
        }
    }
    let coverage = if coverage_reasons.is_empty() { "certain" } else { "uncertain" };

    // The module boundary, `_python_module_command`'s directory rule.
    let module_target = python_module_target(root_path, &changed);

    // The selection ladder.
    let (level, sel_tests, sel_packages, sel_projects, sel_module, sel_reasons) = selection(
        &changed,
        &affected,
        reliable,
        &reliability_reasons,
        coverage,
        &coverage_reasons,
        &module_target,
        &cargo,
        &dotnet_targets,
    );

    // Serialize.
    let mut out = String::new();
    out.push_str("{\"schema\":");
    out.push_str(&SCHEMA.to_string());
    out.push_str(",\"changed\":");
    str_list(&changed, &mut out);
    out.push_str(",\"affected\":");
    match &affected {
        None => out.push_str("null"),
        Some(list) => str_list(list, &mut out),
    }
    out.push_str(",\"affected_unmeasurable\":");
    match &affected {
        None => esc("test-listing-unavailable", &mut out),
        Some(_) => out.push_str("null"),
    }
    out.push_str(",\"callers\":[");
    for (index, entry) in callers.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"line\":");
        out.push_str(&entry.line.to_string());
        out.push_str(",\"path\":");
        esc(&entry.path, &mut out);
        out.push_str(",\"references\":");
        esc(&entry.references, &mut out);
        out.push('}');
    }
    out.push_str("],\"consumers\":{\"direct\":");
    str_list(&direct_consumers.into_iter().collect::<Vec<_>>(), &mut out);
    out.push_str(",\"shared\":");
    str_list(&shared_consumers.into_iter().collect::<Vec<_>>(), &mut out);
    out.push_str("},\"interfaces\":[");
    for (index, (path, symbols)) in interfaces.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"path\":");
        esc(path, &mut out);
        out.push_str(",\"symbols\":");
        str_list(symbols, &mut out);
        out.push('}');
    }
    out.push_str("],\"seam\":");
    match &seam {
        None => out.push_str("null"),
        Some(seam) => esc(seam, &mut out),
    }
    out.push_str(",\"coverage\":");
    esc(coverage, &mut out);
    out.push_str(",\"coverage_reasons\":");
    str_list(&coverage_reasons, &mut out);
    out.push_str(",\"reliable\":");
    out.push_str(if reliable { "true" } else { "false" });
    out.push_str(",\"reliability_reasons\":");
    str_list(&reliability_reasons, &mut out);
    out.push_str(",\"projects\":{\"dotnet\":{\"consumers\":");
    str_list(&dotnet_consumers, &mut out);
    out.push_str(",\"shared\":");
    str_list(&dotnet_shared, &mut out);
    out.push_str(",\"targets\":");
    str_list(&dotnet_targets, &mut out);
    out.push_str(",\"reliable\":");
    out.push_str(if dotnet_reliable { "true" } else { "false" });
    out.push_str("},\"cargo\":{\"owners\":");
    str_list(&cargo.owners, &mut out);
    out.push_str(",\"direct\":");
    str_list(&cargo.direct, &mut out);
    out.push_str(",\"shared\":");
    str_list(&cargo.shared, &mut out);
    out.push_str(",\"reliable\":");
    out.push_str(if cargo.reliable { "true" } else { "false" });
    out.push_str("}},\"selection\":{\"level\":");
    esc(level, &mut out);
    out.push_str(",\"tests\":");
    str_list(&sel_tests, &mut out);
    out.push_str(",\"packages\":");
    str_list(&sel_packages, &mut out);
    out.push_str(",\"projects\":");
    str_list(&sel_projects, &mut out);
    out.push_str(",\"module\":");
    match &sel_module {
        None => out.push_str("null"),
        Some(target) => esc(target, &mut out),
    }
    out.push_str(",\"reasons\":");
    str_list(&sel_reasons, &mut out);
    out.push_str("}}");
    Ok(out)
}

/// `_python_module_command`'s boundary: one shared test directory, or None.
fn python_module_target(root: &Path, changed: &[String]) -> Option<String> {
    let mut dirs: Vec<String> = Vec::new();
    for name in changed {
        if !name.ends_with(".py") {
            continue;
        }
        let parent = parent_dir(name);
        if parent == "." {
            return None;
        }
        let owned: Vec<String> = [format!("tests/{parent}"), format!("{parent}/tests")]
            .into_iter()
            .filter(|candidate| root.join(candidate).is_dir())
            .collect();
        if owned.is_empty() {
            return None;
        }
        dirs.extend(owned);
    }
    let unique: BTreeSet<String> = dirs.into_iter().collect();
    if unique.len() != 1 {
        return None;
    }
    unique.into_iter().next()
}

/// The selection ladder — the hook's `_impact_selection`, step for step.
#[allow(clippy::too_many_arguments)]
fn selection(
    changed: &[String],
    affected: &Option<Vec<String>>,
    reliable: bool,
    reliability_reasons: &[String],
    coverage: &str,
    coverage_reasons: &[String],
    module_target: &Option<String>,
    cargo: &CargoDoc,
    dotnet_targets: &[String],
) -> (&'static str, Vec<String>, Vec<String>, Vec<String>, Option<String>, Vec<String>) {
    if changed.is_empty() {
        return ("targeted", vec![], vec![], vec![], None, vec![]);
    }
    let targeted = affected.as_ref().map(|list| !list.is_empty()).unwrap_or(false)
        || !cargo.owners.is_empty()
        || !dotnet_targets.is_empty();
    if affected.is_some() && targeted && reliable && coverage == "certain" {
        let mut packages = cargo.owners.clone();
        packages.extend(cargo.direct.iter().cloned());
        packages.extend(cargo.shared.iter().cloned());
        return (
            "targeted",
            affected.clone().unwrap(),
            packages,
            dotnet_targets.to_vec(),
            None,
            vec![],
        );
    }
    let mut causes: Vec<String> = Vec::new();
    match affected {
        None => causes.push("impact uncertain: test listing unavailable".to_string()),
        Some(_) => {
            causes.extend(reliability_reasons.iter().cloned());
            if coverage == "uncertain" {
                causes.extend(coverage_reasons.iter().cloned());
            }
        }
    }
    let (level, noun) = match module_target {
        Some(_) => ("module", "the module"),
        None => ("full", "the full suite"),
    };
    let reasons = if causes.is_empty() {
        if module_target.is_some() {
            vec!["affected selection empty; widened to the module".to_string()]
        } else {
            vec!["module boundary uncertain; widened to the full suite".to_string()]
        }
    } else {
        causes
            .iter()
            .map(|cause| format!("{cause}; widened to {noun}"))
            .collect()
    };
    (level, vec![], vec![], vec![], module_target.clone(), reasons)
}

#[pyfunction]
fn impact(
    py: Python<'_>,
    root: String,
    changed: Vec<String>,
    tests: Option<Vec<String>>,
    cargo_json: String,
) -> PyResult<String> {
    py.detach(|| impact_impl(&root, &changed, &tests, &cargo_json)).map_err(err)
}

/// The impact document for the standalone `prometheus-check` runner
/// (ADR-0010): the same JSON the Python route receives. `tests` is the
/// discovered test-file listing, or `None` when discovery failed — the
/// document then widens fail-closed and records why.
pub fn impact_document(
    root: &str,
    changed: &[String],
    tests: Option<Vec<String>>,
    cargo_json: &str,
) -> Option<String> {
    impact_impl(root, changed, &tests, cargo_json).ok()
}

/// Register the impact graph on the `prometheus_core` module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(impact, m)?)?;
    Ok(())
}
