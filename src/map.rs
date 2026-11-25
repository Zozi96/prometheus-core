//! Deterministic repository map with line counts and optional top-level symbols (`prometheus-kit map`).

use crate::budget::{self, KeepPolicy};
use crate::kit_util::is_noise_path;
use crate::outline::{outline_source, Lang, OutlineOptions};
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_MAP_MAX_DEPTH: usize = 3;
pub const DEFAULT_MAP_MAX_SYMBOLS: usize = 6;
pub const DEFAULT_MAP_MAX_TOKENS: usize = 2000;
const MAX_MAP_SYMBOL_BYTES: u64 = 2 * 1024 * 1024;
const BINARY_PROBE_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct MapOptions {
    pub root: PathBuf,
    pub max_depth: usize,
    pub include_symbols: bool,
    pub max_symbols_per_file: usize,
    pub globs: Vec<String>,
    pub lang_type: Option<Lang>,
    pub max_tokens: usize,
    pub include_noise: bool,
    pub hidden: bool,
    pub no_ignore: bool,
}

impl Default for MapOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            max_depth: DEFAULT_MAP_MAX_DEPTH,
            include_symbols: false,
            max_symbols_per_file: DEFAULT_MAP_MAX_SYMBOLS,
            globs: Vec::new(),
            lang_type: None,
            max_tokens: DEFAULT_MAP_MAX_TOKENS,
            include_noise: false,
            hidden: false,
            no_ignore: false,
        }
    }
}

#[derive(Debug)]
pub enum MapError {
    Usage(String),
    Io(String),
}

impl MapError {
    pub fn exit_code(&self) -> i32 {
        match self {
            MapError::Usage(_) => 2,
            MapError::Io(_) => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            MapError::Usage(m) | MapError::Io(m) => m,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MapFileEntry {
    pub name: String,
    pub lines: usize,
    pub binary: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub extra_symbols: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct MapDirEntry {
    pub name: String,
    pub total_files: usize,
    pub total_lines: usize,
    pub collapsed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dirs: Vec<MapDirEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<MapFileEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MapResult {
    pub root: String,
    pub total_files: usize,
    pub total_lines: usize,
    pub tree: MapDirEntry,
    pub truncated: bool,
    pub omitted_entries: usize,
}

struct TempDirNode {
    dirs: BTreeMap<String, TempDirNode>,
    files: Vec<MapFileEntry>,
}

impl TempDirNode {
    fn new() -> Self {
        Self {
            dirs: BTreeMap::new(),
            files: Vec::new(),
        }
    }

    fn insert(&mut self, parts: &[&str], entry: MapFileEntry) {
        if parts.len() <= 1 {
            self.files.push(entry);
            return;
        }
        let child = self
            .dirs
            .entry(parts[0].to_owned())
            .or_insert_with(TempDirNode::new);
        child.insert(&parts[1..], entry);
    }
}

fn scan_file_meta(path: &Path, include_symbols: bool, max_syms: usize) -> (usize, bool, Vec<String>, usize) {
    let Ok(meta) = std::fs::metadata(path) else {
        return (0, false, Vec::new(), 0);
    };
    if !meta.is_file() {
        return (0, false, Vec::new(), 0);
    }
    let Ok(mut file) = File::open(path) else {
        return (0, false, Vec::new(), 0);
    };

    let want_syms = include_symbols
        && meta.len() <= MAX_MAP_SYMBOL_BYTES
        && Lang::from_path(path).is_some();

    if want_syms {
        let mut buf = Vec::with_capacity((meta.len() as usize).min(256 * 1024));
        if file.read_to_end(&mut buf).is_err() {
            return (0, false, Vec::new(), 0);
        }
        if buf[..buf.len().min(BINARY_PROBE_BYTES)].contains(&0) {
            return (0, true, Vec::new(), 0);
        }
        let text = String::from_utf8_lossy(&buf);
        let lines = text.lines().count();
        let lang = Lang::from_path(path).unwrap();
        let doc = outline_source(
            &path.to_string_lossy(),
            &text,
            lang,
            &OutlineOptions::default(),
        );
        let top_items = if doc.items.len() == 1
            && doc.items[0].kind == "namespace"
            && !doc.items[0].children.is_empty()
        {
            &doc.items[0].children
        } else {
            &doc.items
        };
        let total = top_items.len();
        let syms: Vec<String> = top_items
            .iter()
            .take(max_syms)
            .map(|it| it.name.clone())
            .collect();
        let extra = total.saturating_sub(syms.len());
        return (lines, false, syms, extra);
    }

    // Fast streaming byte line-count without keeping file contents in memory
    let mut chunk = [0u8; 32 * 1024];
    let mut probed = false;
    let mut lines = 0usize;
    let mut total_bytes = 0usize;
    let mut last_byte = b'\n';
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if !probed {
                    let probe = &chunk[..n.min(BINARY_PROBE_BYTES)];
                    if probe.contains(&0) {
                        return (0, true, Vec::new(), 0);
                    }
                    probed = true;
                }
                lines += chunk[..n].iter().filter(|&&b| b == b'\n').count();
                last_byte = chunk[n - 1];
                total_bytes += n;
            }
            Err(_) => break,
        }
    }
    if total_bytes > 0 && last_byte != b'\n' {
        lines += 1;
    }
    (lines, false, Vec::new(), 0)
}

fn finalize_dir(name: String, mut node: TempDirNode, depth: usize, max_depth: usize) -> MapDirEntry {
    node.files.sort_by(|a, b| a.name.cmp(&b.name));
    let mut dirs = Vec::with_capacity(node.dirs.len());
    let mut total_files = node.files.len();
    let mut total_lines: usize = node.files.iter().map(|f| f.lines).sum();

    for (child_name, child_node) in node.dirs {
        let built = finalize_dir(child_name, child_node, depth + 1, max_depth);
        total_files += built.total_files;
        total_lines += built.total_lines;
        dirs.push(built);
    }

    let collapse = max_depth > 0 && depth >= max_depth && (!dirs.is_empty() || !node.files.is_empty());
    if collapse {
        MapDirEntry {
            name,
            total_files,
            total_lines,
            collapsed: true,
            dirs: Vec::new(),
            files: Vec::new(),
        }
    } else {
        MapDirEntry {
            name,
            total_files,
            total_lines,
            collapsed: false,
            dirs,
            files: node.files,
        }
    }
}

pub fn execute_map(opts: &MapOptions) -> Result<MapResult, MapError> {
    if !opts.root.exists() {
        return Err(MapError::Io(format!(
            "{}: No such file or directory",
            opts.root.display()
        )));
    }
    if !opts.root.is_dir() {
        return Err(MapError::Io(format!(
            "{}: not a directory",
            opts.root.display()
        )));
    }

    let mut wb = WalkBuilder::new(&opts.root);
    wb.hidden(!opts.hidden)
        .git_ignore(!opts.no_ignore)
        .git_global(!opts.no_ignore)
        .git_exclude(!opts.no_ignore)
        .ignore(!opts.no_ignore)
        .parents(!opts.no_ignore);

    if !opts.globs.is_empty() {
        let mut ob = OverrideBuilder::new(&opts.root);
        for g in &opts.globs {
            ob.add(g)
                .map_err(|e| MapError::Usage(format!("invalid --glob `{g}`: {e}")))?;
        }
        let overrides = ob
            .build()
            .map_err(|e| MapError::Usage(format!("invalid --glob: {e}")))?;
        wb.overrides(overrides);
    }

    let mut root_node = TempDirNode::new();
    for entry in wb.build().flatten() {
        let path = entry.path();
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let Ok(rel) = path.strip_prefix(&opts.root) else {
            continue;
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str.is_empty() {
            continue;
        }
        if !opts.include_noise && is_noise_path(&rel_str) {
            continue;
        }
        if let Some(wanted) = opts.lang_type {
            if Lang::from_path(path) != Some(wanted) {
                continue;
            }
        }
        let parts: Vec<&str> = rel_str.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        let (lines, binary, symbols, extra_symbols) =
            scan_file_meta(path, opts.include_symbols, opts.max_symbols_per_file);
        root_node.insert(
            &parts,
            MapFileEntry {
                name: (*parts.last().unwrap()).to_owned(),
                lines,
                binary,
                symbols,
                extra_symbols,
            },
        );
    }

    let root_name = opts
        .root
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty() && s != ".")
        .unwrap_or_else(|| opts.root.to_string_lossy().to_string());

    let tree = finalize_dir(root_name.clone(), root_node, 0, opts.max_depth);
    let total_files = tree.total_files;
    let total_lines = tree.total_lines;

    Ok(MapResult {
        root: root_name,
        total_files,
        total_lines,
        tree,
        truncated: false,
        omitted_entries: 0,
    })
}

/// `map`'s Keep policy is **upper levels**: one give-up collapses the
/// deepest directory the shared step reaches (children before their
/// parents), then drops root entries. Shared by text and `--json`, so
/// both formats collapse the same directories in the same order.
fn map_trim_step(res: &mut MapResult) -> bool {
    let dropped = collapse_deepest_or_trim(&mut res.tree);
    if dropped == 0 {
        return false;
    }
    res.truncated = true;
    res.omitted_entries += dropped;
    true
}

/// The `map` truncation notice, without its trailing newline. Wording
/// is unchanged.
fn map_notice(omitted_entries: usize) -> String {
    format!("... (+{omitted_entries} omitted entries; narrow with --depth/--glob or --max-tokens)")
}

pub fn render_map_text(res: &MapResult, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return render_map_text_inner(res);
    }
    let mut trimmed = res.clone();
    budget::trim_structured(
        &mut trimmed,
        max_tokens,
        render_map_text_inner,
        map_trim_step,
    );
    let notice = if trimmed.truncated {
        map_notice(trimmed.omitted_entries)
    } else {
        String::new()
    };
    budget::finish_text(
        render_map_text_inner(&trimmed),
        max_tokens,
        KeepPolicy::UpperLevels,
        &notice,
    )
}

fn render_map_text_inner(res: &MapResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{}/ [{} files, {} lines]",
        res.root, res.total_files, res.total_lines
    ));

    fn collect_lines(dir: &MapDirEntry, indent: usize, out: &mut Vec<String>) {
        let pad = "  ".repeat(indent);
        for sub in &dir.dirs {
            if sub.collapsed {
                out.push(format!(
                    "{pad}{}/ ({} files, {}L)",
                    sub.name, sub.total_files, sub.total_lines
                ));
            } else {
                out.push(format!(
                    "{pad}{}/ ({} files, {}L)",
                    sub.name, sub.total_files, sub.total_lines
                ));
                collect_lines(sub, indent + 1, out);
            }
        }
        for f in &dir.files {
            if f.binary {
                out.push(format!("{pad}{} (binary)", f.name));
            } else if f.symbols.is_empty() {
                out.push(format!("{pad}{} ({}L)", f.name, f.lines));
            } else {
                let extra = if f.extra_symbols > 0 {
                    format!(", +{}", f.extra_symbols)
                } else {
                    String::new()
                };
                out.push(format!(
                    "{pad}{} ({}L) [{}{extra}]",
                    f.name,
                    f.lines,
                    f.symbols.join(", ")
                ));
            }
        }
    }

    collect_lines(&res.tree, 1, &mut lines);

    if res.truncated {
        lines.push(map_notice(res.omitted_entries));
    }
    format!("{}\n", lines.join("\n"))
}

/// Find the deepest collapsible directory under `dir`: a directory
/// that is not collapsed and still has children. Depth is compared
/// across the WHOLE tree, not just along the last branch, so a
/// shallow directory never collapses while a deeper one stays
/// expanded (the upper-levels Keep policy, ADR-0017). Ties go to the
/// last candidate in sibling order, preserving the previous
/// behaviour among equals. Returns the index path from `dir` to the
/// chosen directory.
fn deepest_collapsible_path(
    dir: &MapDirEntry,
    depth: usize,
    path: &mut Vec<usize>,
    best: &mut Option<(usize, Vec<usize>)>,
) {
    for (idx, sub) in dir.dirs.iter().enumerate() {
        if sub.collapsed || (sub.dirs.is_empty() && sub.files.is_empty()) {
            continue;
        }
        path.push(idx);
        let candidate_depth = depth + 1;
        let is_better = match best {
            None => true,
            Some((best_depth, _)) => candidate_depth >= *best_depth,
        };
        if is_better {
            *best = Some((candidate_depth, path.clone()));
        }
        deepest_collapsible_path(sub, candidate_depth, path, best);
        path.pop();
    }
}

fn collapse_deepest_dir(dir: &mut MapDirEntry) -> usize {
    let mut best = None;
    deepest_collapsible_path(dir, 0, &mut Vec::new(), &mut best);
    let Some((_, path)) = best else {
        return 0;
    };
    let mut node = dir;
    for idx in &path {
        node = &mut node.dirs[*idx];
    }
    let dropped = node.dirs.len() + node.files.len();
    node.dirs.clear();
    node.files.clear();
    node.collapsed = true;
    dropped.max(1)
}

fn collapse_deepest_or_trim(dir: &mut MapDirEntry) -> usize {
    let collapsed = collapse_deepest_dir(dir);
    if collapsed > 0 {
        return collapsed;
    }
    if !dir.files.is_empty() {
        dir.files.pop();
        return 1;
    }
    if !dir.dirs.is_empty() {
        dir.dirs.pop();
        return 1;
    }
    0
}

pub fn render_map_json(res: &MapResult, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return serde_json::to_string(res).unwrap_or_else(|_| "{}".to_owned());
    }
    // Same upper-levels policy as text, measured against the JSON
    // document; the smallest valid document wins over the budget.
    let mut trimmed = res.clone();
    budget::trim_structured(
        &mut trimmed,
        max_tokens,
        |s| serde_json::to_string(s).unwrap_or_else(|_| "{}".to_owned()),
        map_trim_step,
    );
    serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let d = std::env::temp_dir().join(format!("prom_map_{tag}_{}_{nanos}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
        fn write(&self, rel: &str, data: &[u8]) {
            let p = self.0.join(rel);
            if let Some(par) = p.parent() {
                std::fs::create_dir_all(par).unwrap();
            }
            std::fs::write(p, data).unwrap();
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample_map() -> MapResult {
        let file = |name: &str| MapFileEntry {
            name: name.to_owned(),
            lines: 10,
            binary: false,
            symbols: vec![],
            extra_symbols: 0,
        };
        fn dir(
            name: &str,
            total_files: usize,
            total_lines: usize,
            dirs: Vec<MapDirEntry>,
            files: Vec<MapFileEntry>,
        ) -> MapDirEntry {
            MapDirEntry {
                name: name.to_owned(),
                total_files,
                total_lines,
                collapsed: false,
                dirs,
                files,
            }
        }
        MapResult {
            root: "r".to_owned(),
            total_files: 10,
            total_lines: 100,
            tree: dir(
                "r",
                10,
                100,
                vec![
                    dir(
                        "a",
                        5,
                        50,
                        vec![dir(
                            "b",
                            4,
                            40,
                            vec![],
                            vec![file("b1.rs"), file("b2.rs"), file("b3.rs"), file("b4.rs")],
                        )],
                        vec![file("a1.rs")],
                    ),
                    dir(
                        "c",
                        4,
                        40,
                        vec![],
                        vec![file("c1.rs"), file("c2.rs"), file("c3.rs"), file("c4.rs")],
                    ),
                ],
                vec![file("top.rs")],
            ),
            truncated: false,
            omitted_entries: 0,
        }
    }

    // Exact-output budget-edge tests (#101).
    #[test]
    fn map_text_budget_edge_exact_fit_one_token_less_and_below_notice() {
        let res = sample_map();
        let full = render_map_text(&res, 0);
        assert_eq!(
            full,
            "r/ [10 files, 100 lines]\n  a/ (5 files, 50L)\n    b/ (4 files, 40L)\n\
             \u{20}     b1.rs (10L)\n      b2.rs (10L)\n      b3.rs (10L)\n      b4.rs (10L)\n\
             \u{20}   a1.rs (10L)\n  c/ (4 files, 40L)\n\
             \u{20}   c1.rs (10L)\n    c2.rs (10L)\n    c3.rs (10L)\n    c4.rs (10L)\n  top.rs (10L)\n"
        );
        let exact = full.len().div_ceil(4);
        assert_eq!(render_map_text(&res, exact), full);
        // One token less: upper levels survive, a and the root
        // entries stay, and the notice survives on its own line.
        // UPDATED for the Devin Review finding "Shallow map entries
        // trimmed first": with depth compared across the whole tree,
        // b (depth 2) collapses first and that alone fits — its file
        // lines are the longest — so c stays expanded and only 4
        // entries are omitted. The old order collapsed c first, which
        // did not fit, and ended with both collapsed (+8).
        let less = render_map_text(&res, exact - 1);
        assert_eq!(
            less,
            "r/ [10 files, 100 lines]\n  a/ (5 files, 50L)\n    b/ (4 files, 40L)\n\
             \u{20}   a1.rs (10L)\n  c/ (4 files, 40L)\n\
             \u{20}   c1.rs (10L)\n    c2.rs (10L)\n    c3.rs (10L)\n    c4.rs (10L)\n  top.rs (10L)\n\
             ... (+4 omitted entries; narrow with --depth/--glob or --max-tokens)\n"
        );
        assert!(less.len() <= (exact - 1) * 4);
        // Budget smaller than the notice: the notice alone.
        assert_eq!(
            render_map_text(&res, 10),
            "... (+13 omitted entries; narrow with --depth/--glob or --max-tokens)\n"
        );
    }

    #[test]
    fn map_json_budget_edge_exact_fit_one_token_less_and_below_smallest_valid() {
        let res = sample_map();
        let full = render_map_json(&res, 0);
        let exact = full.len().div_ceil(4);
        assert_eq!(render_map_json(&res, exact), full);
        // One token less, measured against the JSON size: only the
        // first collapse is given up. UPDATED for the Devin Review
        // finding "Shallow map entries trimmed first": the first
        // collapse is now b (depth 2, the deepest directory in the
        // whole tree), not c (depth 1, last branch) as the previous
        // last-branch search picked.
        let less = render_map_json(&res, exact - 1);
        let parsed: serde_json::Value = serde_json::from_str(&less).unwrap();
        assert!(less.len() <= (exact - 1) * 4);
        assert_eq!(parsed["truncated"], serde_json::Value::Bool(true));
        assert_eq!(parsed["omitted_entries"], serde_json::Value::from(4));
        let dirs = parsed["tree"]["dirs"].as_array().unwrap();
        assert_eq!(dirs[1]["name"], serde_json::Value::String("c".to_owned()));
        assert_eq!(dirs[1]["collapsed"], serde_json::Value::Bool(false));
        assert_eq!(dirs[0]["collapsed"], serde_json::Value::Bool(false));
        assert_eq!(
            dirs[0]["dirs"][0]["collapsed"],
            serde_json::Value::Bool(true)
        );
        // Below the smallest valid document: validity wins.
        let tiny = render_map_json(&res, 1);
        assert_eq!(
            tiny,
            "{\"root\":\"r\",\"total_files\":10,\"total_lines\":100,\
             \"tree\":{\"name\":\"r\",\"total_files\":10,\"total_lines\":100,\"collapsed\":false},\
             \"truncated\":true,\"omitted_entries\":13}"
        );
        let _: serde_json::Value = serde_json::from_str(&tiny).unwrap();
    }

    #[test]
    fn map_collapse_order_is_shared_and_deepest_first() {
        // The step both formats use. UPDATED for the Devin Review
        // finding "Shallow map entries trimmed first": the previous
        // order collapsed c (depth 1, last branch) before b (depth 2)
        // because the search only walked the last branch; depth is
        // now compared across the whole tree, so b collapses first,
        // then c (last among the depth-1 ties), then a.
        let mut res = sample_map();
        assert!(map_trim_step(&mut res));
        assert!(
            res.tree.dirs[0].dirs[0].collapsed,
            "b (deepest) collapses first"
        );
        assert!(!res.tree.dirs[1].collapsed);
        assert!(map_trim_step(&mut res));
        assert!(res.tree.dirs[1].collapsed, "c collapses second");
        assert!(!res.tree.dirs[0].collapsed);
        assert!(map_trim_step(&mut res));
        assert!(res.tree.dirs[0].collapsed, "a collapses after its child");
        // And the JSON at a budget that forces exactly two collapses
        // keeps the same directories collapsed as the text does at its
        // own two-collapse budget (each format measured against
        // itself, per ADR-0017 D5).
        let res = sample_map();
        let parsed: serde_json::Value = serde_json::from_str(&render_map_json(&res, 120)).unwrap();
        let dirs = parsed["tree"]["dirs"].as_array().unwrap();
        assert_eq!(dirs[1]["collapsed"], serde_json::Value::Bool(true), "c collapsed in json");
        assert_eq!(
            dirs[0]["dirs"][0]["collapsed"],
            serde_json::Value::Bool(true),
            "b collapsed in json"
        );
        assert_eq!(
            dirs[0]["collapsed"],
            serde_json::Value::Bool(false),
            "a still expanded"
        );
    }

    #[test]
    fn map_collapse_prefers_deepest_across_branches() {
        // Regression (Devin Review, "Shallow map entries trimmed
        // first"): with uneven sibling depths — a/b nested in the
        // FIRST branch, a shallow z in the last — the first collapse
        // must be the deepest directory (a/b), not the shallow last
        // branch (z) the old last-branch search reached first.
        let file = |name: &str| MapFileEntry {
            name: name.to_owned(),
            lines: 1,
            binary: false,
            symbols: vec![],
            extra_symbols: 0,
        };
        let dir = |name: &str, dirs: Vec<MapDirEntry>, files: Vec<MapFileEntry>| {
            let total_files = files.len()
                + dirs
                    .iter()
                    .map(|d: &MapDirEntry| d.total_files)
                    .sum::<usize>();
            MapDirEntry {
                name: name.to_owned(),
                total_files,
                total_lines: total_files,
                collapsed: false,
                dirs,
                files,
            }
        };
        let mut res = MapResult {
            root: "repo".to_owned(),
            total_files: 2,
            total_lines: 2,
            tree: dir(
                "repo",
                vec![
                    dir("a", vec![dir("b", vec![], vec![file("item.rs")])], vec![]),
                    dir("z", vec![], vec![file("some_file.rs")]),
                ],
                vec![],
            ),
            truncated: false,
            omitted_entries: 0,
        };
        assert!(map_trim_step(&mut res));
        assert!(
            res.tree.dirs[0].dirs[0].collapsed,
            "a/b (depth 2) collapses first"
        );
        assert!(!res.tree.dirs[1].collapsed, "z (depth 1) stays expanded");
        assert!(map_trim_step(&mut res));
        assert!(res.tree.dirs[1].collapsed, "z collapses second");
    }

    #[test]
    fn maps_tree_with_symbols_depth_collapse_and_budgets() {
        let tmp = Tmp::new("tree");
        tmp.write("src/a.rs", b"pub struct Alpha;\npub fn run() {}\n");
        tmp.write("src/deep/nested/b.cs", b"namespace N;\npublic class Beta {}\n");
        tmp.write("node_modules/pkg/index.js", b"export const x = 1;\n");
        tmp.write("Cargo.lock", b"# lock\n");

        let res = execute_map(&MapOptions {
            root: tmp.0.clone(),
            max_depth: 2,
            include_symbols: true,
            ..MapOptions::default()
        })
        .unwrap();
        assert_eq!(res.total_files, 2);
        let txt = render_map_text(&res, 2000);
        assert!(txt.contains("a.rs (2L) [Alpha, run]"));
        assert!(txt.contains("deep/ (1 files, 2L)"));
        assert!(!txt.contains("b.cs"));
        assert!(!txt.contains("node_modules"));
        assert!(!txt.contains("Cargo.lock"));

        // Tight JSON & text budget test
        for i in 0..40 {
            tmp.write(&format!("many/file_{i}.rs"), b"pub fn f() {}\n");
        }
        let big = execute_map(&MapOptions {
            root: tmp.0.clone(),
            ..MapOptions::default()
        })
        .unwrap();
        let tight_txt = render_map_text(&big, 80);
        assert!(tight_txt.len() <= 80 * 4);
        assert!(tight_txt.contains("omitted entries"));
        let tight_json = render_map_json(&big, 120);
        assert!(tight_json.len() <= 120 * 4);
        let parsed: serde_json::Value = serde_json::from_str(&tight_json).unwrap();
        assert_eq!(parsed["truncated"], serde_json::Value::Bool(true));
        if let Some(dirs) = parsed["tree"]["dirs"].as_array() {
            for d in dirs {
                if d["files"].is_null() && d["dirs"].is_null() && d["total_files"].as_u64().unwrap_or(0) > 0 {
                    assert_eq!(d["collapsed"], serde_json::Value::Bool(true));
                }
            }
        }
    }
}
