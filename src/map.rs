//! Deterministic repository map with line counts and optional top-level symbols (`prometheus-kit map`).

use crate::kit_util::{clip_to_byte_budget, is_noise_path};
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

pub fn render_map_text(res: &MapResult, max_tokens: usize) -> String {
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

    if max_tokens == 0 {
        return format!("{}\n", lines.join("\n"));
    }

    let budget = max_tokens.saturating_mul(4);
    const RESERVE: usize = 80;
    let mut out = String::new();
    let mut omitted = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        let add = line.len() + 1;
        if idx > 0 && out.len() + add + RESERVE > budget {
            omitted = lines.len() - idx;
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    if omitted > 0 {
        out.push_str(&format!(
            "... (+{omitted} omitted entries; narrow with --depth/--glob or --max-tokens)\n"
        ));
    }
    if out.len() > budget {
        return clip_to_byte_budget(&out, budget);
    }
    out
}

fn collapse_deepest_dir(dir: &mut MapDirEntry) -> usize {
    for sub in dir.dirs.iter_mut().rev() {
        if !sub.collapsed && (!sub.dirs.is_empty() || !sub.files.is_empty()) {
            let deeper = collapse_deepest_dir(sub);
            if deeper > 0 {
                return deeper;
            }
            let dropped = sub.dirs.len() + sub.files.len();
            sub.dirs.clear();
            sub.files.clear();
            sub.collapsed = true;
            return dropped.max(1);
        }
    }
    0
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
    let budget = max_tokens.saturating_mul(4);
    let mut trimmed = res.clone();
    loop {
        let encoded = serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned());
        if encoded.len() <= budget {
            return encoded;
        }
        let dropped = collapse_deepest_or_trim(&mut trimmed.tree);
        if dropped == 0 {
            return encoded;
        }
        trimmed.truncated = true;
        trimmed.omitted_entries += dropped;
    }
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
