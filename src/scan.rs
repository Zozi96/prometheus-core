//! Unified tree scan (spec #43, ticket #47): one deep operation that returns
//! the versioned scan document — tree fingerprint, changed files with a
//! hunk index, the Task delta and the Integration delta kept separate
//! (ADR-0006), their conflict-capable intersection, a content-identical flag
//! for integrations, and submodule / linked-worktree / mid-integration
//! state. Facts only: the document never carries a verdict.
//!
//! The trees it diffs are named by the caller: the current tree (the
//! fingerprint the gate computed), the session baseline, the task baseline,
//! and the integration state's before/after base trees and task tree. Their
//! objects live in the repository's object store and in the session's
//! private store, which staging wrote loose objects into; both are read.
//! A fact that cannot be measured is reported as null with its reason
//! beside it, never as an empty list. Any harder failure raises, and the
//! caller reruns the whole scan on the git CLI route.

use std::collections::BTreeMap;
use std::path::Path;

use gix_imara_diff::{sources::byte_lines, Algorithm, Diff, InternedInput};
use pyo3::prelude::*;

use crate::fingerprint::{err, linked_worktrees_impl, open, real, status_impl, text, Res};

const SCHEMA: u32 = 1;
const CONTEXT: u32 = 3;
/// git's `buffer_is_binary`: a NUL in the first 8000 bytes marks the blob binary.
const BINARY_SNIFF: usize = 8000;

const MODE_GITLINK: u32 = 0o160000;
const MODE_LINK: u32 = 0o120000;
const MODE_TREE: u32 = 0o040000;

fn bx(e: impl std::fmt::Display) -> Box<dyn std::error::Error + Send + Sync> {
    e.to_string().into()
}

/// The object stores a scan reads: the repository's own, plus the session's
/// private store (loose objects only — staging never packs it).
struct Objects {
    repo: gix::Repository,
    loose: Option<gix::odb::loose::Store>,
}

impl Objects {
    fn find(&self, id: gix::ObjectId) -> Res<Option<(gix::objs::Kind, Vec<u8>)>> {
        if let Some(store) = &self.loose {
            let mut buf = Vec::new();
            if let Some(data) = store.try_find(id.as_ref(), &mut buf).map_err(bx)? {
                return Ok(Some((data.kind, data.data.to_vec())));
            }
        }
        match self.repo.try_find_object(id).map_err(bx)? {
            Some(object) => Ok(Some((object.kind, object.data.clone()))),
            None => Ok(None),
        }
    }

    fn tree(&self, id: gix::ObjectId) -> Res<Option<Vec<u8>>> {
        match self.find(id)? {
            Some((gix::objs::Kind::Tree, data)) => Ok(Some(data)),
            Some(_) => Err("named object is not a tree".into()),
            None => Ok(None),
        }
    }

    fn blob(&self, leaf: &Leaf) -> Res<Vec<u8>> {
        if leaf.mode == MODE_GITLINK {
            // git diff renders a gitlink as one synthetic line.
            return Ok(format!("Subproject commit {}\n", leaf.id).into_bytes());
        }
        match self.find(leaf.id)? {
            Some((gix::objs::Kind::Blob, data)) => Ok(data),
            Some(_) => Err("tree entry is not a blob".into()),
            None => Err("blob object unavailable".into()),
        }
    }
}

/// One leaf of a flattened tree: (mode bits, object id).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Leaf {
    mode: u32,
    id: gix::ObjectId,
}

type FlatTree = BTreeMap<String, Leaf>;

fn flatten(objs: &Objects, tree: gix::ObjectId, prefix: &str, out: &mut FlatTree) -> Res<()> {
    let data = objs.tree(tree)?.ok_or("tree object unavailable")?;
    let parsed = gix::objs::TreeRef::from_bytes(&data, gix::hash::Kind::Sha1).map_err(bx)?;
    for entry in parsed.entries {
        let name = text(entry.filename)?;
        let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let mode = entry.mode.value() as u32;
        if mode == MODE_TREE {
            flatten(objs, entry.oid.to_owned(), &path, out)?;
        } else {
            out.insert(path, Leaf { mode, id: entry.oid.to_owned() });
        }
    }
    Ok(())
}

fn flat(objs: &Objects, tree: gix::ObjectId) -> Res<FlatTree> {
    let mut out = FlatTree::new();
    flatten(objs, tree, "", &mut out)?;
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Link,
    Gitlink,
}

fn kind(mode: u32) -> Kind {
    match mode {
        MODE_GITLINK => Kind::Gitlink,
        MODE_LINK => Kind::Link,
        _ => Kind::File,
    }
}

struct Change {
    path: String,
    status: &'static str,
    old: Option<Leaf>,
    new: Option<Leaf>,
}

fn diff_maps(old: &FlatTree, new: &FlatTree) -> Vec<Change> {
    let mut out = Vec::new();
    for (path, new_leaf) in new {
        match old.get(path) {
            None => out.push(Change { path: path.clone(), status: "added", old: None, new: Some(*new_leaf) }),
            Some(old_leaf) if old_leaf != new_leaf => {
                let status = if kind(old_leaf.mode) != kind(new_leaf.mode) { "typechange" } else { "modified" };
                out.push(Change { path: path.clone(), status, old: Some(*old_leaf), new: Some(*new_leaf) });
            }
            Some(_) => {}
        }
    }
    for (path, old_leaf) in old {
        if !new.contains_key(path) {
            out.push(Change { path: path.clone(), status: "deleted", old: Some(*old_leaf), new: None });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn is_binary(data: &[u8]) -> bool {
    data[..data.len().min(BINARY_SNIFF)].contains(&0)
}

struct Hunk {
    old_start: u32,
    old_count: u32,
    new_start: u32,
    new_count: u32,
    header: String,
}

/// git's default funcname rule: the last line before the hunk whose first
/// byte is alphanumeric, `_`, or `$` (xdl's built-in heuristic, no driver).
fn funcname(lines: &[&[u8]], before: u32) -> String {
    for index in (0..before.min(lines.len() as u32)).rev() {
        let line = lines[index as usize];
        let Some(first) = line.first() else { continue };
        if first.is_ascii_alphanumeric() || *first == b'_' || *first == b'$' {
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            // git caps the printed funcname line at 80 bytes.
            let line = &line[..line.len().min(80)];
            return String::from_utf8_lossy(line).into_owned();
        }
    }
    String::new()
}

/// The line diff of two blob contents: (added, deleted, hunks with context).
fn line_diff(old: &[u8], new: &[u8]) -> (u32, u32, Vec<Hunk>) {
    let input = InternedInput::new(byte_lines(old), byte_lines(new));
    let mut diff = Diff::compute(Algorithm::Myers, &input);
    diff.postprocess_lines(&input);
    let added = diff.count_additions();
    let removed = diff.count_removals();
    let old_lines: Vec<&[u8]> = byte_lines(old).collect();
    let new_len = byte_lines(new).count() as u32;
    let old_len = old_lines.len() as u32;
    // Change groups, widened by the context and merged as git merges them.
    let mut groups: Vec<(u32, u32, u32, u32)> = Vec::new();
    for hunk in diff.hunks() {
        let (b, a) = (hunk.before, hunk.after);
        let widened = (
            b.start.saturating_sub(CONTEXT),
            (b.end + CONTEXT).min(old_len),
            a.start.saturating_sub(CONTEXT),
            (a.end + CONTEXT).min(new_len),
        );
        match groups.last_mut() {
            Some(last) if widened.0 <= last.1 => {
                last.1 = last.1.max(widened.1);
                last.3 = last.3.max(widened.3);
            }
            _ => groups.push(widened),
        }
    }
    let hunks = groups
        .into_iter()
        .map(|(b0, b1, a0, a1)| Hunk {
            old_start: if b1 > b0 { b0 + 1 } else { b0 },
            old_count: b1 - b0,
            new_start: if a1 > a0 { a0 + 1 } else { a0 },
            new_count: a1 - a0,
            header: funcname(&old_lines, b0),
        })
        .collect();
    (added, removed, hunks)
}

/// JSON string escaping, the small subset a document emitter needs.
fn esc(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
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

fn names_json(names: &Option<Vec<String>>, out: &mut String) {
    match names {
        None => out.push_str("null"),
        Some(names) => {
            out.push('[');
            for (index, name) in names.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                esc(name, out);
            }
            out.push(']');
        }
    }
}

fn reason_json(reason: Option<&str>, out: &mut String) {
    match reason {
        None => out.push_str("null"),
        Some(reason) => esc(reason, out),
    }
}

fn parse_id(text: &str) -> Res<Option<gix::ObjectId>> {
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(gix::ObjectId::from_hex(text.as_bytes()).map_err(bx)?))
}

/// Names differing between two named trees; Ok(None) when a tree is absent.
fn delta(objs: &Objects, left: gix::ObjectId, right: gix::ObjectId) -> Res<Option<Vec<String>>> {
    if left == right {
        return Ok(Some(Vec::new()));
    }
    if objs.tree(left)?.is_none() || objs.tree(right)?.is_none() {
        return Ok(None);
    }
    let changes = diff_maps(&flat(objs, left)?, &flat(objs, right)?);
    Ok(Some(changes.into_iter().map(|change| change.path).collect()))
}

#[allow(clippy::too_many_arguments)]
fn scan_impl(
    root: &str,
    store: &str,
    current: &str,
    baseline: &str,
    task: &str,
    before_base: &str,
    after_base: &str,
    task_tree: &str,
) -> Res<String> {
    let repo = open(root)?;
    if repo.workdir().is_none() {
        return Err("bare repository".into());
    }
    let loose = if store.is_empty() {
        None
    } else {
        Some(gix::odb::loose::Store::at(store, gix::hash::Kind::Sha1))
    };
    let objs = Objects { repo, loose };
    let current_id = parse_id(current)?.ok_or("current tree is required")?;
    if objs.tree(current_id)?.is_none() {
        return Err("current tree unavailable".into());
    }
    let mut doc = String::with_capacity(4096);
    doc.push_str("{\"schema\":");
    doc.push_str(&SCHEMA.to_string());
    doc.push_str(",\"fingerprint\":");
    esc(current, &mut doc);
    doc.push_str(",\"baseline\":");
    if baseline.is_empty() {
        doc.push_str("null");
    } else {
        esc(baseline, &mut doc);
    }

    // The changed rows against the session baseline.
    doc.push_str(",\"changed\":");
    let mut changed_reason: Option<&str> = None;
    if baseline.is_empty() {
        changed_reason = Some("no-baseline");
        doc.push_str("null");
    } else {
        let baseline_id = parse_id(baseline)?;
        match baseline_id {
            Some(id) if objs.tree(id)?.is_some() => {
                let changes = if id == current_id {
                    Vec::new()
                } else {
                    diff_maps(&flat(&objs, id)?, &flat(&objs, current_id)?)
                };
                doc.push('[');
                for (index, change) in changes.iter().enumerate() {
                    if index > 0 {
                        doc.push(',');
                    }
                    let old_data = change.old.map(|leaf| objs.blob(&leaf)).transpose()?;
                    let new_data = change.new.map(|leaf| objs.blob(&leaf)).transpose()?;
                    let binary = old_data.as_deref().is_some_and(is_binary)
                        || new_data.as_deref().is_some_and(is_binary);
                    doc.push_str("{\"path\":");
                    esc(&change.path, &mut doc);
                    doc.push_str(",\"status\":");
                    esc(change.status, &mut doc);
                    doc.push_str(",\"binary\":");
                    doc.push_str(if binary { "true" } else { "false" });
                    if binary {
                        doc.push_str(",\"added\":null,\"deleted\":null,\"hunks\":[]}");
                        continue;
                    }
                    let (added, deleted, hunks) = line_diff(
                        old_data.as_deref().unwrap_or_default(),
                        new_data.as_deref().unwrap_or_default(),
                    );
                    doc.push_str(",\"added\":");
                    doc.push_str(&added.to_string());
                    doc.push_str(",\"deleted\":");
                    doc.push_str(&deleted.to_string());
                    doc.push_str(",\"hunks\":[");
                    for (index, hunk) in hunks.iter().enumerate() {
                        if index > 0 {
                            doc.push(',');
                        }
                        doc.push_str("{\"old_start\":");
                        doc.push_str(&hunk.old_start.to_string());
                        doc.push_str(",\"old_count\":");
                        doc.push_str(&hunk.old_count.to_string());
                        doc.push_str(",\"new_start\":");
                        doc.push_str(&hunk.new_start.to_string());
                        doc.push_str(",\"new_count\":");
                        doc.push_str(&hunk.new_count.to_string());
                        doc.push_str(",\"header\":");
                        esc(&hunk.header, &mut doc);
                        doc.push('}');
                    }
                    doc.push_str("]}");
                }
                doc.push(']');
            }
            _ => {
                changed_reason = Some("baseline-unavailable");
                doc.push_str("null");
            }
        }
    }
    doc.push_str(",\"changed_unmeasurable\":");
    reason_json(changed_reason, &mut doc);

    // The two deltas, computed and reported separately (ADR-0006).
    let task_delta = match parse_id(task)? {
        None => None,
        Some(id) => delta(&objs, id, current_id)?,
    };
    let task_reason = if task.is_empty() {
        Some("no-task-baseline")
    } else if task_delta.is_none() {
        Some("task-diff-unavailable")
    } else {
        None
    };
    let (integration_delta, integration_reason) = if before_base.is_empty() && after_base.is_empty() {
        (Some(Vec::new()), None)
    } else if before_base.is_empty() || after_base.is_empty() {
        (None, Some("integration-base-incomplete"))
    } else {
        let found = delta(&objs, parse_id(before_base)?.ok_or("before base")?, parse_id(after_base)?.ok_or("after base")?)?;
        let reason = if found.is_none() { Some("integration-diff-unavailable") } else { None };
        (found, reason)
    };
    doc.push_str(",\"task_delta\":");
    names_json(&task_delta, &mut doc);
    doc.push_str(",\"task_delta_unmeasurable\":");
    reason_json(task_reason, &mut doc);
    doc.push_str(",\"integration_delta\":");
    names_json(&integration_delta, &mut doc);
    doc.push_str(",\"integration_delta_unmeasurable\":");
    reason_json(integration_reason, &mut doc);
    doc.push_str(",\"integration_content_identical\":");
    if !after_base.is_empty() && !task_tree.is_empty() {
        doc.push_str(if task_tree == current { "true" } else { "false" });
    } else {
        doc.push_str("null");
    }
    doc.push_str(",\"conflict_capable\":");
    match (&task_delta, &integration_delta) {
        (Some(task), Some(integration)) => {
            let mut capable: Vec<&String> = task.iter().filter(|path| integration.contains(path)).collect();
            capable.sort();
            capable.dedup();
            doc.push('[');
            for (index, path) in capable.iter().enumerate() {
                if index > 0 {
                    doc.push(',');
                }
                esc(path, &mut doc);
            }
            doc.push(']');
        }
        _ => doc.push_str("null"),
    }

    // Submodule and linked-worktree state, from the same walks the
    // fingerprint primitives already prove against the CLI.
    let (_changed, _untracked, submodules) = status_impl(root, None)?;
    doc.push_str(",\"submodules\":[");
    for (index, (path, commit, tracked, untracked)) in submodules.iter().enumerate() {
        if index > 0 {
            doc.push(',');
        }
        doc.push_str("{\"path\":");
        esc(path, &mut doc);
        doc.push_str(",\"commit_changed\":");
        doc.push_str(if *commit { "true" } else { "false" });
        doc.push_str(",\"tracked_changes\":");
        doc.push_str(if *tracked { "true" } else { "false" });
        doc.push_str(",\"untracked_files\":");
        doc.push_str(if *untracked { "true" } else { "false" });
        doc.push('}');
    }
    doc.push(']');
    let mut linked: Vec<String> = linked_worktrees_impl(root)?
        .into_iter()
        .map(|path| real(Path::new(&path)).unwrap_or(path))
        .collect();
    linked.sort();
    doc.push_str(",\"linked_worktrees\":");
    names_json(&Some(linked), &mut doc);

    // Mid-integration state: unmerged index entries and git's markers.
    let index = objs.repo.index_or_empty()?;
    let mut unmerged: Vec<String> = index
        .entries()
        .iter()
        .filter(|entry| entry.stage_raw() != 0)
        .map(|entry| text(entry.path(&index)))
        .collect::<Result<_, _>>()?;
    unmerged.sort();
    unmerged.dedup();
    doc.push_str(",\"unmerged\":");
    names_json(&Some(unmerged.clone()), &mut doc);
    let git_dir = objs.repo.git_dir();
    let in_progress = if git_dir.join("MERGE_HEAD").is_file() {
        "merge"
    } else if git_dir.join("rebase-merge").is_dir() || git_dir.join("rebase-apply").is_dir() {
        "rebase"
    } else if !unmerged.is_empty() {
        "unresolved"
    } else {
        ""
    };
    doc.push_str(",\"integration_in_progress\":");
    esc(in_progress, &mut doc);
    doc.push('}');
    Ok(doc)
}

#[pyfunction]
#[pyo3(signature = (root, store, current, baseline, task, before_base, after_base, task_tree))]
#[allow(clippy::too_many_arguments)]
fn scan(
    py: Python<'_>,
    root: String,
    store: String,
    current: String,
    baseline: String,
    task: String,
    before_base: String,
    after_base: String,
    task_tree: String,
) -> PyResult<String> {
    py.detach(|| scan_impl(&root, &store, &current, &baseline, &task, &before_base, &after_base, &task_tree))
        .map_err(err)
}

/// Register the scan on the `prometheus_core` module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    Ok(())
}
