//! In-process worktree fingerprinting for `prometheus-check`.

use gix::bstr::{BString, ByteSlice};
use gix::dir::entry::{Kind, Status as DirStatus};
use gix::dir::walk::EmissionMode;
use gix::status::index_worktree::Item as WorktreeItem;
use gix::status::plumbing::index_as_worktree::{Change, EntryStatus};

pub(crate) type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) fn text(path: &[u8]) -> Res<String> {
    Ok(std::str::from_utf8(path)?.to_owned())
}

pub(crate) fn open(root: &str) -> Res<gix::Repository> {
    Ok(gix::open(root)?)
}

/// One submodule as `git status --porcelain=v2` reports it: (path, commit changed, tracked changes, untracked files).
type SubmoduleFacts = (String, bool, bool, bool);

/// `status --untracked-files=all --ignore-submodules=none`: every untracked file and submodule state,
/// whatever `status.showUntrackedFiles` says. Its `no` drops the dirwalk entirely, so it is rebuilt here.
fn status_platform(repo: &gix::Repository) -> Res<gix::status::Platform<'_, gix::progress::Discard>> {
    let dirwalk = repo.dirwalk_options()?.emit_untracked(EmissionMode::Matching);
    Ok(repo
        .status(gix::progress::Discard)?
        .index_worktree_submodules(gix::status::Submodule::Given {
            ignore: gix::submodule::config::Ignore::None,
            check_dirty: false,
        })
        .index_worktree_options_mut(|opts| opts.dirwalk_options = Some(dirwalk)))
}

/// `status --porcelain=v2 -z --untracked-files=all --ignore-submodules=none`, as facts:
/// whether anything is listed, the untracked paths (directories end in `/`), and submodule states.
pub(crate) fn status_impl(root: &str, threads: Option<usize>) -> Res<(bool, Vec<String>, Vec<SubmoduleFacts>)> {
    status_walk(root, threads)
}

type StatusFacts = (bool, Vec<String>, Vec<SubmoduleFacts>);

/// Collect status facts from the directory walk.
fn status_walk(root: &str, threads: Option<usize>) -> Res<StatusFacts> {
    let repo = open(root)?;
    let iter = status_platform(&repo)?
        .index_worktree_options_mut(|opts| opts.thread_limit = threads)
        .into_iter(None::<BString>)?;
    let mut changed = false;
    let mut untracked = Vec::new();
    let mut submodules = Vec::new();
    for item in iter {
        match item? {
            gix::status::Item::TreeIndex(_) => changed = true,
            gix::status::Item::IndexWorktree(WorktreeItem::Modification { rela_path, status, .. }) => match status {
                EntryStatus::NeedsUpdate(_) => {}
                EntryStatus::Change(Change::SubmoduleModification(sub)) => {
                    let commit = sub.index_id != sub.checked_out_head_id;
                    let (mut modified, mut new) = (false, false);
                    for change in sub.changes.iter().flatten() {
                        match change {
                            gix::status::Item::IndexWorktree(WorktreeItem::DirectoryContents { entry, .. })
                                if entry.status == DirStatus::Untracked =>
                            {
                                new = true
                            }
                            gix::status::Item::IndexWorktree(WorktreeItem::Modification {
                                status: EntryStatus::NeedsUpdate(_),
                                ..
                            }) => {}
                            _ => modified = true,
                        }
                    }
                    if commit || modified || new {
                        changed = true;
                        submodules.push((text(&rela_path)?, commit, modified, new));
                    }
                }
                _ => changed = true,
            },
            gix::status::Item::IndexWorktree(WorktreeItem::DirectoryContents { entry, .. }) => {
                let empty = entry.property == Some(gix::dir::entry::Property::EmptyDirectory);
                let mut path = text(&entry.rela_path)?;
                if matches!(entry.disk_kind, Some(Kind::Directory | Kind::Repository)) {
                    path.push('/');
                }
                match entry.status {
                    // git status -uall never lists an empty directory; the walk emits it only for ls-files.
                    DirStatus::Untracked if !empty => {
                        changed = true;
                        untracked.push(path);
                    }
                    _ => {}
                }
            }
            gix::status::Item::IndexWorktree(_) => changed = true,
        }
    }
    untracked.sort();
    submodules.sort();
    Ok((changed, untracked, submodules))
}

/// A staged entry for the tree: (mode bits, object id), keyed by repository path.
type Staged = std::collections::BTreeMap<BString, (u32, gix::ObjectId)>;

const MODE_FILE: u32 = 0o100644;
const MODE_EXEC: u32 = 0o100755;
const MODE_LINK: u32 = 0o120000;
const MODE_TREE: u32 = 0o040000;

struct Writer<'a> {
    repo: &'a gix::Repository,
    store: gix::odb::loose::Store,
}

impl Writer<'_> {
    /// Hash `data` as `kind`; store it unless the repository or the store already has it.
    fn put(&self, kind: gix::objs::Kind, data: &[u8]) -> Res<gix::ObjectId> {
        use gix::objs::{Exists, Write};
        let id = gix::objs::compute_hash(gix::hash::Kind::Sha1, kind, data)?;
        if !self.repo.objects.exists(&id) && !self.store.contains(&id) {
            self.store.write_buf(kind, data)?;
        }
        Ok(id)
    }
}

/// `git add` of one work-tree path: its index mode and blob id, or None when it is gone.
fn hash_path(
    w: &Writer<'_>,
    pipeline: &mut gix::filter::Pipeline<'_>,
    index: &gix::index::State,
    rela: &BString,
    old_mode: Option<u32>,
    trust_exec: bool,
    symlinks: bool,
) -> Res<Option<(u32, gix::ObjectId)>> {
    let workdir = w.repo.workdir().ok_or("bare repository")?;
    let rela_path = gix::path::from_bstr(rela.as_bstr())?;
    // As git's has_symlink_leading_path: a parent that is a symlink or not a directory means the path is gone.
    let mut parent = workdir.to_path_buf();
    let components: Vec<_> = rela_path.components().collect();
    for component in &components[..components.len().saturating_sub(1)] {
        parent.push(component);
        match std::fs::symlink_metadata(&parent) {
            Ok(md) if md.is_dir() => {}
            _ => return Ok(None),
        }
    }
    let path = workdir.join(&rela_path);
    let md = match std::fs::symlink_metadata(&path) {
        Ok(md) => md,
        // A parent that became a file (ENOTDIR) means the path is gone, as for git.
        Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if md.is_symlink() {
        let target = std::fs::read_link(&path)?;
        let bytes = gix::path::into_bstr(target)?.into_owned();
        return Ok(Some((MODE_LINK, w.put(gix::objs::Kind::Blob, &bytes)?)));
    }
    if !md.is_file() {
        return Ok(None); // a directory now stands where the file was: git drops the entry
    }
    // As git's ce_mode_from_stat: with core.symlinks off, a regular file standing in for a tracked
    // link (how such a checkout writes it) stays a link; its content is the target.
    let mode = if !symlinks && old_mode == Some(MODE_LINK) {
        MODE_LINK
    } else if trust_exec && executable(&md) {
        MODE_EXEC
    } else if trust_exec {
        MODE_FILE
    } else {
        match old_mode {
            Some(m) if m == MODE_EXEC || m == MODE_FILE => m,
            _ => MODE_FILE,
        }
    };
    let file = std::fs::File::open(&path)?;
    let mut data = Vec::new();
    {
        use gix::filter::plumbing::pipeline::convert::ToGitOutcome;
        use std::io::Read;
        match pipeline.convert_to_git(file, &rela_path, index)? {
            ToGitOutcome::Unchanged(mut r) => r.read_to_end(&mut data)?,
            ToGitOutcome::Buffer(buf) => {
                data.extend_from_slice(buf);
                data.len()
            }
            ToGitOutcome::Process(mut r) => r.read_to_end(&mut data)?,
        };
    }
    Ok(Some((mode, w.put(gix::objs::Kind::Blob, &data)?)))
}

#[cfg(unix)]
fn executable(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o100 != 0
}

/// No executable bit to read: git keeps the index mode, as with `core.fileMode=false`.
#[cfg(not(unix))]
fn executable(_: &std::fs::Metadata) -> bool {
    false
}

/// Writes the tree for `entries` (sorted full paths sharing their first `depth` components); returns its id.
fn write_tree(w: &Writer<'_>, entries: &[(&BString, (u32, gix::ObjectId))], depth: usize) -> Res<gix::ObjectId> {
    let mut tree = gix::objs::Tree::empty();
    let mut i = 0;
    while i < entries.len() {
        let rest: Vec<&[u8]> = entries[i].0.splitn(depth + 2, |b| *b == b'/').collect();
        let name = rest[depth];
        if rest.len() == depth + 1 {
            let (mode, id) = entries[i].1;
            tree.entries.push(gix::objs::tree::Entry {
                mode: gix::objs::tree::EntryMode::try_from(mode).map_err(|_| "bad mode")?,
                filename: name.into(),
                oid: id,
            });
            i += 1;
            continue;
        }
        let mut j = i;
        while j < entries.len() {
            let other: Vec<&[u8]> = entries[j].0.splitn(depth + 2, |b| *b == b'/').collect();
            if other.len() <= depth + 1 || other[depth] != name {
                break;
            }
            j += 1;
        }
        let id = write_tree(w, &entries[i..j], depth + 1)?;
        tree.entries.push(gix::objs::tree::Entry {
            mode: gix::objs::tree::EntryMode::try_from(MODE_TREE).map_err(|_| "bad mode")?,
            filename: name.into(),
            oid: id,
        });
        i = j;
    }
    tree.entries.sort();
    let mut buf = Vec::new();
    gix::objs::WriteTo::write_to(&tree, &mut buf)?;
    w.put(gix::objs::Kind::Tree, &buf)
}

/// Untracked bytecode under `__pycache__/`, pytest's cache, and tox's `.tox/`.
/// A loose `*.pyc` stays, and so does any tracked file: this is only for
/// paths the status walk sees as untracked.
/// A trailing slash stays (an embedded repository is still reported).
fn run_generated(path: &[u8]) -> bool {
    if path.ends_with(b"/") {
        return false;
    }
    let mut parts = path.split(|byte| *byte == b'/').filter(|part| !part.is_empty());
    let Some(name) = parts.next_back() else {
        return false;
    };
    let mut under_pycache = false;
    let mut under_pytest_cache = false;
    let mut under_tox = false;
    for part in parts {
        if part == b"__pycache__" {
            under_pycache = true;
        } else if part == b".pytest_cache" {
            under_pytest_cache = true;
        } else if part == b".tox" {
            under_tox = true;
        }
    }
    under_pytest_cache || under_tox || (under_pycache && name.ends_with(b".pyc"))
}

/// Stage the worktree into a private object store and write its tree.
fn stage_core(repo: &gix::Repository, store: &str) -> Res<String> {
    std::fs::create_dir_all(store)?;
    let w = Writer { repo, store: gix::odb::loose::Store::at(store, gix::hash::Kind::Sha1) };
    let trust_exec = cfg!(unix) && repo.config_snapshot().boolean("core.fileMode").unwrap_or(true);
    let symlinks = repo.config_snapshot().boolean("core.symlinks").unwrap_or(true);
    let drivers = filter_drivers(repo);
    let (mut pipeline, index) = repo.filter_pipeline(None)?;
    let mut staged = Staged::new();
    for entry in index.entries() {
        let path = entry.path(&index);
        if entry.stage_raw() == 0 && !entry.flags.contains(gix::index::entry::Flags::INTENT_TO_ADD) {
            staged.insert(path.to_owned(), (entry.mode.bits(), entry.id));
        }
    }
    let iter = status_platform(repo)?.into_index_worktree_iter(None::<BString>)?;
    let mut redo: Vec<(BString, Option<u32>)> = Vec::new();
    for item in iter {
        match item.map_err(|e| format!("status: {e}"))? {
            WorktreeItem::Modification { rela_path, status, entry, .. } => {
                match status {
                    EntryStatus::Change(Change::SubmoduleModification(_)) => {
                        return Err("a submodule differs; git add would store only its gitlink".into())
                    }
                    // run_generated applies only to untracked entries, not here.
                    EntryStatus::NeedsUpdate(_) => {}
                    // git add -A drops it from the index mid-run, so later paths lose its attributes.
                    EntryStatus::Change(Change::Removed | Change::Type { .. })
                        if rela_path.rsplit_str("/").next() == Some(b".gitattributes".as_bstr()) =>
                    {
                        return Err("route: a tracked .gitattributes was removed or changed type".into())
                    }
                    _ => redo.push((rela_path, Some(entry.mode.bits()))),
                }
            }
            WorktreeItem::DirectoryContents { entry, .. } => {
                if entry.status != DirStatus::Untracked {
                    continue;
                }
                // A repository named like a cache is still an embedded repository.
                if !matches!(entry.disk_kind, Some(Kind::Repository)) && run_generated(entry.rela_path.as_bytes()) {
                    continue;
                }
                // Refuse unproven conversion attributes in a new attributes file.
                if entry.rela_path.rsplit_str("/").next() == Some(b".gitattributes".as_bstr()) {
                    let workdir = repo.workdir().ok_or("bare repository")?;
                    let text = std::fs::read(workdir.join(gix::path::from_bstr(entry.rela_path.as_bstr())?))
                        .unwrap_or_default();
                    if let Some(reason) = unproven_attributes(&text, drivers) {
                        return Err(format!("route: a new .gitattributes uses {reason}").into());
                    }
                }
                match entry.disk_kind {
                    Some(Kind::File | Kind::Symlink) => redo.push((entry.rela_path, None)),
                    Some(Kind::Repository) => return Err("embedded git repository".into()),
                    _ => {}
                }
            }
            other => return Err(format!("unexpected status item: {other:?}").into()),
        }
    }
    let state: &gix::index::State = &index;
    for (path, old_mode) in redo {
        staged.remove(&path);
        let found = hash_path(&w, &mut pipeline, state, &path, old_mode, trust_exec, symlinks)
            .map_err(|e| format!("hash {path}: {e}"))?;
        if let Some(found) = found {
            staged.insert(path, found);
        }
    }
    let entries: Vec<(&BString, (u32, gix::ObjectId))> = staged.iter().map(|(p, v)| (p, *v)).collect();
    Ok(write_tree(&w, &entries, 0)?.to_hex().to_string())
}

fn stage_and_write_impl(root: &str, store: &str) -> Res<String> {
    stage_core(&open(root)?, store)
}

/// Whether any `filter.<driver>` has a command git would run.
fn filter_drivers(repo: &gix::Repository) -> bool {
    repo.config_snapshot()
        .plumbing()
        .sections_by_name("filter")
        .into_iter()
        .flatten()
        .any(|s| ["clean", "smudge", "process"].iter().any(|k| s.value(k).is_some()))
}

/// Bytes of an attribute line this engine parses itself: printable ASCII except a quote or a backslash, or a blank.
fn plain_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | 0x21..=0x7e) && byte != b'"' && byte != b'\\'
}

/// The conversion attribute text names that this engine has not proven equal to git's, if any.
/// Blank lines and `#` comments are skipped. A line of only plain bytes (no quote, backslash, NUL, BOM or
/// other non-ASCII) is parsed: its first word is the pattern, later words are attribute names (a leading
/// `-` or `!` and any `=value` dropped). Any other line is matched as a raw substring, which covers every
/// git quirk. A false hit only sends the call to the git CLI.
fn unproven_attributes(text: &[u8], drivers: bool) -> Option<&'static str> {
    let (mut encoding, mut ident, mut filter) = (false, false, false);
    let blank = |b: &u8| matches!(b, b' ' | b'\t' | b'\r');
    for line in text.split(|&b| b == b'\n') {
        let line = &line[line.iter().position(|b| !blank(b)).unwrap_or(line.len())..];
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if !line.iter().all(|&b| plain_byte(b)) {
            encoding |= line.find("working-tree-encoding").is_some();
            ident |= line.find("ident").is_some();
            filter |= line.find("filter").is_some();
            continue;
        }
        for word in line.split(blank).skip(1) {
            let word = word.strip_prefix(b"-").or_else(|| word.strip_prefix(b"!")).unwrap_or(word);
            let name = word.split(|&b| b == b'=').next().unwrap_or(word);
            encoding |= name == b"working-tree-encoding";
            ident |= name == b"ident";
            filter |= name == b"filter";
        }
    }
    if encoding {
        Some("working-tree-encoding attribute")
    } else if ident {
        Some("ident attribute")
    } else if drivers && filter {
        Some("a filter driver an attribute uses")
    } else {
        None
    }
}

/// Return the worktree tree ID, or None when it cannot be fingerprinted.
pub fn worktree_fingerprint(root: &str, store: &str) -> Option<String> {
    stage_and_write_impl(root, store).ok()
}

#[cfg(test)]
mod tests {
    use super::{stage_and_write_impl, worktree_fingerprint};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU64, Ordering};

    const NAMES: [&str; 13] = ["a", "a.txt", "a-", "a0", "a.b", "b", "B", "x y", "ü.txt", "z", "dir", "dir.txt", "dir-"];
    const RULES: [&str; 7] = ["*.b", "!keep.b", "dir/", "a0", "x y/", "*.dat", "!dir/a"];
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("prometheus-fingerprint-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }
        fn n(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
        fn path(&mut self) -> String {
            let depth = 1 + self.n(3);
            (0..depth).map(|_| NAMES[self.n(NAMES.len())]).collect::<Vec<_>>().join("/")
        }
        fn content(&mut self) -> Vec<u8> {
            if self.n(7) == 0 {
                let count = 1 + self.n(39);
                return (0..count).map(|_| self.next() as u8).collect();
            }
            let eol: &[u8] = [b"\n".as_slice(), b"\r\n", b"\r"][self.n(3)];
            let count = self.n(5);
            let mut bytes = Vec::new();
            for i in 0..count {
                if i > 0 { bytes.extend_from_slice(eol); }
                let word = ["x", "y", "line", ""][self.n(4)];
                for _ in 0..1 + self.n(3) { bytes.extend_from_slice(word.as_bytes()); }
            }
            if self.n(10) < 7 { bytes.extend_from_slice(eol); }
            bytes
        }
    }

    fn git(root: &Path, home: &Path, args: &[&str], extra: &[(&str, &Path)]) -> Output {
        let mut command = Command::new("git");
        command.arg("-C").arg(root).args(args).env("HOME", home).env("GIT_CONFIG_NOSYSTEM", "1");
        for (key, value) in extra { command.env(key, value); }
        command.output().expect("git must be installed")
    }
    fn git_ok(root: &Path, home: &Path, args: &[&str], extra: &[(&str, &Path)]) -> String {
        let out = git(root, home, args, extra);
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim_end().to_owned()
    }
    fn init(root: &Path, home: &Path) {
        fs::create_dir(root).unwrap();
        git_ok(root, home, &["init", "-q"], &[]);
        for (key, val) in [("core.autocrlf", "false"), ("core.eol", "native"), ("status.showUntrackedFiles", "all")] {
            git_ok(root, home, &["config", key, val], &[]);
        }
        #[cfg(unix)]
        for (key, val) in [("core.fileMode", "true"), ("core.symlinks", "true")] {
            git_ok(root, home, &["config", key, val], &[]);
        }
        let empty = home.join("empty");
        fs::write(&empty, "").unwrap();
        for key in ["core.excludesfile", "core.attributesfile"] {
            git_ok(root, home, &["config", key, empty.to_str().unwrap()], &[]);
        }
    }
    fn place(root: &Path, rel: &str, rng: &mut Rng, link: bool) {
        let path = root.join(rel);
        if fs::create_dir_all(path.parent().unwrap()).is_err() { return; }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            let result = if meta.is_dir() { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
            if result.is_err() { return; }
        }
        #[cfg(unix)]
        if link {
            use std::os::unix::fs::symlink;
            let target = ["a", "../a.txt", "dir", "missing", "."][rng.n(5)];
            let _ = symlink(target, &path);
            return;
        }
        #[cfg(not(unix))]
        let _ = link;
        if fs::write(&path, rng.content()).is_ok() {
            #[cfg(unix)]
            if rng.n(5) == 0 {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o755));
            }
        }
    }
    fn expected(root: &Path, home: &Path, temp: &Path) -> String {
        let index = temp.join("index");
        let source = root.join(".git/index");
        if source.exists() { fs::copy(source, &index).unwrap(); }
        let objects = temp.join("git-objects");
        fs::create_dir(&objects).unwrap();
        let alternate = root.join(".git/objects");
        let env = [("GIT_INDEX_FILE", index.as_path()), ("GIT_OBJECT_DIRECTORY", objects.as_path()), ("GIT_ALTERNATE_OBJECT_DIRECTORIES", alternate.as_path())];
        git_ok(root, home, &["-c", "core.splitIndex=false", "add", "-A"], &env);
        git_ok(root, home, &["-c", "core.splitIndex=false", "write-tree", "--missing-ok"], &env)
    }
    fn parity(category: usize) {
        let names = ["plain", "text-auto", "autocrlf-true", "eol-attributes", "gitignore", "staged", "untracked-hidden", "symlinks-off"];
        let mut verified = 0;
        for iteration in 0..20 {
            let tmp = Temp::new();
            let root = tmp.0.join("repo");
            let home = tmp.0.join("home");
            fs::create_dir(&home).unwrap();
            init(&root, &home);
            let mut rng = Rng((category as u64).wrapping_mul(0xd1b54a32d192ed03) ^ iteration as u64 ^ 0x5eed);
            match category {
                1 => fs::write(root.join(".gitattributes"), "* text=auto\n").unwrap(),
                2 => { git_ok(&root, &home, &["config", "core.autocrlf", "true"], &[]); },
                3 => {
                    fs::write(root.join(".gitattributes"), "*.txt eol=lf\n*.b eol=crlf\n*.dat binary\n").unwrap();
                    git_ok(&root, &home, &["config", "core.autocrlf", "input"], &[]);
                },
                4 => {
                    let mut rules = Vec::new();
                    for _ in 0..1 + rng.n(4) { rules.push(RULES[rng.n(RULES.len())]); }
                    fs::write(root.join(".gitignore"), format!("{}\n", rules.join("\n"))).unwrap();
                    let mut outside = Vec::new();
                    for _ in 0..1 + rng.n(4) { outside.push(RULES[rng.n(RULES.len())]); }
                    fs::write(root.join(".git/info/exclude"), format!("{}\n", outside.join("\n"))).unwrap();
                },
                6 => { git_ok(&root, &home, &["config", "status.showUntrackedFiles", "no"], &[]); },
                7 => { git_ok(&root, &home, &["config", "core.symlinks", "false"], &[]); },
                _ => {}
            }
            for _ in 0..3 + rng.n(12) {
                let path = rng.path();
                let link = rng.n(10) == 0;
                place(&root, &path, &mut rng, link);
            }
            git_ok(&root, &home, &["add", "-A"], &[]);
            git_ok(&root, &home, &["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base", "--allow-empty"], &[]);
            let tracked = git(&root, &home, &["ls-files", "-z"], &[]).stdout;
            let tracked: Vec<&str> = tracked.split(|b| *b == 0).filter(|v| !v.is_empty()).map(|v| std::str::from_utf8(v).unwrap()).collect();
            for _ in 0..1 + rng.n(9) {
                let action = rng.n(100);
                if !tracked.is_empty() && action < 45 {
                    let path = root.join(tracked[rng.n(tracked.len())]);
                    if let Ok(meta) = fs::symlink_metadata(&path) {
                        if action < 30 && meta.is_file() {
                            if rng.n(10) < 7 { let _ = fs::write(&path, rng.content()); }
                            else {
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(meta.permissions().mode() ^ 0o111));
                                }
                            }
                        } else if action >= 30 && !meta.is_dir() { let _ = fs::remove_file(&path); }
                    }
                } else {
                    let path = rng.path();
                    place(&root, &path, &mut rng, action < 55);
                }
            }
            if category == 5 {
                let output = git(&root, &home, &["-c", "status.renames=false", "status", "--porcelain", "-z", "-uall"], &[]);
                assert!(output.status.success());
                let changed: Vec<&[u8]> = output.stdout.split(|b| *b == 0).filter(|s| s.len() > 3).collect();
                for _ in 0..rng.n(3).min(changed.len()) {
                    let path = std::str::from_utf8(&changed[rng.n(changed.len())][3..]).unwrap();
                    let args = if rng.n(3) == 0 { vec!["add", "-N", "--", path] } else { vec!["add", "--", path] };
                    let _ = git(&root, &home, &args, &[]);
                }
            }
            let expected = expected(&root, &home, &tmp.0);
            let store = tmp.0.join("core-objects");
            let root_str = root.to_str().unwrap();
            let store_str = store.to_str().unwrap();
            match stage_and_write_impl(root_str, store_str) {
                Ok(got) => {
                    if got != expected {
                        let original = root.join(".git/objects");
                        let reference = tmp.0.join("git-objects");
                        let actual_env = [("GIT_OBJECT_DIRECTORY", store.as_path()), ("GIT_ALTERNATE_OBJECT_DIRECTORIES", original.as_path())];
                        let expected_env = [("GIT_OBJECT_DIRECTORY", reference.as_path()), ("GIT_ALTERNATE_OBJECT_DIRECTORIES", original.as_path())];
                        let actual_tree = git_ok(&root, &home, &["ls-tree", "-r", &got], &actual_env);
                        let expected_tree = git_ok(&root, &home, &["ls-tree", "-r", &expected], &expected_env);
                        panic!("{} iteration {iteration}\nactual:\n{actual_tree}\nexpected:\n{expected_tree}", names[category]);
                    }
                    assert_eq!(worktree_fingerprint(root_str, store_str), Some(expected), "{} iteration {iteration}", names[category]);
                    verified += 1;
                }
                Err(error) if error.to_string().starts_with("route:") => assert_eq!(worktree_fingerprint(root_str, store_str), None),
                Err(error) => panic!("{} iteration {iteration}: {error}", names[category]),
            }
        }
        assert!(verified > 0, "{} had no verified trees", names[category]);
    }
    #[test] fn parity_plain() { parity(0); }
    #[test] fn parity_text_auto() { parity(1); }
    #[test] fn parity_autocrlf_true() { parity(2); }
    #[test] fn parity_eol_attributes() { parity(3); }
    #[test] fn parity_gitignore() { parity(4); }
    #[test] fn parity_staged() { parity(5); }
    #[test] fn parity_untracked_hidden() { parity(6); }
    #[test] fn parity_symlinks_off() { parity(7); }

    #[test]
    fn ignore_negations_apply_in_both_files() {
        let tmp = Temp::new();
        let home = tmp.0.join("home");
        fs::create_dir(&home).unwrap();
        let root = tmp.0.join("repo");
        init(&root, &home);
        let global_excludes = home.join("excludes");
        fs::write(&global_excludes, "*.txt\n!keep.txt\n").unwrap();
        git_ok(&root, &home, &["config", "core.excludesfile", global_excludes.to_str().unwrap()], &[]);
        fs::write(root.join(".gitignore"), "*.dat\n!keep.dat\n").unwrap();
        fs::write(root.join(".git/info/exclude"), "*.b\n!keep.b\n").unwrap();
        for name in ["skip.dat", "keep.dat", "skip.b", "keep.b", "skip.txt", "keep.txt"] {
            fs::write(root.join(name), name).unwrap();
        }
        let tree = expected(&root, &home, &tmp.0);
        let objects = tmp.0.join("git-objects");
        let alternate = root.join(".git/objects");
        let env = [("GIT_OBJECT_DIRECTORY", objects.as_path()), ("GIT_ALTERNATE_OBJECT_DIRECTORIES", alternate.as_path())];
        let names = git_ok(&root, &home, &["ls-tree", "-r", "--name-only", &tree], &env);
        assert_eq!(names.lines().collect::<Vec<_>>(), [".gitignore", "keep.b", "keep.dat", "keep.txt"]);
        let store = tmp.0.join("core-objects");
        assert_eq!(worktree_fingerprint(root.to_str().unwrap(), store.to_str().unwrap()), Some(tree));
    }

    #[test]
    fn routes_unproven_new_attributes() {
        let tmp = Temp::new();
        let home = tmp.0.join("home");
        fs::create_dir(&home).unwrap();
        let root = tmp.0.join("repo");
        init(&root, &home);
        fs::write(root.join(".gitattributes"), "*.txt ident\n").unwrap();
        let store = tmp.0.join("objects");
        let root = root.to_str().unwrap();
        let store = store.to_str().unwrap();
        assert!(stage_and_write_impl(root, store).unwrap_err().to_string().starts_with("route:"));
        assert_eq!(worktree_fingerprint(root, store), None);
    }

    #[test]
    fn refuses_non_repository_and_embedded_repository() {
        let tmp = Temp::new();
        let home = tmp.0.join("home");
        fs::create_dir(&home).unwrap();
        let root = tmp.0.join("repo");
        fs::create_dir(&root).unwrap();
        let store = tmp.0.join("objects");
        assert_eq!(worktree_fingerprint(root.to_str().unwrap(), store.to_str().unwrap()), None);
        git_ok(&root, &home, &["init", "-q"], &[]);
        let embedded = root.join("embedded");
        init(&embedded, &home);
        assert_eq!(worktree_fingerprint(root.to_str().unwrap(), store.to_str().unwrap()), None);
    }

    #[test]
    fn ignores_only_untracked_generated_caches() {
        let tmp = Temp::new();
        let home = tmp.0.join("home");
        fs::create_dir(&home).unwrap();
        let root = tmp.0.join("repo");
        init(&root, &home);
        fs::create_dir_all(root.join("__pycache__")).unwrap();
        fs::write(root.join("__pycache__/tracked.pyc"), "tracked").unwrap();
        git_ok(&root, &home, &["add", "-f", "__pycache__/tracked.pyc"], &[]);
        let store = tmp.0.join("objects");
        let fingerprint = || worktree_fingerprint(root.to_str().unwrap(), store.to_str().unwrap()).unwrap();
        let before = fingerprint();
        for path in ["__pycache__/m.pyc", ".pytest_cache/v/cache/lastfailed", ".tox/py/log"] {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, "ignored").unwrap();
        }
        assert_eq!(fingerprint(), before);
        fs::write(root.join("top.pyc"), "loose").unwrap();
        let loose = fingerprint();
        assert_ne!(loose, before);
        fs::write(root.join("__pycache__/tracked.pyc"), "changed").unwrap();
        assert_ne!(fingerprint(), loose);
    }
}
