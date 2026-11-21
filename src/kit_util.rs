//! Shared deterministic utilities for `prometheus-kit` subcommands (`compact`, `search`, `diff`, `map`).

use crate::check::host_slot_dir;
use crate::store::ensure_private_dir;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn approx_tokens(s: &str) -> usize {
    s.len() / 4
}

/// Strip ANSI CSI/OSC escape sequences and resolve `\r` progress overwrites cleanly.
pub fn strip_ansi_and_cr(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut stripped = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            if i + 1 < bytes.len() && bytes[i + 1] == b'[' {
                // CSI: ESC [ ... <0x40..=0x7e>
                let mut j = i + 2;
                while j < bytes.len() && !(0x40..=0x7e).contains(&bytes[j]) {
                    j += 1;
                }
                i = if j < bytes.len() { j + 1 } else { bytes.len() };
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b']' {
                // OSC: ESC ] ... (BEL | ESC \)
                let mut j = i + 2;
                while j < bytes.len() {
                    if bytes[j] == 0x07 {
                        j += 1;
                        break;
                    }
                    if bytes[j] == 0x1b && j + 1 < bytes.len() && bytes[j + 1] == b'\\' {
                        j += 2;
                        break;
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            // Other 2-byte ESC sequence: only consume the byte after ESC when ASCII so a
            // following multi-byte UTF-8 scalar is never split mid-sequence.
            i += if i + 1 < bytes.len() && bytes[i + 1].is_ascii() {
                2
            } else {
                1
            };
            continue;
        }
        if let Some(ch) = input[i..].chars().next() {
            stripped.push(ch);
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }

    // Normalize `\r\n` -> `\n`, then resolve bare `\r` progress bar overwrites per line.
    let norm = stripped.replace("\r\n", "\n");
    if !norm.contains('\r') {
        return norm;
    }
    let trailing_nl = norm.ends_with('\n');
    let mut out = String::with_capacity(norm.len());
    for (idx, line) in norm.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        if line.contains('\r') {
            let final_seg = line
                .rsplit('\r')
                .find(|seg| !seg.is_empty())
                .unwrap_or("");
            out.push_str(final_seg);
        } else {
            out.push_str(line);
        }
    }
    if trailing_nl && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// True for lockfiles, minified/map artifacts, generated code, and common vendor/build directories.
pub fn is_noise_path(rel_path: &str) -> bool {
    let normalized = rel_path.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let Some(&base) = parts.last() else {
        return false;
    };

    for (idx, &seg) in parts[..parts.len().saturating_sub(1)].iter().enumerate() {
        if matches!(
            seg,
            ".git"
                | "node_modules"
                | "target"
                | "obj"
                | "dist"
                | "__pycache__"
                | ".venv"
                | ".next"
                | ".nuxt"
                | ".pytest_cache"
                | ".mypy_cache"
                | ".ruff_cache"
        ) {
            return true;
        }
        // `.NET` `bin/` outputs are noise, while `src/bin/` (Rust/Go/Python executables) is source.
        if seg == "bin" {
            let prev = idx.checked_sub(1).and_then(|p| parts.get(p).copied());
            if prev != Some("src") {
                return true;
            }
        }
    }

    if matches!(
        base,
        "Cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "uv.lock"
            | "composer.lock"
            | "Gemfile.lock"
            | "packages.lock.json"
            | "flake.lock"
            | "bun.lockb"
            | "bun.lock"
    ) {
        return true;
    }

    let lower = base.to_ascii_lowercase();
    if lower.contains(".generated.") {
        return true;
    }
    matches!(
        lower.as_str(),
        s if s.ends_with(".min.js")
            || s.ends_with(".min.css")
            || s.ends_with(".bundle.js")
            || s.ends_with(".chunk.js")
            || s.ends_with(".js.map")
            || s.ends_with(".css.map")
            || s.ends_with(".designer.cs")
            || s.ends_with(".g.cs")
            || s.ends_with(".g.i.cs")
            || s.ends_with(".pb.go")
            || s.ends_with(".pb.rs")
    )
}

/// Clip `line` to at most `max_chars` centered around `[match_byte_start..match_byte_end]`.
pub fn clip_centered(
    line: &str,
    match_byte_start: usize,
    match_byte_end: usize,
    max_chars: usize,
) -> (String, bool) {
    if max_chars == 0 {
        return (line.to_owned(), false);
    }
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let total = chars.len();
    if total <= max_chars {
        return (line.to_owned(), false);
    }
    let m_start = chars.partition_point(|&(b, _)| b < match_byte_start);
    let m_end = chars.partition_point(|&(b, _)| b < match_byte_end).max(m_start);
    let center = m_start + (m_end.saturating_sub(m_start)) / 2;
    let window = max_chars.saturating_sub(10).max(16);
    let mut win_start = center.saturating_sub(window / 2);
    let mut win_end = (win_start + window).min(total);
    if win_end - win_start < window {
        win_start = win_end.saturating_sub(window);
    }
    win_end = win_end.min(total);

    let slice_start = chars[win_start].0;
    let slice_end = if win_end < total {
        chars[win_end].0
    } else {
        line.len()
    };
    let mut out = String::new();
    if win_start > 0 {
        out.push_str("...");
    }
    out.push_str(&line[slice_start..slice_end]);
    if win_end < total {
        out.push_str(&format!("... (+{} chars)", total - win_end));
    }
    (out, true)
}

/// Enforce an exact byte budget (`max_bytes`) at a UTF-8 char boundary.
pub fn clip_to_byte_budget(text: &str, max_bytes: usize) -> String {
    if max_bytes == 0 || text.len() <= max_bytes {
        return text.to_owned();
    }
    let suffix = "\n... (truncated to --max-tokens)\n";
    if max_bytes <= suffix.len() {
        let mut end = max_bytes;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        return text[..end].to_owned();
    }
    let mut end = max_bytes - suffix.len();
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{suffix}", text[..end].trim_end_matches('\n'))
}

/// Clip `line` from the end cleanly at a UTF-8 char boundary.
pub fn clip_end(line: &str, max_chars: usize) -> (String, bool) {
    if max_chars == 0 {
        return (line.to_owned(), false);
    }
    let total = line.chars().count();
    if total <= max_chars {
        return (line.to_owned(), false);
    }
    let keep = max_chars.saturating_sub(20).max(8);
    let head: String = line.chars().take(keep).collect();
    let omitted = total.saturating_sub(keep);
    (format!("{head}... (+{omitted} chars)"), true)
}

/// Persist full lossless output to an explicit path or an owner-private temp log directory.
pub fn write_spillover_log(explicit: Option<&Path>, prefix: &str, raw: &str) -> Option<PathBuf> {
    if let Some(path) = explicit {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return None;
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && std::fs::create_dir_all(parent).is_err() {
                return None;
            }
        }
        return std::fs::write(path, raw.as_bytes())
            .ok()
            .map(|_| path.to_path_buf());
    }

    let base = host_slot_dir();
    if ensure_private_dir(&base).is_err() {
        return None;
    }
    let dir = base.join("kit-logs");
    if ensure_private_dir(&dir).is_err() {
        return None;
    }
    claim_temp_log(&dir, prefix, raw.as_bytes(), false)
}

/// Temp-only private spillover for `compact --keep-log`: the raw captured
/// bytes are stored unnormalized under `<slot>/kit-logs` with a fixed
/// `compact-*` name. The route is refused — returning None so the caller
/// emits the raw stream instead — whenever the slot sits inside the working
/// tree or any git worktree, an ancestor is insecure, a `.git` marker
/// appears in the route, or the private directory route, a printable path,
/// or an exclusive private file cannot be established.
pub fn write_private_spillover(raw: &[u8]) -> Option<PathBuf> {
    let slot = host_slot_dir();
    if !slot.is_absolute() {
        return None;
    }
    // `.git` as a route component is refused outright.
    if slot.components().any(|c| c.as_os_str() == ".git") {
        return None;
    }
    // Canonicalize the slot's parent so symlinked runtime dirs cannot smuggle
    // the route into the worktree; the slot's own name is kept verbatim and
    // revalidated by `ensure_private_dir`/the Windows pins below.
    let parent = slot.parent()?.canonicalize().ok()?;
    let cwd = std::env::current_dir().ok()?.canonicalize().ok()?;
    // A runtime dir inside the working tree — or anywhere under a git
    // worktree — would leak command output into source control. Any
    // `.git` entry (directory or gitfile) on an ancestor refuses the route.
    if parent.starts_with(&cwd)
        || parent.ancestors().any(|p| match std::fs::symlink_metadata(p.join(".git")) {
            Ok(_) => true,
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        })
    {
        return None;
    }
    #[cfg(unix)]
    if !ancestors_allow_private_logs(&parent) {
        return None;
    }
    let base = parent.join(slot.file_name()?);
    let dir = base.join("kit-logs");
    // An existing `.git` inside the slot or log dir — file or directory —
    // refuses the route before anything is created.
    for target in [&base, &dir] {
        match std::fs::symlink_metadata(target.join(".git")) {
            Ok(_) => return None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    // The `log:` pointer must be printable; control characters or a non-UTF8
    // path fall back to raw output rather than advertising an unreachable log.
    let dir_text = dir.to_str()?;
    if dir_text.chars().any(|c| c.is_control()) {
        return None;
    }
    #[cfg(unix)]
    {
        ensure_private_dir(&base).ok()?;
        ensure_private_dir(&dir).ok()?;
        claim_named_log(&dir, "compact", raw, |path| open_log_new(path, true))
    }
    #[cfg(windows)]
    {
        crate::metrics::windows::write_private_log(&base, raw)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Unique create-new claim inside `dir` using the shared
/// `{prefix}-{millis}-{pid}-{attempt}.log` naming; `open` supplies the
/// platform-private create for each candidate.
pub(crate) fn claim_named_log(
    dir: &Path,
    prefix: &str,
    raw: &[u8],
    open: impl Fn(&Path) -> Option<std::fs::File>,
) -> Option<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let pid = std::process::id();
    for attempt in 0u32..16 {
        let candidate = dir.join(format!("{prefix}-{stamp}-{pid}-{attempt}.log"));
        let Some(mut file) = open(&candidate) else {
            continue;
        };
        if file.write_all(raw).is_ok() {
            return Some(candidate);
        }
        let _ = std::fs::remove_file(&candidate);
        return None;
    }
    None
}

fn claim_temp_log(dir: &Path, prefix: &str, raw: &[u8], private: bool) -> Option<PathBuf> {
    claim_named_log(dir, prefix, raw, |path| open_log_new(path, private))
}

/// Canonical-parent ancestors must be real directories owned by root or this
/// user, and never group/world-writable without the sticky bit — the same
/// posture `ensure_private_dir` demands of the directories it creates.
#[cfg(unix)]
fn ancestors_allow_private_logs(parent: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    parent.ancestors().all(|dir| {
        let Ok(meta) = std::fs::symlink_metadata(dir) else {
            return false;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return false;
        }
        if meta.uid() != 0 && meta.uid() != unsafe { libc::getuid() } {
            return false;
        }
        meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0
    })
}

/// Open `path` with create-new semantics for a log file. `private` adds
/// O_NOFOLLOW on Unix; the Windows kept-log route creates through the strict
/// private descriptor in `metrics::windows` instead, so this open always
/// matches the legacy spillover writer there.
#[cfg(unix)]
fn open_log_new(path: &Path, private: bool) -> Option<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        if private {
            opts.custom_flags(libc::O_NOFOLLOW);
        }
    }
    opts.open(path).ok()
}

#[cfg(windows)]
fn open_log_new(path: &Path, _private: bool) -> Option<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ok()
}

#[cfg(not(any(unix, windows)))]
fn open_log_new(path: &Path, _private: bool) -> Option<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_and_resolves_progress_carriage_returns() {
        let raw = "\x1b[32mDownloading\x1b[0m 10%\rDownloading 80%\rDone!\r\nNext\x1b]0;title\x07 line\n";
        assert_eq!(strip_ansi_and_cr(raw), "Done!\nNext line\n");
        let esc_utf8 = "\x1bé\x1b\u{FFFD}\n";
        assert_eq!(strip_ansi_and_cr(esc_utf8), "é\u{FFFD}\n");
    }

    #[test]
    fn clip_to_byte_budget_enforces_multibyte_bytes() {
        let multi = "あ".repeat(200);
        let clipped = clip_to_byte_budget(&multi, 120);
        assert!(clipped.len() <= 120);
        assert!(clipped.contains("truncated to --max-tokens"));
    }

    #[test]
    fn noise_path_filters_lockfiles_minified_and_dotnet_bin_but_keeps_src_bin() {
        assert!(is_noise_path("Cargo.lock"));
        assert!(is_noise_path("web/package-lock.json"));
        assert!(is_noise_path("wwwroot/app.min.js"));
        assert!(is_noise_path("Views/Home.g.cs"));
        assert!(is_noise_path("src/App/obj/Debug/net9.0/App.dll"));
        assert!(is_noise_path("App/bin/Release/App.dll"));
        assert!(!is_noise_path("core/src/bin/prometheus-kit.rs"));
        assert!(!is_noise_path("build/deployment/targets.json"));
    }

    #[test]
    fn clip_centered_is_utf8_safe_and_keeps_match() {
        let prefix = "á".repeat(120);
        let suffix = "é".repeat(120);
        let line = format!("{prefix}TARGET_MATCH{suffix}");
        let start = line.find("TARGET_MATCH").unwrap();
        let end = start + "TARGET_MATCH".len();
        let (clipped, did) = clip_centered(&line, start, end, 60);
        assert!(did);
        assert!(clipped.contains("TARGET_MATCH"));
        assert!(clipped.chars().count() <= 80);
    }

    #[test]
    fn spillover_log_writes_private_file() {
        let p = write_spillover_log(None, "test-compact", "hello raw log\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "hello raw log\n");
        let _ = std::fs::remove_file(p);
    }
}
