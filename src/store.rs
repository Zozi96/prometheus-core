//! Check slot and hashing primitives for `prometheus-check`.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SLOT_POLL: Duration = Duration::from_millis(20);

// ---------------------------------------------------------------------------
// SHA-256 (std has none; the engine's only crypto dependency, gix, is
// SHA-1). Verified against hashlib by the parity suite and against the
// FIPS 180-4 vectors in this module's tests.

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut block = bytes.to_vec();
    block.push(0x80);
    while block.len() % 64 != 56 {
        block.push(0);
    }
    block.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in block.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

// ---------------------------------------------------------------------------
// The host-wide Check slot. One slot per machine: an OS file lock on
// check-slot.lock (the kernel drops it when the holder dies, so a crash
// cannot wedge the next run), with the holder's metadata in
// check-slot.json. The locked File lives in this registry until release;
// the acquiring process owns it, exactly as the Python route owns its fd.
// Poll and timeout semantics are the Python route's: try at once, poll
// every 20 ms, and on timeout report the holder the metadata names.

static SLOT_COUNTER: AtomicU64 = AtomicU64::new(1);
static SLOTS: Mutex<Option<HashMap<u64, File>>> = Mutex::new(None);

pub enum SlotOutcome {
    Acquired(u64, f64),
    Timeout(f64, Vec<u8>),
    /// The slot could not be taken at all (directory or lock file unusable);
    /// the text names why. Not contention, and not success.
    Unavailable(String),
}

/// Acquire the host-wide Check slot for a native caller (the
/// `prometheus-check` runner, ADR-0010): the same lock file, metadata,
/// poll, and timeout semantics the Python route gets from
/// `store_slot_acquire`, so a gate compiled run and a runner compiled run
/// serialize on the one slot (GLOSSARY: Check slot).
pub fn acquire_slot(
    lock_path: &Path,
    meta_path: &Path,
    session_id: &str,
    host: &str,
    command: &[String],
    timeout_s: f64,
) -> SlotOutcome {
    slot_acquire_impl(lock_path, meta_path, session_id, host, command, timeout_s)
}

/// Release a slot acquired through `acquire_slot` (or the Python
/// binding): true when the token named a held slot.
pub fn release_slot(token: u64) -> bool {
    let file = slots().as_mut().and_then(|map| map.remove(&token));
    match file {
        Some(file) => {
            let _ = file.unlock();
            true
        }
        None => false,
    }
}

fn slots() -> std::sync::MutexGuard<'static, Option<HashMap<u64, File>>> {
    SLOTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Python's `json.dumps` string escaping (ensure_ascii), so the metadata
/// file parses to the same values whichever route wrote it.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch if (ch as u32) < 0x7f => out.push(ch),
            ch => {
                let cp = ch as u32;
                if cp < 0x10000 {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let rest = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (rest >> 10), 0xdc00 + (rest & 0x3ff)));
                }
            }
        }
    }
    out.push('"');
    out
}

fn slot_meta_json(session_id: &str, host: &str, command: &[String]) -> String {
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let command_json = command
        .iter()
        .map(|part| json_escape(part))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\"command\": [{}], \"host\": {}, \"pid\": {}, \"session_id\": {}, \"started_at\": {:?}}}\n",
        command_json,
        json_escape(host),
        std::process::id(),
        json_escape(session_id),
        started_at,
    )
}

/// Create `dir` owner-only, or validate an existing one: a real directory
/// (never a symlink) owned by this user with no group or world access. An
/// `AlreadyExists` race with another creator is validated, not trusted.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("unsafe directory {}: {why}", dir.display()));
    let io = |error: std::io::Error| format!("{}: {error}", dir.display());
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match create_private_dir(dir) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io(error)),
            }
            std::fs::symlink_metadata(dir).map_err(io)?
        }
        Err(error) => return Err(io(error)),
    };
    if meta.file_type().is_symlink() {
        return refuse("it is a symlink");
    }
    if !meta.is_dir() {
        return refuse("it is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::getuid() } {
            return refuse("it belongs to another user");
        }
        if meta.mode() & 0o077 != 0 {
            return refuse("it is accessible to group or others");
        }
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(dir)
    }
}

/// Open a slot file without following a symlink and require a regular
/// file owned by this user. `private` also demands no group or world
/// access (the lock file; the metadata file's mode is the writer's).
fn open_slot_file(path: &Path, create: bool, write: bool, private: bool) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(write).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        let meta = file.metadata()?;
        let unsafe_file = !meta.is_file()
            || meta.uid() != unsafe { libc::getuid() }
            || meta.nlink() != 1
            || (private && meta.mode() & 0o077 != 0);
        if unsafe_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "not a private regular file owned by this user",
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = private;
        options.open(path)
    }
}

fn read_slot_meta(path: &Path) -> Vec<u8> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if let Ok(mut file) = open_slot_file(path, false, false, false) {
        let _ = file.read_to_end(&mut bytes);
    }
    bytes
}

/// Rewrite the holder metadata through a checked handle: a symlink or a
/// foreign file is left untouched, and the slot is kept either way.
fn write_slot_meta(path: &Path, text: &str) {
    use std::io::Write;
    if let Ok(mut file) = open_slot_file(path, true, true, false) {
        if file.set_len(0).is_ok() {
            let _ = file.write_all(text.as_bytes());
        }
    }
}

fn slot_acquire_impl(
    lock_path: &Path,
    meta_path: &Path,
    session_id: &str,
    host: &str,
    command: &[String],
    timeout_s: f64,
) -> SlotOutcome {
    if let Some(parent) = lock_path.parent() {
        if let Err(why) = ensure_private_dir(parent) {
            return SlotOutcome::Unavailable(why);
        }
    }
    let file = match open_slot_file(lock_path, true, true, true) {
        Ok(file) => file,
        Err(error) => {
            return SlotOutcome::Unavailable(format!("lock file {}: {error}", lock_path.display()))
        }
    };
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(_) => {
                // WouldBlock and a lock error alike: the Python route's
                // nonblocking attempt returns False for both and polls on.
                let waited = started.elapsed().as_secs_f64();
                if waited >= timeout_s {
                    let meta = read_slot_meta(meta_path);
                    return SlotOutcome::Timeout(waited, meta);
                }
                std::thread::sleep(SLOT_POLL);
            }
        }
    }
    let waited = started.elapsed().as_secs_f64();
    // A contender that times out names what it can: a failed metadata
    // write never loses the slot.
    write_slot_meta(meta_path, &slot_meta_json(session_id, host, command));
    let token = SLOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    slots()
        .get_or_insert_with(HashMap::new)
        .insert(token, file);
    SlotOutcome::Acquired(token, waited)
}

#[cfg(test)]
mod tests {
    use super::{json_escape, sha256_hex};

    #[test]
    fn sha256_fips_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn json_escape_matches_python_dumps() {
        assert_eq!(json_escape("plain"), "\"plain\"");
        assert_eq!(json_escape("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(json_escape("á"), "\"\\u00e1\"");
        assert_eq!(json_escape("\u{1f600}"), "\"\\ud83d\\ude00\"");
        assert_eq!(json_escape("\u{01}\u{7f}"), "\"\\u0001\\u007f\"");
    }
}
