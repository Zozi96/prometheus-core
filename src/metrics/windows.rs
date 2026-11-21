//! Windows private opening for the metrics store.
//!
//! Mirrors the Unix fd-walk: `savings.jsonl` is reached only through pinned
//! directory handles that refuse `FILE_SHARE_DELETE` and reparse points,
//! missing fixed directories are created only for writes (each atomically
//! with the token user as explicit owner and an owner-only protected DACL),
//! and the private directory plus file are validated through `GetSecurityInfo`
//! against the process token's user SID. Unsafe objects are refused, never
//! repaired.

use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Component, Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GENERIC_READ,
    GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetTokenInformation, IsWellKnownSid, TokenUser, WinCreatorOwnerRightsSid,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `ACCESS_ALLOWED_ACE_TYPE` (0x00); windows-sys does not name ACE-type constants.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const SDDL_REVISION_1: u32 = 1;

const DIR_FLAGS: u32 = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
const DIR_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

/// Owning wrapper for a Win32 `HANDLE`; closes on drop. Handles moved out via
/// [`WinHandle::into_raw`] are no longer closed here.
struct WinHandle(HANDLE);

impl WinHandle {
    fn into_raw(self) -> HANDLE {
        let raw = self.0;
        std::mem::forget(self);
        raw
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Process token's user SID. `TOKEN_USER` points into the same allocation as
/// the returned `PSID`, so the backing buffer must outlive `sid`.
struct TokenUser {
    _buf: Vec<u64>,
    sid: PSID,
}

fn token_user() -> Option<TokenUser> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 || token.is_null() {
            return None;
        }
        let token = WinHandle(token);
        let mut needed = 0u32;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
        if needed < std::mem::size_of::<TOKEN_USER>() as u32 {
            return None;
        }
        // TOKEN_USER embeds pointers; u64 slots keep the buffer aligned.
        let mut buf = vec![0u64; needed.div_ceil(8) as usize];
        let ok = GetTokenInformation(
            token.0,
            TokenUser,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            (buf.len() * std::mem::size_of::<u64>()) as u32,
            &mut needed,
        );
        if ok == 0 {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        if user.User.Sid.is_null() {
            return None;
        }
        Some(TokenUser {
            _buf: buf,
            sid: user.User.Sid,
        })
    }
}

/// `ConvertSidToStringSidW` renders e.g. `S-1-5-21-...`; the returned buffer
/// is `LocalFree`d before the owned `String` comes back.
fn sid_string(sid: PSID) -> Option<String> {
    unsafe {
        let mut text: *mut u16 = null_mut();
        if ConvertSidToStringSidW(sid, &mut text) == 0 || text.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *text.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast::<std::ffi::c_void>());
        Some(s)
    }
}

/// Security descriptor for private objects: the token user as explicit owner
/// plus a protected owner-only DACL, so a newly created file or directory
/// stays private even when its parent DACL has no inheritable ACEs. The
/// descriptor is `LocalFree`d on drop.
struct PrivateDescriptor(PSECURITY_DESCRIPTOR);

impl PrivateDescriptor {
    fn new(owner: PSID) -> Option<Self> {
        let owner_text = sid_string(owner)?;
        let sddl = wide_str(&format!("O:{owner_text}D:P(A;OICI;FA;;;OW)"));
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut size = 0u32;
        let made = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &mut size,
            )
        };
        if made == 0 || sd.is_null() {
            return None;
        }
        Some(Self(sd))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for PrivateDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `default_home` must be an absolute path on a local drive; UNC, device, and
/// other non-disk prefixes are refused before any handle is opened.
fn local_drive_home() -> Option<PathBuf> {
    let home = crate::droid_mode::default_home().ok()?;
    if local_drive(&home) {
        Some(home)
    } else {
        None
    }
}

/// Absolute path on a local drive (`C:\…`, `\\?\C:\…`); UNC, device, and
/// other non-disk prefixes are refused.
fn local_drive(path: &Path) -> bool {
    path.is_absolute()
        && matches!(
            path.components().next(),
            Some(Component::Prefix(prefix))
                if matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                )
        )
}

/// `CreateFileW` with fixed flags; `sa` only matters when the call creates.
fn create_file(
    path: &Path,
    access: u32,
    share: u32,
    sa: *const SECURITY_ATTRIBUTES,
    disposition: u32,
    flags_and_attributes: u32,
) -> Option<WinHandle> {
    let wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share,
            sa,
            disposition,
            flags_and_attributes,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        None
    } else {
        Some(WinHandle(handle))
    }
}

fn open_dir(path: &Path) -> Option<WinHandle> {
    create_file(
        path,
        GENERIC_READ,
        DIR_SHARE,
        null(),
        OPEN_EXISTING,
        DIR_FLAGS,
    )
}

/// Create a fixed directory with the token user as explicit owner and a
/// protected owner-only DACL, so a directory made under a parent without
/// inheritable ACEs still validates. `false` covers both "already exists"
/// and refused creation — callers reopen and validate either way.
fn create_dir(path: &Path, owner: PSID) -> bool {
    let wide = wide_path(path);
    let Some(desc) = PrivateDescriptor::new(owner) else {
        return false;
    };
    let sa = desc.attributes();
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &sa) };
    created != 0 || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS
}

/// Owner SID must equal the token user; with `strict_dacl` the DACL must be
/// present and every ACE an allow for OWNER RIGHTS or the owner SID only.
/// Anything else — null DACL, deny/audit/unknown ACE types, foreign SIDs —
/// is refused rather than repaired.
fn security_ok(handle: HANDLE, owner: PSID, strict_dacl: bool) -> bool {
    unsafe {
        let mut sid_owner: PSID = null_mut();
        let mut group: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let rc = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut sid_owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return false;
        }
        let ok = !sd.is_null()
            && !sid_owner.is_null()
            && EqualSid(sid_owner, owner) != 0
            && (!strict_dacl || dacl_allows_only_owner(dacl, owner));
        if !sd.is_null() {
            LocalFree(sd);
        }
        ok
    }
}

fn dacl_allows_only_owner(dacl: *mut ACL, owner: PSID) -> bool {
    unsafe {
        if dacl.is_null() {
            return false;
        }
        let acl = &*dacl;
        if acl.AceCount == 0 {
            return false;
        }
        for index in 0..acl.AceCount {
            let mut ace: *mut std::ffi::c_void = null_mut();
            if GetAce(dacl, u32::from(index), &mut ace) == 0 || ace.is_null() {
                return false;
            }
            let header = &*(ace as *const ACE_HEADER);
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                return false;
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            // `SidStart` is the first word of the variable-length SID that
            // trails the fixed ACCESS_ALLOWED_ACE fields.
            let sid = (&allowed.SidStart as *const u32)
                .cast::<std::ffi::c_void>()
                .cast_mut();
            if EqualSid(sid, owner) == 0 && !sid_is_owner_rights(sid) {
                return false;
            }
        }
        true
    }
}

fn sid_is_owner_rights(sid: PSID) -> bool {
    unsafe { IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0 }
}

/// The handle must reference a real directory with no reparse point.
fn real_dir(handle: HANDLE) -> bool {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return false;
    }
    let attrs = info.dwFileAttributes;
    attrs & FILE_ATTRIBUTE_DIRECTORY != 0 && attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

/// A pinned directory handle must be a real directory (not a reparse point)
/// owned by the token user; `private` additionally requires the owner-only
/// DACL used for the metrics directory.
fn valid_dir(handle: &WinHandle, private: bool, owner: PSID) -> bool {
    real_dir(handle.0) && security_ok(handle.0, owner, private)
}

/// Open `path` as a pinned directory handle, creating it first when `write`
/// allows. Handles stay open until the caller drops them, which keeps the
/// ancestor chain unrenamable while the metrics file is opened.
fn pinned_dir(path: &Path, write: bool, private: bool, owner: PSID) -> Option<WinHandle> {
    let handle = match open_dir(path) {
        Some(h) => h,
        None if write => {
            let _ = create_dir(path, owner);
            open_dir(path)?
        }
        None => return None,
    };
    if valid_dir(&handle, private, owner) {
        Some(handle)
    } else {
        None
    }
}

/// Open `path` with the given access/disposition, optionally supplying the
/// private descriptor so a creating open stays owner-private even under a
/// non-inheriting parent. The resulting handle must be a single-link regular
/// file with no reparse point and an owner-only DACL.
fn open_file_checked(
    file_path: &Path,
    access: u32,
    disposition: u32,
    private_desc: bool,
    owner: PSID,
) -> Option<File> {
    let desc = if private_desc {
        Some(PrivateDescriptor::new(owner)?)
    } else {
        None
    };
    let sa = desc.as_ref().map(|d| d.attributes());
    let handle = create_file(
        file_path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        sa.as_ref().map_or(null(), std::ptr::from_ref),
        disposition,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle.0, &mut info) } != 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0
        && info.nNumberOfLinks == 1
        && security_ok(handle.0, owner, true);
    if !ok {
        return None;
    }
    let raw = handle.into_raw();
    Some(unsafe { File::from_raw_handle(raw) })
}

/// Open `savings.jsonl` under the pinned metrics directory. The writer opens
/// read+write with `OPEN_ALWAYS` (Windows `try_lock` needs a seekable handle;
/// Unix stays `O_APPEND`) and the private descriptor so `OPEN_ALWAYS` creates
/// a private file even when the metrics directory DACL has no inheritable
/// ACEs; the reader opens `OPEN_EXISTING` read-only and never creates.
fn open_metrics_file(file_path: &Path, write: bool, owner: PSID) -> Option<File> {
    let (access, disposition) = if write {
        (GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS)
    } else {
        (GENERIC_READ, OPEN_EXISTING)
    };
    open_file_checked(file_path, access, disposition, write, owner)
}

/// Open `<home>/.agents/prometheus/metrics/savings.jsonl` with the same
/// refusal posture as the Unix implementation: absolute local-drive home
/// only, every ancestor pinned by a handle that refuses delete-sharing and
/// reparse points, missing fixed directories created only for writes, and
/// nothing created on the read path.
pub(super) fn open_metrics(write: bool) -> Option<File> {
    let home = local_drive_home()?;
    let user = token_user()?;
    let _home_dir = open_dir(&home).filter(|h| valid_dir(h, false, user.sid))?;
    let agents_path = home.join(".agents");
    let _agents = pinned_dir(&agents_path, write, false, user.sid)?;
    let prometheus_path = agents_path.join("prometheus");
    let _prometheus = pinned_dir(&prometheus_path, write, false, user.sid)?;
    let metrics_path = prometheus_path.join("metrics");
    let _metrics = pinned_dir(&metrics_path, write, true, user.sid)?;
    open_metrics_file(&metrics_path.join("savings.jsonl"), write, user.sid)
}

/// Create `path` as a new owner-private file for kept logs: `CREATE_NEW`
/// never truncates an existing name, the private descriptor supplies an
/// owner-only DACL even under a non-inheriting parent, and the handle is
/// validated like the metrics file (regular, single-link, no reparse point,
/// strict owner-only DACL). Returns a writable `File` or None.
fn create_file_private(path: &Path) -> Option<File> {
    let user = token_user()?;
    open_file_checked(
        path,
        GENERIC_READ | GENERIC_WRITE,
        CREATE_NEW,
        true,
        user.sid,
    )
}

/// Pin `path` as a real directory handle — no reparse point — without any
/// ownership or DACL requirement, for ancestors that need not belong to the
/// token user (temp roots, system dirs). The handle's share mode still
/// refuses delete/rename while it is held.
fn pin_plain_dir(path: &Path) -> Option<WinHandle> {
    let handle = open_dir(path)?;
    if real_dir(handle.0) {
        Some(handle)
    } else {
        None
    }
}

/// Write `raw` bytes as a new owner-private log under `base/kit-logs` for
/// `compact --keep-log`. The canonical parent chain and both fixed
/// directories are pinned by handles — refusing reparse points and delete
/// sharing — for the whole create-and-write, so the route cannot be renamed
/// or swapped mid-flight. `base` itself must already be absolute on a local
/// drive; non-local prefixes are refused. Returns the log path or None.
pub(crate) fn write_private_log(base: &Path, raw: &[u8]) -> Option<PathBuf> {
    let user = token_user()?;
    let parent = base.parent()?.canonicalize().ok()?;
    if !local_drive(&parent) {
        return None;
    }
    let mut pins: Vec<WinHandle> = Vec::new();
    for ancestor in parent.ancestors() {
        pins.push(pin_plain_dir(ancestor)?);
    }
    let _slot = pinned_dir(base, true, true, user.sid)?;
    let dir = base.join("kit-logs");
    let _log_dir = pinned_dir(&dir, true, true, user.sid)?;
    crate::kit_util::claim_named_log(&dir, "compact", raw, create_file_private)
}
