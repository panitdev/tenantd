//! File operations on a container's root, for the Files service. They run
//! in one of two places:
//!
//! - Inside the container ([`Root::inside`]): tenantd's helper, exec'd in
//!   the container as the caller's user, works on its own `/`. The
//!   container's mounts, permissions and quota apply as to any process.
//! - On the host ([`Root::open`]), for containers created with host access.
//!   Every path is resolved from a descriptor of the root with
//!   `openat2(2)` and `RESOLVE_IN_ROOT`, so `..` and symlinks (absolute
//!   ones included) resolve the way the container sees them and never lead
//!   out of the root. Paths under a mount the host can't see through fail
//!   with [`FsError::not_served`] set, for the caller to retry inside.
//!   Operations run on a thread of their own whose filesystem UID and GID
//!   and groups are the user's (all per thread on Linux), so the kernel
//!   checks that user's permissions and what it creates is that user's.
//!
//! Either way each operation works on a resolved directory descriptor and
//! one plain name in it.
//!
//! A write replaces the file: the body goes to a temporary file beside it,
//! is flushed with `fdatasync(2)`, then renamed over the target and the
//! directory synced. So a reader never sees half a file and a crash leaves
//! the old file or the new one. The costs: hard links to the old file keep
//! the old contents, its xattrs and ACLs are not carried over, writing
//! needs write permission on the directory (not the file), and the old and
//! new bodies both count against the quota until the rename.
//!
//! Errors are errno values with a detail for logs. Everything here blocks;
//! call it from a blocking thread.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Longest path and name taken, as Linux's `PATH_MAX` and `NAME_MAX`.
pub const PATH_MAX: usize = 4096;
pub const NAME_MAX: usize = 255;
/// `renameat2(2)` flags a rename may carry.
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
/// Prefix of the temporary files a write leaves behind if tenantd dies
/// mid-write.
pub const TEMP_PREFIX: &str = ".tenantd-write-";
/// Most symlinks a write's target follows, as Linux's `MAXSYMLINKS`.
const MAX_SYMLINKS: usize = 40;

/// A failed operation: a Linux errno and a detail for logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsError {
    pub errno: i32,
    pub detail: String,
    /// The path is under a mount the host can't see through (`EXDEV`):
    /// serve the call inside the container instead.
    pub not_served: bool,
}

impl FsError {
    pub fn new(errno: i32, detail: impl Into<String>) -> Self {
        Self {
            errno,
            detail: detail.into(),
            not_served: false,
        }
    }

    fn io(e: io::Error, what: impl std::fmt::Display) -> Self {
        Self::new(
            e.raw_os_error().unwrap_or(libc::EIO),
            format!("{what}: {e}"),
        )
    }
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}: {}", self.errno, self.detail)
    }
}

impl std::error::Error for FsError {}

pub type FsResult<T> = Result<T, FsError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

/// What `stat(2)` says about a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attr {
    pub kind: Kind,
    /// Permission, setuid/setgid and sticky bits.
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub rdev: u32,
    pub dev: u64,
    pub ino: u64,
}

fn ns(s: i64, n: i64) -> i64 {
    s.saturating_mul(1_000_000_000).saturating_add(n)
}

impl Attr {
    fn from_stat(st: &libc::stat) -> Self {
        let kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Kind::Directory,
            libc::S_IFLNK => Kind::Symlink,
            libc::S_IFIFO => Kind::Fifo,
            libc::S_IFSOCK => Kind::Socket,
            libc::S_IFCHR => Kind::CharDevice,
            libc::S_IFBLK => Kind::BlockDevice,
            _ => Kind::File,
        };
        Self {
            kind,
            mode: st.st_mode & 0o7777,
            size: st.st_size as u64,
            uid: st.st_uid,
            gid: st.st_gid,
            nlink: st.st_nlink as u32,
            atime_ns: ns(st.st_atime, st.st_atime_nsec),
            mtime_ns: ns(st.st_mtime, st.st_mtime_nsec),
            ctime_ns: ns(st.st_ctime, st.st_ctime_nsec),
            rdev: st.st_rdev as u32,
            dev: st.st_dev,
            ino: st.st_ino,
        }
    }
}

/// The parts of an absolute container path: no `.` or `..` parts, no empty
/// ones (`//`, a trailing `/`), no NUL. `/` has none.
pub fn components(path: &str) -> FsResult<Vec<&str>> {
    let bad = |m: &str| FsError::new(libc::EINVAL, format!("path {path:?}: {m}"));
    let Some(rest) = path.strip_prefix('/') else {
        return Err(bad("must be absolute"));
    };
    if path.len() > PATH_MAX {
        return Err(FsError::new(libc::ENAMETOOLONG, "path is too long"));
    }
    if path.contains('\0') {
        return Err(bad("contains NUL"));
    }
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<&str> = rest.split('/').collect();
    for p in &parts {
        match *p {
            "" => return Err(bad("has an empty part")),
            "." | ".." => return Err(bad("has a . or .. part")),
            p if p.len() > NAME_MAX => {
                return Err(FsError::new(
                    libc::ENAMETOOLONG,
                    format!("{p:?} is too long"),
                ));
            }
            _ => {}
        }
    }
    Ok(parts)
}

fn cstring(s: &[u8]) -> FsResult<CString> {
    CString::new(s).map_err(|_| FsError::new(libc::EINVAL, "path contains NUL"))
}

/// `parts` relative to the root, `.` for the root itself.
fn rel(parts: &[&str]) -> FsResult<CString> {
    if parts.is_empty() {
        return cstring(b".");
    }
    cstring(parts.join("/").as_bytes())
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

fn check(r: libc::c_long) -> io::Result<libc::c_long> {
    if r < 0 { Err(last_err()) } else { Ok(r) }
}

/// `path` below `dir`: with `confined`, `openat2(2)` resolving it as if
/// `dir` were `/`; else a plain `openat(2)` (inside the container, where
/// `dir` is `/` already and mounts are crossed as the container crosses
/// them).
fn openat2(
    dir: BorrowedFd,
    path: &CStr,
    flags: libc::c_int,
    mode: u32,
    confined: bool,
) -> io::Result<OwnedFd> {
    if !confined {
        loop {
            // SAFETY: valid fd and NUL-terminated path; the result is checked.
            let r = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    path.as_ptr(),
                    flags | libc::O_CLOEXEC,
                    mode as libc::c_uint,
                )
            };
            if r >= 0 {
                // SAFETY: a fresh descriptor we now own.
                return Ok(unsafe { OwnedFd::from_raw_fd(r) });
            }
            let e = last_err();
            if e.raw_os_error() != Some(libc::EINTR) {
                return Err(e);
            }
        }
    }
    // SAFETY: open_how is plain old data; zero is a valid value.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.mode = mode as u64;
    how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV;
    let mut tries = 0;
    loop {
        // SAFETY: valid fd, NUL-terminated path, and `how` of the size given.
        let r = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
                path.as_ptr(),
                &how as *const libc::open_how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if r >= 0 {
            // SAFETY: the kernel returned a fresh descriptor we now own.
            return Ok(unsafe { OwnedFd::from_raw_fd(r as i32) });
        }
        let e = last_err();
        // EAGAIN: a rename raced the resolution; the kernel asks to retry.
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) if tries < 16 => tries += 1,
            _ => return Err(e),
        }
    }
}

fn fstatat(dir: BorrowedFd, name: &CStr, flags: libc::c_int) -> io::Result<libc::stat> {
    // SAFETY: stat is plain old data; filled in by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, NUL-terminated name, and a stat to fill.
    check(unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, flags) } as _)?;
    Ok(st)
}

fn fstat(fd: BorrowedFd) -> io::Result<libc::stat> {
    fstatat(fd, c"", libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW)
}

fn not_found(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOENT)
}

/// Reopen an `O_PATH` descriptor for I/O. The permission check is the
/// caller's, as on any open.
fn reopen(fd: BorrowedFd, flags: libc::c_int) -> io::Result<OwnedFd> {
    let p = cstring(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())
        .map_err(|e| io::Error::other(e.detail))?;
    // SAFETY: NUL-terminated path; the result is checked.
    let r = unsafe { libc::open(p.as_ptr(), flags | libc::O_CLOEXEC) };
    if r < 0 {
        return Err(last_err());
    }
    // SAFETY: a fresh descriptor we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

fn fd_path(fd: BorrowedFd) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Whether `path` is the root of a mount (`STATX_ATTR_MOUNT_ROOT`, or a
/// device change from its parent where the kernel doesn't report that).
pub fn is_mount_root(path: &Path) -> io::Result<bool> {
    const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;
    let p = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // struct statx is 256 bytes: stx_attributes at byte 8, stx_attributes_mask
    // at byte 40.
    let mut buf = [0u64; 32];
    // SAFETY: NUL-terminated path and a buffer the size of struct statx.
    check(unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            p.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            0u32,
            buf.as_mut_ptr(),
        )
    })?;
    let (attributes, mask) = (buf[1], buf[5]);
    if mask & STATX_ATTR_MOUNT_ROOT != 0 {
        return Ok(attributes & STATX_ATTR_MOUNT_ROOT != 0);
    }
    use std::os::unix::fs::MetadataExt;
    let parent = path.parent().unwrap_or(Path::new("/"));
    Ok(std::fs::symlink_metadata(path)?.dev() != std::fs::metadata(parent)?.dev())
}

/// Who an operation runs as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups.
    pub groups: Vec<u32>,
}

impl Ident {
    pub fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            groups: Vec::new(),
        }
    }

    /// The calling process's own.
    pub fn current() -> Self {
        // SAFETY: no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Self {
            uid,
            gid,
            groups: Vec::new(),
        }
    }

    fn is_self(&self) -> bool {
        // SAFETY: no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        self.uid == uid && self.gid == gid
    }

    /// Take this identity for the calling thread's filesystem access. Raw
    /// syscalls: libc's `setgroups` would change every thread's.
    fn assume(&self) -> FsResult<()> {
        let fail = |what: &str| {
            FsError::new(
                libc::EPERM,
                format!(
                    "can't act as {}:{} ({what}: {})",
                    self.uid,
                    self.gid,
                    last_err()
                ),
            )
        };
        // SAFETY: a valid array of `len` gids.
        let r = unsafe {
            libc::syscall(
                libc::SYS_setgroups,
                self.groups.len(),
                self.groups.as_ptr() as *const libc::gid_t,
            )
        };
        if r < 0 {
            return Err(fail("setgroups"));
        }
        // setfs[ug]id return the previous ID and never fail outright; asking
        // again with an invalid one reads back the current.
        // SAFETY: no memory involved.
        unsafe {
            libc::syscall(libc::SYS_setfsgid, self.gid);
            if libc::syscall(libc::SYS_setfsgid, u32::MAX) as u32 != self.gid {
                return Err(fail("setfsgid"));
            }
            libc::syscall(libc::SYS_setfsuid, self.uid);
            if libc::syscall(libc::SYS_setfsuid, u32::MAX) as u32 != self.uid {
                return Err(fail("setfsuid"));
            }
        }
        Ok(())
    }

    /// Run `f` as this identity: right here when it is tenantd's own (or
    /// root), else on a thread of its own that ends with it.
    pub fn run<T: Send>(&self, f: impl FnOnce() -> FsResult<T> + Send) -> FsResult<T> {
        if self.is_self() {
            return f();
        }
        std::thread::scope(|s| {
            s.spawn(|| {
                self.assume()?;
                f()
            })
            .join()
            .unwrap_or_else(|_| Err(FsError::new(libc::EIO, "file operation panicked")))
        })
    }
}

/// A regular file at `path` below `dir`, opened read-only. A FIFO or device
/// is refused before it is opened, so nothing blocks on one.
fn open_regular(
    dir: BorrowedFd,
    path: &CStr,
    confined: bool,
) -> io::Result<(OwnedFd, File, libc::stat)> {
    let p = openat2(dir, path, libc::O_PATH, 0, confined)?;
    let st = fstat(p.as_fd())?;
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => {}
        libc::S_IFDIR => return Err(io::Error::from_raw_os_error(libc::EISDIR)),
        _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
    }
    let f = File::from(reopen(p.as_fd(), libc::O_RDONLY)?);
    Ok((p, f, st))
}

/// A container's root, opened for file operations as one user.
pub struct Root {
    fd: OwnedFd,
    /// Where the root is, as `/proc` names it.
    host: PathBuf,
    ident: Ident,
    /// Resolve with `RESOLVE_IN_ROOT`: the root is a host directory.
    confined: bool,
    /// Container paths of mounts the host can't see through.
    mounts: Vec<String>,
}

/// A directory resolved inside the root and one name in it.
struct Entry {
    dir: OwnedFd,
    name: CString,
    /// The entry's container path, its directory's symlinks resolved.
    path: String,
}

impl Root {
    /// Open a container's root at `path` on the host to act as `ident`,
    /// refusing paths at or below `mounts` with [`FsError::not_served`].
    pub fn open(path: &Path, ident: Ident, mounts: &[String]) -> FsResult<Self> {
        Self::at(path, ident, true, mounts)
    }

    /// `/`, from inside the container, as this process's own user.
    pub fn inside() -> FsResult<Self> {
        Self::at(Path::new("/"), Ident::current(), false, &[])
    }

    fn at(path: &Path, ident: Ident, confined: bool, mounts: &[String]) -> FsResult<Self> {
        let p = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FsError::new(libc::EINVAL, "root path contains NUL"))?;
        // SAFETY: NUL-terminated path; the result is checked.
        let r = unsafe {
            libc::open(
                p.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if r < 0 {
            return Err(FsError::io(
                last_err(),
                format!("opening {}", path.display()),
            ));
        }
        // SAFETY: a fresh descriptor we now own.
        let fd = unsafe { OwnedFd::from_raw_fd(r) };
        let host = fd_path(fd.as_fd()).map_err(|e| FsError::io(e, "locating the root"))?;
        let mounts = mounts
            .iter()
            .map(|m| m.trim_end_matches('/').to_string())
            .filter(|m| !m.is_empty())
            .collect();
        Ok(Self {
            fd,
            host,
            ident,
            confined,
            mounts,
        })
    }

    pub fn ident(&self) -> &Ident {
        &self.ident
    }

    fn root(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// `path`, relative to the root, resolved inside it.
    fn open_path(&self, path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
        openat2(self.root(), path, flags, 0, self.confined)
    }

    /// The container path of a descriptor resolved inside the root.
    fn container_path(&self, fd: BorrowedFd) -> FsResult<String> {
        let p = fd_path(fd).map_err(|e| FsError::io(e, "locating the file"))?;
        let b = p.as_os_str().as_bytes();
        if b.ends_with(b" (deleted)") {
            return Err(FsError::new(libc::ENOENT, "removed while in use"));
        }
        let rest = p
            .strip_prefix(&self.host)
            .map_err(|_| FsError::new(libc::ESTALE, "the container's root moved"))?;
        Ok(format!("/{}", rest.to_string_lossy()))
    }

    /// Refuse a container path at or below a volume or FUSE mount.
    fn outside_mounts(&self, path: &str) -> FsResult<()> {
        match self.mounts.iter().find(|m| {
            path == m.as_str()
                || path
                    .strip_prefix(m.as_str())
                    .is_some_and(|r| r.starts_with('/'))
        }) {
            Some(m) => Err(FsError {
                not_served: true,
                ..FsError::new(
                    libc::EXDEV,
                    format!("{path} is in the mount at {m}, which the host can't see"),
                )
            }),
            None => Ok(()),
        }
    }

    fn resolved(&self, fd: BorrowedFd) -> FsResult<String> {
        let path = self.container_path(fd)?;
        self.outside_mounts(&path)?;
        Ok(path)
    }

    fn open_dir(&self, parts: &[&str]) -> FsResult<OwnedFd> {
        self.open_path(&rel(parts)?, libc::O_PATH | libc::O_DIRECTORY)
            .map_err(|e| FsError::io(e, format!("opening /{}", parts.join("/"))))
    }

    /// The directory of `parts` (which must not be the root) and its last
    /// name. With `parents`, missing directories are made (0755).
    fn entry(&self, parts: &[&str], parents: bool) -> FsResult<Entry> {
        let (name, up) = parts
            .split_last()
            .ok_or_else(|| FsError::new(libc::EBUSY, "the root itself"))?;
        let dir = if parents {
            self.make_dirs(up)?
        } else {
            self.open_dir(up)?
        };
        self.entry_in(dir, name.as_bytes())
    }

    fn entry_in(&self, dir: OwnedFd, name: &[u8]) -> FsResult<Entry> {
        let dpath = self.container_path(dir.as_fd())?;
        let n = String::from_utf8_lossy(name);
        let path = match dpath.as_str() {
            "/" => format!("/{n}"),
            d => format!("{d}/{n}"),
        };
        self.outside_mounts(&path)?;
        Ok(Entry {
            dir,
            name: cstring(name)?,
            path,
        })
    }

    /// What a write to `parts` replaces and its `lstat`, `None` if nothing
    /// is there yet. A symlink is followed to its target, which need not
    /// exist, as writing through the link would.
    fn write_target(
        &self,
        parts: &[&str],
        parents: bool,
        path: &str,
    ) -> FsResult<(Entry, Option<libc::stat>)> {
        let mut e = self.entry(parts, parents)?;
        for _ in 0..MAX_SYMLINKS {
            let st = match fstatat(e.dir.as_fd(), &e.name, libc::AT_SYMLINK_NOFOLLOW) {
                Ok(st) => st,
                Err(err) if not_found(&err) => return Ok((e, None)),
                Err(err) => return Err(FsError::io(err, path)),
            };
            if st.st_mode & libc::S_IFMT != libc::S_IFLNK {
                return Ok((e, Some(st)));
            }
            let target =
                readlinkat(e.dir.as_fd(), &e.name).map_err(|err| FsError::io(err, path))?;
            let full = if target.starts_with(b"/") {
                target
            } else {
                let dir = e.path.rsplit_once('/').map_or("", |(d, _)| d);
                [dir.as_bytes(), b"/", &target].concat()
            };
            let (dir, name) = match full.iter().rposition(|b| *b == b'/') {
                Some(i) => (&full[..i], &full[i + 1..]),
                None => (&b""[..], &full[..]),
            };
            if matches!(name, b"" | b"." | b"..") {
                return Err(FsError::new(
                    libc::EISDIR,
                    format!("{path} links to a directory"),
                ));
            }
            let rel = match dir.iter().position(|b| *b != b'/') {
                Some(i) => cstring(&dir[i..])?,
                None => cstring(b".")?,
            };
            let d = self
                .open_path(&rel, libc::O_PATH | libc::O_DIRECTORY)
                .map_err(|err| FsError::io(err, format!("{path}: following its symlink")))?;
            e = self.entry_in(d, name)?;
        }
        Err(FsError::new(
            libc::ELOOP,
            format!("{path}: too many symlinks"),
        ))
    }

    /// `mkdir -p`, each part resolved inside the root.
    fn make_dirs(&self, parts: &[&str]) -> FsResult<OwnedFd> {
        let mut cur = self.open_dir(&[])?;
        for i in 0..parts.len() {
            match self.open_path(&rel(&parts[..=i])?, libc::O_PATH | libc::O_DIRECTORY) {
                Ok(fd) => cur = fd,
                Err(e) if not_found(&e) => {
                    self.resolved(cur.as_fd())?;
                    let name = cstring(parts[i].as_bytes())?;
                    // SAFETY: valid fd and NUL-terminated name.
                    let r = unsafe { libc::mkdirat(cur.as_raw_fd(), name.as_ptr(), 0o755) };
                    if r < 0 && last_err().raw_os_error() != Some(libc::EEXIST) {
                        return Err(FsError::io(
                            last_err(),
                            format!("making /{}", parts[..=i].join("/")),
                        ));
                    }
                    // The umask (tenantd's is 0077) cut the mode; set it on
                    // the directory itself, never through a symlink.
                    // SAFETY: valid fd and NUL-terminated name.
                    let d = unsafe {
                        libc::openat(
                            cur.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if d < 0 {
                        return Err(FsError::io(
                            last_err(),
                            format!("opening /{}", parts[..=i].join("/")),
                        ));
                    }
                    // SAFETY: a fresh descriptor we now own.
                    let d = unsafe { OwnedFd::from_raw_fd(d) };
                    if r == 0 {
                        // SAFETY: valid fd.
                        unsafe { libc::fchmod(d.as_raw_fd(), 0o755) };
                    }
                    cur = d;
                }
                Err(e) => {
                    return Err(FsError::io(
                        e,
                        format!("opening /{}", parts[..=i].join("/")),
                    ));
                }
            }
        }
        Ok(cur)
    }

    /// `lstat`, or `stat` with `follow`. Returns the path stat-ed, its
    /// symlinks resolved when following.
    pub fn stat(&self, path: &str, follow: bool) -> FsResult<(String, Attr)> {
        let parts = components(path)?;
        self.ident.run(|| {
            if follow || parts.is_empty() {
                let fd = self
                    .open_path(&rel(&parts)?, libc::O_PATH)
                    .map_err(|e| FsError::io(e, path))?;
                let resolved = self.resolved(fd.as_fd())?;
                let st = fstat(fd.as_fd()).map_err(|e| FsError::io(e, path))?;
                return Ok((resolved, Attr::from_stat(&st)));
            }
            let e = self.entry(&parts, false)?;
            let st = fstatat(e.dir.as_fd(), &e.name, libc::AT_SYMLINK_NOFOLLOW)
                .map_err(|err| FsError::io(err, path))?;
            Ok((e.path, Attr::from_stat(&st)))
        })
    }

    /// The directory's entries (without `.` and `..`), each `lstat`-ed.
    /// Names that aren't UTF-8 come back lossily.
    pub fn read_dir(&self, path: &str) -> FsResult<Vec<(String, Attr)>> {
        let parts = components(path)?;
        self.ident.run(|| {
            let fd = self
                .open_path(&rel(&parts)?, libc::O_RDONLY | libc::O_DIRECTORY)
                .map_err(|e| FsError::io(e, path))?;
            self.resolved(fd.as_fd())?;
            let raw = fd.into_raw_fd();
            // SAFETY: we own `raw`; the DIR takes it over.
            let dirp = unsafe { libc::fdopendir(raw) };
            if dirp.is_null() {
                let e = last_err();
                // SAFETY: fdopendir failed, so `raw` is still ours.
                unsafe { libc::close(raw) };
                return Err(FsError::io(e, path));
            }
            struct Dir(*mut libc::DIR);
            impl Drop for Dir {
                fn drop(&mut self) {
                    // SAFETY: a DIR from fdopendir, closed once.
                    unsafe { libc::closedir(self.0) };
                }
            }
            let dir = Dir(dirp);
            // SAFETY: a valid DIR.
            let dfd = unsafe { BorrowedFd::borrow_raw(libc::dirfd(dir.0)) };
            let mut out = Vec::new();
            loop {
                // SAFETY: errno is thread-local; readdir reports errors there.
                unsafe { *libc::__errno_location() = 0 };
                // SAFETY: a valid DIR, read by this thread only.
                let ent = unsafe { libc::readdir(dir.0) };
                if ent.is_null() {
                    let e = last_err();
                    if e.raw_os_error().unwrap_or(0) != 0 {
                        return Err(FsError::io(e, path));
                    }
                    break;
                }
                // SAFETY: readdir returned a valid entry with a NUL-terminated name.
                let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
                if matches!(name.to_bytes(), b"." | b"..") {
                    continue;
                }
                match fstatat(dfd, name, libc::AT_SYMLINK_NOFOLLOW) {
                    Ok(st) => out.push((
                        OsStr::from_bytes(name.to_bytes())
                            .to_string_lossy()
                            .into_owned(),
                        Attr::from_stat(&st),
                    )),
                    // Removed since it was listed.
                    Err(e) if not_found(&e) => {}
                    Err(e) => return Err(FsError::io(e, format!("{path}/{name:?}"))),
                }
            }
            out.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(out)
        })
    }

    /// A regular file, following symlinks, open for reading.
    pub fn open_read(&self, path: &str) -> FsResult<(Reader, Attr)> {
        let parts = components(path)?;
        self.ident.run(|| {
            let (p, f, st) = open_regular(self.root(), &rel(&parts)?, self.confined)
                .map_err(|e| FsError::io(e, path))?;
            self.resolved(p.as_fd())?;
            Ok((Reader { file: f }, Attr::from_stat(&st)))
        })
    }

    /// Start replacing (or creating) the file at `path` with a body
    /// written to a temporary file beside it. Nothing changes at `path`
    /// until [`PendingWrite::commit`]; dropping the write removes the
    /// temporary file.
    pub fn begin_write(&self, path: &str, opts: &WriteOptions) -> FsResult<PendingWrite> {
        let parts = components(path)?;
        if opts.mode.is_some_and(|m| m & !0o7777 != 0) {
            return Err(FsError::new(
                libc::EINVAL,
                "mode takes permission bits only",
            ));
        }
        self.ident.run(|| {
            let (e, existing) = self.write_target(&parts, opts.parents, path)?;
            let regular = existing.filter(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG);
            if let Some(st) = existing {
                if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                    return Err(FsError::new(libc::EISDIR, format!("{path} is a directory")));
                }
                if opts.exclusive {
                    return Err(FsError::new(libc::EEXIST, format!("{path} exists")));
                }
            }
            let mode = opts
                .mode
                .or(regular.map(|st| st.st_mode & 0o7777))
                .unwrap_or(0o644);
            let tmp = temp_name()?;
            // SAFETY: valid fd and NUL-terminated name.
            let r = unsafe {
                libc::openat(
                    e.dir.as_raw_fd(),
                    tmp.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600 as libc::c_uint,
                )
            };
            if r < 0 {
                return Err(FsError::io(
                    last_err(),
                    format!("creating a file beside {path}"),
                ));
            }
            // SAFETY: a fresh descriptor we now own.
            let file = File::from(unsafe { OwnedFd::from_raw_fd(r) });
            let w = PendingWrite {
                file: Some(file),
                dir: e.dir,
                tmp,
                name: e.name,
                path: path.to_string(),
                exclusive: opts.exclusive,
                ident: self.ident.clone(),
                written: 0,
            };
            let fd = w.file().as_raw_fd();
            // Root replacing a file keeps its owner, as writing into it would.
            if let Some(st) = regular.filter(|_| self.ident.uid == 0) {
                // SAFETY: valid fd.
                if unsafe { libc::fchown(fd, st.st_uid, st.st_gid) } < 0 {
                    return Err(FsError::io(last_err(), format!("chown {path}")));
                }
            }
            // SAFETY: valid fd.
            if unsafe { libc::fchmod(fd, mode) } < 0 {
                return Err(FsError::io(last_err(), format!("chmod {path}")));
            }
            Ok(w)
        })
    }

    /// `renameat2(2)` with `flags` ([`RENAME_NOREPLACE`], [`RENAME_EXCHANGE`]).
    pub fn rename(&self, from: &str, to: &str, flags: u32) -> FsResult<()> {
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0
            || flags == RENAME_NOREPLACE | RENAME_EXCHANGE
        {
            return Err(FsError::new(
                libc::EINVAL,
                format!("rename flags {flags:#x}"),
            ));
        }
        let (fp, tp) = (components(from)?, components(to)?);
        self.ident.run(|| {
            let f = self.entry(&fp, false)?;
            let t = self.entry(&tp, false)?;
            renameat2(&f, &t, flags).map_err(|e| FsError::io(e, format!("{from} -> {to}")))
        })
    }

    /// `unlink(2)`, or `rmdir(2)` with `directory`.
    pub fn remove(&self, path: &str, directory: bool) -> FsResult<()> {
        let parts = components(path)?;
        self.ident.run(|| {
            let e = self.entry(&parts, false)?;
            let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
            // SAFETY: valid fd and NUL-terminated name.
            check(unsafe { libc::unlinkat(e.dir.as_raw_fd(), e.name.as_ptr(), flags) } as _)
                .map_err(|err| FsError::io(err, path))?;
            Ok(())
        })
    }

    /// `mkdir(2)` with `mode` (0755 when `None`), set exactly, not cut by
    /// the umask. With `parents`, missing parents are made (0755) and an
    /// existing directory is no error.
    pub fn mkdir(&self, path: &str, mode: Option<u32>, parents: bool) -> FsResult<Attr> {
        let parts = components(path)?;
        let mode = mode.unwrap_or(0o755);
        if mode & !0o7777 != 0 {
            return Err(FsError::new(
                libc::EINVAL,
                "mode takes permission bits only",
            ));
        }
        self.ident.run(|| {
            if parts.is_empty() {
                if parents {
                    let fd = self.open_dir(&[])?;
                    let st = fstat(fd.as_fd()).map_err(|e| FsError::io(e, path))?;
                    return Ok(Attr::from_stat(&st));
                }
                return Err(FsError::new(libc::EEXIST, "the root itself"));
            }
            let e = self.entry(&parts, parents)?;
            // SAFETY: valid fd and NUL-terminated name.
            let r = unsafe { libc::mkdirat(e.dir.as_raw_fd(), e.name.as_ptr(), 0o700) };
            if r < 0 {
                let err = last_err();
                if parents && err.raw_os_error() == Some(libc::EEXIST) {
                    let st =
                        fstatat(e.dir.as_fd(), &e.name, 0).map_err(|err| FsError::io(err, path))?;
                    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                        return Ok(Attr::from_stat(&st));
                    }
                }
                return Err(FsError::io(err, path));
            }
            // SAFETY: valid fd and NUL-terminated name.
            let d = unsafe {
                libc::openat(
                    e.dir.as_raw_fd(),
                    e.name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if d < 0 {
                return Err(FsError::io(last_err(), path));
            }
            // SAFETY: a fresh descriptor we now own.
            let d = unsafe { OwnedFd::from_raw_fd(d) };
            // SAFETY: valid fd.
            if unsafe { libc::fchmod(d.as_raw_fd(), mode) } < 0 {
                return Err(FsError::io(last_err(), format!("chmod {path}")));
            }
            let st = fstat(d.as_fd()).map_err(|err| FsError::io(err, path))?;
            Ok(Attr::from_stat(&st))
        })
    }

    /// `symlink(2)`: a link at `path` to `target`, which is stored as
    /// given and need not exist.
    pub fn symlink(&self, path: &str, target: &[u8]) -> FsResult<()> {
        let parts = components(path)?;
        if target.is_empty() || target.len() > PATH_MAX {
            return Err(FsError::new(libc::EINVAL, "symlink target length"));
        }
        let target = cstring(target)?;
        self.ident.run(|| {
            let e = self.entry(&parts, false)?;
            // SAFETY: NUL-terminated strings and a valid fd.
            check(
                unsafe { libc::symlinkat(target.as_ptr(), e.dir.as_raw_fd(), e.name.as_ptr()) }
                    as _,
            )
            .map_err(|err| FsError::io(err, path))?;
            Ok(())
        })
    }

    /// `readlink(2)`: the target of the symlink at `path`, as stored.
    pub fn read_link(&self, path: &str) -> FsResult<Vec<u8>> {
        let parts = components(path)?;
        self.ident.run(|| {
            if parts.is_empty() {
                return Err(FsError::new(libc::EINVAL, "the root is no symlink"));
            }
            let e = self.entry(&parts, false)?;
            readlinkat(e.dir.as_fd(), &e.name).map_err(|err| FsError::io(err, path))
        })
    }

    /// `chmod(2)` and the modification time of what is at `path`,
    /// following a symlink there. `None` leaves that one as it is.
    pub fn set_attr(&self, path: &str, mode: Option<u32>, mtime_ns: Option<i64>) -> FsResult<Attr> {
        let parts = components(path)?;
        if mode.is_some_and(|m| m & !0o7777 != 0) {
            return Err(FsError::new(
                libc::EINVAL,
                "mode takes permission bits only",
            ));
        }
        self.ident.run(|| {
            let fd = self
                .open_path(&rel(&parts)?, libc::O_PATH)
                .map_err(|e| FsError::io(e, path))?;
            self.resolved(fd.as_fd())?;
            // The descriptor's magic link names the file itself, whatever
            // happens to the path meanwhile.
            let proc = cstring(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?;
            if let Some(mode) = mode {
                // SAFETY: NUL-terminated path.
                check(unsafe { libc::chmod(proc.as_ptr(), mode) } as _)
                    .map_err(|e| FsError::io(e, format!("chmod {path}")))?;
            }
            if let Some(t) = mtime_ns {
                let times = [
                    libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                    libc::timespec {
                        tv_sec: t.div_euclid(1_000_000_000),
                        tv_nsec: t.rem_euclid(1_000_000_000),
                    },
                ];
                // SAFETY: NUL-terminated path and two timespecs.
                check(
                    unsafe { libc::utimensat(libc::AT_FDCWD, proc.as_ptr(), times.as_ptr(), 0) }
                        as _,
                )
                .map_err(|e| FsError::io(e, format!("touch {path}")))?;
            }
            let st = fstat(fd.as_fd()).map_err(|e| FsError::io(e, path))?;
            Ok(Attr::from_stat(&st))
        })
    }
}

fn readlinkat(dir: BorrowedFd, name: &CStr) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; PATH_MAX];
    // SAFETY: valid fd, NUL-terminated name and a buffer of the size given.
    let n = check(unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    } as _)? as usize;
    buf.truncate(n);
    Ok(buf)
}

fn renameat2(from: &Entry, to: &Entry, flags: u32) -> io::Result<()> {
    // SAFETY: valid fds and NUL-terminated names.
    check(unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from.dir.as_raw_fd(),
            from.name.as_ptr(),
            to.dir.as_raw_fd(),
            to.name.as_ptr(),
            flags,
        )
    })?;
    Ok(())
}

fn temp_name() -> FsResult<CString> {
    use std::hash::{BuildHasher, Hasher};
    static N: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(N.fetch_add(1, Ordering::Relaxed));
    h.write_u32(std::process::id());
    cstring(format!("{TEMP_PREFIX}{:016x}", h.finish()).as_bytes())
}

/// How [`Root::begin_write`] writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteOptions {
    /// Default: the replaced file's, or 0644.
    pub mode: Option<u32>,
    /// Make missing parent directories (0755).
    pub parents: bool,
    /// Fail with `EEXIST` if the path exists.
    pub exclusive: bool,
}

/// An open file being read.
#[derive(Debug)]
pub struct Reader {
    file: File,
}

impl Reader {
    /// Up to `buf.len()` bytes at `offset`; 0 at the end of the file.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> FsResult<usize> {
        loop {
            match self.file.read_at(buf, offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => return r.map_err(|e| FsError::io(e, "reading")),
            }
        }
    }
}

/// A body on its way to a file; see [`Root::begin_write`].
#[derive(Debug)]
pub struct PendingWrite {
    file: Option<File>,
    dir: OwnedFd,
    tmp: CString,
    name: CString,
    path: String,
    exclusive: bool,
    ident: Ident,
    written: u64,
}

impl PendingWrite {
    fn file(&self) -> &File {
        self.file.as_ref().expect("file is open until commit")
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Append to the body. Past the tenant's quota this fails with `ENOSPC`
    /// (XFS project quotas report that, not `EDQUOT`).
    pub fn write(&mut self, data: &[u8]) -> FsResult<()> {
        let path = self.path.clone();
        self.file
            .as_mut()
            .expect("file is open until commit")
            .write_all(data)
            .map_err(|e| FsError::io(e, format!("writing {path}")))?;
        self.written += data.len() as u64;
        Ok(())
    }

    /// Flush the body to disk and move it into place, atomically.
    pub fn commit(mut self) -> FsResult<Attr> {
        let path = self.path.clone();
        let file = self.file.take().expect("committed once");
        let attr = file
            .sync_data()
            .and_then(|_| fstat(file.as_fd()))
            .map_err(|e| FsError::io(e, format!("writing {path}")));
        drop(file);
        let attr = Attr::from_stat(&attr?);
        let flags = if self.exclusive { RENAME_NOREPLACE } else { 0 };
        let ident = self.ident.clone();
        ident.run(|| {
            // SAFETY: valid fd and NUL-terminated names.
            check(unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    self.dir.as_raw_fd(),
                    self.tmp.as_ptr(),
                    self.dir.as_raw_fd(),
                    self.name.as_ptr(),
                    flags,
                )
            })
            .map_err(|e| FsError::io(e, format!("replacing {path}")))
        })?;
        self.tmp = CString::default();
        // So the rename survives a crash too. It is done either way, so a
        // failure here is not the caller's.
        if let Ok(d) = reopen(self.dir.as_fd(), libc::O_RDONLY | libc::O_DIRECTORY) {
            let _ = File::from(d).sync_all();
        }
        Ok(attr)
    }
}

impl Drop for PendingWrite {
    fn drop(&mut self) {
        if !self.tmp.is_empty() {
            // SAFETY: valid fd and NUL-terminated name. tenantd's own
            // identity can remove what any container user created.
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.tmp.as_ptr(), 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A root with a passwd file and a few files, opened as this test's
    /// own user (switching identity needs root).
    fn root(mounts: &[&str]) -> (tempfile::TempDir, PathBuf, Root) {
        let d = tempfile::tempdir().unwrap();
        let r = d.path().join("rootfs");
        fs::create_dir_all(r.join("etc")).unwrap();
        fs::create_dir_all(r.join("data")).unwrap();
        fs::create_dir_all(r.join("home/u")).unwrap();
        fs::write(r.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        fs::write(r.join("etc/hostname"), "box\n").unwrap();
        let mounts: Vec<String> = mounts.iter().map(|m| m.to_string()).collect();
        let root = Root::open(&r, Ident::current(), &mounts).unwrap();
        (d, r, root)
    }

    #[test]
    fn paths_are_checked() {
        assert_eq!(components("/").unwrap(), Vec::<&str>::new());
        assert_eq!(components("/a/b").unwrap(), vec!["a", "b"]);
        for bad in ["", "a", "/a/", "//a", "/a/../b", "/./a", "/a\0b"] {
            assert_eq!(components(bad).unwrap_err().errno, libc::EINVAL, "{bad:?}");
        }
        let long = format!("/{}", "a".repeat(256));
        assert_eq!(components(&long).unwrap_err().errno, libc::ENAMETOOLONG);
    }

    #[test]
    fn symlinks_resolve_inside_the_root() {
        let (_d, r, root) = root(&[]);
        // On the host this would be the host's /etc/passwd.
        symlink("/etc/passwd", r.join("home/u/abs")).unwrap();
        symlink("../../../../../../etc/hostname", r.join("home/u/rel")).unwrap();
        let (p, a) = root.stat("/home/u/abs", true).unwrap();
        assert_eq!(p, "/etc/passwd");
        assert_eq!(a.size, fs::metadata(r.join("etc/passwd")).unwrap().len());
        let (rd, _) = root.open_read("/home/u/rel").unwrap();
        let mut buf = [0u8; 16];
        let n = rd.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf[..n], b"box\n");
        let (p, a) = root.stat("/home/u/abs", false).unwrap();
        assert_eq!((p.as_str(), a.kind), ("/home/u/abs", Kind::Symlink));
        // A symlinked parent directory resolves inside too.
        symlink("/", r.join("home/up")).unwrap();
        let (p, _) = root.stat("/home/up/etc/hostname", false).unwrap();
        assert_eq!(p, "/etc/hostname");
        // Writing through a symlinked directory stays inside.
        symlink("/etc", r.join("home/etc")).unwrap();
        let mut w = root
            .begin_write("/home/etc/new", &Default::default())
            .unwrap();
        w.write(b"x").unwrap();
        w.commit().unwrap();
        assert_eq!(fs::read(r.join("etc/new")).unwrap(), b"x");
    }

    #[test]
    fn writes_follow_a_symlink_at_the_target() {
        let (_d, r, root) = root(&[]);
        let put = |p: &str, body: &[u8]| {
            let mut w = root.begin_write(p, &Default::default()).unwrap();
            w.write(body).unwrap();
            w.commit().unwrap()
        };
        // An absolute link resolves in the root, not on the host.
        symlink("/etc/hostname", r.join("home/u/abs")).unwrap();
        put("/home/u/abs", b"via abs");
        assert_eq!(fs::read(r.join("etc/hostname")).unwrap(), b"via abs");
        assert!(
            fs::symlink_metadata(r.join("home/u/abs"))
                .unwrap()
                .is_symlink()
        );
        // A relative one, through a chain, to a file not there yet.
        symlink("../../data/new", r.join("home/u/rel")).unwrap();
        symlink("rel", r.join("home/u/chain")).unwrap();
        put("/home/u/chain", b"made");
        assert_eq!(fs::read(r.join("data/new")).unwrap(), b"made");
        symlink("loop", r.join("loop")).unwrap();
        let e = root
            .begin_write("/loop", &Default::default())
            .err()
            .unwrap();
        assert_eq!(e.errno, libc::ELOOP);
        symlink("/etc", r.join("dirlink")).unwrap();
        let e = root
            .begin_write("/dirlink", &Default::default())
            .err()
            .unwrap();
        assert_eq!(e.errno, libc::EISDIR);
    }

    #[test]
    fn unconfined_resolves_plainly() {
        // Inside the container the root is `/` and openat2 may be missing;
        // relative paths work the same.
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("a")).unwrap();
        fs::write(d.path().join("a/f"), "f").unwrap();
        symlink("f", d.path().join("a/l")).unwrap();
        let root = Root::at(d.path(), Ident::current(), false, &[]).unwrap();
        let (p, a) = root.stat("/a/l", true).unwrap();
        assert_eq!((p.as_str(), a.size), ("/a/f", 1));
        let mut w = root.begin_write("/a/l", &Default::default()).unwrap();
        w.write(b"g!").unwrap();
        w.commit().unwrap();
        assert_eq!(fs::read(d.path().join("a/f")).unwrap(), b"g!");
        root.rename("/a/f", "/a/g", 0).unwrap();
        root.remove("/a/g", false).unwrap();
        assert_eq!(root.read_dir("/a").unwrap().len(), 1);
    }

    #[test]
    fn stat_and_read_dir() {
        let (_d, r, root) = root(&[]);
        let (p, a) = root.stat("/", false).unwrap();
        assert_eq!((p.as_str(), a.kind), ("/", Kind::Directory));
        let names: Vec<String> = root
            .read_dir("/")
            .unwrap()
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert_eq!(names, ["data", "etc", "home"]);
        let e = root.read_dir("/etc").unwrap();
        assert_eq!(e[0].0, "hostname");
        assert_eq!(e[0].1.size, 4);
        assert_eq!(root.stat("/nope", false).unwrap_err().errno, libc::ENOENT);
        assert_eq!(
            root.read_dir("/etc/hostname").unwrap_err().errno,
            libc::ENOTDIR
        );
        assert_eq!(root.open_read("/etc").unwrap_err().errno, libc::EISDIR);
        // A FIFO is refused rather than opened (which would block).
        let fifo = cstring(r.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        assert_eq!(root.open_read("/fifo").unwrap_err().errno, libc::EINVAL);
    }

    #[test]
    fn writes_replace_atomically() {
        let (_d, r, root) = root(&[]);
        let mut w = root
            .begin_write("/etc/hostname", &Default::default())
            .unwrap();
        w.write(b"new").unwrap();
        // Nothing changes until commit.
        assert_eq!(fs::read(r.join("etc/hostname")).unwrap(), b"box\n");
        drop(w);
        assert_eq!(fs::read(r.join("etc/hostname")).unwrap(), b"box\n");
        let leftovers = fs::read_dir(r.join("etc"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(TEMP_PREFIX)
            })
            .count();
        assert_eq!(leftovers, 0, "an abandoned write leaves nothing behind");

        fs::set_permissions(r.join("etc/hostname"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut w = root
            .begin_write("/etc/hostname", &Default::default())
            .unwrap();
        w.write(b"new").unwrap();
        w.write(b"er").unwrap();
        assert_eq!(w.written(), 5);
        let a = w.commit().unwrap();
        assert_eq!(
            (a.size, a.mode),
            (5, 0o600),
            "keeps the replaced file's mode"
        );
        assert_eq!(fs::read(r.join("etc/hostname")).unwrap(), b"newer");

        let opts = WriteOptions {
            exclusive: true,
            ..Default::default()
        };
        assert_eq!(
            root.begin_write("/etc/hostname", &opts).unwrap_err().errno,
            libc::EEXIST
        );
        assert_eq!(
            root.begin_write("/etc", &Default::default())
                .unwrap_err()
                .errno,
            libc::EISDIR
        );
        assert_eq!(
            root.begin_write("/a/b/c", &Default::default())
                .unwrap_err()
                .errno,
            libc::ENOENT
        );
        let opts = WriteOptions {
            parents: true,
            mode: Some(0o640),
            ..Default::default()
        };
        let mut w = root.begin_write("/a/b/c", &opts).unwrap();
        w.write(b"deep").unwrap();
        assert_eq!(w.commit().unwrap().mode, 0o640);
        let dmode = fs::metadata(r.join("a/b")).unwrap().permissions().mode() & 0o7777;
        assert_eq!(dmode, 0o755);
        // Exclusive create racing another writer: the loser fails, the
        // winner's file stays.
        let opts = WriteOptions {
            exclusive: true,
            ..Default::default()
        };
        let mut w = root.begin_write("/x", &opts).unwrap();
        fs::write(r.join("x"), "first").unwrap();
        w.write(b"second").unwrap();
        assert_eq!(w.commit().unwrap_err().errno, libc::EEXIST);
        assert_eq!(fs::read(r.join("x")).unwrap(), b"first");
    }

    #[test]
    fn rename_and_remove() {
        let (_d, r, root) = root(&[]);
        fs::create_dir_all(r.join("tmp")).unwrap();
        root.rename("/etc/hostname", "/tmp/h", 0).unwrap();
        assert_eq!(fs::read(r.join("tmp/h")).unwrap(), b"box\n");
        fs::write(r.join("tmp/g"), "g").unwrap();
        assert_eq!(
            root.rename("/tmp/h", "/tmp/g", RENAME_NOREPLACE)
                .unwrap_err()
                .errno,
            libc::EEXIST
        );
        root.rename("/tmp/h", "/tmp/g", RENAME_EXCHANGE).unwrap();
        assert_eq!(fs::read(r.join("tmp/h")).unwrap(), b"g");
        assert_eq!(
            root.rename("/tmp/h", "/tmp/g", 4).unwrap_err().errno,
            libc::EINVAL
        );
        assert_eq!(root.rename("/", "/x", 0).unwrap_err().errno, libc::EBUSY);
        assert_eq!(root.remove("/tmp", false).unwrap_err().errno, libc::EISDIR);
        assert_eq!(
            root.remove("/tmp", true).unwrap_err().errno,
            libc::ENOTEMPTY
        );
        root.remove("/tmp/h", false).unwrap();
        root.remove("/tmp/g", false).unwrap();
        root.remove("/tmp", true).unwrap();
        assert!(!r.join("tmp").exists());
        // A symlink is removed itself, never what it points at.
        symlink("/etc/passwd", r.join("l")).unwrap();
        root.remove("/l", false).unwrap();
        assert!(r.join("etc/passwd").exists());
    }

    #[test]
    fn mounts_are_not_served() {
        let (_d, r, root) = root(&["/data/"]);
        fs::write(r.join("data/x"), "hidden by the mount").unwrap();
        symlink("/data/x", r.join("toward")).unwrap();
        for e in [
            root.stat("/data", false).unwrap_err(),
            root.begin_write("/toward", &Default::default())
                .err()
                .unwrap(),
            root.stat("/data/x", false).unwrap_err(),
            root.stat("/toward", true).unwrap_err(),
            root.read_dir("/data").unwrap_err(),
            root.begin_write("/data/x", &Default::default())
                .err()
                .unwrap(),
            root.remove("/data", true).unwrap_err(),
            root.rename("/etc/hostname", "/data/h", 0).unwrap_err(),
        ] {
            assert_eq!((e.errno, e.not_served), (libc::EXDEV, true), "{e}");
        }
        // Not just a prefix: /database is not /data.
        fs::write(r.join("database"), "").unwrap();
        root.stat("/database", false).unwrap();
    }

    #[test]
    fn mkdir_sets_the_mode_and_takes_parents() {
        let (_d, r, root) = root(&[]);
        let a = root.mkdir("/data/x", Some(0o750), false).unwrap();
        assert_eq!(a.kind, Kind::Directory);
        assert_eq!(
            fs::metadata(r.join("data/x")).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        assert_eq!(
            root.mkdir("/data/x", None, false).unwrap_err().errno,
            libc::EEXIST
        );
        root.mkdir("/data/x", None, true).unwrap();
        root.mkdir("/data/a/b/c", None, true).unwrap();
        assert!(r.join("data/a/b/c").is_dir());
        assert_eq!(
            root.mkdir("/data/q/r", None, false).unwrap_err().errno,
            libc::ENOENT
        );
        assert_eq!(
            root.mkdir("/etc/passwd", None, true).unwrap_err().errno,
            libc::EEXIST
        );
        root.mkdir("/", None, true).unwrap();
    }

    #[test]
    fn symlinks_are_made_and_read_as_given() {
        let (_d, r, root) = root(&[]);
        root.symlink("/data/l", b"/etc/passwd").unwrap();
        assert_eq!(
            fs::read_link(r.join("data/l")).unwrap(),
            Path::new("/etc/passwd")
        );
        assert_eq!(root.read_link("/data/l").unwrap(), b"/etc/passwd");
        assert_eq!(
            root.read_link("/etc/passwd").unwrap_err().errno,
            libc::EINVAL
        );
        assert_eq!(
            root.symlink("/data/l", b"x").unwrap_err().errno,
            libc::EEXIST
        );
        assert_eq!(
            root.read_link("/data/none").unwrap_err().errno,
            libc::ENOENT
        );
    }

    #[test]
    fn set_attr_changes_mode_and_mtime_through_a_link() {
        let (_d, r, root) = root(&[]);
        symlink("/etc/hostname", r.join("data/h")).unwrap();
        let a = root
            .set_attr("/data/h", Some(0o600), Some(1_000_000_123))
            .unwrap();
        assert_eq!(a.kind, Kind::File);
        assert_eq!(a.mode, 0o600);
        assert_eq!(a.mtime_ns, 1_000_000_123);
        let m = fs::metadata(r.join("etc/hostname")).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o600);
        let a = root.set_attr("/etc/hostname", None, None).unwrap();
        assert_eq!(a.mode, 0o600);
        assert_eq!(
            root.set_attr("/etc/x", Some(0o644), None)
                .unwrap_err()
                .errno,
            libc::ENOENT
        );
        assert_eq!(
            root.set_attr("/etc/hostname", Some(0o10000), None)
                .unwrap_err()
                .errno,
            libc::EINVAL
        );
    }
}
