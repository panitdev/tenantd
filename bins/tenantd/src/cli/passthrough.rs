//! `container serve-fuse --dir`: export a host directory through
//! `Containers.ServeFuse`.
//!
//! Every path is resolved under the directory with `openat2(RESOLVE_BENEATH)`
//! and operated on by name through its parent's descriptor, so neither `..`
//! nor a symlink inside the tree can reach outside it. Names that are not
//! UTF-8 are not exported (paths are strings on the wire). Files are
//! created as the user running the server; the caller's uid and gid are not
//! applied.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tenantd_client::fuse::{Context, Error, Filesystem, Result, errno};
use tenantd_client::pb;

/// Files up to this size are sent with their open, saving the first read.
const INLINE_MAX: u64 = 64 << 10;
const RESOLVE: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;

/// `struct open_how`, which libc doesn't let us build.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

struct Inner {
    root: OwnedFd,
    read_only: bool,
    ttl_ms: u32,
    files: Mutex<HashMap<u64, Arc<File>>>,
    next_handle: AtomicU64,
}

#[derive(Clone)]
pub struct Passthrough(Arc<Inner>);

impl Passthrough {
    pub fn new(dir: &std::path::Path, read_only: bool, ttl_ms: u32) -> io::Result<Self> {
        let c = cstr(dir.to_str().ok_or_else(einval)?)?;
        // SAFETY: valid NUL-terminated path.
        let fd = cvt(unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        Ok(Self(Arc::new(Inner {
            // SAFETY: open returned a new fd we own.
            root: unsafe { OwnedFd::from_raw_fd(fd) },
            read_only,
            ttl_ms,
            files: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        })))
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner) -> io::Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || f(&inner))
            .await
            .map_err(|e| Error::new(errno::EIO).detail(e.to_string()))?
            .map_err(Error::from)
    }
}

// ---- syscall helpers -------------------------------------------------------

fn einval() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| einval())
}

fn owned(fd: libc::c_int) -> OwnedFd {
    // SAFETY: the caller got `fd` from a call that returned a new descriptor.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

/// `(parent relative to the root, name)` of a path other than `/`.
fn split(path: &str) -> io::Result<(&str, &str)> {
    valid(path)?;
    let rest = path
        .strip_prefix('/')
        .filter(|r| !r.is_empty())
        .ok_or_else(einval)?;
    Ok(match rest.rfind('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (".", rest),
    })
}

/// Absolute, without empty, `.` or `..` components.
fn valid(path: &str) -> io::Result<()> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err(einval());
    };
    if rest.is_empty() {
        return Ok(());
    }
    if rest.contains('\0')
        || rest
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(einval());
    }
    Ok(())
}

/// Path relative to the root, `.` for the root itself.
fn relative(path: &str) -> io::Result<&str> {
    valid(path)?;
    Ok(match &path[1..] {
        "" => ".",
        r => r,
    })
}

fn openat2(dir: RawFd, rel: &str, flags: i32, mode: u32) -> io::Result<OwnedFd> {
    let c = cstr(rel)?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: u64::from(mode),
        resolve: RESOLVE,
    };
    loop {
        // SAFETY: valid dirfd, NUL-terminated path and open_how of the size given.
        let r = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir,
                c.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if r >= 0 {
            return Ok(owned(r as libc::c_int));
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            // Escaping the tree is a refusal, not a missing file.
            return Err(if e.raw_os_error() == Some(libc::EXDEV) {
                io::Error::from_raw_os_error(libc::EACCES)
            } else {
                e
            });
        }
    }
}

fn fstatat(dir: RawFd, name: &str, flags: libc::c_int) -> io::Result<libc::stat> {
    let c = cstr(name)?;
    // SAFETY: an all-zero stat is valid; the pointers outlive the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstatat(dir, c.as_ptr(), &mut st, flags) })?;
    Ok(st)
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    fstatat(fd, "", libc::AT_EMPTY_PATH)
}

fn ns(sec: i64, nsec: i64) -> i64 {
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

fn kind(mode: u32) -> pb::FileKind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => pb::FileKind::File,
        libc::S_IFDIR => pb::FileKind::Directory,
        libc::S_IFLNK => pb::FileKind::Symlink,
        libc::S_IFIFO => pb::FileKind::Fifo,
        libc::S_IFSOCK => pb::FileKind::Socket,
        libc::S_IFCHR => pb::FileKind::CharDevice,
        libc::S_IFBLK => pb::FileKind::BlockDevice,
        _ => pb::FileKind::Unspecified,
    }
}

impl Inner {
    fn attr(&self, st: &libc::stat) -> pb::FileAttr {
        let mut id = Vec::with_capacity(16);
        id.extend_from_slice(&st.st_dev.to_le_bytes());
        id.extend_from_slice(&st.st_ino.to_le_bytes());
        pb::FileAttr {
            kind: kind(st.st_mode) as i32,
            mode: st.st_mode & 0o7777,
            size: st.st_size as u64,
            uid: st.st_uid,
            gid: st.st_gid,
            nlink: st.st_nlink as u32,
            atime_ns: ns(st.st_atime, st.st_atime_nsec),
            mtime_ns: ns(st.st_mtime, st.st_mtime_nsec),
            ctime_ns: ns(st.st_ctime, st.st_ctime_nsec),
            rdev: st.st_rdev as u32,
            ttl_ms: self.ttl_ms,
            object_id: Some(id),
        }
    }

    fn writable(&self) -> io::Result<()> {
        if self.read_only {
            Err(io::Error::from_raw_os_error(libc::EROFS))
        } else {
            Ok(())
        }
    }

    fn parent(&self, rel: &str) -> io::Result<OwnedFd> {
        openat2(
            self.root.as_raw_fd(),
            rel,
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )
    }

    fn stat(&self, path: &str) -> io::Result<pb::FileAttr> {
        valid(path)?;
        let st = if path == "/" {
            fstat(self.root.as_raw_fd())?
        } else {
            let (p, n) = split(path)?;
            fstatat(self.parent(p)?.as_raw_fd(), n, libc::AT_SYMLINK_NOFOLLOW)?
        };
        Ok(self.attr(&st))
    }

    fn list(&self, path: &str) -> io::Result<Vec<pb::DirEntry>> {
        let fd = openat2(
            self.root.as_raw_fd(),
            relative(path)?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        // SAFETY: fdopendir takes over the descriptor on success.
        let dir = unsafe { libc::fdopendir(fd.as_raw_fd()) };
        if dir.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _ = fd.into_raw_fd();
        let dfd = unsafe { libc::dirfd(dir) };
        let mut out = Vec::new();
        loop {
            // SAFETY: dir is open; readdir's result is read before the next call.
            let e = unsafe { libc::readdir(dir) };
            if e.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) };
            let Ok(name) = name.to_str() else { continue };
            if name == "." || name == ".." {
                continue;
            }
            // Gone since it was listed: leave it out.
            let Ok(st) = fstatat(dfd, name, libc::AT_SYMLINK_NOFOLLOW) else {
                continue;
            };
            out.push(pb::DirEntry {
                name: name.to_string(),
                attr: Some(self.attr(&st)),
            });
        }
        // SAFETY: closes the descriptor fdopendir took.
        unsafe { libc::closedir(dir) };
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn keep(&self, f: File) -> u64 {
        let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.files.lock().unwrap().insert(h, Arc::new(f));
        h
    }

    fn file(&self, handle: u64) -> io::Result<Arc<File>> {
        self.files
            .lock()
            .unwrap()
            .get(&handle)
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
    }

    fn opened(&self, f: File, readable: bool) -> io::Result<pb::OpenReply> {
        let st = fstat(f.as_raw_fd())?;
        let inline = if readable
            && st.st_mode & libc::S_IFMT == libc::S_IFREG
            && (st.st_size as u64) <= INLINE_MAX
        {
            let mut buf = vec![0u8; st.st_size as usize];
            let mut got = 0;
            while got < buf.len() {
                match f.read_at(&mut buf[got..], got as u64)? {
                    0 => break,
                    n => got += n,
                }
            }
            buf.truncate(got);
            Some(buf)
        } else {
            None
        };
        let attr = self.attr(&st);
        Ok(pb::OpenReply {
            handle: self.keep(f),
            attr: Some(attr),
            inline_data: inline,
            ..Default::default()
        })
    }

    fn open(&self, r: &pb::Open) -> io::Result<pb::OpenReply> {
        let flags = r.flags as i32;
        let acc = flags & libc::O_ACCMODE;
        if acc != libc::O_RDONLY || flags & libc::O_TRUNC != 0 {
            self.writable()?;
        }
        let fd = openat2(
            self.root.as_raw_fd(),
            relative(&r.path)?,
            (flags & !(libc::O_CREAT | libc::O_EXCL)) | libc::O_NOFOLLOW,
            0,
        )?;
        self.opened(File::from(fd), acc == libc::O_RDONLY)
    }

    fn create(&self, r: &pb::Create) -> io::Result<pb::OpenReply> {
        self.writable()?;
        let (p, n) = split(&r.path)?;
        let dir = self.parent(p)?;
        let c = cstr(n)?;
        let flags = (r.flags as i32) | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: valid dirfd and NUL-terminated name without slashes.
        let fd = cvt(unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, r.mode) })?;
        self.opened(File::from(owned(fd)), false)
    }

    fn mkdir(&self, r: &pb::Mkdir) -> io::Result<pb::FileAttr> {
        self.writable()?;
        let (p, n) = split(&r.path)?;
        let dir = self.parent(p)?;
        let c = cstr(n)?;
        // SAFETY: valid dirfd and name.
        cvt(unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), r.mode) })?;
        Ok(self.attr(&fstatat(dir.as_raw_fd(), n, libc::AT_SYMLINK_NOFOLLOW)?))
    }

    fn symlink(&self, r: &pb::Symlink) -> io::Result<pb::FileAttr> {
        self.writable()?;
        let (p, n) = split(&r.path)?;
        let dir = self.parent(p)?;
        let (target, c) = (cstr(&r.target)?, cstr(n)?);
        // SAFETY: valid dirfd and NUL-terminated strings.
        cvt(unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), c.as_ptr()) })?;
        Ok(self.attr(&fstatat(dir.as_raw_fd(), n, libc::AT_SYMLINK_NOFOLLOW)?))
    }

    fn remove(&self, path: &str, flags: libc::c_int) -> io::Result<()> {
        self.writable()?;
        let (p, n) = split(path)?;
        let dir = self.parent(p)?;
        let c = cstr(n)?;
        // SAFETY: valid dirfd and name.
        cvt(unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), flags) })?;
        Ok(())
    }

    fn rename(&self, r: &pb::Rename) -> io::Result<()> {
        self.writable()?;
        let ((fp, fnm), (tp, tn)) = (split(&r.from)?, split(&r.to)?);
        let (fd, td) = (self.parent(fp)?, self.parent(tp)?);
        let (fc, tc) = (cstr(fnm)?, cstr(tn)?);
        // SAFETY: valid dirfds and NUL-terminated names.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                fd.as_raw_fd(),
                fc.as_ptr(),
                td.as_raw_fd(),
                tc.as_ptr(),
                r.flags,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn readlink(&self, path: &str) -> io::Result<String> {
        let (p, n) = split(path)?;
        let dir = self.parent(p)?;
        let c = cstr(n)?;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        // SAFETY: the buffer is valid for its length.
        let len = unsafe {
            libc::readlinkat(
                dir.as_raw_fd(),
                c.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(len as usize);
        String::from_utf8(buf).map_err(|_| einval())
    }

    fn set_attr(&self, r: &pb::SetAttr) -> io::Result<pb::FileAttr> {
        self.writable()?;
        // Through an open file, or a descriptor that names the inode alone
        // (never a symlink's target).
        let held;
        let (fd, path) = match r.handle.map(|h| self.file(h)).transpose()? {
            Some(f) => {
                held = f;
                (held.as_raw_fd(), None)
            }
            None => {
                let o = openat2(
                    self.root.as_raw_fd(),
                    relative(&r.path)?,
                    libc::O_PATH | libc::O_NOFOLLOW,
                    0,
                )?;
                let st = fstat(o.as_raw_fd())?;
                if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    return Ok(self.attr(&st));
                }
                let raw = o.as_raw_fd();
                // Kept open until the end of the call.
                std::mem::forget(o);
                (
                    raw,
                    Some(CString::new(format!("/proc/self/fd/{raw}")).unwrap()),
                )
            }
        };
        let res = (|| {
            let p = path.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
            if let Some(mode) = r.mode {
                // SAFETY: valid descriptor or /proc path.
                cvt(unsafe {
                    match path {
                        Some(_) => libc::chmod(p, mode & 0o7777),
                        None => libc::fchmod(fd, mode & 0o7777),
                    }
                })?;
            }
            if r.uid.is_some() || r.gid.is_some() {
                let (u, g) = (r.uid.unwrap_or(u32::MAX), r.gid.unwrap_or(u32::MAX));
                // SAFETY: as above.
                cvt(unsafe {
                    match path {
                        Some(_) => libc::chown(p, u, g),
                        None => libc::fchown(fd, u, g),
                    }
                })?;
            }
            if let Some(size) = r.size {
                // SAFETY: as above.
                cvt(unsafe {
                    match path {
                        Some(_) => libc::truncate(p, size as libc::off_t),
                        None => libc::ftruncate(fd, size as libc::off_t),
                    }
                })?;
            }
            if r.atime_ns.is_some() || r.mtime_ns.is_some() {
                let ts = |v: Option<i64>| match v {
                    Some(v) => libc::timespec {
                        tv_sec: v.div_euclid(1_000_000_000),
                        tv_nsec: v.rem_euclid(1_000_000_000),
                    },
                    None => libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                };
                let times = [ts(r.atime_ns), ts(r.mtime_ns)];
                // SAFETY: two timespecs; valid descriptor or /proc path.
                cvt(unsafe {
                    match path {
                        Some(_) => libc::utimensat(libc::AT_FDCWD, p, times.as_ptr(), 0),
                        None => libc::futimens(fd, times.as_ptr()),
                    }
                })?;
            }
            Ok(self.attr(&fstat(fd)?))
        })();
        if path.is_some() {
            // SAFETY: the descriptor was leaked above and is ours to close.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        res
    }

    fn stat_fs(&self) -> io::Result<pb::StatFsReply> {
        // SAFETY: an all-zero statvfs is valid.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor and out pointer.
        cvt(unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut s) })?;
        Ok(pb::StatFsReply {
            blocks: s.f_blocks as u64,
            bfree: s.f_bfree as u64,
            bavail: s.f_bavail as u64,
            files: s.f_files as u64,
            ffree: s.f_ffree as u64,
            bsize: s.f_frsize as u32,
            namelen: s.f_namemax as u32,
        })
    }
}

impl Filesystem for Passthrough {
    async fn stat(&self, _cx: &Context, r: pb::Stat) -> Result<pb::FileAttr> {
        self.run(move |i| i.stat(&r.path))
            .await
            .map_err(|e| match e.errno {
                errno::ENOENT => e.cached_for_ms(self.0.ttl_ms),
                _ => e,
            })
    }

    async fn read_dir(&self, _cx: &Context, r: pb::ReadDir) -> Result<Vec<pb::DirEntry>> {
        self.run(move |i| i.list(&r.path)).await
    }

    async fn readlink(&self, _cx: &Context, r: pb::Readlink) -> Result<String> {
        self.run(move |i| i.readlink(&r.path)).await
    }

    async fn open(&self, _cx: &Context, r: pb::Open) -> Result<pb::OpenReply> {
        self.run(move |i| i.open(&r)).await
    }

    async fn read(&self, _cx: &Context, r: pb::Read) -> Result<Vec<u8>> {
        self.run(move |i| {
            let f = i.file(r.handle)?;
            let mut buf = vec![0u8; r.size as usize];
            let mut got = 0;
            while got < buf.len() {
                match f.read_at(&mut buf[got..], r.offset + got as u64)? {
                    0 => break,
                    n => got += n,
                }
            }
            buf.truncate(got);
            Ok(buf)
        })
        .await
    }

    async fn write(&self, _cx: &Context, r: pb::Write) -> Result<pb::WriteReply> {
        self.run(move |i| {
            i.writable()?;
            let f = i.file(r.handle)?;
            f.write_all_at(&r.data, r.offset)?;
            Ok(pb::WriteReply {
                written: r.data.len() as u32,
                attr: Some(i.attr(&fstat(f.as_raw_fd())?)),
            })
        })
        .await
    }

    async fn release(&self, _cx: &Context, r: pb::Release) -> Result<()> {
        self.0.files.lock().unwrap().remove(&r.handle);
        Ok(())
    }

    async fn fsync(&self, _cx: &Context, r: pb::Fsync) -> Result<()> {
        self.run(move |i| {
            let f = i.file(r.handle)?;
            if r.datasync {
                f.sync_data()
            } else {
                f.sync_all()
            }
        })
        .await
    }

    async fn create(&self, _cx: &Context, r: pb::Create) -> Result<pb::OpenReply> {
        self.run(move |i| i.create(&r)).await
    }

    async fn mkdir(&self, _cx: &Context, r: pb::Mkdir) -> Result<pb::FileAttr> {
        self.run(move |i| i.mkdir(&r)).await
    }

    async fn unlink(&self, _cx: &Context, r: pb::Unlink) -> Result<()> {
        self.run(move |i| i.remove(&r.path, 0)).await
    }

    async fn rmdir(&self, _cx: &Context, r: pb::Rmdir) -> Result<()> {
        self.run(move |i| i.remove(&r.path, libc::AT_REMOVEDIR))
            .await
    }

    async fn rename(&self, _cx: &Context, r: pb::Rename) -> Result<()> {
        self.run(move |i| i.rename(&r)).await
    }

    async fn symlink(&self, _cx: &Context, r: pb::Symlink) -> Result<pb::FileAttr> {
        self.run(move |i| i.symlink(&r)).await
    }

    async fn set_attr(&self, _cx: &Context, r: pb::SetAttr) -> Result<pb::FileAttr> {
        self.run(move |i| i.set_attr(&r)).await
    }

    async fn stat_fs(&self, _cx: &Context, _r: pb::StatFs) -> Result<pb::StatFsReply> {
        self.run(|i| i.stat_fs()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fs(dir: &std::path::Path, ro: bool) -> Passthrough {
        Passthrough::new(dir, ro, 100).unwrap()
    }

    fn cx() -> Context {
        Context::default()
    }

    #[test]
    fn paths_are_validated() {
        assert_eq!(split("/a").unwrap(), (".", "a"));
        assert_eq!(split("/a/b/c").unwrap(), ("a/b", "c"));
        assert!(split("/").is_err());
        for bad in ["a", "/a/../b", "/a//b", "/./a", "/a/", "/a\0b"] {
            assert!(valid(bad).is_err(), "{bad:?}");
        }
        assert_eq!(relative("/").unwrap(), ".");
    }

    #[tokio::test]
    async fn serves_reads_writes_and_listings() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("hello"), "hi\n").unwrap();
        let p = fs(d.path(), false);

        let a = p
            .stat(
                &cx(),
                pb::Stat {
                    path: "/hello".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!((a.size, a.kind()), (3, pb::FileKind::File));
        let e = p
            .stat(
                &cx(),
                pb::Stat {
                    path: "/nope".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!((e.errno, e.negative_ttl_ms), (errno::ENOENT, 100));

        let o = p
            .open(
                &cx(),
                pb::Open {
                    path: "/hello".into(),
                    flags: libc::O_RDONLY as u32,
                },
            )
            .await
            .unwrap();
        assert_eq!(o.inline_data.as_deref(), Some(&b"hi\n"[..]));
        let got = p
            .read(
                &cx(),
                pb::Read {
                    handle: o.handle,
                    offset: 1,
                    size: 10,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(got, b"i\n");
        p.release(
            &cx(),
            pb::Release {
                handle: o.handle,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let c = p
            .create(
                &cx(),
                pb::Create {
                    path: "/new".into(),
                    mode: 0o644,
                    flags: libc::O_WRONLY as u32,
                },
            )
            .await
            .unwrap();
        let w = p
            .write(
                &cx(),
                pb::Write {
                    handle: c.handle,
                    data: b"abc".to_vec(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!((w.written, w.attr.unwrap().size), (3, 3));
        assert_eq!(std::fs::read(d.path().join("new")).unwrap(), b"abc");

        p.mkdir(
            &cx(),
            pb::Mkdir {
                path: "/sub".into(),
                mode: 0o755,
            },
        )
        .await
        .unwrap();
        p.rename(
            &cx(),
            pb::Rename {
                from: "/new".into(),
                to: "/sub/moved".into(),
                flags: 0,
            },
        )
        .await
        .unwrap();
        let names: Vec<_> = p
            .read_dir(&cx(), pb::ReadDir { path: "/".into() })
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["hello", "sub"]);
        let a = p
            .set_attr(
                &cx(),
                pb::SetAttr {
                    path: "/sub/moved".into(),
                    size: Some(1),
                    mode: Some(0o600),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!((a.size, a.mode), (1, 0o600));
        p.unlink(
            &cx(),
            pb::Unlink {
                path: "/sub/moved".into(),
            },
        )
        .await
        .unwrap();
        p.rmdir(
            &cx(),
            pb::Rmdir {
                path: "/sub".into(),
            },
        )
        .await
        .unwrap();
        assert!(!d.path().join("sub").exists());
        assert!(p.stat_fs(&cx(), pb::StatFs {}).await.unwrap().bsize > 0);
    }

    #[tokio::test]
    async fn symlinks_cannot_leave_the_tree() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "x").unwrap();
        let d = tempfile::tempdir().unwrap();
        symlink(outside.path(), d.path().join("out")).unwrap();
        symlink("/etc/passwd", d.path().join("abs")).unwrap();
        std::fs::write(d.path().join("in"), "ok").unwrap();
        symlink("in", d.path().join("rel")).unwrap();
        let p = fs(d.path(), false);

        // Through a link that leaves, nothing resolves.
        for path in ["/out/secret", "/abs"] {
            let o = p
                .open(
                    &cx(),
                    pb::Open {
                        path: path.into(),
                        flags: 0,
                    },
                )
                .await;
            assert!(o.is_err(), "{path} escaped");
        }
        let e = p
            .stat(
                &cx(),
                pb::Stat {
                    path: "/out/secret".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.errno, errno::EACCES);
        // The links themselves are files of the tree.
        let a = p
            .stat(
                &cx(),
                pb::Stat {
                    path: "/out".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(a.kind(), pb::FileKind::Symlink);
        assert_eq!(
            p.readlink(
                &cx(),
                pb::Readlink {
                    path: "/rel".into()
                }
            )
            .await
            .unwrap(),
            "in"
        );
        // A link inside the tree resolves.
        assert!(
            p.open(
                &cx(),
                pb::Open {
                    path: "/rel".into(),
                    flags: 0
                }
            )
            .await
            .is_err(),
            "no follow at the end"
        );
        // Changing a link's mode doesn't reach its target.
        let before = std::fs::metadata(d.path().join("in")).unwrap();
        p.set_attr(
            &cx(),
            pb::SetAttr {
                path: "/rel".into(),
                mode: Some(0o000),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::metadata(d.path().join("in"))
                .unwrap()
                .permissions(),
            before.permissions()
        );
    }

    #[tokio::test]
    async fn read_only_refuses_changes() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), "x").unwrap();
        let p = fs(d.path(), true);
        let e = p
            .mkdir(
                &cx(),
                pb::Mkdir {
                    path: "/d".into(),
                    mode: 0o755,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.errno, errno::EROFS);
        let e = p
            .open(
                &cx(),
                pb::Open {
                    path: "/f".into(),
                    flags: libc::O_RDWR as u32,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.errno, errno::EROFS);
        assert!(
            p.open(
                &cx(),
                pb::Open {
                    path: "/f".into(),
                    flags: 0
                }
            )
            .await
            .is_ok()
        );
    }
}
