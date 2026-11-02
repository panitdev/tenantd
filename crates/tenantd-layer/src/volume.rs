//! Volumes: `<tenant dir>/volumes/<id>/`, inheriting the tenant's project
//! ID, so every write to one counts against the tenant's quota.
//!
//! Callers on the host (the control plane) use volumes at their path, so a
//! volume's root takes the owner and mode it was created with, and the
//! directories above it are made traversable (`--x`) but not listable.
//!
//! A volume holds what containers wrote, so pruning trusts none of it:
//! every step is relative to a directory fd opened `O_NOFOLLOW`, symlinks
//! are removed rather than followed, and nothing on another device (a
//! mount) is entered.

use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use tenantd_core::backend::VolumeBackend;
use tenantd_core::error::Context;
use tenantd_core::fsutil::remove_tree_one_fs;
use tenantd_core::model::{PruneReport, VolumeOwner};
use tenantd_core::{Error, Result, VolumeId};

use crate::blocking;

/// Directories deeper than this below the prune point are left alone; it
/// bounds the fds a prune holds open.
const MAX_DEPTH: usize = 128;

fn volumes_dir(tenant_dir: &Path) -> PathBuf {
    tenant_dir.join("volumes")
}

/// Add `--x` for group and others, keeping the rest.
fn make_traversable(dir: &Path) -> io::Result<()> {
    let mode = fs::symlink_metadata(dir)?.permissions().mode();
    if mode & 0o011 != 0o011 {
        fs::set_permissions(dir, fs::Permissions::from_mode((mode | 0o011) & 0o7777))?;
    }
    Ok(())
}

fn create(tenant_dir: &Path, v: &VolumeId, owner: VolumeOwner) -> Result<PathBuf> {
    let parent = volumes_dir(tenant_dir);
    let dir = parent.join(v.as_str());
    fs::DirBuilder::new()
        .mode(0o711)
        .recursive(true)
        .create(&parent)
        .context(format!("creating {}", parent.display()))?;
    for d in [tenant_dir.parent(), Some(tenant_dir), Some(&parent)]
        .into_iter()
        .flatten()
    {
        make_traversable(d).context(format!("chmod {}", d.display()))?;
    }
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::internal(format!("creating {}", dir.display()), e)),
    }
    // Only tenantd writes in `volumes/`, so this is the directory it made.
    if !fs::symlink_metadata(&dir)?.is_dir() {
        return Err(Error::Internal(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    std::os::unix::fs::chown(&dir, Some(owner.uid), Some(owner.gid))
        .context(format!("chown {}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(owner.mode))
        .context(format!("chmod {}", dir.display()))?;
    Ok(dir)
}

fn list(tenant_dir: &Path) -> Result<Vec<VolumeId>> {
    let entries = match fs::read_dir(volumes_dir(tenant_dir)) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for e in entries {
        let e = e?;
        if e.file_type()?.is_dir()
            && let Ok(id) = VolumeId::new(e.file_name().to_string_lossy())
        {
            out.push(id);
        }
    }
    out.sort();
    Ok(out)
}

fn last_os_error<T>() -> io::Result<T> {
    Err(io::Error::last_os_error())
}

fn cname(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::other("name contains NUL"))
}

fn stat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: an all-zero stat is a valid value to overwrite.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, NUL-terminated name and a stat to fill.
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        return last_os_error();
    }
    Ok(st)
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: as in `stat_at`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and a stat to fill.
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return last_os_error();
    }
    Ok(st)
}

/// Open a directory below `dir` without following a symlink, and without
/// touching its access time when allowed (`O_NOATIME` needs ownership or
/// `CAP_FOWNER`).
fn open_dir_at(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    for extra in [libc::O_NOATIME, 0] {
        // SAFETY: valid fd and NUL-terminated name.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | extra) };
        if fd >= 0 {
            // SAFETY: openat returned a new fd we own.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        if extra == 0 || e.raw_os_error() != Some(libc::EPERM) {
            return Err(e);
        }
    }
    unreachable!()
}

/// The names in a directory, without `.` and `..`.
fn read_names(dir: &OwnedFd) -> io::Result<Vec<CString>> {
    // SAFETY: dup of a valid fd; fdopendir takes ownership of the copy.
    let copy = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return last_os_error();
    }
    // SAFETY: `copy` is a directory fd we own.
    let d = unsafe { libc::fdopendir(copy) };
    if d.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so the copy is still ours to close.
        unsafe { libc::close(copy) };
        return Err(e);
    }
    // The copy shares the offset with `dir`; start from the top.
    // SAFETY: valid DIR stream.
    unsafe { libc::rewinddir(d) };
    let mut out = Vec::new();
    loop {
        // SAFETY: valid DIR stream; the entry is read before the next call.
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            out.push(name.to_owned());
        }
    }
    // SAFETY: valid DIR stream, closed once.
    unsafe { libc::closedir(d) };
    Ok(out)
}

fn unlink_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: valid fd and NUL-terminated name.
    if unsafe { libc::unlinkat(dir, name.as_ptr(), flags) } < 0 {
        return last_os_error();
    }
    Ok(())
}

struct Pruner {
    dev: libc::dev_t,
    cutoff: Option<i64>,
    rep: PruneReport,
}

impl Pruner {
    fn old(&self, st: &libc::stat) -> bool {
        let used = st.st_atime.max(st.st_mtime).max(st.st_ctime);
        self.cutoff.is_none_or(|c| used <= c)
    }

    /// Prune `name` in `dir`. Returns whether it is gone. Entries that
    /// can't be read or removed are kept.
    fn entry(&mut self, dir: RawFd, name: &CStr, depth: usize) -> bool {
        let st = match stat_at(dir, name) {
            Ok(st) => st,
            Err(e) => return e.raw_os_error() == Some(libc::ENOENT),
        };
        if st.st_dev != self.dev {
            return false; // a mount point
        }
        // Judged by its times before the walk below changes them.
        let old = self.old(&st);
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            if depth >= MAX_DEPTH {
                return false;
            }
            let Ok(fd) = open_dir_at(dir, name) else {
                return false;
            };
            // Swapped for something else between the stat and the open.
            match fstat(fd.as_raw_fd()) {
                Ok(s) if s.st_dev == st.st_dev && s.st_ino == st.st_ino => {}
                _ => return false,
            }
            if !self.children(&fd, depth + 1) || !old {
                return false;
            }
            if unlink_at(dir, name, libc::AT_REMOVEDIR).is_err() {
                return false;
            }
            self.rep.entries += 1;
            return true;
        }
        if !old || unlink_at(dir, name, 0).is_err() {
            return false;
        }
        self.rep.entries += 1;
        if st.st_nlink <= 1 {
            self.rep.bytes += (st.st_blocks as u64).saturating_mul(512);
        }
        true
    }

    /// Prune everything in `dir`. Returns whether it is now empty.
    fn children(&mut self, dir: &OwnedFd, depth: usize) -> bool {
        let Ok(names) = read_names(dir) else {
            return false;
        };
        let mut empty = true;
        for n in names {
            empty &= self.entry(dir.as_raw_fd(), &n, depth);
        }
        empty
    }
}

fn prune(root: &Path, prefix: &Path, cutoff: Option<i64>) -> Result<PruneReport> {
    let names: Vec<&OsStr> = prefix
        .components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n),
            _ => Err(Error::invalid("path prefix must be relative and plain")),
        })
        .collect::<Result<_>>()?;
    let root_c = cname(root.as_os_str())?;
    let root_fd =
        open_dir_at(libc::AT_FDCWD, &root_c).context(format!("opening {}", root.display()))?;
    let mut p = Pruner {
        dev: fstat(root_fd.as_raw_fd())?.st_dev,
        cutoff,
        rep: PruneReport::default(),
    };
    let Some((last, parents)) = names.split_last() else {
        p.children(&root_fd, 0);
        return Ok(p.rep);
    };
    let mut dir = root_fd;
    for n in parents {
        match open_dir_at(dir.as_raw_fd(), &cname(n)?) {
            Ok(fd) if fstat(fd.as_raw_fd())?.st_dev == p.dev => dir = fd,
            Ok(_) => return Ok(p.rep),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
                ) =>
            {
                return Ok(p.rep);
            }
            Err(e) => return Err(e.into()),
        }
    }
    p.entry(dir.as_raw_fd(), &cname(last)?, 0);
    Ok(p.rep)
}

pub struct HostVolumes;

#[async_trait]
impl VolumeBackend for HostVolumes {
    fn path(&self, tenant_dir: &Path, v: &VolumeId) -> PathBuf {
        volumes_dir(tenant_dir).join(v.as_str())
    }

    async fn create(&self, tenant_dir: &Path, v: &VolumeId, owner: VolumeOwner) -> Result<PathBuf> {
        let (d, v) = (tenant_dir.to_path_buf(), v.clone());
        blocking(move || create(&d, &v, owner)).await
    }

    async fn exists(&self, tenant_dir: &Path, v: &VolumeId) -> Result<bool> {
        let p = self.path(tenant_dir, v);
        blocking(move || match fs::symlink_metadata(&p) {
            Ok(m) => Ok(m.is_dir()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        })
        .await
    }

    async fn delete(&self, tenant_dir: &Path, v: &VolumeId) -> Result<()> {
        let p = self.path(tenant_dir, v);
        blocking(move || remove_tree_one_fs(&p).context(format!("removing {}", p.display()))).await
    }

    async fn prune(
        &self,
        tenant_dir: &Path,
        v: &VolumeId,
        prefix: &Path,
        cutoff: Option<i64>,
    ) -> Result<PruneReport> {
        let (root, prefix) = (self.path(tenant_dir, v), prefix.to_path_buf());
        blocking(move || prune(&root, &prefix, cutoff)).await
    }

    async fn list_owned(&self, tenant_dir: &Path) -> Result<Vec<VolumeId>> {
        let d = tenant_dir.to_path_buf();
        blocking(move || list(&d)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn owner() -> VolumeOwner {
        // SAFETY: no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        VolumeOwner {
            uid,
            gid,
            mode: 0o1777,
        }
    }

    #[tokio::test]
    async fn create_list_delete() {
        let d = tempfile::tempdir().unwrap();
        let tenant = d.path().join("tenants/t");
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&tenant)
            .unwrap();
        let v = VolumeId::new("ws").unwrap();
        let b = HostVolumes;
        assert!(!b.exists(&tenant, &v).await.unwrap());
        let p = b.create(&tenant, &v, owner()).await.unwrap();
        assert_eq!(p, tenant.join("volumes/ws"));
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
            0o1777
        );
        assert_eq!(
            fs::metadata(&tenant).unwrap().permissions().mode() & 0o777,
            0o711
        );
        fs::write(p.join("f"), "x").unwrap();
        // Idempotent, and keeps the contents.
        b.create(
            &tenant,
            &v,
            VolumeOwner {
                mode: 0o755,
                ..owner()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert!(p.join("f").exists());
        assert_eq!(b.list_owned(&tenant).await.unwrap(), vec![v.clone()]);
        b.delete(&tenant, &v).await.unwrap();
        b.delete(&tenant, &v).await.unwrap();
        assert!(!b.exists(&tenant, &v).await.unwrap());
        assert!(b.list_owned(&tenant).await.unwrap().is_empty());
    }

    #[test]
    fn prune_by_age_without_following_links() {
        let d = tempfile::tempdir().unwrap();
        let (root, outside) = (d.path().join("vol"), d.path().join("outside"));
        fs::create_dir_all(root.join("s-1/deep/er")).unwrap();
        fs::create_dir_all(root.join("s-2")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("precious"), "keep").unwrap();
        fs::write(root.join("s-1/deep/er/old"), vec![0u8; 8192]).unwrap();
        fs::write(root.join("s-1/new"), "n").unwrap();
        fs::write(root.join("s-2/old"), "o").unwrap();
        fs::write(root.join("shared-old"), "o").unwrap();
        fs::write(root.join("shared-new"), "n").unwrap();
        symlink(&outside, root.join("s-2/link")).unwrap();

        // A prefix that is missing, or leads through a symlink, does nothing.
        assert_eq!(
            prune(&root, Path::new("nope/x"), None).unwrap(),
            PruneReport::default()
        );
        assert_eq!(
            prune(&root, Path::new("s-2/link/precious"), None).unwrap(),
            PruneReport::default()
        );
        assert!(outside.join("precious").exists());

        // Everything was just written, so an age cutoff keeps it all.
        let r = prune(&root, Path::new(""), Some(tenantd_core::now() - 3600)).unwrap();
        assert_eq!(r, PruneReport::default());

        // older_than = 0 takes everything at or below the prefix, links
        // included but never their targets; the volume root stays.
        let r = prune(&root, Path::new("s-2"), None).unwrap();
        assert_eq!(r.entries, 3); // old, link, s-2
        assert!(!root.join("s-2").exists());
        assert!(outside.join("precious").exists());
        let r = prune(&root, Path::new("s-1"), None).unwrap();
        assert_eq!(r.entries, 5); // old, er, deep, new, s-1
        assert!(r.bytes >= 8192);
        let r = prune(&root, Path::new(""), None).unwrap();
        assert_eq!(r.entries, 2);
        assert!(root.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn prune_keeps_recent_by_every_time() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("vol");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("f"), "x").unwrap();
        // Everything was just changed: a cutoff in the past keeps it, one
        // in the future takes it.
        let past = Some(tenantd_core::now() - 60);
        assert_eq!(prune(&root, Path::new(""), past).unwrap().entries, 0);
        let future = Some(tenantd_core::now() + 60);
        assert_eq!(prune(&root, Path::new(""), future).unwrap().entries, 1);
        assert!(!root.join("f").exists());
    }
}
