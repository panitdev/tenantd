//! Containers' FUSE mounts, on the host.
//!
//! gVisor's own FUSE lives in its Sentry, out of reach of a server outside
//! the sandbox. So tenantd mounts a host FUSE filesystem per container at
//! `<fuse dir>/<tenant>.<sandbox>.<container>` and the container
//! bind-mounts it like a volume; runsc's gofer serves it from the host.
//!
//! tenantd also runs the kernel side of the mount. Its session turns
//! kernel requests into the path-based operations of
//! [`tenantd_core::fuse`], which go to whichever caller's server is
//! attached (see [`pathfs`] for what it answers itself, [`router`] for
//! queueing). The session outlives any one server, so a server may restart
//! or move; it ends with the container. Nothing here stats the mount: with
//! no server attached, that would hang.
//!
//! The mount is `allow_other` (runsc's gofer reaches it, not tenantd) and
//! `default_permissions`: the kernel checks mode bits against the
//! attributes the server reports, so permission checks cost no round trips.

mod pathfs;
mod router;

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fuser::{Config, Session, SessionACL};
use tenantd_core::backend::FuseBackend;
use tenantd_core::error::Context;
use tenantd_core::fuse::{FuseLimits, FuseLink};
use tenantd_core::{ContainerKey, Error, Result};
use tracing::{info, warn};

use self::pathfs::PathFs;
use self::router::Router;

use crate::blocking;
use crate::mount::{self, mount_entries_under};

const FSTYPE: &str = "fuse.tenantd";

pub struct HostFuse {
    dir: PathBuf,
    sessions: Arc<Mutex<HashMap<ContainerKey, Arc<Router>>>>,
}

impl HostFuse {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            sessions: Arc::default(),
        }
    }

    fn point(&self, c: &ContainerKey) -> PathBuf {
        self.dir.join(c.to_string())
    }
}

/// The FUSE connection's number under `/sys/fs/fuse/connections`: the
/// kernel's encoding of the superblock's device number.
fn connection_id((major, minor): (u32, u32)) -> u64 {
    (u64::from(major) << 20) | u64::from(minor)
}

/// Abort the connection mounted at `point`, if any, so requests waiting on
/// it fail, then detach the mount and remove the mount point.
fn release(point: &Path) -> io::Result<()> {
    for m in mount_entries_under(point)?
        .into_iter()
        .filter(|m| m.point == point)
    {
        if m.fstype.starts_with("fuse") {
            let abort = format!("/sys/fs/fuse/connections/{}/abort", connection_id(m.dev));
            if let Err(e) = fs::write(&abort, "1") {
                // Without fusectl the connection still ends once its last
                // fd closes.
                warn!(path = abort, error = %e, "aborting FUSE connection failed");
            }
        }
        let tgt = CString::new(point.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::other("path contains NUL"))?;
        // SAFETY: valid NUL-terminated path.
        if unsafe { libc::umount2(tgt.as_ptr(), libc::MNT_DETACH) } < 0 {
            let e = io::Error::last_os_error();
            if !matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOENT)) {
                return Err(e);
            }
        }
    }
    match fs::remove_dir(point) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Open `/dev/fuse` and mount a new connection on `point`.
fn mount_fresh(point: &Path) -> io::Result<OwnedFd> {
    // SAFETY: NUL-terminated literal path.
    let fd = unsafe { libc::open(c"/dev/fuse".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: no preconditions.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let data = format!(
        "fd={},rootmode=40000,user_id={uid},group_id={gid},allow_other,default_permissions",
        fd.as_raw_fd()
    );
    mount::mount(
        "tenantd",
        point,
        Some(FSTYPE),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(&data),
    )?;
    Ok(fd)
}

/// Mount a fresh session on `point` and run it on its own thread, which
/// ends when the connection does. The returned router is how requests
/// reach servers.
fn start_session(key: &ContainerKey, point: &Path) -> io::Result<Arc<Router>> {
    let fd = mount_fresh(point)?;
    let router = Router::new();
    let fs = PathFs::new(router.clone());
    let mut config = Config::default();
    config.acl = SessionACL::All;
    let session = match Session::from_fd(fs.clone(), fd, SessionACL::All, config) {
        Ok(s) => s,
        Err(e) => {
            let _ = release(point);
            return Err(e);
        }
    };
    fs.set_notifier(session.notifier());
    let (r, name) = (router.clone(), key.to_string());
    std::thread::Builder::new()
        .name(format!("fuse-{name}"))
        .spawn(move || {
            if let Err(e) = session.run() {
                warn!(container = name, error = %e, "FUSE session ended with an error");
            }
            // Whoever still waits on the mount fails instead of hanging.
            r.close();
        })
        .inspect_err(|_| {
            let _ = release(point);
        })?;
    Ok(router)
}

#[async_trait]
impl FuseBackend for HostFuse {
    async fn mount(&self, c: &ContainerKey) -> Result<PathBuf> {
        let (dir, point, sessions, key) = (
            self.dir.clone(),
            self.point(c),
            self.sessions.clone(),
            c.clone(),
        );
        blocking(move || {
            let held = sessions.lock().unwrap().contains_key(&key);
            if held && mount::is_mountpoint(&point)? {
                return Ok(point);
            }
            // Whatever is there is no session tenantd can serve.
            if let Some(old) = sessions.lock().unwrap().remove(&key) {
                old.close();
            }
            release(&point).context(format!("releasing {}", point.display()))?;
            fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&dir)
                .context(format!("creating {}", dir.display()))?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&point)
                .context(format!("creating {}", point.display()))?;
            let router = start_session(&key, &point)
                .context(format!("mounting FUSE on {}", point.display()))?;
            sessions.lock().unwrap().insert(key.clone(), router);
            info!(container = %key, point = %point.display(), "FUSE session mounted");
            Ok(point)
        })
        .await
    }

    fn attach(&self, c: &ContainerKey, theirs: FuseLimits) -> Result<Option<FuseLink>> {
        let router = self.sessions.lock().unwrap().get(c).cloned();
        Ok(router.and_then(|r| r.attach(theirs)))
    }

    fn has_session(&self, c: &ContainerKey) -> bool {
        self.sessions.lock().unwrap().contains_key(c)
    }

    async fn unmount(&self, c: &ContainerKey) -> Result<()> {
        let (point, sessions, key) = (self.point(c), self.sessions.clone(), c.clone());
        blocking(move || {
            release(&point).context(format!("releasing {}", point.display()))?;
            if let Some(router) = sessions.lock().unwrap().remove(&key) {
                router.close();
                info!(container = %key, "FUSE session released");
            }
            Ok(())
        })
        .await
    }

    async fn list_owned(&self) -> Result<Vec<ContainerKey>> {
        let dir = self.dir.clone();
        blocking(move || {
            let mut out: Vec<ContainerKey> = Vec::new();
            match fs::read_dir(&dir) {
                Ok(entries) => {
                    for e in entries {
                        if let Ok(k) = e?.file_name().to_string_lossy().parse() {
                            out.push(k);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::internal(format!("listing {}", dir.display()), e)),
            }
            for m in mount_entries_under(&dir)? {
                if let Some(k) = m
                    .point
                    .strip_prefix(&dir)
                    .ok()
                    .and_then(|p| p.to_str())
                    .and_then(|p| p.parse().ok())
                {
                    out.push(k);
                }
            }
            out.sort();
            out.dedup();
            Ok(out)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tenantd_core::fuse::{
        DirEntry, FileAttr, FileKind, FuseError, FuseEvent, FuseOp, FuseReply, FuseResult,
        OpenReply,
    };

    const CONTENT: &[u8] = b"hello from fuse\n";

    fn attr(kind: FileKind, size: u64) -> FileAttr {
        FileAttr {
            kind,
            mode: if kind == FileKind::Directory {
                0o755
            } else {
                0o444
            },
            size,
            uid: 0,
            gid: 0,
            nlink: 1,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            rdev: 0,
            ttl_ms: 1000,
            object_id: None,
        }
    }

    fn answer(op: FuseOp) -> FuseResult {
        let file = || attr(FileKind::File, CONTENT.len() as u64);
        match op {
            FuseOp::Stat { path } if path == "/" => {
                Ok(FuseReply::Attr(attr(FileKind::Directory, 0)))
            }
            FuseOp::Stat { path } if path == "/hello" => Ok(FuseReply::Attr(file())),
            FuseOp::Stat { .. } => Err(FuseError::new(libc::ENOENT)),
            FuseOp::ReadDir { path } if path == "/" => Ok(FuseReply::Dir(vec![DirEntry {
                name: "hello".into(),
                attr: file(),
            }])),
            FuseOp::Open { .. } => Ok(FuseReply::Open(OpenReply {
                handle: 7,
                keep_cache: false,
                direct_io: false,
                buffered_writes: false,
                attr: Some(file()),
                inline_data: None,
            })),
            FuseOp::Read { offset, size, .. } => {
                let start = (offset as usize).min(CONTENT.len());
                let end = (start + size as usize).min(CONTENT.len());
                Ok(FuseReply::Data(CONTENT[start..end].to_vec()))
            }
            FuseOp::Release { .. } | FuseOp::Flush { .. } => Ok(FuseReply::Ok),
            _ => Err(FuseError::new(libc::ENOSYS)),
        }
    }

    /// A server of one read-only file, `hello`. Returns how many requests
    /// it answered once its link ends.
    async fn serve_hello(mut link: FuseLink) -> usize {
        let mut served = 0;
        while let Some(ev) = link.events.recv().await {
            match ev {
                FuseEvent::Request { id, op, .. } => {
                    served += 1;
                    link.respond(id, answer(op));
                }
                FuseEvent::Replaced => break,
                FuseEvent::Cancel { .. } => {}
            }
        }
        served
    }

    /// kind, bytes or link target, mode
    type MemNode = (FileKind, Vec<u8>, u32);

    /// A writable in-memory tree, answering in the way a real server would.
    #[derive(Default)]
    struct MemFs {
        nodes: std::sync::Mutex<std::collections::BTreeMap<String, MemNode>>,
        next_handle: std::sync::atomic::AtomicU64,
    }

    impl MemFs {
        fn attr(kind: FileKind, data: &[u8], mode: u32) -> FileAttr {
            FileAttr {
                kind,
                mode,
                size: data.len() as u64,
                nlink: 1,
                ttl_ms: 1000,
                ..attr(kind, 0)
            }
        }

        fn answer(&self, op: FuseOp) -> FuseResult {
            use std::sync::atomic::Ordering::Relaxed;
            let mut n = self.nodes.lock().unwrap();
            let parent = |p: &str| {
                p.rsplit_once('/')
                    .map_or("/", |(d, _)| if d.is_empty() { "/" } else { d })
                    .to_string()
            };
            let get = |n: &std::collections::BTreeMap<_, (FileKind, Vec<u8>, u32)>, p: &str| {
                if p == "/" {
                    return Some(Self::attr(FileKind::Directory, &[], 0o755));
                }
                n.get(p).map(|(k, d, m)| Self::attr(*k, d, *m))
            };
            let enoent = || Err(FuseError::new(libc::ENOENT));
            match op {
                FuseOp::Stat { path } => {
                    get(&n, &path).map_or_else(enoent, |a| Ok(FuseReply::Attr(a)))
                }
                FuseOp::ReadDir { path } => Ok(FuseReply::Dir(
                    n.iter()
                        .filter(|(p, _)| parent(p) == path)
                        .map(|(p, (k, d, m))| DirEntry {
                            name: p.rsplit('/').next().unwrap().to_string(),
                            attr: Self::attr(*k, d, *m),
                        })
                        .collect(),
                )),
                FuseOp::Create { path, mode, .. } => {
                    n.insert(path.clone(), (FileKind::File, vec![], mode & 0o7777));
                    Ok(FuseReply::Open(OpenReply {
                        handle: self.next_handle.fetch_add(1, Relaxed) + 1,
                        keep_cache: false,
                        direct_io: false,
                        buffered_writes: false,
                        attr: get(&n, &path),
                        inline_data: None,
                    }))
                }
                FuseOp::Open { path, .. } => {
                    if !n.contains_key(&path) {
                        return enoent();
                    }
                    Ok(FuseReply::Open(OpenReply {
                        handle: self.next_handle.fetch_add(1, Relaxed) + 1,
                        keep_cache: false,
                        direct_io: false,
                        buffered_writes: false,
                        attr: get(&n, &path),
                        inline_data: None,
                    }))
                }
                FuseOp::Write {
                    path, offset, data, ..
                } => {
                    let Some((_, bytes, _)) = n.get_mut(&path) else {
                        return enoent();
                    };
                    let end = offset as usize + data.len();
                    if bytes.len() < end {
                        bytes.resize(end, 0);
                    }
                    bytes[offset as usize..end].copy_from_slice(&data);
                    Ok(FuseReply::Written {
                        written: data.len() as u32,
                        attr: get(&n, &path),
                    })
                }
                FuseOp::Read {
                    path, offset, size, ..
                } => {
                    let Some((_, bytes, _)) = n.get(&path) else {
                        return enoent();
                    };
                    let start = (offset as usize).min(bytes.len());
                    Ok(FuseReply::Data(
                        bytes[start..(start + size as usize).min(bytes.len())].to_vec(),
                    ))
                }
                FuseOp::Mkdir { path, mode } => {
                    n.insert(path.clone(), (FileKind::Directory, vec![], mode));
                    Ok(FuseReply::Attr(get(&n, &path).unwrap()))
                }
                FuseOp::Symlink { path, target } => {
                    n.insert(
                        path.clone(),
                        (FileKind::Symlink, target.into_bytes(), 0o777),
                    );
                    Ok(FuseReply::Attr(get(&n, &path).unwrap()))
                }
                FuseOp::Readlink { path } => match n.get(&path) {
                    Some((_, t, _)) => Ok(FuseReply::Target(String::from_utf8(t.clone()).unwrap())),
                    None => enoent(),
                },
                FuseOp::Unlink { path } | FuseOp::Rmdir { path } => {
                    n.remove(&path).map_or_else(enoent, |_| Ok(FuseReply::Ok))
                }
                FuseOp::Rename { from, to, .. } => {
                    let moved: Vec<_> = n
                        .keys()
                        .filter(|k| **k == from || k.starts_with(&format!("{from}/")))
                        .cloned()
                        .collect();
                    if moved.is_empty() {
                        return enoent();
                    }
                    for k in moved {
                        let v = n.remove(&k).unwrap();
                        n.insert(format!("{to}{}", &k[from.len()..]), v);
                    }
                    Ok(FuseReply::Ok)
                }
                FuseOp::SetAttr { path, set } => {
                    let Some((_, bytes, mode)) = n.get_mut(&path) else {
                        return enoent();
                    };
                    if let Some(size) = set.size {
                        bytes.resize(size as usize, 0);
                    }
                    if let Some(m) = set.mode {
                        *mode = m & 0o7777;
                    }
                    Ok(FuseReply::Attr(get(&n, &path).unwrap()))
                }
                FuseOp::Release { .. } | FuseOp::Flush { .. } | FuseOp::Fsync { .. } => {
                    Ok(FuseReply::Ok)
                }
                FuseOp::StatFs => Err(FuseError::new(libc::ENOSYS)),
            }
        }
    }

    /// Needs to mount FUSE; see the test below.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn host_fuse_writes_and_renames_through_a_server() {
        let d = tempfile::tempdir().unwrap();
        let fuse = HostFuse::new(d.path().join("fuse"));
        let c: ContainerKey = "t.s.c".parse().unwrap();
        let point = fuse.mount(&c).await.unwrap();
        let fs = std::sync::Arc::new(MemFs::default());
        let mut link = fuse.attach(&c, FuseLimits::SERVER).unwrap().unwrap();
        let served = fs.clone();
        let server = tokio::spawn(async move {
            while let Some(ev) = link.events.recv().await {
                if let FuseEvent::Request { id, op, .. } = ev {
                    link.respond(id, served.answer(op));
                }
            }
        });

        let p = point.clone();
        tokio::time::timeout(
            Duration::from_secs(20),
            tokio::task::spawn_blocking(move || {
                use std::io::{Read, Seek, SeekFrom, Write};
                std::fs::create_dir(p.join("dir")).unwrap();
                std::fs::write(p.join("dir/a"), b"hello world").unwrap();
                assert_eq!(std::fs::read(p.join("dir/a")).unwrap(), b"hello world");

                // Rewrite in place, append and read back through one handle.
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(p.join("dir/a"))
                    .unwrap();
                f.seek(SeekFrom::Start(6)).unwrap();
                f.write_all(b"FUSE!").unwrap();
                f.seek(SeekFrom::End(0)).unwrap();
                f.write_all(b" more").unwrap();
                f.seek(SeekFrom::Start(0)).unwrap();
                let mut s = String::new();
                f.read_to_string(&mut s).unwrap();
                assert_eq!(s, "hello FUSE! more");
                drop(f);

                // Big writes cross the request size limit in pieces.
                let big = vec![7u8; 3 << 20];
                std::fs::write(p.join("big"), &big).unwrap();
                assert_eq!(std::fs::read(p.join("big")).unwrap(), big);

                // Truncate, chmod, listing sees sizes and modes.
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(p.join("dir/a"))
                    .unwrap();
                f.set_len(5).unwrap();
                drop(f);
                std::fs::set_permissions(
                    p.join("dir/a"),
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                )
                .unwrap();
                let m = std::fs::metadata(p.join("dir/a")).unwrap();
                assert_eq!(m.len(), 5);
                assert_eq!(
                    std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777,
                    0o600
                );

                // Rename a directory with a file inside; old names vanish.
                std::fs::rename(p.join("dir"), p.join("moved")).unwrap();
                assert!(std::fs::metadata(p.join("dir/a")).is_err());
                assert_eq!(std::fs::read(p.join("moved/a")).unwrap(), b"hello");

                std::os::unix::fs::symlink("moved/a", p.join("link")).unwrap();
                assert_eq!(
                    std::fs::read_link(p.join("link")).unwrap().to_str(),
                    Some("moved/a")
                );
                assert_eq!(std::fs::read(p.join("link")).unwrap(), b"hello");

                let mut names: Vec<_> = std::fs::read_dir(&p)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect();
                names.sort();
                assert_eq!(names, ["big", "link", "moved"]);

                std::fs::remove_file(p.join("moved/a")).unwrap();
                assert!(std::fs::metadata(p.join("moved/a")).is_err());
                std::fs::remove_dir(p.join("moved")).unwrap();
                assert!(
                    std::fs::read_dir(&p)
                        .unwrap()
                        .all(|e| e.unwrap().file_name() != "moved")
                );
            }),
        )
        .await
        .expect("operations through FUSE hung")
        .unwrap();

        fuse.unmount(&c).await.unwrap();
        server.abort();
    }

    #[test]
    fn connection_ids() {
        assert_eq!(connection_id((0, 53)), 53);
        assert_eq!(connection_id((1, 2)), (1 << 20) | 2);
    }

    /// Needs to mount FUSE. Run unprivileged inside a user+mount namespace:
    /// `unshare -rm cargo test -p tenantd-layer -- --ignored`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn host_fuse_mounts_serves_and_releases() {
        let d = tempfile::tempdir().unwrap();
        let fuse = HostFuse::new(d.path().join("fuse"));
        let c: ContainerKey = "t.s.c".parse().unwrap();
        assert!(fuse.attach(&c, FuseLimits::SERVER).unwrap().is_none());
        assert!(!fuse.has_session(&c));
        let point = fuse.mount(&c).await.unwrap();
        assert_eq!(point, d.path().join("fuse/t.s.c"));
        assert_eq!(fuse.mount(&c).await.unwrap(), point, "kept while held");
        assert_eq!(fuse.list_owned().await.unwrap(), vec![c.clone()]);

        // Reads through the mount reach the attached server.
        let server = tokio::spawn(serve_hello(
            fuse.attach(&c, FuseLimits::SERVER).unwrap().unwrap(),
        ));
        let p = point.clone();
        let read = tokio::task::spawn_blocking(move || std::fs::read(p.join("hello")));
        let got = tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .expect("read through FUSE hung")
            .unwrap()
            .unwrap();
        assert_eq!(got, CONTENT);
        let names: Vec<_> = std::fs::read_dir(&point)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec!["hello"]);
        assert!(std::fs::metadata(point.join("absent")).is_err());
        // Writes are refused by this server, and say so.
        let e = std::fs::write(point.join("new"), b"x").unwrap_err();
        assert!(
            matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EACCES)),
            "{e}"
        );

        // A second server replaces the first, which is told.
        let second = tokio::spawn(serve_hello(
            fuse.attach(&c, FuseLimits::SERVER).unwrap().unwrap(),
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("the replaced server was not told")
                .unwrap()
                > 0
        );

        // Releasing ends the session and its server.
        fuse.unmount(&c).await.unwrap();
        fuse.unmount(&c).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), second)
            .await
            .expect("the server outlived the mount")
            .unwrap();
        assert!(!point.exists());
        assert!(fuse.list_owned().await.unwrap().is_empty());
        assert!(!fuse.has_session(&c));

        // With no server, a reader blocks; releasing fails it, not hangs.
        let point = fuse.mount(&c).await.unwrap();
        let p = point.clone();
        let blocked = tokio::task::spawn_blocking(move || std::fs::read(p.join("hello")));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!blocked.is_finished());
        fuse.unmount(&c).await.unwrap();
        let res = tokio::time::timeout(Duration::from_secs(10), blocked)
            .await
            .expect("blocked reader was not released")
            .unwrap();
        assert!(res.is_err());

        // A mount tenantd doesn't hold (as after a restart) is replaced.
        fuse.mount(&c).await.unwrap();
        let fresh = HostFuse::new(d.path().join("fuse"));
        assert_eq!(fresh.list_owned().await.unwrap(), vec![c.clone()]);
        fresh.mount(&c).await.unwrap();
        assert!(fresh.has_session(&c));
        fresh.unmount(&c).await.unwrap();
        fuse.unmount(&c).await.unwrap();
    }
}
