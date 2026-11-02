//! Containers' FUSE connections, mounted on the host.
//!
//! gVisor's own FUSE lives in its Sentry, out of reach of a server outside
//! the sandbox. So tenantd mounts a host FUSE filesystem per container at
//! `<fuse dir>/<tenant>.<sandbox>.<container>` and the container
//! bind-mounts it like a volume; runsc's gofer serves it from the host.
//! The `/dev/fuse` fd behind the mount goes to the caller, who runs the
//! server. tenantd keeps a duplicate, so the connection survives the
//! server's restarts, and drops it when the container ends.
//!
//! The mount is `allow_other` (runsc's gofer reaches it, not tenantd) and
//! without `default_permissions`: the server decides every access. Nothing
//! here stats the mount: with no server answering, that would hang.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tenantd_core::backend::FuseBackend;
use tenantd_core::error::Context;
use tenantd_core::{ContainerKey, Error, Result};
use tracing::{info, warn};

use crate::blocking;
use crate::mount::{self, mount_entries_under};

const FSTYPE: &str = "fuse.tenantd";

pub struct HostFuse {
    dir: PathBuf,
    conns: Arc<Mutex<HashMap<ContainerKey, OwnedFd>>>,
}

impl HostFuse {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            conns: Arc::default(),
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
        "fd={},rootmode=40000,user_id={uid},group_id={gid},allow_other",
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

#[async_trait]
impl FuseBackend for HostFuse {
    async fn mount(&self, c: &ContainerKey) -> Result<PathBuf> {
        let (dir, point, conns, key) = (
            self.dir.clone(),
            self.point(c),
            self.conns.clone(),
            c.clone(),
        );
        blocking(move || {
            let held = conns.lock().unwrap().contains_key(&key);
            if held && mount::is_mountpoint(&point)? {
                return Ok(point);
            }
            // Whatever is there is no connection tenantd can hand out.
            conns.lock().unwrap().remove(&key);
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
            let fd =
                mount_fresh(&point).context(format!("mounting FUSE on {}", point.display()))?;
            conns.lock().unwrap().insert(key.clone(), fd);
            info!(container = %key, point = %point.display(), "FUSE connection mounted");
            Ok(point)
        })
        .await
    }

    fn connection(&self, c: &ContainerKey) -> Result<Option<OwnedFd>> {
        match self.conns.lock().unwrap().get(c) {
            Some(fd) => Ok(Some(fd.try_clone().context("duplicating the FUSE fd")?)),
            None => Ok(None),
        }
    }

    async fn unmount(&self, c: &ContainerKey) -> Result<()> {
        let (point, conns, key) = (self.point(c), self.conns.clone(), c.clone());
        blocking(move || {
            release(&point).context(format!("releasing {}", point.display()))?;
            if conns.lock().unwrap().remove(&key).is_some() {
                info!(container = %key, "FUSE connection released");
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

/// A minimal FUSE server for tests: one read-only file, `hello`.
#[cfg(test)]
pub(crate) mod hello {
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;

    pub const CONTENT: &[u8] = b"hello from fuse\n";

    fn attr(ino: u64) -> Vec<u8> {
        let (mode, size, nlink) = if ino == 1 {
            (0o040755u32, 0u64, 2u32)
        } else {
            (0o100444, CONTENT.len() as u64, 1)
        };
        let mut a = Vec::with_capacity(88);
        for v in [ino, size, 1, 0, 0, 0] {
            a.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0u32, 0, 0, mode, nlink, 0, 0, 0, 4096, 0] {
            a.extend_from_slice(&v.to_le_bytes());
        }
        a
    }

    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }

    fn u64_at(b: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
    }

    /// Serve until the connection ends. Returns how many requests came.
    pub fn serve(fd: OwnedFd) -> usize {
        let mut dev = std::fs::File::from(fd);
        let mut buf = vec![0u8; 1 << 20];
        let mut served = 0;
        loop {
            let n = match dev.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(_) => return served, // ENODEV: aborted or unmounted
            };
            served += 1;
            let req = &buf[..n];
            let (op, unique, node) = (u32_at(req, 4), u64_at(req, 8), u64_at(req, 16));
            let body = &req[40..];
            let reply: Option<std::result::Result<Vec<u8>, i32>> = match op {
                26 => {
                    // INIT
                    let mut out = Vec::new();
                    for v in [7u32, 31, u32_at(body, 8), 0] {
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                    out.extend_from_slice(&16u16.to_le_bytes());
                    out.extend_from_slice(&12u16.to_le_bytes());
                    out.extend_from_slice(&(128u32 << 10).to_le_bytes());
                    out.extend_from_slice(&1u32.to_le_bytes());
                    out.resize(64, 0);
                    Some(Ok(out))
                }
                3 => {
                    // GETATTR
                    let mut out = vec![0u8; 16];
                    out.extend(attr(node));
                    Some(Ok(out))
                }
                1 => {
                    // LOOKUP
                    let name = body.split(|&b| b == 0).next().unwrap_or_default();
                    if node == 1 && name == b"hello" {
                        let mut out = Vec::new();
                        for v in [2u64, 0, 0, 0] {
                            out.extend_from_slice(&v.to_le_bytes());
                        }
                        out.extend_from_slice(&[0u8; 8]);
                        out.extend(attr(2));
                        Some(Ok(out))
                    } else {
                        Some(Err(libc::ENOENT))
                    }
                }
                14 | 27 => Some(Ok(vec![0u8; 16])), // OPEN, OPENDIR
                15 => {
                    // READ
                    let (off, size) = (u64_at(body, 8) as usize, u32_at(body, 16) as usize);
                    let start = off.min(CONTENT.len());
                    Some(Ok(
                        CONTENT[start..(start + size).min(CONTENT.len())].to_vec()
                    ))
                }
                28 => {
                    // READDIR: just `hello`, once
                    let mut out = Vec::new();
                    if u64_at(body, 8) == 0 {
                        out.extend_from_slice(&2u64.to_le_bytes());
                        out.extend_from_slice(&1u64.to_le_bytes());
                        out.extend_from_slice(&5u32.to_le_bytes());
                        out.extend_from_slice(&8u32.to_le_bytes());
                        out.extend_from_slice(b"hello\0\0\0");
                    }
                    Some(Ok(out))
                }
                18 | 25 | 29 => Some(Ok(Vec::new())), // RELEASE, FLUSH, RELEASEDIR
                2 | 36 | 42 => None,                  // FORGET, INTERRUPT, BATCH_FORGET
                _ => Some(Err(libc::ENOSYS)),
            };
            let Some(reply) = reply else { continue };
            let (err, data) = match reply {
                Ok(d) => (0i32, d),
                Err(e) => (-e, Vec::new()),
            };
            let mut out = Vec::with_capacity(16 + data.len());
            out.extend_from_slice(&((16 + data.len()) as u32).to_le_bytes());
            out.extend_from_slice(&err.to_le_bytes());
            out.extend_from_slice(&unique.to_le_bytes());
            out.extend(data);
            if dev.write_all(&out).is_err() {
                return served;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn connection_ids() {
        assert_eq!(connection_id((0, 53)), 53);
        assert_eq!(connection_id((1, 2)), (1 << 20) | 2);
    }

    /// Needs to mount FUSE. Run unprivileged inside a user+mount namespace:
    /// `unshare -rm cargo test -p tenantd-layer -- --ignored`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn host_fuse_mounts_hands_out_and_releases() {
        let d = tempfile::tempdir().unwrap();
        let fuse = HostFuse::new(d.path().join("fuse"));
        let c: ContainerKey = "t.s.c".parse().unwrap();
        assert!(fuse.connection(&c).unwrap().is_none());
        let point = fuse.mount(&c).await.unwrap();
        assert_eq!(point, d.path().join("fuse/t.s.c"));
        assert_eq!(fuse.mount(&c).await.unwrap(), point, "kept while held");
        assert_eq!(fuse.list_owned().await.unwrap(), vec![c.clone()]);

        // The server gets a duplicate; reads through the mount reach it.
        let server = std::thread::spawn({
            let fd = fuse.connection(&c).unwrap().unwrap();
            move || hello::serve(fd)
        });
        let p = point.clone();
        let read = tokio::task::spawn_blocking(move || std::fs::read(p.join("hello")));
        let got = tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .expect("read through FUSE hung")
            .unwrap()
            .unwrap();
        assert_eq!(got, hello::CONTENT);
        let names: Vec<_> = std::fs::read_dir(&point)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec!["hello"]);

        // Releasing ends the server's connection too.
        fuse.unmount(&c).await.unwrap();
        fuse.unmount(&c).await.unwrap();
        assert!(server.join().unwrap() > 0);
        assert!(!point.exists());
        assert!(fuse.list_owned().await.unwrap().is_empty());
        assert!(fuse.connection(&c).unwrap().is_none());

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
        assert!(fresh.connection(&c).unwrap().is_some());
        fresh.unmount(&c).await.unwrap();
        fuse.unmount(&c).await.unwrap();
    }
}
