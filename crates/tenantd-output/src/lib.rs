//! Process output on the host. The runtime writes each stream straight into
//! its file under `<tenant dir>/sandboxes/<sandbox>/processes/<id>/`, so the
//! tenant's project quota counts it and tenantd is never in the data path.
//!
//! The limit keeps the head: a watcher thread gets inotify `IN_MODIFY` for
//! every watched stream and punches out `[limit, size)` (limit rounded up to
//! the block size) with `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`. Disk
//! use stays at about the limit, while the writer's position and the file's
//! logical size are untouched: the size is how much was written. Between a
//! write and its punch usage can overshoot; the tenant quota is the backstop.

mod sys;

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tenantd_core::backend::OutputStore;
use tenantd_core::error::Context;
use tenantd_core::fsutil::remove_tree_one_fs;
use tenantd_core::model::{ProcessIo, Stream};
use tenantd_core::{Bytes, Error, ProcessId, Result, SandboxId};
use tracing::{debug, warn};

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::internal("output task", e))?
}

/// One stream file being kept to its head.
struct Limited {
    path: PathBuf,
    file: File,
    /// `limit` rounded up to the block size: everything from here is freed.
    keep: u64,
    /// Freed up to here (block-aligned), so repeated punches stay small.
    punched: u64,
}

impl Limited {
    fn open(path: &Path, limit: Bytes) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).open(path)?;
        let block = file.metadata()?.blksize().max(1);
        Ok(Self {
            path: path.to_path_buf(),
            file,
            keep: limit.div_ceil(block) * block,
            punched: 0,
        })
    }

    fn enforce(&mut self) -> io::Result<()> {
        let meta = self.file.metadata()?;
        let size = meta.len();
        let from = self.keep.max(self.punched);
        if size <= from {
            return Ok(());
        }
        sys::punch_hole(&self.file, from, size - from)?;
        let block = meta.blksize().max(1);
        // The block holding `size` was only zeroed past `size`; free it on
        // the next pass, once the file has grown past it.
        self.punched = self.keep.max(size / block * block);
        Ok(())
    }
}

#[derive(Default)]
struct Watches {
    by_wd: HashMap<i32, Limited>,
    by_path: HashMap<PathBuf, i32>,
}

struct Watcher {
    fd: OwnedFd,
    watches: Mutex<Watches>,
}

impl Watcher {
    fn start() -> io::Result<Arc<Self>> {
        let w = Arc::new(Self {
            fd: sys::inotify_init()?,
            watches: Mutex::default(),
        });
        let run = w.clone();
        std::thread::Builder::new()
            .name("tenantd-output".into())
            .spawn(move || run.run())?;
        Ok(w)
    }

    fn run(&self) {
        let mut buf = vec![0u8; 64 << 10];
        loop {
            let events = match sys::read_events(&self.fd, &mut buf) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!(error = %e, "output watcher stopped; limits are enforced only on exit and reconcile");
                    return;
                }
            };
            let mut w = self.watches.lock().unwrap();
            for ev in events {
                if ev.mask & sys::IN_Q_OVERFLOW != 0 {
                    w.by_wd.values_mut().for_each(enforce_logged);
                } else if ev.mask & sys::IN_IGNORED != 0 {
                    if let Some(l) = w.by_wd.remove(&ev.wd) {
                        w.by_path.remove(&l.path);
                    }
                } else if ev.mask & sys::IN_MODIFY != 0
                    && let Some(l) = w.by_wd.get_mut(&ev.wd)
                {
                    enforce_logged(l);
                }
            }
        }
    }

    fn watch(&self, path: &Path, limit: Bytes) -> io::Result<()> {
        let mut l = Limited::open(path, limit)?;
        let mut w = self.watches.lock().unwrap();
        // Same inode, same wd: re-adding replaces the entry.
        let wd = sys::add_watch(&self.fd, path, sys::IN_MODIFY)?;
        l.enforce()?;
        w.by_path.insert(path.to_path_buf(), wd);
        w.by_wd.insert(wd, l);
        Ok(())
    }

    fn unwatch(&self, path: &Path) {
        let mut w = self.watches.lock().unwrap();
        if let Some(wd) = w.by_path.remove(path) {
            w.by_wd.remove(&wd);
            sys::rm_watch(&self.fd, wd);
        }
    }
}

fn enforce_logged(l: &mut Limited) {
    if let Err(e) = l.enforce() {
        warn!(file = %l.path.display(), error = %e, "punching output past its limit failed");
    }
}

/// [`OutputStore`] on the host filesystem. The watcher thread starts on the
/// first watch.
#[derive(Default)]
pub struct FileOutput {
    watcher: Mutex<Option<Arc<Watcher>>>,
}

impl FileOutput {
    pub fn new() -> Self {
        Self::default()
    }

    fn watcher(&self) -> Result<Arc<Watcher>> {
        let mut w = self.watcher.lock().unwrap();
        if let Some(w) = &*w {
            return Ok(w.clone());
        }
        let started = Watcher::start().context("starting the output watcher")?;
        *w = Some(started.clone());
        Ok(started)
    }

    fn unwatch_io(&self, io: &ProcessIo) {
        if let Some(w) = &*self.watcher.lock().unwrap() {
            w.unwatch(&io.stdout);
            w.unwatch(&io.stderr);
        }
    }
}

fn size_of(p: &Path) -> io::Result<Bytes> {
    match fs::metadata(p) {
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

fn read_at(p: &Path, offset: Bytes, len: usize) -> io::Result<Vec<u8>> {
    let f = match File::open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut buf = vec![0u8; len];
    let mut n = 0;
    while n < len {
        match f.read_at(&mut buf[n..], offset + n as u64) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(n);
    Ok(buf)
}

#[async_trait]
impl OutputStore for FileOutput {
    fn io(&self, tenant_dir: &Path, s: &SandboxId, p: &ProcessId) -> ProcessIo {
        let dir = tenant_dir
            .join("sandboxes")
            .join(s.as_str())
            .join("processes")
            .join(p.as_str());
        ProcessIo {
            stdout: dir.join("stdout"),
            stderr: dir.join("stderr"),
            pid_file: dir.join("pid"),
            dir,
        }
    }

    async fn prepare(&self, io: &ProcessIo) -> Result<()> {
        self.unwatch_io(io);
        let io = io.clone();
        blocking(move || {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&io.dir)
                .context(format!("creating {}", io.dir.display()))?;
            for p in [&io.stdout, &io.stderr] {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(p)
                    .context(format!("creating {}", p.display()))?;
            }
            match fs::remove_file(&io.pid_file) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            }
        })
        .await
    }

    async fn watch(&self, io: &ProcessIo, limit: Bytes) -> Result<()> {
        let (w, io) = (self.watcher()?, io.clone());
        blocking(move || {
            for p in [&io.stdout, &io.stderr] {
                w.watch(p, limit)
                    .context(format!("watching {}", p.display()))?;
            }
            debug!(dir = %io.dir.display(), limit, "output limit armed");
            Ok(())
        })
        .await
    }

    async fn unwatch(&self, io: &ProcessIo) {
        self.unwatch_io(io);
    }

    async fn trim(&self, io: &ProcessIo, limit: Bytes) -> Result<()> {
        let io = io.clone();
        blocking(move || {
            for p in [&io.stdout, &io.stderr] {
                match Limited::open(p, limit) {
                    Ok(mut l) => l.enforce().context(format!("trimming {}", p.display()))?,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(Error::internal(format!("opening {}", p.display()), e)),
                }
            }
            Ok(())
        })
        .await
    }

    async fn sizes(&self, io: &ProcessIo) -> Result<(Bytes, Bytes)> {
        let io = io.clone();
        blocking(move || Ok((size_of(&io.stdout)?, size_of(&io.stderr)?))).await
    }

    async fn read(&self, io: &ProcessIo, s: Stream, offset: Bytes, len: usize) -> Result<Vec<u8>> {
        let p = io.stream(s).clone();
        blocking(move || read_at(&p, offset, len).context(format!("reading {}", p.display()))).await
    }

    async fn remove(&self, io: &ProcessIo) -> Result<()> {
        self.unwatch_io(io);
        let dir = io.dir.clone();
        blocking(move || remove_tree_one_fs(&dir).context(format!("removing {}", dir.display())))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, Instant};

    fn io_in(d: &Path) -> ProcessIo {
        FileOutput::new().io(
            &d.join("tenants/t"),
            &"box".parse().unwrap(),
            &"p".parse().unwrap(),
        )
    }

    /// Allocated bytes, from st_blocks (512-byte units).
    fn on_disk(p: &Path) -> u64 {
        fs::metadata(p).unwrap().blocks() * 512
    }

    fn punch_supported(d: &Path) -> bool {
        let p = d.join("probe");
        fs::write(&p, vec![1u8; 1 << 16]).unwrap();
        let ok = sys::punch_hole(&File::options().write(true).open(&p).unwrap(), 0, 4096).is_ok();
        fs::remove_file(p).unwrap();
        ok
    }

    #[tokio::test]
    async fn keeps_the_head_of_a_growing_file() {
        let d = tempfile::tempdir().unwrap();
        if !punch_supported(d.path()) {
            eprintln!("skipping: no punch-hole on this filesystem");
            return;
        }
        let out = FileOutput::new();
        let io = io_in(d.path());
        out.prepare(&io).await.unwrap();
        assert_eq!(out.sizes(&io).await.unwrap(), (0, 0));
        let limit = 10_000;
        out.watch(&io, limit).await.unwrap();

        // The writer appends past the limit, as a sandboxed process would.
        let mut w = OpenOptions::new().append(true).open(&io.stdout).unwrap();
        let chunk: Vec<u8> = (0..=255u8).cycle().take(64 << 10).collect();
        for _ in 0..32 {
            w.write_all(&chunk).unwrap();
        }
        w.flush().unwrap();
        let written = 32 * chunk.len() as u64;
        let deadline = Instant::now() + Duration::from_secs(5);
        while on_disk(&io.stdout) > 64 << 10 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            on_disk(&io.stdout) <= 64 << 10,
            "{} bytes still allocated",
            on_disk(&io.stdout)
        );
        assert_eq!(out.sizes(&io).await.unwrap(), (written, 0));
        // The head is intact; the writer keeps its position.
        let head = out
            .read(&io, Stream::Stdout, 0, limit as usize)
            .await
            .unwrap();
        assert_eq!(head, chunk[..limit as usize]);
        w.write_all(b"tail").unwrap();
        assert_eq!(out.sizes(&io).await.unwrap().0, written + 4);

        out.unwatch(&io).await;
        out.trim(&io, limit).await.unwrap();
        assert_eq!(out.read(&io, Stream::Stderr, 0, 10).await.unwrap(), b"");
        out.remove(&io).await.unwrap();
        out.remove(&io).await.unwrap();
        assert!(!io.dir.exists());
        assert_eq!(out.sizes(&io).await.unwrap(), (0, 0));
        assert!(
            out.read(&io, Stream::Stdout, 0, 1)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn prepare_replaces_leftovers() {
        let d = tempfile::tempdir().unwrap();
        let out = FileOutput::new();
        let io = io_in(d.path());
        out.prepare(&io).await.unwrap();
        fs::write(&io.stdout, b"old").unwrap();
        fs::write(&io.pid_file, b"42").unwrap();
        out.prepare(&io).await.unwrap();
        assert_eq!(out.sizes(&io).await.unwrap(), (0, 0));
        assert!(!io.pid_file.exists());
    }
}
