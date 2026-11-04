//! The kernel side of a container's FUSE mount: a [`fuser::Filesystem`]
//! that turns inode-based kernel requests into the path-based operations of
//! [`tenantd_core::fuse`], and answers what it can without asking the
//! server.
//!
//! tenantd keeps the inode table (inode <-> path, lookup counts, hard links
//! by the server's `object_id`) and, within the `ttl_ms` the server gave,
//! caches attributes, whole-directory listings and absent names. INIT,
//! FORGET, ACCESS, OPENDIR/READDIR/RELEASEDIR and the first read of a small
//! file (`inline_data`) never leave the host. Everything else is submitted
//! to the [`Router`] together with a closure that completes the kernel's
//! reply, so no kernel request blocks the session thread.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileHandle, FileType, FopenFlags, Generation, INodeNo,
    KernelConfig, LockOwner, Notifier, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
    WriteFlags,
};
use tenantd_core::fuse as sem;
use tenantd_core::fuse::{Caller, FuseError, FuseOp, FuseReply, FuseResult, InvalidateTarget};

use super::router::Router;

const ROOT: u64 = 1;
/// Entries a cache map may hold before expired ones are swept.
const SWEEP_AT: usize = 16384;

type FsResult<T> = Result<T, FuseError>;
type WriteDone = Box<dyn FnOnce(FsResult<(u32, Option<sem::FileAttr>)>) + Send>;

// ---- conversions -----------------------------------------------------------

fn errno(e: &FuseError) -> Errno {
    Errno::from_i32(if e.errno > 0 { e.errno } else { libc::EIO })
}

fn eio() -> FuseError {
    FuseError::new(libc::EIO)
}

fn kind(k: sem::FileKind) -> FileType {
    match k {
        sem::FileKind::File => FileType::RegularFile,
        sem::FileKind::Directory => FileType::Directory,
        sem::FileKind::Symlink => FileType::Symlink,
        sem::FileKind::Fifo => FileType::NamedPipe,
        sem::FileKind::Socket => FileType::Socket,
        sem::FileKind::CharDevice => FileType::CharDevice,
        sem::FileKind::BlockDevice => FileType::BlockDevice,
    }
}

fn to_time(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

fn from_time(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_nanos()).unwrap_or(i64::MAX),
    }
}

fn from_time_or_now(t: TimeOrNow) -> i64 {
    match t {
        TimeOrNow::SpecificTime(t) => from_time(t),
        TimeOrNow::Now => from_time(SystemTime::now()),
    }
}

fn attr_out(ino: u64, a: &sem::FileAttr) -> fuser::FileAttr {
    fuser::FileAttr {
        ino: INodeNo(ino),
        size: a.size,
        blocks: a.size.div_ceil(512),
        atime: to_time(a.atime_ns),
        mtime: to_time(a.mtime_ns),
        ctime: to_time(a.ctime_ns),
        crtime: to_time(a.ctime_ns),
        kind: kind(a.kind),
        perm: (a.mode & 0o7777) as u16,
        nlink: a.nlink,
        uid: a.uid,
        gid: a.gid,
        rdev: a.rdev,
        blksize: 4096,
        flags: 0,
    }
}

fn ttl(a: &sem::FileAttr) -> Duration {
    Duration::from_millis(u64::from(a.ttl_ms))
}

fn open_flags(o: &sem::OpenReply) -> FopenFlags {
    let mut f = FopenFlags::empty();
    if o.keep_cache {
        f |= FopenFlags::FOPEN_KEEP_CACHE;
    }
    if o.direct_io {
        f |= FopenFlags::FOPEN_DIRECT_IO;
    }
    f
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn under(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && (prefix == "/" || path.as_bytes()[prefix.len()] == b'/'))
}

/// A stable `d_ino` for directory listings; lookups assign the real ones.
fn dirent_ino(path: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in path.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x100000001b3);
    }
    h | (1 << 62)
}

// ---- tables ----------------------------------------------------------------

struct Node {
    /// The path requests use.
    path: String,
    /// Other paths of the same file (hard links).
    aliases: Vec<String>,
    nlookup: u64,
    object_id: Option<Vec<u8>>,
}

struct Cached<T> {
    value: T,
    expires: Instant,
}

impl<T> Cached<T> {
    fn fresh(&self) -> bool {
        Instant::now() < self.expires
    }
}

struct OpenFile {
    /// The file's start, from the server's open, until it is written.
    inline: Option<Vec<u8>>,
    size: u64,
}

struct DirSnapshot {
    entries: Vec<(u64, FileType, String)>,
}

struct Tables {
    next_ino: u64,
    next_dir_handle: u64,
    nodes: HashMap<u64, Node>,
    by_path: HashMap<String, u64>,
    by_object: HashMap<Vec<u8>, u64>,
    attrs: HashMap<u64, Cached<sem::FileAttr>>,
    listings: HashMap<String, Cached<Arc<Vec<sem::DirEntry>>>>,
    negatives: HashMap<String, Instant>,
    dirs: HashMap<u64, Arc<DirSnapshot>>,
    files: HashMap<(u64, u64), OpenFile>,
}

impl Tables {
    fn new() -> Self {
        let mut t = Tables {
            next_ino: ROOT + 1,
            next_dir_handle: 1,
            nodes: HashMap::new(),
            by_path: HashMap::new(),
            by_object: HashMap::new(),
            attrs: HashMap::new(),
            listings: HashMap::new(),
            negatives: HashMap::new(),
            dirs: HashMap::new(),
            files: HashMap::new(),
        };
        t.nodes.insert(
            ROOT,
            Node {
                path: "/".into(),
                aliases: Vec::new(),
                nlookup: 1,
                object_id: None,
            },
        );
        t.by_path.insert("/".into(), ROOT);
        t
    }

    fn path_of(&self, ino: u64) -> Option<String> {
        self.nodes.get(&ino).map(|n| n.path.clone())
    }

    /// Count one more kernel lookup of `path` and return its inode.
    fn register(&mut self, path: &str, a: &sem::FileAttr) -> u64 {
        self.negatives.remove(path);
        if let Some(oid) = &a.object_id
            && let Some(&ino) = self.by_object.get(oid)
        {
            self.alias(ino, path);
            self.nodes.get_mut(&ino).unwrap().nlookup += 1;
            return ino;
        }
        if let Some(&ino) = self.by_path.get(path) {
            let n = self.nodes.get_mut(&ino).unwrap();
            if n.object_id.is_none() || n.object_id == a.object_id {
                if n.object_id.is_none()
                    && let Some(oid) = &a.object_id
                {
                    n.object_id = Some(oid.clone());
                    self.by_object.insert(oid.clone(), ino);
                }
                n.nlookup += 1;
                return ino;
            }
            // Another file now stands at this path; the old node lives on
            // for the kernel's references until it is forgotten.
            self.unmap_path(ino, path);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(
            ino,
            Node {
                path: path.to_string(),
                aliases: Vec::new(),
                nlookup: 1,
                object_id: a.object_id.clone(),
            },
        );
        self.by_path.insert(path.to_string(), ino);
        if let Some(oid) = &a.object_id {
            self.by_object.insert(oid.clone(), ino);
        }
        ino
    }

    fn alias(&mut self, ino: u64, path: &str) {
        let n = self.nodes.get_mut(&ino).unwrap();
        if n.path != path && !n.aliases.iter().any(|p| p == path) {
            n.aliases.push(path.to_string());
        }
        self.by_path.insert(path.to_string(), ino);
    }

    /// `path` no longer names `ino`. A node left with no path keeps its last
    /// one, which its open files still use.
    fn unmap_path(&mut self, ino: u64, path: &str) {
        if self.by_path.get(path) == Some(&ino) {
            self.by_path.remove(path);
        }
        if let Some(n) = self.nodes.get_mut(&ino) {
            if n.path == path {
                if let Some(p) = n.aliases.pop() {
                    n.path = p;
                }
            } else {
                n.aliases.retain(|p| p != path);
            }
        }
    }

    fn forget(&mut self, ino: u64, count: u64) {
        if ino == ROOT {
            return;
        }
        let Some(n) = self.nodes.get_mut(&ino) else {
            return;
        };
        n.nlookup = n.nlookup.saturating_sub(count);
        if n.nlookup > 0 {
            return;
        }
        let n = self.nodes.remove(&ino).unwrap();
        for p in std::iter::once(&n.path).chain(&n.aliases) {
            if self.by_path.get(p) == Some(&ino) {
                self.by_path.remove(p);
            }
        }
        if let Some(oid) = &n.object_id
            && self.by_object.get(oid) == Some(&ino)
        {
            self.by_object.remove(oid);
        }
        self.attrs.remove(&ino);
    }

    /// `from` (and everything below it) is now at `to`.
    fn rename_paths(&mut self, from: &str, to: &str) {
        let dead: Vec<(String, u64)> = self
            .by_path
            .iter()
            .filter(|(k, _)| under(k, to))
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        for (k, ino) in dead {
            self.unmap_path(ino, &k);
        }
        let moved: Vec<(String, u64)> = self
            .by_path
            .iter()
            .filter(|(k, _)| under(k, from))
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        for (old, ino) in moved {
            let new = format!("{to}{}", &old[from.len()..]);
            self.by_path.remove(&old);
            self.by_path.insert(new.clone(), ino);
            if let Some(n) = self.nodes.get_mut(&ino) {
                if n.path == old {
                    n.path = new;
                } else if let Some(p) = n.aliases.iter_mut().find(|p| **p == old) {
                    *p = new;
                }
            }
            self.attrs.remove(&ino);
        }
        for p in [from, to] {
            self.listings.retain(|k, _| !under(k, p));
            self.negatives.retain(|k, _| !under(k, p));
            self.touch_parent(p);
        }
    }

    /// A name in `path`'s directory changed: its listing and the negative
    /// answer for the name itself are stale.
    fn touch_parent(&mut self, path: &str) {
        self.listings.remove(parent_of(path));
        self.negatives.remove(path);
    }

    fn cache_attr(&mut self, ino: u64, a: &sem::FileAttr) {
        if self.attrs.len() >= SWEEP_AT {
            self.attrs.retain(|_, c| c.fresh());
        }
        if a.ttl_ms == 0 {
            self.attrs.remove(&ino);
            return;
        }
        self.attrs.insert(
            ino,
            Cached {
                value: a.clone(),
                expires: Instant::now() + ttl(a),
            },
        );
    }

    fn fresh_attr(&self, ino: u64) -> Option<(sem::FileAttr, Duration)> {
        let c = self.attrs.get(&ino).filter(|c| c.fresh())?;
        let left = c.expires.saturating_duration_since(Instant::now());
        Some((c.value.clone(), left))
    }

    fn cache_listing(&mut self, dir: &str, entries: Arc<Vec<sem::DirEntry>>) {
        if self.listings.len() >= SWEEP_AT {
            self.listings.retain(|_, c| c.fresh());
        }
        // An empty listing says nothing about how long it holds.
        let Some(ttl_ms) = entries
            .iter()
            .map(|e| e.attr.ttl_ms)
            .min()
            .filter(|&t| t > 0)
        else {
            self.listings.remove(dir);
            return;
        };
        self.listings.insert(
            dir.to_string(),
            Cached {
                value: entries,
                expires: Instant::now() + Duration::from_millis(u64::from(ttl_ms)),
            },
        );
    }

    fn fresh_listing(&self, dir: &str) -> Option<Arc<Vec<sem::DirEntry>>> {
        self.listings
            .get(dir)
            .filter(|c| c.fresh())
            .map(|c| c.value.clone())
    }

    fn cache_negative(&mut self, path: &str, ttl_ms: u32) {
        if self.negatives.len() >= SWEEP_AT {
            let now = Instant::now();
            self.negatives.retain(|_, e| *e > now);
        }
        if ttl_ms > 0 {
            self.negatives.insert(
                path.to_string(),
                Instant::now() + Duration::from_millis(u64::from(ttl_ms)),
            );
        }
    }

    fn fresh_negative(&self, path: &str) -> bool {
        self.negatives
            .get(path)
            .is_some_and(|e| *e > Instant::now())
    }

    /// Forget what is cached for `path`. Returns what the kernel should be
    /// told to drop: inodes, and (parent inode, name) entries.
    fn invalidate_path(&mut self, path: &str, recursive: bool) -> (Vec<u64>, Vec<(u64, String)>) {
        let hit = |k: &str| if recursive { under(k, path) } else { k == path };
        let paths: Vec<(String, u64)> = self
            .by_path
            .iter()
            .filter(|(k, _)| hit(k))
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        let mut inos = Vec::new();
        let mut entries = Vec::new();
        for (p, ino) in paths {
            self.attrs.remove(&ino);
            inos.push(ino);
            if let Some(&parent) = self.by_path.get(parent_of(&p))
                && p != "/"
            {
                entries.push((parent, p.rsplit('/').next().unwrap_or_default().to_string()));
            }
        }
        self.listings.retain(|k, _| !hit(k));
        self.negatives.retain(|k, _| !hit(k));
        self.touch_parent(path);
        (inos, entries)
    }
}

// ---- the filesystem --------------------------------------------------------

struct State {
    router: Arc<Router>,
    t: Mutex<Tables>,
    notifier: Mutex<Option<Notifier>>,
}

#[derive(Clone)]
pub struct PathFs(Arc<State>);

impl PathFs {
    /// A filesystem submitting to `router`. Server invalidations reach it
    /// through the router's hook.
    pub fn new(router: Arc<Router>) -> Self {
        let st = Arc::new(State {
            router: router.clone(),
            t: Mutex::new(Tables::new()),
            notifier: Mutex::new(None),
        });
        let weak: Weak<State> = Arc::downgrade(&st);
        router.set_invalidate_hook(move |target| {
            if let Some(st) = weak.upgrade() {
                st.invalidate(target);
            }
        });
        PathFs(st)
    }

    /// How to tell the kernel to drop its caches.
    pub fn set_notifier(&self, n: Notifier) {
        *self.0.notifier.lock().unwrap() = Some(n);
    }
}

impl State {
    fn call(
        self: &Arc<Self>,
        req: &Request,
        op: FuseOp,
        done: impl FnOnce(FuseResult) + Send + 'static,
    ) {
        let caller = Caller {
            uid: req.uid(),
            gid: req.gid(),
            pid: req.pid(),
        };
        self.router.submit(caller, op, Box::new(done));
    }

    fn path_of(&self, ino: INodeNo) -> Result<String, Errno> {
        self.t
            .lock()
            .unwrap()
            .path_of(ino.0)
            .ok_or(Errno::from_i32(libc::ESTALE))
    }

    fn child(&self, parent: INodeNo, name: &OsStr) -> Result<String, Errno> {
        let dir = self.path_of(parent)?;
        let name = name.to_str().ok_or(Errno::EINVAL)?;
        Ok(join(&dir, name))
    }

    fn invalidate(&self, target: InvalidateTarget) {
        let (inos, entries) = {
            let mut t = self.t.lock().unwrap();
            match target {
                InvalidateTarget::Path { path, recursive } => t.invalidate_path(&path, recursive),
                InvalidateTarget::Object(oid) => {
                    let paths: Vec<String> = t
                        .by_object
                        .get(&oid)
                        .and_then(|i| t.nodes.get(i))
                        .map(|n| {
                            std::iter::once(n.path.clone())
                                .chain(n.aliases.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut all = (Vec::new(), Vec::new());
                    for p in paths {
                        let (i, e) = t.invalidate_path(&p, false);
                        all.0.extend(i);
                        all.1.extend(e);
                    }
                    all
                }
            }
        };
        if let Some(n) = &*self.notifier.lock().unwrap() {
            for (parent, name) in entries {
                let _ = n.inval_entry(INodeNo(parent), OsStr::new(&name));
            }
            for ino in inos {
                let _ = n.inval_inode(INodeNo(ino), 0, 0);
            }
        }
    }

    /// Register a looked-up path and reply with its entry.
    fn entry(&self, path: &str, a: &sem::FileAttr, reply: ReplyEntry) {
        let ino = {
            let mut t = self.t.lock().unwrap();
            let ino = t.register(path, a);
            t.cache_attr(ino, a);
            ino
        };
        reply.entry(&ttl(a), &attr_out(ino, a), Generation(0));
    }

    /// A name under `path`'s directory changed.
    fn touched(&self, path: &str) {
        self.t.lock().unwrap().touch_parent(path);
    }
}

#[allow(clippy::too_many_arguments)]
fn read_chunks(
    st: Arc<State>,
    caller: Caller,
    path: String,
    handle: u64,
    offset: u64,
    size: u32,
    mut acc: Vec<u8>,
    done: Box<dyn FnOnce(FsResult<Vec<u8>>) + Send>,
) {
    let limit = st.router.limits().max_read;
    let want = (size as usize - acc.len()).min(limit as usize) as u32;
    let op = FuseOp::Read {
        path: path.clone(),
        handle,
        offset: offset + acc.len() as u64,
        size: want,
    };
    let st2 = st.clone();
    st.router.submit(
        caller,
        op,
        Box::new(move |res| match res {
            Ok(FuseReply::Data(mut d)) => {
                d.truncate(want as usize);
                let short = (d.len() as u32) < want;
                acc.extend_from_slice(&d);
                if short || acc.len() >= size as usize {
                    done(Ok(acc));
                } else {
                    read_chunks(st2, caller, path, handle, offset, size, acc, done);
                }
            }
            Ok(_) => done(Err(eio())),
            Err(e) => done(Err(e)),
        }),
    );
}

#[allow(clippy::too_many_arguments)]
fn write_chunks(
    st: Arc<State>,
    caller: Caller,
    path: String,
    handle: u64,
    offset: u64,
    data: Arc<Vec<u8>>,
    pos: usize,
    last: Option<sem::FileAttr>,
    done: WriteDone,
) {
    let limit = st.router.limits().max_write as usize;
    let n = (data.len() - pos).min(limit);
    let op = FuseOp::Write {
        path: path.clone(),
        handle,
        offset: offset + pos as u64,
        data: data[pos..pos + n].to_vec(),
    };
    let st2 = st.clone();
    st.router.submit(
        caller,
        op,
        Box::new(move |res| match res {
            Ok(FuseReply::Written { written, attr }) => {
                let w = (written as usize).min(n);
                let pos = pos + w;
                let attr = attr.or(last);
                if w < n || pos == data.len() {
                    done(Ok((pos as u32, attr)));
                } else {
                    write_chunks(st2, caller, path, handle, offset, data, pos, attr, done);
                }
            }
            Ok(_) => done(Err(eio())),
            Err(e) => done(Err(e)),
        }),
    );
}

impl fuser::Filesystem for PathFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        let _ = config.set_max_write(sem::MAX_IO);
        Ok(())
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let st = &self.0;
        let path = match st.child(parent, name) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        // Answer from what is cached, if it is fresh.
        {
            let t = st.t.lock().unwrap();
            if t.fresh_negative(&path) {
                return reply.error(Errno::ENOENT);
            }
            if let Some(list) = t.fresh_listing(parent_of(&path)) {
                let found = list.iter().find(|e| Some(e.name.as_str()) == name.to_str());
                drop(t);
                return match found {
                    Some(e) => st.entry(&path, &e.attr, reply),
                    None => reply.error(Errno::ENOENT),
                };
            }
            if let Some(&ino) = t.by_path.get(&path)
                && let Some((a, _)) = t.fresh_attr(ino)
            {
                drop(t);
                return st.entry(&path, &a, reply);
            }
        }
        let st2 = st.clone();
        st.call(
            req,
            FuseOp::Stat { path: path.clone() },
            move |res| match res {
                Ok(FuseReply::Attr(a)) => st2.entry(&path, &a, reply),
                Ok(_) => reply.error(Errno::EIO),
                Err(e) => {
                    if e.errno == libc::ENOENT {
                        st2.t
                            .lock()
                            .unwrap()
                            .cache_negative(&path, e.negative_ttl_ms);
                    }
                    reply.error(errno(&e));
                }
            },
        );
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.0.t.lock().unwrap().forget(ino.0, nlookup);
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let st = &self.0;
        let path = match st.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        if let Some((a, left)) = st.t.lock().unwrap().fresh_attr(ino.0) {
            return reply.attr(&left, &attr_out(ino.0, &a));
        }
        let st2 = st.clone();
        st.call(req, FuseOp::Stat { path }, move |res| match res {
            Ok(FuseReply::Attr(a)) => {
                st2.t.lock().unwrap().cache_attr(ino.0, &a);
                reply.attr(&ttl(&a), &attr_out(ino.0, &a));
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let st = &self.0;
        let path = match st.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let set = sem::SetAttr {
            handle: fh.map(|h| h.0),
            mode,
            uid,
            gid,
            size,
            atime_ns: atime.map(from_time_or_now),
            mtime_ns: mtime.map(from_time_or_now),
        };
        {
            let mut t = st.t.lock().unwrap();
            t.attrs.remove(&ino.0);
            t.touch_parent(&path);
            if size.is_some() {
                t.files.retain(|(i, _), f| {
                    if *i == ino.0 {
                        f.inline = None;
                    }
                    true
                });
            }
        }
        let st2 = st.clone();
        st.call(req, FuseOp::SetAttr { path, set }, move |res| match res {
            Ok(FuseReply::Attr(a)) => {
                st2.t.lock().unwrap().cache_attr(ino.0, &a);
                reply.attr(&ttl(&a), &attr_out(ino.0, &a));
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    fn readlink(&self, req: &Request, ino: INodeNo, reply: ReplyData) {
        let path = match self.0.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        self.0
            .call(req, FuseOp::Readlink { path }, move |res| match res {
                Ok(FuseReply::Target(t)) => reply.data(t.as_bytes()),
                Ok(_) => reply.error(Errno::EIO),
                Err(e) => reply.error(errno(&e)),
            });
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let st = &self.0;
        let path = match st.child(parent, name) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        st.touched(&path);
        let (st2, p2) = (st.clone(), path.clone());
        let op = FuseOp::Mkdir {
            path,
            mode: mode & !umask,
        };
        st.call(req, op, move |res| match res {
            Ok(FuseReply::Attr(a)) => {
                st2.touched(&p2);
                st2.entry(&p2, &a, reply);
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let st = &self.0;
        let path = match st.child(parent, link_name) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let Some(target) = target.to_str() else {
            return reply.error(Errno::EINVAL);
        };
        st.touched(&path);
        let (st2, p2) = (st.clone(), path.clone());
        let op = FuseOp::Symlink {
            path,
            target: target.to_string(),
        };
        st.call(req, op, move |res| match res {
            Ok(FuseReply::Attr(a)) => {
                st2.touched(&p2);
                st2.entry(&p2, &a, reply);
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.remove(req, parent, name, reply, false);
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.remove(req, parent, name, reply, true);
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let st = &self.0;
        let (from, to) = match (st.child(parent, name), st.child(newparent, newname)) {
            (Ok(f), Ok(t)) => (f, t),
            (Err(e), _) | (_, Err(e)) => return reply.error(e),
        };
        let st2 = st.clone();
        let op = FuseOp::Rename {
            from: from.clone(),
            to: to.clone(),
            flags: flags.bits(),
        };
        st.call(req, op, move |res| match res {
            Ok(FuseReply::Ok) => {
                st2.t.lock().unwrap().rename_paths(&from, &to);
                reply.ok();
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let st = &self.0;
        let path = match st.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let st2 = st.clone();
        let op = FuseOp::Open {
            path,
            flags: flags.0 as u32,
        };
        st.call(req, op, move |res| match res {
            Ok(FuseReply::Open(o)) => {
                st2.opened(ino.0, &o);
                reply.opened(FileHandle(o.handle), open_flags(&o));
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let st = &self.0;
        let path = match st.child(parent, name) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        st.touched(&path);
        let (st2, p2) = (st.clone(), path.clone());
        let op = FuseOp::Create {
            path,
            mode: mode & !umask,
            flags: flags as u32,
        };
        st.call(req, op, move |res| match res {
            Ok(FuseReply::Open(o)) => {
                let Some(a) = o.attr.clone() else {
                    return reply.error(Errno::EIO);
                };
                st2.touched(&p2);
                let ino = {
                    let mut t = st2.t.lock().unwrap();
                    let ino = t.register(&p2, &a);
                    t.cache_attr(ino, &a);
                    ino
                };
                st2.opened(ino, &o);
                reply.created(
                    &ttl(&a),
                    &attr_out(ino, &a),
                    Generation(0),
                    FileHandle(o.handle),
                    open_flags(&o),
                );
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let st = &self.0;
        let path = match st.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        // The start of a small file came with its open.
        if let Some(f) = st.t.lock().unwrap().files.get(&(ino.0, fh.0))
            && let Some(data) = &f.inline
        {
            let end = offset.saturating_add(u64::from(size));
            let complete = data.len() as u64 >= f.size;
            if end <= data.len() as u64 || complete {
                let from = (offset as usize).min(data.len());
                let to = (end as usize).min(data.len());
                return reply.data(&data[from..to]);
            }
        }
        let caller = Caller {
            uid: req.uid(),
            gid: req.gid(),
            pid: req.pid(),
        };
        read_chunks(
            st.clone(),
            caller,
            path,
            fh.0,
            offset,
            size,
            Vec::new(),
            Box::new(move |res| match res {
                Ok(d) => reply.data(&d),
                Err(e) => reply.error(errno(&e)),
            }),
        );
    }

    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let st = &self.0;
        let path = match st.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        if data.is_empty() {
            return reply.written(0);
        }
        {
            let mut t = st.t.lock().unwrap();
            t.attrs.remove(&ino.0);
            t.touch_parent(&path);
            if let Some(f) = t.files.get_mut(&(ino.0, fh.0)) {
                f.inline = None;
            }
        }
        let caller = Caller {
            uid: req.uid(),
            gid: req.gid(),
            pid: req.pid(),
        };
        let st2 = st.clone();
        write_chunks(
            st.clone(),
            caller,
            path,
            fh.0,
            offset,
            Arc::new(data.to_vec()),
            0,
            None,
            Box::new(move |res| match res {
                Ok((written, attr)) => {
                    if let Some(a) = attr {
                        st2.t.lock().unwrap().cache_attr(ino.0, &a);
                    }
                    reply.written(written);
                }
                Err(e) => reply.error(errno(&e)),
            }),
        );
    }

    fn flush(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let path = match self.0.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        self.0
            .call(req, FuseOp::Flush { path, handle: fh.0 }, empty(reply));
    }

    fn release(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let st = &self.0;
        let path = {
            let mut t = st.t.lock().unwrap();
            t.files.remove(&(ino.0, fh.0));
            t.path_of(ino.0)
        };
        let Some(path) = path else {
            return reply.ok();
        };
        st.call(req, FuseOp::Release { path, handle: fh.0 }, empty(reply));
    }

    fn fsync(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let path = match self.0.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let op = FuseOp::Fsync {
            path,
            handle: fh.0,
            datasync,
        };
        self.0.call(req, op, empty(reply));
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let st = &self.0;
        let path = match st.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        // Bind first: in an `if let` the guard would live through the body,
        // and opened_dir takes the same lock (a self-deadlock on the second
        // opendir of a directory, which hung every later request).
        let cached = st.t.lock().unwrap().fresh_listing(&path);
        if let Some(list) = cached {
            return st.opened_dir(ino.0, &path, &list, reply);
        }
        let st2 = st.clone();
        st.call(
            req,
            FuseOp::ReadDir { path: path.clone() },
            move |res| match res {
                Ok(FuseReply::Dir(entries)) => {
                    let list = Arc::new(entries);
                    st2.t.lock().unwrap().cache_listing(&path, list.clone());
                    st2.opened_dir(ino.0, &path, &list, reply);
                }
                Ok(_) => reply.error(Errno::EIO),
                Err(e) => reply.error(errno(&e)),
            },
        );
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let snap = self.0.t.lock().unwrap().dirs.get(&fh.0).cloned();
        let Some(snap) = snap else {
            return reply.error(Errno::EBADF);
        };
        for (i, (ino, kind, name)) in snap.entries.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*ino), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.0.t.lock().unwrap().dirs.remove(&fh.0);
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _ds: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn statfs(&self, req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        self.0.call(req, FuseOp::StatFs, move |res| match res {
            Ok(FuseReply::StatFs(s)) => reply.statfs(
                s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.bsize, s.namelen, s.bsize,
            ),
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }

    // Answered here, quietly: not part of the protocol.
    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: fuser::ReplyXattr,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(Errno::ENOSYS);
    }

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::ENOSYS);
    }
}

impl PathFs {
    fn remove(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty, dir: bool) {
        let st = &self.0;
        let path = match st.child(parent, name) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let (st2, p2) = (st.clone(), path.clone());
        let op = if dir {
            FuseOp::Rmdir { path }
        } else {
            FuseOp::Unlink { path }
        };
        st.call(req, op, move |res| match res {
            Ok(FuseReply::Ok) => {
                let mut t = st2.t.lock().unwrap();
                if let Some(&ino) = t.by_path.get(&p2) {
                    t.attrs.remove(&ino);
                    t.unmap_path(ino, &p2);
                }
                t.listings.retain(|k, _| !under(k, &p2));
                t.touch_parent(&p2);
                drop(t);
                reply.ok();
            }
            Ok(_) => reply.error(Errno::EIO),
            Err(e) => reply.error(errno(&e)),
        });
    }
}

impl State {
    /// Remember what the server said about a file it opened.
    fn opened(&self, ino: u64, o: &sem::OpenReply) {
        let mut t = self.t.lock().unwrap();
        let size = o.attr.as_ref().map_or(u64::MAX, |a| a.size);
        if let Some(a) = &o.attr {
            t.cache_attr(ino, a);
        }
        t.files.insert(
            (ino, o.handle),
            OpenFile {
                inline: o.inline_data.clone(),
                size,
            },
        );
    }

    fn opened_dir(&self, ino: u64, path: &str, list: &[sem::DirEntry], reply: ReplyOpen) {
        let mut entries = Vec::with_capacity(list.len() + 2);
        let up = self
            .t
            .lock()
            .unwrap()
            .by_path
            .get(parent_of(path))
            .copied()
            .unwrap_or(ino);
        entries.push((ino, FileType::Directory, ".".to_string()));
        entries.push((up, FileType::Directory, "..".to_string()));
        for e in list {
            entries.push((
                dirent_ino(&join(path, &e.name)),
                kind(e.attr.kind),
                e.name.clone(),
            ));
        }
        let mut t = self.t.lock().unwrap();
        let dh = t.next_dir_handle;
        t.next_dir_handle += 1;
        t.dirs.insert(dh, Arc::new(DirSnapshot { entries }));
        drop(t);
        reply.opened(FileHandle(dh), FopenFlags::empty());
    }
}

/// Complete a reply that carries no data.
fn empty(reply: ReplyEmpty) -> impl FnOnce(FuseResult) + Send + 'static {
    move |res| match res {
        Ok(FuseReply::Ok) => reply.ok(),
        Ok(_) => reply.error(Errno::EIO),
        Err(e) => reply.error(errno(&e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(oid: Option<&str>) -> sem::FileAttr {
        sem::FileAttr {
            kind: sem::FileKind::File,
            mode: 0o644,
            size: 3,
            uid: 0,
            gid: 0,
            nlink: 1,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            rdev: 0,
            ttl_ms: 1000,
            object_id: oid.map(|s| s.as_bytes().to_vec()),
        }
    }

    #[test]
    fn paths() {
        assert_eq!(parent_of("/a"), "/");
        assert_eq!(parent_of("/a/b"), "/a");
        assert_eq!(join("/", "a"), "/a");
        assert_eq!(join("/a", "b"), "/a/b");
        assert!(under("/a/b", "/a") && under("/a", "/a") && under("/a", "/"));
        assert!(!under("/ab", "/a"));
    }

    #[test]
    fn lookups_share_inodes_and_forget_ends_them() {
        let mut t = Tables::new();
        let a = t.register("/f", &attr(None));
        assert_eq!(t.register("/f", &attr(None)), a, "same path, same inode");
        t.forget(a, 1);
        assert!(t.path_of(a).is_some(), "one lookup is still counted");
        t.forget(a, 1);
        assert!(t.path_of(a).is_none());
        assert_ne!(t.register("/f", &attr(None)), a, "inodes are not reused");
    }

    #[test]
    fn hard_links_share_an_inode_by_object_id() {
        let mut t = Tables::new();
        let a = t.register("/a", &attr(Some("x")));
        let b = t.register("/b", &attr(Some("x")));
        assert_eq!(a, b);
        // Removing the primary path moves the file to its other name.
        t.unmap_path(a, "/a");
        assert_eq!(t.path_of(a).as_deref(), Some("/b"));
        // A different file at a path takes a new inode.
        let c = t.register("/b", &attr(Some("y")));
        assert_ne!(c, a);
    }

    #[test]
    fn rename_moves_everything_below() {
        let mut t = Tables::new();
        let d = t.register("/d", &attr(None));
        let f = t.register("/d/f", &attr(None));
        let old = t.register("/e", &attr(None));
        t.rename_paths("/d", "/e");
        assert_eq!(t.path_of(d).as_deref(), Some("/e"));
        assert_eq!(t.path_of(f).as_deref(), Some("/e/f"));
        assert_eq!(t.by_path.get("/e"), Some(&d), "the old /e lost its name");
        assert_eq!(t.by_path.get("/d"), None);
        assert_eq!(
            t.path_of(old).as_deref(),
            Some("/e"),
            "it keeps a stale path"
        );
    }

    #[test]
    fn caches_expire_and_invalidate() {
        let mut t = Tables::new();
        let ino = t.register("/f", &attr(None));
        let mut a = attr(None);
        t.cache_attr(ino, &a);
        assert!(t.fresh_attr(ino).is_some());
        a.ttl_ms = 0;
        t.cache_attr(ino, &a);
        assert!(t.fresh_attr(ino).is_none(), "ttl 0 is not cached");

        t.cache_negative("/gone", 1000);
        assert!(t.fresh_negative("/gone"));
        t.cache_listing(
            "/",
            Arc::new(vec![sem::DirEntry {
                name: "f".into(),
                attr: attr(None),
            }]),
        );
        assert!(t.fresh_listing("/").is_some());
        t.cache_listing("/empty", Arc::new(vec![]));
        assert!(t.fresh_listing("/empty").is_none(), "empty has no ttl");

        let (inos, entries) = t.invalidate_path("/f", false);
        assert_eq!(inos, vec![ino]);
        assert_eq!(entries, vec![(ROOT, "f".to_string())]);
        assert!(
            t.fresh_listing("/").is_none(),
            "the parent listing goes too"
        );
        t.cache_negative("/gone", 1000);
        t.invalidate_path("/gone", false);
        assert!(!t.fresh_negative("/gone"));
    }
}
