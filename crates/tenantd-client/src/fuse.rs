//! Serving a container's FUSE slot.
//!
//! tenantd mounts the filesystem and speaks the kernel protocol; the
//! caller's server answers path-based operations over
//! `Containers.ServeFuse`. A server implements [`Filesystem`] (every
//! operation it leaves out fails with `ENOSYS`) and hands it to [`attach`]:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use tenantd_client::fuse::{self, Context, Error, Filesystem, Result};
//! # use tenantd_client::pb;
//! struct Empty;
//! impl Filesystem for Empty {
//!     async fn stat(&self, _cx: &Context, req: pb::Stat) -> Result<pb::FileAttr> {
//!         if req.path == "/" {
//!             Ok(pb::FileAttr {
//!                 kind: pb::FileKind::Directory as i32,
//!                 mode: 0o755,
//!                 nlink: 2,
//!                 ttl_ms: 1000,
//!                 ..Default::default()
//!             })
//!         } else {
//!             Err(Error::not_found().cached_for_ms(1000))
//!         }
//!     }
//! }
//!
//! # async fn f() -> Result<(), Box<dyn std::error::Error>> {
//! let ch = tenantd_client::connect("/run/tenantd/api.sock").await?;
//! let container = pb::ContainerRef { tenant: "acme".into(), sandbox: "box1".into(), id: "s1".into() };
//! let session = fuse::attach(ch.clone(), container.clone(), Arc::new(Empty), Default::default()).await?;
//! // The server is attached: the container can start.
//! tenantd_client::ContainersClient::new(ch).start_container(container).await?;
//! session.run().await?; // until the container ends or another server replaces this one
//! # Ok(()) }
//! ```
//!
//! Paths are absolute within the exported tree. Attributes carry a `ttl_ms`
//! that lets tenantd and the kernel cache them; `0` asks for every access.
//! A server that finds out its data changed behind tenantd's back tells it
//! with [`Invalidator`].

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tonic::transport::Channel;

use crate::pb::{self, fuse_request::Op, fuse_response::Result as Res};

/// The protocol version [`attach`] speaks.
pub const VERSION: u32 = 1;

/// Linux errno values a server commonly answers with.
pub mod errno {
    pub const EPERM: i32 = libc::EPERM;
    pub const ENOENT: i32 = libc::ENOENT;
    pub const EIO: i32 = libc::EIO;
    pub const EACCES: i32 = libc::EACCES;
    pub const EEXIST: i32 = libc::EEXIST;
    pub const ENOTDIR: i32 = libc::ENOTDIR;
    pub const EISDIR: i32 = libc::EISDIR;
    pub const EINVAL: i32 = libc::EINVAL;
    pub const ENOSPC: i32 = libc::ENOSPC;
    pub const EROFS: i32 = libc::EROFS;
    pub const ENOTEMPTY: i32 = libc::ENOTEMPTY;
    pub const ENOSYS: i32 = libc::ENOSYS;
}

/// A failed operation: a Linux errno, for the container to see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub errno: i32,
    /// For tenantd's logs; the container never sees it.
    pub detail: String,
    /// With `ENOENT`: how long the absence may be cached.
    pub negative_ttl_ms: u32,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(errno: i32) -> Self {
        Self {
            errno,
            detail: String::new(),
            negative_ttl_ms: 0,
        }
    }

    pub fn not_found() -> Self {
        Self::new(errno::ENOENT)
    }

    pub fn unsupported() -> Self {
        Self::new(errno::ENOSYS)
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Let the absence be cached for `ms` milliseconds.
    pub fn cached_for_ms(mut self, ms: u32) -> Self {
        self.negative_ttl_ms = ms;
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::io::Error::from_raw_os_error(self.errno))?;
        if !self.detail.is_empty() {
            write!(f, " ({})", self.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        let errno = e.raw_os_error().unwrap_or(match e.kind() {
            std::io::ErrorKind::NotFound => errno::ENOENT,
            std::io::ErrorKind::PermissionDenied => errno::EACCES,
            std::io::ErrorKind::AlreadyExists => errno::EEXIST,
            std::io::ErrorKind::InvalidInput => errno::EINVAL,
            _ => errno::EIO,
        });
        Self::new(errno).detail(e.to_string())
    }
}

/// Whose access a request is, as the kernel reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

/// A filesystem to serve. Operations run concurrently, each on its own
/// task, so a server must be safe to call from many at once.
#[allow(unused_variables)]
pub trait Filesystem: Send + Sync + 'static {
    fn stat(
        &self,
        cx: &Context,
        req: pb::Stat,
    ) -> impl Future<Output = Result<pb::FileAttr>> + Send {
        async { Err(Error::unsupported()) }
    }
    /// The whole directory with each entry's attributes, without `.` and `..`.
    fn read_dir(
        &self,
        cx: &Context,
        req: pb::ReadDir,
    ) -> impl Future<Output = Result<Vec<pb::DirEntry>>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn readlink(
        &self,
        cx: &Context,
        req: pb::Readlink,
    ) -> impl Future<Output = Result<String>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn open(
        &self,
        cx: &Context,
        req: pb::Open,
    ) -> impl Future<Output = Result<pb::OpenReply>> + Send {
        async { Err(Error::unsupported()) }
    }
    /// A short read ends the file.
    fn read(&self, cx: &Context, req: pb::Read) -> impl Future<Output = Result<Vec<u8>>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn write(
        &self,
        cx: &Context,
        req: pb::Write,
    ) -> impl Future<Output = Result<pb::WriteReply>> + Send {
        async { Err(Error::unsupported()) }
    }
    /// Every close of a descriptor. Succeeds by default.
    fn flush(&self, cx: &Context, req: pb::Flush) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    /// The last close of a handle. Succeeds by default.
    fn release(&self, cx: &Context, req: pb::Release) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
    fn fsync(&self, cx: &Context, req: pb::Fsync) -> impl Future<Output = Result<()>> + Send {
        async { Err(Error::unsupported()) }
    }
    /// Create and open; the reply carries the new file's attributes.
    fn create(
        &self,
        cx: &Context,
        req: pb::Create,
    ) -> impl Future<Output = Result<pb::OpenReply>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn mkdir(
        &self,
        cx: &Context,
        req: pb::Mkdir,
    ) -> impl Future<Output = Result<pb::FileAttr>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn unlink(&self, cx: &Context, req: pb::Unlink) -> impl Future<Output = Result<()>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn rmdir(&self, cx: &Context, req: pb::Rmdir) -> impl Future<Output = Result<()>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn rename(&self, cx: &Context, req: pb::Rename) -> impl Future<Output = Result<()>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn symlink(
        &self,
        cx: &Context,
        req: pb::Symlink,
    ) -> impl Future<Output = Result<pb::FileAttr>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn set_attr(
        &self,
        cx: &Context,
        req: pb::SetAttr,
    ) -> impl Future<Output = Result<pb::FileAttr>> + Send {
        async { Err(Error::unsupported()) }
    }
    fn stat_fs(
        &self,
        cx: &Context,
        req: pb::StatFs,
    ) -> impl Future<Output = Result<pb::StatFsReply>> + Send {
        async { Err(Error::unsupported()) }
    }
}

async fn dispatch<F: Filesystem>(fs: &F, cx: &Context, op: Op) -> Result<Res> {
    Ok(match op {
        Op::Stat(r) => Res::Attr(fs.stat(cx, r).await?),
        Op::ReadDir(r) => Res::Dir(pb::DirListing {
            entries: fs.read_dir(cx, r).await?,
        }),
        Op::Readlink(r) => Res::Target(fs.readlink(cx, r).await?),
        Op::Open(r) => Res::Open(fs.open(cx, r).await?),
        Op::Read(r) => Res::Data(fs.read(cx, r).await?),
        Op::Write(r) => Res::Write(fs.write(cx, r).await?),
        Op::Flush(r) => ok(fs.flush(cx, r).await?),
        Op::Release(r) => ok(fs.release(cx, r).await?),
        Op::Fsync(r) => ok(fs.fsync(cx, r).await?),
        Op::Create(r) => Res::Open(fs.create(cx, r).await?),
        Op::Mkdir(r) => Res::Attr(fs.mkdir(cx, r).await?),
        Op::Unlink(r) => ok(fs.unlink(cx, r).await?),
        Op::Rmdir(r) => ok(fs.rmdir(cx, r).await?),
        Op::Rename(r) => ok(fs.rename(cx, r).await?),
        Op::Symlink(r) => Res::Attr(fs.symlink(cx, r).await?),
        Op::SetAttr(r) => Res::Attr(fs.set_attr(cx, r).await?),
        Op::StatFs(r) => Res::Statfs(fs.stat_fs(cx, r).await?),
    })
}

fn ok(_: ()) -> Res {
    Res::Ok(pb::FuseOk {})
}

async fn answer<F: Filesystem>(fs: &F, req: pb::FuseRequest) -> pb::FuseResponse {
    let cx = Context {
        uid: req.uid,
        gid: req.gid,
        pid: req.pid,
    };
    let res = match req.op {
        Some(op) => dispatch(fs, &cx, op).await,
        None => Err(Error::unsupported().detail("request without an operation")),
    };
    match res {
        Ok(result) => pb::FuseResponse {
            id: req.id,
            result: Some(result),
            ..Default::default()
        },
        Err(e) => pb::FuseResponse {
            id: req.id,
            errno: if e.errno > 0 { e.errno } else { errno::EIO },
            detail: e.detail,
            negative_ttl_ms: e.negative_ttl_ms,
            ..Default::default()
        },
    }
}

/// Tell tenantd that what it cached no longer holds.
#[derive(Clone)]
pub struct Invalidator {
    out: mpsc::Sender<pb::FuseServerMessage>,
}

impl Invalidator {
    async fn send(&self, target: pb::invalidate::Target, recursive: bool) -> bool {
        let msg = pb::FuseServerMessage {
            msg: Some(pb::fuse_server_message::Msg::Invalidate(pb::Invalidate {
                target: Some(target),
                recursive,
            })),
        };
        self.out.send(msg).await.is_ok()
    }

    /// Drop the attributes, listing and absence cached for `path`, and with
    /// `recursive` everything below it. `false` when the session is over.
    pub async fn path(&self, path: impl Into<String>, recursive: bool) -> bool {
        self.send(pb::invalidate::Target::Path(path.into()), recursive)
            .await
    }

    /// Drop what is cached for every path of the file with this `object_id`.
    pub async fn object(&self, object_id: Vec<u8>) -> bool {
        self.send(pb::invalidate::Target::ObjectId(object_id), false)
            .await
    }
}

/// An attached server. [`Session::run`] serves until the stream ends.
pub struct Session<F> {
    fs: Arc<F>,
    events: tonic::Streaming<pb::FuseServerEvent>,
    out: mpsc::Sender<pb::FuseServerMessage>,
    /// Counts attaches to this container's session; the first is 1.
    pub generation: u64,
    /// What tenantd and this server agreed on.
    pub limits: pb::FuseLimits,
}

/// Attach `fs` as the server of `container`'s FUSE slot, replacing any
/// server attached before. `limits` are what this server can take; zeroes
/// accept tenantd's. Once this returns, a `created` container can start.
pub async fn attach<F: Filesystem>(
    channel: Channel,
    container: pb::ContainerRef,
    fs: Arc<F>,
    limits: pb::FuseLimits,
) -> Result<Session<F>, Status> {
    let (out, rx) = mpsc::channel(64);
    let hello = pb::FuseServerMessage {
        msg: Some(pb::fuse_server_message::Msg::Attach(pb::Attach {
            container: Some(container),
            version: VERSION,
            limits: Some(limits),
        })),
    };
    out.send(hello)
        .await
        .map_err(|_| Status::internal("outbound stream closed"))?;
    let mut events = crate::ContainersClient::new(channel)
        .serve_fuse(ReceiverStream::new(rx))
        .await?
        .into_inner();
    let first = events
        .message()
        .await?
        .and_then(|e| e.event)
        .ok_or_else(|| Status::unavailable("tenantd closed the stream before attaching"))?;
    let pb::fuse_server_event::Event::Attached(a) = first else {
        return Err(Status::internal("tenantd did not start with attached"));
    };
    Ok(Session {
        fs,
        events,
        out,
        generation: a.generation,
        limits: a.limits.unwrap_or_default(),
    })
}

impl<F: Filesystem> Session<F> {
    /// A handle for telling tenantd to drop what it cached.
    pub fn invalidator(&self) -> Invalidator {
        Invalidator {
            out: self.out.clone(),
        }
    }

    /// Serve requests until the stream ends: `Ok` when the container ended
    /// or tenantd shut the stream, `Aborted` when another server replaced
    /// this one.
    pub async fn run(mut self) -> Result<(), Status> {
        let mut running: HashMap<u64, AbortHandle> = HashMap::new();
        let result = loop {
            let Some(ev) = self.events.message().await?.and_then(|e| e.event) else {
                break Ok(());
            };
            match ev {
                pb::fuse_server_event::Event::Request(req) => {
                    let (fs, out, id) = (self.fs.clone(), self.out.clone(), req.id);
                    if running.len() >= 1024 {
                        running.retain(|_, h| !h.is_finished());
                    }
                    let task = tokio::spawn(async move {
                        let resp = answer(&*fs, req).await;
                        let _ = out
                            .send(pb::FuseServerMessage {
                                msg: Some(pb::fuse_server_message::Msg::Response(resp)),
                            })
                            .await;
                    });
                    running.insert(id, task.abort_handle());
                }
                pb::fuse_server_event::Event::Cancel(c) => {
                    if let Some(h) = running.remove(&c.id) {
                        h.abort();
                    }
                }
                pb::fuse_server_event::Event::Attached(_) => {}
            }
        };
        for h in running.values() {
            h.abort();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fs;

    impl Filesystem for Fs {
        async fn stat(&self, _cx: &Context, req: pb::Stat) -> Result<pb::FileAttr> {
            match req.path.as_str() {
                "/" => Ok(pb::FileAttr::default()),
                _ => Err(Error::not_found().cached_for_ms(50)),
            }
        }
        async fn read(&self, cx: &Context, req: pb::Read) -> Result<Vec<u8>> {
            Ok(format!("{}:{}", cx.uid, req.size).into_bytes())
        }
    }

    fn request(op: Op) -> pb::FuseRequest {
        pb::FuseRequest {
            id: 9,
            uid: 1000,
            op: Some(op),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn operations_dispatch_and_failures_carry_errno() {
        let r = answer(&Fs, request(Op::Stat(pb::Stat { path: "/".into() }))).await;
        assert_eq!((r.id, r.errno), (9, 0));
        assert!(matches!(r.result, Some(Res::Attr(_))));

        let r = answer(&Fs, request(Op::Stat(pb::Stat { path: "/x".into() }))).await;
        assert_eq!((r.errno, r.negative_ttl_ms), (errno::ENOENT, 50));
        assert!(r.result.is_none());

        let r = answer(
            &Fs,
            request(Op::Read(pb::Read {
                size: 4,
                ..Default::default()
            })),
        )
        .await;
        assert!(matches!(r.result, Some(Res::Data(d)) if d == b"1000:4"));

        // Left out: ENOSYS. Flush and release succeed unasked.
        let r = answer(&Fs, request(Op::Unlink(pb::Unlink::default()))).await;
        assert_eq!(r.errno, errno::ENOSYS);
        let r = answer(&Fs, request(Op::Release(pb::Release::default()))).await;
        assert!(matches!(r.result, Some(Res::Ok(_))));

        let r = answer(
            &Fs,
            pb::FuseRequest {
                id: 1,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(r.errno, errno::ENOSYS);
    }

    #[test]
    fn io_errors_keep_their_errno() {
        let e = Error::from(std::io::Error::from_raw_os_error(libc::ENOSPC));
        assert_eq!(e.errno, errno::ENOSPC);
        let e = Error::from(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
        assert_eq!(e.errno, errno::ENOENT);
    }
}
