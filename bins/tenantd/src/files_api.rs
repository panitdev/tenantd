//! `Files`: file access to a running container's root.
//!
//! The core admits each call ([`Tenantd::file_access`]). The operations
//! themselves ([`ops`]) run on a `tenantd_layer::files::Root` in one of two
//! places: inside the container, in the file helper ([`crate::files_helper`])
//! that each call execs there, or here on the host for a container with
//! host file access, falling back to the helper for paths under a mount.
//! Filesystem errors are replies with an errno; a gRPC error means the call
//! was refused.
//!
//! [`Tenantd::file_access`]: tenantd_core::Tenantd::file_access

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tenantd_client::pb::{self, file_write_request::Msg, files_server::Files};
use tenantd_core::backend::PipedProcess;
use tenantd_core::files::FileAccess;
use tenantd_core::{Error, Result};
use tenantd_layer::files::{Ident, Root};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::api::{Api, container_key, status};
use crate::files_helper::{Call, HelperCall, MAX_MESSAGE};

/// How long an abandoned write's helper gets to clean up before it is
/// killed.
const ABANDON_GRACE: Duration = Duration::from_secs(10);

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::internal("file task", e))
}

/// The file operations, on whichever side of the container they run.
pub mod ops {
    use std::io;

    use tenantd_client::pb;
    use tenantd_layer::files::{
        Attr, FsError, FsResult, Kind, PendingWrite, Reader, Root, WriteOptions,
    };

    /// Largest `data` a Read sends in one message.
    pub const READ_CHUNK: usize = 256 << 10;

    /// A host call that reached a mount the host can't see through.
    #[derive(Debug)]
    pub struct NotServed;

    /// Done, or to be served through the helper instead.
    pub type Served<T> = Result<T, NotServed>;

    fn split<T>(r: FsResult<T>) -> Served<FsResult<T>> {
        match r {
            Err(e) if e.not_served => Err(NotServed),
            r => Ok(r),
        }
    }

    /// Inside the container, where nothing is out of view.
    pub fn served<T>(r: Served<T>) -> io::Result<T> {
        r.map_err(|_| io::Error::other("a mount inside the container"))
    }

    fn pb_kind(k: Kind) -> pb::FileKind {
        match k {
            Kind::File => pb::FileKind::File,
            Kind::Directory => pb::FileKind::Directory,
            Kind::Symlink => pb::FileKind::Symlink,
            Kind::Fifo => pb::FileKind::Fifo,
            Kind::Socket => pb::FileKind::Socket,
            Kind::CharDevice => pb::FileKind::CharDevice,
            Kind::BlockDevice => pb::FileKind::BlockDevice,
        }
    }

    pub fn pb_attr(a: Attr) -> pb::FileAttr {
        let mut id = a.dev.to_le_bytes().to_vec();
        id.extend(a.ino.to_le_bytes());
        pb::FileAttr {
            kind: pb_kind(a.kind) as i32,
            mode: a.mode,
            size: a.size,
            uid: a.uid,
            gid: a.gid,
            nlink: a.nlink,
            atime_ns: a.atime_ns,
            mtime_ns: a.mtime_ns,
            ctime_ns: a.ctime_ns,
            rdev: a.rdev,
            ttl_ms: 0,
            object_id: Some(id),
        }
    }

    /// `(errno, detail)` of a result, zero on success.
    fn err_parts<T>(r: &FsResult<T>) -> (i32, String) {
        match r {
            Ok(_) => (0, String::new()),
            Err(e) => (e.errno, e.detail.clone()),
        }
    }

    pub fn stat(root: &Root, r: &pb::FileStatRequest) -> Served<pb::FileStatResponse> {
        let res = split(root.stat(&r.path, r.follow))?;
        let (errno, detail) = err_parts(&res);
        let (path, attr) = match res {
            Ok((p, a)) => (p, Some(pb_attr(a))),
            Err(_) => (String::new(), None),
        };
        Ok(pb::FileStatResponse {
            errno,
            detail,
            attr,
            path,
        })
    }

    pub fn read_dir(root: &Root, r: &pb::FileReadDirRequest) -> Served<pb::FileReadDirResponse> {
        let res = split(root.read_dir(&r.path))?;
        let (errno, detail) = err_parts(&res);
        Ok(pb::FileReadDirResponse {
            errno,
            detail,
            entries: res
                .unwrap_or_default()
                .into_iter()
                .map(|(name, a)| pb::DirEntry {
                    name,
                    attr: Some(pb_attr(a)),
                })
                .collect(),
        })
    }

    pub fn rename(root: &Root, r: &pb::FileRenameRequest) -> Served<pb::FileRenameResponse> {
        let res = split(root.rename(&r.from, &r.to, r.flags))?;
        let (errno, detail) = err_parts(&res);
        Ok(pb::FileRenameResponse { errno, detail })
    }

    pub fn remove(root: &Root, r: &pb::FileRemoveRequest) -> Served<pb::FileRemoveResponse> {
        let res = split(root.remove(&r.path, r.directory))?;
        let (errno, detail) = err_parts(&res);
        Ok(pb::FileRemoveResponse { errno, detail })
    }

    pub type Opened = FsResult<(Reader, Attr)>;

    pub fn open_read(root: &Root, path: &str) -> Served<Opened> {
        split(root.open_read(path))
    }

    /// The messages of a Read: the attributes (or the errno that ended
    /// it), then `length` bytes (0: to the end) from `offset`, until `emit`
    /// says stop.
    pub fn read(
        opened: Opened,
        mut offset: u64,
        length: u64,
        mut emit: impl FnMut(pb::FileReadResponse) -> bool,
    ) {
        let reader = match opened {
            Ok((reader, attr)) => {
                let first = pb::FileReadResponse {
                    attr: Some(pb_attr(attr)),
                    offset,
                    ..Default::default()
                };
                if !emit(first) {
                    return;
                }
                reader
            }
            Err(FsError { errno, detail, .. }) => {
                emit(pb::FileReadResponse {
                    errno,
                    detail,
                    ..Default::default()
                });
                return;
            }
        };
        let mut left = if length == 0 { u64::MAX } else { length };
        let mut buf = vec![0u8; READ_CHUNK];
        while left > 0 {
            let want = left.min(READ_CHUNK as u64) as usize;
            let m = match reader.read_at(&mut buf[..want], offset) {
                Ok(0) => return,
                Ok(n) => {
                    let m = pb::FileReadResponse {
                        offset,
                        data: buf[..n].to_vec(),
                        ..Default::default()
                    };
                    offset += n as u64;
                    left -= n as u64;
                    m
                }
                Err(e) => {
                    emit(pb::FileReadResponse {
                        errno: e.errno,
                        detail: e.detail,
                        offset,
                        ..Default::default()
                    });
                    return;
                }
            };
            if !emit(m) {
                return;
            }
        }
    }

    /// A write's body on its way in. Dropping it before
    /// [`Body::finish`] leaves the target as it was.
    #[derive(Debug)]
    pub struct Body {
        w: PendingWrite,
        size: Option<u64>,
    }

    pub fn begin_write(root: &Root, h: &pb::FileWriteHeader) -> Served<FsResult<Body>> {
        let opts = WriteOptions {
            mode: h.mode,
            parents: h.parents,
            exclusive: h.exclusive,
        };
        Ok(split(root.begin_write(&h.path, &opts))?.map(|w| Body { w, size: h.size }))
    }

    impl Body {
        pub fn push(&mut self, data: &[u8]) -> FsResult<()> {
            if self
                .size
                .is_some_and(|s| self.w.written() + data.len() as u64 > s)
            {
                return Err(FsError::new(libc::EIO, "the body is longer than its size"));
            }
            self.w.write(data)
        }

        /// The file's attributes and the bytes written.
        pub fn finish(self) -> FsResult<(Attr, u64)> {
            let n = self.w.written();
            if let Some(size) = self.size.filter(|s| *s != n) {
                return Err(FsError::new(
                    libc::EIO,
                    format!("the body ended at {n} of {size} bytes"),
                ));
            }
            self.w.commit().map(|a| (a, n))
        }
    }

    pub fn write_reply(r: FsResult<(Attr, u64)>) -> pb::FileWriteResponse {
        let (errno, detail) = err_parts(&r);
        let (attr, written) = match r {
            Ok((a, n)) => (Some(pb_attr(a)), n),
            Err(_) => (None, 0),
        };
        pb::FileWriteResponse {
            errno,
            detail,
            attr,
            written,
        }
    }
}

use ops::Served;

/// The host root of `a`, opened as its user, when it has host access.
async fn host_root(a: &FileAccess) -> Result<Option<Arc<Root>>> {
    let Some(h) = a.host.clone() else {
        return Ok(None);
    };
    let (user, layers) = (a.helper.user.clone(), a.helper.image_layers.clone());
    blocking(move || {
        // As an exec (and so the helper) resolves it: in the image's
        // layers, with no supplementary groups.
        let (uid, gid) = tenantd_runtime_runsc::resolve_user_in_layers(user.as_deref(), &layers)?;
        let ident = Ident {
            uid,
            gid,
            groups: Vec::new(),
        };
        Root::open(&h.root, ident, &h.mounts)
            .map(|r| Some(Arc::new(r)))
            .map_err(|e| Error::Internal(format!("opening the container's root: {e}")))
    })
    .await?
}

/// `f` on the host root, when there is one and it can serve the call.
async fn on_host<T: Send + 'static>(
    root: Option<Arc<Root>>,
    f: impl FnOnce(&Root) -> Served<T> + Send + 'static,
) -> Result<Option<T>> {
    match root {
        None => Ok(None),
        Some(r) => Ok(blocking(move || f(&r)).await?.ok()),
    }
}

fn helper_io(e: std::io::Error) -> Error {
    Error::internal("talking to the file helper", e)
}

async fn send(w: &mut PipedProcess, m: &impl Message) -> std::io::Result<()> {
    w.stdin
        .write_all(&m.encode_length_delimited_to_vec())
        .await?;
    w.stdin.flush().await
}

/// The next message from the helper, `None` at the end of its output.
async fn recv<M: Message + Default>(
    r: &mut BufReader<impl AsyncRead + Unpin>,
) -> std::io::Result<Option<M>> {
    let mut len: u64 = 0;
    for i in 0..10 {
        let b = match r.read_u8().await {
            Ok(b) => b,
            Err(e) if i == 0 && e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };
        len |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            if len as usize > MAX_MESSAGE {
                return Err(std::io::Error::other(format!("a {len}-byte message")));
            }
            let mut buf = vec![0u8; len as usize];
            r.read_exact(&mut buf).await?;
            return M::decode(buf.as_slice())
                .map(Some)
                .map_err(std::io::Error::other);
        }
    }
    Err(std::io::Error::other("bad message length"))
}

/// Why the helper gave no reply, from how it exited.
fn no_reply(exit: Result<()>, got: std::io::Result<()>) -> Error {
    match exit {
        Err(Error::Internal(m)) if m.to_ascii_lowercase().contains("no such file") => {
            Error::FailedPrecondition(format!(
                "the container has no file helper (created before file access; recreate it): {m}"
            ))
        }
        Err(e) => e,
        Ok(()) => match got {
            Err(e) => helper_io(e),
            Ok(()) => Error::Internal("the file helper exited without a reply".into()),
        },
    }
}

type Stdout = BufReader<std::pin::Pin<Box<dyn AsyncRead + Send>>>;

/// Start the helper on `call`; its output to read from.
async fn start_helper(api: &Api, a: &FileAccess, call: Call) -> Result<(PipedProcess, Stdout)> {
    let mut p = api.tenantd.file_helper(a).await?;
    let stdout = BufReader::new(std::mem::replace(
        &mut p.stdout,
        Box::pin(tokio::io::empty()),
    ));
    if let Err(e) = send(&mut p, &HelperCall { call: Some(call) }).await {
        // It died before taking the call; its exit says why.
        return Err(no_reply(p.exit.await, Err(e)));
    }
    Ok((p, stdout))
}

/// The helper's one reply.
async fn reply<M: Message + Default>(p: PipedProcess, mut out: Stdout) -> Result<M> {
    match recv::<M>(&mut out).await {
        Ok(Some(m)) => {
            // It exits once it has answered; reap it.
            let _ = p.exit.await;
            Ok(m)
        }
        Ok(None) => Err(no_reply(p.exit.await, Ok(()))),
        Err(e) => Err(no_reply(p.exit.await, Err(e))),
    }
}

impl Api {
    async fn admit(
        &self,
        c: Option<pb::ContainerRef>,
        user: &str,
        write: bool,
    ) -> Result<FileAccess> {
        let c = c.ok_or_else(|| Error::invalid("container is required"))?;
        let key = container_key(&c.tenant, &c.sandbox, &c.id)?;
        self.tenantd.file_access(&key, Some(user), write).await
    }

    /// A one-message call: on the host when it can, else through the
    /// helper.
    async fn unary<M: Message + Default + Send + 'static>(
        &self,
        a: FileAccess,
        call: Call,
        host: impl FnOnce(&Root) -> Served<M> + Send + 'static,
    ) -> Result<M> {
        if let Some(m) = on_host(host_root(&a).await?, host).await? {
            return Ok(m);
        }
        let (p, out) = start_helper(self, &a, call).await?;
        reply(p, out).await
    }

    async fn write_on_host(
        &self,
        root: Option<Arc<Root>>,
        h: &pb::FileWriteHeader,
        inbound: &mut Streaming<pb::FileWriteRequest>,
    ) -> Result<Option<pb::FileWriteResponse>> {
        let h2 = h.clone();
        let mut body = match on_host(root, move |r| ops::begin_write(r, &h2)).await? {
            None => return Ok(None),
            Some(Err(e)) => return Ok(Some(ops::write_reply(Err(e)))),
            Some(Ok(b)) => b,
        };
        // Dropping `body` on any way out but finish removes the temporary
        // file, leaving the target as it was.
        loop {
            let data = match inbound.message().await {
                Ok(Some(pb::FileWriteRequest {
                    msg: Some(Msg::Data(d)),
                })) => d,
                Ok(Some(_)) => return Err(Error::invalid("expected data after the header")),
                Ok(None) => break,
                Err(s) => return Err(body_failed(s)),
            };
            let (back, res) = blocking(move || {
                let res = body.push(&data);
                (body, res)
            })
            .await?;
            body = back;
            if let Err(e) = res {
                return Ok(Some(ops::write_reply(Err(e))));
            }
        }
        Ok(Some(ops::write_reply(
            blocking(move || body.finish()).await?,
        )))
    }

    async fn write_in_helper(
        &self,
        a: &FileAccess,
        h: pb::FileWriteHeader,
        inbound: &mut Streaming<pb::FileWriteRequest>,
    ) -> Result<pb::FileWriteResponse> {
        let (mut p, out) = start_helper(self, a, Call::Write(h)).await?;
        loop {
            let m = match inbound.message().await {
                Ok(Some(
                    m @ pb::FileWriteRequest {
                        msg: Some(Msg::Data(_)),
                    },
                )) => m,
                Ok(Some(_)) => return Err(Error::invalid("expected data after the header")),
                // Commit.
                Ok(None) => pb::FileWriteRequest { msg: None },
                Err(s) => {
                    // Ending its input abandons the write; give it the time
                    // to remove its file.
                    let PipedProcess { stdin, exit, .. } = p;
                    drop(stdin);
                    let _ = tokio::time::timeout(ABANDON_GRACE, exit).await;
                    return Err(body_failed(s));
                }
            };
            let commit = m.msg.is_none();
            // A helper that stopped reading has answered already (an error
            // such as ENOSPC); its reply follows.
            if send(&mut p, &m).await.is_err() || commit {
                break;
            }
        }
        reply(p, out).await
    }
}

fn body_failed(s: Status) -> Error {
    Error::Unavailable(format!("the body's stream failed: {}", s.message()))
}

type ReadTx = mpsc::Sender<std::result::Result<pb::FileReadResponse, Status>>;

/// Forward a helper's Read messages, then its exit if it failed.
async fn pump_helper(p: PipedProcess, mut out: Stdout, tx: ReadTx) {
    loop {
        match recv::<pb::FileReadResponse>(&mut out).await {
            Ok(Some(m)) => {
                if tx.send(Ok(m)).await.is_err() {
                    // The caller left; dropping the helper kills it.
                    return;
                }
            }
            Ok(None) => {
                if let Err(e) = p.exit.await {
                    let _ = tx.send(Err(status(e))).await;
                }
                return;
            }
            Err(e) => {
                let _ = tx.send(Err(status(no_reply(p.exit.await, Err(e))))).await;
                return;
            }
        }
    }
}

#[tonic::async_trait]
impl Files for Api {
    async fn stat(
        &self,
        req: Request<pb::FileStatRequest>,
    ) -> std::result::Result<Response<pb::FileStatResponse>, Status> {
        let r = req.into_inner();
        self.timed("FileStat", async {
            let a = self.admit(r.container.clone(), &r.user, false).await?;
            let r2 = r.clone();
            self.unary(a, Call::Stat(r), move |root| ops::stat(root, &r2))
                .await
        })
        .await
    }

    async fn read_dir(
        &self,
        req: Request<pb::FileReadDirRequest>,
    ) -> std::result::Result<Response<pb::FileReadDirResponse>, Status> {
        let r = req.into_inner();
        self.timed("FileReadDir", async {
            let a = self.admit(r.container.clone(), &r.user, false).await?;
            let r2 = r.clone();
            self.unary(a, Call::ReadDir(r), move |root| ops::read_dir(root, &r2))
                .await
        })
        .await
    }

    type ReadStream = ReceiverStream<std::result::Result<pb::FileReadResponse, Status>>;

    async fn read(
        &self,
        req: Request<pb::FileReadRequest>,
    ) -> std::result::Result<Response<Self::ReadStream>, Status> {
        let r = req.into_inner();
        let (tx, rx) = mpsc::channel(4);
        self.timed("FileRead", async {
            let a = self.admit(r.container.clone(), &r.user, false).await?;
            let path = r.path.clone();
            let opened = on_host(host_root(&a).await?, move |root| {
                ops::open_read(root, &path)
            })
            .await?;
            let (offset, length) = (r.offset, r.length);
            match opened {
                Some(opened) => {
                    let tx = tx.clone();
                    tokio::task::spawn_blocking(move || {
                        ops::read(opened, offset, length, |m| tx.blocking_send(Ok(m)).is_ok())
                    });
                }
                None => {
                    let (p, out) = start_helper(self, &a, Call::Read(r)).await?;
                    tokio::spawn(pump_helper(p, out, tx.clone()));
                }
            }
            Ok(())
        })
        .await?;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn write(
        &self,
        req: Request<Streaming<pb::FileWriteRequest>>,
    ) -> std::result::Result<Response<pb::FileWriteResponse>, Status> {
        let mut inbound = req.into_inner();
        let Some(Msg::Header(h)) = inbound.message().await?.and_then(|m| m.msg) else {
            return Err(Status::invalid_argument("expected the header first"));
        };
        self.timed("FileWrite", async {
            let a = self.admit(h.container.clone(), &h.user, true).await?;
            let root = host_root(&a).await?;
            if let Some(r) = self.write_on_host(root, &h, &mut inbound).await? {
                return Ok(r);
            }
            self.write_in_helper(&a, h, &mut inbound).await
        })
        .await
    }

    async fn rename(
        &self,
        req: Request<pb::FileRenameRequest>,
    ) -> std::result::Result<Response<pb::FileRenameResponse>, Status> {
        let r = req.into_inner();
        self.timed("FileRename", async {
            let a = self.admit(r.container.clone(), &r.user, false).await?;
            let r2 = r.clone();
            self.unary(a, Call::Rename(r), move |root| ops::rename(root, &r2))
                .await
        })
        .await
    }

    async fn remove(
        &self,
        req: Request<pb::FileRemoveRequest>,
    ) -> std::result::Result<Response<pb::FileRemoveResponse>, Status> {
        let r = req.into_inner();
        self.timed("FileRemove", async {
            let a = self.admit(r.container.clone(), &r.user, false).await?;
            let r2 = r.clone();
            self.unary(a, Call::Remove(r), move |root| ops::remove(root, &r2))
                .await
        })
        .await
    }
}
