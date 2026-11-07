//! File access to a running container's root, over `Files`.
//!
//! ```no_run
//! # async fn f() -> Result<(), Box<dyn std::error::Error>> {
//! use tenantd_client::files::{Files, WriteOptions};
//! use tenantd_client::pb;
//!
//! let ch = tenantd_client::connect("/run/tenantd/api.sock").await?;
//! let container = pb::ContainerRef { tenant: "acme".into(), sandbox: "box1".into(), id: "s1".into() };
//! let mut files = Files::new(ch, container);
//! files.write("/work/in.txt", b"hello".to_vec(), &WriteOptions::default()).await?;
//! let back = files.read("/work/in.txt").await?;
//! match files.stat("/work/missing", false).await {
//!     Err(e) if e.is_not_found() => {}
//!     other => { other?; }
//! }
//! # Ok(()) }
//! ```
//!
//! [`Files::volume`] works on a volume instead: paths are absolute within
//! it, it needs no container, and every call acts as the volume's owner.
//!
//! Paths are absolute within the container's root and resolve as the
//! container sees them. A call acts as the image's user unless
//! [`Files::as_user`] names another one of the profile's `exec.users`.
//! Each call execs tenantd's helper in the container (tens of
//! milliseconds) unless the container was created with
//! `host_file_access`. Works the same over the Unix socket and
//! [`crate::tls`].

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::{Status, Streaming};

pub use crate::fuse::errno;
use crate::pb::{self, file_write_request::Msg, files_client::FilesClient};

/// Bytes per `data` message a write sends.
pub const WRITE_CHUNK: usize = 256 << 10;

/// Why a file call failed.
#[derive(Debug)]
pub enum Error {
    /// The filesystem said no: a Linux errno, with tenantd's detail.
    Errno { errno: i32, detail: String },
    /// tenantd refused the call (unknown container, not running, policy)
    /// or the transport failed.
    Status(Status),
    /// A reply that doesn't follow the protocol.
    Protocol(String),
    /// Reading the body to write failed; the target is left as it was.
    Io(std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// The errno, when the filesystem refused.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Errno { errno, .. } => Some(*errno),
            _ => None,
        }
    }

    /// `ENOENT`: nothing at the path.
    pub fn is_not_found(&self) -> bool {
        self.errno() == Some(errno::ENOENT)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Errno { errno, detail } => {
                write!(f, "{}", std::io::Error::from_raw_os_error(*errno))?;
                if !detail.is_empty() {
                    write!(f, " ({detail})")?;
                }
                Ok(())
            }
            Error::Status(s) => write!(f, "tenantd: {}: {}", s.code(), s.message()),
            Error::Protocol(m) => write!(f, "tenantd: {m}"),
            Error::Io(e) => write!(f, "reading the body: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Status(s) => Some(s),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Status> for Error {
    fn from(s: Status) -> Self {
        Error::Status(s)
    }
}

fn check(errno: i32, detail: String) -> Result<()> {
    if errno == 0 {
        Ok(())
    } else {
        Err(Error::Errno { errno, detail })
    }
}

fn attr(a: Option<pb::FileAttr>) -> Result<pb::FileAttr> {
    a.ok_or_else(|| Error::Protocol("reply carries no attributes".into()))
}

/// How [`Files::write`] writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteOptions {
    /// Default: the replaced file's, or 0644.
    pub mode: Option<u32>,
    /// Create missing parent directories (0755).
    pub parents: bool,
    /// Fail with `EEXIST` if the path exists.
    pub exclusive: bool,
    /// For [`Files::write_from`]: the body's length, when known. A body
    /// that ends short (a reader that stops early) or runs long then fails
    /// with `EIO` instead of replacing the file. [`Files::write`] always
    /// sends its data's.
    pub size: Option<u64>,
}

/// What [`Files::stat`] found.
#[derive(Clone, Debug, PartialEq)]
pub struct Stat {
    /// The path stat-ed, its symlinks resolved when following.
    pub path: String,
    pub attr: pb::FileAttr,
}

/// A file being read in chunks; see [`Files::read_range`].
pub struct FileReader {
    attr: pb::FileAttr,
    inner: Streaming<pb::FileReadResponse>,
}

impl FileReader {
    /// The file's attributes when the read began.
    pub fn attr(&self) -> &pb::FileAttr {
        &self.attr
    }

    /// The next chunk and its offset; `None` once the range is done.
    pub async fn chunk(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        match self.inner.message().await? {
            None => Ok(None),
            Some(m) => {
                check(m.errno, m.detail)?;
                Ok(Some((m.offset, m.data)))
            }
        }
    }

    /// Everything left, in one buffer.
    pub async fn to_end(mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some((_, d)) = self.chunk().await? {
            out.extend_from_slice(&d);
        }
        Ok(out)
    }
}

/// What file calls work on.
#[derive(Clone, Debug)]
enum Target {
    Container(pb::ContainerRef),
    Volume(pb::VolumeRef),
}

/// File calls on one container as one user, or on one volume.
#[derive(Clone)]
pub struct Files {
    inner: FilesClient<Channel>,
    target: Target,
    user: String,
}

impl Files {
    pub fn new(ch: Channel, container: pb::ContainerRef) -> Self {
        Self {
            inner: FilesClient::new(ch),
            target: Target::Container(container),
            user: String::new(),
        }
    }

    /// File calls on a volume, served on the host as its owner whether or
    /// not a container binds it. Symlinks resolve inside the volume.
    pub fn volume(ch: Channel, volume: pb::VolumeRef) -> Self {
        Self {
            inner: FilesClient::new(ch),
            target: Target::Volume(volume),
            user: String::new(),
        }
    }

    /// Act as `user`, one of the profile's `exec.users` (`""` or
    /// `"image"`: the image's user). Not for a volume, whose calls are
    /// always its owner's.
    pub fn as_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    fn container(&self) -> Option<pb::ContainerRef> {
        match &self.target {
            Target::Container(c) => Some(c.clone()),
            Target::Volume(_) => None,
        }
    }

    fn vol(&self) -> Option<pb::VolumeRef> {
        match &self.target {
            Target::Volume(v) => Some(v.clone()),
            Target::Container(_) => None,
        }
    }

    /// `lstat`, or `stat` with `follow`.
    pub async fn stat(&mut self, path: impl Into<String>, follow: bool) -> Result<Stat> {
        let r = self
            .inner
            .stat(pb::FileStatRequest {
                container: self.container(),
                volume: self.vol(),
                path: path.into(),
                follow,
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)?;
        Ok(Stat {
            path: r.path,
            attr: attr(r.attr)?,
        })
    }

    /// The directory's entries, each with its `lstat` attributes.
    pub async fn read_dir(&mut self, path: impl Into<String>) -> Result<Vec<pb::DirEntry>> {
        let r = self
            .inner
            .read_dir(pb::FileReadDirRequest {
                container: self.container(),
                volume: self.vol(),
                path: path.into(),
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)?;
        Ok(r.entries)
    }

    /// `length` bytes from `offset` (0: to the end), as a stream of chunks.
    pub async fn read_range(
        &mut self,
        path: impl Into<String>,
        offset: u64,
        length: u64,
    ) -> Result<FileReader> {
        let mut inner = self
            .inner
            .read(pb::FileReadRequest {
                container: self.container(),
                volume: self.vol(),
                path: path.into(),
                offset,
                length,
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        let first = inner
            .message()
            .await?
            .ok_or_else(|| Error::Protocol("read ended before it began".into()))?;
        check(first.errno, first.detail)?;
        Ok(FileReader {
            attr: attr(first.attr)?,
            inner,
        })
    }

    /// The whole file.
    pub async fn read(&mut self, path: impl Into<String>) -> Result<Vec<u8>> {
        self.read_range(path, 0, 0).await?.to_end().await
    }

    /// Replace (or create) the file with `data`, atomically.
    pub async fn write(
        &mut self,
        path: impl Into<String>,
        data: impl Into<Vec<u8>>,
        opts: &WriteOptions,
    ) -> Result<pb::FileAttr> {
        let data = data.into();
        let mut msgs = vec![self.header(path.into(), opts, Some(data.len() as u64))];
        msgs.extend(data.chunks(WRITE_CHUNK).map(|c| pb::FileWriteRequest {
            msg: Some(Msg::Data(c.to_vec())),
        }));
        let r = self
            .inner
            .write(tokio_stream::iter(msgs))
            .await?
            .into_inner();
        reply(r)
    }

    /// Replace (or create) the file with everything `body` yields. If
    /// reading `body` fails, the call is cancelled and the target is left
    /// as it was.
    pub async fn write_from<R>(
        &mut self,
        path: impl Into<String>,
        mut body: R,
        opts: &WriteOptions,
    ) -> Result<pb::FileAttr>
    where
        R: AsyncRead + Unpin + Send,
    {
        let (tx, rx) = mpsc::channel(4);
        tx.send(self.header(path.into(), opts, opts.size))
            .await
            .expect("the receiver is held below");
        let call = self.inner.write(ReceiverStream::new(rx));
        tokio::pin!(call);
        let feed = async move {
            loop {
                let mut buf = vec![0u8; WRITE_CHUNK];
                let n = body.read(&mut buf).await?;
                if n == 0 {
                    // Dropping the sender ends the body.
                    return Ok::<_, std::io::Error>(());
                }
                buf.truncate(n);
                let m = pb::FileWriteRequest {
                    msg: Some(Msg::Data(buf)),
                };
                if tx.send(m).await.is_err() {
                    // The call ended early; its reply says why.
                    return Ok(());
                }
            }
        };
        tokio::pin!(feed);
        let mut fed = false;
        loop {
            tokio::select! {
                r = &mut call => return reply(r?.into_inner()),
                // Returning drops the call, which cancels it.
                f = &mut feed, if !fed => match f {
                    Ok(()) => fed = true,
                    Err(e) => return Err(Error::Io(e)),
                },
            }
        }
    }

    fn header(&self, path: String, opts: &WriteOptions, size: Option<u64>) -> pb::FileWriteRequest {
        pb::FileWriteRequest {
            msg: Some(Msg::Header(pb::FileWriteHeader {
                container: self.container(),
                volume: self.vol(),
                path,
                mode: opts.mode,
                parents: opts.parents,
                exclusive: opts.exclusive,
                size,
                user: self.user.clone(),
            })),
        }
    }

    /// `renameat2(2)`; `flags` is 0, [`RENAME_NOREPLACE`] or
    /// [`RENAME_EXCHANGE`].
    pub async fn rename(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        flags: u32,
    ) -> Result<()> {
        let r = self
            .inner
            .rename(pb::FileRenameRequest {
                container: self.container(),
                volume: self.vol(),
                from: from.into(),
                to: to.into(),
                flags,
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)
    }

    /// `unlink(2)`: a file, symlink or other non-directory.
    pub async fn remove(&mut self, path: impl Into<String>) -> Result<()> {
        self.remove_any(path.into(), false).await
    }

    /// `rmdir(2)`: an empty directory.
    pub async fn remove_dir(&mut self, path: impl Into<String>) -> Result<()> {
        self.remove_any(path.into(), true).await
    }

    /// `mkdir(2)` with `mode` (0755 when `None`), exactly, whatever the
    /// umask. With `parents`, `mkdir -p`: missing parents are made and an
    /// existing directory is no error.
    pub async fn mkdir(
        &mut self,
        path: impl Into<String>,
        mode: Option<u32>,
        parents: bool,
    ) -> Result<pb::FileAttr> {
        let r = self
            .inner
            .mkdir(pb::FileMkdirRequest {
                container: self.container(),
                volume: self.vol(),
                path: path.into(),
                mode,
                parents,
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)?;
        attr(r.attr)
    }

    /// `symlink(2)`: a link at `path` to `target`, stored as given.
    pub async fn symlink(
        &mut self,
        path: impl Into<String>,
        target: impl Into<String>,
    ) -> Result<()> {
        let r = self
            .inner
            .symlink(pb::FileSymlinkRequest {
                container: self.container(),
                volume: self.vol(),
                path: path.into(),
                target: target.into(),
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)
    }

    /// `readlink(2)`: the link's target as stored.
    pub async fn read_link(&mut self, path: impl Into<String>) -> Result<Vec<u8>> {
        let r = self
            .inner
            .read_link(pb::FileReadLinkRequest {
                container: self.container(),
                volume: self.vol(),
                path: path.into(),
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)?;
        Ok(r.target)
    }

    /// Set the mode and/or modification time (nanoseconds since the epoch)
    /// of what is at `path`, following a symlink there.
    pub async fn set_attr(
        &mut self,
        path: impl Into<String>,
        mode: Option<u32>,
        mtime_ns: Option<i64>,
    ) -> Result<pb::FileAttr> {
        let r = self
            .inner
            .set_attr(pb::FileSetAttrRequest {
                container: self.container(),
                volume: self.vol(),
                path: path.into(),
                mode,
                mtime_ns,
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)?;
        attr(r.attr)
    }

    async fn remove_any(&mut self, path: String, directory: bool) -> Result<()> {
        let r = self
            .inner
            .remove(pb::FileRemoveRequest {
                container: self.container(),
                volume: self.vol(),
                path,
                directory,
                user: self.user.clone(),
            })
            .await?
            .into_inner();
        check(r.errno, r.detail)
    }
}

/// `renameat2(2)` flags.
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;

fn reply(r: pb::FileWriteResponse) -> Result<pb::FileAttr> {
    check(r.errno, r.detail)?;
    attr(r.attr)
}
