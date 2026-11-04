//! The semantic view of a container's FUSE mount.
//!
//! tenantd's host backend speaks the kernel protocol; what reaches the
//! caller's server is the path-based operations below, which the API maps
//! one-to-one onto `Containers.ServeFuse`. Nothing here depends on the
//! transport, so a server may be on another machine.
//!
//! A [`FuseLink`] is one attached server: the backend pushes
//! [`FuseEvent`]s into it, and the server answers through [`FuseLink::respond`].
//! Dropping the link detaches the server, which fails what it had not
//! answered with `EIO`.

use std::sync::Arc;

use tokio::sync::mpsc;

/// Linux errno values the core and backends use themselves.
pub const EIO: i32 = 5;
pub const ENOSYS: i32 = 38;

/// Protocol version spoken in `Attach`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest request or reply payload tenantd accepts, whatever a server asks.
pub const MAX_IO: u32 = 1 << 20;
pub const MAX_INFLIGHT: u32 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuseLimits {
    pub max_read: u32,
    pub max_write: u32,
    pub max_inflight: u32,
}

impl FuseLimits {
    /// tenantd's own ceilings.
    pub const SERVER: FuseLimits = FuseLimits {
        max_read: MAX_IO,
        max_write: MAX_IO,
        max_inflight: MAX_INFLIGHT,
    };

    /// "No preference", for a server that takes whatever tenantd offers.
    pub const ANY: FuseLimits = FuseLimits {
        max_read: 0,
        max_write: 0,
        max_inflight: 0,
    };

    /// What both sides can take. A zero from the server is "no preference".
    pub fn negotiate(self, theirs: FuseLimits) -> FuseLimits {
        let pick = |ours: u32, theirs: u32| if theirs == 0 { ours } else { ours.min(theirs) };
        FuseLimits {
            max_read: pick(self.max_read, theirs.max_read).max(4096),
            max_write: pick(self.max_write, theirs.max_write).max(4096),
            max_inflight: pick(self.max_inflight, theirs.max_inflight).max(1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileAttr {
    pub kind: FileKind,
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub rdev: u32,
    pub ttl_ms: u32,
    /// Equal for the hard links of one file.
    pub object_id: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub attr: FileAttr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenReply {
    pub handle: u64,
    pub keep_cache: bool,
    pub direct_io: bool,
    pub buffered_writes: bool,
    pub attr: Option<FileAttr>,
    pub inline_data: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatFsReply {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetAttr {
    pub handle: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime_ns: Option<i64>,
    pub mtime_ns: Option<i64>,
}

/// Whose access a request is, as the kernel reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FuseOp {
    Stat {
        path: String,
    },
    ReadDir {
        path: String,
    },
    Readlink {
        path: String,
    },
    Open {
        path: String,
        flags: u32,
    },
    Read {
        path: String,
        handle: u64,
        offset: u64,
        size: u32,
    },
    Write {
        path: String,
        handle: u64,
        offset: u64,
        data: Vec<u8>,
    },
    Flush {
        path: String,
        handle: u64,
    },
    Release {
        path: String,
        handle: u64,
    },
    Fsync {
        path: String,
        handle: u64,
        datasync: bool,
    },
    Create {
        path: String,
        mode: u32,
        flags: u32,
    },
    Mkdir {
        path: String,
        mode: u32,
    },
    Unlink {
        path: String,
    },
    Rmdir {
        path: String,
    },
    Rename {
        from: String,
        to: String,
        flags: u32,
    },
    Symlink {
        path: String,
        target: String,
    },
    SetAttr {
        path: String,
        set: SetAttr,
    },
    StatFs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FuseReply {
    Attr(FileAttr),
    Dir(Vec<DirEntry>),
    Open(OpenReply),
    Data(Vec<u8>),
    Written {
        written: u32,
        attr: Option<FileAttr>,
    },
    Target(String),
    StatFs(StatFsReply),
    Ok,
}

/// A failed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuseError {
    pub errno: i32,
    pub detail: String,
    /// With `ENOENT`: how long the absence may be cached.
    pub negative_ttl_ms: u32,
}

impl FuseError {
    pub fn new(errno: i32) -> Self {
        Self {
            errno,
            detail: String::new(),
            negative_ttl_ms: 0,
        }
    }
}

pub type FuseResult = std::result::Result<FuseReply, FuseError>;

/// What `Invalidate` names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidateTarget {
    Path { path: String, recursive: bool },
    Object(Vec<u8>),
}

#[derive(Debug)]
pub enum FuseEvent {
    Request {
        id: u64,
        caller: Caller,
        op: FuseOp,
    },
    /// The kernel gave up on the request.
    Cancel {
        id: u64,
    },
    /// Another server attached; this link is over.
    Replaced,
}

/// The backend's end of a link.
pub trait FuseSession: Send + Sync {
    fn respond(&self, generation: u64, id: u64, result: FuseResult);
    fn invalidate(&self, generation: u64, target: InvalidateTarget);
    /// The server is gone. Fails what it had not answered.
    fn detach(&self, generation: u64);
}

/// One attached server of a container's FUSE mount.
pub struct FuseLink {
    pub generation: u64,
    pub limits: FuseLimits,
    pub events: mpsc::Receiver<FuseEvent>,
    session: Arc<dyn FuseSession>,
}

impl FuseLink {
    pub fn new(
        generation: u64,
        limits: FuseLimits,
        events: mpsc::Receiver<FuseEvent>,
        session: Arc<dyn FuseSession>,
    ) -> Self {
        Self {
            generation,
            limits,
            events,
            session,
        }
    }

    /// Answer request `id`. Unknown, answered and cancelled ids are ignored.
    pub fn respond(&self, id: u64, result: FuseResult) {
        self.session.respond(self.generation, id, result);
    }

    pub fn invalidate(&self, target: InvalidateTarget) {
        self.session.invalidate(self.generation, target);
    }
}

impl Drop for FuseLink {
    fn drop(&mut self) {
        self.session.detach(self.generation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_take_the_smaller_side() {
        let theirs = FuseLimits {
            max_read: 65536,
            max_write: 0,
            max_inflight: 8,
        };
        let got = FuseLimits::SERVER.negotiate(theirs);
        assert_eq!(got.max_read, 65536);
        assert_eq!(got.max_write, MAX_IO);
        assert_eq!(got.max_inflight, 8);
        // Never below what a page needs.
        let tiny = FuseLimits {
            max_read: 1,
            max_write: 1,
            max_inflight: 1,
        };
        assert_eq!(FuseLimits::SERVER.negotiate(tiny).max_read, 4096);
    }
}
