//! `Containers.ServeFuse`: the caller's FUSE server, over gRPC.
//!
//! One stream per attached server. This module maps between the wire
//! messages and the transport-neutral types of [`tenantd_core::fuse`], and
//! pumps events and responses between the stream and a [`FuseLink`]. The
//! link being dropped when the stream ends is what detaches the server.

use tenantd_client::pb::{
    self, fuse_request::Op, fuse_response::Result as Res, fuse_server_event::Event,
    fuse_server_message::Msg,
};
use tenantd_core::fuse::{
    self as sem, FuseError, FuseEvent, FuseLimits, FuseLink, FuseOp, FuseReply, FuseResult,
    InvalidateTarget,
};
use tokio::sync::mpsc;
use tonic::{Status, Streaming};

pub type EventTx = mpsc::Sender<Result<pb::FuseServerEvent, Status>>;

pub fn limits_in(l: Option<pb::FuseLimits>) -> FuseLimits {
    let l = l.unwrap_or_default();
    FuseLimits {
        max_read: l.max_read,
        max_write: l.max_write,
        max_inflight: l.max_inflight,
    }
}

fn limits_out(l: FuseLimits) -> pb::FuseLimits {
    pb::FuseLimits {
        max_read: l.max_read,
        max_write: l.max_write,
        max_inflight: l.max_inflight,
    }
}

fn kind_in(k: pb::FileKind) -> Option<sem::FileKind> {
    Some(match k {
        pb::FileKind::Unspecified => return None,
        pb::FileKind::File => sem::FileKind::File,
        pb::FileKind::Directory => sem::FileKind::Directory,
        pb::FileKind::Symlink => sem::FileKind::Symlink,
        pb::FileKind::Fifo => sem::FileKind::Fifo,
        pb::FileKind::Socket => sem::FileKind::Socket,
        pb::FileKind::CharDevice => sem::FileKind::CharDevice,
        pb::FileKind::BlockDevice => sem::FileKind::BlockDevice,
    })
}

fn bad() -> FuseError {
    FuseError {
        errno: sem::EIO,
        detail: "malformed response".into(),
        negative_ttl_ms: 0,
    }
}

fn attr_in(a: pb::FileAttr) -> Result<sem::FileAttr, FuseError> {
    Ok(sem::FileAttr {
        kind: kind_in(a.kind()).ok_or_else(bad)?,
        mode: a.mode,
        size: a.size,
        uid: a.uid,
        gid: a.gid,
        nlink: a.nlink,
        atime_ns: a.atime_ns,
        mtime_ns: a.mtime_ns,
        ctime_ns: a.ctime_ns,
        rdev: a.rdev,
        ttl_ms: a.ttl_ms,
        object_id: a.object_id.filter(|o| !o.is_empty()),
    })
}

fn open_in(o: pb::OpenReply) -> Result<sem::OpenReply, FuseError> {
    Ok(sem::OpenReply {
        handle: o.handle,
        keep_cache: o.keep_cache,
        direct_io: o.direct_io,
        buffered_writes: o.buffered_writes,
        attr: o.attr.map(attr_in).transpose()?,
        inline_data: o.inline_data,
    })
}

/// A server's response as a result.
pub fn response_in(r: pb::FuseResponse) -> FuseResult {
    if r.errno != 0 {
        return Err(FuseError {
            errno: if r.errno > 0 { r.errno } else { sem::EIO },
            detail: r.detail,
            negative_ttl_ms: r.negative_ttl_ms,
        });
    }
    Ok(match r.result.ok_or_else(bad)? {
        Res::Attr(a) => FuseReply::Attr(attr_in(a)?),
        Res::Dir(d) => FuseReply::Dir(
            d.entries
                .into_iter()
                .map(|e| {
                    Ok(sem::DirEntry {
                        name: e.name,
                        attr: attr_in(e.attr.ok_or_else(bad)?)?,
                    })
                })
                .collect::<Result<_, FuseError>>()?,
        ),
        Res::Open(o) => FuseReply::Open(open_in(o)?),
        Res::Data(d) => FuseReply::Data(d),
        Res::Write(w) => FuseReply::Written {
            written: w.written,
            attr: w.attr.map(attr_in).transpose()?,
        },
        Res::Target(t) => FuseReply::Target(t),
        Res::Statfs(s) => FuseReply::StatFs(sem::StatFsReply {
            blocks: s.blocks,
            bfree: s.bfree,
            bavail: s.bavail,
            files: s.files,
            ffree: s.ffree,
            bsize: s.bsize,
            namelen: s.namelen,
        }),
        Res::Ok(_) => FuseReply::Ok,
    })
}

fn request_out(id: u64, caller: sem::Caller, op: FuseOp) -> pb::FuseRequest {
    let op = match op {
        FuseOp::Stat { path } => Op::Stat(pb::Stat { path }),
        FuseOp::ReadDir { path } => Op::ReadDir(pb::ReadDir { path }),
        FuseOp::Readlink { path } => Op::Readlink(pb::Readlink { path }),
        FuseOp::Open { path, flags } => Op::Open(pb::Open { path, flags }),
        FuseOp::Read {
            path,
            handle,
            offset,
            size,
        } => Op::Read(pb::Read {
            path,
            handle,
            offset,
            size,
        }),
        FuseOp::Write {
            path,
            handle,
            offset,
            data,
        } => Op::Write(pb::Write {
            path,
            handle,
            offset,
            data,
        }),
        FuseOp::Flush { path, handle } => Op::Flush(pb::Flush { path, handle }),
        FuseOp::Release { path, handle } => Op::Release(pb::Release { path, handle }),
        FuseOp::Fsync {
            path,
            handle,
            datasync,
        } => Op::Fsync(pb::Fsync {
            path,
            handle,
            datasync,
        }),
        FuseOp::Create { path, mode, flags } => Op::Create(pb::Create { path, mode, flags }),
        FuseOp::Mkdir { path, mode } => Op::Mkdir(pb::Mkdir { path, mode }),
        FuseOp::Unlink { path } => Op::Unlink(pb::Unlink { path }),
        FuseOp::Rmdir { path } => Op::Rmdir(pb::Rmdir { path }),
        FuseOp::Rename { from, to, flags } => Op::Rename(pb::Rename { from, to, flags }),
        FuseOp::Symlink { path, target } => Op::Symlink(pb::Symlink { path, target }),
        FuseOp::SetAttr { path, set } => Op::SetAttr(pb::SetAttr {
            path,
            handle: set.handle,
            mode: set.mode,
            uid: set.uid,
            gid: set.gid,
            size: set.size,
            atime_ns: set.atime_ns,
            mtime_ns: set.mtime_ns,
        }),
        FuseOp::StatFs => Op::StatFs(pb::StatFs {}),
    };
    pb::FuseRequest {
        id,
        uid: caller.uid,
        gid: caller.gid,
        pid: caller.pid,
        op: Some(op),
    }
}

fn invalidate_in(i: pb::Invalidate) -> Option<InvalidateTarget> {
    Some(match i.target? {
        pb::invalidate::Target::Path(path) => InvalidateTarget::Path {
            path,
            recursive: i.recursive,
        },
        pb::invalidate::Target::ObjectId(o) if !o.is_empty() => InvalidateTarget::Object(o),
        pb::invalidate::Target::ObjectId(_) => return None,
    })
}

fn event(e: Event) -> Result<pb::FuseServerEvent, Status> {
    Ok(pb::FuseServerEvent { event: Some(e) })
}

/// Pump an attached server until its stream ends. Dropping `link` on the
/// way out detaches the server, failing what it had not answered.
pub async fn run(mut link: FuseLink, mut inbound: Streaming<pb::FuseServerMessage>, out: EventTx) {
    let attached = Event::Attached(pb::Attached {
        generation: link.generation,
        limits: Some(limits_out(link.limits)),
    });
    if out.send(event(attached)).await.is_err() {
        return;
    }
    // Events are read apart from the link, which answers on the same task.
    let mut events = std::mem::replace(&mut link.events, mpsc::channel(1).1);
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Some(FuseEvent::Request { id, caller, op }) => {
                    let msg = event(Event::Request(request_out(id, caller, op)));
                    if out.send(msg).await.is_err() {
                        return;
                    }
                }
                Some(FuseEvent::Cancel { id }) => {
                    let msg = event(Event::Cancel(pb::Cancel { id }));
                    if out.send(msg).await.is_err() {
                        return;
                    }
                }
                Some(FuseEvent::Replaced) => {
                    let _ = out.send(Err(Status::aborted("another FUSE server attached"))).await;
                    return;
                }
                // The mount is gone: the container ended.
                None => return,
            },
            msg = inbound.message() => match msg {
                Ok(Some(m)) => match m.msg {
                    Some(Msg::Response(r)) => link.respond(r.id, response_in(r)),
                    Some(Msg::Invalidate(i)) => match invalidate_in(i) {
                        Some(t) => link.invalidate(t),
                        None => {
                            let _ = out.send(Err(Status::invalid_argument("invalidate names nothing"))).await;
                            return;
                        }
                    },
                    Some(Msg::Attach(_)) | None => {
                        let _ = out.send(Err(Status::invalid_argument("expected a response or invalidate"))).await;
                        return;
                    }
                },
                // The server hung up.
                Ok(None) | Err(_) => return,
            },
        }
    }
}
