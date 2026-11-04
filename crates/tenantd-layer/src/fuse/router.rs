//! Between the kernel side of a container's FUSE mount and the caller's
//! server: requests go to the attached [`FuseLink`], or wait in a queue
//! while none is attached; each is completed by the server's response or,
//! if its server goes away first, with `EIO`. A write is never replayed on
//! another server, so only requests that were never sent are carried over.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tenantd_core::fuse::{
    Caller, EIO, FuseError, FuseEvent, FuseLimits, FuseLink, FuseOp, FuseResult, FuseSession,
    InvalidateTarget,
};
use tokio::sync::mpsc;

/// Requests waiting for a server, beyond which new ones fail rather than
/// pile up without bound.
const MAX_QUEUED: usize = 4096;

/// Completes a request. Runs outside the router's lock.
pub type Done = Box<dyn FnOnce(FuseResult) + Send>;
type InvalidateHook = Box<dyn Fn(InvalidateTarget) + Send + Sync>;

struct Queued {
    id: u64,
    caller: Caller,
    op: FuseOp,
    done: Done,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    generation: u64,
    closed: bool,
    server: Option<Server>,
    inflight: HashMap<u64, Done>,
    queued: VecDeque<Queued>,
}

struct Server {
    events: mpsc::Sender<FuseEvent>,
    limits: FuseLimits,
}

pub struct Router {
    inner: Mutex<Inner>,
    /// Told when a server invalidates; set by the filesystem.
    on_invalidate: Mutex<Option<InvalidateHook>>,
}

fn fail(errno: i32) -> FuseResult {
    Err(FuseError::new(errno))
}

fn run(done: Vec<(Done, FuseResult)>) {
    for (d, r) in done {
        d(r);
    }
}

impl Inner {
    /// Send queued requests while the server has room.
    fn pump(&mut self, failed: &mut Vec<(Done, FuseResult)>) {
        while let Some(server) = &self.server {
            if self.inflight.len() >= server.limits.max_inflight as usize {
                return;
            }
            let Some(q) = self.queued.pop_front() else {
                return;
            };
            let ev = FuseEvent::Request {
                id: q.id,
                caller: q.caller,
                op: q.op,
            };
            match server.events.try_send(ev) {
                Ok(()) => {
                    self.inflight.insert(q.id, q.done);
                }
                Err(_) => {
                    // The receiver is gone: the link's drop will detach it.
                    failed.push((q.done, fail(EIO)));
                }
            }
        }
    }

    fn fail_inflight(&mut self, failed: &mut Vec<(Done, FuseResult)>) {
        for (_, d) in self.inflight.drain() {
            failed.push((d, fail(EIO)));
        }
    }
}

impl Router {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            on_invalidate: Mutex::new(None),
        })
    }

    pub fn set_invalidate_hook(&self, f: impl Fn(InvalidateTarget) + Send + Sync + 'static) {
        *self.on_invalidate.lock().unwrap() = Some(Box::new(f));
    }

    /// The limits of the attached server, or tenantd's own when none is.
    pub fn limits(&self) -> FuseLimits {
        match &self.inner.lock().unwrap().server {
            Some(s) => s.limits,
            None => FuseLimits::SERVER,
        }
    }

    #[cfg(test)]
    pub fn has_server(&self) -> bool {
        self.inner.lock().unwrap().server.is_some()
    }

    /// Send `op` to the server, or queue it until one attaches. `done`
    /// runs exactly once, on whichever thread completes the request.
    pub fn submit(&self, caller: Caller, op: FuseOp, done: Done) {
        let mut failed = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            if g.closed {
                failed.push((done, fail(EIO)));
            } else if g.queued.len() >= MAX_QUEUED {
                failed.push((done, fail(libc::EAGAIN)));
            } else {
                g.next_id += 1;
                let id = g.next_id;
                g.queued.push_back(Queued {
                    id,
                    caller,
                    op,
                    done,
                });
                g.pump(&mut failed);
            }
        }
        run(failed);
    }

    /// Attach a server, replacing the current one. Whatever the old server
    /// had not answered fails with `EIO`; requests still queued go to the
    /// new one.
    pub fn attach(self: &Arc<Self>, theirs: FuseLimits) -> Option<FuseLink> {
        let limits = FuseLimits::SERVER.negotiate(theirs);
        let mut failed = Vec::new();
        let link = {
            let mut g = self.inner.lock().unwrap();
            if g.closed {
                return None;
            }
            if let Some(old) = g.server.take() {
                // One slot beyond `max_inflight` is kept for this.
                let _ = old.events.try_send(FuseEvent::Replaced);
            }
            g.fail_inflight(&mut failed);
            g.generation += 1;
            let (tx, rx) = mpsc::channel(limits.max_inflight as usize + 1);
            g.server = Some(Server { events: tx, limits });
            g.pump(&mut failed);
            FuseLink::new(g.generation, limits, rx, self.clone())
        };
        run(failed);
        Some(link)
    }

    /// The mount is going away: fail everything, now and later.
    pub fn close(&self) {
        let mut failed = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            g.closed = true;
            g.server = None;
            g.fail_inflight(&mut failed);
            for q in g.queued.drain(..) {
                failed.push((q.done, fail(EIO)));
            }
        }
        run(failed);
    }
}

impl FuseSession for Router {
    fn respond(&self, generation: u64, id: u64, result: FuseResult) {
        let mut failed = Vec::new();
        let done = {
            let mut g = self.inner.lock().unwrap();
            if g.generation != generation {
                return;
            }
            let d = g.inflight.remove(&id);
            g.pump(&mut failed);
            d
        };
        run(failed);
        if let Some(d) = done {
            d(result);
        }
    }

    fn invalidate(&self, generation: u64, target: InvalidateTarget) {
        if self.inner.lock().unwrap().generation != generation {
            return;
        }
        if let Some(f) = &*self.on_invalidate.lock().unwrap() {
            f(target);
        }
    }

    fn detach(&self, generation: u64) {
        let mut failed = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            if g.generation != generation || g.server.is_none() {
                return;
            }
            g.server = None;
            g.fail_inflight(&mut failed);
        }
        run(failed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;
    use tenantd_core::fuse::FuseReply;

    fn stat(p: &str) -> FuseOp {
        FuseOp::Stat { path: p.into() }
    }

    fn submit(r: &Router, p: &str) -> std_mpsc::Receiver<FuseResult> {
        let (tx, rx) = std_mpsc::channel();
        r.submit(
            Caller::default(),
            stat(p),
            Box::new(move |res| tx.send(res).unwrap()),
        );
        rx
    }

    fn next_id(link: &mut FuseLink) -> (u64, FuseOp) {
        match link.events.try_recv().unwrap() {
            FuseEvent::Request { id, op, .. } => (id, op),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn queued_until_a_server_attaches_then_answered() {
        let r = Router::new();
        let waiting = submit(&r, "/a");
        assert!(waiting.try_recv().is_err(), "waits with no server");
        let mut link = r.attach(FuseLimits::SERVER).unwrap();
        let (id, op) = next_id(&mut link);
        assert_eq!(op, stat("/a"));
        link.respond(id, Ok(FuseReply::Ok));
        assert_eq!(waiting.try_recv().unwrap(), Ok(FuseReply::Ok));
        // Unknown and repeated ids are ignored.
        link.respond(id, Ok(FuseReply::Ok));
        link.respond(999, Ok(FuseReply::Ok));
    }

    #[test]
    fn replacing_a_server_fails_what_it_held_and_keeps_the_queue() {
        let r = Router::new();
        let mut one = r.attach(FuseLimits {
            max_read: 0,
            max_write: 0,
            max_inflight: 1,
        });
        let first = submit(&r, "/sent");
        let second = submit(&r, "/queued");
        let one_link = one.as_mut().unwrap();
        next_id(one_link);
        assert!(one_link.events.try_recv().is_err(), "window of one");

        let mut two = r.attach(FuseLimits::SERVER).unwrap();
        assert_eq!(first.try_recv().unwrap().unwrap_err().errno, EIO);
        assert!(matches!(
            one_link.events.try_recv().unwrap(),
            FuseEvent::Replaced
        ));
        let (id, op) = next_id(&mut two);
        assert_eq!(op, stat("/queued"), "never-sent requests move over");
        two.respond(id, Ok(FuseReply::Ok));
        assert_eq!(second.try_recv().unwrap(), Ok(FuseReply::Ok));
        // The old link answering late changes nothing.
        one_link.respond(id, fail(libc::EACCES));
    }

    #[test]
    fn dropping_the_link_fails_in_flight_and_queues_new_requests() {
        let r = Router::new();
        let mut link = r.attach(FuseLimits::SERVER).unwrap();
        let sent = submit(&r, "/sent");
        next_id(&mut link);
        drop(link);
        assert_eq!(sent.try_recv().unwrap().unwrap_err().errno, EIO);
        assert!(!r.has_server());
        let later = submit(&r, "/later");
        assert!(later.try_recv().is_err());
        let mut again = r.attach(FuseLimits::SERVER).unwrap();
        assert_eq!(next_id(&mut again).1, stat("/later"));
    }

    #[test]
    fn close_fails_everything_and_refuses_servers() {
        let r = Router::new();
        let queued = submit(&r, "/q");
        r.close();
        assert_eq!(queued.try_recv().unwrap().unwrap_err().errno, EIO);
        assert_eq!(submit(&r, "/x").try_recv().unwrap().unwrap_err().errno, EIO);
        assert!(r.attach(FuseLimits::SERVER).is_none());
    }
}
