//! The FUSE socket (`server.fuse_socket`): hands a container's `/dev/fuse`
//! connection to its server, which gRPC can't do. Same mode, group and
//! callers as the API socket; the protocol is in [`tenantd_client::fuse`].

use std::collections::HashSet;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use tenantd_client::fuse::{MAX_REQUEST, parse_request, send_with_fd};
use tenantd_core::{ContainerKey, Error, Tenantd};
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, warn};

use crate::serve::peer_allowed;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn code(e: &Error) -> &'static str {
    match e {
        Error::InvalidArgument(_) => "INVALID_ARGUMENT",
        Error::NotFound(_) => "NOT_FOUND",
        Error::AlreadyExists(_) => "ALREADY_EXISTS",
        Error::PermissionDenied { .. } => "PERMISSION_DENIED",
        Error::FailedPrecondition(_) => "FAILED_PRECONDITION",
        Error::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
        Error::Unavailable(_) => "UNAVAILABLE",
        Error::Internal(_) => "INTERNAL",
    }
}

async fn read_line(s: &mut UnixStream) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 128];
    while !buf.contains(&b'\n') {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too long",
            ));
        }
    }
    let line = buf.split(|&b| b == b'\n').next().unwrap_or_default();
    String::from_utf8(line.to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))
}

async fn attach(t: &Tenantd, line: &str) -> Result<OwnedFd, Error> {
    let (tenant, sandbox, container) = parse_request(line)
        .ok_or_else(|| Error::invalid("expected: attach-fuse <tenant> <sandbox> <container>"))?;
    let key: ContainerKey = format!("{tenant}.{sandbox}.{container}").parse()?;
    t.attach_fuse(&key).await
}

async fn handle(mut s: UnixStream, t: Arc<Tenantd>) -> io::Result<()> {
    let line = tokio::time::timeout(IO_TIMEOUT, read_line(&mut s))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no request"))??;
    let reply = attach(&t, &line).await;
    let s = s.into_std()?;
    s.set_nonblocking(false)?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    tokio::task::spawn_blocking(move || match reply {
        Ok(fd) => send_with_fd(&s, b"ok\n", fd.as_raw_fd()),
        Err(e) => {
            debug!(request = line, error = %e, "FUSE attach refused");
            let msg = e.to_string().replace(['\n', '\r'], " ");
            (&s).write_all(format!("err {} {msg}\n", code(&e)).as_bytes())
        }
    })
    .await
    .map_err(io::Error::other)?
}

/// Serve the FUSE socket until the task is dropped.
pub async fn serve(l: UnixListener, allowed: Arc<HashSet<u32>>, tenantd: Arc<Tenantd>) {
    loop {
        let s = match l.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                warn!(error = %e, "FUSE socket accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !peer_allowed(&s, &allowed) {
            continue;
        }
        let t = tenantd.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(s, t).await {
                debug!(error = %e, "FUSE socket connection failed");
            }
        });
    }
}
