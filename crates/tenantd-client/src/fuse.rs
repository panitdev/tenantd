//! The FUSE socket: how a caller takes a container's `/dev/fuse`
//! connection, which gRPC can't carry.
//!
//! One request per connection. The client sends
//! `attach-fuse <tenant> <sandbox> <container>\n`; tenantd answers `ok\n`
//! with the fd attached as `SCM_RIGHTS`, or `err <CODE> <message>\n` where
//! `CODE` is a gRPC code name such as `NOT_FOUND`.
//!
//! ```no_run
//! # fn f() -> std::io::Result<()> {
//! let fd = tenantd_client::fuse::attach_fuse(
//!     tenantd_client::fuse::DEFAULT_SOCKET, "acme", "box1", "s1")?;
//! // Serve FUSE on `fd`, then call Containers.StartContainer.
//! # Ok(()) }
//! ```

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_SOCKET: &str = "/run/tenantd/fuse.sock";

/// Longest request line tenantd reads.
pub const MAX_REQUEST: usize = 512;

/// A refusal from tenantd, inside the `io::Error` that
/// [`attach_fuse`] returns (`io::ErrorKind::Other`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachError {
    /// A gRPC code name, e.g. `FAILED_PRECONDITION`.
    pub code: String,
    pub message: String,
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.to_lowercase(), self.message)
    }
}

impl std::error::Error for AttachError {}

fn plain(s: &str) -> bool {
    !s.is_empty() && !s.bytes().any(|b| b.is_ascii_whitespace() || b == 0)
}

/// The request line for a container.
pub fn request(tenant: &str, sandbox: &str, container: &str) -> io::Result<String> {
    if ![tenant, sandbox, container].iter().all(|s| plain(s)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tenant, sandbox and container must be non-empty without whitespace",
        ));
    }
    Ok(format!("attach-fuse {tenant} {sandbox} {container}\n"))
}

/// Parse a request line (without its newline) into (tenant, sandbox,
/// container).
pub fn parse_request(line: &str) -> Option<(&str, &str, &str)> {
    let mut w = line.split(' ');
    match (w.next(), w.next(), w.next(), w.next(), w.next()) {
        (Some("attach-fuse"), Some(t), Some(s), Some(c), None)
            if [t, s, c].iter().all(|x| plain(x)) =>
        {
            Some((t, s, c))
        }
        _ => None,
    }
}

/// Take the FUSE connection of `tenant.sandbox.container` from tenantd's
/// FUSE socket. Blocking; gives up after 30 seconds.
pub fn attach_fuse(
    socket: impl AsRef<Path>,
    tenant: &str,
    sandbox: &str,
    container: &str,
) -> io::Result<OwnedFd> {
    let line = request(tenant, sandbox, container)?;
    let mut s = UnixStream::connect(socket)?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;
    s.write_all(line.as_bytes())?;
    let (mut reply, fd) = recv_with_fd(&s)?;
    while !reply.contains(&b'\n') && reply.len() < 4096 {
        let mut buf = [0u8; 512];
        match s.read(&mut buf)? {
            0 => break,
            n => reply.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&reply);
    let text = text.lines().next().unwrap_or_default();
    match (text, fd) {
        ("ok", Some(fd)) => Ok(fd),
        ("ok", None) => Err(io::Error::other("tenantd replied ok without an fd")),
        (err, _) => {
            let rest = err.strip_prefix("err ").unwrap_or(err);
            let (code, message) = rest.split_once(' ').unwrap_or((rest, ""));
            Err(io::Error::other(AttachError {
                code: code.to_string(),
                message: message.to_string(),
            }))
        }
    }
}

/// Space for one fd's control message, aligned for `cmsghdr`.
#[repr(C, align(8))]
struct CmsgBuf([u8; 64]);

/// One `recvmsg`: the bytes read and the fd attached to them, if any.
fn recv_with_fd(s: &UnixStream) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut data = vec![0u8; 512];
    let mut cbuf = CmsgBuf([0; 64]);
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    // SAFETY: an all-zero msghdr is valid; the pointers set below outlive
    // the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.0.as_mut_ptr().cast();
    msg.msg_controllen = cbuf.0.len() as _;
    let n = loop {
        // SAFETY: valid socket and msghdr.
        let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    data.truncate(n);
    let mut fd = None;
    // SAFETY: msg was filled by recvmsg; the CMSG_* walk stays inside it.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let first = libc::CMSG_DATA(c).cast::<RawFd>();
                for i in 0..payload / std::mem::size_of::<RawFd>() {
                    let got = OwnedFd::from_raw_fd(first.add(i).read_unaligned());
                    // Keep the first; any extra is closed on drop.
                    if fd.is_none() {
                        fd = Some(got);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok((data, fd))
}

/// Server side: send `line` with `fd` attached, in one `sendmsg`. Blocking.
pub fn send_with_fd(s: &UnixStream, line: &[u8], fd: RawFd) -> io::Result<()> {
    let mut cbuf = CmsgBuf([0; 64]);
    let mut iov = libc::iovec {
        iov_base: line.as_ptr() as *mut _,
        iov_len: line.len(),
    };
    // SAFETY: as in `recv_with_fd`.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.0.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE is a pure size computation.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as _;
    // SAFETY: the buffer holds one control message of CMSG_SPACE(4) bytes.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(c).cast::<RawFd>().write_unaligned(fd);
    }
    let sent = loop {
        // SAFETY: valid socket and msghdr.
        let n = unsafe { libc::sendmsg(s.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    // The fd went with the first byte; the rest needs no ancillary data.
    let mut s = s;
    s.write_all(&line[sent..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_lines() {
        assert_eq!(request("t", "s", "c").unwrap(), "attach-fuse t s c\n");
        assert!(request("t", "s c", "c").is_err());
        assert!(request("", "s", "c").is_err());
        assert_eq!(parse_request("attach-fuse t s c"), Some(("t", "s", "c")));
        for bad in [
            "attach-fuse t s",
            "attach-fuse t s c d",
            "attach t s c",
            "attach-fuse t  c",
        ] {
            assert_eq!(parse_request(bad), None, "{bad}");
        }
    }

    #[test]
    fn fd_crosses_the_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, mut w) = io::pipe().unwrap();
        send_with_fd(&a, b"ok\n", r.as_raw_fd()).unwrap();
        drop(r);
        let (data, fd) = recv_with_fd(&b).unwrap();
        assert_eq!(data, b"ok\n");
        // The received fd is the pipe's read end.
        w.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        std::fs::File::from(fd.unwrap())
            .read_exact(&mut got)
            .unwrap();
        assert_eq!(&got, b"x");
    }
}
