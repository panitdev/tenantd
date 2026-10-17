//! The thin unsafe layer: inotify and hole punching.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub const IN_MODIFY: u32 = libc::IN_MODIFY;
pub const IN_IGNORED: u32 = libc::IN_IGNORED;
pub const IN_Q_OVERFLOW: u32 = libc::IN_Q_OVERFLOW;

/// A blocking inotify instance (reads park the watcher thread).
pub fn inotify_init() -> io::Result<OwnedFd> {
    // SAFETY: no pointers; the returned fd is owned below.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn add_watch(fd: &OwnedFd, path: &Path, mask: u32) -> io::Result<i32> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: c is a valid NUL-terminated string for the call's duration.
    let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), mask) };
    if wd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(wd)
}

pub fn rm_watch(fd: &OwnedFd, wd: i32) {
    // SAFETY: plain syscall; a stale wd only yields EINVAL.
    unsafe { libc::inotify_rm_watch(fd.as_raw_fd(), wd) };
}

/// One decoded inotify event (the name, which file watches never carry,
/// is skipped).
pub struct Event {
    pub wd: i32,
    pub mask: u32,
}

/// Block for the next batch of events.
pub fn read_events(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<Vec<Event>> {
    // SAFETY: buf is valid for writes of buf.len() bytes.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let (n, head) = (n as usize, std::mem::size_of::<libc::inotify_event>());
    let mut out = Vec::new();
    let mut off = 0;
    while off + head <= n {
        // SAFETY: the kernel wrote a whole inotify_event header at `off`;
        // read_unaligned copes with the byte buffer's alignment.
        let ev: libc::inotify_event =
            unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
        out.push(Event {
            wd: ev.wd,
            mask: ev.mask,
        });
        off += head + ev.len as usize;
    }
    Ok(out)
}

/// Free the blocks of `[offset, offset + len)` without changing the size.
pub fn punch_hole(f: &File, offset: u64, len: u64) -> io::Result<()> {
    // SAFETY: plain syscall on an fd we own.
    let r = unsafe {
        libc::fallocate(
            f.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as libc::off_t,
            len as libc::off_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
