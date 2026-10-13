//! Mount helpers and a `/proc/self/mountinfo` reader.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::other("path contains NUL"))
}

pub fn mount(
    source: &str,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let src = CString::new(source).map_err(io::Error::other)?;
    let tgt = cstr(target)?;
    let fs = fstype
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    // SAFETY: all pointers are valid NUL-terminated strings or null.
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fs.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr() as *const libc::c_void),
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Unmount; a busy mount is detached instead.
pub fn unmount(target: &Path) -> io::Result<()> {
    let tgt = cstr(target)?;
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::umount2(tgt.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EINVAL) | Some(libc::ENOENT) => Ok(()), // not mounted
        Some(libc::EBUSY) => {
            // SAFETY: as above.
            if unsafe { libc::umount2(tgt.as_ptr(), libc::MNT_DETACH) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        _ => Err(e),
    }
}

/// Undo mountinfo's octal escapes (`\040` for space, etc.).
fn unescape(s: &str) -> PathBuf {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    PathBuf::from(std::ffi::OsStr::from_bytes(&out))
}

pub fn parse_mountpoints(mountinfo: &str) -> Vec<PathBuf> {
    mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(unescape)
        .collect()
}

/// Mount points at or below `dir`, deepest first.
pub fn mounts_under(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let info = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut v: Vec<PathBuf> = parse_mountpoints(&info)
        .into_iter()
        .filter(|m| m.starts_with(dir))
        .collect();
    v.sort_by_key(|m| std::cmp::Reverse(m.components().count()));
    v.dedup();
    Ok(v)
}

pub fn is_mountpoint(p: &Path) -> io::Result<bool> {
    Ok(mounts_under(p)?.iter().any(|m| m == p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mountinfo() {
        let info = "36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw\n\
                    37 35 0:5 / /data/tenants/a/sandboxes/b\\040c/rootfs rw - overlay overlay rw,lowerdir=x\n";
        assert_eq!(
            parse_mountpoints(info),
            vec![
                PathBuf::from("/mnt/parent"),
                PathBuf::from("/data/tenants/a/sandboxes/b c/rootfs")
            ]
        );
    }
}
