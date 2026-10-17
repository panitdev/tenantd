//! The thin unsafe layer: project ID attributes, XFS quota commands and the
//! punch-hole probe.
//!
//! Quota commands go through `quotactl_fd(2)` (Linux 5.14+) on an open
//! directory of the filesystem, so no block device path is needed.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FsXattr {
    pub xflags: u32,
    pub extsize: u32,
    pub nextents: u32,
    pub projid: u32,
    pub cowextsize: u32,
    pub pad: [u8; 8],
}

const FS_IOC_FSGETXATTR: libc::c_ulong = 0x801c_581f; // _IOR('X', 31, struct fsxattr)
const FS_IOC_FSSETXATTR: libc::c_ulong = 0x401c_5820; // _IOW('X', 32, struct fsxattr)
pub const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;

pub fn get_xattr(f: &File) -> io::Result<FsXattr> {
    let mut x = FsXattr::default();
    // SAFETY: the ioctl writes one `struct fsxattr` into `x`.
    let r = unsafe {
        libc::ioctl(
            f.as_raw_fd(),
            FS_IOC_FSGETXATTR as _,
            &mut x as *mut FsXattr,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(x)
    }
}

pub fn set_xattr(f: &File, x: &FsXattr) -> io::Result<()> {
    // SAFETY: the ioctl reads one `struct fsxattr` from `x`.
    let r = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_FSSETXATTR as _, x as *const FsXattr) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set the project ID; on directories also the inherit flag, so everything
/// created below is charged to the same project.
pub fn set_project(f: &File, project: u32, is_dir: bool) -> io::Result<()> {
    let mut x = get_xattr(f)?;
    let want_flags = if is_dir {
        x.xflags | FS_XFLAG_PROJINHERIT
    } else {
        x.xflags
    };
    if x.projid == project && x.xflags == want_flags {
        return Ok(());
    }
    x.projid = project;
    x.xflags = want_flags;
    set_xattr(f, &x)
}

// <linux/dqblk_xfs.h>
const fn xqm_cmd(x: u32) -> u32 {
    (('X' as u32) << 8) + x
}
const Q_XGETQUOTA: u32 = xqm_cmd(3);
const Q_XSETQLIM: u32 = xqm_cmd(4);
const Q_XGETQSTATV: u32 = xqm_cmd(8);
const PRJQUOTA: u32 = 2;
const fn qcmd(cmd: u32, kind: u32) -> libc::c_int {
    ((cmd << 8) | (kind & 0xff)) as libc::c_int
}

const FS_DQUOT_VERSION: i8 = 1;
const FS_PROJ_QUOTA: i8 = 2;
const FS_DQ_BSOFT: u16 = 1 << 2;
const FS_DQ_BHARD: u16 = 1 << 3;
pub const FS_QUOTA_PDQ_ACCT: u16 = 1 << 4;
pub const FS_QUOTA_PDQ_ENFD: u16 = 1 << 5;
const FS_QSTATV_VERSION1: i8 = 1;
/// Quota block counts are in 512-byte basic blocks.
pub const BB: u64 = 512;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FsDiskQuota {
    pub version: i8,
    pub flags: i8,
    pub fieldmask: u16,
    pub id: u32,
    pub blk_hardlimit: u64,
    pub blk_softlimit: u64,
    pub ino_hardlimit: u64,
    pub ino_softlimit: u64,
    pub bcount: u64,
    pub icount: u64,
    pub itimer: i32,
    pub btimer: i32,
    pub iwarns: u16,
    pub bwarns: u16,
    pub itimer_hi: i8,
    pub btimer_hi: i8,
    pub rtbtimer_hi: i8,
    pub padding2: i8,
    pub rtb_hardlimit: u64,
    pub rtb_softlimit: u64,
    pub rtbcount: u64,
    pub rtbtimer: i32,
    pub rtbwarns: u16,
    pub padding3: i16,
    pub padding4: [u8; 8],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FsQfilestatv {
    pub ino: u64,
    pub nblks: u64,
    pub nextents: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct FsQuotaStatv {
    pub version: i8,
    pub pad1: u8,
    pub flags: u16,
    pub incoredqs: u32,
    pub uquota: FsQfilestatv,
    pub gquota: FsQfilestatv,
    pub pquota: FsQfilestatv,
    pub btimelimit: i32,
    pub itimelimit: i32,
    pub rtbtimelimit: i32,
    pub bwarnlimit: u16,
    pub iwarnlimit: u16,
    pub rtbwarnlimit: u16,
    pub pad3: u16,
    pub pad4: u32,
    pub pad2: [u64; 7],
}

const _: () = assert!(std::mem::size_of::<FsXattr>() == 28);
const _: () = assert!(std::mem::size_of::<FsDiskQuota>() == 112);
const _: () = assert!(std::mem::size_of::<FsQuotaStatv>() == 160);

const SYS_QUOTACTL_FD: libc::c_long = 443;

fn quotactl_fd(f: &File, cmd: libc::c_int, id: u32, addr: *mut libc::c_void) -> io::Result<()> {
    // SAFETY: `addr` points to a struct of the size the command expects.
    let r = unsafe { libc::syscall(SYS_QUOTACTL_FD, f.as_raw_fd(), cmd, id, addr) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn quota_state(f: &File) -> io::Result<FsQuotaStatv> {
    let mut s = FsQuotaStatv {
        version: FS_QSTATV_VERSION1,
        ..Default::default()
    };
    quotactl_fd(
        f,
        qcmd(Q_XGETQSTATV, PRJQUOTA),
        0,
        &mut s as *mut _ as *mut _,
    )?;
    Ok(s)
}

/// Returns (bytes used, hard limit in bytes; 0 = none).
pub fn get_project_quota(f: &File, project: u32) -> io::Result<(u64, u64)> {
    let mut d = FsDiskQuota::default();
    match quotactl_fd(
        f,
        qcmd(Q_XGETQUOTA, PRJQUOTA),
        project,
        &mut d as *mut _ as *mut _,
    ) {
        Ok(()) => Ok((d.bcount * BB, d.blk_hardlimit * BB)),
        // No dquot yet: nothing charged and no limit.
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok((0, 0)),
        Err(e) => Err(e),
    }
}

/// Set soft and hard block limits; 0 removes the limit. Bytes are rounded
/// up to whole basic blocks.
pub fn set_project_limit(f: &File, project: u32, bytes: u64) -> io::Result<()> {
    let blocks = bytes.div_ceil(BB);
    let mut d = FsDiskQuota {
        version: FS_DQUOT_VERSION,
        flags: FS_PROJ_QUOTA,
        fieldmask: FS_DQ_BSOFT | FS_DQ_BHARD,
        id: project,
        blk_hardlimit: blocks,
        blk_softlimit: blocks,
        ..Default::default()
    };
    quotactl_fd(
        f,
        qcmd(Q_XSETQLIM, PRJQUOTA),
        project,
        &mut d as *mut _ as *mut _,
    )
}

pub const XFS_SUPER_MAGIC: i64 = 0x5846_5342;

pub fn fs_magic(f: &File) -> io::Result<i64> {
    // SAFETY: fstatfs fills the zeroed struct.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatfs(f.as_raw_fd(), &mut s) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(s.f_type as i64)
    }
}

/// Free `[offset, offset + len)` of `f` without changing its size.
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
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
