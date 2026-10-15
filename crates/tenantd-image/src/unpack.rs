//! Unpack one layer tarball into its own directory, ready to be an overlay
//! lowerdir. OCI whiteouts become overlayfs whiteouts:
//! `.wh.<name>` -> a 0/0 character device, `.wh..wh..opq` -> the
//! `trusted.overlay.opaque=y` xattr on the directory.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";
/// Mode for directories a layer implies but doesn't list, including the layer
/// root. tenantd runs with `UMask=0077`, so anything left to the umask would
/// be 0700 and unreadable to a non-root user inside the sandbox.
const IMPLIED_DIR_MODE: u32 = 0o755;

fn create_implied_dir(p: &Path) -> io::Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(IMPLIED_DIR_MODE))
}

pub fn decompressor(path: &Path) -> io::Result<Box<dyn Read>> {
    let mut f = BufReader::new(File::open(path)?);
    let mut magic = [0u8; 4];
    let n = {
        use std::io::BufRead;
        let buf = f.fill_buf()?;
        let n = buf.len().min(4);
        magic[..n].copy_from_slice(&buf[..n]);
        n
    };
    Ok(match &magic[..n] {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::GzDecoder::new(f)),
        [0x28, 0xb5, 0x2f, 0xfd] => Box::new(zstd::stream::read::Decoder::with_buffer(f)?),
        _ => Box::new(f),
    })
}

/// Relative path with only normal components; `None` for anything else.
fn clean(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::RootDir => {}
            _ => return None,
        }
    }
    Some(out)
}

/// Create `rel` under `root` one component at a time, refusing to follow a
/// symlink, so a layer can't plant `a -> /etc` and then whiteout `a/x`.
fn safe_dir(root: &Path, rel: &Path) -> io::Result<PathBuf> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(io::Error::other(format!("{} is a symlink", cur.display())));
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                fs::remove_file(&cur)?;
                create_implied_dir(&cur)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => create_implied_dir(&cur)?,
            Err(e) => return Err(e),
        }
    }
    Ok(cur)
}

/// Create the missing directories of `rel` under `root` with
/// `IMPLIED_DIR_MODE`; tar would create them under the umask. Anything already
/// there, symlinks included, is left for tar's own checks.
fn implied_parents(root: &Path, rel: &Path) -> io::Result<()> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => create_implied_dir(&cur)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn whiteout(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(_) => {}
    }
    let c = cpath(path)?;
    // SAFETY: valid path; creates a 0/0 character device (overlay whiteout).
    let r = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR, libc::makedev(0, 0)) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_opaque(dir: &Path) -> io::Result<()> {
    let c = cpath(dir)?;
    let name = CString::new("trusted.overlay.opaque").unwrap();
    // SAFETY: valid strings; the value is one byte.
    let r = unsafe { libc::lsetxattr(c.as_ptr(), name.as_ptr(), b"y".as_ptr() as *const _, 1, 0) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn unpack_layer(blob: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    fs::set_permissions(dst, fs::Permissions::from_mode(IMPLIED_DIR_MODE))?;
    let mut ar = tar::Archive::new(decompressor(blob)?);
    ar.set_preserve_permissions(true);
    // SAFETY: geteuid has no preconditions.
    ar.set_preserve_ownerships(unsafe { libc::geteuid() } == 0);
    ar.set_unpack_xattrs(true);
    ar.set_preserve_mtime(true);
    ar.set_overwrite(true);
    for entry in ar.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.into_owned();
        let Some(rel) = clean(&raw) else {
            return Err(io::Error::other(format!(
                "layer entry {} escapes the layer",
                raw.display()
            )));
        };
        let Some(name) = rel.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            // `./` itself: the layer root takes its mode, never its owner.
            if entry.header().entry_type().is_dir() {
                let mode = entry.header().mode()? & 0o7777;
                fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
            }
            continue;
        };
        let parent = rel.parent().unwrap_or(Path::new(""));
        if name == OPAQUE {
            set_opaque(&safe_dir(dst, parent)?)?;
        } else if let Some(hidden) = name.strip_prefix(WHITEOUT_PREFIX) {
            if hidden.is_empty() || hidden == "." || hidden == ".." || hidden.contains('/') {
                return Err(io::Error::other(format!("bad whiteout {}", raw.display())));
            }
            whiteout(&safe_dir(dst, parent)?.join(hidden))?;
        } else {
            implied_parents(dst, parent)?;
            entry.unpack_in(dst)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(entries: &[(&str, Option<&str>, Option<&str>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data, link) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o755);
            match (data, link) {
                (_, Some(target)) => {
                    h.set_entry_type(tar::EntryType::Symlink);
                    h.set_size(0);
                    b.append_link(&mut h, path, target).unwrap();
                }
                (Some(d), None) => {
                    h.set_size(d.len() as u64);
                    h.set_entry_type(tar::EntryType::Regular);
                    b.append_data(&mut h, path, d.as_bytes()).unwrap();
                }
                (None, None) => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    b.append_data(&mut h, path, &[][..]).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn unpacks_gzip_and_zstd() {
        let d = tempfile::tempdir().unwrap();
        let tar = layer(&[
            ("etc/", None, None),
            ("etc/hostname", Some("box"), None),
            ("bin/sh", Some("#!"), None),
        ]);
        for (i, blob) in [
            gz(&tar),
            zstd::encode_all(&tar[..], 1).unwrap(),
            tar.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            let src = d.path().join(format!("blob{i}"));
            fs::write(&src, blob).unwrap();
            let dst = d.path().join(format!("out{i}"));
            unpack_layer(&src, &dst).unwrap();
            assert_eq!(fs::read_to_string(dst.join("etc/hostname")).unwrap(), "box");
            assert!(dst.join("bin/sh").exists());
        }
    }

    #[test]
    fn implied_dirs_ignore_the_daemon_umask() {
        // tenantd runs with UMask=0077; a 0700 layer root or implied parent
        // locks non-root image users out of their own rootfs.
        // SAFETY: umask has no preconditions.
        unsafe { libc::umask(0o077) };
        let d = tempfile::tempdir().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let src = d.path().join("blob");
        fs::write(&src, layer(&[("usr/local/bin/entry", Some("#!"), None)])).unwrap();
        let dst = d.path().join("out");
        unpack_layer(&src, &dst).unwrap();
        for p in ["", "usr", "usr/local", "usr/local/bin"] {
            assert_eq!(mode(&dst.join(p)), 0o755, "{p:?}");
        }

        // An explicit `./` entry sets the root's mode.
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o750);
        h.set_size(0);
        b.append_data(&mut h, "./", &[][..]).unwrap();
        fs::write(&src, b.into_inner().unwrap()).unwrap();
        let dst = d.path().join("out2");
        unpack_layer(&src, &dst).unwrap();
        assert_eq!(mode(&dst), 0o750);
    }

    #[test]
    fn whiteouts_cannot_escape_through_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("keep"), "x").unwrap();
        let tar = layer(&[
            ("evil", None, Some(victim.to_str().unwrap())),
            ("evil/.wh.keep", Some(""), None),
        ]);
        let src = d.path().join("blob");
        fs::write(&src, tar).unwrap();
        assert!(unpack_layer(&src, &d.path().join("out")).is_err());
        assert!(victim.join("keep").exists());
    }

    #[test]
    fn rejects_parent_traversal() {
        assert!(clean(Path::new("../etc/passwd")).is_none());
        assert_eq!(clean(Path::new("./a/b")).unwrap(), PathBuf::from("a/b"));
        assert_eq!(clean(Path::new("/a")).unwrap(), PathBuf::from("a"));
    }

    /// mknod and trusted.* xattrs need real root.
    #[test]
    #[ignore]
    fn converts_whiteouts() {
        let d = tempfile::tempdir().unwrap();
        let tar = layer(&[
            ("a/.wh..wh..opq", Some(""), None),
            ("a/.wh.gone", Some(""), None),
        ]);
        let src = d.path().join("blob");
        fs::write(&src, tar).unwrap();
        let dst = d.path().join("out");
        unpack_layer(&src, &dst).unwrap();
        use std::os::unix::fs::FileTypeExt;
        assert!(
            fs::symlink_metadata(dst.join("a/gone"))
                .unwrap()
                .file_type()
                .is_char_device()
        );
    }
}
