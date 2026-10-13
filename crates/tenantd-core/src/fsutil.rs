//! Small std-only filesystem helpers shared by the host backends.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// `remove_dir_all` that never crosses a mount: if anything below `root`
/// lives on another device (an overlay still mounted, a bind mount), it
/// fails before deleting through it. Missing `root` is success.
pub fn remove_tree_one_fs(root: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.is_dir() {
        return fs::remove_file(root);
    }
    check_one_fs(root, meta.dev())?;
    fs::remove_dir_all(root)
}

fn check_one_fs(dir: &Path, dev: u64) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.dev() != dev {
            return Err(io::Error::other(format!(
                "{} is on another filesystem (still mounted?)",
                entry.path().display()
            )));
        }
        if meta.is_dir() {
            check_one_fs(&entry.path(), dev)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_tree() {
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("t");
        fs::create_dir_all(t.join("a/b")).unwrap();
        fs::write(t.join("a/b/f"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc", t.join("a/link")).unwrap();
        remove_tree_one_fs(&t).unwrap();
        assert!(!t.exists());
        assert!(Path::new("/etc").exists());
        remove_tree_one_fs(&t).unwrap();
    }
}
