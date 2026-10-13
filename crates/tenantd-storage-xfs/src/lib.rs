//! XFS project quota. Each tenant directory carries a project ID with the
//! inherit flag; the quota on that project is the tenant's storage limit.

mod sys;

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tenantd_core::backend::{StorageBackend, Usage};
use tenantd_core::error::Context;
use tenantd_core::fsutil::remove_tree_one_fs;
use tenantd_core::{Bytes, Error, ProjectId, Result, TenantId};
use tracing::{info, warn};

pub struct XfsProjectQuota {
    root: PathBuf,
}

impl XfsProjectQuota {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn tenants_dir(&self) -> PathBuf {
        self.root.join("tenants")
    }

    fn open_root(&self) -> Result<File> {
        File::open(&self.root).context(format!("opening {}", self.root.display()))
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::internal("storage task", e))?
}

/// Tag `dir` and everything below it on the same filesystem with `project`.
/// Used when a directory already exists (repair after drift); a fresh
/// directory only needs its own tag thanks to the inherit flag.
fn apply_project_tree(dir: &Path, project: u32, dev: u64) -> io::Result<()> {
    let f = File::open(dir)?;
    sys::set_project(&f, project, true)?;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.dev() != dev {
            continue; // a mount (overlay rootfs): not ours to tag
        }
        if meta.is_dir() {
            apply_project_tree(&path, project, dev)?;
        } else if meta.is_file() {
            sys::set_project(&File::open(&path)?, project, false)?;
        }
    }
    Ok(())
}

fn read_project(dir: &Path) -> io::Result<Option<ProjectId>> {
    let x = sys::get_xattr(&File::open(dir)?)?;
    Ok((x.projid != 0 && x.xflags & sys::FS_XFLAG_PROJINHERIT != 0).then_some(ProjectId(x.projid)))
}

#[async_trait]
impl StorageBackend for XfsProjectQuota {
    async fn verify(&self) -> Result<()> {
        let root = self.root.clone();
        let f = self.open_root()?;
        blocking(move || {
            let magic = sys::fs_magic(&f).context("statfs")?;
            if magic != sys::XFS_SUPER_MAGIC {
                return Err(Error::Unavailable(format!("{} is not on XFS (magic {magic:#x})", root.display())));
            }
            let st = sys::quota_state(&f).context("reading quota state")?;
            let need = sys::FS_QUOTA_PDQ_ACCT | sys::FS_QUOTA_PDQ_ENFD;
            if st.flags & need != need {
                return Err(Error::Unavailable(format!(
                    "project quota accounting and enforcement must be on for {} (mount with prjquota)",
                    root.display()
                )));
            }
            Ok(())
        })
        .await
    }

    fn tenant_dir(&self, t: &TenantId) -> PathBuf {
        self.tenants_dir().join(t.as_str())
    }

    async fn create_tenant(
        &self,
        t: &TenantId,
        project: ProjectId,
        limit: Bytes,
    ) -> Result<PathBuf> {
        let dir = self.tenant_dir(t);
        let tenants = self.tenants_dir();
        let root = self.open_root()?;
        blocking(move || {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&tenants)
                .context("creating tenants dir")?;
            let fresh = match fs::create_dir(&dir) {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(Error::internal(format!("creating {}", dir.display()), e)),
            };
            if fresh {
                sys::set_project(&File::open(&dir)?, project.0, true)
                    .context("setting project ID")?;
            } else {
                let dev = fs::metadata(&dir)?.dev();
                apply_project_tree(&dir, project.0, dev).context("re-applying project ID")?;
            }
            sys::set_project_limit(&root, project.0, limit).context("setting quota limit")?;
            Ok(dir)
        })
        .await
    }

    async fn set_limit(&self, project: ProjectId, limit: Bytes) -> Result<()> {
        let root = self.open_root()?;
        blocking(move || {
            sys::set_project_limit(&root, project.0, limit).context("setting quota limit")
        })
        .await
    }

    async fn usage(&self, project: ProjectId) -> Result<Usage> {
        let root = self.open_root()?;
        blocking(move || {
            let (used, limit) =
                sys::get_project_quota(&root, project.0).context("reading quota")?;
            Ok(Usage { used, limit })
        })
        .await
    }

    async fn delete_tenant(&self, t: &TenantId, project: Option<ProjectId>) -> Result<()> {
        let dir = self.tenant_dir(t);
        let root = self.open_root()?;
        blocking(move || {
            remove_tree_one_fs(&dir).context(format!("removing {}", dir.display()))?;
            if let Some(p) = project {
                sys::set_project_limit(&root, p.0, 0).context("clearing quota limit")?;
            }
            info!(dir = %dir.display(), "tenant directory removed");
            Ok(())
        })
        .await
    }

    async fn list_tenants(&self) -> Result<Vec<(TenantId, Option<ProjectId>)>> {
        let tenants = self.tenants_dir();
        blocking(move || {
            let mut out = Vec::new();
            let entries = match fs::read_dir(&tenants) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(e.into()),
            };
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let Ok(id) = TenantId::new(&name) else {
                    warn!(name, "ignoring non-tenant entry in tenants dir");
                    continue;
                };
                if entry.file_type()?.is_dir() {
                    out.push((id, read_project(&entry.path())?));
                }
            }
            Ok(out)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs only on XFS with prjquota and as root:
    /// `TENANTD_XFS_TEST_ROOT=/mnt/xfs cargo test -p tenantd-storage-xfs -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn quota_on_real_xfs() {
        let Ok(root) = std::env::var("TENANTD_XFS_TEST_ROOT") else {
            return;
        };
        let s = XfsProjectQuota::new(&root);
        s.verify().await.unwrap();
        let t = TenantId::new("xfs-test").unwrap();
        let p = ProjectId(4_000_000);
        let dir = s.create_tenant(&t, p, 1 << 20).await.unwrap();
        assert_eq!(s.usage(p).await.unwrap().limit, 1 << 20);
        let r = fs::write(dir.join("big"), vec![0u8; 2 << 20]);
        assert!(r.is_err(), "write past the quota must fail");
        fs::remove_file(dir.join("big")).ok();
        assert!(
            s.list_tenants()
                .await
                .unwrap()
                .contains(&(t.clone(), Some(p)))
        );
        s.delete_tenant(&t, Some(p)).await.unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn non_xfs_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let s = XfsProjectQuota::new(d.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let magic = sys::fs_magic(&File::open(d.path()).unwrap()).unwrap();
        if magic != sys::XFS_SUPER_MAGIC {
            assert!(matches!(
                rt.block_on(s.verify()),
                Err(Error::Unavailable(_))
            ));
        }
    }
}
