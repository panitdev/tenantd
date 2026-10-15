//! Writable layers. Each sandbox owns `<tenant dir>/sandboxes/<id>/`, which
//! inherits the tenant's project ID:
//!
//! - `host-overlay`: `upper/` and `work/` there, merged with the cached image
//!   layers onto `rootfs/`. Every write is a real file in the tenant's quota.
//! - `memory`: a read-only image view on `rootfs/`; runsc keeps writes in
//!   memory (`--overlay2=root:memory`).
//! - `read-only`: a read-only image view on `rootfs/`, used as is.
//!
//! Lowerdirs only ever come from the image cache, and every path is built
//! from validated IDs under the storage root.

mod mount;

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tenantd_core::backend::{
    Accounting, LayerTraits, Reclaim, ReclaimOutcome, RootfsSpec, RuntimeHandle, WritableLayer,
};
use tenantd_core::config::RuntimeKind;
use tenantd_core::error::Context;
use tenantd_core::fsutil::remove_tree_one_fs;
use tenantd_core::model::{LayerKind, ResolvedSandbox};
use tenantd_core::{Error, Result, SandboxId};
use tracing::info;

pub use mount::{is_mountpoint, mounts_under};

const RUNSC: &[RuntimeKind] = &[RuntimeKind::RunscDirect];

pub fn sandbox_dir(tenant_dir: &Path, s: &SandboxId) -> PathBuf {
    tenant_dir.join("sandboxes").join(s.as_str())
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::internal("layer task", e))?
}

/// Image layers for `lowerdir`, topmost first, each checked to be a plain
/// directory under the image cache.
fn lowerdirs(cache: &Path, layers: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if layers.is_empty() {
        return Err(Error::FailedPrecondition("image has no layers".into()));
    }
    let mut out = Vec::with_capacity(layers.len());
    for l in layers.iter().rev() {
        let ok = l.is_absolute()
            && l.starts_with(cache)
            && l.components().all(|c| {
                matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            && !l.to_string_lossy().contains([':', ',', '\\']);
        if !ok {
            return Err(Error::Internal(format!(
                "refusing lowerdir {} outside the image cache",
                l.display()
            )));
        }
        out.push(l.clone());
    }
    Ok(out)
}

fn join_lower(dirs: &[PathBuf]) -> String {
    dirs.iter()
        .map(|d| d.to_string_lossy())
        .collect::<Vec<_>>()
        .join(":")
}

/// Mount a read-only merged view of `layers` on `target`. Overlayfs needs
/// two lowerdirs without an upper, so one layer is bind-mounted instead.
fn mount_readonly_view(cache: &Path, layers: &[PathBuf], target: &Path) -> Result<()> {
    if is_mountpoint(target)? {
        return Ok(());
    }
    let lowers = lowerdirs(cache, layers)?;
    if lowers.len() == 1 {
        mount::mount(
            &lowers[0].to_string_lossy(),
            target,
            None,
            libc::MS_BIND,
            None,
        )
        .context("bind-mounting image")?;
        mount::mount(
            "none",
            target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NODEV,
            None,
        )
        .context("remounting image read-only")?;
    } else {
        let data = format!("lowerdir={}", join_lower(&lowers));
        mount::mount(
            "overlay",
            target,
            Some("overlay"),
            libc::MS_RDONLY | libc::MS_NODEV,
            Some(&data),
        )
        .context("mounting read-only overlay")?;
    }
    Ok(())
}

/// Unmount everything below the sandbox dir and remove it, never crossing
/// into a mount that is still there.
fn teardown_dir(dir: &Path) -> Result<()> {
    for m in mounts_under(dir)? {
        mount::unmount(&m).context(format!("unmounting {}", m.display()))?;
    }
    remove_tree_one_fs(dir).context(format!("removing {}", dir.display()))?;
    Ok(())
}

fn list_dirs(tenant_dir: &Path) -> Result<Vec<SandboxId>> {
    let dir = tenant_dir.join("sandboxes");
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for e in entries {
        let e = e?;
        if e.file_type()?.is_dir()
            && let Ok(id) = SandboxId::new(e.file_name().to_string_lossy())
        {
            out.push(id);
        }
    }
    Ok(out)
}

async fn teardown_sandbox(s: &SandboxId, tenant_dir: &Path) -> Result<()> {
    let dir = sandbox_dir(tenant_dir, s);
    blocking(move || teardown_dir(&dir)).await
}

async fn list_sandboxes(tenant_dir: &Path) -> Result<Vec<SandboxId>> {
    let d = tenant_dir.to_path_buf();
    blocking(move || list_dirs(&d)).await
}

pub struct HostOverlay {
    image_cache: PathBuf,
}

impl HostOverlay {
    pub fn new(image_cache: impl Into<PathBuf>) -> Self {
        Self {
            image_cache: image_cache.into(),
        }
    }
}

#[async_trait]
impl WritableLayer for HostOverlay {
    fn kind(&self) -> LayerKind {
        LayerKind::HostOverlay
    }

    fn traits(&self) -> LayerTraits {
        LayerTraits {
            accounting: Accounting::Exact,
            reclaim: Reclaim::Immediate,
            survives_stop: true,
            needs_size_cap: false,
            runtimes: RUNSC,
        }
    }

    async fn prepare(&self, s: &ResolvedSandbox, tenant_dir: &Path) -> Result<RootfsSpec> {
        let dir = sandbox_dir(tenant_dir, &s.key.sandbox);
        let cache = self.image_cache.clone();
        let layers = s.image.layers.clone();
        blocking(move || {
            let (upper, work, rootfs) = (dir.join("upper"), dir.join("work"), dir.join("rootfs"));
            for d in [&upper, &work, &rootfs] {
                fs::create_dir_all(d).context(format!("creating {}", d.display()))?;
            }
            // The overlay root takes the upperdir's mode. tenantd's umask
            // would make it 0700, locking non-root image users out of `/`.
            fs::set_permissions(&upper, fs::Permissions::from_mode(0o755))
                .context(format!("chmod {}", upper.display()))?;
            if !is_mountpoint(&rootfs)? {
                let data = format!(
                    "lowerdir={},upperdir={},workdir={}",
                    join_lower(&lowerdirs(&cache, &layers)?),
                    upper.display(),
                    work.display()
                );
                mount::mount(
                    "overlay",
                    &rootfs,
                    Some("overlay"),
                    libc::MS_NODEV,
                    Some(&data),
                )
                .context("mounting host overlay")?;
                info!(rootfs = %rootfs.display(), "host overlay mounted");
            }
            Ok(RootfsSpec::Path(rootfs))
        })
        .await
    }

    async fn reclaim(&self, _h: &RuntimeHandle) -> Result<ReclaimOutcome> {
        Ok(ReclaimOutcome::NotNeeded)
    }

    async fn teardown(&self, s: &SandboxId, tenant_dir: &Path) -> Result<()> {
        teardown_sandbox(s, tenant_dir).await
    }

    async fn list_owned(&self, tenant_dir: &Path) -> Result<Vec<SandboxId>> {
        list_sandboxes(tenant_dir).await
    }
}

pub struct MemoryLayer {
    image_cache: PathBuf,
}

impl MemoryLayer {
    pub fn new(image_cache: impl Into<PathBuf>) -> Self {
        Self {
            image_cache: image_cache.into(),
        }
    }
}

#[async_trait]
impl WritableLayer for MemoryLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Memory
    }

    fn traits(&self) -> LayerTraits {
        LayerTraits {
            accounting: Accounting::Memory,
            reclaim: Reclaim::Immediate,
            survives_stop: false,
            needs_size_cap: false,
            runtimes: RUNSC,
        }
    }

    async fn prepare(&self, s: &ResolvedSandbox, tenant_dir: &Path) -> Result<RootfsSpec> {
        let rootfs = sandbox_dir(tenant_dir, &s.key.sandbox).join("rootfs");
        let (cache, layers) = (self.image_cache.clone(), s.image.layers.clone());
        blocking(move || {
            fs::create_dir_all(&rootfs)?;
            mount_readonly_view(&cache, &layers, &rootfs)?;
            Ok(RootfsSpec::Memory(rootfs))
        })
        .await
    }

    async fn reclaim(&self, _h: &RuntimeHandle) -> Result<ReclaimOutcome> {
        Ok(ReclaimOutcome::NotNeeded)
    }

    async fn teardown(&self, s: &SandboxId, tenant_dir: &Path) -> Result<()> {
        teardown_sandbox(s, tenant_dir).await
    }

    async fn list_owned(&self, tenant_dir: &Path) -> Result<Vec<SandboxId>> {
        list_sandboxes(tenant_dir).await
    }
}

pub struct ReadOnlyLayer {
    image_cache: PathBuf,
}

impl ReadOnlyLayer {
    pub fn new(image_cache: impl Into<PathBuf>) -> Self {
        Self {
            image_cache: image_cache.into(),
        }
    }
}

#[async_trait]
impl WritableLayer for ReadOnlyLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::ReadOnly
    }

    fn traits(&self) -> LayerTraits {
        LayerTraits {
            accounting: Accounting::None,
            reclaim: Reclaim::Immediate,
            survives_stop: false,
            needs_size_cap: false,
            runtimes: RUNSC,
        }
    }

    async fn prepare(&self, s: &ResolvedSandbox, tenant_dir: &Path) -> Result<RootfsSpec> {
        let rootfs = sandbox_dir(tenant_dir, &s.key.sandbox).join("rootfs");
        let (cache, layers) = (self.image_cache.clone(), s.image.layers.clone());
        blocking(move || {
            fs::create_dir_all(&rootfs)?;
            mount_readonly_view(&cache, &layers, &rootfs)?;
            Ok(RootfsSpec::ReadOnly(rootfs))
        })
        .await
    }

    async fn reclaim(&self, _h: &RuntimeHandle) -> Result<ReclaimOutcome> {
        Ok(ReclaimOutcome::NotNeeded)
    }

    async fn teardown(&self, s: &SandboxId, tenant_dir: &Path) -> Result<()> {
        teardown_sandbox(s, tenant_dir).await
    }

    async fn list_owned(&self, tenant_dir: &Path) -> Result<Vec<SandboxId>> {
        list_sandboxes(tenant_dir).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenantd_core::SandboxKey;
    use tenantd_core::model::{ImageConfig, NetworkMode, ResolvedImage};

    #[test]
    fn lowerdirs_must_come_from_the_cache() {
        let cache = Path::new("/data/images");
        let ok = vec![
            PathBuf::from("/data/images/layers/a"),
            PathBuf::from("/data/images/layers/b"),
        ];
        assert_eq!(
            lowerdirs(cache, &ok).unwrap(),
            vec![ok[1].clone(), ok[0].clone()]
        );
        for bad in [
            "/etc",
            "/data/images/../../etc",
            "/data/images/a:b",
            "/data/images/a,upperdir=/x",
            "rel",
        ] {
            assert!(lowerdirs(cache, &[PathBuf::from(bad)]).is_err(), "{bad}");
        }
        assert!(lowerdirs(cache, &[]).is_err());
    }

    fn spec(tenant_dir_cache: &Path, layers: Vec<PathBuf>) -> ResolvedSandbox {
        let _ = tenant_dir_cache;
        ResolvedSandbox {
            key: SandboxKey::new("t".parse().unwrap(), "s".parse().unwrap()),
            profile: "p".into(),
            image: ResolvedImage {
                reference: "r".into(),
                digest: "d".into(),
                layers,
                config: ImageConfig::default(),
            },
            memory: 1,
            cpus: 1.0,
            pids: 1,
            capabilities: vec![],
            rootfs: LayerKind::HostOverlay,
            size: None,
            tmp_size: 0,
            network: NetworkMode::None,
            dns: vec![],
        }
    }

    /// Needs CAP_SYS_ADMIN. Run unprivileged inside a user+mount namespace:
    /// `unshare -rm cargo test -p tenantd-layer -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn overlay_writes_land_in_upper_and_teardown_cleans_up() {
        // SAFETY: umask has no preconditions. tenantd runs with UMask=0077.
        unsafe { libc::umask(0o077) };
        let d = tempfile::tempdir().unwrap();
        let cache = d.path().join("images");
        let (l1, l2) = (cache.join("layers/1"), cache.join("layers/2"));
        fs::create_dir_all(&l1).unwrap();
        fs::create_dir_all(&l2).unwrap();
        fs::write(l1.join("base"), "1").unwrap();
        fs::write(l2.join("top"), "2").unwrap();
        let tenant = d.path().join("tenants/t");
        let s = spec(&cache, vec![l1.clone(), l2.clone()]);

        let layer = HostOverlay::new(&cache);
        let RootfsSpec::Path(root) = layer.prepare(&s, &tenant).await.unwrap() else {
            panic!()
        };
        layer.prepare(&s, &tenant).await.unwrap(); // idempotent
        let root_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o7777;
        assert_eq!(root_mode, 0o755, "overlay root must not inherit the umask");
        assert_eq!(fs::read_to_string(root.join("base")).unwrap(), "1");
        fs::write(root.join("new"), "x").unwrap();
        fs::remove_file(root.join("base")).unwrap();
        let upper = sandbox_dir(&tenant, &s.key.sandbox).join("upper");
        assert_eq!(fs::read_to_string(upper.join("new")).unwrap(), "x");
        assert!(l1.join("base").exists(), "image layer untouched");
        assert_eq!(
            layer.list_owned(&tenant).await.unwrap(),
            vec![s.key.sandbox.clone()]
        );

        layer.teardown(&s.key.sandbox, &tenant).await.unwrap();
        assert!(!sandbox_dir(&tenant, &s.key.sandbox).exists());
        assert!(l1.join("base").exists() && l2.join("top").exists());

        for (layer, layers) in [
            (
                Box::new(MemoryLayer::new(&cache)) as Box<dyn WritableLayer>,
                vec![l1.clone()],
            ),
            (
                Box::new(ReadOnlyLayer::new(&cache)),
                vec![l1.clone(), l2.clone()],
            ),
        ] {
            let s = spec(&cache, layers);
            let root = match layer.prepare(&s, &tenant).await.unwrap() {
                RootfsSpec::Memory(p) | RootfsSpec::ReadOnly(p) => p,
                other => panic!("{other:?}"),
            };
            assert!(root.join("base").exists());
            assert!(
                fs::write(root.join("x"), "x").is_err(),
                "view must be read-only"
            );
            layer.teardown(&s.key.sandbox, &tenant).await.unwrap();
            assert!(l1.join("base").exists());
        }
    }
}
