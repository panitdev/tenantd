//! The traits that keep the core independent of the filesystem, the
//! writable layer, the runtime, the image cache and the network.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::config::RuntimeKind;
use crate::model::{LayerKind, NetworkMode, ResolvedImage, ResolvedSandbox};
use crate::{Bytes, ProjectId, Result, SandboxId, SandboxKey, TenantId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub used: Bytes,
    pub limit: Bytes,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Refuse to start if quota is not actually enforced on the storage root.
    async fn verify(&self) -> Result<()>;
    /// The directory a tenant lives in. Pure; touches nothing.
    fn tenant_dir(&self, t: &TenantId) -> PathBuf;
    /// Create (or repair) the tenant directory, tag it with `project` and
    /// the inherit flag, and set the limit. Idempotent.
    async fn create_tenant(
        &self,
        t: &TenantId,
        project: ProjectId,
        limit: Bytes,
    ) -> Result<PathBuf>;
    async fn set_limit(&self, project: ProjectId, limit: Bytes) -> Result<()>;
    async fn usage(&self, project: ProjectId) -> Result<Usage>;
    /// Remove the directory and clear the limit (when `project` is known).
    /// Must refuse to cross into mounts below the directory. Idempotent.
    async fn delete_tenant(&self, t: &TenantId, project: Option<ProjectId>) -> Result<()>;
    /// Tenant directories on disk and the project ID each carries (`None`
    /// when the directory has no project ID set). For reconcile.
    async fn list_tenants(&self) -> Result<Vec<(TenantId, Option<ProjectId>)>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Accounting {
    /// Real files in the tenant directory, counted by the quota.
    Exact,
    /// Space is counted until the sandbox restarts.
    HighWaterMark,
    /// Writes count against the sandbox's memory limit.
    Memory,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reclaim {
    Immediate,
    OnRestart,
    Checkpoint,
}

#[derive(Clone, Debug)]
pub struct LayerTraits {
    pub accounting: Accounting,
    pub reclaim: Reclaim,
    pub survives_stop: bool,
    /// The core refuses a profile without a size cap.
    pub needs_size_cap: bool,
    pub runtimes: &'static [RuntimeKind],
}

/// What the runtime gets as the sandbox root. A small closed enum, never
/// free-form runtime flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootfsSpec {
    /// A writable host directory (the merged overlay).
    Path(PathBuf),
    /// A read-only view of the image; the runtime layers memory on top.
    Memory(PathBuf),
    /// A read-only view of the image, used as is.
    ReadOnly(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReclaimOutcome {
    NotNeeded,
    Reclaimed(Bytes),
}

#[async_trait]
pub trait WritableLayer: Send + Sync {
    fn kind(&self) -> LayerKind;
    fn traits(&self) -> LayerTraits;
    /// Build the sandbox's root inside its tenant dir. Idempotent: called
    /// again on start and by reconcile.
    async fn prepare(&self, s: &ResolvedSandbox, tenant_dir: &Path) -> Result<RootfsSpec>;
    /// No-op for `Reclaim::Immediate`.
    async fn reclaim(&self, h: &RuntimeHandle) -> Result<ReclaimOutcome>;
    /// Unmount and remove everything the sandbox owns under the tenant dir.
    /// Idempotent, and must cope with any layer's layout (reconcile uses it
    /// for orphans whose layer is unknown).
    async fn teardown(&self, s: &SandboxId, tenant_dir: &Path) -> Result<()>;
    /// Sandbox directories under the tenant dir. For reconcile.
    async fn list_owned(&self, tenant_dir: &Path) -> Result<Vec<SandboxId>>;
}

/// The runtime's name for a sandbox; tenantd uses the sandbox key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeHandle(pub String);

impl RuntimeHandle {
    pub fn for_key(k: &SandboxKey) -> Self {
        Self(k.to_string())
    }

    pub fn key(&self) -> Option<SandboxKey> {
        self.0.parse().ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeState {
    Created,
    Running,
    Stopped,
    Missing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeEvent {
    Exited {
        handle: RuntimeHandle,
        exit_code: Option<i32>,
        oom: bool,
    },
}

/// Where the sandbox's network namespace is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetAttachment {
    pub netns: PathBuf,
}

#[async_trait]
pub trait RuntimeBackend: Send + Sync {
    fn kind(&self) -> RuntimeKind;
    async fn verify(&self) -> Result<()>;
    async fn create(
        &self,
        spec: &ResolvedSandbox,
        root: &RootfsSpec,
        net: &NetAttachment,
    ) -> Result<RuntimeHandle>;
    async fn start(&self, h: &RuntimeHandle) -> Result<()>;
    async fn stop(&self, h: &RuntimeHandle, grace: Duration) -> Result<()>;
    /// Remove the container. Idempotent.
    async fn destroy(&self, h: &RuntimeHandle) -> Result<()>;
    async fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeState>;
    async fn list_owned(&self) -> Result<Vec<RuntimeHandle>>;
    /// Make sure the exit of a running container will be reported on
    /// [`RuntimeBackend::events`]. Idempotent; reconcile calls it after a
    /// restart to re-attach.
    async fn watch(&self, h: &RuntimeHandle) -> Result<()>;
    fn events(&self) -> BoxStream<'static, RuntimeEvent>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub images: Vec<String>,
    pub layers: Vec<String>,
}

#[async_trait]
pub trait ImageStore: Send + Sync {
    /// Pull (if needed) and unpack an image, pinning it to a digest. The
    /// reference is already normalised and allowed by policy.
    async fn resolve(&self, reference: &str) -> Result<ResolvedImage>;
    /// Drop manifests not in `in_use` (digests) and layers no remaining
    /// manifest references.
    async fn gc(&self, in_use: &HashSet<String>) -> Result<GcReport>;
}

#[async_trait]
pub trait NetworkBackend: Send + Sync {
    async fn verify(&self) -> Result<()>;
    /// Create the namespace (and attach egress for `Egress`). Idempotent.
    async fn setup(&self, key: &SandboxKey, mode: NetworkMode) -> Result<NetAttachment>;
    /// Detach and remove the namespace. Idempotent.
    async fn teardown(&self, key: &SandboxKey) -> Result<()>;
    async fn list_owned(&self) -> Result<Vec<SandboxKey>>;
}
