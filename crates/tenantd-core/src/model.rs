use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Bytes, ProjectId, SandboxId, SandboxKey, TenantId};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TenantLimits {
    /// Aggregate storage quota shared by all of the tenant's sandboxes.
    pub storage: Bytes,
    /// Optional ceilings across the tenant's active sandboxes.
    pub cpus: Option<f64>,
    pub memory: Option<Bytes>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    Provisioning,
    Ready,
    Deleting,
}

impl TenantState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Deleting => "deleting",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub id: TenantId,
    pub project: ProjectId,
    pub limits: TenantLimits,
    pub state: TenantState,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Caller-supplied adjustments. They may only tighten the profile.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Overrides {
    pub memory: Option<Bytes>,
    pub cpus: Option<f64>,
    pub pids: Option<u32>,
    pub size: Option<Bytes>,
}

/// The sandbox lifecycle. `Creating`, `Starting`, `Stopping` and `Destroying`
/// are intents recorded before touching the host, so a crash mid-way leaves
/// something reconcile can finish or undo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Creating,
    Starting,
    Running,
    Stopping,
    Stopped,
    Exited,
    Destroying,
}

impl SandboxState {
    pub const ALL: [SandboxState; 7] = [
        Self::Creating,
        Self::Starting,
        Self::Running,
        Self::Stopping,
        Self::Stopped,
        Self::Exited,
        Self::Destroying,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Exited => "exited",
            Self::Destroying => "destroying",
        }
    }

    /// Whether the sandbox holds (or is about to hold) CPU and memory.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Creating | Self::Starting | Self::Running | Self::Stopping
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayerKind {
    HostOverlay,
    Memory,
    ReadOnly,
    Filestore,
}

impl LayerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostOverlay => "host-overlay",
            Self::Memory => "memory",
            Self::ReadOnly => "read-only",
            Self::Filestore => "filestore",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    None,
    Egress,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Egress => "egress",
        }
    }
}

/// Process defaults from the image config.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
}

/// An image pinned to a manifest digest, with its unpacked layers in the
/// host cache, base layer first.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedImage {
    pub reference: String,
    pub digest: String,
    pub layers: Vec<PathBuf>,
    pub config: ImageConfig,
}

/// Everything a backend needs to run a sandbox. Built only inside tenantd
/// from profile + overrides + tenant, so backends never see raw caller input.
/// Stored with the sandbox row, so a restart or reconcile uses the exact spec
/// the sandbox was admitted with, even after a config reload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSandbox {
    pub key: SandboxKey,
    pub profile: String,
    pub image: ResolvedImage,
    pub memory: Bytes,
    pub cpus: f64,
    pub pids: u32,
    pub capabilities: Vec<String>,
    pub rootfs: LayerKind,
    pub size: Option<Bytes>,
    pub tmp_size: Bytes,
    pub network: NetworkMode,
    pub dns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SandboxRecord {
    pub tenant: TenantId,
    pub id: SandboxId,
    pub profile: String,
    /// The image reference as the caller sent it, for idempotency checks.
    pub image: String,
    pub overrides: Overrides,
    pub spec: ResolvedSandbox,
    pub state: SandboxState,
    pub exit_code: Option<i32>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl SandboxRecord {
    pub fn key(&self) -> SandboxKey {
        SandboxKey::new(self.tenant.clone(), self.id.clone())
    }
}
