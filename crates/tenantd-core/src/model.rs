use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Bytes, ProcessId, ProcessKey, ProjectId, SandboxId, SandboxKey, TenantId};

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

/// A process start as the caller asked for it. Kept on the row so a
/// repeated start can be compared with the original.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSpec {
    /// Required; no shell is implied.
    pub args: Vec<String>,
    /// `KEY=VALUE`, appended to the image env.
    pub env: Vec<String>,
    /// `None` uses the image's working directory.
    pub cwd: Option<String>,
    /// `None` runs as the image's user.
    pub user: Option<String>,
    pub tty: bool,
    pub stdin: bool,
}

impl ProcessSpec {
    /// A stable digest of the spec, kept in tombstones. FNV-1a over
    /// length-prefixed fields, so it never depends on a serialiser.
    pub fn digest(&self) -> String {
        let mut h = 0xcbf29ce484222325u64;
        let mut feed = |b: &[u8]| {
            for &x in (b.len() as u64).to_le_bytes().iter().chain(b) {
                h = (h ^ x as u64).wrapping_mul(0x100000001b3);
            }
        };
        for (tag, list) in [("args", &self.args), ("env", &self.env)] {
            feed(tag.as_bytes());
            feed(&(list.len() as u64).to_le_bytes());
            list.iter().for_each(|s| feed(s.as_bytes()));
        }
        for opt in [&self.cwd, &self.user] {
            match opt {
                Some(s) => feed(format!("+{s}").as_bytes()),
                None => feed(b"-"),
            }
        }
        feed(&[self.tty as u8, self.stdin as u8]);
        format!("fnv1a64:{h:016x}")
    }
}

/// The exec policy a process was started under, kept on its row so a
/// config reload never changes it mid-flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLimits {
    /// Bytes kept per stream; the rest is discarded.
    pub output_limit: Bytes,
    pub retention_secs: u64,
    pub tombstone_secs: u64,
}

/// Where a process's output and runtime files live, inside its sandbox's
/// directory and so inside the tenant's quota.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIo {
    pub dir: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    /// The runtime writes the in-sandbox PID here once the process runs.
    pub pid_file: PathBuf,
}

impl ProcessIo {
    pub fn stream(&self, s: Stream) -> &PathBuf {
        match s {
            Stream::Stdout => &self.stdout,
            Stream::Stderr => &self.stderr,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Stdout,
    Stderr,
}

/// `Starting` is an intent recorded before exec; `Lost` means tenantd can
/// no longer tell what happened to the process (it may never have run).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Starting,
    Running,
    Exited,
    Lost,
}

impl ProcessState {
    pub const ALL: [ProcessState; 4] = [Self::Starting, Self::Running, Self::Exited, Self::Lost];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Exited => "exited",
            Self::Lost => "lost",
        }
    }

    /// Counted against `max_processes`.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Starting | Self::Running)
    }
}

/// The signals a caller may send. A closed set, never a raw number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signal {
    Term,
    Kill,
    Int,
    Hup,
    Quit,
    Usr1,
    Usr2,
}

impl Signal {
    pub const ALL: [Signal; 7] = [
        Self::Term,
        Self::Kill,
        Self::Int,
        Self::Hup,
        Self::Quit,
        Self::Usr1,
        Self::Usr2,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Term => "SIGTERM",
            Self::Kill => "SIGKILL",
            Self::Int => "SIGINT",
            Self::Hup => "SIGHUP",
            Self::Quit => "SIGQUIT",
            Self::Usr1 => "SIGUSR1",
            Self::Usr2 => "SIGUSR2",
        }
    }

    /// The Linux signal number (x86-64 and arm64 agree on these).
    pub fn number(self) -> i32 {
        match self {
            Self::Hup => 1,
            Self::Int => 2,
            Self::Quit => 3,
            Self::Kill => 9,
            Self::Usr1 => 10,
            Self::Usr2 => 12,
            Self::Term => 15,
        }
    }

    pub fn from_number(n: i32) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.number() == n)
    }
}

/// Everything a runtime needs to exec a process. Built only inside tenantd
/// from the caller's spec, the sandbox's resolved spec and the profile's
/// exec policy; capabilities are always the sandbox's.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedProcess {
    pub key: ProcessKey,
    pub args: Vec<String>,
    /// Image env, `PATH` and `HOSTNAME` defaults, then the caller's env.
    pub env: Vec<String>,
    pub cwd: String,
    /// The user to resolve (`None` = root). Names are looked up in the
    /// image's layers, never in the sandbox's writable root.
    pub user: Option<String>,
    pub capabilities: Vec<String>,
    pub image_layers: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub tenant: TenantId,
    pub sandbox: SandboxId,
    pub id: ProcessId,
    pub spec: ProcessSpec,
    pub limits: ProcessLimits,
    pub io: ProcessIo,
    pub state: ProcessState,
    /// PID inside the sandbox.
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    /// Raw signal number, when a signal killed the process.
    pub signal: Option<i32>,
    pub stdout_dropped: Bytes,
    pub stderr_dropped: Bytes,
    pub created_at: i64,
    pub updated_at: i64,
    pub exited_at: Option<i64>,
}

impl ProcessRecord {
    pub fn key(&self) -> ProcessKey {
        ProcessKey {
            tenant: self.tenant.clone(),
            sandbox: self.sandbox.clone(),
            id: self.id.clone(),
        }
    }

    pub fn sandbox_key(&self) -> SandboxKey {
        SandboxKey::new(self.tenant.clone(), self.sandbox.clone())
    }

    pub fn dropped(&self, s: Stream) -> Bytes {
        match s {
            Stream::Stdout => self.stdout_dropped,
            Stream::Stderr => self.stderr_dropped,
        }
    }
}

/// Reserves a garbage-collected or deleted process's ID until `expires_at`,
/// so a retried start can't run it again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTombstone {
    pub key: ProcessKey,
    pub spec_digest: String,
    pub expires_at: i64,
}
