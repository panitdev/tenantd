//! The operator's TOML file. It is the whole policy: anything a caller can't
//! express through a profile, it can't do.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::id::validate_id;
use crate::model::{LayerKind, NetworkMode};
use crate::size::ByteSize;
use crate::{Error, Result};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub runtime: RuntimeConfig,
    pub images: ImagesConfig,
    pub network: NetworkConfig,
    #[serde(default)]
    pub reconcile: ReconcileConfig,
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub socket: PathBuf,
    /// `host:port` for a TCP listener, or an absolute path for a Unix socket.
    pub metrics: Option<String>,
    /// SQLite state file.
    pub state: PathBuf,
    /// Group that owns the API socket (mode 0660). Defaults to root's group.
    pub socket_gid: Option<u32>,
    #[serde(default)]
    pub callers: Vec<Caller>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub uid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageKind {
    XfsProject,
    Ext4Project,
    Zfs,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub backend: StorageKind,
    pub root: PathBuf,
    pub project_id_range: [u32; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKind {
    RunscDirect,
    Containerd,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub backend: RuntimeKind,
    pub runsc: PathBuf,
    /// `runsc --root`: holds the state of tenantd's containers only.
    pub root: PathBuf,
    /// OCI bundles and sandbox stdout/stderr logs.
    #[serde(default = "default_runtime_state_dir")]
    pub state_dir: PathBuf,
    /// Inclusive range of accepted `runsc --version` releases, e.g.
    /// `"release-20250101.0"`. Compared lexically after the `release-` prefix.
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    /// Grace period between SIGTERM and SIGKILL on stop.
    #[serde(default = "default_stop_grace")]
    pub stop_grace_secs: u64,
    /// Extra global runsc flags, fixed by the operator (e.g. `--platform=kvm`).
    #[serde(default)]
    pub extra_flags: Vec<String>,
}

fn default_runtime_state_dir() -> PathBuf {
    "/var/lib/tenantd/runtime".into()
}

fn default_stop_grace() -> u64 {
    10
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagesConfig {
    /// Unpacked layers, outside every tenant project.
    pub cache: PathBuf,
    /// Registries reached over plain HTTP (testing only).
    #[serde(default)]
    pub insecure_registries: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub cni_bin: PathBuf,
    pub egress_subnet: String,
    #[serde(default = "default_netns_dir")]
    pub netns_dir: PathBuf,
    #[serde(default = "default_bridge")]
    pub bridge: String,
    #[serde(default = "default_dns")]
    pub dns: Vec<String>,
    /// host-local IPAM state.
    #[serde(default = "default_cni_data_dir")]
    pub cni_data_dir: PathBuf,
}

fn default_cni_data_dir() -> PathBuf {
    "/var/lib/tenantd/cni".into()
}

fn default_netns_dir() -> PathBuf {
    "/run/tenantd/netns".into()
}

fn default_bridge() -> String {
    "tenantd0".into()
}

fn default_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileConfig {
    #[serde(default = "default_reconcile_interval")]
    pub interval_secs: u64,
    #[serde(default)]
    pub delete_orphans: bool,
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_reconcile_interval(),
            delete_orphans: false,
        }
    }
}

fn default_reconcile_interval() -> u64 {
    180
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Allowlist patterns matched against the normalised reference; `*`
    /// matches any run of characters.
    pub images: Vec<String>,
    pub memory: ByteSize,
    pub cpus: f64,
    pub pids: u32,
    pub rootfs: LayerKind,
    pub network: NetworkMode,
    /// Capabilities kept in the sandbox; everything else is dropped.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Size cap per sandbox, required by layers that declare `needs_size_cap`.
    pub size: Option<ByteSize>,
    /// Size of the `/tmp` tmpfs on a read-only root.
    #[serde(default = "default_tmp_size")]
    pub tmp_size: ByteSize,
}

fn default_tmp_size() -> ByteSize {
    ByteSize(64 << 20)
}

pub const KNOWN_CAPABILITIES: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
];

impl Config {
    pub fn from_toml(s: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(s).map_err(|e| Error::invalid(format!("config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| Error::invalid(format!("reading {}: {e}", path.display())))?;
        Self::from_toml(&s)
    }

    /// Checks that need nothing but the file. Checks against backend traits
    /// (layer support, size caps) happen in [`crate::Tenantd::new`].
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::invalid(format!("config: {m}")));
        let [lo, hi] = self.storage.project_id_range;
        if lo == 0 || lo > hi {
            return bad(format!(
                "storage.project_id_range [{lo}, {hi}] must be non-empty and above 0"
            ));
        }
        for p in [
            &self.storage.root,
            &self.runtime.root,
            &self.runtime.state_dir,
            &self.images.cache,
        ] {
            if !p.is_absolute() {
                return bad(format!("{} must be an absolute path", p.display()));
            }
        }
        if self
            .images
            .cache
            .starts_with(self.storage.root.join("tenants"))
        {
            return bad("images.cache must be outside every tenant directory".into());
        }
        parse_cidr(&self.network.egress_subnet)?;
        for ns in &self.network.dns {
            if ns.parse::<std::net::IpAddr>().is_err() {
                return bad(format!("network.dns entry {ns:?} is not an IP address"));
            }
        }
        if self.profiles.is_empty() {
            return bad("at least one profile is required".into());
        }
        for (name, p) in &self.profiles {
            validate_id("profile", name).or_else(|e| bad(format!("profile name: {e}")))?;
            let at = |field: &str| format!("profiles.{name}.{field}");
            if p.images.is_empty() {
                return bad(format!("{} must list at least one pattern", at("images")));
            }
            if p.memory.0 == 0 || !(p.cpus > 0.0 && p.cpus.is_finite()) || p.pids == 0 {
                return bad(format!(
                    "{}: memory, cpus and pids must be positive",
                    at("*")
                ));
            }
            for c in &p.capabilities {
                if !KNOWN_CAPABILITIES.contains(&c.as_str()) {
                    return bad(format!("{}: unknown capability {c:?}", at("capabilities")));
                }
            }
            if p.size.is_some_and(|s| s.0 == 0) {
                return bad(format!("{} must be positive", at("size")));
            }
        }
        Ok(())
    }

    pub fn profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .get(name)
            .ok_or_else(|| Error::denied("profiles", format!("no profile named {name:?}")))
    }

    pub fn tenants_dir(&self) -> PathBuf {
        self.storage.root.join("tenants")
    }
}

/// Parses `a.b.c.d/len`.
pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let err = || Error::invalid(format!("config: {s:?} is not an IPv4 CIDR"));
    let (ip, len) = s.split_once('/').ok_or_else(err)?;
    let ip: Ipv4Addr = ip.parse().map_err(|_| err())?;
    let len: u8 = len.parse().map_err(|_| err())?;
    if len > 30 {
        return Err(err());
    }
    Ok((ip, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const EXAMPLE: &str = include_str!("../../../examples/tenantd.toml");

    #[test]
    fn example_parses() {
        let cfg = Config::from_toml(EXAMPLE).unwrap();
        assert_eq!(cfg.profiles["default"].memory.0, 4 << 30);
        assert_eq!(cfg.profiles["scratch"].rootfs, LayerKind::Memory);
        assert_eq!(cfg.server.callers[0].uid, 1000);
        assert_eq!(cfg.reconcile.interval_secs, 180);
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let with = |from: &str, to: &str| EXAMPLE.replacen(from, to, 1);
        assert!(Config::from_toml(&with("pids = 1024", "pids = 1024\nprivileged = true")).is_err());
        assert!(Config::from_toml(&with("pids = 1024", "pids = 0")).is_err());
        assert!(Config::from_toml(&with("[100000, 199999]", "[5, 1]")).is_err());
        assert!(Config::from_toml(&with("10.88.0.0/16", "10.88.0.0")).is_err());
        assert!(
            Config::from_toml(&with("rootfs = \"host-overlay\"", "rootfs = \"bind\"")).is_err()
        );
        assert!(
            Config::from_toml(&with(
                "pids = 1024",
                "pids = 1024\ncapabilities = [\"CAP_EVIL\"]"
            ))
            .is_err()
        );
    }
}
