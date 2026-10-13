//! One network namespace per sandbox, bind-mounted at
//! `<netns_dir>/<tenant>.<sandbox>`, handed to runsc through the OCI spec.
//!
//! - `none`: the namespace is empty; runsc's netstack provides loopback.
//! - `egress`: the standard CNI `bridge` (with host-local IPAM and masquerade)
//!   then `firewall` plugins, run with a config tenantd generates. The
//!   result is saved beside the namespace for DEL. No inbound ports.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use serde_json::{Value, json};
use tenantd_core::backend::{NetAttachment, NetworkBackend};
use tenantd_core::config::NetworkConfig;
use tenantd_core::error::Context;
use tenantd_core::model::NetworkMode;
use tenantd_core::{Error, Result, SandboxKey};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

const NSFS_MAGIC: i64 = 0x6e73_6673;
const CNI_VERSION: &str = "1.0.0";
const NET_NAME: &str = "tenantd";
const PLUGINS: [&str; 3] = ["bridge", "host-local", "firewall"];

pub struct CniNetwork {
    cfg: NetworkConfig,
}

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn is_nsfs(p: &Path) -> bool {
    let Ok(c) = cpath(p) else { return false };
    // SAFETY: statfs fills the zeroed struct.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    unsafe { libc::statfs(c.as_ptr(), &mut s) == 0 && s.f_type as i64 == NSFS_MAGIC }
}

/// Create a network namespace and pin it at `path`. Runs on a throwaway
/// thread so the daemon's own threads stay in the host namespace.
fn create_netns(path: &Path) -> io::Result<()> {
    std::fs::File::create(path)?;
    let target = cpath(path)?;
    std::thread::spawn(move || -> io::Result<()> {
        // SAFETY: unshare only affects this thread, which exits right after.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: gettid has no preconditions.
        let tid = unsafe { libc::gettid() };
        let src = CString::new(format!("/proc/self/task/{tid}/ns/net")).unwrap();
        // SAFETY: valid strings; a bind mount with no fs type or data.
        let r = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if r != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .join()
    .map_err(|_| io::Error::other("netns thread panicked"))?
}

fn remove_netns(path: &Path) -> io::Result<()> {
    if let Ok(c) = cpath(path) {
        // SAFETY: valid path. Not mounted (EINVAL) or missing (ENOENT) is fine.
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

impl CniNetwork {
    pub fn new(cfg: NetworkConfig) -> Self {
        Self { cfg }
    }

    fn ns_path(&self, key: &SandboxKey) -> PathBuf {
        self.cfg.netns_dir.join(key.to_string())
    }

    fn result_path(&self, key: &SandboxKey) -> PathBuf {
        self.cfg.netns_dir.join(format!("{key}.cni.json"))
    }

    fn bridge_conf(&self) -> Value {
        json!({
            "cniVersion": CNI_VERSION,
            "name": NET_NAME,
            "type": "bridge",
            "bridge": self.cfg.bridge,
            "isGateway": true,
            "ipMasq": true,
            "hairpinMode": false,
            "ipam": {
                "type": "host-local",
                "ranges": [[{ "subnet": self.cfg.egress_subnet }]],
                "routes": [{ "dst": "0.0.0.0/0" }],
                "dataDir": self.cfg.cni_data_dir.join("networks"),
            },
        })
    }

    fn firewall_conf(&self, prev: &Value) -> Value {
        json!({
            "cniVersion": CNI_VERSION,
            "name": NET_NAME,
            "type": "firewall",
            "backend": "iptables",
            "prevResult": prev,
        })
    }

    async fn exec(&self, command: &str, key: &SandboxKey, conf: &Value) -> Result<Value> {
        let plugin = conf["type"].as_str().unwrap_or_default().to_string();
        let mut child = tokio::process::Command::new(self.cfg.cni_bin.join(&plugin))
            .env_clear()
            .env("CNI_COMMAND", command)
            .env("CNI_CONTAINERID", key.to_string())
            .env("CNI_NETNS", self.ns_path(key))
            .env("CNI_IFNAME", "eth0")
            .env("CNI_PATH", &self.cfg.cni_bin)
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(format!("running CNI plugin {plugin}"))?;
        let input = serde_json::to_vec(conf).context("encoding CNI config")?;
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(&input).await?;
        drop(stdin);
        let out = child.wait_with_output().await?;
        if !out.status.success() {
            let msg = serde_json::from_slice::<Value>(&out.stdout)
                .ok()
                .and_then(|v| v["msg"].as_str().map(str::to_string))
                .unwrap_or_else(|| String::from_utf8_lossy(&out.stderr).into_owned());
            return Err(Error::Internal(format!("CNI {plugin} {command}: {msg}")));
        }
        if out.stdout.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&out.stdout).context(format!("CNI {plugin} {command} output"))
    }

    async fn cni_add(&self, key: &SandboxKey) -> Result<()> {
        let bridge = self.bridge_conf();
        let res = self.exec("ADD", key, &bridge).await?;
        let res = match self.exec("ADD", key, &self.firewall_conf(&res)).await {
            Ok(r) => r,
            Err(e) => {
                let _ = self.exec("DEL", key, &with_prev(bridge, &res)).await;
                return Err(e);
            }
        };
        let tmp = self.result_path(key).with_extension("tmp");
        tokio::fs::write(
            &tmp,
            serde_json::to_vec(&res).context("encoding CNI result")?,
        )
        .await?;
        tokio::fs::rename(&tmp, self.result_path(key)).await?;
        Ok(())
    }

    async fn cni_del(&self, key: &SandboxKey) -> Result<()> {
        let path = self.result_path(key);
        let prev: Value = match tokio::fs::read(&path).await {
            Ok(b) => serde_json::from_slice(&b).unwrap_or(Value::Null),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        self.exec("DEL", key, &self.firewall_conf(&prev)).await?;
        self.exec("DEL", key, &with_prev(self.bridge_conf(), &prev))
            .await?;
        tokio::fs::remove_file(&path).await?;
        Ok(())
    }
}

fn with_prev(mut conf: Value, prev: &Value) -> Value {
    conf["prevResult"] = prev.clone();
    conf
}

#[async_trait]
impl NetworkBackend for CniNetwork {
    async fn verify(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.cfg.netns_dir).await?;
        let missing: Vec<_> = PLUGINS
            .iter()
            .filter(|p| !self.cfg.cni_bin.join(p).exists())
            .collect();
        if !missing.is_empty() {
            return Err(Error::Unavailable(format!(
                "CNI plugins {missing:?} not found in {}; egress profiles will fail",
                self.cfg.cni_bin.display()
            )));
        }
        Ok(())
    }

    async fn setup(&self, key: &SandboxKey, mode: NetworkMode) -> Result<NetAttachment> {
        tokio::fs::create_dir_all(&self.cfg.netns_dir).await?;
        let ns = self.ns_path(key);
        if !is_nsfs(&ns) {
            let p = ns.clone();
            tokio::task::spawn_blocking(move || {
                remove_netns(&p)?;
                create_netns(&p)
            })
            .await
            .map_err(|e| Error::internal("netns task", e))?
            .context(format!("creating netns {}", ns.display()))?;
            info!(netns = %ns.display(), "network namespace created");
        }
        if mode == NetworkMode::Egress
            && !tokio::fs::try_exists(self.result_path(key)).await?
            && let Err(e) = self.cni_add(key).await
        {
            let _ = self.teardown(key).await;
            return Err(e);
        }
        Ok(NetAttachment { netns: ns })
    }

    async fn teardown(&self, key: &SandboxKey) -> Result<()> {
        if let Err(e) = self.cni_del(key).await {
            warn!(sandbox = %key, error = %e, "CNI DEL failed");
            return Err(e);
        }
        let ns = self.ns_path(key);
        tokio::task::spawn_blocking(move || remove_netns(&ns))
            .await
            .map_err(|e| Error::internal("netns task", e))?
            .context("removing netns")?;
        Ok(())
    }

    async fn list_owned(&self) -> Result<Vec<SandboxKey>> {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&self.cfg.netns_dir).await {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(e) = rd.next_entry().await? {
            let name = e.file_name().to_string_lossy().into_owned();
            let base = name.strip_suffix(".cni.json").unwrap_or(&name);
            if let Ok(k) = base.parse::<SandboxKey>()
                && !out.contains(&k)
            {
                out.push(k);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> NetworkConfig {
        NetworkConfig {
            cni_bin: dir.join("cni-bin"),
            egress_subnet: "10.88.0.0/16".into(),
            netns_dir: dir.join("netns"),
            bridge: "tenantd0".into(),
            dns: vec![],
            cni_data_dir: dir.join("cni"),
        }
    }

    #[test]
    fn generated_config() {
        let n = CniNetwork::new(cfg(Path::new("/x")));
        let b = n.bridge_conf();
        assert_eq!(b["type"], "bridge");
        assert_eq!(b["ipam"]["ranges"][0][0]["subnet"], "10.88.0.0/16");
        let f = n.firewall_conf(&json!({"ips": []}));
        assert_eq!(f["prevResult"]["ips"], json!([]));
    }

    /// Needs CAP_SYS_ADMIN: `unshare -rmn cargo test -p tenantd-net -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn netns_lifecycle() {
        let d = tempfile::tempdir().unwrap();
        let n = CniNetwork::new(cfg(d.path()));
        let k: SandboxKey = "t.s".parse().unwrap();
        let a = n.setup(&k, NetworkMode::None).await.unwrap();
        assert!(is_nsfs(&a.netns));
        assert_eq!(n.setup(&k, NetworkMode::None).await.unwrap(), a);
        assert_eq!(n.list_owned().await.unwrap(), vec![k.clone()]);
        n.teardown(&k).await.unwrap();
        assert!(!a.netns.exists());
        n.teardown(&k).await.unwrap();
        assert!(n.list_owned().await.unwrap().is_empty());
        assert!(n.verify().await.is_err(), "no CNI plugins in the temp dir");
    }
}
