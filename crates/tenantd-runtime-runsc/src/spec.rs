//! OCI `config.json` for one sandbox, and the `process.json` for one exec,
//! built only from resolved specs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxCpuBuilder, LinuxMemoryBuilder,
    LinuxNamespaceBuilder, LinuxNamespaceType, LinuxPidsBuilder, LinuxResourcesBuilder, Mount,
    MountBuilder, PosixRlimitBuilder, PosixRlimitType, Process, ProcessBuilder, RootBuilder, Spec,
    SpecBuilder, UserBuilder,
};
use tenantd_core::backend::{NetAttachment, RootfsSpec};
use tenantd_core::error::Context;
use tenantd_core::model::{NetworkMode, ResolvedProcess, ResolvedSandbox};
use tenantd_core::{Error, Result};

const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const CPU_PERIOD: u64 = 100_000;

/// Files the bundle provides to the sandbox (bind-mounted read-only).
pub struct BundleFiles {
    pub resolv_conf: Option<PathBuf>,
    pub hosts: PathBuf,
}

pub fn cgroups_path(s: &ResolvedSandbox) -> PathBuf {
    PathBuf::from(format!("/tenantd/{}/{}", s.key.tenant, s.key.sandbox))
}

pub fn overlay_flag(root: &RootfsSpec) -> &'static str {
    match root {
        RootfsSpec::Memory(_) => "root:memory",
        RootfsSpec::Path(_) | RootfsSpec::ReadOnly(_) => "none",
    }
}

fn mount(dest: &str, typ: &str, source: &str, opts: &[&str]) -> Result<Mount> {
    MountBuilder::default()
        .destination(dest)
        .typ(typ)
        .source(source)
        .options(opts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .build()
        .context("building mount")
}

fn capabilities(names: &[String]) -> Result<HashSet<Capability>> {
    names
        .iter()
        .map(|n| {
            n.strip_prefix("CAP_")
                .and_then(|s| s.parse::<Capability>().ok())
                .ok_or_else(|| Error::Internal(format!("unknown capability {n}")))
        })
        .collect()
}

/// Resolve the image's `User` to numeric IDs. Names are looked up in the
/// image's /etc/passwd and /etc/group, never following symlinks out of it.
pub fn resolve_user(user: Option<&str>, rootfs: &Path) -> Result<(u32, u32)> {
    resolve_user_with(user, |file| {
        let etc = rootfs.join("etc");
        let path = etc.join(file);
        let plain = |p: &Path| {
            std::fs::symlink_metadata(p)
                .map(|m| !m.file_type().is_symlink())
                .unwrap_or(false)
        };
        if plain(&etc) && plain(&path) {
            std::fs::read_to_string(path).unwrap_or_default()
        } else {
            String::new()
        }
    })
}

/// [`resolve_user`] against the image's unpacked layers (topmost first)
/// rather than a sandbox root, which the tenant can write to. A whiteout
/// (0/0 char device) hides the file in lower layers; symlinks are never
/// followed.
pub fn resolve_user_in_layers(user: Option<&str>, layers: &[PathBuf]) -> Result<(u32, u32)> {
    resolve_user_with(user, |file| {
        for layer in layers.iter().rev() {
            let etc = layer.join("etc");
            let path = etc.join(file);
            let Ok(m) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let etc_ok = std::fs::symlink_metadata(&etc).is_ok_and(|m| m.is_dir());
            // A whiteout, a symlink or anything else hides it: no entries.
            return if etc_ok && m.is_file() {
                std::fs::read_to_string(path).unwrap_or_default()
            } else {
                String::new()
            };
        }
        String::new()
    })
}

fn resolve_user_with(user: Option<&str>, read: impl Fn(&str) -> String) -> Result<(u32, u32)> {
    let Some(u) = user.filter(|u| !u.is_empty()) else {
        return Ok((0, 0));
    };
    let (name, group) = match u.split_once(':') {
        Some((n, g)) => (n, Some(g)),
        None => (u, None),
    };
    let lookup = |db: &str, key: &str, field: usize| -> Option<u32> {
        db.lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f.first() == Some(&key))?
            .get(field)?
            .parse()
            .ok()
    };
    let passwd = read("passwd");
    let (uid, primary_gid) = match name.parse::<u32>() {
        Ok(uid) => (uid, None),
        Err(_) => {
            let uid = lookup(&passwd, name, 2)
                .ok_or_else(|| Error::invalid(format!("image user {name} not in /etc/passwd")))?;
            (uid, lookup(&passwd, name, 3))
        }
    };
    let gid = match group {
        Some(g) => match g.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => lookup(&read("group"), g, 2)
                .ok_or_else(|| Error::invalid(format!("image group {g} not in /etc/group")))?,
        },
        None => primary_gid.unwrap_or_else(|| {
            let by_uid = passwd
                .lines()
                .map(|l| l.split(':').collect::<Vec<_>>())
                .find(|f| f.get(2) == Some(&uid.to_string().as_str()));
            by_uid.and_then(|f| f.get(3)?.parse().ok()).unwrap_or(0)
        }),
    };
    Ok((uid, gid))
}

/// The locked-down process: the given capabilities in the bounding,
/// effective and permitted sets only, `noNewPrivileges`, no terminal.
fn process(
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    (uid, gid): (u32, u32),
    cap_names: &[String],
) -> Result<Process> {
    let caps = capabilities(cap_names)?;
    ProcessBuilder::default()
        .terminal(false)
        .user(
            UserBuilder::default()
                .uid(uid)
                .gid(gid)
                .build()
                .context("user")?,
        )
        .args(args)
        .env(env)
        .cwd(cwd)
        .no_new_privileges(true)
        .capabilities(
            LinuxCapabilitiesBuilder::default()
                .bounding(caps.clone())
                .effective(caps.clone())
                .permitted(caps)
                .inheritable(HashSet::new())
                .ambient(HashSet::new())
                .build()
                .context("capabilities")?,
        )
        .rlimits(vec![
            PosixRlimitBuilder::default()
                .typ(PosixRlimitType::RlimitNofile)
                .soft(65536u64)
                .hard(65536u64)
                .build()
                .context("rlimit")?,
        ])
        .build()
        .context("process")
}

/// `process.json` for `runsc exec --process`. Env and cwd are already final;
/// capabilities are the sandbox's.
pub fn exec_process(p: &ResolvedProcess) -> Result<Process> {
    let ids = resolve_user_in_layers(p.user.as_deref(), &p.image_layers)?;
    process(
        p.args.clone(),
        p.env.clone(),
        p.cwd.clone(),
        ids,
        &p.capabilities,
    )
}

pub fn build(
    s: &ResolvedSandbox,
    root: &RootfsSpec,
    net: &NetAttachment,
    files: &BundleFiles,
) -> Result<Spec> {
    let (root_path, readonly) = match root {
        RootfsSpec::Path(p) | RootfsSpec::Memory(p) => (p, false),
        RootfsSpec::ReadOnly(p) => (p, true),
    };
    let img = &s.image.config;
    let args: Vec<String> = img.entrypoint.iter().chain(&img.cmd).cloned().collect();
    if args.is_empty() {
        return Err(Error::invalid(format!(
            "image {} has no entrypoint or cmd",
            s.image.reference
        )));
    }
    let mut env = img.env.clone();
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push(DEFAULT_PATH.into());
    }
    env.push(format!("HOSTNAME={}", s.key.sandbox));
    let (uid, gid) = resolve_user(img.user.as_deref(), root_path)?;
    let process = process(
        args,
        env,
        img.working_dir.clone().unwrap_or_else(|| "/".into()),
        (uid, gid),
        &s.capabilities,
    )?;

    let tmpfs_size = |n: u64| format!("size={n}");
    let mut mounts = vec![
        mount("/proc", "proc", "proc", &["nosuid", "noexec", "nodev"])?,
        mount(
            "/dev",
            "tmpfs",
            "tmpfs",
            &["nosuid", "strictatime", "mode=755", "size=65536k"],
        )?,
        mount(
            "/dev/pts",
            "devpts",
            "devpts",
            &[
                "nosuid",
                "noexec",
                "newinstance",
                "ptmxmode=0666",
                "mode=0620",
            ],
        )?,
        mount(
            "/dev/shm",
            "tmpfs",
            "shm",
            &["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
        )?,
        mount(
            "/dev/mqueue",
            "mqueue",
            "mqueue",
            &["nosuid", "noexec", "nodev"],
        )?,
        mount(
            "/sys",
            "sysfs",
            "sysfs",
            &["nosuid", "noexec", "nodev", "ro"],
        )?,
        mount(
            "/etc/hosts",
            "bind",
            &files.hosts.to_string_lossy(),
            &["rbind", "ro"],
        )?,
    ];
    if readonly {
        let size = tmpfs_size(s.tmp_size);
        mounts.push(mount(
            "/tmp",
            "tmpfs",
            "tmpfs",
            &["nosuid", "nodev", "mode=1777", &size],
        )?);
    }
    if let (NetworkMode::Egress, Some(r)) = (s.network, &files.resolv_conf) {
        mounts.push(mount(
            "/etc/resolv.conf",
            "bind",
            &r.to_string_lossy(),
            &["rbind", "ro"],
        )?);
    }

    let ns = |typ, path: Option<&Path>| {
        let b = LinuxNamespaceBuilder::default().typ(typ);
        match path {
            Some(p) => b.path(p),
            None => b,
        }
        .build()
        .context("namespace")
    };
    let resources = LinuxResourcesBuilder::default()
        .memory(
            LinuxMemoryBuilder::default()
                .limit(s.memory as i64)
                .build()
                .context("memory")?,
        )
        .cpu(
            LinuxCpuBuilder::default()
                .quota((s.cpus * CPU_PERIOD as f64).round() as i64)
                .period(CPU_PERIOD)
                .build()
                .context("cpu")?,
        )
        .pids(
            LinuxPidsBuilder::default()
                .limit(s.pids as i64)
                .build()
                .context("pids")?,
        )
        .build()
        .context("resources")?;
    let linux = LinuxBuilder::default()
        .namespaces(vec![
            ns(LinuxNamespaceType::Pid, None)?,
            ns(LinuxNamespaceType::Network, Some(&net.netns))?,
            ns(LinuxNamespaceType::Ipc, None)?,
            ns(LinuxNamespaceType::Uts, None)?,
            ns(LinuxNamespaceType::Mount, None)?,
        ])
        .resources(resources)
        .cgroups_path(cgroups_path(s))
        .build()
        .context("linux")?;

    SpecBuilder::default()
        .version("1.0.2")
        .root(
            RootBuilder::default()
                .path(root_path)
                .readonly(readonly)
                .build()
                .context("root")?,
        )
        .hostname(s.key.sandbox.to_string())
        .process(process)
        .mounts(mounts)
        .linux(linux)
        .build()
        .context("spec")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenantd_core::SandboxKey;
    use tenantd_core::model::{ImageConfig, LayerKind, ResolvedImage};

    fn sandbox() -> ResolvedSandbox {
        ResolvedSandbox {
            key: SandboxKey::new("t".parse().unwrap(), "s".parse().unwrap()),
            profile: "default".into(),
            image: ResolvedImage {
                reference: "docker.io/library/alpine:latest".into(),
                digest: "sha256:x".into(),
                layers: vec![],
                config: ImageConfig {
                    entrypoint: vec!["/bin/sh".into()],
                    cmd: vec!["-c".into(), "sleep 1".into()],
                    env: vec!["A=1".into()],
                    working_dir: None,
                    user: Some("1000:1000".into()),
                },
            },
            memory: 1 << 30,
            cpus: 1.5,
            pids: 100,
            capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            rootfs: LayerKind::ReadOnly,
            size: None,
            tmp_size: 1 << 20,
            network: NetworkMode::Egress,
            dns: vec![],
        }
    }

    #[test]
    fn spec_is_locked_down() {
        let s = sandbox();
        let files = BundleFiles {
            resolv_conf: Some("/b/resolv.conf".into()),
            hosts: "/b/hosts".into(),
        };
        let net = NetAttachment {
            netns: "/run/tenantd/netns/t.s".into(),
        };
        let spec = build(&s, &RootfsSpec::ReadOnly("/r".into()), &net, &files).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        let p = &v["process"];
        assert_eq!(p["noNewPrivileges"], true);
        assert_eq!(p["user"]["uid"], 1000);
        assert_eq!(p["args"], serde_json::json!(["/bin/sh", "-c", "sleep 1"]));
        assert_eq!(
            p["capabilities"]["bounding"],
            serde_json::json!(["CAP_NET_BIND_SERVICE"])
        );
        assert_eq!(p["capabilities"]["ambient"], serde_json::json!([]));
        assert!(
            p["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap().starts_with("PATH="))
        );
        assert_eq!(v["root"]["readonly"], true);
        assert_eq!(v["linux"]["resources"]["memory"]["limit"], 1 << 30);
        assert_eq!(v["linux"]["resources"]["cpu"]["quota"], 150_000);
        assert_eq!(v["linux"]["resources"]["pids"]["limit"], 100);
        assert_eq!(v["linux"]["cgroupsPath"], "/tenantd/t/s");
        let nsv = v["linux"]["namespaces"].as_array().unwrap();
        assert!(
            nsv.iter()
                .any(|n| n["type"] == "network" && n["path"] == "/run/tenantd/netns/t.s")
        );
        let dests: Vec<_> = v["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["destination"].as_str().unwrap())
            .collect();
        assert!(dests.contains(&"/tmp") && dests.contains(&"/etc/resolv.conf"));
        assert!(v.get("hooks").is_none() || v["hooks"].is_null());
    }

    #[test]
    fn exec_process_is_locked_down_and_reads_users_from_the_image() {
        let d = tempfile::tempdir().unwrap();
        let (base, top) = (d.path().join("base"), d.path().join("top"));
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::create_dir_all(top.join("etc")).unwrap();
        std::fs::write(base.join("etc/passwd"), "app:x:1:1::/:/bin/sh\n").unwrap();
        std::fs::write(top.join("etc/passwd"), "app:x:1001:1002::/:/bin/sh\n").unwrap();
        let mut p = ResolvedProcess {
            key: "t.s"
                .parse::<tenantd_core::SandboxKey>()
                .map(|k| tenantd_core::ProcessKey::new(k, "p".parse().unwrap()))
                .unwrap(),
            args: vec!["make".into(), "test".into()],
            env: vec!["PATH=/bin".into(), "CI=1".into()],
            cwd: "/src".into(),
            user: Some("app".into()),
            capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            image_layers: vec![base.clone(), top.clone()],
        };
        let v = serde_json::to_value(exec_process(&p).unwrap()).unwrap();
        assert_eq!(v["noNewPrivileges"], true);
        assert_eq!(
            (v["user"]["uid"].clone(), v["user"]["gid"].clone()),
            (1001.into(), 1002.into())
        );
        assert_eq!(v["args"], serde_json::json!(["make", "test"]));
        assert_eq!(v["cwd"], "/src");
        assert_eq!(v["env"], serde_json::json!(["PATH=/bin", "CI=1"]));
        assert_eq!(
            v["capabilities"]["bounding"],
            serde_json::json!(["CAP_NET_BIND_SERVICE"])
        );
        assert_eq!(v["capabilities"]["ambient"], serde_json::json!([]));
        assert_eq!(v["terminal"], false);

        // The top layer's file is a symlink: it hides the base layer's
        // passwd rather than being followed.
        std::fs::remove_file(top.join("etc/passwd")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", top.join("etc/passwd")).unwrap();
        assert!(exec_process(&p).is_err());
        p.user = Some("7:8".into());
        let v = serde_json::to_value(exec_process(&p).unwrap()).unwrap();
        assert_eq!(v["user"]["uid"], 7);
    }

    #[test]
    fn users() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("etc")).unwrap();
        std::fs::write(
            d.path().join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\napp:x:1001:1002::/home/app:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(d.path().join("etc/group"), "root:x:0:\nstaff:x:50:\n").unwrap();
        assert_eq!(resolve_user(None, d.path()).unwrap(), (0, 0));
        assert_eq!(resolve_user(Some("app"), d.path()).unwrap(), (1001, 1002));
        assert_eq!(
            resolve_user(Some("app:staff"), d.path()).unwrap(),
            (1001, 50)
        );
        assert_eq!(resolve_user(Some("1001"), d.path()).unwrap(), (1001, 1002));
        assert_eq!(resolve_user(Some("7:8"), d.path()).unwrap(), (7, 8));
        assert!(resolve_user(Some("nobody"), d.path()).is_err());
    }
}
