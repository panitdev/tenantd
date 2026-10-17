//! Profile resolution and admission. Every rule that refuses a request names
//! itself in [`Error::PermissionDenied`].

use crate::backend::LayerTraits;
use crate::config::{Config, Profile};
use crate::model::{
    LayerKind, NetworkMode, Overrides, ProcessLimits, ProcessSpec, ResolvedImage, ResolvedProcess,
    ResolvedSandbox, SandboxRecord, TenantRecord,
};
use crate::{Bytes, Error, ProcessKey, Result, SandboxKey};

/// Caps on a process start's args and env.
pub const PROCESS_MAX_ENTRIES: usize = 256;
pub const PROCESS_MAX_BYTES: usize = 128 << 10;

const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// A request that passed profile policy but whose image is not resolved yet.
#[derive(Clone, Debug)]
pub struct Plan {
    pub key: SandboxKey,
    pub profile: String,
    pub image_ref: String,
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

impl Plan {
    pub fn with_image(self, image: ResolvedImage) -> ResolvedSandbox {
        ResolvedSandbox {
            key: self.key,
            profile: self.profile,
            image,
            memory: self.memory,
            cpus: self.cpus,
            pids: self.pids,
            capabilities: self.capabilities,
            rootfs: self.rootfs,
            size: self.size,
            tmp_size: self.tmp_size,
            network: self.network,
            dns: self.dns,
        }
    }
}

/// Resolve profile + overrides. Overrides may only tighten.
pub fn plan(
    cfg: &Config,
    key: SandboxKey,
    profile_name: &str,
    image: &str,
    ov: &Overrides,
    layer: &LayerTraits,
) -> Result<Plan> {
    let p: &Profile = cfg.profile(profile_name)?;
    let rule = |f: &str| format!("profiles.{profile_name}.{f}");

    let image_ref = normalize_reference(image)?;
    if !p.images.iter().any(|pat| glob_match(pat, &image_ref)) {
        return Err(Error::denied(
            rule("images"),
            format!("image {image_ref} is not allowed"),
        ));
    }

    fn tighten<T: PartialOrd + Copy + std::fmt::Display>(
        rule: String,
        base: T,
        want: Option<T>,
        zero: T,
    ) -> Result<T> {
        match want {
            None => Ok(base),
            Some(w) if w <= zero => {
                Err(Error::invalid(format!("{rule} override must be positive")))
            }
            Some(w) if w > base => Err(Error::denied(
                rule,
                format!("{w} exceeds the profile's {base}"),
            )),
            Some(w) => Ok(w),
        }
    }
    let memory = tighten(rule("memory"), p.memory.0, ov.memory, 0)?;
    let cpus = tighten(rule("cpus"), p.cpus, ov.cpus, 0.0)?;
    if ov.cpus.is_some_and(|c| !c.is_finite()) {
        return Err(Error::invalid("cpus override must be finite"));
    }
    let pids = tighten(rule("pids"), p.pids, ov.pids, 0)?;
    let size = match (p.size, ov.size) {
        (Some(base), want) => Some(tighten(rule("size"), base.0, want, 0)?),
        (None, Some(_)) if !layer.needs_size_cap => {
            return Err(Error::invalid(format!(
                "{} layers take no size cap",
                p.rootfs.as_str()
            )));
        }
        (None, want) => want,
    };
    if layer.needs_size_cap && size.is_none() {
        return Err(Error::denied(rule("size"), "this layer needs a size cap"));
    }

    Ok(Plan {
        key,
        profile: profile_name.to_string(),
        image_ref,
        memory,
        cpus,
        pids,
        capabilities: p.capabilities.clone(),
        rootfs: p.rootfs,
        size,
        tmp_size: p.tmp_size.0,
        network: p.network,
        dns: cfg.network.dns.clone(),
    })
}

/// Tenant-wide ceilings, checked against the tenant's other sandboxes.
/// `others` must exclude the sandbox being admitted.
pub fn admit(
    tenant: &TenantRecord,
    others: &[SandboxRecord],
    memory: Bytes,
    cpus: f64,
    size: Option<Bytes>,
) -> Result<()> {
    let active = others.iter().filter(|s| s.state.is_active());
    let rule = |f: &str| format!("tenant.{}.{f}", tenant.id);
    if let Some(limit) = tenant.limits.memory {
        let used: Bytes = active.clone().map(|s| s.spec.memory).sum();
        if used.saturating_add(memory) > limit {
            return Err(Error::denied(
                rule("memory"),
                format!(
                    "{used} bytes in use + {memory} requested exceeds the {limit} byte ceiling"
                ),
            ));
        }
    }
    if let Some(limit) = tenant.limits.cpus {
        let used: f64 = active.map(|s| s.spec.cpus).sum();
        if used + cpus > limit + 1e-9 {
            return Err(Error::denied(
                rule("cpus"),
                format!("{used} cpus in use + {cpus} requested exceeds the {limit} cpu ceiling"),
            ));
        }
    }
    // Size caps of every sandbox that holds a capped layer must fit the
    // tenant's storage limit together.
    if let Some(size) = size {
        let used: Bytes = others.iter().filter_map(|s| s.spec.size).sum();
        if used.saturating_add(size) > tenant.limits.storage {
            return Err(Error::denied(
                rule("storage"),
                format!(
                    "size caps of {used} + {size} bytes exceed the {} byte quota",
                    tenant.limits.storage
                ),
            ));
        }
    }
    Ok(())
}

/// Shape checks on a process spec that need no config.
pub fn validate_process_spec(p: &ProcessSpec) -> Result<()> {
    if p.args.is_empty() || p.args[0].is_empty() {
        return Err(Error::invalid("args are required"));
    }
    if p.args.len() > PROCESS_MAX_ENTRIES || p.env.len() > PROCESS_MAX_ENTRIES {
        return Err(Error::invalid(format!(
            "args and env take at most {PROCESS_MAX_ENTRIES} entries each"
        )));
    }
    let strings = p.args.iter().chain(&p.env).chain(&p.cwd).chain(&p.user);
    if strings.clone().any(|s| s.contains('\0')) {
        return Err(Error::invalid(
            "args, env, cwd and user must not contain NUL",
        ));
    }
    let total: usize = strings.map(|s| s.len()).sum();
    if total > PROCESS_MAX_BYTES {
        return Err(Error::invalid(format!(
            "args, env, cwd and user take at most {PROCESS_MAX_BYTES} bytes together"
        )));
    }
    if let Some(e) = p
        .env
        .iter()
        .find(|e| e.split_once('=').is_none_or(|(k, _)| k.is_empty()))
    {
        return Err(Error::invalid(format!("env entry {e:?} is not KEY=VALUE")));
    }
    if p.cwd.as_ref().is_some_and(|c| !c.starts_with('/')) {
        return Err(Error::invalid("cwd must be an absolute path"));
    }
    Ok(())
}

/// Resolve a process start against the sandbox and the exec policy of its
/// profile in the *current* config. The process gets the sandbox's
/// capabilities, never more.
pub fn plan_process(
    cfg: &Config,
    sandbox: &SandboxRecord,
    key: ProcessKey,
    p: &ProcessSpec,
) -> Result<(ResolvedProcess, ProcessLimits)> {
    validate_process_spec(p)?;
    let name = &sandbox.profile;
    let exec = &cfg.profile(name)?.exec;
    let rule = |f: &str| format!("profiles.{name}.exec{f}");
    if !exec.enabled {
        return Err(Error::denied(
            rule(""),
            "exec is not enabled for this profile",
        ));
    }
    let user = p
        .user
        .as_deref()
        .filter(|u| !u.is_empty())
        .unwrap_or("image");
    if !exec.users.iter().any(|u| u == user) {
        return Err(Error::denied(
            rule(".users"),
            format!("user {user:?} is not allowed"),
        ));
    }
    if p.tty && !exec.tty {
        return Err(Error::denied(rule(".tty"), "tty is not allowed"));
    }
    if p.tty || p.stdin {
        return Err(Error::invalid(
            "tty and stdin processes are not supported yet",
        ));
    }

    let img = &sandbox.spec.image.config;
    let mut env = img.env.clone();
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push(DEFAULT_PATH.into());
    }
    env.push(format!("HOSTNAME={}", sandbox.id));
    env.extend(p.env.iter().cloned());
    let resolved = ResolvedProcess {
        key,
        args: p.args.clone(),
        env,
        cwd: p
            .cwd
            .clone()
            .or_else(|| img.working_dir.clone().filter(|d| !d.is_empty()))
            .unwrap_or_else(|| "/".into()),
        user: match user {
            "image" => img.user.clone().filter(|u| !u.is_empty()),
            u => Some(u.to_string()),
        },
        capabilities: sandbox.spec.capabilities.clone(),
        image_layers: sandbox.spec.image.layers.clone(),
    };
    let limits = ProcessLimits {
        output_limit: exec.output_limit.0,
        retention_secs: exec.retention_secs,
        tombstone_secs: exec.tombstone_secs,
    };
    Ok((resolved, limits))
}

/// Normalise a reference the way registries resolve it:
/// `ubuntu` -> `docker.io/library/ubuntu:latest`.
pub fn normalize_reference(r: &str) -> Result<String> {
    let bad = || Error::invalid(format!("bad image reference {r:?}"));
    if r.is_empty()
        || r.len() > 512
        || !r
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/:@".contains(&b))
        || r.starts_with('/')
        || r.contains("//")
        || r.contains("..")
    {
        return Err(bad());
    }
    let (name, digest) = match r.split_once('@') {
        Some((n, d)) => {
            let hex = d.strip_prefix("sha256:").ok_or_else(bad)?;
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad());
            }
            (n, Some(d))
        }
        None => (r, None),
    };
    let (repo, tag) = match name.rfind(':') {
        Some(i) if !name[i..].contains('/') => (&name[..i], Some(&name[i + 1..])),
        _ => (name, None),
    };
    if repo.is_empty() || tag.is_some_and(|t| t.is_empty()) {
        return Err(bad());
    }
    let first = repo.split('/').next().unwrap_or_default();
    let has_registry =
        repo.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    let mut out = if has_registry {
        repo.to_string()
    } else if repo.contains('/') {
        format!("docker.io/{repo}")
    } else {
        format!("docker.io/library/{repo}")
    };
    if out
        .split('/')
        .skip(1)
        .any(|c| c.bytes().any(|b| b.is_ascii_uppercase()))
    {
        return Err(bad());
    }
    match (tag, digest) {
        (Some(t), Some(d)) => out = format!("{out}:{t}@{d}"),
        (Some(t), None) => out = format!("{out}:{t}"),
        (None, Some(d)) => out = format!("{out}@{d}"),
        (None, None) => out.push_str(":latest"),
    }
    Ok(out)
}

/// `*` matches any run of characters; everything else is literal.
pub fn glob_match(pattern: &str, s: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), s.as_bytes());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize() {
        let n = |s| normalize_reference(s).unwrap();
        assert_eq!(n("ubuntu"), "docker.io/library/ubuntu:latest");
        assert_eq!(n("user/app:1"), "docker.io/user/app:1");
        assert_eq!(n("ghcr.io/example/app"), "ghcr.io/example/app:latest");
        assert_eq!(n("localhost:5000/app:dev"), "localhost:5000/app:dev");
        let d = format!("sha256:{}", "a".repeat(64));
        assert_eq!(n(&format!("ghcr.io/x/y@{d}")), format!("ghcr.io/x/y@{d}"));
        assert!(normalize_reference("ghcr.io/x/y@sha256:abc").is_err());
        assert!(normalize_reference("../etc").is_err());
        assert!(normalize_reference("a b").is_err());
        assert!(normalize_reference("ghcr.io/X/y").is_err());
    }

    #[test]
    fn globs() {
        assert!(glob_match("ghcr.io/example/*", "ghcr.io/example/app:1"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*c*e", "abcde"));
        assert!(!glob_match("ghcr.io/example/*", "ghcr.io/examplex/app:1"));
        assert!(!glob_match(
            "ghcr.io/example/app:1",
            "ghcr.io/example/app:12"
        ));
    }
}
