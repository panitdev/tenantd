//! runsc-direct: tenantd writes an OCI bundle per sandbox and drives
//! `runsc create/start/state/kill/wait/delete` itself, so flags are set per
//! sandbox and no shim is needed. `--root` holds tenantd's containers only.
//!
//! A container in a sandbox is a second runsc container with its own bundle,
//! joined to the sandbox's through the CRI annotations; every other call
//! takes its ID like a sandbox's.
//!
//! Processes: a foreground `runsc exec --process <json>` child with stdout
//! and stderr handed over as files (like create's), `kill --pid`,
//! `wait --pid` and `ps --format=json`. Not `--detach`: its hidden child
//! reaps the exit status, so a `wait --pid` issued after a fast process
//! exits finds nothing. tenantd keeps the exec child instead.

mod spec;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::FutureExt;
use futures::StreamExt;
use futures::stream::BoxStream;
use serde::Deserialize;
use tenantd_core::backend::{
    BindMount, ContainerRun, NetAttachment, PipedProcess, ProcInfo, RootfsSpec, RuntimeBackend,
    RuntimeEvent, RuntimeHandle, RuntimeState,
};
use tenantd_core::config::{RuntimeConfig, RuntimeKind};
use tenantd_core::error::Context;
use tenantd_core::model::{NetworkMode, ProcessIo, ResolvedProcess, ResolvedSandbox, Signal};
use tenantd_core::{Error, Result};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

pub use spec::{build as build_spec, exec_process, resolve_user, resolve_user_in_layers};

/// How long `runsc exec` may take to start a process.
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// How long `runsc start` may take.
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// In a bundle: the runsc flags `create` used, one per line, for `start`.
const START_FLAGS: &str = "runsc.flags";

/// The raw exit code of a `runsc exec` child, once it exits.
type ExecExit = oneshot::Receiver<Option<i32>>;

/// The most of a piped process's stderr kept for its error.
const PIPED_STDERR_MAX: usize = 4 << 10;

pub struct RunscRuntime {
    cfg: RuntimeConfig,
    /// tenantd's own binary, bound into every container as the file helper.
    helper: Option<PathBuf>,
    watched: Arc<Mutex<HashSet<String>>>,
    watched_processes: Arc<Mutex<HashSet<(String, u32)>>>,
    /// Exit codes of the `runsc exec` children, until `watch_process`
    /// takes them.
    exec_children: Arc<Mutex<HashMap<(String, u32), ExecExit>>>,
    tx: mpsc::UnboundedSender<RuntimeEvent>,
    rx: Mutex<Option<mpsc::UnboundedReceiver<RuntimeEvent>>>,
}

#[derive(Deserialize)]
struct StateOut {
    status: String,
}

#[derive(Deserialize)]
struct WaitOut {
    #[serde(rename = "exitStatus")]
    exit_status: i32,
}

#[derive(Deserialize)]
struct ListItem {
    id: String,
}

/// `wait --pid` status: negative is a signal number (runsc's encoding for
/// a signalled process), otherwise the exit code.
fn process_status(exit_status: i32) -> (Option<i32>, Option<i32>) {
    if exit_status < 0 {
        (None, Some(-exit_status))
    } else {
        (Some(exit_status), None)
    }
}

/// A foreground `runsc exec`'s own exit code: the process's code, or 128+N
/// when signal N killed it (runsc emulates the shell), or 128 when runsc
/// itself failed. Ambiguous for a process that exits 129 and up, so this is
/// only the fallback for when `wait --pid` came too late.
fn exec_exit_status(code: i32) -> (Option<i32>, Option<i32>) {
    match code {
        128 => (None, None),
        129..=192 => (None, Some(code - 128)),
        c => (Some(c), None),
    }
}

fn log_tail(path: &Path) -> String {
    let all = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = all.lines().rev().take(5).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

/// `ps --format=json` prints the in-sandbox PIDs only, e.g. `[1,16]`.
fn parse_ps(out: &str) -> Result<Vec<u32>> {
    let pids: Option<Vec<u32>> = serde_json::from_str(out.trim()).context("parsing runsc ps")?;
    Ok(pids.unwrap_or_default())
}

/// A pid file once fully written; a partial write reads as not yet.
async fn started_pid(path: &Path) -> Option<u32> {
    let s = tokio::fs::read_to_string(path).await.ok()?;
    s.trim().parse().ok()
}

fn flag_path(flag: &str, p: &Path) -> OsString {
    let mut f = OsString::from(flag);
    f.push(p);
    f
}

fn not_found(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("does not exist") || s.contains("not found") || s.contains("no such")
}

/// `runsc version release-20261005.0` -> `20261005.0`.
pub fn parse_version(out: &str) -> Option<String> {
    let first = out.lines().next()?;
    let v = first.split_whitespace().last()?;
    Some(v.strip_prefix("release-").unwrap_or(v).to_string())
}

fn version_key(v: &str) -> Vec<u64> {
    v.strip_prefix("release-")
        .unwrap_or(v)
        .split('.')
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

impl RunscRuntime {
    pub fn new(cfg: RuntimeConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        // Looked up now: once a package upgrade replaces the binary, the
        // running one's path reads "... (deleted)".
        let helper = std::env::current_exe().ok();
        Self {
            cfg,
            helper,
            watched: Arc::default(),
            watched_processes: Arc::default(),
            exec_children: Arc::default(),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    fn bundle_dir(&self, id: &str) -> PathBuf {
        self.cfg.state_dir.join("bundles").join(id)
    }

    fn log_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("logs")
    }

    fn global(&self) -> Vec<OsString> {
        let mut v: Vec<OsString> = vec!["--root".into(), self.cfg.root.clone().into()];
        v.extend(self.cfg.extra_flags.iter().map(OsString::from));
        v
    }

    fn command(&self, extra_global: &[OsString], args: &[&str]) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(&self.cfg.runsc);
        c.args(self.global())
            .args(extra_global)
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        c
    }

    /// Run a short runsc command, returning stdout. Errors carry stderr.
    async fn run(&self, args: &[&str]) -> std::result::Result<String, String> {
        let out = self
            .command(&[], args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("running runsc: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    async fn state(&self, id: &str) -> Result<RuntimeState> {
        match self.run(&["state", id]).await {
            Ok(out) => {
                let s: StateOut = serde_json::from_str(&out).context("parsing runsc state")?;
                Ok(match s.status.as_str() {
                    "creating" | "created" => RuntimeState::Created,
                    "stopped" => RuntimeState::Stopped,
                    _ => RuntimeState::Running,
                })
            }
            Err(e) if not_found(&e) => Ok(RuntimeState::Missing),
            Err(e) => Err(Error::Internal(format!("runsc state {id}: {e}"))),
        }
    }

    async fn wait_stopped(&self, id: &str, timeout: Duration) -> Result<bool> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if matches!(
                self.state(id).await?,
                RuntimeState::Stopped | RuntimeState::Missing
            ) {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn write_bundle_files(
        &self,
        s: &ResolvedSandbox,
        bundle: &Path,
    ) -> Result<spec::BundleFiles> {
        let hosts = bundle.join("hosts");
        tokio::fs::write(
            &hosts,
            format!(
                "127.0.0.1\tlocalhost {0}\n::1\tlocalhost {0}\n",
                s.key.sandbox
            ),
        )
        .await?;
        let resolv_conf = if s.network == NetworkMode::Egress {
            let p = bundle.join("resolv.conf");
            let body: String = s
                .dns
                .iter()
                .map(|ns| format!("nameserver {ns}\n"))
                .collect();
            tokio::fs::write(&p, body).await?;
            Some(p)
        } else {
            None
        };
        Ok(spec::BundleFiles { resolv_conf, hosts })
    }

    fn make_bundle(&self, h: &RuntimeHandle) -> Result<PathBuf> {
        let bundle = self.bundle_dir(&h.0);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&bundle)?;
        Ok(bundle)
    }

    /// Write `config.json` and run `runsc create`. A container whose spec
    /// carries the CRI annotations joins the sandbox they name.
    async fn create_from(
        &self,
        h: &RuntimeHandle,
        bundle: &Path,
        oci: &oci_spec::runtime::Spec,
        root: &RootfsSpec,
        extra_flags: &[String],
    ) -> Result<()> {
        let id = h.0.as_str();
        let json = serde_json::to_vec_pretty(oci).context("encoding config.json")?;
        tokio::fs::write(bundle.join("config.json"), json).await?;

        // The container inherits runsc create's stdio, so point it at the logs.
        let logs = self.log_dir();
        let stdout = self.open_log(&logs.join(format!("{id}.out")))?;
        let stderr = self.open_log(&logs.join(format!("{id}.err")))?;
        let runsc_log = logs.join(format!("{id}.runsc.log"));
        // `runsc start` needs these too: it sets up a joining container's
        // root, and without them it uses runsc's default overlay, a
        // filestore in the upper dir that the host never sees. Kept in the
        // bundle so a start after a daemon restart still has them.
        let mut runtime_flags = vec![
            format!("--overlay2={}", spec::overlay_flag(root)),
            "--network=sandbox".to_string(),
        ];
        runtime_flags.extend(extra_flags.iter().cloned());
        tokio::fs::write(bundle.join(START_FLAGS), runtime_flags.join("\n")).await?;
        let mut flags: Vec<OsString> = runtime_flags.iter().map(OsString::from).collect();
        flags.push(flag_path("--log=", &runsc_log));
        let status = self
            .command(
                &flags,
                &["create", "--bundle", &bundle.to_string_lossy(), id],
            )
            .stdout(stdout)
            .stderr(stderr)
            .status()
            .await
            .context("running runsc create")?;
        if !status.success() {
            return Err(Error::Internal(format!(
                "runsc create {id} failed ({status}): {}",
                log_tail(&runsc_log)
            )));
        }
        Ok(())
    }

    /// Create or append; the daemon's umask keeps it private.
    fn open_log(&self, path: &Path) -> Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .context(format!("opening {}", path.display()))
    }
}

/// Exit with OOM? Reads the sandbox cgroup's `memory.events` (cgroup v2)
/// before the container is deleted.
fn oom_killed(cgroup: &Path) -> bool {
    let p = Path::new("/sys/fs/cgroup")
        .join(cgroup.strip_prefix("/").unwrap_or(cgroup))
        .join("memory.events");
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("oom_kill ")?.trim().parse::<u64>().ok())
        })
        .is_some_and(|n| n > 0)
}

#[async_trait]
impl RuntimeBackend for RunscRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::RunscDirect
    }

    fn runtime_mounts(&self, s: &ResolvedSandbox) -> Vec<String> {
        spec::runtime_mounts(s)
            .into_iter()
            .map(String::from)
            .collect()
    }

    async fn verify(&self) -> Result<()> {
        let out = tokio::process::Command::new(&self.cfg.runsc)
            .arg("--version")
            .output()
            .await
            .map_err(|e| {
                Error::Unavailable(format!("running {}: {e}", self.cfg.runsc.display()))
            })?;
        let text = String::from_utf8_lossy(&out.stdout);
        let v = parse_version(&text).ok_or_else(|| {
            Error::Unavailable(format!("can't parse runsc version from {text:?}"))
        })?;
        if let Some(min) = &self.cfg.min_version
            && version_key(&v) < version_key(min)
        {
            return Err(Error::Unavailable(format!(
                "runsc {v} is older than the pinned minimum {min}"
            )));
        }
        if let Some(max) = &self.cfg.max_version
            && version_key(&v) > version_key(max)
        {
            return Err(Error::Unavailable(format!(
                "runsc {v} is newer than the pinned maximum {max}"
            )));
        }
        for d in [
            &self.cfg.root,
            &self.cfg.state_dir.join("bundles"),
            &self.log_dir(),
        ] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(d)
                .context(format!("creating {}", d.display()))?;
        }
        debug!(version = v, "runsc verified");
        Ok(())
    }

    async fn create(
        &self,
        s: &ResolvedSandbox,
        root: &RootfsSpec,
        net: &NetAttachment,
    ) -> Result<RuntimeHandle> {
        let h = RuntimeHandle::for_key(&s.key);
        let bundle = self.make_bundle(&h)?;
        let files = self.write_bundle_files(s, &bundle).await?;
        let oci = spec::build(s, root, net, &files)?;
        self.create_from(&h, &bundle, &oci, root, &[]).await?;
        info!(sandbox = h.0, "runsc container created");
        Ok(h)
    }

    async fn create_container(
        &self,
        s: &ResolvedSandbox,
        c: &ContainerRun<'_>,
        net: &NetAttachment,
    ) -> Result<RuntimeHandle> {
        let h = RuntimeHandle::for_container(c.key);
        let sandbox = RuntimeHandle::for_key(&s.key);
        let bundle = self.make_bundle(&h)?;
        let files = self.write_bundle_files(s, &bundle).await?;
        let helper = self
            .helper
            .clone()
            .ok_or_else(|| Error::Internal("can't find tenantd's own binary".into()))?;
        let mut mounts = c.mounts.to_vec();
        mounts.push(BindMount {
            source: helper,
            destination: tenantd_core::files::HELPER_PATH.into(),
            read_only: true,
        });
        let oci = spec::build_container(s, &sandbox.0, c.args, c.root, &mounts, net, &files)?;
        let mut extra = Vec::new();
        // The Files service changes this root from the host. runsc's default
        // for a root, `exclusive`, trusts its own cache and would keep
        // serving a replaced file's old inode; `shared` revalidates each
        // lookup, at a cost to every file operation in the container. A
        // read-only root never changes.
        if c.host_file_access && matches!(c.root, RootfsSpec::Path(_)) {
            extra.push("--file-access=shared".to_string());
        }
        self.create_from(&h, &bundle, &oci, c.root, &extra).await?;
        info!(container = h.0, "runsc container created in its sandbox");
        Ok(h)
    }

    async fn start(&self, h: &RuntimeHandle) -> Result<()> {
        // A container joining a sandbox takes `runsc start`'s stdio as its
        // own, and the sandbox holds those fds for the container's life. A
        // pipe here would never reach EOF, so give it the container's logs,
        // as `create_from` does, and read errors from runsc's own log.
        let id = h.0.as_str();
        let logs = self.log_dir();
        let stdout = self.open_log(&logs.join(format!("{id}.out")))?;
        let stderr = self.open_log(&logs.join(format!("{id}.err")))?;
        let runsc_log = logs.join(format!("{id}.runsc.log"));
        let mut flags: Vec<OsString> =
            match tokio::fs::read_to_string(self.bundle_dir(id).join(START_FLAGS)).await {
                Ok(s) => s.lines().map(OsString::from).collect(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.into()),
            };
        flags.push(flag_path("--log=", &runsc_log));
        let run = self
            .command(&flags, &["start", id])
            .stdout(stdout)
            .stderr(stderr)
            .status();
        let status = tokio::time::timeout(START_TIMEOUT, run)
            .await
            .map_err(|_| Error::Internal(format!("runsc start {id} timed out")))?
            .context("running runsc start")?;
        if !status.success() {
            return Err(Error::Internal(format!(
                "runsc start {id} failed ({status}): {}",
                log_tail(&runsc_log)
            )));
        }
        Ok(())
    }

    async fn stop(&self, h: &RuntimeHandle, grace: Duration) -> Result<()> {
        let id = h.0.as_str();
        if matches!(
            self.state(id).await?,
            RuntimeState::Stopped | RuntimeState::Missing
        ) {
            return Ok(());
        }
        if let Err(e) = self.run(&["kill", id, "SIGTERM"]).await {
            debug!(sandbox = id, error = e, "SIGTERM failed");
        }
        if self.wait_stopped(id, grace).await? {
            return Ok(());
        }
        if let Err(e) = self.run(&["kill", "--all", id, "SIGKILL"]).await
            && !not_found(&e)
        {
            warn!(sandbox = id, error = e, "SIGKILL failed");
        }
        if self.wait_stopped(id, Duration::from_secs(10)).await? {
            Ok(())
        } else {
            Err(Error::Internal(format!("{id} did not stop after SIGKILL")))
        }
    }

    async fn destroy(&self, h: &RuntimeHandle) -> Result<()> {
        match self.run(&["delete", "--force", &h.0]).await {
            Ok(_) => {}
            Err(e) if not_found(&e) => {}
            Err(e) => return Err(Error::Internal(format!("runsc delete {}: {e}", h.0))),
        }
        match tokio::fs::remove_dir_all(self.bundle_dir(&h.0)).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        Ok(())
    }

    async fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeState> {
        self.state(&h.0).await
    }

    async fn list_owned(&self) -> Result<Vec<RuntimeHandle>> {
        let out = self
            .run(&["list", "--format=json"])
            .await
            .map_err(|e| Error::Internal(format!("runsc list: {e}")))?;
        let items: Option<Vec<ListItem>> =
            serde_json::from_str(out.trim()).context("parsing runsc list")?;
        Ok(items
            .unwrap_or_default()
            .into_iter()
            .map(|i| RuntimeHandle(i.id))
            .collect())
    }

    async fn watch(&self, h: &RuntimeHandle) -> Result<()> {
        if !self.watched.lock().unwrap().insert(h.0.clone()) {
            return Ok(());
        }
        let cmd = self
            .command(&[], &["wait", &h.0])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        let (watched, tx, handle) = (self.watched.clone(), self.tx.clone(), h.clone());
        let cgroup = h
            .key()
            .map(|k| PathBuf::from(format!("/tenantd/{}/{}", k.tenant, k.sandbox)));
        tokio::spawn(async move {
            let exit_code = match cmd.await {
                Ok(out) if out.status.success() => serde_json::from_slice::<WaitOut>(&out.stdout)
                    .ok()
                    .map(|w| w.exit_status),
                Ok(out) => {
                    debug!(sandbox = handle.0, stderr = %String::from_utf8_lossy(&out.stderr), "runsc wait failed");
                    None
                }
                Err(e) => {
                    warn!(sandbox = handle.0, error = %e, "runsc wait could not run");
                    None
                }
            };
            let oom = cgroup.as_deref().is_some_and(oom_killed);
            watched.lock().unwrap().remove(&handle.0);
            let _ = tx.send(RuntimeEvent::Exited {
                handle,
                exit_code,
                oom,
            });
        });
        Ok(())
    }

    fn events(&self) -> BoxStream<'static, RuntimeEvent> {
        match self.rx.lock().unwrap().take() {
            Some(mut rx) => futures::stream::poll_fn(move |cx| rx.poll_recv(cx)).boxed(),
            None => futures::stream::empty().boxed(),
        }
    }

    async fn exec(&self, h: &RuntimeHandle, p: &ResolvedProcess, io: &ProcessIo) -> Result<u32> {
        let id = h.0.as_str();
        let process = spec::exec_process(p)?;
        let json = serde_json::to_vec_pretty(&process).context("encoding process.json")?;
        let process_json = io.dir.join("process.json");
        tokio::fs::write(&process_json, json).await?;
        match tokio::fs::remove_file(&io.pid_file).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        // The process keeps these as its stdout and stderr after runsc
        // exec returns; its own log goes next to them, inside the quota.
        let stdout = self.open_log(&io.stdout)?;
        let stderr = self.open_log(&io.stderr)?;
        let runsc_log = io.dir.join("runsc.log");
        let flags = [flag_path("--log=", &runsc_log)];
        let (json_arg, pid_arg) = (
            process_json.to_string_lossy(),
            io.pid_file.to_string_lossy(),
        );
        let mut child = self
            .command(
                &flags,
                &[
                    "exec",
                    "--process",
                    &json_arg,
                    "--internal-pid-file",
                    &pid_arg,
                    id,
                ],
            )
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .context("running runsc exec")?;
        // runsc writes the pid file once the process is started, then waits
        // on it. A fast process can be gone by the time we look, so the pid
        // file is checked again after the child exits.
        let deadline = Instant::now() + EXEC_TIMEOUT;
        let pid = loop {
            if let Some(pid) = started_pid(&io.pid_file).await {
                break pid;
            }
            if let Some(status) = child.try_wait().context("waiting for runsc exec")? {
                match started_pid(&io.pid_file).await {
                    Some(pid) => break pid,
                    None => {
                        return Err(Error::Internal(format!(
                            "runsc exec {id} failed ({status}): {}",
                            log_tail(&runsc_log)
                        )));
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::Internal(format!("runsc exec {id} timed out")));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(child.wait().await.ok().and_then(|s| s.code()));
        });
        self.exec_children
            .lock()
            .unwrap()
            .insert((id.to_string(), pid), rx);
        info!(sandbox = id, pid, process = %p.key.id, "process started");
        Ok(pid)
    }

    async fn recorded_pid(&self, io: &ProcessIo) -> Result<Option<u32>> {
        match tokio::fs::read_to_string(&io.pid_file).await {
            Ok(s) => s
                .trim()
                .parse()
                .map(Some)
                .map_err(|e| Error::internal(format!("parsing {}", io.pid_file.display()), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn signal(&self, h: &RuntimeHandle, pid: u32, sig: Signal) -> Result<()> {
        let pid = pid.to_string();
        match self.run(&["kill", "--pid", &pid, &h.0, sig.name()]).await {
            Ok(_) => Ok(()),
            Err(e) if not_found(&e) => Ok(()),
            Err(e) => Err(Error::Internal(format!(
                "runsc kill --pid {pid} {}: {e}",
                h.0
            ))),
        }
    }

    async fn watch_process(&self, h: &RuntimeHandle, pid: u32) -> Result<()> {
        let key = (h.0.clone(), pid);
        if !self.watched_processes.lock().unwrap().insert(key.clone()) {
            return Ok(());
        }
        // Set when tenantd started the process itself (not after a restart).
        let child = self.exec_children.lock().unwrap().remove(&key);
        let cmd = self
            .command(&[], &["wait", "--pid", &pid.to_string(), &h.0])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        let (watched, tx, handle) = (self.watched_processes.clone(), self.tx.clone(), h.clone());
        tokio::spawn(async move {
            let waited = match cmd.await {
                Ok(out) if out.status.success() => serde_json::from_slice::<WaitOut>(&out.stdout)
                    .ok()
                    .map(|w| process_status(w.exit_status)),
                Ok(out) => {
                    debug!(sandbox = handle.0, pid, stderr = %String::from_utf8_lossy(&out.stderr), "runsc wait --pid failed");
                    None
                }
                Err(e) => {
                    warn!(sandbox = handle.0, pid, error = %e, "runsc wait --pid could not run");
                    None
                }
            };
            // runsc hands the exit status to one waiter only; when the exec
            // child got it first, its exit code is all that is left.
            let (exit_code, signal) = match (waited, child) {
                (Some(s), _) => s,
                (None, Some(rx)) => rx
                    .await
                    .ok()
                    .flatten()
                    .map_or((None, None), exec_exit_status),
                (None, None) => (None, None),
            };
            watched.lock().unwrap().remove(&key);
            let _ = tx.send(RuntimeEvent::ProcessExited {
                handle,
                pid,
                exit_code,
                signal,
            });
        });
        Ok(())
    }

    async fn list_processes(&self, h: &RuntimeHandle) -> Result<Vec<ProcInfo>> {
        let out = self
            .run(&["ps", "--format=json", &h.0])
            .await
            .map_err(|e| Error::Internal(format!("runsc ps {}: {e}", h.0)))?;
        Ok(parse_ps(&out)?
            .into_iter()
            .map(|pid| ProcInfo { pid })
            .collect())
    }

    async fn exec_piped(&self, h: &RuntimeHandle, p: &ResolvedProcess) -> Result<PipedProcess> {
        use std::hash::{DefaultHasher, Hash, Hasher};
        use tokio::io::AsyncReadExt;

        let id = h.0.clone();
        let process = spec::exec_process(p)?;
        let json = serde_json::to_vec_pretty(&process).context("encoding process.json")?;
        // One file per distinct process (a user's calls share one), in the
        // bundle, which goes with the container.
        let mut hasher = DefaultHasher::new();
        json.hash(&mut hasher);
        let path = self
            .bundle_dir(&id)
            .join(format!("piped-{:016x}.json", hasher.finish()));
        if !tokio::fs::try_exists(&path).await? {
            let tmp = path.with_extension(format!("tmp{}", std::process::id()));
            tokio::fs::write(&tmp, &json).await?;
            tokio::fs::rename(&tmp, &path).await?;
        }
        let mut child = self
            .command(&[], &["exec", "--process", &path.to_string_lossy(), &id])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("running runsc exec")?;
        let (Some(stdin), Some(stdout), Some(mut stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(Error::Internal("runsc exec without its pipes".into()));
        };
        let exit = async move {
            // Read to the end, so a chatty failure can't block on a full
            // pipe, keeping the tail.
            let mut tail = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > PIPED_STDERR_MAX {
                    tail.drain(..tail.len() - PIPED_STDERR_MAX);
                }
            }
            let status = child.wait().await.context("waiting for runsc exec")?;
            if status.success() {
                return Ok(());
            }
            Err(Error::Internal(format!(
                "{} in {id} failed ({status}): {}",
                tenantd_core::files::HELPER_PATH,
                String::from_utf8_lossy(&tail).trim()
            )))
        }
        .boxed();
        Ok(PipedProcess {
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            exit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(
            parse_version("runsc version release-20261005.0\nspec: 1.1.0\n").as_deref(),
            Some("20261005.0")
        );
        assert!(version_key("20261005.0") > version_key("release-20250101.3"));
        assert!(version_key("20261005.1") > version_key("20261005.0"));
    }

    #[test]
    fn errors() {
        assert!(not_found("loading container: file does not exist"));
        assert!(not_found("sending signal: no such process"));
        assert!(!not_found("permission denied"));
    }

    #[test]
    fn process_output_shapes() {
        assert_eq!(process_status(3), (Some(3), None));
        assert_eq!(process_status(-9), (None, Some(9)));
        assert_eq!(exec_exit_status(3), (Some(3), None));
        assert_eq!(exec_exit_status(143), (None, Some(15)));
        assert_eq!(exec_exit_status(128), (None, None));
        assert_eq!(parse_ps("[1,16]\n").unwrap(), vec![1, 16]);
        assert!(parse_ps("null").unwrap().is_empty());
    }
}
