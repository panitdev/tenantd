//! In-memory backends that behave like the real ones (idempotent steps,
//! state the reconcile loop can inspect) with hooks to inject failures and
//! simulate crashes.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use futures::channel::mpsc;
use futures::stream::BoxStream;
use tenantd_core::backend::*;
use tenantd_core::config::{Config, RuntimeKind};
use tenantd_core::model::{
    ImageConfig, LayerKind, NetworkMode, ProcessIo, ResolvedImage, ResolvedProcess,
    ResolvedSandbox, Signal, Stream,
};
use tenantd_core::{
    Backends, Bytes, Error, ProcessId, ProjectId, Result, SandboxId, SandboxKey, TenantId, Tenantd,
};
use tenantd_state::SqliteState;

/// Named failure points. `fail("runtime.start")` makes the next call fail.
#[derive(Default)]
pub struct Faults(Mutex<HashMap<&'static str, usize>>);

impl Faults {
    pub fn fail(&self, point: &'static str) {
        *self.0.lock().unwrap().entry(point).or_default() += 1;
    }

    fn check(&self, point: &'static str) -> Result<()> {
        let mut m = self.0.lock().unwrap();
        match m.get_mut(point) {
            Some(n) if *n > 0 => {
                *n -= 1;
                Err(Error::Internal(format!("injected failure at {point}")))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FakeTenant {
    pub project: Option<ProjectId>,
    pub limit: Bytes,
    pub used: Bytes,
}

pub struct FakeStorage {
    pub root: PathBuf,
    pub tenants: Mutex<HashMap<TenantId, FakeTenant>>,
    pub limits: Mutex<HashMap<ProjectId, Bytes>>,
    pub enforcing: AtomicBool,
    pub faults: Arc<Faults>,
}

#[async_trait]
impl StorageBackend for FakeStorage {
    async fn verify(&self) -> Result<()> {
        if self.enforcing.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Error::Unavailable("quota off".into()))
        }
    }

    fn tenant_dir(&self, t: &TenantId) -> PathBuf {
        self.root.join("tenants").join(t.as_str())
    }

    async fn create_tenant(
        &self,
        t: &TenantId,
        project: ProjectId,
        limit: Bytes,
    ) -> Result<PathBuf> {
        self.faults.check("storage.create_tenant")?;
        let mut m = self.tenants.lock().unwrap();
        let e = m.entry(t.clone()).or_insert(FakeTenant {
            project: None,
            limit: 0,
            used: 0,
        });
        e.project = Some(project);
        self.faults.check("storage.set_limit")?;
        e.limit = limit;
        self.limits.lock().unwrap().insert(project, limit);
        Ok(self.tenant_dir(t))
    }

    async fn set_limit(&self, project: ProjectId, limit: Bytes) -> Result<()> {
        self.faults.check("storage.set_limit")?;
        self.limits.lock().unwrap().insert(project, limit);
        for t in self
            .tenants
            .lock()
            .unwrap()
            .values_mut()
            .filter(|t| t.project == Some(project))
        {
            t.limit = limit;
        }
        Ok(())
    }

    async fn usage(&self, project: ProjectId) -> Result<Usage> {
        let used = self
            .tenants
            .lock()
            .unwrap()
            .values()
            .filter(|t| t.project == Some(project))
            .map(|t| t.used)
            .sum();
        let limit = self
            .limits
            .lock()
            .unwrap()
            .get(&project)
            .copied()
            .unwrap_or(0);
        Ok(Usage { used, limit })
    }

    async fn delete_tenant(&self, t: &TenantId, project: Option<ProjectId>) -> Result<()> {
        self.faults.check("storage.delete_tenant")?;
        self.tenants.lock().unwrap().remove(t);
        if let Some(p) = project {
            self.limits.lock().unwrap().remove(&p);
        }
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<(TenantId, Option<ProjectId>)>> {
        Ok(self
            .tenants
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.project))
            .collect())
    }
}

pub struct FakeLayer {
    pub kind: LayerKind,
    pub survives_stop: bool,
    /// (tenant dir, sandbox) -> mounted?
    pub dirs: Arc<Mutex<HashMap<(PathBuf, SandboxId), bool>>>,
    pub faults: Arc<Faults>,
}

#[async_trait]
impl WritableLayer for FakeLayer {
    fn kind(&self) -> LayerKind {
        self.kind
    }

    fn traits(&self) -> LayerTraits {
        LayerTraits {
            accounting: if self.survives_stop {
                Accounting::Exact
            } else {
                Accounting::Memory
            },
            reclaim: Reclaim::Immediate,
            survives_stop: self.survives_stop,
            needs_size_cap: false,
            runtimes: &[RuntimeKind::RunscDirect],
        }
    }

    async fn prepare(&self, s: &ResolvedSandbox, tenant_dir: &Path) -> Result<RootfsSpec> {
        self.faults.check("layer.prepare")?;
        let root = tenant_dir
            .join("sandboxes")
            .join(s.key.sandbox.as_str())
            .join("rootfs");
        self.dirs
            .lock()
            .unwrap()
            .insert((tenant_dir.to_path_buf(), s.key.sandbox.clone()), true);
        Ok(match self.kind {
            LayerKind::Memory => RootfsSpec::Memory(root),
            LayerKind::ReadOnly => RootfsSpec::ReadOnly(root),
            _ => RootfsSpec::Path(root),
        })
    }

    async fn reclaim(&self, _h: &RuntimeHandle) -> Result<ReclaimOutcome> {
        Ok(ReclaimOutcome::NotNeeded)
    }

    async fn teardown(&self, s: &SandboxId, tenant_dir: &Path) -> Result<()> {
        self.faults.check("layer.teardown")?;
        self.dirs
            .lock()
            .unwrap()
            .remove(&(tenant_dir.to_path_buf(), s.clone()));
        Ok(())
    }

    async fn list_owned(&self, tenant_dir: &Path) -> Result<Vec<SandboxId>> {
        Ok(self
            .dirs
            .lock()
            .unwrap()
            .keys()
            .filter(|(d, _)| d == tenant_dir)
            .map(|(_, s)| s.clone())
            .collect())
    }
}

pub struct FakeRuntime {
    pub containers: Mutex<HashMap<RuntimeHandle, RuntimeState>>,
    pub watched: Mutex<HashSet<RuntimeHandle>>,
    pub created_specs: Mutex<Vec<(ResolvedSandbox, RootfsSpec, NetAttachment)>>,
    pub verified: AtomicBool,
    pub faults: Arc<Faults>,
    /// Exec'd processes still alive, by container.
    pub processes: Mutex<HashSet<(RuntimeHandle, u32)>>,
    pub watched_processes: Mutex<HashSet<(RuntimeHandle, u32)>>,
    /// What each exec was asked to run.
    pub execs: Mutex<Vec<ResolvedProcess>>,
    pub signals: Mutex<Vec<(RuntimeHandle, u32, Signal)>>,
    /// PID files written by exec, as runsc's `--internal-pid-file` would.
    pub pid_files: Mutex<HashMap<PathBuf, u32>>,
    next_pid: AtomicU32,
    tx: mpsc::UnboundedSender<RuntimeEvent>,
    rx: Mutex<Option<mpsc::UnboundedReceiver<RuntimeEvent>>>,
}

impl FakeRuntime {
    fn new(faults: Arc<Faults>) -> Self {
        let (tx, rx) = mpsc::unbounded();
        Self {
            containers: Mutex::default(),
            watched: Mutex::default(),
            created_specs: Mutex::default(),
            verified: AtomicBool::new(true),
            faults,
            processes: Mutex::default(),
            watched_processes: Mutex::default(),
            execs: Mutex::default(),
            signals: Mutex::default(),
            pid_files: Mutex::default(),
            next_pid: AtomicU32::new(100),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    /// An exec'd process exits on its own; reported if it is watched.
    pub fn exit_process(&self, k: &SandboxKey, pid: u32, code: i32) {
        self.end_process(&RuntimeHandle::for_key(k), pid, Some(code), None);
    }

    fn end_process(
        &self,
        h: &RuntimeHandle,
        pid: u32,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) {
        let key = (h.clone(), pid);
        let alive = self.processes.lock().unwrap().remove(&key);
        if alive && self.watched_processes.lock().unwrap().remove(&key) {
            let _ = self.tx.unbounded_send(RuntimeEvent::ProcessExited {
                handle: h.clone(),
                pid,
                exit_code,
                signal,
            });
        }
    }

    /// The container's processes die with it, unreported (a real `runsc
    /// wait --pid` would fail).
    fn kill_processes(&self, h: &RuntimeHandle) {
        self.processes.lock().unwrap().retain(|(c, _)| c != h);
        self.watched_processes
            .lock()
            .unwrap()
            .retain(|(c, _)| c != h);
    }

    pub fn alive(&self, k: &SandboxKey, pid: u32) -> bool {
        self.processes
            .lock()
            .unwrap()
            .contains(&(RuntimeHandle::for_key(k), pid))
    }

    /// The workload exits on its own.
    pub fn exit(&self, k: &SandboxKey, code: i32, oom: bool) {
        let h = RuntimeHandle::for_key(k);
        self.containers
            .lock()
            .unwrap()
            .insert(h.clone(), RuntimeState::Stopped);
        let _ = self.tx.unbounded_send(RuntimeEvent::Exited {
            handle: h,
            exit_code: Some(code),
            oom,
        });
    }

    pub fn state(&self, k: &SandboxKey) -> RuntimeState {
        self.containers
            .lock()
            .unwrap()
            .get(&RuntimeHandle::for_key(k))
            .copied()
            .unwrap_or(RuntimeState::Missing)
    }
}

#[async_trait]
impl RuntimeBackend for FakeRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::RunscDirect
    }

    async fn verify(&self) -> Result<()> {
        if self.verified.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Error::Unavailable("runsc missing".into()))
        }
    }

    async fn create(
        &self,
        spec: &ResolvedSandbox,
        root: &RootfsSpec,
        net: &NetAttachment,
    ) -> Result<RuntimeHandle> {
        self.faults.check("runtime.create")?;
        let h = RuntimeHandle::for_key(&spec.key);
        let mut c = self.containers.lock().unwrap();
        if c.contains_key(&h) {
            return Err(Error::AlreadyExists(h.0));
        }
        c.insert(h.clone(), RuntimeState::Created);
        self.created_specs
            .lock()
            .unwrap()
            .push((spec.clone(), root.clone(), net.clone()));
        Ok(h)
    }

    async fn start(&self, h: &RuntimeHandle) -> Result<()> {
        self.faults.check("runtime.start")?;
        match self.containers.lock().unwrap().get_mut(h) {
            Some(s @ RuntimeState::Created) => {
                *s = RuntimeState::Running;
                Ok(())
            }
            other => Err(Error::FailedPrecondition(format!(
                "start {}: {other:?}",
                h.0
            ))),
        }
    }

    async fn stop(&self, h: &RuntimeHandle, _grace: Duration) -> Result<()> {
        self.faults.check("runtime.stop")?;
        if let Some(s) = self.containers.lock().unwrap().get_mut(h) {
            *s = RuntimeState::Stopped;
        }
        self.kill_processes(h);
        Ok(())
    }

    async fn destroy(&self, h: &RuntimeHandle) -> Result<()> {
        self.faults.check("runtime.destroy")?;
        self.containers.lock().unwrap().remove(h);
        self.watched.lock().unwrap().remove(h);
        self.kill_processes(h);
        Ok(())
    }

    async fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeState> {
        Ok(self
            .containers
            .lock()
            .unwrap()
            .get(h)
            .copied()
            .unwrap_or(RuntimeState::Missing))
    }

    async fn list_owned(&self) -> Result<Vec<RuntimeHandle>> {
        Ok(self.containers.lock().unwrap().keys().cloned().collect())
    }

    async fn watch(&self, h: &RuntimeHandle) -> Result<()> {
        self.watched.lock().unwrap().insert(h.clone());
        Ok(())
    }

    fn events(&self) -> BoxStream<'static, RuntimeEvent> {
        match self.rx.lock().unwrap().take() {
            Some(rx) => rx.boxed(),
            None => futures::stream::empty().boxed(),
        }
    }

    /// Fault points: `runtime.exec` fails before anything runs;
    /// `runtime.exec.after_start` fails after the process started and its
    /// PID file was written.
    async fn exec(&self, h: &RuntimeHandle, p: &ResolvedProcess, io: &ProcessIo) -> Result<u32> {
        self.faults.check("runtime.exec")?;
        if self.containers.lock().unwrap().get(h) != Some(&RuntimeState::Running) {
            return Err(Error::FailedPrecondition(format!("{} is not running", h.0)));
        }
        let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        self.processes.lock().unwrap().insert((h.clone(), pid));
        self.pid_files
            .lock()
            .unwrap()
            .insert(io.pid_file.clone(), pid);
        self.execs.lock().unwrap().push(p.clone());
        self.faults.check("runtime.exec.after_start")?;
        Ok(pid)
    }

    async fn recorded_pid(&self, io: &ProcessIo) -> Result<Option<u32>> {
        Ok(self.pid_files.lock().unwrap().get(&io.pid_file).copied())
    }

    /// Terminating signals end the process (reported like a real exit);
    /// SIGUSR1/2 are only recorded.
    async fn signal(&self, h: &RuntimeHandle, pid: u32, sig: Signal) -> Result<()> {
        self.faults.check("runtime.signal")?;
        self.signals.lock().unwrap().push((h.clone(), pid, sig));
        if !matches!(sig, Signal::Usr1 | Signal::Usr2) {
            self.end_process(h, pid, None, Some(sig.number()));
        }
        Ok(())
    }

    async fn watch_process(&self, h: &RuntimeHandle, pid: u32) -> Result<()> {
        self.faults.check("runtime.watch_process")?;
        self.watched_processes
            .lock()
            .unwrap()
            .insert((h.clone(), pid));
        Ok(())
    }

    async fn list_processes(&self, h: &RuntimeHandle) -> Result<Vec<ProcInfo>> {
        if self.containers.lock().unwrap().get(h) != Some(&RuntimeState::Running) {
            return Err(Error::FailedPrecondition(format!("{} is not running", h.0)));
        }
        Ok(self
            .processes
            .lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| c == h)
            .map(|&(_, pid)| ProcInfo { pid })
            .collect())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeFile {
    /// Bytes still on disk: the head, once a limit is enforced.
    pub data: Vec<u8>,
    /// Bytes written (the file's logical size).
    pub size: Bytes,
}

/// Output files in memory. A watched file keeps only its head, as the
/// punch-hole watcher would.
#[derive(Default)]
pub struct FakeOutput {
    pub files: Mutex<HashMap<PathBuf, FakeFile>>,
    /// Watched process directories and their limits.
    pub watched: Mutex<HashMap<PathBuf, Bytes>>,
    pub faults: Arc<Faults>,
}

impl FakeOutput {
    /// The process writes to one of its streams.
    pub fn write(&self, io: &ProcessIo, s: Stream, bytes: &[u8]) {
        let limit = self.watched.lock().unwrap().get(&io.dir).copied();
        let mut files = self.files.lock().unwrap();
        let f = files.entry(io.stream(s).clone()).or_default();
        f.size += bytes.len() as Bytes;
        f.data.extend_from_slice(bytes);
        if let Some(l) = limit {
            f.data.truncate(l as usize);
        }
    }

    fn trim_now(&self, io: &ProcessIo, limit: Bytes) {
        let mut files = self.files.lock().unwrap();
        for p in [&io.stdout, &io.stderr] {
            if let Some(f) = files.get_mut(p) {
                f.data.truncate(limit as usize);
            }
        }
    }
}

#[async_trait]
impl OutputStore for FakeOutput {
    fn io(&self, tenant_dir: &Path, s: &SandboxId, p: &ProcessId) -> ProcessIo {
        let dir = tenant_dir
            .join("sandboxes")
            .join(s.as_str())
            .join("processes")
            .join(p.as_str());
        ProcessIo {
            stdout: dir.join("stdout"),
            stderr: dir.join("stderr"),
            pid_file: dir.join("pid"),
            dir,
        }
    }

    async fn prepare(&self, io: &ProcessIo) -> Result<()> {
        self.faults.check("output.prepare")?;
        let mut files = self.files.lock().unwrap();
        files.insert(io.stdout.clone(), FakeFile::default());
        files.insert(io.stderr.clone(), FakeFile::default());
        Ok(())
    }

    async fn watch(&self, io: &ProcessIo, limit: Bytes) -> Result<()> {
        self.watched.lock().unwrap().insert(io.dir.clone(), limit);
        self.trim_now(io, limit);
        Ok(())
    }

    async fn unwatch(&self, io: &ProcessIo) {
        self.watched.lock().unwrap().remove(&io.dir);
    }

    async fn trim(&self, io: &ProcessIo, limit: Bytes) -> Result<()> {
        self.trim_now(io, limit);
        Ok(())
    }

    async fn sizes(&self, io: &ProcessIo) -> Result<(Bytes, Bytes)> {
        let files = self.files.lock().unwrap();
        let size = |p: &PathBuf| files.get(p).map_or(0, |f| f.size);
        Ok((size(&io.stdout), size(&io.stderr)))
    }

    async fn read(&self, io: &ProcessIo, s: Stream, offset: Bytes, len: usize) -> Result<Vec<u8>> {
        let files = self.files.lock().unwrap();
        Ok(files
            .get(io.stream(s))
            .map(|f| {
                let start = (offset as usize).min(f.data.len());
                f.data[start..(start + len).min(f.data.len())].to_vec()
            })
            .unwrap_or_default())
    }

    async fn remove(&self, io: &ProcessIo) -> Result<()> {
        self.faults.check("output.remove")?;
        self.watched.lock().unwrap().remove(&io.dir);
        self.files
            .lock()
            .unwrap()
            .retain(|p, _| !p.starts_with(&io.dir));
        Ok(())
    }
}

#[derive(Default)]
pub struct FakeImages {
    pub pulled: Mutex<HashSet<String>>,
    pub faults: Arc<Faults>,
}

pub fn fake_digest(reference: &str) -> String {
    let h = reference.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100000001b3)
    });
    format!("sha256:{h:064x}")
}

#[async_trait]
impl ImageStore for FakeImages {
    async fn resolve(&self, reference: &str) -> Result<ResolvedImage> {
        self.faults.check("images.resolve")?;
        let digest = fake_digest(reference);
        self.pulled.lock().unwrap().insert(digest.clone());
        Ok(ResolvedImage {
            reference: reference.into(),
            digest: digest.clone(),
            layers: vec![PathBuf::from("/fake/layers").join(&digest[7..])],
            config: ImageConfig {
                cmd: vec!["/bin/sh".into()],
                ..Default::default()
            },
        })
    }

    async fn gc(&self, in_use: &HashSet<String>) -> Result<GcReport> {
        let mut p = self.pulled.lock().unwrap();
        let gone: Vec<String> = p.iter().filter(|d| !in_use.contains(*d)).cloned().collect();
        p.retain(|d| in_use.contains(d));
        Ok(GcReport {
            images: gone,
            layers: vec![],
        })
    }
}

#[derive(Default)]
pub struct FakeNetwork {
    pub namespaces: Mutex<HashMap<SandboxKey, NetworkMode>>,
    pub faults: Arc<Faults>,
}

#[async_trait]
impl NetworkBackend for FakeNetwork {
    async fn verify(&self) -> Result<()> {
        Ok(())
    }

    async fn setup(&self, key: &SandboxKey, mode: NetworkMode) -> Result<NetAttachment> {
        self.faults.check("network.setup")?;
        self.namespaces.lock().unwrap().insert(key.clone(), mode);
        Ok(NetAttachment {
            netns: PathBuf::from("/run/fake/netns").join(key.to_string()),
        })
    }

    async fn teardown(&self, key: &SandboxKey) -> Result<()> {
        self.faults.check("network.teardown")?;
        self.namespaces.lock().unwrap().remove(key);
        Ok(())
    }

    async fn list_owned(&self) -> Result<Vec<SandboxKey>> {
        Ok(self.namespaces.lock().unwrap().keys().cloned().collect())
    }
}

pub const TEST_CONFIG: &str = r#"
[server]
socket = "/run/tenantd/api.sock"
state = "/var/lib/tenantd/state.db"

[storage]
backend = "xfs-project"
root = "/data"
project_id_range = [100, 199]

[runtime]
backend = "runsc-direct"
runsc = "/usr/local/bin/runsc"
root = "/run/tenantd/runsc"

[images]
cache = "/data/images"

[network]
cni_bin = "/opt/cni/bin"
egress_subnet = "10.88.0.0/16"

[profiles.default]
images = ["docker.io/library/*", "ghcr.io/example/*"]
memory = "4g"
cpus = 2.0
pids = 1024
rootfs = "host-overlay"
network = "egress"

[profiles.default.exec]
enabled = true
users = ["image", "1000"]
max_processes = 2
output_limit = 16
retention_secs = 60
tombstone_secs = 120

[profiles.scratch]
images = ["docker.io/library/*"]
memory = "1g"
cpus = 1.0
pids = 512
rootfs = "memory"
network = "none"
"#;

/// The fake host: everything that would survive a daemon crash.
pub struct Host {
    pub storage: Arc<FakeStorage>,
    pub layer_dirs: Arc<Mutex<HashMap<(PathBuf, SandboxId), bool>>>,
    pub runtime: Arc<FakeRuntime>,
    pub images: Arc<FakeImages>,
    pub network: Arc<FakeNetwork>,
    pub output: Arc<FakeOutput>,
    pub state: SqliteState,
    pub faults: Arc<Faults>,
}

impl Host {
    pub fn new() -> Self {
        let faults = Arc::new(Faults::default());
        Self {
            storage: Arc::new(FakeStorage {
                root: "/data".into(),
                tenants: Mutex::default(),
                limits: Mutex::default(),
                enforcing: AtomicBool::new(true),
                faults: faults.clone(),
            }),
            layer_dirs: Arc::default(),
            runtime: Arc::new(FakeRuntime::new(faults.clone())),
            images: Arc::new(FakeImages {
                faults: faults.clone(),
                ..Default::default()
            }),
            network: Arc::new(FakeNetwork {
                faults: faults.clone(),
                ..Default::default()
            }),
            output: Arc::new(FakeOutput {
                faults: faults.clone(),
                ..Default::default()
            }),
            state: SqliteState::in_memory().unwrap(),
            faults,
        }
    }

    pub fn service(&self, cfg: &str) -> Arc<Tenantd> {
        let layer = |kind, survives_stop| -> Arc<dyn WritableLayer> {
            Arc::new(FakeLayer {
                kind,
                survives_stop,
                dirs: self.layer_dirs.clone(),
                faults: self.faults.clone(),
            })
        };
        Tenantd::new(
            Config::from_toml(cfg).unwrap(),
            Backends {
                storage: self.storage.clone(),
                layers: vec![
                    layer(LayerKind::HostOverlay, true),
                    layer(LayerKind::Memory, false),
                    layer(LayerKind::ReadOnly, false),
                ],
                runtime: self.runtime.clone(),
                images: self.images.clone(),
                network: self.network.clone(),
                output: self.output.clone(),
                state: Arc::new(self.state.clone()),
            },
        )
        .unwrap()
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

/// A service wired to a fake host, with health already checked.
pub struct Env {
    pub tenantd: Arc<Tenantd>,
    pub host: Host,
}

impl Env {
    pub async fn new() -> Self {
        let host = Host::new();
        let tenantd = host.service(TEST_CONFIG);
        tenantd.check_health().await;
        Self { tenantd, host }
    }

    /// Simulate a daemon crash and restart: a fresh service over the same
    /// host and state. In-memory locks, health and blocks are lost, and so
    /// are the runtime's process watches and the output watcher.
    pub async fn restart(&mut self) {
        self.host.runtime.watched_processes.lock().unwrap().clear();
        self.host.output.watched.lock().unwrap().clear();
        self.tenantd = self.host.service(TEST_CONFIG);
        self.tenantd.check_health().await;
    }
}
