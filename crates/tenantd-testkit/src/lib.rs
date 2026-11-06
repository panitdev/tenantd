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
use tenantd_core::fuse::{
    FuseEvent, FuseLimits, FuseLink, FuseOp, FuseResult, FuseSession, InvalidateTarget,
};
use tenantd_core::model::{
    ImageConfig, LayerKind, NetworkMode, ProcessIo, PruneReport, ResolvedImage, ResolvedProcess,
    ResolvedSandbox, Signal, Stream, VolumeOwner,
};
use tenantd_core::{
    Backends, Bytes, ContainerId, ContainerKey, Error, ProcessId, ProjectId, Result, SandboxId,
    SandboxKey, TenantId, Tenantd, VolumeId,
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
    /// Container roots, (tenant dir, sandbox, container).
    pub container_dirs: Arc<Mutex<HashSet<(PathBuf, SandboxId, ContainerId)>>>,
    /// Where container roots are real directories, for file access; unset,
    /// they are only paths under the fake storage root.
    pub files_dir: Arc<Mutex<Option<PathBuf>>>,
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
            host_root: self.kind != LayerKind::Memory,
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
        // Container roots live inside the sandbox's directory.
        self.container_dirs
            .lock()
            .unwrap()
            .retain(|(d, sb, _)| !(d == tenant_dir && sb == s));
        Ok(())
    }

    async fn prepare_container(
        &self,
        s: &ResolvedSandbox,
        c: &ContainerId,
        tenant_dir: &Path,
    ) -> Result<RootfsSpec> {
        self.faults.check("layer.prepare_container")?;
        let root = tenant_dir
            .join("sandboxes")
            .join(s.key.sandbox.as_str())
            .join("containers")
            .join(c.as_str())
            .join("rootfs");
        self.container_dirs.lock().unwrap().insert((
            tenant_dir.to_path_buf(),
            s.key.sandbox.clone(),
            c.clone(),
        ));
        Ok(match self.kind {
            LayerKind::Memory => RootfsSpec::Memory(root),
            LayerKind::ReadOnly => RootfsSpec::ReadOnly(root),
            _ => RootfsSpec::Path(root),
        })
    }

    async fn container_files_root(
        &self,
        s: &SandboxId,
        c: &ContainerId,
        tenant_dir: &Path,
    ) -> Result<Option<PathBuf>> {
        self.faults.check("layer.container_files_root")?;
        if self.kind == LayerKind::Memory {
            return Ok(None);
        }
        let key = (tenant_dir.to_path_buf(), s.clone(), c.clone());
        if !self.container_dirs.lock().unwrap().contains(&key) {
            return Err(Error::FailedPrecondition(format!(
                "container root of {s}.{c} is not mounted"
            )));
        }
        let base = self.files_dir.lock().unwrap().clone();
        Ok(Some(match base {
            Some(b) => {
                let root = b.join(s.as_str()).join(c.as_str());
                std::fs::create_dir_all(&root)?;
                root
            }
            None => tenant_dir
                .join("sandboxes")
                .join(s.as_str())
                .join("containers")
                .join(c.as_str())
                .join("rootfs"),
        }))
    }

    async fn teardown_container(
        &self,
        s: &SandboxId,
        c: &ContainerId,
        tenant_dir: &Path,
    ) -> Result<()> {
        self.faults.check("layer.teardown_container")?;
        self.container_dirs.lock().unwrap().remove(&(
            tenant_dir.to_path_buf(),
            s.clone(),
            c.clone(),
        ));
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

/// A container the runtime was asked to create: key, init, root, binds.
pub type CreatedContainer = (ContainerKey, Vec<String>, RootfsSpec, Vec<BindMount>);

/// Stands in for the file helper exec'd in a container; see
/// [`FakeRuntime::helper`].
pub type HelperFn =
    Arc<dyn Fn(&RuntimeHandle, &ResolvedProcess) -> Result<PipedProcess> + Send + Sync>;

pub struct FakeRuntime {
    pub containers: Mutex<HashMap<RuntimeHandle, RuntimeState>>,
    pub watched: Mutex<HashSet<RuntimeHandle>>,
    pub created_specs: Mutex<Vec<(ResolvedSandbox, RootfsSpec, NetAttachment)>>,
    /// Containers created in sandboxes, with their init, roots and binds.
    pub created_containers: Mutex<Vec<CreatedContainer>>,
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
    /// Containers created with host file access.
    pub host_file_access: Mutex<HashSet<ContainerKey>>,
    /// What `exec_piped` runs; unset, it fails.
    pub helper: Mutex<Option<HelperFn>>,
    /// What each `exec_piped` was asked to run.
    pub piped: Mutex<Vec<ResolvedProcess>>,
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
            created_containers: Mutex::default(),
            verified: AtomicBool::new(true),
            faults,
            processes: Mutex::default(),
            watched_processes: Mutex::default(),
            execs: Mutex::default(),
            signals: Mutex::default(),
            pid_files: Mutex::default(),
            host_file_access: Mutex::default(),
            helper: Mutex::default(),
            piped: Mutex::default(),
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

    /// A container's init exits on its own.
    pub fn exit_container(&self, k: &ContainerKey, code: i32) {
        let h = RuntimeHandle::for_container(k);
        self.containers
            .lock()
            .unwrap()
            .insert(h.clone(), RuntimeState::Stopped);
        self.kill_processes(&h);
        let _ = self.tx.unbounded_send(RuntimeEvent::Exited {
            handle: h,
            exit_code: Some(code),
            oom: false,
        });
    }

    pub fn container_state(&self, k: &ContainerKey) -> RuntimeState {
        self.containers
            .lock()
            .unwrap()
            .get(&RuntimeHandle::for_container(k))
            .copied()
            .unwrap_or(RuntimeState::Missing)
    }

    pub fn container_alive(&self, k: &ContainerKey, pid: u32) -> bool {
        self.processes
            .lock()
            .unwrap()
            .contains(&(RuntimeHandle::for_container(k), pid))
    }

    /// A sandbox going down takes the containers in it along, as gVisor
    /// does: they stop, unreported.
    fn stop_containers_in(&self, h: &RuntimeHandle) {
        let prefix = format!("{}.", h.0);
        let inside: Vec<RuntimeHandle> = self
            .containers
            .lock()
            .unwrap()
            .keys()
            .filter(|c| c.0.starts_with(&prefix))
            .cloned()
            .collect();
        for c in inside {
            self.containers
                .lock()
                .unwrap()
                .insert(c.clone(), RuntimeState::Stopped);
            self.kill_processes(&c);
        }
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

    fn runtime_mounts(&self, _s: &ResolvedSandbox) -> Vec<String> {
        vec!["/proc".into(), "/dev".into()]
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

    async fn create_container(
        &self,
        s: &ResolvedSandbox,
        run: &ContainerRun<'_>,
        _net: &NetAttachment,
    ) -> Result<RuntimeHandle> {
        self.faults.check("runtime.create_container")?;
        let ContainerRun {
            key: c,
            args,
            root,
            mounts,
            host_file_access,
        } = *run;
        let sandbox = RuntimeHandle::for_key(&s.key);
        let h = RuntimeHandle::for_container(c);
        let mut m = self.containers.lock().unwrap();
        if m.get(&sandbox) != Some(&RuntimeState::Running) {
            return Err(Error::FailedPrecondition(format!(
                "sandbox {} is not running",
                sandbox.0
            )));
        }
        if m.contains_key(&h) {
            return Err(Error::AlreadyExists(h.0));
        }
        m.insert(h.clone(), RuntimeState::Created);
        if host_file_access {
            self.host_file_access.lock().unwrap().insert(c.clone());
        }
        self.created_containers.lock().unwrap().push((
            c.clone(),
            args.to_vec(),
            root.clone(),
            mounts.to_vec(),
        ));
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
        self.stop_containers_in(h);
        Ok(())
    }

    async fn destroy(&self, h: &RuntimeHandle) -> Result<()> {
        self.faults.check("runtime.destroy")?;
        self.containers.lock().unwrap().remove(h);
        self.watched.lock().unwrap().remove(h);
        self.kill_processes(h);
        self.stop_containers_in(h);
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

    async fn exec_piped(&self, h: &RuntimeHandle, p: &ResolvedProcess) -> Result<PipedProcess> {
        self.faults.check("runtime.exec_piped")?;
        if self.containers.lock().unwrap().get(h) != Some(&RuntimeState::Running) {
            return Err(Error::FailedPrecondition(format!("{} is not running", h.0)));
        }
        self.piped.lock().unwrap().push(p.clone());
        let helper = self.helper.lock().unwrap().clone();
        match helper {
            Some(f) => f(h, p),
            None => Err(Error::Unavailable("no file helper in the fake".into())),
        }
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

/// Volume directories, by (tenant dir, volume), with what each holds.
#[derive(Default)]
pub struct FakeVolumes {
    pub dirs: Mutex<HashMap<(PathBuf, VolumeId), FakeVolume>>,
    pub faults: Arc<Faults>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeVolume {
    pub owner: Option<VolumeOwner>,
    /// Relative path -> last used (Unix seconds).
    pub files: HashMap<PathBuf, i64>,
}

impl FakeVolumes {
    /// A container or the host writes a file into a volume.
    pub fn write(&self, tenant_dir: &Path, v: &VolumeId, path: &str, used: i64) {
        if let Some(vol) = self
            .dirs
            .lock()
            .unwrap()
            .get_mut(&(tenant_dir.to_path_buf(), v.clone()))
        {
            vol.files.insert(path.into(), used);
        }
    }

    pub fn files(&self, tenant_dir: &Path, v: &VolumeId) -> Vec<PathBuf> {
        let mut f: Vec<PathBuf> = self
            .dirs
            .lock()
            .unwrap()
            .get(&(tenant_dir.to_path_buf(), v.clone()))
            .map(|v| v.files.keys().cloned().collect())
            .unwrap_or_default();
        f.sort();
        f
    }
}

#[async_trait]
impl VolumeBackend for FakeVolumes {
    fn path(&self, tenant_dir: &Path, v: &VolumeId) -> PathBuf {
        tenant_dir.join("volumes").join(v.as_str())
    }

    async fn create(&self, tenant_dir: &Path, v: &VolumeId, owner: VolumeOwner) -> Result<PathBuf> {
        self.faults.check("volumes.create")?;
        self.dirs
            .lock()
            .unwrap()
            .entry((tenant_dir.to_path_buf(), v.clone()))
            .or_default()
            .owner = Some(owner);
        Ok(self.path(tenant_dir, v))
    }

    async fn exists(&self, tenant_dir: &Path, v: &VolumeId) -> Result<bool> {
        Ok(self
            .dirs
            .lock()
            .unwrap()
            .contains_key(&(tenant_dir.to_path_buf(), v.clone())))
    }

    async fn delete(&self, tenant_dir: &Path, v: &VolumeId) -> Result<()> {
        self.faults.check("volumes.delete")?;
        self.dirs
            .lock()
            .unwrap()
            .remove(&(tenant_dir.to_path_buf(), v.clone()));
        Ok(())
    }

    /// Files only; directories are implied by their paths.
    async fn prune(
        &self,
        tenant_dir: &Path,
        v: &VolumeId,
        prefix: &Path,
        cutoff: Option<i64>,
    ) -> Result<PruneReport> {
        let mut dirs = self.dirs.lock().unwrap();
        let Some(vol) = dirs.get_mut(&(tenant_dir.to_path_buf(), v.clone())) else {
            return Err(Error::Internal(format!("no volume directory {v}")));
        };
        let before = vol.files.len();
        vol.files
            .retain(|p, used| !(p.starts_with(prefix) && cutoff.is_none_or(|c| *used <= c)));
        Ok(PruneReport {
            entries: (before - vol.files.len()) as u64,
            bytes: 0,
        })
    }

    async fn list_owned(&self, tenant_dir: &Path) -> Result<Vec<VolumeId>> {
        Ok(self
            .dirs
            .lock()
            .unwrap()
            .keys()
            .filter(|(d, _)| d == tenant_dir)
            .map(|(_, v)| v.clone())
            .collect())
    }
}

/// FUSE mounts on the fake host. A session stands in for the kernel side
/// of a mount: a test pushes requests at the attached server with
/// [`FakeFuse::inject`] and reads what it answered with
/// [`FakeFuse::responses`].
#[derive(Default)]
pub struct FakeFuse {
    /// Mounted containers, and whether this service instance holds the
    /// session (`false` after a restart).
    pub mounted: Mutex<HashMap<ContainerKey, bool>>,
    sessions: Mutex<HashMap<ContainerKey, Arc<FakeSession>>>,
    pub faults: Arc<Faults>,
}

#[derive(Default)]
struct FakeSessionInner {
    generation: u64,
    events: Option<tokio::sync::mpsc::Sender<FuseEvent>>,
    next_id: u64,
    responses: Vec<(u64, FuseResult)>,
    invalidations: Vec<InvalidateTarget>,
    /// Servers that went away, by generation.
    detached: Vec<u64>,
}

#[derive(Default)]
struct FakeSession {
    inner: Mutex<FakeSessionInner>,
}

impl FuseSession for FakeSession {
    fn respond(&self, generation: u64, id: u64, result: FuseResult) {
        let mut g = self.inner.lock().unwrap();
        if g.generation == generation {
            g.responses.push((id, result));
        }
    }

    fn invalidate(&self, generation: u64, target: InvalidateTarget) {
        let mut g = self.inner.lock().unwrap();
        if g.generation == generation {
            g.invalidations.push(target);
        }
    }

    fn detach(&self, generation: u64) {
        let mut g = self.inner.lock().unwrap();
        g.detached.push(generation);
        if g.generation == generation {
            g.events = None;
        }
    }
}

impl FakeFuse {
    /// What a daemon restart does: the sessions are gone, the mounts stay.
    pub fn lose_sessions(&self) {
        self.sessions.lock().unwrap().clear();
        for held in self.mounted.lock().unwrap().values_mut() {
            *held = false;
        }
    }

    pub fn is_mounted(&self, c: &ContainerKey) -> bool {
        self.mounted.lock().unwrap().contains_key(c)
    }

    fn session(&self, c: &ContainerKey) -> Option<Arc<FakeSession>> {
        self.sessions.lock().unwrap().get(c).cloned()
    }

    /// Send a request to `c`'s attached server, as the kernel would.
    /// Returns its id, or `None` with no server attached.
    pub fn inject(&self, c: &ContainerKey, op: FuseOp) -> Option<u64> {
        let s = self.session(c)?;
        let mut g = s.inner.lock().unwrap();
        g.next_id += 1;
        let id = g.next_id;
        let tx = g.events.as_ref()?;
        tx.try_send(FuseEvent::Request {
            id,
            caller: Default::default(),
            op,
        })
        .ok()?;
        Some(id)
    }

    /// What the current server answered, in order.
    pub fn responses(&self, c: &ContainerKey) -> Vec<(u64, FuseResult)> {
        self.session(c)
            .map(|s| s.inner.lock().unwrap().responses.clone())
            .unwrap_or_default()
    }

    /// What the current server asked to invalidate.
    pub fn invalidations(&self, c: &ContainerKey) -> Vec<InvalidateTarget> {
        self.session(c)
            .map(|s| s.inner.lock().unwrap().invalidations.clone())
            .unwrap_or_default()
    }

    /// Whether a server is attached to `c` now.
    pub fn has_server(&self, c: &ContainerKey) -> bool {
        self.session(c)
            .is_some_and(|s| s.inner.lock().unwrap().events.is_some())
    }

    /// How many servers have attached to `c` over its session.
    pub fn attaches(&self, c: &ContainerKey) -> u64 {
        self.session(c)
            .map_or(0, |s| s.inner.lock().unwrap().generation)
    }
}

#[async_trait]
impl FuseBackend for FakeFuse {
    async fn mount(&self, c: &ContainerKey) -> Result<PathBuf> {
        self.faults.check("fuse.mount")?;
        let point = PathBuf::from("/run/fake/fuse").join(c.to_string());
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.contains_key(c) {
            return Ok(point);
        }
        sessions.insert(c.clone(), Arc::new(FakeSession::default()));
        self.mounted.lock().unwrap().insert(c.clone(), true);
        Ok(point)
    }

    fn attach(&self, c: &ContainerKey, theirs: FuseLimits) -> Result<Option<FuseLink>> {
        let Some(s) = self.session(c) else {
            return Ok(None);
        };
        let limits = FuseLimits::SERVER.negotiate(theirs);
        let (tx, rx) = tokio::sync::mpsc::channel(limits.max_inflight as usize + 1);
        let mut g = s.inner.lock().unwrap();
        if let Some(old) = g.events.replace(tx) {
            let _ = old.try_send(FuseEvent::Replaced);
        }
        g.generation += 1;
        g.responses.clear();
        g.invalidations.clear();
        let generation = g.generation;
        drop(g);
        Ok(Some(FuseLink::new(generation, limits, rx, s)))
    }

    fn has_session(&self, c: &ContainerKey) -> bool {
        self.sessions.lock().unwrap().contains_key(c)
    }

    async fn unmount(&self, c: &ContainerKey) -> Result<()> {
        self.faults.check("fuse.unmount")?;
        self.sessions.lock().unwrap().remove(c);
        self.mounted.lock().unwrap().remove(c);
        Ok(())
    }

    async fn list_owned(&self) -> Result<Vec<ContainerKey>> {
        Ok(self.mounted.lock().unwrap().keys().cloned().collect())
    }
}

pub const TEST_CONFIG: &str = r#"
[server]
socket = "/run/tenantd/api.sock"
state = "/var/lib/tenantd/state.db"

[[server.callers]]
uid = 1000

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

[profiles.default.volumes.workspace]
path = "/workspace"

[profiles.default.volumes.tmp]
path = "/tmp"

[profiles.default.volumes.cache]
path = "/cache"
read_only = true

[profiles.default.fuse]
path = "/mnt"

[profiles.pinned]
images = ["docker.io/library/*"]
memory = "1g"
cpus = 1.0
pids = 512
rootfs = "host-overlay"
network = "none"

[profiles.pinned.volumes.workspace]
path = "/workspace"
required = true

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
    pub container_dirs: Arc<Mutex<HashSet<(PathBuf, SandboxId, ContainerId)>>>,
    /// See [`FakeLayer::files_dir`].
    pub files_dir: Arc<Mutex<Option<PathBuf>>>,
    pub runtime: Arc<FakeRuntime>,
    pub images: Arc<FakeImages>,
    pub network: Arc<FakeNetwork>,
    pub output: Arc<FakeOutput>,
    pub volumes: Arc<FakeVolumes>,
    pub fuse: Arc<FakeFuse>,
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
            container_dirs: Arc::default(),
            files_dir: Arc::default(),
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
            volumes: Arc::new(FakeVolumes {
                faults: faults.clone(),
                ..Default::default()
            }),
            fuse: Arc::new(FakeFuse {
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
                container_dirs: self.container_dirs.clone(),
                files_dir: self.files_dir.clone(),
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
                volumes: self.volumes.clone(),
                fuse: self.fuse.clone(),
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
        self.host.fuse.lose_sessions();
        self.tenantd = self.host.service(TEST_CONFIG);
        self.tenantd.check_health().await;
    }
}
