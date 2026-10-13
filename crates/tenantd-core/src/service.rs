//! The orchestration. Every multi-step operation records its intent in the
//! state store before touching the host, and every host step is idempotent,
//! so a crash at any point leaves something reconcile can finish or undo.
//!
//! Locking: one async mutex per tenant and one per sandbox, always taken in
//! that order. Tenant locks cover admission and tenant lifecycle; sandbox
//! locks cover host work on one sandbox.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::{OwnedMutexGuard, broadcast};
use tracing::{info, warn};

use crate::backend::{
    ImageStore, NetworkBackend, RuntimeBackend, RuntimeEvent, RuntimeHandle, RuntimeState,
    StorageBackend, Usage, WritableLayer,
};
use crate::config::Config;
use crate::events::{Event, EventKind};
use crate::model::{
    LayerKind, Overrides, SandboxRecord, SandboxState, TenantLimits, TenantRecord, TenantState,
};
use crate::policy;
use crate::state::StateStore;
use crate::{Error, ProjectId, Result, SandboxId, SandboxKey, TenantId, now};

pub struct Backends {
    pub storage: Arc<dyn StorageBackend>,
    pub layers: Vec<Arc<dyn WritableLayer>>,
    pub runtime: Arc<dyn RuntimeBackend>,
    pub images: Arc<dyn ImageStore>,
    pub network: Arc<dyn NetworkBackend>,
    pub state: Arc<dyn StateStore>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentHealth {
    pub name: &'static str,
    pub ok: bool,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct TenantInfo {
    pub record: TenantRecord,
    pub usage: Option<Usage>,
    pub sandbox_count: usize,
}

pub struct Tenantd {
    config: RwLock<Arc<Config>>,
    pub(crate) storage: Arc<dyn StorageBackend>,
    pub(crate) layers: HashMap<LayerKind, Arc<dyn WritableLayer>>,
    pub(crate) runtime: Arc<dyn RuntimeBackend>,
    pub(crate) images: Arc<dyn ImageStore>,
    pub(crate) network: Arc<dyn NetworkBackend>,
    pub(crate) state: Arc<dyn StateStore>,
    pub(crate) tenant_locks: KeyedLocks<TenantId>,
    pub(crate) sandbox_locks: KeyedLocks<SandboxKey>,
    /// Image resolution holds it shared until the sandbox row exists; GC
    /// holds it exclusively, so GC never removes an image mid-create.
    pub(crate) image_gate: tokio::sync::RwLock<()>,
    events: broadcast::Sender<Event>,
    health: Mutex<Vec<ComponentHealth>>,
    /// Tenants whose directory lost its project ID and couldn't be repaired.
    pub(crate) blocked: Mutex<HashMap<TenantId, String>>,
    /// Project IDs found on disk without a row; never handed out.
    pub(crate) reserved_projects: Mutex<HashSet<u32>>,
}

impl Tenantd {
    pub fn new(config: Config, b: Backends) -> Result<Arc<Self>> {
        let layers: HashMap<_, _> = b.layers.into_iter().map(|l| (l.kind(), l)).collect();
        check_profiles(&config, &layers, b.runtime.as_ref())?;
        let (events, _) = broadcast::channel(1024);
        Ok(Arc::new(Self {
            config: RwLock::new(Arc::new(config)),
            storage: b.storage,
            layers,
            runtime: b.runtime,
            images: b.images,
            network: b.network,
            state: b.state,
            tenant_locks: KeyedLocks::default(),
            sandbox_locks: KeyedLocks::default(),
            image_gate: tokio::sync::RwLock::new(()),
            events,
            health: Mutex::new(Vec::new()),
            blocked: Mutex::new(HashMap::new()),
            reserved_projects: Mutex::new(HashSet::new()),
        }))
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.read().unwrap().clone()
    }

    /// Swap in a new policy. A config that fails validation is rejected and
    /// the old one stays active. Backend settings (paths, sockets) only take
    /// effect on restart; profiles, limits and reconcile settings apply now.
    pub fn reload_config(&self, new: Config) -> Result<()> {
        new.validate()?;
        check_profiles(&new, &self.layers, self.runtime.as_ref())?;
        *self.config.write().unwrap() = Arc::new(new);
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub(crate) fn emit(&self, kind: EventKind) {
        let _ = self.events.send(Event::now(kind));
    }

    pub(crate) fn layer(&self, kind: LayerKind) -> Result<&Arc<dyn WritableLayer>> {
        self.layers.get(&kind).ok_or_else(|| {
            Error::FailedPrecondition(format!("{} layers are not available", kind.as_str()))
        })
    }

    fn stop_grace(&self) -> Duration {
        Duration::from_secs(self.config().runtime.stop_grace_secs)
    }

    // ---- health ---------------------------------------------------------

    /// Run every backend's verify and remember the result. Creates are
    /// refused while storage or runtime enforcement is failing.
    pub async fn check_health(&self) -> Vec<ComponentHealth> {
        let res = |name, r: Result<()>| match r {
            Ok(()) => ComponentHealth {
                name,
                ok: true,
                message: String::new(),
            },
            Err(e) => ComponentHealth {
                name,
                ok: false,
                message: e.to_string(),
            },
        };
        let h = vec![
            res("storage", self.storage.verify().await),
            res("runtime", self.runtime.verify().await),
            res("network", self.network.verify().await),
        ];
        for c in h.iter().filter(|c| !c.ok) {
            warn!(component = c.name, message = %c.message, "health check failed");
        }
        *self.health.lock().unwrap() = h.clone();
        h
    }

    pub fn last_health(&self) -> Vec<ComponentHealth> {
        self.health.lock().unwrap().clone()
    }

    fn require_enforcement(&self) -> Result<()> {
        let h = self.health.lock().unwrap();
        if h.is_empty() {
            return Err(Error::Unavailable("health not checked yet".into()));
        }
        match h.iter().find(|c| !c.ok && c.name != "network") {
            Some(c) => Err(Error::Unavailable(format!(
                "{} enforcement is failing: {}",
                c.name, c.message
            ))),
            None => Ok(()),
        }
    }

    fn require_unblocked(&self, t: &TenantId) -> Result<()> {
        match self.blocked.lock().unwrap().get(t) {
            Some(why) => Err(Error::FailedPrecondition(format!(
                "tenant {t} is blocked: {why}"
            ))),
            None => Ok(()),
        }
    }

    // ---- tenants --------------------------------------------------------

    pub async fn create_tenant(&self, id: TenantId, limits: TenantLimits) -> Result<TenantRecord> {
        validate_limits(&limits)?;
        self.require_enforcement()?;
        let _t = self.tenant_locks.lock(id.clone()).await;
        let rec = match self.state.get_tenant(&id).await? {
            Some(r) if r.limits != limits => {
                return Err(Error::AlreadyExists(format!(
                    "tenant {id} exists with different limits"
                )));
            }
            Some(r) => match r.state {
                TenantState::Ready => return Ok(r),
                TenantState::Deleting => {
                    return Err(Error::FailedPrecondition(format!(
                        "tenant {id} is being deleted"
                    )));
                }
                TenantState::Provisioning => r,
            },
            None => {
                let [lo, hi] = self.config().storage.project_id_range;
                let exclude = self.reserved_projects.lock().unwrap().clone();
                self.state
                    .insert_tenant(&id, &limits, (lo, hi), &exclude)
                    .await?
            }
        };
        self.provision_tenant(rec).await
    }

    /// Steps 2-4 of tenant creation; rolls back on failure. Caller holds the
    /// tenant lock.
    pub(crate) async fn provision_tenant(&self, mut rec: TenantRecord) -> Result<TenantRecord> {
        match self
            .storage
            .create_tenant(&rec.id, rec.project, rec.limits.storage)
            .await
        {
            Ok(_) => {
                rec.state = TenantState::Ready;
                rec.updated_at = now();
                self.state.update_tenant(&rec).await?;
                info!(tenant = %rec.id, project = %rec.project, "tenant ready");
                Ok(rec)
            }
            Err(e) => {
                warn!(tenant = %rec.id, error = %e, "tenant provisioning failed, rolling back");
                self.storage
                    .delete_tenant(&rec.id, Some(rec.project))
                    .await?;
                self.state.delete_tenant(&rec.id).await?;
                Err(e)
            }
        }
    }

    pub async fn update_tenant(&self, id: &TenantId, limits: TenantLimits) -> Result<TenantRecord> {
        validate_limits(&limits)?;
        let _t = self.tenant_locks.lock(id.clone()).await;
        let mut rec = self.ready_tenant(id).await?;
        // Row first: if we crash before the quota call, reconcile sees the
        // limit differs and re-applies it from the row.
        rec.limits = limits;
        rec.updated_at = now();
        self.state.update_tenant(&rec).await?;
        self.storage
            .set_limit(rec.project, rec.limits.storage)
            .await?;
        Ok(rec)
    }

    pub async fn get_tenant(&self, id: &TenantId) -> Result<TenantInfo> {
        let record = self
            .state
            .get_tenant(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("tenant {id}")))?;
        let usage = match record.state {
            TenantState::Ready => Some(self.storage.usage(record.project).await?),
            _ => None,
        };
        let sandbox_count = self.state.list_sandboxes(Some(id)).await?.len();
        Ok(TenantInfo {
            record,
            usage,
            sandbox_count,
        })
    }

    pub async fn list_tenants(&self) -> Result<Vec<TenantRecord>> {
        self.state.list_tenants().await
    }

    /// Fails while sandboxes exist unless `force`. Deleting a missing tenant
    /// succeeds.
    pub async fn delete_tenant(&self, id: &TenantId, force: bool) -> Result<()> {
        let _t = self.tenant_locks.lock(id.clone()).await;
        let Some(mut rec) = self.state.get_tenant(id).await? else {
            return Ok(());
        };
        let sandboxes = self.state.list_sandboxes(Some(id)).await?;
        if !sandboxes.is_empty() && !force {
            return Err(Error::FailedPrecondition(format!(
                "tenant {id} has {} sandboxes; destroy them or pass force",
                sandboxes.len()
            )));
        }
        rec.state = TenantState::Deleting;
        rec.updated_at = now();
        self.state.update_tenant(&rec).await?;
        self.finish_delete_tenant(&rec).await
    }

    /// Caller holds the tenant lock and the row is `deleting`.
    pub(crate) async fn finish_delete_tenant(&self, rec: &TenantRecord) -> Result<()> {
        for s in self.state.list_sandboxes(Some(&rec.id)).await? {
            let _s = self.sandbox_locks.lock(s.key()).await;
            if let Some(s) = self.state.get_sandbox(&s.tenant, &s.id).await? {
                self.destroy_locked(s).await?;
            }
        }
        let dir = self.storage.tenant_dir(&rec.id);
        if let Some(layer) = self.layers.values().next() {
            for orphan in layer.list_owned(&dir).await.unwrap_or_default() {
                layer.teardown(&orphan, &dir).await?;
            }
        }
        self.storage
            .delete_tenant(&rec.id, Some(rec.project))
            .await?;
        self.state.delete_tenant(&rec.id).await?;
        self.blocked.lock().unwrap().remove(&rec.id);
        info!(tenant = %rec.id, "tenant deleted");
        Ok(())
    }

    async fn ready_tenant(&self, id: &TenantId) -> Result<TenantRecord> {
        let rec = self
            .state
            .get_tenant(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("tenant {id}")))?;
        if rec.state != TenantState::Ready {
            return Err(Error::FailedPrecondition(format!(
                "tenant {id} is {}",
                rec.state.as_str()
            )));
        }
        Ok(rec)
    }

    // ---- sandboxes ------------------------------------------------------

    pub async fn create_sandbox(
        &self,
        tenant: TenantId,
        id: SandboxId,
        profile: String,
        image: String,
        overrides: Overrides,
    ) -> Result<SandboxRecord> {
        self.require_enforcement()?;
        self.require_unblocked(&tenant)?;
        let key = SandboxKey::new(tenant.clone(), id.clone());
        if let Some(r) = self.state.get_sandbox(&tenant, &id).await? {
            return same_request(r, &profile, &image, &overrides);
        }
        // Make sure the tenant exists before pulling anything for it.
        self.ready_tenant(&tenant).await?;

        let cfg = self.config();
        let layer = self.layer(cfg.profile(&profile)?.rootfs)?;
        let plan = policy::plan(
            &cfg,
            key.clone(),
            &profile,
            &image,
            &overrides,
            &layer.traits(),
        )?;

        let gate = self.image_gate.read().await;
        let resolved = self.images.resolve(&plan.image_ref).await?;
        let spec = plan.with_image(resolved);

        let t = self.tenant_locks.lock(tenant.clone()).await;
        let trec = self.ready_tenant(&tenant).await?;
        if let Some(r) = self.state.get_sandbox(&tenant, &id).await? {
            return same_request(r, &profile, &image, &overrides);
        }
        let others = self.state.list_sandboxes(Some(&tenant)).await?;
        policy::admit(&trec, &others, spec.memory, spec.cpus, spec.size)?;
        let ts = now();
        let mut rec = SandboxRecord {
            tenant,
            id,
            profile,
            image,
            overrides,
            spec,
            state: SandboxState::Creating,
            exit_code: None,
            created_at: ts,
            updated_at: ts,
        };
        self.state.insert_sandbox(&rec).await?;
        let _s = self.sandbox_locks.lock(key.clone()).await;
        drop(t);
        drop(gate);

        match self.bring_up(&rec).await {
            Ok(()) => {
                self.set_state(&mut rec, SandboxState::Running).await?;
                info!(sandbox = %key, "sandbox running");
                Ok(rec)
            }
            Err(e) => {
                warn!(sandbox = %key, error = %e, "sandbox create failed, rolling back");
                self.tear_down(&rec, true).await?;
                self.state.delete_sandbox(&rec.tenant, &rec.id).await?;
                Err(e)
            }
        }
    }

    pub async fn get_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<SandboxRecord> {
        self.state
            .get_sandbox(t, s)
            .await?
            .ok_or_else(|| Error::NotFound(format!("sandbox {t}.{s}")))
    }

    pub async fn list_sandboxes(&self, t: &TenantId) -> Result<Vec<SandboxRecord>> {
        self.state.list_sandboxes(Some(t)).await
    }

    pub async fn list_all_sandboxes(&self) -> Result<Vec<SandboxRecord>> {
        self.state.list_sandboxes(None).await
    }

    pub fn layer_survives_stop(&self, kind: LayerKind) -> bool {
        self.layers
            .get(&kind)
            .is_some_and(|l| l.traits().survives_stop)
    }

    pub async fn stop_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<SandboxRecord> {
        let _s = self
            .sandbox_locks
            .lock(SandboxKey::new(t.clone(), s.clone()))
            .await;
        let mut rec = self.get_sandbox(t, s).await?;
        match rec.state {
            SandboxState::Stopped | SandboxState::Exited => return Ok(rec),
            SandboxState::Running | SandboxState::Stopping | SandboxState::Starting => {}
            other => {
                return Err(Error::FailedPrecondition(format!(
                    "sandbox is {}",
                    other.as_str()
                )));
            }
        }
        self.set_state(&mut rec, SandboxState::Stopping).await?;
        self.finish_stop(&mut rec).await?;
        Ok(rec)
    }

    pub(crate) async fn finish_stop(&self, rec: &mut SandboxRecord) -> Result<()> {
        self.tear_down(rec, false).await?;
        self.set_state(rec, SandboxState::Stopped).await
    }

    pub async fn start_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<SandboxRecord> {
        self.require_enforcement()?;
        self.require_unblocked(t)?;
        let tl = self.tenant_locks.lock(t.clone()).await;
        let _s = self
            .sandbox_locks
            .lock(SandboxKey::new(t.clone(), s.clone()))
            .await;
        let mut rec = self.get_sandbox(t, s).await?;
        match rec.state {
            SandboxState::Running => return Ok(rec),
            SandboxState::Stopped | SandboxState::Exited => {}
            other => {
                return Err(Error::FailedPrecondition(format!(
                    "sandbox is {}",
                    other.as_str()
                )));
            }
        }
        let trec = self.ready_tenant(t).await?;
        let others: Vec<_> = self
            .state
            .list_sandboxes(Some(t))
            .await?
            .into_iter()
            .filter(|o| o.id != rec.id)
            .collect();
        policy::admit(&trec, &others, rec.spec.memory, rec.spec.cpus, None)?;
        rec.exit_code = None;
        self.set_state(&mut rec, SandboxState::Starting).await?;
        drop(tl);
        self.finish_start(&mut rec).await?;
        Ok(rec)
    }

    pub(crate) async fn finish_start(&self, rec: &mut SandboxRecord) -> Result<()> {
        match self.bring_up(rec).await {
            Ok(()) => self.set_state(rec, SandboxState::Running).await,
            Err(e) => {
                warn!(sandbox = %rec.key(), error = %e, "sandbox start failed");
                self.tear_down(rec, false).await?;
                self.set_state(rec, SandboxState::Stopped).await?;
                Err(e)
            }
        }
    }

    /// Destroying a missing sandbox succeeds.
    pub async fn destroy_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<()> {
        let _s = self
            .sandbox_locks
            .lock(SandboxKey::new(t.clone(), s.clone()))
            .await;
        match self.state.get_sandbox(t, s).await? {
            Some(rec) => self.destroy_locked(rec).await,
            None => Ok(()),
        }
    }

    pub(crate) async fn destroy_locked(&self, mut rec: SandboxRecord) -> Result<()> {
        if rec.state != SandboxState::Destroying {
            self.set_state(&mut rec, SandboxState::Destroying).await?;
        }
        self.tear_down(&rec, true).await?;
        self.state.delete_sandbox(&rec.tenant, &rec.id).await?;
        info!(sandbox = %rec.key(), "sandbox destroyed");
        Ok(())
    }

    pub(crate) async fn set_state(
        &self,
        rec: &mut SandboxRecord,
        state: SandboxState,
    ) -> Result<()> {
        rec.state = state;
        rec.updated_at = now();
        self.state.update_sandbox(rec).await
    }

    /// Prepare the layer, the network and the container, and start it.
    /// Every step is idempotent, so this both creates and resumes.
    pub(crate) async fn bring_up(&self, rec: &SandboxRecord) -> Result<()> {
        let key = rec.key();
        let dir = self.storage.tenant_dir(&rec.tenant);
        let root = self
            .layer(rec.spec.rootfs)?
            .prepare(&rec.spec, &dir)
            .await?;
        let net = self.network.setup(&key, rec.spec.network).await?;
        let h = RuntimeHandle::for_key(&key);
        match self.runtime.inspect(&h).await? {
            RuntimeState::Running => {}
            RuntimeState::Created => self.runtime.start(&h).await?,
            state => {
                if state == RuntimeState::Stopped {
                    self.runtime.destroy(&h).await?;
                }
                self.runtime.create(&rec.spec, &root, &net).await?;
                self.runtime.start(&h).await?;
            }
        }
        self.runtime.watch(&h).await
    }

    /// Stop and remove the container and the network; remove the layer too
    /// when `remove_layer` or when the layer doesn't survive a stop. Tries
    /// every step and returns the first error.
    pub(crate) async fn tear_down(&self, rec: &SandboxRecord, remove_layer: bool) -> Result<()> {
        let key = rec.key();
        let h = RuntimeHandle::for_key(&key);
        let mut first: Option<Error> = None;
        let mut keep = |r: Result<()>| {
            if let Err(e) = r {
                warn!(sandbox = %key, error = %e, "teardown step failed");
                first.get_or_insert(e);
            }
        };
        let runtime = async {
            match self.runtime.inspect(&h).await? {
                RuntimeState::Missing => Ok(()),
                RuntimeState::Stopped => self.runtime.destroy(&h).await,
                _ => {
                    self.runtime.stop(&h, self.stop_grace()).await?;
                    self.runtime.destroy(&h).await
                }
            }
        };
        keep(runtime.await);
        keep(self.network.teardown(&key).await);
        let layer = self.layers.get(&rec.spec.rootfs);
        if remove_layer || !layer.is_some_and(|l| l.traits().survives_stop) {
            let layer = layer.or_else(|| self.layers.values().next());
            if let Some(l) = layer {
                keep(
                    l.teardown(&rec.id, &self.storage.tenant_dir(&rec.tenant))
                        .await,
                );
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    // ---- runtime events -------------------------------------------------

    /// Feed runtime events into sandbox state. Runs until the runtime's
    /// event stream ends.
    pub fn spawn_event_pump(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut events = this.runtime.events();
            while let Some(ev) = events.next().await {
                let this = this.clone();
                tokio::spawn(async move { this.on_runtime_event(ev).await });
            }
        })
    }

    pub async fn on_runtime_event(&self, ev: RuntimeEvent) {
        let RuntimeEvent::Exited {
            handle,
            exit_code,
            oom,
        } = ev;
        let Some(key) = handle.key() else { return };
        if oom {
            self.emit(EventKind::SandboxOom { key: key.clone() });
        }
        let _s = self.sandbox_locks.lock(key.clone()).await;
        let Ok(Some(mut rec)) = self.state.get_sandbox(&key.tenant, &key.sandbox).await else {
            return;
        };
        // Exits during stop/destroy are expected; only a running sandbox
        // exiting on its own is news.
        if rec.state != SandboxState::Running {
            return;
        }
        if let Err(e) = self.mark_exited(&mut rec, exit_code).await {
            warn!(sandbox = %key, error = %e, "recording exit failed; reconcile will retry");
        }
    }

    pub(crate) async fn mark_exited(
        &self,
        rec: &mut SandboxRecord,
        exit_code: Option<i32>,
    ) -> Result<()> {
        self.tear_down(rec, false).await?;
        rec.exit_code = exit_code;
        self.set_state(rec, SandboxState::Exited).await?;
        info!(sandbox = %rec.key(), ?exit_code, "sandbox exited");
        self.emit(EventKind::SandboxExited {
            key: rec.key(),
            exit_code,
        });
        Ok(())
    }

    pub(crate) fn project_reserved(&self, p: ProjectId) {
        self.reserved_projects.lock().unwrap().insert(p.0);
    }
}

fn same_request(
    r: SandboxRecord,
    profile: &str,
    image: &str,
    ov: &Overrides,
) -> Result<SandboxRecord> {
    if r.profile == profile && r.image == image && &r.overrides == ov {
        Ok(r)
    } else {
        Err(Error::AlreadyExists(format!(
            "sandbox {} exists with a different spec",
            r.key()
        )))
    }
}

fn validate_limits(l: &TenantLimits) -> Result<()> {
    if l.storage == 0 {
        return Err(Error::invalid("storage limit must be positive"));
    }
    if l.cpus.is_some_and(|c| !(c > 0.0 && c.is_finite())) {
        return Err(Error::invalid("cpu ceiling must be positive"));
    }
    if l.memory == Some(0) {
        return Err(Error::invalid("memory ceiling must be positive"));
    }
    Ok(())
}

/// Checks a config against what this build's backends can do: every profile's
/// layer must exist, support the runtime, and have a size cap if it needs one.
fn check_profiles(
    cfg: &Config,
    layers: &HashMap<LayerKind, Arc<dyn WritableLayer>>,
    runtime: &dyn RuntimeBackend,
) -> Result<()> {
    if cfg.runtime.backend != runtime.kind() {
        return Err(Error::invalid(format!(
            "config: runtime backend {:?} is not available",
            cfg.runtime.backend
        )));
    }
    for (name, p) in &cfg.profiles {
        let l = layers.get(&p.rootfs).ok_or_else(|| {
            Error::invalid(format!(
                "config: profiles.{name}.rootfs {} is not available",
                p.rootfs.as_str()
            ))
        })?;
        let t = l.traits();
        if !t.runtimes.contains(&runtime.kind()) {
            return Err(Error::invalid(format!(
                "config: profiles.{name}.rootfs {} does not work with {:?}",
                p.rootfs.as_str(),
                runtime.kind()
            )));
        }
        if t.needs_size_cap && p.size.is_none() {
            return Err(Error::invalid(format!(
                "config: profiles.{name}.size is required for {} layers",
                p.rootfs.as_str()
            )));
        }
    }
    Ok(())
}

/// One async mutex per key. Idle entries are pruned as the map grows.
pub(crate) struct KeyedLocks<K>(Mutex<HashMap<K, Arc<tokio::sync::Mutex<()>>>>);

impl<K> Default for KeyedLocks<K> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<K: Eq + Hash + Clone> KeyedLocks<K> {
    pub(crate) async fn lock(&self, k: K) -> OwnedMutexGuard<()> {
        let m = {
            let mut map = self.0.lock().unwrap();
            if map.len() > 1024 {
                map.retain(|_, v| Arc::strong_count(v) > 1);
            }
            map.entry(k).or_default().clone()
        };
        m.lock_owned().await
    }
}
