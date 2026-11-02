//! Containers inside running sandboxes: the sandbox's image on a writable
//! root of their own, sharing the sandbox's kernel, network and limits, so
//! many of them cost one sandbox.
//!
//! A create follows the intent pattern: the row is inserted as `creating`
//! under the sandbox lock (so a stop can't race it), the host work runs
//! under the container lock, and the row turns `running` once the
//! container is started. A container is never restarted: when its init
//! exits or its sandbox stops it ends `exited`, and its root stays until
//! it is deleted.
//!
//! Volumes are bind-mounted through the profile's slots, resolved and
//! checked at create and kept on the row. A container with a FUSE slot
//! gets a host FUSE mount, bind-mounted like a volume; its row stops at
//! `created` (root and mount ready, no runtime container yet) until the
//! caller's FUSE server holds the connection, because anything touching
//! the mount, runsc included, blocks until a server answers. Then
//! [`Tenantd::start_container`] runs it.

use std::os::fd::OwnedFd;

use tracing::{info, warn};

use crate::Tenantd;
use crate::backend::{BindMount, RootfsSpec, RuntimeHandle, RuntimeState};
use crate::events::EventKind;
use crate::model::{
    ContainerRecord, ContainerSpec, ContainerState, ProcessState, SandboxRecord, SandboxState,
    VolumeState,
};
use crate::{ContainerKey, Error, Result, SandboxKey, VolumeKey, now, policy};

fn same_container(r: ContainerRecord, spec: &ContainerSpec) -> Result<ContainerRecord> {
    if &r.spec() == spec {
        Ok(r)
    } else {
        Err(Error::AlreadyExists(format!(
            "container {} exists with a different command, volumes or FUSE slot",
            r.key()
        )))
    }
}

impl Tenantd {
    /// Idempotent on the key: the same spec returns the existing container,
    /// a different one is `AlreadyExists`. The sandbox must be running.
    /// `args` is its init; empty runs the image's entrypoint and cmd,
    /// anything else needs the profile's exec rights. Bound volumes must be
    /// ready. With `fuse`, the container is left `created`; see
    /// [`Tenantd::attach_fuse`] and [`Tenantd::start_container`].
    pub async fn create_container(
        &self,
        key: ContainerKey,
        spec: impl Into<ContainerSpec>,
    ) -> Result<ContainerRecord> {
        let spec = spec.into();
        self.require_enforcement()?;
        self.require_unblocked(&key.tenant)?;
        if let Some(r) = self.existing_container(&key).await? {
            return same_container(r, &spec);
        }

        let sk = key.sandbox_key();
        let sandbox_lock = self.sandbox_locks.lock(sk.clone()).await;
        let sandbox = self.running_sandbox(&sk).await?;
        if let Some(r) = self.state.get_container(&key).await? {
            return same_container(r, &spec);
        }
        let cfg = self.config();
        policy::check_container_args(&cfg, &sandbox, &spec.args)?;
        let (volumes, fuse) = policy::plan_container_mounts(&cfg, &sandbox, &spec)?;
        // Held until the row exists, so none of them is deleted meanwhile.
        let mut volume_locks = Vec::with_capacity(volumes.len());
        let mut keys: Vec<VolumeKey> = volumes
            .iter()
            .map(|m| VolumeKey::new(key.tenant.clone(), m.volume.clone()))
            .collect();
        keys.sort();
        keys.dedup();
        for vk in keys {
            volume_locks.push(self.volume_locks.lock(vk.clone()).await);
            match self.state.get_volume(&vk.tenant, &vk.volume).await? {
                Some(v) if v.state == VolumeState::Ready => {}
                Some(v) => {
                    return Err(Error::FailedPrecondition(format!(
                        "volume {vk} is {}",
                        v.state.as_str()
                    )));
                }
                None => return Err(Error::NotFound(format!("volume {vk}"))),
            }
        }
        let ts = now();
        let mut rec = ContainerRecord {
            tenant: key.tenant.clone(),
            sandbox: key.sandbox.clone(),
            id: key.id.clone(),
            args: spec.args,
            volumes,
            fuse,
            state: ContainerState::Creating,
            exit_code: None,
            created_at: ts,
            updated_at: ts,
        };
        self.state.insert_container(&rec).await?;
        drop(volume_locks);
        let _c = self.container_locks.lock(key.clone()).await;
        drop(sandbox_lock);

        match self.bring_up_container(&sandbox, &rec).await {
            Ok(state) => {
                self.set_container_state(&mut rec, state).await?;
                info!(container = %key, state = state.as_str(), "container created");
                Ok(rec)
            }
            Err(e) => {
                warn!(container = %key, error = %e, "container create failed, rolling back");
                self.tear_down_container(&sandbox, &rec, true).await?;
                self.state.delete_container(&key).await?;
                Err(e)
            }
        }
    }

    /// A row for `key`; one still `creating` is re-read once its in-flight
    /// create finishes.
    async fn existing_container(&self, key: &ContainerKey) -> Result<Option<ContainerRecord>> {
        let row = self.state.get_container(key).await?;
        if row
            .as_ref()
            .is_some_and(|r| r.state == ContainerState::Creating)
        {
            let _c = self.container_locks.lock(key.clone()).await;
            return self.state.get_container(key).await;
        }
        Ok(row)
    }

    /// Run a `created` container: its FUSE server must have attached.
    /// Starting a running container returns it as is; an exited one is
    /// never restarted.
    pub async fn start_container(&self, key: &ContainerKey) -> Result<ContainerRecord> {
        self.require_enforcement()?;
        self.require_unblocked(&key.tenant)?;
        let sk = key.sandbox_key();
        let sandbox_lock = self.sandbox_locks.lock(sk.clone()).await;
        let _c = self.container_locks.lock(key.clone()).await;
        let mut rec = self.get_container(key).await?;
        match rec.state {
            ContainerState::Running => return Ok(rec),
            ContainerState::Created => {}
            other => {
                return Err(Error::FailedPrecondition(format!(
                    "container {key} is {}",
                    other.as_str()
                )));
            }
        }
        let sandbox = self.running_sandbox(&sk).await?;
        drop(sandbox_lock);
        if rec.fuse.is_some() && !self.fuse_attached.lock().unwrap().contains(key) {
            return Err(Error::FailedPrecondition(format!(
                "container {key} waits for its FUSE server: attach it over the FUSE socket first"
            )));
        }
        let res = async {
            let (root, mounts) = self.prepare_container(&sandbox, &rec).await?;
            self.run_container(&sandbox, &rec, &root, &mounts).await
        };
        if let Err(e) = res.await {
            warn!(container = %key, error = %e, "container start failed; it stays created");
            if let Err(e2) = self.remove_runtime_container(key).await {
                warn!(container = %key, error = %e2, "removing the half-started container failed");
            }
            return Err(e);
        }
        self.set_container_state(&mut rec, ContainerState::Running)
            .await?;
        info!(container = %key, "container running");
        Ok(rec)
    }

    /// The container's FUSE connection, for its server. Each call hands out
    /// a duplicate of the same connection, so a server that restarts can
    /// attach again; a reattached server finds the connection already
    /// initialised (no `FUSE_INIT` comes). tenantd loses its connections
    /// when it restarts: a `created` container gets a fresh one, a running
    /// one has to be recreated.
    pub async fn attach_fuse(&self, key: &ContainerKey) -> Result<OwnedFd> {
        let _c = self.container_locks.lock(key.clone()).await;
        let rec = self.get_container(key).await?;
        if rec.fuse.is_none() {
            return Err(Error::FailedPrecondition(format!(
                "container {key} has no FUSE slot"
            )));
        }
        let fd = match rec.state {
            ContainerState::Created => match self.fuse.connection(key)? {
                Some(fd) => fd,
                None => {
                    self.fuse.mount(key).await?;
                    self.fuse.connection(key)?.ok_or_else(|| {
                        Error::Internal(format!("FUSE mount of {key} holds no connection"))
                    })?
                }
            },
            ContainerState::Running => self.fuse.connection(key)?.ok_or_else(|| {
                Error::FailedPrecondition(format!(
                    "tenantd lost the FUSE connection of {key} when it restarted; \
                     recreate the container"
                ))
            })?,
            other => {
                return Err(Error::FailedPrecondition(format!(
                    "container {key} is {}",
                    other.as_str()
                )));
            }
        };
        self.fuse_attached.lock().unwrap().insert(key.clone());
        info!(container = %key, "FUSE connection handed to its server");
        Ok(fd)
    }

    pub(crate) async fn running_sandbox(&self, sk: &SandboxKey) -> Result<SandboxRecord> {
        let sandbox = self.get_sandbox(&sk.tenant, &sk.sandbox).await?;
        if sandbox.state != SandboxState::Running {
            return Err(Error::FailedPrecondition(format!(
                "sandbox {sk} is {}",
                sandbox.state.as_str()
            )));
        }
        Ok(sandbox)
    }

    pub async fn get_container(&self, key: &ContainerKey) -> Result<ContainerRecord> {
        self.state
            .get_container(key)
            .await?
            .ok_or_else(|| Error::NotFound(format!("container {key}")))
    }

    pub async fn list_containers(&self, sk: &SandboxKey) -> Result<Vec<ContainerRecord>> {
        self.get_sandbox(&sk.tenant, &sk.sandbox).await?;
        self.state.list_containers(Some(sk)).await
    }

    pub async fn list_all_containers(&self) -> Result<Vec<ContainerRecord>> {
        self.state.list_containers(None).await
    }

    /// Ends the container's processes, removes the container and its root.
    /// Its process rows stay until their retention passes. Deleting a
    /// missing container succeeds.
    pub async fn delete_container(&self, key: &ContainerKey) -> Result<()> {
        let sk = key.sandbox_key();
        let _s = self.sandbox_locks.lock(sk.clone()).await;
        let _c = self.container_locks.lock(key.clone()).await;
        let Some(rec) = self.state.get_container(key).await? else {
            return Ok(());
        };
        let sandbox = self.get_sandbox(&sk.tenant, &sk.sandbox).await?;
        self.delete_container_locked(&sandbox, rec).await
    }

    /// Caller holds the sandbox and container locks.
    pub(crate) async fn delete_container_locked(
        &self,
        sandbox: &SandboxRecord,
        mut rec: ContainerRecord,
    ) -> Result<()> {
        if rec.state != ContainerState::Destroying {
            self.set_container_state(&mut rec, ContainerState::Destroying)
                .await?;
        }
        self.tear_down_container(sandbox, &rec, true).await?;
        self.state.delete_container(&rec.key()).await?;
        info!(container = %rec.key(), "container deleted");
        Ok(())
    }

    pub(crate) async fn set_container_state(
        &self,
        rec: &mut ContainerRecord,
        state: ContainerState,
    ) -> Result<()> {
        rec.state = state;
        rec.updated_at = now();
        self.state.update_container(rec).await
    }

    /// Prepare the container and, unless it waits for a FUSE server, run
    /// it. Returns the state it reached. Every step is idempotent, so this
    /// both creates and resumes.
    pub(crate) async fn bring_up_container(
        &self,
        sandbox: &SandboxRecord,
        rec: &ContainerRecord,
    ) -> Result<ContainerState> {
        let (root, mounts) = self.prepare_container(sandbox, rec).await?;
        if rec.fuse.is_some() {
            return Ok(ContainerState::Created);
        }
        self.run_container(sandbox, rec, &root, &mounts).await?;
        Ok(ContainerState::Running)
    }

    /// The container's root, its FUSE mount, and the bind mounts of its
    /// volumes and FUSE slot. Idempotent; a FUSE connection tenantd holds
    /// is kept, a lost one is replaced.
    pub(crate) async fn prepare_container(
        &self,
        sandbox: &SandboxRecord,
        rec: &ContainerRecord,
    ) -> Result<(RootfsSpec, Vec<BindMount>)> {
        let dir = self.storage.tenant_dir(&rec.tenant);
        let root = self
            .layer(sandbox.spec.rootfs)?
            .prepare_container(&sandbox.spec, &rec.id, &dir)
            .await?;
        let mut mounts = Vec::with_capacity(rec.volumes.len() + 1);
        for m in &rec.volumes {
            if !self.volumes.exists(&dir, &m.volume).await? {
                return Err(Error::FailedPrecondition(format!(
                    "volume {}.{} has no directory",
                    rec.tenant, m.volume
                )));
            }
            mounts.push(BindMount {
                source: self.volumes.path(&dir, &m.volume),
                destination: m.path.clone(),
                read_only: m.read_only,
            });
        }
        if let Some(path) = &rec.fuse {
            mounts.push(BindMount {
                source: self.fuse.mount(&rec.key()).await?,
                destination: path.clone(),
                read_only: false,
            });
        }
        Ok((root, mounts))
    }

    /// Create and start the prepared container in its sandbox. Idempotent.
    pub(crate) async fn run_container(
        &self,
        sandbox: &SandboxRecord,
        rec: &ContainerRecord,
        root: &RootfsSpec,
        mounts: &[BindMount],
    ) -> Result<()> {
        let key = rec.key();
        // Already set up for the running sandbox; this only finds it.
        let net = self
            .network
            .setup(&rec.sandbox_key(), sandbox.spec.network)
            .await?;
        let h = RuntimeHandle::for_container(&key);
        match self.runtime.inspect(&h).await? {
            RuntimeState::Running => {}
            RuntimeState::Created => self.runtime.start(&h).await?,
            state => {
                if state == RuntimeState::Stopped {
                    self.runtime.destroy(&h).await?;
                }
                self.runtime
                    .create_container(&sandbox.spec, &key, &rec.args, root, mounts, &net)
                    .await?;
                self.runtime.start(&h).await?;
            }
        }
        self.runtime.watch(&h).await
    }

    /// Stop and remove the runtime container, if there is one.
    pub(crate) async fn remove_runtime_container(&self, key: &ContainerKey) -> Result<()> {
        let h = RuntimeHandle::for_container(key);
        match self.runtime.inspect(&h).await? {
            RuntimeState::Missing => Ok(()),
            RuntimeState::Stopped => self.runtime.destroy(&h).await,
            _ => {
                self.runtime.stop(&h, self.stop_grace()).await?;
                self.runtime.destroy(&h).await
            }
        }
    }

    /// End the container's processes, stop and remove it from the sandbox,
    /// unmount its FUSE connection, and remove its root when
    /// `remove_root`. Tries every step and returns the first error.
    pub(crate) async fn tear_down_container(
        &self,
        sandbox: &SandboxRecord,
        rec: &ContainerRecord,
        remove_root: bool,
    ) -> Result<()> {
        let key = rec.key();
        let mut first: Option<Error> = None;
        let mut keep = |r: Result<()>| {
            if let Err(e) = r {
                warn!(container = %key, error = %e, "container teardown step failed");
                first.get_or_insert(e);
            }
        };
        keep(self.end_container_processes(&key).await);
        keep(self.remove_runtime_container(&key).await);
        if rec.fuse.is_some() {
            self.fuse_attached.lock().unwrap().remove(&key);
            keep(self.fuse.unmount(&key).await);
        }
        if remove_root {
            let layer = self
                .layers
                .get(&sandbox.spec.rootfs)
                .or_else(|| self.layers.values().next());
            if let Some(l) = layer {
                keep(
                    l.teardown_container(
                        &rec.sandbox,
                        &rec.id,
                        &self.storage.tenant_dir(&rec.tenant),
                    )
                    .await,
                );
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Every container of a sandbox that is stopping ends: running ones as
    /// `exited`, half-created ones are removed. Their roots stay unless
    /// `remove_roots`. Caller holds the sandbox lock.
    pub(crate) async fn end_containers(
        &self,
        sandbox: &SandboxRecord,
        remove_roots: bool,
    ) -> Result<()> {
        let mut first: Option<Error> = None;
        for row in self.state.list_containers(Some(&sandbox.key())).await? {
            let _c = self.container_locks.lock(row.key()).await;
            let Some(mut rec) = self.state.get_container(&row.key()).await? else {
                continue;
            };
            let res = async {
                match rec.state {
                    ContainerState::Creating | ContainerState::Destroying => {
                        self.tear_down_container(sandbox, &rec, true).await?;
                        self.state.delete_container(&rec.key()).await
                    }
                    ContainerState::Created | ContainerState::Running => {
                        self.tear_down_container(sandbox, &rec, remove_roots)
                            .await?;
                        self.set_container_state(&mut rec, ContainerState::Exited)
                            .await
                    }
                    ContainerState::Exited => {
                        self.tear_down_container(sandbox, &rec, remove_roots).await
                    }
                }
            };
            if let Err(e) = res.await {
                warn!(container = %row.key(), error = %e, "ending container failed");
                first.get_or_insert(e);
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// The container's init exited on its own.
    pub(crate) async fn on_container_exit(&self, key: &ContainerKey, exit_code: Option<i32>) {
        let sk = key.sandbox_key();
        let _s = self.sandbox_locks.lock(sk.clone()).await;
        let _c = self.container_locks.lock(key.clone()).await;
        let Ok(Some(mut rec)) = self.state.get_container(key).await else {
            return;
        };
        // Exits during create, stop or delete are expected.
        if rec.state != ContainerState::Running {
            return;
        }
        let Ok(sandbox) = self.get_sandbox(&sk.tenant, &sk.sandbox).await else {
            return;
        };
        if let Err(e) = self
            .mark_container_exited(&sandbox, &mut rec, exit_code)
            .await
        {
            warn!(container = %key, error = %e, "recording exit failed; reconcile will retry");
        }
    }

    /// Caller holds the sandbox and container locks.
    pub(crate) async fn mark_container_exited(
        &self,
        sandbox: &SandboxRecord,
        rec: &mut ContainerRecord,
        exit_code: Option<i32>,
    ) -> Result<()> {
        self.tear_down_container(sandbox, rec, false).await?;
        rec.exit_code = exit_code;
        self.set_container_state(rec, ContainerState::Exited)
            .await?;
        info!(container = %rec.key(), ?exit_code, "container exited");
        self.emit(EventKind::ContainerExited {
            key: rec.key(),
            exit_code,
        });
        Ok(())
    }

    /// Like `end_processes`, for one container's processes.
    pub(crate) async fn end_container_processes(&self, key: &ContainerKey) -> Result<()> {
        for row in self.state.list_processes(Some(&key.sandbox_key())).await? {
            if !row.state.is_live() || row.container.as_ref() != Some(&key.id) {
                continue;
            }
            let _p = self.process_locks.lock(row.key()).await;
            let Some(mut rec) = self.state.get_process(&row.key()).await? else {
                continue;
            };
            let state = match rec.state {
                ProcessState::Running => ProcessState::Exited,
                ProcessState::Starting => ProcessState::Lost,
                _ => continue,
            };
            self.finish_process(&mut rec, state, None, None).await?;
        }
        Ok(())
    }
}
