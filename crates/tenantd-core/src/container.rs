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

use tracing::{info, warn};

use crate::Tenantd;
use crate::backend::{RuntimeHandle, RuntimeState};
use crate::events::EventKind;
use crate::model::{ContainerRecord, ContainerState, ProcessState, SandboxRecord, SandboxState};
use crate::{ContainerKey, Error, Result, SandboxKey, now, policy};

fn same_container(r: ContainerRecord, args: &[String]) -> Result<ContainerRecord> {
    if r.args == args {
        Ok(r)
    } else {
        Err(Error::AlreadyExists(format!(
            "container {} exists with a different command",
            r.key()
        )))
    }
}

impl Tenantd {
    /// Idempotent on the key: the same `args` return the existing
    /// container, different ones are `AlreadyExists`. The sandbox must be
    /// running. `args` is its init; empty runs the image's entrypoint and
    /// cmd, anything else needs the profile's exec rights.
    pub async fn create_container(
        &self,
        key: ContainerKey,
        args: Vec<String>,
    ) -> Result<ContainerRecord> {
        self.require_enforcement()?;
        self.require_unblocked(&key.tenant)?;
        if let Some(r) = self.existing_container(&key).await? {
            return same_container(r, &args);
        }

        let sk = key.sandbox_key();
        let sandbox_lock = self.sandbox_locks.lock(sk.clone()).await;
        let sandbox = self.running_sandbox(&sk).await?;
        if let Some(r) = self.state.get_container(&key).await? {
            return same_container(r, &args);
        }
        policy::check_container_args(&self.config(), &sandbox, &args)?;
        let ts = now();
        let mut rec = ContainerRecord {
            tenant: key.tenant.clone(),
            sandbox: key.sandbox.clone(),
            id: key.id.clone(),
            args,
            state: ContainerState::Creating,
            exit_code: None,
            created_at: ts,
            updated_at: ts,
        };
        self.state.insert_container(&rec).await?;
        let _c = self.container_locks.lock(key.clone()).await;
        drop(sandbox_lock);

        match self.bring_up_container(&sandbox, &rec).await {
            Ok(()) => {
                self.set_container_state(&mut rec, ContainerState::Running)
                    .await?;
                info!(container = %key, "container running");
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

    /// Prepare the container's root and create and start it in the
    /// sandbox. Every step is idempotent, so this both creates and resumes.
    pub(crate) async fn bring_up_container(
        &self,
        sandbox: &SandboxRecord,
        rec: &ContainerRecord,
    ) -> Result<()> {
        let key = rec.key();
        let dir = self.storage.tenant_dir(&rec.tenant);
        let root = self
            .layer(sandbox.spec.rootfs)?
            .prepare_container(&sandbox.spec, &rec.id, &dir)
            .await?;
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
                    .create_container(&sandbox.spec, &key, &rec.args, &root, &net)
                    .await?;
                self.runtime.start(&h).await?;
            }
        }
        self.runtime.watch(&h).await
    }

    /// End the container's processes, stop and remove it from the sandbox,
    /// and remove its root when `remove_root`. Tries every step and returns
    /// the first error.
    pub(crate) async fn tear_down_container(
        &self,
        sandbox: &SandboxRecord,
        rec: &ContainerRecord,
        remove_root: bool,
    ) -> Result<()> {
        let key = rec.key();
        let h = RuntimeHandle::for_container(&key);
        let mut first: Option<Error> = None;
        let mut keep = |r: Result<()>| {
            if let Err(e) = r {
                warn!(container = %key, error = %e, "container teardown step failed");
                first.get_or_insert(e);
            }
        };
        keep(self.end_container_processes(&key).await);
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
                    ContainerState::Running => {
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
