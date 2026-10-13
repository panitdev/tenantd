//! Compare three views — the database, the tenant directories on disk, and
//! the runtime's containers with their mounts and namespaces — and finish,
//! undo or clean up whatever doesn't match.

use std::collections::{HashMap, HashSet};

use tracing::{info, warn};

use crate::Tenantd;
use crate::backend::RuntimeHandle;
use crate::events::EventKind;
use crate::model::{SandboxState, TenantState};
use crate::{ProjectId, SandboxKey, TenantId};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// (action, target, detail)
    pub actions: Vec<(String, String, String)>,
    pub errors: Vec<String>,
}

impl ReconcileReport {
    fn act(&mut self, t: &Tenantd, action: &str, target: impl ToString, detail: impl ToString) {
        let (target, detail) = (target.to_string(), detail.to_string());
        info!(action, target, detail, "reconcile");
        t.emit(EventKind::Reconcile {
            action: action.into(),
            target: target.clone(),
            detail: detail.clone(),
        });
        self.actions.push((action.into(), target, detail));
    }

    fn err(&mut self, target: impl ToString, e: impl ToString) {
        let msg = format!("{}: {}", target.to_string(), e.to_string());
        warn!(error = msg, "reconcile");
        self.errors.push(msg);
    }
}

impl Tenantd {
    pub async fn reconcile(&self) -> ReconcileReport {
        let mut rep = ReconcileReport::default();
        self.check_health().await;
        self.reconcile_tenants(&mut rep).await;
        self.reconcile_sandboxes(&mut rep).await;
        self.reconcile_images(&mut rep).await;
        rep
    }

    async fn reconcile_tenants(&self, rep: &mut ReconcileReport) {
        let rows = match self.state.list_tenants().await {
            Ok(r) => r,
            Err(e) => return rep.err("state", e),
        };
        let on_disk: Option<HashMap<TenantId, Option<ProjectId>>> =
            match self.storage.list_tenants().await {
                Ok(v) => Some(v.into_iter().collect()),
                Err(e) => {
                    rep.err("storage", e);
                    None
                }
            };

        for row in &rows {
            let _t = self.tenant_locks.lock(row.id.clone()).await;
            let rec = match self.state.get_tenant(&row.id).await {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) => {
                    rep.err(&row.id, e);
                    continue;
                }
            };
            let target = format!("tenant/{}", rec.id);
            match rec.state {
                TenantState::Provisioning => match self.provision_tenant(rec).await {
                    Ok(_) => rep.act(self, "finish_create", &target, "tenant ready"),
                    Err(e) => rep.act(self, "rollback_create", &target, e),
                },
                TenantState::Deleting => match self.finish_delete_tenant(&rec).await {
                    Ok(()) => rep.act(self, "finish_delete", &target, "tenant deleted"),
                    Err(e) => rep.err(&target, e),
                },
                TenantState::Ready => {
                    if let Some(disk) = &on_disk {
                        let found = disk.get(&rec.id).copied().flatten();
                        if found != Some(rec.project) {
                            let why = match found {
                                None if !disk.contains_key(&rec.id) => {
                                    "directory missing".to_string()
                                }
                                None => "project ID missing".to_string(),
                                Some(p) => format!("project ID {p}, expected {}", rec.project),
                            };
                            match self
                                .storage
                                .create_tenant(&rec.id, rec.project, rec.limits.storage)
                                .await
                            {
                                Ok(_) => {
                                    self.blocked.lock().unwrap().remove(&rec.id);
                                    rep.act(self, "reapply_project", &target, why);
                                }
                                Err(e) => {
                                    self.blocked
                                        .lock()
                                        .unwrap()
                                        .insert(rec.id.clone(), format!("{why}: {e}"));
                                    rep.err(
                                        &target,
                                        format!("{why}; repair failed, sandboxes refused: {e}"),
                                    );
                                    continue;
                                }
                            }
                        } else {
                            self.blocked.lock().unwrap().remove(&rec.id);
                        }
                    }
                    match self.storage.usage(rec.project).await {
                        Ok(u) => {
                            if u.limit != rec.limits.storage {
                                match self
                                    .storage
                                    .set_limit(rec.project, rec.limits.storage)
                                    .await
                                {
                                    Ok(()) => rep.act(
                                        self,
                                        "reapply_limit",
                                        &target,
                                        format!("{} -> {}", u.limit, rec.limits.storage),
                                    ),
                                    Err(e) => rep.err(&target, e),
                                }
                            }
                            if u.used >= rec.limits.storage {
                                self.emit(EventKind::QuotaExceeded {
                                    tenant: rec.id.clone(),
                                    used: u.used,
                                    limit: rec.limits.storage,
                                });
                            }
                        }
                        Err(e) => rep.err(&target, e),
                    }
                }
            }
        }

        let Some(disk) = on_disk else { return };
        let known: HashSet<&TenantId> = rows.iter().map(|r| &r.id).collect();
        let delete = self.config().reconcile.delete_orphans;
        for (id, project) in disk {
            if known.contains(&id) {
                continue;
            }
            let target = format!("tenant/{id}");
            if let Some(p) = project {
                self.project_reserved(p);
            }
            if !delete {
                rep.act(
                    self,
                    "orphan_tenant_dir",
                    &target,
                    "no row; kept (reconcile.delete_orphans = false)",
                );
                continue;
            }
            let _t = self.tenant_locks.lock(id.clone()).await;
            let dir = self.storage.tenant_dir(&id);
            if let Some(layer) = self.layers.values().next() {
                for s in layer.list_owned(&dir).await.unwrap_or_default() {
                    if let Err(e) = layer.teardown(&s, &dir).await {
                        rep.err(&target, e);
                    }
                }
            }
            match self.storage.delete_tenant(&id, project).await {
                Ok(()) => {
                    if let Some(p) = project {
                        self.reserved_projects.lock().unwrap().remove(&p.0);
                    }
                    rep.act(self, "delete_orphan_tenant_dir", &target, "removed");
                }
                Err(e) => rep.err(&target, e),
            }
        }
    }

    async fn reconcile_sandboxes(&self, rep: &mut ReconcileReport) {
        let rows = match self.state.list_sandboxes(None).await {
            Ok(r) => r,
            Err(e) => return rep.err("state", e),
        };
        let containers: HashSet<RuntimeHandle> = match self.runtime.list_owned().await {
            Ok(v) => v.into_iter().collect(),
            Err(e) => {
                rep.err("runtime", e);
                return;
            }
        };
        let netns: HashSet<SandboxKey> = match self.network.list_owned().await {
            Ok(v) => v.into_iter().collect(),
            Err(e) => {
                rep.err("network", e);
                HashSet::new()
            }
        };

        for row in &rows {
            let key = row.key();
            let _s = self.sandbox_locks.lock(key.clone()).await;
            let mut rec = match self.state.get_sandbox(&key.tenant, &key.sandbox).await {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) => {
                    rep.err(&key, e);
                    continue;
                }
            };
            let target = format!("sandbox/{key}");
            let h = RuntimeHandle::for_key(&key);
            match rec.state {
                SandboxState::Creating => match self.bring_up(&rec).await {
                    Ok(()) => match self.set_state(&mut rec, SandboxState::Running).await {
                        Ok(()) => rep.act(self, "finish_create", &target, "running"),
                        Err(e) => rep.err(&target, e),
                    },
                    Err(e) => {
                        let undo = async {
                            self.tear_down(&rec, true).await?;
                            self.state.delete_sandbox(&rec.tenant, &rec.id).await
                        };
                        match undo.await {
                            Ok(()) => rep.act(self, "rollback_create", &target, e),
                            Err(e2) => rep.err(&target, format!("rollback after {e} failed: {e2}")),
                        }
                    }
                },
                SandboxState::Starting => match self.finish_start(&mut rec).await {
                    Ok(()) => rep.act(self, "finish_start", &target, "running"),
                    Err(e) => rep.act(self, "rollback_start", &target, e),
                },
                SandboxState::Stopping => match self.finish_stop(&mut rec).await {
                    Ok(()) => rep.act(self, "finish_stop", &target, "stopped"),
                    Err(e) => rep.err(&target, e),
                },
                SandboxState::Destroying => match self.destroy_locked(rec).await {
                    Ok(()) => rep.act(self, "finish_destroy", &target, "destroyed"),
                    Err(e) => rep.err(&target, e),
                },
                SandboxState::Running => match self.runtime.inspect(&h).await {
                    Ok(crate::backend::RuntimeState::Running) => {
                        if let Err(e) = self.runtime.watch(&h).await {
                            rep.err(&target, e);
                        }
                    }
                    Ok(crate::backend::RuntimeState::Created) => match self.bring_up(&rec).await {
                        Ok(()) => rep.act(
                            self,
                            "finish_start",
                            &target,
                            "container was created but not started",
                        ),
                        Err(e) => rep.err(&target, e),
                    },
                    Ok(state) => match self.mark_exited(&mut rec, None).await {
                        Ok(()) => {
                            rep.act(self, "mark_exited", &target, format!("container {state:?}"))
                        }
                        Err(e) => rep.err(&target, e),
                    },
                    Err(e) => rep.err(&target, e),
                },
                SandboxState::Stopped | SandboxState::Exited => {
                    if containers.contains(&h) || netns.contains(&key) {
                        match self.tear_down(&rec, false).await {
                            Ok(()) => rep.act(
                                self,
                                "cleanup_stopped",
                                &target,
                                "removed leftover container/netns",
                            ),
                            Err(e) => rep.err(&target, e),
                        }
                    }
                }
            }
        }

        let known: HashSet<SandboxKey> = rows.iter().map(|r| r.key()).collect();
        for h in containers {
            let owned = h.key().is_some_and(|k| known.contains(&k));
            if owned {
                continue;
            }
            let target = format!("container/{}", h.0);
            let res = async {
                if self.runtime.inspect(&h).await? != crate::backend::RuntimeState::Stopped {
                    self.runtime
                        .stop(&h, std::time::Duration::from_secs(1))
                        .await?;
                }
                self.runtime.destroy(&h).await
            };
            match res.await {
                Ok(()) => rep.act(self, "delete_orphan_container", &target, "no row"),
                Err(e) => rep.err(&target, e),
            }
        }
        for key in netns.into_iter().filter(|k| !known.contains(k)) {
            let target = format!("netns/{key}");
            match self.network.teardown(&key).await {
                Ok(()) => rep.act(self, "delete_orphan_netns", &target, "no row"),
                Err(e) => rep.err(&target, e),
            }
        }

        // Sandbox directories with no row, under tenants we know.
        let delete = self.config().reconcile.delete_orphans;
        let Some(layer) = self.layers.values().next() else {
            return;
        };
        let tenants: HashSet<TenantId> = match self.state.list_tenants().await {
            Ok(t) => t
                .into_iter()
                .filter(|t| t.state == TenantState::Ready)
                .map(|t| t.id)
                .collect(),
            Err(_) => return,
        };
        for t in tenants {
            let dir = self.storage.tenant_dir(&t);
            for s in layer.list_owned(&dir).await.unwrap_or_default() {
                let key = SandboxKey::new(t.clone(), s.clone());
                if known.contains(&key) {
                    continue;
                }
                let _s = self.sandbox_locks.lock(key.clone()).await;
                if matches!(self.state.get_sandbox(&t, &s).await, Ok(Some(_))) {
                    continue; // created since we listed
                }
                let target = format!("sandbox-dir/{key}");
                if !delete {
                    rep.act(
                        self,
                        "orphan_sandbox_dir",
                        &target,
                        "no row; kept (reconcile.delete_orphans = false)",
                    );
                    continue;
                }
                match layer.teardown(&s, &dir).await {
                    Ok(()) => rep.act(
                        self,
                        "delete_orphan_sandbox_dir",
                        &target,
                        "unmounted and removed",
                    ),
                    Err(e) => rep.err(&target, e),
                }
            }
        }
    }

    async fn reconcile_images(&self, rep: &mut ReconcileReport) {
        let _gate = self.image_gate.write().await;
        let in_use: HashSet<String> = match self.state.list_sandboxes(None).await {
            Ok(rows) => rows.into_iter().map(|r| r.spec.image.digest).collect(),
            Err(e) => return rep.err("state", e),
        };
        match self.images.gc(&in_use).await {
            Ok(r) => {
                for d in r.images {
                    rep.act(self, "gc_image", format!("image/{d}"), "unreferenced");
                }
                for d in r.layers {
                    rep.act(self, "gc_layer", format!("layer/{d}"), "unreferenced");
                }
            }
            Err(e) => rep.err("images", e),
        }
    }
}
