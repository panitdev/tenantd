//! gRPC surface. Thin: validates IDs, calls the service, maps errors to
//! status codes and records latency.

use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::Stream;
use tenantd_client::pb::{
    self, processes_server::Processes, sandboxes_server::Sandboxes, system_server::System,
    tenants_server::Tenants,
};
use tenantd_core::events::{Event, EventKind};
use tenantd_core::model::{
    Overrides, ProcessRecord, ProcessSpec, SandboxRecord, Signal, TenantLimits, TenantRecord,
};
use tenantd_core::process::OutputChunk;
use tenantd_core::service::TenantInfo;
use tenantd_core::{Error, ProcessId, ProcessKey, SandboxId, SandboxKey, TenantId, Tenantd};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};

use crate::metrics::Metrics;

pub const RULE_METADATA: &str = "x-tenantd-rule";

pub fn status(e: Error) -> Status {
    match e {
        Error::InvalidArgument(m) => Status::invalid_argument(m),
        Error::NotFound(m) => Status::not_found(m),
        Error::AlreadyExists(m) => Status::already_exists(m),
        Error::PermissionDenied { rule, message } => {
            let mut s = Status::permission_denied(format!("denied by {rule}: {message}"));
            if let Ok(v) = rule.parse() {
                s.metadata_mut().insert(RULE_METADATA, v);
            }
            s
        }
        Error::FailedPrecondition(m) => Status::failed_precondition(m),
        Error::ResourceExhausted(m) => Status::resource_exhausted(m),
        Error::Unavailable(m) => Status::unavailable(m),
        Error::Internal(m) => Status::internal(m),
    }
}

#[derive(Clone)]
pub struct Api {
    pub tenantd: Arc<Tenantd>,
    pub metrics: Arc<Metrics>,
}

impl Api {
    async fn timed<T, F>(&self, op: &'static str, f: F) -> Result<Response<T>, Status>
    where
        F: Future<Output = tenantd_core::Result<T>>,
    {
        let start = Instant::now();
        let res = f.await.map_err(status);
        let code = match &res {
            Ok(_) => tonic::Code::Ok,
            Err(s) => s.code(),
        };
        self.metrics.observe(op, code, start.elapsed());
        res.map(Response::new)
    }
}

fn tenant_id(s: &str) -> tenantd_core::Result<TenantId> {
    TenantId::new(s)
}

fn sandbox_id(s: &str) -> tenantd_core::Result<SandboxId> {
    SandboxId::new(s)
}

fn process_key(t: &str, s: &str, p: &str) -> tenantd_core::Result<ProcessKey> {
    Ok(ProcessKey::new(
        SandboxKey::new(tenant_id(t)?, sandbox_id(s)?),
        ProcessId::new(p)?,
    ))
}

fn process_ref(r: Option<pb::ProcessRef>) -> tenantd_core::Result<ProcessKey> {
    let r = r.ok_or_else(|| Error::invalid("process is required"))?;
    process_key(&r.tenant, &r.sandbox, &r.id)
}

fn signal(raw: i32) -> tenantd_core::Result<Signal> {
    use pb::Signal as S;
    Ok(match S::try_from(raw).unwrap_or(S::Unspecified) {
        S::Sigterm => Signal::Term,
        S::Sigkill => Signal::Kill,
        S::Sigint => Signal::Int,
        S::Sighup => Signal::Hup,
        S::Sigquit => Signal::Quit,
        S::Sigusr1 => Signal::Usr1,
        S::Sigusr2 => Signal::Usr2,
        S::Unspecified => return Err(Error::invalid("signal is required")),
    })
}

/// A raw signal number as the enum; numbers outside it are UNSPECIFIED.
fn pb_signal(n: i32) -> i32 {
    use pb::Signal as S;
    (match Signal::from_number(n) {
        Some(Signal::Term) => S::Sigterm,
        Some(Signal::Kill) => S::Sigkill,
        Some(Signal::Int) => S::Sigint,
        Some(Signal::Hup) => S::Sighup,
        Some(Signal::Quit) => S::Sigquit,
        Some(Signal::Usr1) => S::Sigusr1,
        Some(Signal::Usr2) => S::Sigusr2,
        None => S::Unspecified,
    }) as i32
}

fn stream(raw: i32) -> tenantd_core::Result<tenantd_core::model::Stream> {
    match pb::Stream::try_from(raw) {
        Ok(pb::Stream::Stdout) => Ok(tenantd_core::model::Stream::Stdout),
        Ok(pb::Stream::Stderr) => Ok(tenantd_core::model::Stream::Stderr),
        _ => Err(Error::invalid("stream must be STDOUT or STDERR")),
    }
}

fn pb_process(r: ProcessRecord) -> pb::Process {
    pb::Process {
        tenant: r.tenant.into(),
        sandbox: r.sandbox.into(),
        id: r.id.into(),
        args: r.spec.args,
        user: r.spec.user.unwrap_or_default(),
        tty: r.spec.tty,
        state: r.state.as_str().into(),
        pid: r.pid.unwrap_or(0),
        exit_code: r.exit_code,
        signal: r.signal.map(pb_signal),
        stdout_dropped: r.stdout_dropped,
        stderr_dropped: r.stderr_dropped,
        created_at: r.created_at,
        exited_at: r.exited_at,
        output_limit: r.limits.output_limit,
    }
}

fn pb_chunk(c: OutputChunk) -> pb::OutputChunk {
    use pb::output_chunk::{Data, Kind, Truncated};
    pb::OutputChunk {
        kind: Some(match c {
            OutputChunk::Data { offset, bytes } => Kind::Data(Data { offset, bytes }),
            OutputChunk::Truncated { offset, dropped } => Kind::Truncated(Truncated {
                offset,
                dropped_bytes: dropped,
            }),
        }),
    }
}

fn limits(l: Option<pb::TenantLimits>) -> tenantd_core::Result<TenantLimits> {
    let l = l.ok_or_else(|| Error::invalid("limits are required"))?;
    Ok(TenantLimits {
        storage: l.storage_bytes,
        cpus: l.cpus,
        memory: l.memory_bytes,
    })
}

fn pb_tenant(r: &TenantRecord, used: u64, sandbox_count: usize) -> pb::Tenant {
    pb::Tenant {
        id: r.id.to_string(),
        limits: Some(pb::TenantLimits {
            storage_bytes: r.limits.storage,
            cpus: r.limits.cpus,
            memory_bytes: r.limits.memory,
        }),
        project_id: r.project.0,
        state: r.state.as_str().into(),
        used_bytes: used,
        sandbox_count: sandbox_count as u32,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

fn pb_tenant_info(i: TenantInfo) -> pb::Tenant {
    pb_tenant(&i.record, i.usage.map_or(0, |u| u.used), i.sandbox_count)
}

fn pb_sandbox(t: &Tenantd, r: SandboxRecord) -> pb::Sandbox {
    pb::Sandbox {
        tenant: r.tenant.to_string(),
        id: r.id.to_string(),
        profile: r.profile,
        image: r.spec.image.reference.clone(),
        image_digest: r.spec.image.digest.clone(),
        state: r.state.as_str().into(),
        resources: Some(pb::Resources {
            memory_bytes: r.spec.memory,
            cpus: r.spec.cpus,
            pids: r.spec.pids,
            size_bytes: r.spec.size,
        }),
        exit_code: r.exit_code,
        rootfs: r.spec.rootfs.as_str().into(),
        network: r.spec.network.as_str().into(),
        layer_survives_stop: t.layer_survives_stop(r.spec.rootfs),
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

pub fn pb_event(e: Event) -> pb::Event {
    use pb::event::Kind;
    let kind = match e.kind {
        EventKind::SandboxExited { key, exit_code } => Kind::SandboxExited(pb::SandboxExited {
            tenant: key.tenant.into(),
            id: key.sandbox.into(),
            exit_code,
        }),
        EventKind::SandboxOom { key } => Kind::SandboxOom(pb::SandboxOom {
            tenant: key.tenant.into(),
            id: key.sandbox.into(),
        }),
        EventKind::ProcessExited {
            key,
            exit_code,
            signal,
            stdout_dropped,
            stderr_dropped,
        } => Kind::ProcessExited(pb::ProcessExited {
            tenant: key.tenant.into(),
            sandbox: key.sandbox.into(),
            id: key.id.into(),
            exit_code,
            signal: signal.map(pb_signal),
            stdout_dropped,
            stderr_dropped,
        }),
        EventKind::QuotaExceeded {
            tenant,
            used,
            limit,
        } => Kind::QuotaExceeded(pb::QuotaExceeded {
            tenant: tenant.into(),
            used_bytes: used,
            limit_bytes: limit,
        }),
        EventKind::Reconcile {
            action,
            target,
            detail,
        } => Kind::Reconcile(pb::ReconcileAction {
            action,
            target,
            detail,
        }),
    };
    pb::Event {
        time: e.time,
        kind: Some(kind),
    }
}

#[tonic::async_trait]
impl Tenants for Api {
    async fn create_tenant(
        &self,
        req: Request<pb::CreateTenantRequest>,
    ) -> Result<Response<pb::Tenant>, Status> {
        let r = req.into_inner();
        self.timed("CreateTenant", async {
            let rec = self
                .tenantd
                .create_tenant(tenant_id(&r.id)?, limits(r.limits)?)
                .await?;
            Ok(pb_tenant_info(self.tenantd.get_tenant(&rec.id).await?))
        })
        .await
    }

    async fn update_tenant(
        &self,
        req: Request<pb::UpdateTenantRequest>,
    ) -> Result<Response<pb::Tenant>, Status> {
        let r = req.into_inner();
        self.timed("UpdateTenant", async {
            let id = tenant_id(&r.id)?;
            self.tenantd.update_tenant(&id, limits(r.limits)?).await?;
            Ok(pb_tenant_info(self.tenantd.get_tenant(&id).await?))
        })
        .await
    }

    async fn get_tenant(
        &self,
        req: Request<pb::GetTenantRequest>,
    ) -> Result<Response<pb::Tenant>, Status> {
        let r = req.into_inner();
        self.timed("GetTenant", async {
            Ok(pb_tenant_info(
                self.tenantd.get_tenant(&tenant_id(&r.id)?).await?,
            ))
        })
        .await
    }

    async fn list_tenants(
        &self,
        _req: Request<pb::ListTenantsRequest>,
    ) -> Result<Response<pb::ListTenantsResponse>, Status> {
        self.timed("ListTenants", async {
            let mut tenants = Vec::new();
            for t in self.tenantd.list_tenants().await? {
                tenants.push(pb_tenant_info(self.tenantd.get_tenant(&t.id).await?));
            }
            Ok(pb::ListTenantsResponse { tenants })
        })
        .await
    }

    async fn delete_tenant(
        &self,
        req: Request<pb::DeleteTenantRequest>,
    ) -> Result<Response<pb::DeleteTenantResponse>, Status> {
        let r = req.into_inner();
        self.timed("DeleteTenant", async {
            self.tenantd
                .delete_tenant(&tenant_id(&r.id)?, r.force)
                .await?;
            Ok(pb::DeleteTenantResponse {})
        })
        .await
    }
}

#[tonic::async_trait]
impl Sandboxes for Api {
    async fn create_sandbox(
        &self,
        req: Request<pb::CreateSandboxRequest>,
    ) -> Result<Response<pb::Sandbox>, Status> {
        let r = req.into_inner();
        self.timed("CreateSandbox", async {
            let o = r.overrides.unwrap_or_default();
            let ov = Overrides {
                memory: o.memory_bytes,
                cpus: o.cpus,
                pids: o.pids,
                size: o.size_bytes,
            };
            let rec = self
                .tenantd
                .create_sandbox(
                    tenant_id(&r.tenant)?,
                    sandbox_id(&r.id)?,
                    r.profile,
                    r.image,
                    ov,
                )
                .await?;
            Ok(pb_sandbox(&self.tenantd, rec))
        })
        .await
    }

    async fn get_sandbox(
        &self,
        req: Request<pb::SandboxRef>,
    ) -> Result<Response<pb::Sandbox>, Status> {
        let r = req.into_inner();
        self.timed("GetSandbox", async {
            let rec = self
                .tenantd
                .get_sandbox(&tenant_id(&r.tenant)?, &sandbox_id(&r.id)?)
                .await?;
            Ok(pb_sandbox(&self.tenantd, rec))
        })
        .await
    }

    async fn list_sandboxes(
        &self,
        req: Request<pb::ListSandboxesRequest>,
    ) -> Result<Response<pb::ListSandboxesResponse>, Status> {
        let r = req.into_inner();
        self.timed("ListSandboxes", async {
            let recs = self.tenantd.list_sandboxes(&tenant_id(&r.tenant)?).await?;
            Ok(pb::ListSandboxesResponse {
                sandboxes: recs
                    .into_iter()
                    .map(|s| pb_sandbox(&self.tenantd, s))
                    .collect(),
            })
        })
        .await
    }

    async fn stop_sandbox(
        &self,
        req: Request<pb::SandboxRef>,
    ) -> Result<Response<pb::Sandbox>, Status> {
        let r = req.into_inner();
        self.timed("StopSandbox", async {
            let rec = self
                .tenantd
                .stop_sandbox(&tenant_id(&r.tenant)?, &sandbox_id(&r.id)?)
                .await?;
            Ok(pb_sandbox(&self.tenantd, rec))
        })
        .await
    }

    async fn start_sandbox(
        &self,
        req: Request<pb::SandboxRef>,
    ) -> Result<Response<pb::Sandbox>, Status> {
        let r = req.into_inner();
        self.timed("StartSandbox", async {
            let rec = self
                .tenantd
                .start_sandbox(&tenant_id(&r.tenant)?, &sandbox_id(&r.id)?)
                .await?;
            Ok(pb_sandbox(&self.tenantd, rec))
        })
        .await
    }

    async fn destroy_sandbox(
        &self,
        req: Request<pb::SandboxRef>,
    ) -> Result<Response<pb::DestroySandboxResponse>, Status> {
        let r = req.into_inner();
        self.timed("DestroySandbox", async {
            self.tenantd
                .destroy_sandbox(&tenant_id(&r.tenant)?, &sandbox_id(&r.id)?)
                .await?;
            Ok(pb::DestroySandboxResponse {})
        })
        .await
    }
}

type OutputStream = Pin<Box<dyn Stream<Item = Result<pb::OutputChunk, Status>> + Send>>;

#[tonic::async_trait]
impl Processes for Api {
    async fn start_process(
        &self,
        req: Request<pb::StartProcessRequest>,
    ) -> Result<Response<pb::Process>, Status> {
        let r = req.into_inner();
        self.timed("StartProcess", async {
            let key = process_key(&r.tenant, &r.sandbox, &r.id)?;
            let none_if_empty = |s: String| Some(s).filter(|s| !s.is_empty());
            let spec = ProcessSpec {
                args: r.args,
                env: r.env,
                cwd: none_if_empty(r.cwd),
                user: none_if_empty(r.user),
                tty: r.tty,
                stdin: r.stdin,
            };
            Ok(pb_process(self.tenantd.start_process(key, spec).await?))
        })
        .await
    }

    async fn get_process(
        &self,
        req: Request<pb::ProcessRef>,
    ) -> Result<Response<pb::Process>, Status> {
        let r = req.into_inner();
        self.timed("GetProcess", async {
            let key = process_key(&r.tenant, &r.sandbox, &r.id)?;
            Ok(pb_process(self.tenantd.get_process(&key).await?))
        })
        .await
    }

    async fn list_processes(
        &self,
        req: Request<pb::ListProcessesRequest>,
    ) -> Result<Response<pb::ListProcessesResponse>, Status> {
        let r = req.into_inner();
        self.timed("ListProcesses", async {
            let sk = SandboxKey::new(tenant_id(&r.tenant)?, sandbox_id(&r.sandbox)?);
            let recs = self.tenantd.list_processes(&sk).await?;
            Ok(pb::ListProcessesResponse {
                processes: recs.into_iter().map(pb_process).collect(),
            })
        })
        .await
    }

    async fn signal_process(
        &self,
        req: Request<pb::SignalProcessRequest>,
    ) -> Result<Response<pb::Process>, Status> {
        let r = req.into_inner();
        self.timed("SignalProcess", async {
            let key = process_ref(r.process)?;
            let rec = self.tenantd.signal_process(&key, signal(r.signal)?).await?;
            Ok(pb_process(rec))
        })
        .await
    }

    async fn wait_process(
        &self,
        req: Request<pb::WaitProcessRequest>,
    ) -> Result<Response<pb::Process>, Status> {
        let r = req.into_inner();
        self.timed("WaitProcess", async {
            let key = process_ref(r.process)?;
            let timeout = (r.timeout_ms > 0).then(|| Duration::from_millis(r.timeout_ms));
            Ok(pb_process(self.tenantd.wait_process(&key, timeout).await?))
        })
        .await
    }

    type ReadOutputStream = OutputStream;

    async fn read_output(
        &self,
        req: Request<pb::ReadOutputRequest>,
    ) -> Result<Response<OutputStream>, Status> {
        let r = req.into_inner();
        let res = self
            .timed("ReadOutput", async {
                let key = process_ref(r.process)?;
                let s = stream(r.stream)?;
                self.tenantd.read_output(key, s, r.offset, r.follow).await
            })
            .await?;
        let out = res.into_inner().map(|c| c.map(pb_chunk).map_err(status));
        Ok(Response::new(Box::pin(out)))
    }

    async fn delete_process(
        &self,
        req: Request<pb::DeleteProcessRequest>,
    ) -> Result<Response<pb::DeleteProcessResponse>, Status> {
        let r = req.into_inner();
        self.timed("DeleteProcess", async {
            let key = process_ref(r.process)?;
            self.tenantd.delete_process(&key, r.force).await?;
            Ok(pb::DeleteProcessResponse {})
        })
        .await
    }
}

type EventStream = Pin<Box<dyn Stream<Item = Result<pb::Event, Status>> + Send>>;

#[tonic::async_trait]
impl System for Api {
    async fn health(
        &self,
        _req: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        self.timed("Health", async {
            let h = self.tenantd.check_health().await;
            let enforcing = h.iter().filter(|c| c.name != "network").all(|c| c.ok);
            Ok(pb::HealthResponse {
                enforcing,
                components: h
                    .into_iter()
                    .map(|c| pb::ComponentHealth {
                        name: c.name.into(),
                        ok: c.ok,
                        message: c.message,
                    })
                    .collect(),
            })
        })
        .await
    }

    type WatchEventsStream = EventStream;

    async fn watch_events(
        &self,
        _req: Request<pb::WatchEventsRequest>,
    ) -> Result<Response<EventStream>, Status> {
        let rx = self.tenantd.subscribe();
        let s = BroadcastStream::new(rx).filter_map(|r| match r {
            Ok(e) => Some(Ok(pb_event(e))),
            // A slow watcher missed events; tell it rather than silently skipping.
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                Some(Err(Status::data_loss(format!("missed {n} events"))))
            }
        });
        Ok(Response::new(Box::pin(s)))
    }
}
