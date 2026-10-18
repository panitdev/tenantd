//! `tenantd serve`: the daemon. Fails closed: exits non-zero when quota or
//! runtime enforcement isn't in place.

use std::collections::HashSet;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Args;
use futures::Stream;
use tenantd_client::pb::{
    processes_server::ProcessesServer, sandboxes_server::SandboxesServer,
    system_server::SystemServer, tenants_server::TenantsServer,
};
use tenantd_core::config::{Config, RuntimeKind, StorageKind};
use tenantd_core::state::StateStore;
use tenantd_core::{Backends, Tenantd};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tracing::{error, info, warn};

use crate::api::Api;
use crate::metrics::{self, Metrics};

#[derive(Args)]
pub struct ConfigPath {
    /// Operator policy file.
    #[arg(
        short,
        long,
        env = "TENANTD_CONFIG",
        default_value = "/etc/tenantd/tenantd.toml"
    )]
    pub config: PathBuf,
}

#[derive(Args)]
pub struct ServeArgs {
    #[command(flatten)]
    config: ConfigPath,
    /// Log as JSON lines.
    #[arg(long)]
    log_json: bool,
}

pub fn init_tracing(json: bool) {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let sub = tracing_subscriber::fmt().with_env_filter(filter);
    if json { sub.json().init() } else { sub.init() }
}

/// `tenantd config check`: validate against the real backends without
/// touching the host.
pub fn check_config(path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(path)?;
    let state = Arc::new(tenantd_state::SqliteState::in_memory()?);
    Tenantd::new(cfg.clone(), build_backends(&cfg, state)?)?;
    println!("{}: ok", path.display());
    Ok(())
}

fn build_backends(cfg: &Config, state: Arc<dyn StateStore>) -> anyhow::Result<Backends> {
    let storage = match cfg.storage.backend {
        StorageKind::XfsProject => {
            Arc::new(tenantd_storage_xfs::XfsProjectQuota::new(&cfg.storage.root))
        }
        other => bail!("storage backend {other:?} is not available in this build"),
    };
    let runtime = match cfg.runtime.backend {
        RuntimeKind::RunscDirect => Arc::new(tenantd_runtime_runsc::RunscRuntime::new(
            cfg.runtime.clone(),
        )),
        other => bail!("runtime backend {other:?} is not available in this build"),
    };
    let cache = &cfg.images.cache;
    Ok(Backends {
        storage,
        layers: vec![
            Arc::new(tenantd_layer::HostOverlay::new(cache)),
            Arc::new(tenantd_layer::MemoryLayer::new(cache)),
            Arc::new(tenantd_layer::ReadOnlyLayer::new(cache)),
        ],
        runtime,
        images: Arc::new(tenantd_image::OciImageStore::new(
            cache,
            cfg.images.insecure_registries.clone(),
        )),
        network: Arc::new(tenantd_net::CniNetwork::new(cfg.network.clone())),
        output: Arc::new(tenantd_output::FileOutput::new()),
        state,
    })
}

/// Bind the API socket: mode 0660, optionally group-owned by `gid`.
fn bind_socket(path: &Path, gid: Option<u32>) -> anyhow::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(_) => {}
    }
    let l = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    Ok(l)
}

/// Accepted connections whose peer (by `SO_PEERCRED`) is root or a listed
/// caller UID. Everything else is dropped before a byte is read.
fn authorized(
    l: UnixListener,
    allowed: Arc<HashSet<u32>>,
) -> impl Stream<Item = std::io::Result<UnixStream>> {
    UnixListenerStream::new(l).filter_map(move |conn| match conn {
        Ok(s) => match s.peer_cred() {
            Ok(c) if c.uid() == 0 || allowed.contains(&c.uid()) => Some(Ok(s)),
            Ok(c) => {
                warn!(uid = c.uid(), pid = ?c.pid(), "refused connection from unlisted uid");
                None
            }
            Err(e) => {
                warn!(error = %e, "refused connection: no peer credentials");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "accept failed");
            None
        }
    })
}

async fn serve_api(
    l: UnixListener,
    allowed: HashSet<u32>,
    api: Api,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    tonic::transport::Server::builder()
        .add_service(TenantsServer::new(api.clone()))
        .add_service(SandboxesServer::new(api.clone()))
        .add_service(ProcessesServer::new(api.clone()))
        .add_service(SystemServer::new(api))
        .serve_with_incoming_shutdown(authorized(l, Arc::new(allowed)), shutdown)
        .await?;
    Ok(())
}

async fn run(args: ServeArgs) -> anyhow::Result<()> {
    let cfg = Config::load(&args.config.config)?;
    let backends = build_backends(
        &cfg,
        Arc::new(tenantd_state::SqliteState::open(&cfg.server.state)?),
    )?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        warn!("not running as root; quota, mount and runsc calls will fail");
    }

    backends
        .storage
        .verify()
        .await
        .context("storage quota enforcement is not in place")?;
    backends
        .runtime
        .verify()
        .await
        .context("runtime check failed")?;
    let tenantd = Tenantd::new(cfg.clone(), backends)?;
    tenantd.check_health().await;
    tenantd.spawn_event_pump();

    let rep = tenantd.reconcile().await;
    info!(
        actions = rep.actions.len(),
        errors = rep.errors.len(),
        "startup reconcile done"
    );

    {
        let t = tenantd.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(
                    t.config().reconcile.interval_secs.max(1),
                ))
                .await;
                let rep = t.reconcile().await;
                if !rep.actions.is_empty() || !rep.errors.is_empty() {
                    info!(
                        actions = rep.actions.len(),
                        errors = rep.errors.len(),
                        "reconcile"
                    );
                }
            }
        });
    }
    {
        let (t, path) = (tenantd.clone(), args.config.config.clone());
        let mut hup = signal(SignalKind::hangup())?;
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                match Config::load(&path).and_then(|c| t.reload_config(c)) {
                    Ok(()) => info!(config = %path.display(), "config reloaded"),
                    Err(e) => error!(error = %e, "config reload rejected; keeping the old config"),
                }
            }
        });
    }

    let metrics = Arc::new(Metrics::new());
    if let Some(addr) = cfg.server.metrics.clone() {
        let (m, t) = (metrics.clone(), tenantd.clone());
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(addr, m, t).await {
                error!(error = %e, "metrics server stopped");
            }
        });
    }

    let listener = bind_socket(&cfg.server.socket, cfg.server.socket_gid)?;
    let allowed: HashSet<u32> = cfg.server.callers.iter().map(|c| c.uid).collect();
    info!(socket = %cfg.server.socket.display(), callers = ?allowed, "tenantd serving");
    let mut term = signal(SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        info!("shutting down; sandboxes keep running and are re-attached on start");
    };
    serve_api(listener, allowed, Api { tenantd, metrics }, shutdown).await?;
    let _ = std::fs::remove_file(&cfg.server.socket);
    Ok(())
}

pub async fn main(args: ServeArgs) -> ExitCode {
    init_tracing(args.log_json);
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api;
    use tenantd_client::pb;
    use tenantd_testkit::{Host, TEST_CONFIG};

    async fn start(allowed: HashSet<u32>) -> (tempfile::TempDir, PathBuf, Host, Arc<Tenantd>) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let host = Host::new();
        let tenantd = host.service(TEST_CONFIG);
        tenantd.check_health().await;
        let l = bind_socket(&sock, None).unwrap();
        let api = Api {
            tenantd: tenantd.clone(),
            metrics: Arc::new(Metrics::new()),
        };
        tokio::spawn(serve_api(l, allowed, api, std::future::pending()));
        (dir, sock, host, tenantd)
    }

    fn me() -> u32 {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() }
    }

    #[tokio::test]
    async fn api_over_unix_socket() {
        let (_d, sock, _host, _t) = start(HashSet::from([me()])).await;
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let ch = tenantd_client::connect(&sock).await.unwrap();
        let mut tenants = tenantd_client::TenantsClient::new(ch.clone());
        let mut sandboxes = tenantd_client::SandboxesClient::new(ch.clone());
        let mut system = tenantd_client::SystemClient::new(ch);

        assert!(
            system
                .health(pb::HealthRequest {})
                .await
                .unwrap()
                .into_inner()
                .enforcing
        );
        let limits = Some(pb::TenantLimits {
            storage_bytes: 1 << 30,
            cpus: None,
            memory_bytes: None,
        });
        let t = tenants
            .create_tenant(pb::CreateTenantRequest {
                id: "acme".into(),
                limits,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!((t.state.as_str(), t.project_id), ("ready", 100));

        let bad = tenants
            .create_tenant(pb::CreateTenantRequest {
                id: "Bad/Id".into(),
                limits: None,
            })
            .await
            .unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);

        let req = |image: &str| pb::CreateSandboxRequest {
            tenant: "acme".into(),
            id: "box".into(),
            profile: "default".into(),
            image: image.into(),
            overrides: None,
        };
        let denied = sandboxes
            .create_sandbox(req("quay.io/evil/x"))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            denied.metadata().get(api::RULE_METADATA).unwrap(),
            "profiles.default.images"
        );

        let s = sandboxes
            .create_sandbox(req("alpine"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            (s.state.as_str(), s.rootfs.as_str(), s.layer_survives_stop),
            ("running", "host-overlay", true)
        );
        let again = sandboxes
            .create_sandbox(req("alpine"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(again.created_at, s.created_at);
        assert_eq!(
            sandboxes
                .create_sandbox(req("busybox"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );

        let r = pb::SandboxRef {
            tenant: "acme".into(),
            id: "box".into(),
        };
        assert_eq!(
            sandboxes
                .stop_sandbox(r.clone())
                .await
                .unwrap()
                .into_inner()
                .state,
            "stopped"
        );
        let del = tenants
            .delete_tenant(pb::DeleteTenantRequest {
                id: "acme".into(),
                force: false,
            })
            .await
            .unwrap_err();
        assert_eq!(del.code(), tonic::Code::FailedPrecondition);
        sandboxes.destroy_sandbox(r.clone()).await.unwrap();
        assert_eq!(
            sandboxes.get_sandbox(r).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        tenants
            .delete_tenant(pb::DeleteTenantRequest {
                id: "acme".into(),
                force: false,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn processes_over_unix_socket() {
        let (_d, sock, host, tenantd) = start(HashSet::from([me()])).await;
        tenantd.spawn_event_pump();
        let ch = tenantd_client::connect(&sock).await.unwrap();
        let mut events = tenantd_client::SystemClient::new(ch.clone())
            .watch_events(pb::WatchEventsRequest {})
            .await
            .unwrap()
            .into_inner();
        tenantd_client::TenantsClient::new(ch.clone())
            .create_tenant(pb::CreateTenantRequest {
                id: "acme".into(),
                limits: Some(pb::TenantLimits {
                    storage_bytes: 1 << 30,
                    cpus: None,
                    memory_bytes: None,
                }),
            })
            .await
            .unwrap();
        tenantd_client::SandboxesClient::new(ch.clone())
            .create_sandbox(pb::CreateSandboxRequest {
                tenant: "acme".into(),
                id: "box".into(),
                profile: "default".into(),
                image: "alpine".into(),
                overrides: None,
            })
            .await
            .unwrap();
        let mut procs = tenantd_client::ProcessesClient::new(ch);
        let start = |user: &str| pb::StartProcessRequest {
            tenant: "acme".into(),
            sandbox: "box".into(),
            id: "build".into(),
            args: vec!["make".into()],
            user: user.into(),
            ..Default::default()
        };
        let denied = procs.start_process(start("0")).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            denied.metadata().get(api::RULE_METADATA).unwrap(),
            "profiles.default.exec.users"
        );
        let p = procs.start_process(start("")).await.unwrap().into_inner();
        assert_eq!((p.state.as_str(), p.output_limit), ("running", 16));
        let r = pb::ProcessRef {
            tenant: "acme".into(),
            sandbox: "box".into(),
            id: "build".into(),
        };
        let rec = tenantd
            .get_process(
                &"acme.box"
                    .parse::<tenantd_core::SandboxKey>()
                    .map(|k| tenantd_core::ProcessKey::new(k, "build".parse().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        host.output
            .write(&rec.io, tenantd_core::model::Stream::Stdout, &[b'x'; 20]);

        let mut chunks = procs
            .read_output(pb::ReadOutputRequest {
                process: Some(r.clone()),
                stream: pb::Stream::Stdout as i32,
                offset: 0,
                follow: false,
            })
            .await
            .unwrap()
            .into_inner();
        use pb::output_chunk::Kind;
        let mut got = Vec::new();
        while let Some(c) = chunks.message().await.unwrap() {
            got.push(c.kind.unwrap());
        }
        assert!(matches!(&got[0], Kind::Data(d) if d.bytes == [b'x'; 16]));
        assert!(matches!(&got[1], Kind::Truncated(t) if t.offset == 16 && t.dropped_bytes == 4));
        let bad = procs
            .read_output(pb::ReadOutputRequest {
                process: Some(r.clone()),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);

        let sig = |s: pb::Signal| pb::SignalProcessRequest {
            process: Some(r.clone()),
            signal: s as i32,
        };
        assert_eq!(
            procs
                .signal_process(sig(pb::Signal::Unspecified))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        procs
            .signal_process(sig(pb::Signal::Sigkill))
            .await
            .unwrap();
        let done = procs
            .wait_process(pb::WaitProcessRequest {
                process: Some(r.clone()),
                timeout_ms: 5000,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(done.state, "exited");
        assert_eq!(done.signal, Some(pb::Signal::Sigkill as i32));
        assert_eq!(done.stdout_dropped, 4);
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(5), events.message())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let Some(pb::event::Kind::ProcessExited(x)) = ev.kind {
                assert_eq!(
                    (x.id.as_str(), x.signal),
                    ("build", Some(pb::Signal::Sigkill as i32))
                );
                break;
            }
        }
        let list = procs
            .list_processes(pb::ListProcessesRequest {
                tenant: "acme".into(),
                sandbox: "box".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(list.processes.len(), 1);
        procs
            .delete_process(pb::DeleteProcessRequest {
                process: Some(r.clone()),
                force: false,
            })
            .await
            .unwrap();
        assert_eq!(
            procs.get_process(r).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            procs.start_process(start("")).await.unwrap_err().code(),
            tonic::Code::AlreadyExists
        );
    }

    #[tokio::test]
    async fn cli_follow_marks_truncation_and_ends_at_exit() {
        let (_d, sock, host, tenantd) = start(HashSet::from([me()])).await;
        tenantd.spawn_event_pump();
        let limits = tenantd_core::model::TenantLimits {
            storage: 1 << 30,
            cpus: None,
            memory: None,
        };
        tenantd
            .create_tenant("t".parse().unwrap(), limits)
            .await
            .unwrap();
        tenantd
            .create_sandbox(
                "t".parse().unwrap(),
                "box".parse().unwrap(),
                "default".into(),
                "alpine".into(),
                Default::default(),
            )
            .await
            .unwrap();
        let key: tenantd_core::ProcessKey =
            tenantd_core::ProcessKey::new("t.box".parse().unwrap(), "p".parse().unwrap());
        let p = tenantd
            .start_process(
                key.clone(),
                tenantd_core::model::ProcessSpec {
                    args: vec!["yes".into()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let ch = tenantd_client::connect(&sock).await.unwrap();
        let r = pb::ProcessRef {
            tenant: "t".into(),
            sandbox: "box".into(),
            id: "p".into(),
        };
        let mut out = Vec::new();
        let follow = crate::cli::copy_output(
            tenantd_client::ProcessesClient::new(ch),
            r,
            pb::Stream::Stdout,
            0,
            true,
            &mut out,
        );
        let writer = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            host.output.write(
                &p.io,
                tenantd_core::model::Stream::Stdout,
                b"0123456789abcdefXYZ",
            );
            // Past the limit while the reader is already there: the mark
            // must count this too.
            tokio::time::sleep(Duration::from_millis(250)).await;
            host.output
                .write(&p.io, tenantd_core::model::Stream::Stdout, b"WV");
            tokio::time::sleep(Duration::from_millis(50)).await;
            host.runtime
                .exit_process(&key.sandbox_key(), p.pid.unwrap(), 0);
        };
        let (res, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(follow, writer)
        })
        .await
        .unwrap();
        res.unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "0123456789abcdef\n[truncated: 5 bytes dropped]\n"
        );
    }

    #[tokio::test]
    async fn events_stream() {
        let (_d, sock, host, tenantd) = start(HashSet::from([me()])).await;
        let ch = tenantd_client::connect(&sock).await.unwrap();
        let mut events = tenantd_client::SystemClient::new(ch.clone())
            .watch_events(pb::WatchEventsRequest {})
            .await
            .unwrap()
            .into_inner();
        let limits = Some(pb::TenantLimits {
            storage_bytes: 10,
            cpus: None,
            memory_bytes: None,
        });
        tenantd_client::TenantsClient::new(ch)
            .create_tenant(pb::CreateTenantRequest {
                id: "a".into(),
                limits,
            })
            .await
            .unwrap();
        host.storage
            .tenants
            .lock()
            .unwrap()
            .get_mut(&"a".parse().unwrap())
            .unwrap()
            .used = 10;
        tenantd.reconcile().await;
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(5), events.message())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let Some(pb::event::Kind::QuotaExceeded(q)) = ev.kind {
                assert_eq!(
                    (q.tenant.as_str(), q.used_bytes, q.limit_bytes),
                    ("a", 10, 10)
                );
                break;
            }
        }
    }

    #[tokio::test]
    async fn metrics_render() {
        let (_d, _sock, _host, tenantd) = start(HashSet::new()).await;
        let limits = tenantd_core::model::TenantLimits {
            storage: 5,
            cpus: None,
            memory: None,
        };
        tenantd
            .create_tenant("a".parse().unwrap(), limits)
            .await
            .unwrap();
        let m = Metrics::new();
        m.observe("GetTenant", tonic::Code::Ok, Duration::from_millis(3));
        let text = m.render(&tenantd).await;
        assert!(
            text.contains("tenantd_tenant_storage_limit_bytes{tenant=\"a\"} 5"),
            "{text}"
        );
        assert!(
            text.contains("tenantd_sandboxes{state=\"running\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("tenantd_processes{state=\"running\"} 0"),
            "{text}"
        );
        assert!(
            text.contains(
                "tenantd_operation_duration_seconds_count{op=\"GetTenant\",code=\"Ok\"} 1"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn unlisted_uids_are_refused() {
        if me() == 0 {
            return; // root is always allowed
        }
        let (_d, sock, _host, _t) = start(HashSet::new()).await;
        let ch = tenantd_client::connect(&sock).await.unwrap();
        let mut system = tenantd_client::SystemClient::new(ch);
        assert!(system.health(pb::HealthRequest {}).await.is_err());
    }

    #[test]
    fn example_config_builds() {
        let cfg = Config::load(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/tenantd.toml"
        )))
        .unwrap();
        let state = Arc::new(tenantd_state::SqliteState::in_memory().unwrap());
        let b = build_backends(&cfg, state).unwrap();
        Tenantd::new(cfg, b).unwrap();
    }
}
