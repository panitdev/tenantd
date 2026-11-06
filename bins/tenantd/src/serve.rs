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
    containers_server::ContainersServer, files_server::FilesServer,
    processes_server::ProcessesServer, sandboxes_server::SandboxesServer,
    system_server::SystemServer, tenants_server::TenantsServer, volumes_server::VolumesServer,
};
use tenantd_core::config::{Config, RuntimeKind, StorageKind};
use tenantd_core::state::StateStore;
use tenantd_core::{Backends, Tenantd};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

use crate::api::Api;
use crate::metrics::{self, Metrics};
use crate::tls::{self, Conn, NetListener, TlsReload};

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
    if let Some(t) = &cfg.server.tls {
        tls::server_config(t)?;
    }
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
        volumes: Arc::new(tenantd_layer::HostVolumes),
        fuse: Arc::new(tenantd_layer::HostFuse::new(&cfg.runtime.fuse_dir)),
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

/// Whether the peer (by `SO_PEERCRED`) is root or a listed caller UID.
pub fn peer_allowed(s: &UnixStream, allowed: &HashSet<u32>) -> bool {
    match s.peer_cred() {
        Ok(c) if c.uid() == 0 || allowed.contains(&c.uid()) => true,
        Ok(c) => {
            warn!(uid = c.uid(), pid = ?c.pid(), "refused connection from unlisted uid");
            false
        }
        Err(e) => {
            warn!(error = %e, "refused connection: no peer credentials");
            false
        }
    }
}

/// Accept socket connections whose peer is allowed. Everything else is
/// dropped before a byte is read.
async fn accept_unix(
    l: UnixListener,
    allowed: HashSet<u32>,
    tx: mpsc::Sender<std::io::Result<Conn>>,
) {
    loop {
        tokio::select! {
            _ = tx.closed() => return,
            r = l.accept() => match r {
                Ok((s, _)) if peer_allowed(&s, &allowed) => {
                    if tx.send(Ok(Conn::Unix(s))).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
}

/// Authorized connections from the socket and, in network mode, finished
/// mTLS handshakes.
fn authorized(
    unix: UnixListener,
    allowed: HashSet<u32>,
    net: Option<NetListener>,
) -> impl Stream<Item = std::io::Result<Conn>> {
    let (tx, rx) = mpsc::channel(64);
    if let Some(net) = net {
        tokio::spawn(tls::accept_tls(net, tx.clone()));
    }
    tokio::spawn(accept_unix(unix, allowed, tx));
    ReceiverStream::new(rx)
}

async fn serve_api(
    l: UnixListener,
    allowed: HashSet<u32>,
    net: Option<NetListener>,
    api: Api,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    tonic::transport::Server::builder()
        .add_service(TenantsServer::new(api.clone()))
        .add_service(SandboxesServer::new(api.clone()))
        .add_service(ContainersServer::new(api.clone()))
        .add_service(VolumesServer::new(api.clone()))
        .add_service(ProcessesServer::new(api.clone()))
        .add_service(FilesServer::new(api.clone()))
        .add_service(SystemServer::new(api))
        .serve_with_incoming_shutdown(authorized(l, allowed, net), shutdown)
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
    // Read the TLS files before anything starts, so a bad one fails closed.
    let tls_reload = cfg
        .server
        .tls
        .as_ref()
        .map(|t| TlsReload::new(t).map(Arc::new))
        .transpose()?;
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
        let tls_reload = tls_reload.clone();
        let mut hup = signal(SignalKind::hangup())?;
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                let new = Config::load(&path);
                let new_tls = new.as_ref().ok().and_then(|c| c.server.tls.clone());
                if let Err(e) = new.and_then(|c| t.reload_config(c)) {
                    error!(error = %e, "config reload rejected; keeping the old config");
                    continue;
                }
                info!(config = %path.display(), "config reloaded");
                match (&tls_reload, &new_tls) {
                    (Some(r), new) => {
                        if let Err(e) = r.reload(new.as_ref()) {
                            error!(error = %format!("{e:#}"), "TLS reload rejected; keeping the old TLS config");
                        }
                    }
                    (None, Some(_)) => {
                        warn!("server.tls was added; restart tenantd to start listening")
                    }
                    (None, None) => {}
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
    let net = match (&cfg.server.tls, tls_reload) {
        (Some(t), Some(tls)) => {
            let tcp = TcpListener::bind(t.listen)
                .await
                .with_context(|| format!("binding server.tls.listen {}", t.listen))?;
            info!(listen = %t.listen, clients = ?t.clients, "tenantd serving over mTLS");
            Some(NetListener { tcp, tls })
        }
        _ => None,
    };
    info!(socket = %cfg.server.socket.display(), callers = ?allowed, "tenantd serving");
    let mut term = signal(SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        info!("shutting down; sandboxes keep running and are re-attached on start");
    };
    serve_api(listener, allowed, net, Api { tenantd, metrics }, shutdown).await?;
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
        tokio::spawn(serve_api(l, allowed, None, api, std::future::pending()));
        (dir, sock, host, tenantd)
    }

    fn me() -> u32 {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() }
    }

    /// Serve `exec_piped` with the real helper on the container's fake root.
    fn fake_helper(host: &Host, roots: PathBuf) {
        use tenantd_core::backend::PipedProcess;
        use tokio::net::unix::pipe;
        let f: tenantd_testkit::HelperFn = Arc::new(move |h, _p| {
            let c = h.container().expect("a container");
            let root = roots.join(c.sandbox.as_str()).join(c.id.as_str());
            let (in_r, in_w) = std::io::pipe().unwrap();
            let (out_r, out_w) = std::io::pipe().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                std::fs::create_dir_all(&root).unwrap();
                let root = tenantd_layer::files::Root::open(
                    &root,
                    tenantd_layer::files::Ident::current(),
                    &[],
                )
                .unwrap();
                let mut input = std::io::BufReader::new(in_r);
                let mut output = std::io::BufWriter::new(out_w);
                let r = crate::files_helper::serve(&root, &mut input, &mut output)
                    .and_then(|_| std::io::Write::flush(&mut output));
                let _ = tx.send(r.map_err(|e| e.to_string()));
            });
            Ok(PipedProcess {
                stdin: Box::pin(pipe::Sender::from_owned_fd(in_w.into()).unwrap()),
                stdout: Box::pin(pipe::Receiver::from_owned_fd(out_r.into()).unwrap()),
                exit: Box::pin(async move {
                    match rx.await {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(tenantd_core::Error::Internal(e)),
                        Err(_) => Err(tenantd_core::Error::Internal("helper panicked".into())),
                    }
                }),
            })
        });
        *host.runtime.helper.lock().unwrap() = Some(f);
    }

    /// Every Files call on container `id` of acme.box, whose root is `root`.
    async fn exercise_files(ch: &tonic::transport::Channel, id: &str, user: &str, root: &Path) {
        use tenantd_client::files::{self, Files, WriteOptions, errno};
        let c = pb::ContainerRef {
            tenant: "acme".into(),
            sandbox: "box".into(),
            id: id.into(),
        };
        let user = user.to_string();
        let mut f = Files::new(ch.clone(), c.clone()).as_user(&user);

        // Bigger than a read chunk, a write chunk and the output limit.
        let body: Vec<u8> = (0..(600u32 << 10)).map(|i| (i % 251) as u8).collect();
        let opts = WriteOptions {
            parents: true,
            ..Default::default()
        };
        let a = f.write("/work/big", body.clone(), &opts).await.unwrap();
        assert_eq!((a.size, a.mode), (body.len() as u64, 0o644));
        assert_eq!(f.read("/work/big").await.unwrap(), body);
        let mut r = f.read_range("/work/big", 300 << 10, 1000).await.unwrap();
        assert_eq!(r.attr().size, body.len() as u64);
        let (off, chunk) = r.chunk().await.unwrap().unwrap();
        assert_eq!(
            (off, &chunk[..]),
            (300 << 10, &body[300 << 10..(300 << 10) + 1000])
        );
        assert!(r.chunk().await.unwrap().is_none());

        // An absolute symlink is the container's view, not the host's.
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/passwd"), "inside\n").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("work/pw")).unwrap();
        let st = f.stat("/work/pw", true).await.unwrap();
        assert_eq!((st.path.as_str(), st.attr.size), ("/etc/passwd", 7));
        assert_eq!(f.read("/work/pw").await.unwrap(), b"inside\n");
        let st = f.stat("/work/pw", false).await.unwrap();
        assert_eq!(st.attr.kind(), pb::FileKind::Symlink);
        let names: Vec<String> = f
            .read_dir("/work")
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["big", "pw"]);

        // A body that fails midway leaves the target as it was.
        f.write("/work/small", b"old".to_vec(), &opts)
            .await
            .unwrap();
        struct Broken(bool);
        impl tokio::io::AsyncRead for Broken {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if std::mem::replace(&mut self.0, true) {
                    return std::task::Poll::Ready(Err(std::io::Error::other("disk gone")));
                }
                buf.put_slice(b"partial");
                std::task::Poll::Ready(Ok(()))
            }
        }
        let e = f
            .write_from("/work/small", Broken(false), &opts)
            .await
            .unwrap_err();
        assert!(matches!(e, files::Error::Io(_)), "{e}");
        f.write_from("/work/streamed", &b"from a reader"[..], &opts)
            .await
            .unwrap();
        assert_eq!(f.read("/work/streamed").await.unwrap(), b"from a reader");
        let sized = WriteOptions {
            size: Some(100),
            ..Default::default()
        };
        let e = f
            .write_from("/work/streamed", &b"cut off"[..], &sized)
            .await
            .unwrap_err();
        assert_eq!(e.errno(), Some(tenantd_client::files::errno::EIO), "{e}");
        assert_eq!(f.read("/work/streamed").await.unwrap(), b"from a reader");
        // A body shorter than its declared size is refused too.
        let mut raw = tenantd_client::FilesClient::new(ch.clone());
        let msgs = vec![
            pb::FileWriteRequest {
                msg: Some(pb::file_write_request::Msg::Header(pb::FileWriteHeader {
                    container: Some(c.clone()),
                    path: "/work/small".into(),
                    size: Some(10),
                    user: user.clone(),
                    ..Default::default()
                })),
            },
            pb::FileWriteRequest {
                msg: Some(pb::file_write_request::Msg::Data(b"short".to_vec())),
            },
        ];
        let r = raw
            .write(tokio_stream::iter(msgs))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(r.errno, errno::EIO);
        // The server drops a cancelled write's temporary file a moment later.
        for _ in 0..100 {
            let left: Vec<_> = std::fs::read_dir(root.join("work"))
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .filter(|n| n.to_string_lossy().starts_with(".tenantd-write-"))
                .collect();
            if left.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(f.read("/work/small").await.unwrap(), b"old");
        let names: Vec<String> = f
            .read_dir("/work")
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["big", "pw", "small", "streamed"]);

        let e = f
            .write(
                "/work/small",
                b"x".to_vec(),
                &WriteOptions {
                    exclusive: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.errno(), Some(errno::EEXIST));
        f.write("/other/x", b"x".to_vec(), &opts).await.unwrap();
        f.rename("/work/small", "/other/x", files::RENAME_NOREPLACE)
            .await
            .unwrap_err();
        f.rename("/work/small", "/other/moved", 0).await.unwrap();
        assert!(
            f.stat("/work/small", false)
                .await
                .unwrap_err()
                .is_not_found()
        );
        assert_eq!(f.read("/other/moved").await.unwrap(), b"old");
        let e = f.remove_dir("/other").await.unwrap_err();
        assert_eq!(e.errno(), Some(errno::ENOTEMPTY));
        f.remove("/other/moved").await.unwrap();
        f.remove("/other/x").await.unwrap();
        f.remove_dir("/other").await.unwrap();
        assert!(f.read_dir("/other").await.unwrap_err().is_not_found());
        assert_eq!(
            f.read("/work").await.unwrap_err().errno(),
            Some(errno::EISDIR)
        );
    }

    /// The Files service end to end over the socket, through the client's
    /// wrappers, on a real directory standing in for the container's root.
    /// It acts as this test's own user: switching identity needs root.
    #[tokio::test]
    async fn files_over_unix_socket() {
        use tenantd_client::files::{self, Files, WriteOptions};

        let (d, sock, host, tenantd) = start(HashSet::from([me()])).await;
        *host.files_dir.lock().unwrap() = Some(d.path().join("roots"));
        // SAFETY: no preconditions.
        let user = format!("{}:{}", me(), unsafe { libc::getegid() });
        let mut cfg = Config::from_toml(TEST_CONFIG).unwrap();
        cfg.profiles.get_mut("default").unwrap().exec.users = vec![user.clone()];
        tenantd.reload_config(cfg).unwrap();

        let ch = tenantd_client::connect(&sock).await.unwrap();
        tenantd_client::TenantsClient::new(ch.clone())
            .create_tenant(pb::CreateTenantRequest {
                id: "acme".into(),
                limits: Some(pb::TenantLimits {
                    storage_bytes: 1 << 30,
                    ..Default::default()
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
        let roots = d.path().join("roots");
        fake_helper(&host, roots.clone());
        for (id, host_access) in [("s1", false), ("s2", true)] {
            tenantd_client::ContainersClient::new(ch.clone())
                .create_container(pb::CreateContainerRequest {
                    tenant: "acme".into(),
                    sandbox: "box".into(),
                    id: id.into(),
                    host_file_access: host_access,
                    ..Default::default()
                })
                .await
                .unwrap();
            let before = host.runtime.piped.lock().unwrap().len();
            exercise_files(&ch, id, &user, &roots.join("box").join(id)).await;
            let piped = host.runtime.piped.lock().unwrap().clone();
            if host_access {
                assert_eq!(piped.len(), before, "served from the host");
            } else {
                assert!(piped.len() > before + 20, "served by the helper");
                assert_eq!(piped[before].args, [tenantd_core::files::HELPER_PATH]);
                assert_eq!(piped[before].user.as_deref(), Some(user.as_str()));
            }
        }
        // On the host, a path under a mount goes through the helper.
        let root = roots.join("box/s2");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::write(root.join("proc/cpus"), "4").unwrap();
        let c = pb::ContainerRef {
            tenant: "acme".into(),
            sandbox: "box".into(),
            id: "s2".into(),
        };
        let mut f = Files::new(ch.clone(), c.clone()).as_user(&user);
        let before = host.runtime.piped.lock().unwrap().len();
        assert_eq!(f.read("/proc/cpus").await.unwrap(), b"4");
        f.write("/proc/cpus", b"8".to_vec(), &WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(host.runtime.piped.lock().unwrap().len(), before + 2);
        assert_eq!(std::fs::read(root.join("proc/cpus")).unwrap(), b"8");

        // Refusals are gRPC errors, not errnos.
        let mut other = Files::new(
            ch.clone(),
            pb::ContainerRef {
                id: "nope".into(),
                ..c.clone()
            },
        )
        .as_user(&user);
        match other.stat("/", false).await.unwrap_err() {
            files::Error::Status(s) => assert_eq!(s.code(), tonic::Code::NotFound),
            e => panic!("{e}"),
        }
        let mut root_user = Files::new(ch, c).as_user("0");
        match root_user.stat("/", false).await.unwrap_err() {
            files::Error::Status(s) => assert_eq!(s.code(), tonic::Code::PermissionDenied),
            e => panic!("{e}"),
        }
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
    async fn containers_over_unix_socket() {
        let (_d, sock, host, _tenantd) = start(HashSet::from([me()])).await;
        let ch = tenantd_client::connect(&sock).await.unwrap();
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
        let mut containers = tenantd_client::ContainersClient::new(ch.clone());
        let r = pb::ContainerRef {
            tenant: "acme".into(),
            sandbox: "box".into(),
            id: "s1".into(),
        };
        let c = containers
            .create_container(pb::CreateContainerRequest {
                tenant: "acme".into(),
                sandbox: "box".into(),
                id: "s1".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(c.state, "running");
        assert_eq!(
            containers
                .list_containers(pb::ListContainersRequest {
                    tenant: "acme".into(),
                    sandbox: "box".into(),
                })
                .await
                .unwrap()
                .into_inner()
                .containers,
            vec![c]
        );
        let bad = containers
            .create_container(pb::CreateContainerRequest {
                tenant: "acme".into(),
                sandbox: "box".into(),
                id: "Bad".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);

        let mut procs = tenantd_client::ProcessesClient::new(ch);
        let p = procs
            .start_process(pb::StartProcessRequest {
                tenant: "acme".into(),
                sandbox: "box".into(),
                id: "p1".into(),
                args: vec!["make".into()],
                container: "s1".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(p.container, "s1");
        assert!(
            host.runtime
                .container_alive(&"acme.box.s1".parse().unwrap(), p.pid)
        );

        containers.delete_container(r.clone()).await.unwrap();
        assert_eq!(
            containers.get_container(r).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
    }

    #[tokio::test]
    async fn volumes_and_fuse_over_the_unix_socket() {
        use pb::fuse_server_event::Event;
        use pb::fuse_server_message::Msg;
        use tenantd_core::fuse::{FuseOp, FuseReply};
        let (_d, sock, host, _tenantd) = start(HashSet::from([me()])).await;
        let ch = tenantd_client::connect(&sock).await.unwrap();
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

        let mut volumes = tenantd_client::VolumesClient::new(ch.clone());
        let v = volumes
            .create_volume(pb::CreateVolumeRequest {
                tenant: "acme".into(),
                id: "ws".into(),
                uid: Some(1000),
                gid: Some(1000),
                mode: Some(0o1777),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!((v.state.as_str(), v.uid, v.mode), ("ready", 1000, 0o1777));
        assert_eq!(v.path, "/data/tenants/acme/volumes/ws");
        let denied = volumes
            .create_volume(pb::CreateVolumeRequest {
                tenant: "acme".into(),
                id: "x".into(),
                uid: Some(4242),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            denied.metadata().get(api::RULE_METADATA).unwrap(),
            "server.callers"
        );

        let mut containers = tenantd_client::ContainersClient::new(ch.clone());
        let r = pb::ContainerRef {
            tenant: "acme".into(),
            sandbox: "box".into(),
            id: "s1".into(),
        };
        let c = containers
            .create_container(pb::CreateContainerRequest {
                tenant: "acme".into(),
                sandbox: "box".into(),
                id: "s1".into(),
                volumes: [("workspace".to_string(), "ws".to_string())].into(),
                fuse: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(c.state, "created");
        assert_eq!(c.fuse_path, "/mnt");
        assert_eq!(c.volumes[0].path, "/workspace");
        assert_eq!(
            containers
                .start_container(r.clone())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );

        // A server opens ServeFuse with an attach naming the container.
        let k: tenantd_core::ContainerKey = "acme.box.s1".parse().unwrap();
        let attach_msg = |tenant: &str, id: &str, version: u32| pb::FuseServerMessage {
            msg: Some(Msg::Attach(pb::Attach {
                container: Some(pb::ContainerRef {
                    tenant: tenant.into(),
                    sandbox: "box".into(),
                    id: id.into(),
                }),
                version,
                limits: None,
            })),
        };
        let open = |first: pb::FuseServerMessage| {
            let mut containers = containers.clone();
            async move {
                let (tx, rx) = tokio::sync::mpsc::channel(16);
                tx.send(first).await.unwrap();
                let events = containers
                    .serve_fuse(tokio_stream::wrappers::ReceiverStream::new(rx))
                    .await?
                    .into_inner();
                Ok::<_, tonic::Status>((tx, events))
            }
        };
        let refused = |r: Result<_, tonic::Status>| match r {
            Err(e) => e.code(),
            Ok(_) => panic!("the attach was accepted"),
        };
        assert_eq!(
            refused(open(attach_msg("acme", "nope", 1)).await),
            tonic::Code::NotFound
        );
        assert_eq!(
            refused(open(attach_msg("acme", "BAD", 1)).await),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            refused(open(attach_msg("acme", "s1", 99)).await),
            tonic::Code::FailedPrecondition
        );
        let not_attach = pb::FuseServerMessage {
            msg: Some(Msg::Invalidate(pb::Invalidate::default())),
        };
        assert_eq!(
            refused(open(not_attach).await),
            tonic::Code::InvalidArgument
        );
        assert!(!host.fuse.has_server(&k));

        let (tx, mut events) = open(attach_msg("acme", "s1", 1)).await.unwrap();
        let Some(Event::Attached(a)) = events.message().await.unwrap().unwrap().event else {
            panic!("expected attached first");
        };
        assert_eq!(a.generation, 1);
        assert!(a.limits.unwrap().max_inflight > 0);
        assert!(host.fuse.has_server(&k));

        // A request reaches the server and its response comes back.
        let id = host.fuse.inject(&k, FuseOp::StatFs).unwrap();
        let Some(Event::Request(rq)) = events.message().await.unwrap().unwrap().event else {
            panic!("expected a request");
        };
        assert_eq!(rq.id, id);
        assert!(matches!(rq.op, Some(pb::fuse_request::Op::StatFs(_))));
        tx.send(pb::FuseServerMessage {
            msg: Some(Msg::Response(pb::FuseResponse {
                id,
                result: Some(pb::fuse_response::Result::Statfs(pb::StatFsReply {
                    blocks: 10,
                    bsize: 4096,
                    ..Default::default()
                })),
                ..Default::default()
            })),
        })
        .await
        .unwrap();
        let id2 = host
            .fuse
            .inject(&k, FuseOp::Stat { path: "/x".into() })
            .unwrap();
        events.message().await.unwrap().unwrap();
        tx.send(pb::FuseServerMessage {
            msg: Some(Msg::Response(pb::FuseResponse {
                id: id2,
                errno: 2,
                negative_ttl_ms: 5,
                ..Default::default()
            })),
        })
        .await
        .unwrap();
        for _ in 0..100 {
            if host.fuse.responses(&k).len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got = host.fuse.responses(&k);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(matches!(&got[0], (i, Ok(FuseReply::StatFs(s))) if *i == id && s.blocks == 10));
        assert!(
            matches!(&got[1], (i, Err(e)) if *i == id2 && e.errno == 2 && e.negative_ttl_ms == 5)
        );

        // A second server replaces the first, which is aborted.
        let (_tx2, mut events2) = open(attach_msg("acme", "s1", 1)).await.unwrap();
        let Some(Event::Attached(a2)) = events2.message().await.unwrap().unwrap().event else {
            panic!("expected attached");
        };
        assert_eq!(a2.generation, 2);
        assert_eq!(
            events.message().await.unwrap_err().code(),
            tonic::Code::Aborted
        );

        let c = containers
            .start_container(r.clone())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(c.state, "running");
        assert_eq!(
            volumes
                .delete_volume(pb::VolumeRef {
                    tenant: "acme".into(),
                    id: "ws".into(),
                })
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        containers.delete_container(r).await.unwrap();
        assert!(!host.fuse.is_mounted(&k));
        let rep = volumes
            .prune_volume(pb::PruneVolumeRequest {
                volume: Some(pb::VolumeRef {
                    tenant: "acme".into(),
                    id: "ws".into(),
                }),
                path_prefix: "../etc".into(),
                older_than_secs: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(rep.code(), tonic::Code::InvalidArgument);
        volumes
            .delete_volume(pb::VolumeRef {
                tenant: "acme".into(),
                id: "ws".into(),
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
                None,
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

    /// A CA, a server certificate for localhost and 127.0.0.1, and client
    /// certificates, as PEM files.
    struct Pki {
        dir: tempfile::TempDir,
        ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    }

    impl Pki {
        fn new() -> Self {
            let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            p.distinguished_name
                .push(rcgen::DnType::CommonName, "tenantd test CA");
            let ca = rcgen::CertifiedIssuer::self_signed(p, rcgen::KeyPair::generate().unwrap())
                .unwrap();
            let pki = Self {
                dir: tempfile::tempdir().unwrap(),
                ca,
            };
            std::fs::write(pki.path("ca.pem"), pki.ca.pem()).unwrap();
            pki.leaf("server", &["localhost", "127.0.0.1"]);
            pki
        }

        fn path(&self, f: &str) -> PathBuf {
            self.dir.path().join(f)
        }

        /// `<name>.pem` and `<name>.key`, signed by this CA.
        fn leaf(&self, name: &str, sans: &[&str]) {
            let key = rcgen::KeyPair::generate().unwrap();
            let sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
            let cert = rcgen::CertificateParams::new(sans)
                .unwrap()
                .signed_by(&key, &self.ca)
                .unwrap();
            std::fs::write(self.path(&format!("{name}.pem")), cert.pem()).unwrap();
            std::fs::write(self.path(&format!("{name}.key")), key.serialize_pem()).unwrap();
        }

        fn listener(&self, listen: std::net::SocketAddr, clients: &[&str]) -> TlsListener {
            TlsListener {
                listen,
                cert: self.path("server.pem"),
                key: self.path("server.key"),
                client_ca: self.path("ca.pem"),
                clients: clients.iter().map(|c| c.to_string()).collect(),
            }
        }

        /// A client trusting this CA for the server, presenting `name`
        /// (from this PKI or `from`'s).
        fn client(&self, from: &Pki, name: &str) -> tenantd_client::tls::ClientTls {
            tenantd_client::tls::ClientTls::from_pem_files(
                self.path("ca.pem"),
                from.path(&format!("{name}.pem")),
                from.path(&format!("{name}.key")),
            )
            .unwrap()
        }
    }

    use tenantd_core::config::TlsListener;

    async fn start_tls(
        pki: &Pki,
        clients: &[&str],
    ) -> (tempfile::TempDir, PathBuf, String, Arc<TlsReload>, Host) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let host = Host::new();
        let tenantd = host.service(TEST_CONFIG);
        tenantd.check_health().await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let tls = Arc::new(TlsReload::new(&pki.listener(addr, clients)).unwrap());
        let net = NetListener {
            tcp,
            tls: tls.clone(),
        };
        let api = Api {
            tenantd,
            metrics: Arc::new(Metrics::new()),
        };
        let l = bind_socket(&sock, None).unwrap();
        tokio::spawn(serve_api(
            l,
            HashSet::from([me()]),
            Some(net),
            api,
            std::future::pending(),
        ));
        (dir, sock, addr.to_string(), tls, host)
    }

    async fn healthy(ch: Result<tonic::transport::Channel, tonic::transport::Error>) -> bool {
        match ch {
            Ok(ch) => tenantd_client::SystemClient::new(ch)
                .health(pb::HealthRequest {})
                .await
                .is_ok(),
            Err(_) => false,
        }
    }

    #[tokio::test]
    async fn api_over_mtls() {
        let pki = Pki::new();
        pki.leaf("cp", &["cp.test"]);
        let (_d, sock, addr, _tls, _host) = start_tls(&pki, &["cp.test"]).await;
        let tls = pki.client(&pki, "cp");

        // By IP SAN, and by DNS SAN with an explicit server name.
        let ch = tenantd_client::tls::connect(&addr, None, &tls)
            .await
            .unwrap();
        let mut tenants = tenantd_client::TenantsClient::new(ch);
        tenants
            .create_tenant(pb::CreateTenantRequest {
                id: "acme".into(),
                limits: Some(pb::TenantLimits {
                    storage_bytes: 1 << 30,
                    ..Default::default()
                }),
            })
            .await
            .unwrap();
        let ch = tenantd_client::tls::connect(&addr, Some("localhost"), &tls).await;
        assert!(healthy(ch).await);

        // The socket keeps working next to the TLS listener and sees the
        // same daemon.
        let ch = tenantd_client::connect(&sock).await.unwrap();
        let t = tenantd_client::TenantsClient::new(ch)
            .get_tenant(pb::GetTenantRequest { id: "acme".into() })
            .await
            .unwrap();
        assert_eq!(t.into_inner().id, "acme");
    }

    #[tokio::test]
    async fn mtls_refuses_unlisted_untrusted_and_anonymous_clients() {
        let pki = Pki::new();
        pki.leaf("cp", &["cp.test"]);
        pki.leaf("other", &["other.test"]);
        let rogue = Pki::new();
        rogue.leaf("cp", &["cp.test"]);
        let (_d, _sock, addr, _tls, _host) = start_tls(&pki, &["cp.test"]).await;

        // Right CA, name not listed.
        let ch = tenantd_client::tls::connect(&addr, None, &pki.client(&pki, "other")).await;
        assert!(!healthy(ch).await);
        // Listed name, wrong CA.
        let ch = tenantd_client::tls::connect(&addr, None, &pki.client(&rogue, "cp")).await;
        assert!(!healthy(ch).await);
        // The server's name is checked too.
        let ch =
            tenantd_client::tls::connect(&addr, Some("cp.test"), &pki.client(&pki, "cp")).await;
        assert!(!healthy(ch).await);
        // Plaintext h2.
        let ch = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await;
        assert!(!healthy(ch).await);
        // TLS without a client certificate.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(
                tenantd_client::tls::read_certs(&pki.path("ca.pem"))
                    .unwrap()
                    .remove(0),
            )
            .unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap(); // TLS 1.3: the client finishes before the server decides
        let mut buf = [0u8; 1];
        use tokio::io::AsyncReadExt;
        assert!(!matches!(s.read(&mut buf).await, Ok(1..)));

        // The listener survives all of that.
        let ch = tenantd_client::tls::connect(&addr, None, &pki.client(&pki, "cp")).await;
        assert!(healthy(ch).await);
    }

    #[tokio::test]
    async fn mtls_reload_applies_to_new_connections() {
        let pki = Pki::new();
        pki.leaf("cp", &["cp.test"]);
        pki.leaf("cp2", &["cp2.test"]);
        let (_d, _sock, addr, tls, _host) = start_tls(&pki, &["cp.test"]).await;
        let bound = addr.parse().unwrap();
        let (cp, cp2) = (pki.client(&pki, "cp"), pki.client(&pki, "cp2"));
        assert!(healthy(tenantd_client::tls::connect(&addr, None, &cp).await).await);

        tls.reload(Some(&pki.listener(bound, &["cp2.test"])))
            .unwrap();
        assert!(!healthy(tenantd_client::tls::connect(&addr, None, &cp).await).await);
        assert!(healthy(tenantd_client::tls::connect(&addr, None, &cp2).await).await);

        // Rotated server certificate, picked up by the same reload.
        pki.leaf("server", &["localhost"]);
        tls.reload(Some(&pki.listener(bound, &["cp2.test"])))
            .unwrap();
        assert!(!healthy(tenantd_client::tls::connect(&addr, None, &cp2).await).await);
        let ch = tenantd_client::tls::connect(&addr, Some("localhost"), &cp2).await;
        assert!(healthy(ch).await);

        // Moving or dropping the listener needs a restart; a broken file
        // keeps the old config.
        let moved = pki.listener("127.0.0.1:1".parse().unwrap(), &["cp2.test"]);
        assert!(tls.reload(Some(&moved)).is_err());
        assert!(tls.reload(None).is_err());
        let mut broken = pki.listener(bound, &["cp.test"]);
        broken.key = pki.path("missing.key");
        assert!(tls.reload(Some(&broken)).is_err());
        let ch = tenantd_client::tls::connect(&addr, Some("localhost"), &cp2).await;
        assert!(healthy(ch).await);
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
