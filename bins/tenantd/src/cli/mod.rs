//! Operator commands over a running daemon's API socket. These never read
//! the daemon config, open the state DB or need root; only socket access.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Subcommand};
use tenantd_client::pb;
use tenantd_client::{
    ContainersClient, ProcessesClient, SandboxesClient, SystemClient, TenantsClient, VolumesClient,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tonic::transport::Channel;

#[derive(Args)]
pub struct Conn {
    /// The daemon's API socket.
    #[arg(
        short,
        long,
        global = true,
        env = "TENANTD_SOCKET",
        default_value = "/run/tenantd/api.sock"
    )]
    socket: PathBuf,
}

#[derive(Subcommand)]
pub enum ClientCmd {
    /// Manage tenants.
    Tenant {
        #[command(flatten)]
        conn: Conn,
        #[command(subcommand)]
        cmd: TenantCmd,
    },
    /// Manage sandboxes.
    Sandbox {
        #[command(flatten)]
        conn: Conn,
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
    /// Manage containers inside sandboxes.
    Container {
        #[command(flatten)]
        conn: Conn,
        #[command(subcommand)]
        cmd: ContainerCmd,
    },
    /// Manage tenants' volumes.
    Volume {
        #[command(flatten)]
        conn: Conn,
        #[command(subcommand)]
        cmd: VolumeCmd,
    },
    /// Run a command in a running sandbox: start it, stream its output and
    /// exit with its exit code (128+n when signal n killed it).
    Exec {
        #[command(flatten)]
        conn: Conn,
        #[command(flatten)]
        args: ExecArgs,
    },
    /// Processes started in sandboxes.
    Process {
        #[command(flatten)]
        conn: Conn,
        #[command(subcommand)]
        cmd: ProcessCmd,
    },
    /// Backend checks and quota enforcement status.
    Health {
        #[command(flatten)]
        conn: Conn,
    },
    /// Stream events (exits, OOM, quota, reconcile actions) as JSON lines.
    Events {
        #[command(flatten)]
        conn: Conn,
    },
}

#[derive(Args)]
pub struct LimitArgs {
    /// Storage quota, e.g. 10g.
    #[arg(long, value_parser = size)]
    pub storage: u64,
    /// CPU ceiling across running sandboxes.
    #[arg(long)]
    cpus: Option<f64>,
    /// Memory ceiling across running sandboxes, e.g. 8g.
    #[arg(long, value_parser = size)]
    pub memory: Option<u64>,
}

impl LimitArgs {
    fn pb(&self) -> Option<pb::TenantLimits> {
        Some(pb::TenantLimits {
            storage_bytes: self.storage,
            cpus: self.cpus,
            memory_bytes: self.memory,
        })
    }
}

#[derive(Subcommand)]
pub enum TenantCmd {
    Create {
        id: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Update {
        id: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Get {
        id: String,
    },
    List,
    Delete {
        id: String,
        /// Destroy the tenant's sandboxes first.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum SandboxCmd {
    Create {
        tenant: String,
        id: String,
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        image: String,
        #[arg(long, value_parser = size)]
        memory: Option<u64>,
        #[arg(long)]
        cpus: Option<f64>,
        #[arg(long)]
        pids: Option<u32>,
        #[arg(long, value_parser = size)]
        size: Option<u64>,
    },
    Get {
        tenant: String,
        id: String,
    },
    List {
        tenant: String,
    },
    Stop {
        tenant: String,
        id: String,
    },
    Start {
        tenant: String,
        id: String,
    },
    Destroy {
        tenant: String,
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ContainerCmd {
    /// Start a container from the sandbox's image, inside the running sandbox.
    Create {
        tenant: String,
        sandbox: String,
        id: String,
        /// SLOT=VOLUME: mount a volume through one of the profile's slots;
        /// repeatable.
        #[arg(long = "volume", short = 'v', value_parser = binding)]
        volumes: Vec<(String, String)>,
        /// Mount the profile's FUSE slot. The container then waits
        /// "created" for its server; see attach-fuse.
        #[arg(long)]
        fuse: bool,
        /// Its init and arguments; default: the image's entrypoint and cmd.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Run a created container, once its FUSE server has attached.
    Start {
        tenant: String,
        sandbox: String,
        id: String,
    },
    /// Take the container's FUSE connection and run its server: the
    /// command gets the connection as fd 3 (also in TENANTD_FUSE_FD), as
    /// libfuse servers take `/dev/fd/3` for a mount point. Exits with the
    /// server's exit code.
    AttachFuse {
        tenant: String,
        sandbox: String,
        id: String,
        /// The daemon's FUSE socket.
        #[arg(
            long,
            env = "TENANTD_FUSE_SOCKET",
            default_value = tenantd_client::fuse::DEFAULT_SOCKET
        )]
        fuse_socket: PathBuf,
        /// Start the container once the server runs.
        #[arg(long)]
        start: bool,
        /// The server and its arguments.
        #[arg(last = true, required = true)]
        server: Vec<String>,
    },
    Get {
        tenant: String,
        sandbox: String,
        id: String,
    },
    List {
        tenant: String,
        sandbox: String,
    },
    /// End its processes and remove it and its root.
    Rm {
        tenant: String,
        sandbox: String,
        id: String,
    },
}

#[derive(Subcommand)]
pub enum VolumeCmd {
    /// Create a volume in the tenant's quota.
    Create {
        tenant: String,
        id: String,
        /// Owner of its root: root or a caller UID.
        #[arg(long)]
        uid: Option<u32>,
        #[arg(long)]
        gid: Option<u32>,
        /// Mode of its root, in octal; default 755.
        #[arg(long, value_parser = octal)]
        mode: Option<u32>,
    },
    Get {
        tenant: String,
        id: String,
    },
    List {
        tenant: String,
    },
    /// Remove it and everything in it; refused while a container binds it.
    Rm {
        tenant: String,
        id: String,
    },
    /// Remove what is at or below a path and unused for a while.
    Prune {
        tenant: String,
        id: String,
        /// Relative to the volume; default: all of it.
        #[arg(long, default_value = "")]
        prefix: String,
        /// Seconds without access, modification or change; 0 removes all.
        #[arg(long, default_value_t = 0)]
        older_than: u64,
    },
}

fn binding(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .ok_or_else(|| format!("{s:?} is not SLOT=VOLUME"))
}

fn octal(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0o"), 8).map_err(|e| format!("{s:?}: {e}"))
}

#[derive(Args)]
pub struct ExecArgs {
    pub tenant: String,
    pub sandbox: String,
    /// Run in this container of the sandbox; default: the sandbox's own.
    #[arg(long, short)]
    pub container: Option<String>,
    /// Process ID; generated when omitted. Starting the same ID again with
    /// the same command returns the existing process.
    #[arg(long)]
    pub id: Option<String>,
    /// User to run as (must be allowed by the profile); default: the image's.
    #[arg(long, short)]
    pub user: Option<String>,
    /// KEY=VALUE added to the image env; repeatable.
    #[arg(long = "env", short = 'e')]
    pub env: Vec<String>,
    /// Working directory; default: the image's.
    #[arg(long, short = 'w')]
    pub cwd: Option<String>,
    /// Print the process ID and return instead of following it.
    #[arg(long, short)]
    pub detach: bool,
    /// The command and its arguments; no shell is implied.
    #[arg(last = true, required = true)]
    pub args: Vec<String>,
}

#[derive(Args)]
pub struct ProcessRefArgs {
    tenant: String,
    sandbox: String,
    id: String,
}

impl ProcessRefArgs {
    fn pb(&self) -> pb::ProcessRef {
        pb::ProcessRef {
            tenant: self.tenant.clone(),
            sandbox: self.sandbox.clone(),
            id: self.id.clone(),
        }
    }
}

#[derive(Subcommand)]
pub enum ProcessCmd {
    /// List a sandbox's processes.
    Ps { tenant: String, sandbox: String },
    /// Show one process.
    Get {
        #[command(flatten)]
        process: ProcessRefArgs,
    },
    /// Send a signal.
    Kill {
        #[command(flatten)]
        process: ProcessRefArgs,
        #[arg(long, default_value = "SIGTERM", value_parser = signal)]
        signal: pb::Signal,
    },
    /// Print retained output.
    Logs {
        #[command(flatten)]
        process: ProcessRefArgs,
        /// Read stderr instead of stdout.
        #[arg(long)]
        stderr: bool,
        /// Keep streaming until the process exits.
        #[arg(long, short)]
        follow: bool,
        /// Start at this byte offset.
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },
    /// Wait for the process to exit and exit with its code.
    Wait {
        #[command(flatten)]
        process: ProcessRefArgs,
        /// Give up after this many seconds and print the current state.
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Remove an exited process and its output.
    Rm {
        #[command(flatten)]
        process: ProcessRefArgs,
        /// SIGKILL a live process first.
        #[arg(long)]
        force: bool,
    },
}

/// `SIGTERM`, `TERM` or `term`.
fn signal(s: &str) -> Result<pb::Signal, String> {
    let up = s.to_ascii_uppercase();
    let name = if up.starts_with("SIG") {
        up
    } else {
        format!("SIG{up}")
    };
    pb::Signal::from_str_name(&name)
        .filter(|s| *s != pb::Signal::Unspecified)
        .ok_or_else(|| format!("unknown signal {s:?}"))
}

fn signal_number(s: i32) -> Option<i32> {
    use pb::Signal as S;
    Some(match S::try_from(s).ok()? {
        S::Sighup => 1,
        S::Sigint => 2,
        S::Sigquit => 3,
        S::Sigkill => 9,
        S::Sigusr1 => 10,
        S::Sigusr2 => 12,
        S::Sigterm => 15,
        S::Unspecified => return None,
    })
}

/// The shell's convention: the exit code, 128+n for signal n, 255 when
/// unknown (lost, or the status couldn't be read).
fn exit_status(p: &pb::Process) -> i32 {
    match (p.exit_code, p.signal.and_then(signal_number)) {
        (Some(c), _) => c,
        (None, Some(n)) => 128 + n,
        _ => 255,
    }
}

fn generated_id() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("exec-{:x}{:05x}", t.as_secs(), t.subsec_micros())
}

fn print_process(p: &pb::Process) {
    let end = match (p.exit_code, p.signal) {
        (Some(c), _) => format!(" (exit {c})"),
        (None, Some(s)) => format!(
            " ({})",
            pb::Signal::try_from(s).map_or("signal", |s| s.as_str_name())
        ),
        _ => String::new(),
    };
    let dropped = if p.stdout_dropped + p.stderr_dropped > 0 {
        format!(
            "  dropped out {} err {}",
            human(p.stdout_dropped),
            human(p.stderr_dropped)
        )
    } else {
        String::new()
    };
    println!(
        "{:<24} {:<8}{end} pid {:<6}{dropped}  {}",
        p.id,
        p.state,
        p.pid,
        p.args.join(" ")
    );
}

/// Copy one stream to `out`, marking a truncation inline.
pub(crate) async fn copy_output(
    mut c: ProcessesClient<Channel>,
    process: pb::ProcessRef,
    stream: pb::Stream,
    offset: u64,
    follow: bool,
    mut out: impl AsyncWrite + Unpin,
) -> anyhow::Result<()> {
    use pb::output_chunk::Kind;
    let mut chunks = c
        .read_output(pb::ReadOutputRequest {
            process: Some(process),
            stream: stream as i32,
            offset,
            follow,
        })
        .await?
        .into_inner();
    while let Some(chunk) = chunks.message().await? {
        match chunk.kind {
            Some(Kind::Data(d)) => out.write_all(&d.bytes).await?,
            Some(Kind::Truncated(t)) => {
                let mark = format!("\n[truncated: {} bytes dropped]\n", t.dropped_bytes);
                out.write_all(mark.as_bytes()).await?
            }
            None => {}
        }
        out.flush().await?;
    }
    out.flush().await?;
    Ok(())
}

async fn exec(ch: Channel, a: ExecArgs) -> anyhow::Result<()> {
    let mut c = ProcessesClient::new(ch);
    let p = c
        .start_process(pb::StartProcessRequest {
            tenant: a.tenant,
            sandbox: a.sandbox,
            id: a.id.unwrap_or_else(generated_id),
            args: a.args,
            env: a.env,
            cwd: a.cwd.unwrap_or_default(),
            user: a.user.unwrap_or_default(),
            tty: false,
            stdin: false,
            container: a.container.unwrap_or_default(),
        })
        .await?
        .into_inner();
    if a.detach {
        println!("{}", p.id);
        return Ok(());
    }
    let r = pb::ProcessRef {
        tenant: p.tenant,
        sandbox: p.sandbox,
        id: p.id,
    };
    let out = copy_output(
        c.clone(),
        r.clone(),
        pb::Stream::Stdout,
        0,
        true,
        tokio::io::stdout(),
    );
    let err = copy_output(
        c.clone(),
        r.clone(),
        pb::Stream::Stderr,
        0,
        true,
        tokio::io::stderr(),
    );
    tokio::try_join!(out, err)?;
    let done = c
        .wait_process(pb::WaitProcessRequest {
            process: Some(r),
            timeout_ms: 0,
        })
        .await?
        .into_inner();
    std::process::exit(exit_status(&done));
}

async fn process(ch: Channel, cmd: ProcessCmd) -> anyhow::Result<()> {
    let mut c = ProcessesClient::new(ch);
    match cmd {
        ProcessCmd::Ps { tenant, sandbox } => c
            .list_processes(pb::ListProcessesRequest { tenant, sandbox })
            .await?
            .into_inner()
            .processes
            .iter()
            .for_each(print_process),
        ProcessCmd::Get { process } => {
            print_process(&c.get_process(process.pb()).await?.into_inner())
        }
        ProcessCmd::Kill { process, signal } => print_process(
            &c.signal_process(pb::SignalProcessRequest {
                process: Some(process.pb()),
                signal: signal as i32,
            })
            .await?
            .into_inner(),
        ),
        ProcessCmd::Logs {
            process,
            stderr,
            follow,
            offset,
        } => {
            let (s, out): (_, Box<dyn AsyncWrite + Unpin + Send>) = if stderr {
                (pb::Stream::Stderr, Box::new(tokio::io::stderr()))
            } else {
                (pb::Stream::Stdout, Box::new(tokio::io::stdout()))
            };
            copy_output(c, process.pb(), s, offset, follow, out).await?
        }
        ProcessCmd::Wait { process, timeout } => {
            let p = c
                .wait_process(pb::WaitProcessRequest {
                    process: Some(process.pb()),
                    timeout_ms: timeout.map_or(0, |t| t.saturating_mul(1000).max(1)),
                })
                .await?
                .into_inner();
            print_process(&p);
            if matches!(p.state.as_str(), "starting" | "running") {
                std::process::exit(124);
            }
            std::process::exit(exit_status(&p));
        }
        ProcessCmd::Rm { process, force } => {
            c.delete_process(pb::DeleteProcessRequest {
                process: Some(process.pb()),
                force,
            })
            .await?;
            println!(
                "removed {}.{}.{}",
                process.tenant, process.sandbox, process.id
            );
        }
    }
    Ok(())
}

fn size(s: &str) -> Result<u64, String> {
    tenantd_core::size::parse_size(s).map_err(|e| e.to_string())
}

fn human(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn print_tenant(t: &pb::Tenant) {
    let l = t.limits.unwrap_or_default();
    let mut extra = String::new();
    if let Some(c) = l.cpus {
        extra += &format!("  cpus≤{c}");
    }
    if let Some(m) = l.memory_bytes {
        extra += &format!("  memory≤{}", human(m));
    }
    println!(
        "{:<24} {:<12} project {:<8} {} / {}  {} sandboxes{extra}",
        t.id,
        t.state,
        t.project_id,
        human(t.used_bytes),
        human(l.storage_bytes),
        t.sandbox_count
    );
}

fn print_sandbox(s: &pb::Sandbox) {
    let r = s.resources.unwrap_or_default();
    let exit = s
        .exit_code
        .map(|c| format!(" (exit {c})"))
        .unwrap_or_default();
    println!(
        "{}.{:<20} {:<10}{exit} {:<10} {:<12} {:<6} mem {} cpus {} pids {}  {}",
        s.tenant,
        s.id,
        s.state,
        s.profile,
        s.rootfs,
        s.network,
        human(r.memory_bytes),
        r.cpus,
        r.pids,
        s.image
    );
}

fn print_container(c: &pb::Container) {
    let exit = c
        .exit_code
        .map(|c| format!(" (exit {c})"))
        .unwrap_or_default();
    let mut mounts: Vec<String> = c
        .volumes
        .iter()
        .map(|m| {
            let ro = if m.read_only { ":ro" } else { "" };
            format!("{}={}{ro}", m.path, m.volume)
        })
        .collect();
    if !c.fuse_path.is_empty() {
        mounts.push(format!("{}=fuse", c.fuse_path));
    }
    let mounts = if mounts.is_empty() {
        String::new()
    } else {
        format!("  {}", mounts.join(" "))
    };
    println!(
        "{}.{}.{:<20} {}{exit}{mounts}",
        c.tenant, c.sandbox, c.id, c.state
    );
}

fn print_volume(v: &pb::Volume) {
    println!(
        "{}.{:<20} {:<9} {}:{} {:04o}  {}",
        v.tenant, v.id, v.state, v.uid, v.gid, v.mode, v.path
    );
}

/// Run `server` with the FUSE connection as fd 3, optionally start the
/// container, and exit with the server's code.
async fn attach_fuse(
    mut k: ContainersClient<Channel>,
    r: pb::ContainerRef,
    socket: PathBuf,
    start: bool,
    server: Vec<String>,
) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let fd = {
        let (s, t, sb, c) = (
            socket.clone(),
            r.tenant.clone(),
            r.sandbox.clone(),
            r.id.clone(),
        );
        tokio::task::spawn_blocking(move || tenantd_client::fuse::attach_fuse(&s, &t, &sb, &c))
            .await?
            .with_context(|| format!("attaching via {}", socket.display()))?
    };
    let raw = fd.as_raw_fd();
    let mut cmd = std::process::Command::new(&server[0]);
    cmd.args(&server[1..]).env("TENANTD_FUSE_FD", "3");
    // SAFETY: dup2 is async-signal-safe; it runs between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("running {}", server[0]))?;
    drop(fd);
    if start && let Err(e) = k.start_container(r).await {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.into());
    }
    let status = tokio::task::spawn_blocking(move || child.wait()).await??;
    use std::os::unix::process::ExitStatusExt;
    std::process::exit(
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
    );
}

fn event_json(e: pb::Event) -> serde_json::Value {
    use pb::event::Kind;
    use serde_json::json;
    let body = match e.kind {
        Some(Kind::SandboxExited(x)) => {
            json!({"type": "sandbox_exited", "tenant": x.tenant, "id": x.id, "exit_code": x.exit_code})
        }
        Some(Kind::SandboxOom(x)) => json!({"type": "sandbox_oom", "tenant": x.tenant, "id": x.id}),
        Some(Kind::ProcessExited(x)) => {
            let signal = x
                .signal
                .map(|s| pb::Signal::try_from(s).map_or("SIGNAL_UNSPECIFIED", |s| s.as_str_name()));
            json!({"type": "process_exited", "tenant": x.tenant, "sandbox": x.sandbox, "id": x.id,
                   "exit_code": x.exit_code, "signal": signal,
                   "stdout_dropped": x.stdout_dropped, "stderr_dropped": x.stderr_dropped})
        }
        Some(Kind::ContainerExited(x)) => {
            json!({"type": "container_exited", "tenant": x.tenant, "sandbox": x.sandbox, "id": x.id,
                   "exit_code": x.exit_code})
        }
        Some(Kind::QuotaExceeded(x)) => {
            json!({"type": "quota_exceeded", "tenant": x.tenant, "used_bytes": x.used_bytes, "limit_bytes": x.limit_bytes})
        }
        Some(Kind::Reconcile(x)) => {
            json!({"type": "reconcile", "action": x.action, "target": x.target, "detail": x.detail})
        }
        None => json!({"type": "unknown"}),
    };
    let mut v = body;
    v["time"] = e.time.into();
    v
}

pub async fn run(cmd: ClientCmd) -> anyhow::Result<()> {
    let socket = match &cmd {
        ClientCmd::Tenant { conn, .. }
        | ClientCmd::Sandbox { conn, .. }
        | ClientCmd::Container { conn, .. }
        | ClientCmd::Volume { conn, .. }
        | ClientCmd::Exec { conn, .. }
        | ClientCmd::Process { conn, .. }
        | ClientCmd::Health { conn }
        | ClientCmd::Events { conn } => &conn.socket,
    };
    let ch = tenantd_client::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    match cmd {
        ClientCmd::Tenant { cmd: c, .. } => {
            let mut t = TenantsClient::new(ch);
            match c {
                TenantCmd::Create { id, limits } => print_tenant(
                    &t.create_tenant(pb::CreateTenantRequest {
                        id,
                        limits: limits.pb(),
                    })
                    .await?
                    .into_inner(),
                ),
                TenantCmd::Update { id, limits } => print_tenant(
                    &t.update_tenant(pb::UpdateTenantRequest {
                        id,
                        limits: limits.pb(),
                    })
                    .await?
                    .into_inner(),
                ),
                TenantCmd::Get { id } => print_tenant(
                    &t.get_tenant(pb::GetTenantRequest { id })
                        .await?
                        .into_inner(),
                ),
                TenantCmd::List => t
                    .list_tenants(pb::ListTenantsRequest {})
                    .await?
                    .into_inner()
                    .tenants
                    .iter()
                    .for_each(print_tenant),
                TenantCmd::Delete { id, force } => {
                    t.delete_tenant(pb::DeleteTenantRequest {
                        id: id.clone(),
                        force,
                    })
                    .await?;
                    println!("deleted {id}");
                }
            }
        }
        ClientCmd::Sandbox { cmd: c, .. } => {
            let mut s = SandboxesClient::new(ch);
            let r = |tenant, id| pb::SandboxRef { tenant, id };
            match c {
                SandboxCmd::Create {
                    tenant,
                    id,
                    profile,
                    image,
                    memory,
                    cpus,
                    pids,
                    size,
                } => {
                    let overrides = Some(pb::Overrides {
                        memory_bytes: memory,
                        cpus,
                        pids,
                        size_bytes: size,
                    });
                    let req = pb::CreateSandboxRequest {
                        tenant,
                        id,
                        profile,
                        image,
                        overrides,
                    };
                    print_sandbox(&s.create_sandbox(req).await?.into_inner())
                }
                SandboxCmd::Get { tenant, id } => {
                    print_sandbox(&s.get_sandbox(r(tenant, id)).await?.into_inner())
                }
                SandboxCmd::List { tenant } => s
                    .list_sandboxes(pb::ListSandboxesRequest { tenant })
                    .await?
                    .into_inner()
                    .sandboxes
                    .iter()
                    .for_each(print_sandbox),
                SandboxCmd::Stop { tenant, id } => {
                    print_sandbox(&s.stop_sandbox(r(tenant, id)).await?.into_inner())
                }
                SandboxCmd::Start { tenant, id } => {
                    print_sandbox(&s.start_sandbox(r(tenant, id)).await?.into_inner())
                }
                SandboxCmd::Destroy { tenant, id } => {
                    s.destroy_sandbox(r(tenant.clone(), id.clone())).await?;
                    println!("destroyed {tenant}.{id}");
                }
            }
        }
        ClientCmd::Container { cmd: c, .. } => {
            let mut k = ContainersClient::new(ch);
            let r = |tenant, sandbox, id| pb::ContainerRef {
                tenant,
                sandbox,
                id,
            };
            match c {
                ContainerCmd::Create {
                    tenant,
                    sandbox,
                    id,
                    volumes,
                    fuse,
                    args,
                } => {
                    let req = pb::CreateContainerRequest {
                        tenant,
                        sandbox,
                        id,
                        args,
                        volumes: volumes.into_iter().collect(),
                        fuse,
                    };
                    print_container(&k.create_container(req).await?.into_inner())
                }
                ContainerCmd::Start {
                    tenant,
                    sandbox,
                    id,
                } => print_container(
                    &k.start_container(r(tenant, sandbox, id))
                        .await?
                        .into_inner(),
                ),
                ContainerCmd::AttachFuse {
                    tenant,
                    sandbox,
                    id,
                    fuse_socket,
                    start,
                    server,
                } => attach_fuse(k, r(tenant, sandbox, id), fuse_socket, start, server).await?,
                ContainerCmd::Get {
                    tenant,
                    sandbox,
                    id,
                } => print_container(&k.get_container(r(tenant, sandbox, id)).await?.into_inner()),
                ContainerCmd::List { tenant, sandbox } => k
                    .list_containers(pb::ListContainersRequest { tenant, sandbox })
                    .await?
                    .into_inner()
                    .containers
                    .iter()
                    .for_each(print_container),
                ContainerCmd::Rm {
                    tenant,
                    sandbox,
                    id,
                } => {
                    k.delete_container(r(tenant.clone(), sandbox.clone(), id.clone()))
                        .await?;
                    println!("deleted {tenant}.{sandbox}.{id}");
                }
            }
        }
        ClientCmd::Volume { cmd: c, .. } => {
            let mut v = VolumesClient::new(ch);
            let r = |tenant, id| pb::VolumeRef { tenant, id };
            match c {
                VolumeCmd::Create {
                    tenant,
                    id,
                    uid,
                    gid,
                    mode,
                } => print_volume(
                    &v.create_volume(pb::CreateVolumeRequest {
                        tenant,
                        id,
                        uid,
                        gid,
                        mode,
                    })
                    .await?
                    .into_inner(),
                ),
                VolumeCmd::Get { tenant, id } => {
                    print_volume(&v.get_volume(r(tenant, id)).await?.into_inner())
                }
                VolumeCmd::List { tenant } => v
                    .list_volumes(pb::ListVolumesRequest { tenant })
                    .await?
                    .into_inner()
                    .volumes
                    .iter()
                    .for_each(print_volume),
                VolumeCmd::Rm { tenant, id } => {
                    v.delete_volume(r(tenant.clone(), id.clone())).await?;
                    println!("deleted {tenant}.{id}");
                }
                VolumeCmd::Prune {
                    tenant,
                    id,
                    prefix,
                    older_than,
                } => {
                    let rep = v
                        .prune_volume(pb::PruneVolumeRequest {
                            volume: Some(r(tenant, id)),
                            path_prefix: prefix,
                            older_than_secs: older_than,
                        })
                        .await?
                        .into_inner();
                    println!(
                        "removed {} entries, {}",
                        rep.removed_entries,
                        human(rep.removed_bytes)
                    );
                }
            }
        }
        ClientCmd::Exec { args, .. } => exec(ch, args).await?,
        ClientCmd::Process { cmd, .. } => process(ch, cmd).await?,
        ClientCmd::Health { .. } => {
            let h = SystemClient::new(ch)
                .health(pb::HealthRequest {})
                .await?
                .into_inner();
            println!("enforcing: {}", h.enforcing);
            for c in h.components {
                println!(
                    "  {:<8} {}{}",
                    c.name,
                    if c.ok { "ok" } else { "FAIL" },
                    if c.message.is_empty() {
                        String::new()
                    } else {
                        format!("  {}", c.message)
                    }
                );
            }
            if !h.enforcing {
                std::process::exit(2);
            }
        }
        ClientCmd::Events { .. } => {
            let mut stream = SystemClient::new(ch)
                .watch_events(pb::WatchEventsRequest {})
                .await?
                .into_inner();
            while let Some(e) = stream.message().await? {
                println!("{}", event_json(e));
            }
        }
    }
    Ok(())
}

/// Print a command error, gRPC statuses as `error: <code>: <message>`.
pub fn report(e: anyhow::Error) -> ExitCode {
    match e.downcast_ref::<tonic::Status>() {
        Some(s) => eprintln!(
            "error: {}: {}",
            format!("{:?}", s.code()).to_lowercase(),
            s.message()
        ),
        None => eprintln!("error: {e:#}"),
    }
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_sizes() {
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(512), "512 B");
    }

    #[test]
    fn signals_and_exit_codes() {
        assert_eq!(signal("SIGTERM"), Ok(pb::Signal::Sigterm));
        assert_eq!(signal("kill"), Ok(pb::Signal::Sigkill));
        assert!(signal("SEGV").is_err());
        assert!(signal("SIGNAL_UNSPECIFIED").is_err());
        let p = |exit_code, signal| pb::Process {
            exit_code,
            signal,
            ..Default::default()
        };
        assert_eq!(exit_status(&p(Some(3), None)), 3);
        assert_eq!(exit_status(&p(None, Some(pb::Signal::Sigkill as i32))), 137);
        assert_eq!(
            exit_status(&p(None, Some(pb::Signal::Unspecified as i32))),
            255
        );
        assert_eq!(exit_status(&p(None, None)), 255);
        let id = generated_id();
        assert!(
            tenantd_core::id::validate_id("process", &id).is_ok(),
            "{id}"
        );
    }
}
