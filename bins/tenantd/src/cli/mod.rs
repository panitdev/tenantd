//! Operator commands over a running daemon's API socket. These never read
//! the daemon config, open the state DB or need root; only socket access.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Subcommand};
use tenantd_client::pb;
use tenantd_client::{SandboxesClient, SystemClient, TenantsClient};

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

fn event_json(e: pb::Event) -> serde_json::Value {
    use pb::event::Kind;
    use serde_json::json;
    let body = match e.kind {
        Some(Kind::SandboxExited(x)) => {
            json!({"type": "sandbox_exited", "tenant": x.tenant, "id": x.id, "exit_code": x.exit_code})
        }
        Some(Kind::SandboxOom(x)) => json!({"type": "sandbox_oom", "tenant": x.tenant, "id": x.id}),
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
}
