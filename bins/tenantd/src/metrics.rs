//! Prometheus text on a second socket or a localhost port: per-tenant bytes
//! used and limit, sandbox and process counts by state, operation latency.

use std::sync::Arc;
use std::time::Duration;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use tenantd_core::Tenantd;
use tenantd_core::model::{ProcessState, SandboxState, TenantState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TenantLabel {
    tenant: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct StateLabel {
    state: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OpLabel {
    op: String,
    code: String,
}

fn latency_histogram() -> Histogram {
    Histogram::new(exponential_buckets(0.001, 2.0, 16))
}

pub struct Metrics {
    registry: Registry,
    used: Family<TenantLabel, Gauge>,
    limit: Family<TenantLabel, Gauge>,
    sandboxes: Family<StateLabel, Gauge>,
    processes: Family<StateLabel, Gauge>,
    ops: Family<OpLabel, Histogram, fn() -> Histogram>,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("tenantd");
        let used = Family::<TenantLabel, Gauge>::default();
        let limit = Family::<TenantLabel, Gauge>::default();
        let sandboxes = Family::<StateLabel, Gauge>::default();
        let processes = Family::<StateLabel, Gauge>::default();
        let ops = Family::<OpLabel, Histogram, fn() -> Histogram>::new_with_constructor(
            latency_histogram,
        );
        registry.register(
            "tenant_storage_used_bytes",
            "Bytes charged to the tenant's project quota",
            used.clone(),
        );
        registry.register(
            "tenant_storage_limit_bytes",
            "The tenant's storage quota",
            limit.clone(),
        );
        registry.register("sandboxes", "Sandboxes by state", sandboxes.clone());
        registry.register(
            "processes",
            "Processes tenantd started, by state",
            processes.clone(),
        );
        registry.register(
            "operation_duration_seconds",
            "API operation latency",
            ops.clone(),
        );
        Self {
            registry,
            used,
            limit,
            sandboxes,
            processes,
            ops,
        }
    }

    pub fn observe(&self, op: &str, code: tonic::Code, d: Duration) {
        self.ops
            .get_or_create(&OpLabel {
                op: op.into(),
                code: format!("{code:?}"),
            })
            .observe(d.as_secs_f64());
    }

    async fn refresh(&self, t: &Tenantd) {
        self.used.clear();
        self.limit.clear();
        if let Ok(tenants) = t.list_tenants().await {
            for rec in tenants
                .into_iter()
                .filter(|r| r.state == TenantState::Ready)
            {
                let l = TenantLabel {
                    tenant: rec.id.to_string(),
                };
                self.limit.get_or_create(&l).set(rec.limits.storage as i64);
                if let Ok(info) = t.get_tenant(&rec.id).await
                    && let Some(u) = info.usage
                {
                    self.used.get_or_create(&l).set(u.used as i64);
                }
            }
        }
        if let Ok(all) = t.list_all_sandboxes().await {
            for s in SandboxState::ALL {
                let n = all.iter().filter(|r| r.state == s).count();
                self.sandboxes
                    .get_or_create(&StateLabel {
                        state: s.as_str().into(),
                    })
                    .set(n as i64);
            }
        }
        if let Ok(all) = t.list_all_processes().await {
            for s in ProcessState::ALL {
                let n = all.iter().filter(|r| r.state == s).count();
                self.processes
                    .get_or_create(&StateLabel {
                        state: s.as_str().into(),
                    })
                    .set(n as i64);
            }
        }
    }

    pub async fn render(&self, t: &Tenantd) -> String {
        self.refresh(t).await;
        let mut out = String::new();
        if let Err(e) = encode(&mut out, &self.registry) {
            warn!(error = %e, "encoding metrics");
        }
        out
    }
}

async fn respond<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    m: &Metrics,
    t: &Tenantd,
) {
    let mut buf = vec![0u8; 4096];
    let mut n = 0;
    while n < buf.len() {
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf[n..])).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
            Ok(Ok(k)) => n += k,
        }
        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let (status, ctype, body) = if req.starts_with("GET /metrics ") || req.starts_with("GET / ") {
        (
            "200 OK",
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
            m.render(t).await,
        )
    } else {
        ("404 Not Found", "text/plain", "not found\n".to_string())
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes()).await;
    let _ = s.write_all(body.as_bytes()).await;
}

/// Serve `GET /metrics` on `addr`: `host:port`, or an absolute socket path.
pub async fn serve(addr: String, m: Arc<Metrics>, t: Arc<Tenantd>) -> anyhow::Result<()> {
    if addr.starts_with('/') {
        let _ = std::fs::remove_file(&addr);
        let l = tokio::net::UnixListener::bind(&addr)?;
        loop {
            let (s, _) = l.accept().await?;
            let (m, t) = (m.clone(), t.clone());
            tokio::spawn(async move { respond(s, &m, &t).await });
        }
    } else {
        let l = tokio::net::TcpListener::bind(&addr).await?;
        debug!(addr, "metrics listening");
        loop {
            let (s, _) = l.accept().await?;
            let (m, t) = (m.clone(), t.clone());
            tokio::spawn(async move { respond(s, &m, &t).await });
        }
    }
}
