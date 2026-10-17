//! gRPC types for tenantd plus a Unix-socket connector for control planes.
//!
//! ```no_run
//! # async fn f() -> Result<(), Box<dyn std::error::Error>> {
//! let ch = tenantd_client::connect("/run/tenantd/api.sock").await?;
//! let mut tenants = tenantd_client::TenantsClient::new(ch);
//! let t = tenants.get_tenant(tenantd_client::pb::GetTenantRequest { id: "acme".into() }).await?;
//! # Ok(()) }
//! ```

use std::path::PathBuf;

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};

pub mod pb {
    tonic::include_proto!("tenantd.v1");
}

pub use pb::processes_client::ProcessesClient;
pub use pb::sandboxes_client::SandboxesClient;
pub use pb::system_client::SystemClient;
pub use pb::tenants_client::TenantsClient;

/// Connect to tenantd's Unix socket. The URI is a placeholder; every
/// connection goes to `path`.
pub async fn connect(path: impl Into<PathBuf>) -> Result<Channel, tonic::transport::Error> {
    let path = path.into();
    Endpoint::from_static("http://tenantd.local")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                Ok::<_, std::io::Error>(TokioIo::new(tokio::net::UnixStream::connect(path).await?))
            }
        }))
        .await
}
