# tenantd-client

Rust gRPC client for [tenantd](https://github.com/panitdev/tenantd), a per-host
daemon that runs multi-tenant sandboxes on gVisor. It connects over tenantd's
Unix socket, or over the network with mutual TLS, and exposes the generated
`tenantd.v1` types and service clients.

```rust,no_run
# async fn f() -> Result<(), Box<dyn std::error::Error>> {
let ch = tenantd_client::connect("/run/tenantd/api.sock").await?;
let mut tenants = tenantd_client::TenantsClient::new(ch);
let t = tenants
    .get_tenant(tenantd_client::pb::GetTenantRequest { id: "acme".into() })
    .await?;
# Ok(()) }
```

With the `tls` feature, connect to a daemon's `[server.tls]` listener:

```rust,ignore
use tenantd_client::tls::ClientTls;
let tls = ClientTls::from_pem_files("ca.pem", "client.pem", "client.key")?;
let ch = tenantd_client::tls::connect("tenantd-1.internal:7443", None, &tls).await?;
```

`tenantd_client::files` wraps the `Files` service: read, write (from bytes
or an `AsyncRead`), stat, list, rename and remove files in a running
container's root, with filesystem errors as errno values.

The client and daemon share one version; use the client release that matches
your tenantd.

Licensed under Apache-2.0.
