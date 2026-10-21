# tenantd-client

Rust gRPC client for [tenantd](https://github.com/panitdev/tenantd), a per-host
daemon that runs multi-tenant sandboxes on gVisor. It connects over tenantd's
Unix socket and exposes the generated `tenantd.v1` types and service clients.

```rust,no_run
# async fn f() -> Result<(), Box<dyn std::error::Error>> {
let ch = tenantd_client::connect("/run/tenantd/api.sock").await?;
let mut tenants = tenantd_client::TenantsClient::new(ch);
let t = tenants
    .get_tenant(tenantd_client::pb::GetTenantRequest { id: "acme".into() })
    .await?;
# Ok(()) }
```

The client and daemon share one version; use the client release that matches
your tenantd.

Licensed under Apache-2.0.
