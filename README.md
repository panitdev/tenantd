# tenantd

A small Rust daemon, one per host, that holds the root-level permissions a
sandbox platform needs and exposes only a fixed set of operations over a Unix
socket. It creates tenants with an aggregate storage quota (XFS project quota)
and runs their sandboxes by calling gVisor's `runsc` directly, with no Docker.
Each sandbox's writable root is a host overlayfs whose upper directory sits
inside the tenant's quota, so every write is a real file the quota counts
exactly, and deletes free space at once.

The rule: generic over backends, narrow over operations. Callers never pass
mounts, capabilities, `privileged`, raw annotations or host paths; everything
a caller can do is a profile in the operator's config.

## Layout

```
proto/tenantd.proto              gRPC API (Tenants, Sandboxes, System)
crates/tenantd-core              model, policy, ID validation, backend traits, orchestration, reconcile
crates/tenantd-storage-xfs       FS_IOC_FSSETXATTR + quotactl_fd, thin unsafe module
crates/tenantd-layer             host-overlay, memory, read-only writable layers
crates/tenantd-runtime-runsc     OCI bundles, runsc create/start/kill/wait/delete
crates/tenantd-image             registry pull by digest, digest checks, unpack + whiteouts, GC
crates/tenantd-net               netns lifecycle, CNI bridge + firewall
crates/tenantd-state             SQLite schema + migrations
crates/tenantd-client            generated gRPC client + Unix socket connector
crates/tenantd-testkit           fake backends; service-level tests in tests/service.rs
bins/tenantd                     daemon: config, gRPC on UDS, SO_PEERCRED, metrics, SIGHUP
bins/tenantctl                   operator CLI over the same socket
examples/tenantd.toml            the reference config
deploy/tenantd.service           systemd unit
```

## Build and run

```sh
cargo build --release                      # target/release/{tenantd,tenantctl}
tenantd --check-config -c examples/tenantd.toml
sudo tenantd -c /etc/tenantd/tenantd.toml  # or install deploy/tenantd.service
```

For a single-file install, build with `--target x86_64-unknown-linux-musl`
(`aws-lc-rs`, pulled in by the registry client's rustls, needs `cmake` and a C
compiler for that target).

Host requirements: the storage root on XFS mounted with `prjquota`; Linux
5.14+ (`quotactl_fd`); `runsc` installed separately (pin a range with
`runtime.min_version` / `max_version`); for `egress` profiles the CNI
`bridge`, `host-local` and `firewall` plugins in `network.cni_bin`.

tenantd fails closed: it exits non-zero at startup if project quota isn't
enforced on the storage root or `runsc` is missing or out of range, and
refuses creates while either check fails at runtime (`Health` reports it).

```sh
tenantctl tenant create acme --storage 10g --memory 8g --cpus 4
tenantctl sandbox create acme box1 --profile default --image ghcr.io/example/app:1
tenantctl sandbox stop acme box1      # host-overlay layer is kept
tenantctl sandbox start acme box1
tenantctl events                      # JSON lines: exits, OOM, quota, reconcile
tenantctl health
```

Policy denials come back as `PERMISSION_DENIED` naming the rule (also in the
`x-tenantd-rule` response header), e.g. `profiles.default.images` or
`tenant.acme.memory`.

## Crash safety

Every multi-step operation writes its intent (`provisioning`, `creating`,
`starting`, `stopping`, `destroying`) to SQLite before touching the host, and
every host step is idempotent. On startup and every `reconcile.interval_secs`
reconcile compares the database, the tenant directories, and tenantd's runsc
containers, overlay mounts and namespaces, then finishes or rolls back stuck
operations, marks sandboxes whose container vanished as `exited`, removes
containers and namespaces with no row, re-applies lost project IDs and drifted
limits, and garbage-collects unreferenced image layers. Orphan directories are
only reported unless `reconcile.delete_orphans = true`.

## Tests

```sh
cargo test --workspace                    # 50 tests, no privileges needed

# Real overlay mounts and network namespaces, unprivileged in a user namespace:
unshare -rmn cargo test -p tenantd-layer -p tenantd-net -- --ignored

# Real registry pull (network):
cargo test -p tenantd-image -- --ignored pulls_a_real_image

# Real XFS project quota (root, XFS mounted with prjquota):
sudo TENANTD_XFS_TEST_ROOT=/mnt/xfs cargo test -p tenantd-storage-xfs -- --ignored
```

`tenantd-testkit/tests/service.rs` drives the whole service against fakes,
including crash injection: a step fails *and* its rollback fails, the service
is rebuilt over the same state and host, and reconcile must finish or undo
the operation.

## Status against the milestones

| Phase | State |
| --- | --- |
| M0 spike (runsc `--overlay2=none` on host overlay in an XFS project) | Not run here: needs a host with runsc and an XFS `prjquota` volume. Do this first; it gates the design. |
| M1 storage, tenant API and state, tenantctl | Implemented. XFS ioctl/quotactl struct layouts checked against kernel headers; the live quota test needs an XFS host. |
| M2 runsc-direct, image cache, CNI, profiles and policy | Implemented. Image pull/unpack tested against Docker Hub; overlay and netns tested in a user namespace; runsc invocation and CNI egress not yet run against real binaries. |
| M3 reconcile, events, metrics, crash-injection tests | Implemented and tested with fakes. |

Open items carried from the proposal: whether shared image layers need their
own limit; tenant-wide CPU/memory is admission-checked (no parent cgroup);
registry auth is anonymous only; OOM detection reads the sandbox cgroup's
`memory.events` (`/sys/fs/cgroup/tenantd/<tenant>/<sandbox>`), which depends on
runsc creating that cgroup path — confirm in M0/M2.
