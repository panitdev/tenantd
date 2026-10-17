# tenantd

A per-host daemon that runs multi-tenant sandboxes on gVisor with exact,
aggregate storage quotas.

tenantd holds the root-level permissions a sandbox platform needs and exposes
only a fixed set of operations over a Unix socket. Callers create tenants,
start sandboxes from operator-defined profiles, and run commands inside them.
They never pass mounts, capabilities, host paths or raw runtime options.

## Install

> [!NOTE]
> There is no stable release yet. Packages are built from `main` and
> published as the [`edge`](https://github.com/panitdev/tenantd/releases/tag/edge)
> prerelease. Expect breaking changes.

Requirements:

- Linux 5.14 or newer, x86_64 or aarch64
- An XFS filesystem mounted with `prjquota` for the storage root

The packages and the tarball bundle a pinned gVisor `runsc` and the CNI
plugins tenantd needs, so you don't install them separately.

### Debian / Ubuntu

```sh
gh release download edge -R panitdev/tenantd -p '*amd64.deb'
sudo apt install ./tenantd_*_amd64.deb
```

### Fedora / RHEL / Rocky

```sh
gh release download edge -R panitdev/tenantd -p '*x86_64.rpm'
sudo dnf install ./tenantd-*.x86_64.rpm
```

### Arch Linux

```sh
gh release download edge -R panitdev/tenantd -p '*.pkg.tar.zst'
sudo pacman -U ./tenantd-*.pkg.tar.zst
```

Packages install a systemd unit. Edit `/etc/tenantd/tenantd.toml`, then run
`sudo systemctl enable --now tenantd`.

### Any distro (tarball)

```sh
gh release download edge -R panitdev/tenantd -p '*linux-x86_64.tar.gz'
tar -xzf tenantd-*-linux-x86_64.tar.gz && cd tenantd-*-linux-x86_64
sudo install -D tenantd.toml /etc/tenantd/tenantd.toml   # then edit it
sudo ./tenantd service install -c /etc/tenantd/tenantd.toml
```

`service install` writes a systemd unit for the binary and config, then
enables and starts it. `sudo tenantd service uninstall` removes it.

Every edge build is also published under a pinned `edge-<sha>` tag that never
moves. `SHA256SUMS` is signed with cosign (keyless):

```sh
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'https://github.com/panitdev/tenantd/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c --ignore-missing SHA256SUMS
```

### From source

```sh
cargo build --release
```

You then install `runsc` ([gVisor](https://gvisor.dev/docs/user_guide/install/))
and the CNI `bridge`, `host-local` and `firewall` plugins yourself.

tenantd fails closed. It refuses to start if project quota isn't enforced on
the storage root or if `runsc` is missing or outside the configured version
range. If either check fails later, it rejects new creates until the check
passes again.

## Quick start

```sh
tenantd tenant create acme --storage 10g --memory 8g --cpus 4
tenantd sandbox create acme box1 --profile default --image ghcr.io/example/app:1

tenantd exec acme box1 -- sh -c 'make test'     # streams output, exits with its code
tenantd exec -d --id build1 acme box1 -- make   # detached
tenantd process logs acme box1 build1 -f

tenantd sandbox stop acme box1                  # writable layer is kept
tenantd sandbox start acme box1
```

The CLI talks to the running daemon over `/run/tenantd/api.sock` (override
with `--socket` or `TENANTD_SOCKET`). Any UID listed in the config can use
it. Run `tenantd --help` for the full command list, including `process ps`,
`process kill`, `process wait`, `events` and `health`.

## How it works

- **Storage.** Each tenant is an XFS project with one quota. A sandbox's
  writable root is a host overlayfs whose upper directory sits inside that
  project, so every write counts against the quota exactly and deletes free
  space immediately. Process output files are stored there too.
- **Runtime.** tenantd builds OCI bundles and drives `runsc` directly. Docker
  is not involved. Images are pulled by digest, verified, and cached as shared
  layers.
- **Policy.** Everything a caller can do is defined by a profile in the
  operator's config: allowed images, resources, network and exec rights. A
  denial returns `PERMISSION_DENIED` naming the rule, for example
  `profiles.default.images`.
- **Crash safety.** Multi-step operations record their intent in SQLite before
  touching the host, and every host step is idempotent. A periodic reconcile
  finishes or rolls back interrupted operations and cleans up anything left
  behind.

Interactive processes (tty, stdin, attach) are not supported yet.

## Configuration

[`examples/tenantd.toml`](examples/tenantd.toml) is the annotated reference
config. The gRPC API is defined in [`proto/tenantd.proto`](proto/tenantd.proto).
To reload the config, send `SIGHUP`. Running sandboxes and processes are not
affected.

## Development

```sh
cargo test --workspace                                    # no privileges needed
unshare -rmn cargo test -p tenantd-layer -p tenantd-net -- --ignored
cargo test -p tenantd-image -- --ignored pulls_a_real_image   # needs network
sudo TENANTD_XFS_TEST_ROOT=/mnt/xfs cargo test -p tenantd-storage-xfs -- --ignored
```

The ignored tests use real overlay mounts, network namespaces, registries and
XFS quotas. `crates/tenantd-testkit` runs the whole service against fake
backends, including crash-injection scenarios.
