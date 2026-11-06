# tenantd

A per-host daemon that runs multi-tenant sandboxes on gVisor with exact,
aggregate storage quotas.

tenantd holds the root-level permissions a sandbox platform needs and exposes
only a fixed set of operations over a Unix socket, and optionally over the
network with mutual TLS. Callers create tenants,
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
tenantd container create acme box1 s1 -- sleep infinity  # own root, same sandbox
tenantd exec --container s1 acme box1 -- make test
tenantd process logs acme box1 build1 -f
tenantd file put --parents acme box1 s1 /work/input.json < input.json
tenantd file cat acme box1 s1 /work/result.json

tenantd volume create acme ws --uid 1000 --gid 1000 --mode 1777
tenantd container create acme box1 s2 --volume workspace=ws -- sleep infinity
tenantd volume prune acme ws --prefix s-1 --older-than 0   # drop a session's files

tenantd container create acme box1 s3 --fuse -- sleep infinity    # waits "created"
tenantd container serve-fuse acme box1 s3 --dir ./data --start    # export ./data to it

tenantd sandbox stop acme box1                  # writable layer is kept
tenantd sandbox start acme box1
```

The CLI talks to the running daemon over `/run/tenantd/api.sock` (override
with `--socket` or `TENANTD_SOCKET`). Any UID listed in the config can use
it. Run `tenantd --help` for the full command list, including `process ps`,
`process kill`, `process wait`, `events` and `health`.

### Network mode (mTLS)

To reach tenantd from another machine, such as a control plane or a FUSE
server, add a `[server.tls]` listener. It serves the same API as the socket,
which keeps working next to it:

```toml
[server.tls]
listen = "0.0.0.0:7443"
cert = "/etc/tenantd/tls/server.pem"         # chain, leaf first
key = "/etc/tenantd/tls/server.key"
client_ca = "/etc/tenantd/tls/clients-ca.pem"
clients = ["cp-1.internal", "cp-2.internal"]  # client subjectAltNames
```

Every connection must present a client certificate that chains to
`client_ca` *and* carries one of `clients` as a DNS or IP subjectAltName.
Both checks happen during the handshake, so other peers never reach the
API. Use a CA that issues only tenantd clients. Sessions are never resumed,
so each connection is checked against the current list. `SIGHUP` re-reads
the certificates, key, CA and `clients` for new connections; open
connections are kept. Changing `listen` needs a restart.

```sh
tenantd health --endpoint tenantd-1.internal:7443 \
  --tls-ca ca.pem --tls-cert cp-1.pem --tls-key cp-1.key
```

The flags also read `TENANTD_ENDPOINT`, `TENANTD_TLS_CA`, `TENANTD_TLS_CERT`
and `TENANTD_TLS_KEY`. `--tls-server-name` sets the name the daemon's
certificate must carry when it isn't the endpoint's host. In Rust, enable
the `tls` feature of `tenantd-client` and use `tenantd_client::tls::connect`.

## How it works

- **Storage.** Each tenant is an XFS project with one quota. A sandbox's
  writable root is a host overlayfs whose upper directory sits inside that
  project, so every write counts against the quota exactly and deletes free
  space immediately. Process output files are stored there too.
- **Runtime.** tenantd builds OCI bundles and drives `runsc` directly. Docker
  is not involved. Images are pulled by digest, verified, and cached as shared
  layers.
- **Containers.** A sandbox can run more containers from its image, each
  with its own writable root in the tenant's quota but sharing the
  sandbox's gVisor kernel, network and limits, so many of them cost one
  sandbox. runsc adds them to the running sandbox; they are never
  restarted, and stopping the sandbox ends them.
- **Files.** Callers read and write a running container's files through
  the `Files` service (stat, list, read, write, rename, remove) rather than
  by exec'ing a binary from the image and parsing its output. By default
  each call execs tenantd's own small helper in the container (tenantd's
  binary, bound read-only at `/dev/.tenantd-files` in every container), as
  the image user or another of the profile's `exec.users`. So it sees just
  what the container sees, `/tmp`, volumes and FUSE included, on any
  layer, and costs one `runsc exec` per call. A container created with
  `--host-file-access` is served from the host instead (`openat2` with
  `RESOLVE_IN_ROOT`, so symlinks and `..` still mean what they mean to the
  container), much faster per call. The price is runsc's
  `--file-access=shared` for that container, which revalidates every file
  lookup in it. A write goes to a temporary file that replaces the target
  only once the whole body has arrived. It needs the profile's exec rights.
- **Volumes.** A volume is a directory in the tenant's project, so it
  counts against the same quota, and the only state that outlives a
  container. A container mounts volumes only through the slots its profile
  declares (`[profiles.<name>.volumes.<slot>]`), bound when it is created.
  Callers on the host can use a volume at its path; its root takes the
  owner (root or a caller UID) and mode it was created with. Prune removes
  what under a path hasn't been used for a while, never following symlinks.
- **FUSE.** A container can ask for its profile's FUSE slot. tenantd
  mounts a FUSE filesystem on the host and bind-mounts it into the
  container, where gVisor serves it like any host directory. The caller
  runs the filesystem, over the same API as everything else: it opens
  `Containers.ServeFuse` and answers path-based requests (stat, read dir,
  read, write, rename, ...), then starts the container. tenantd speaks the
  kernel protocol itself, caches what the server lets it (attributes,
  listings, absent names, the start of small files) and runs no filesystem
  code, so a server can be on another machine. A server that restarts
  attaches again to the same mount; requests wait while none is attached.
  `tenantd container serve-fuse --dir` exports a host directory; the
  protocol is in [`proto/tenantd.proto`](proto/tenantd.proto) and the Rust
  client in `tenantd-client`.
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

The ignored tests use real overlay and FUSE mounts, network namespaces,
registries and XFS quotas. `crates/tenantd-testkit` runs the whole service against fake
backends, including crash-injection scenarios.
