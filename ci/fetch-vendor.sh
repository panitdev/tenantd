#!/usr/bin/env bash
# Download the pinned gVisor bundle and CNI plugins for one architecture and
# verify their published checksums.
# Usage: fetch-vendor.sh <x86_64|aarch64> <outdir>
# Reads RUNSC_VERSION and CNI_VERSION from the environment (ci/versions.env).
#
# Output layout:
#   <outdir>/gvisor/runsc             the runsc binary
#   <outdir>/gvisor/gvisor-bin/...    helpers shipped alongside it
#   <outdir>/cni/{bridge,firewall,host-local,loopback}
set -euo pipefail

arch=${1:?arch}
out=${2:?outdir}
: "${RUNSC_VERSION:?}" "${CNI_VERSION:?}"

case "$arch" in
  x86_64)        cni_arch=amd64 ;;
  aarch64|arm64) arch=aarch64; cni_arch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

mkdir -p "$out/gvisor" "$out/cni"
cd "$out"

# gVisor releases are a bundle (runsc + gvisor-bin/), not a bare binary.
# Keep the bundle's layout intact: runsc may look for its helpers next to it.
base="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_VERSION}/${arch}"
curl -fsSLO "$base/gvisor.tar.bz2"
curl -fsSLO "$base/gvisor.tar.bz2.sha512"
sha512sum -c gvisor.tar.bz2.sha512
# The containerd shim is not used: tenantd calls runsc directly.
tar -xjf gvisor.tar.bz2 -C gvisor --exclude containerd-shim-runsc-v1
rm gvisor.tar.bz2 gvisor.tar.bz2.sha512
test -x gvisor/runsc

tgz="cni-plugins-linux-${cni_arch}-${CNI_VERSION}.tgz"
curl -fsSLO "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/${tgz}"
curl -fsSLO "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/${tgz}.sha256"
sha256sum -c "${tgz}.sha256"
# Only the plugins tenantd's egress mode uses.
tar -xzf "$tgz" -C cni ./bridge ./firewall ./host-local ./loopback
rm "$tgz" "${tgz}.sha256"
