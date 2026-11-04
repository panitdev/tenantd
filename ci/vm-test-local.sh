#!/usr/bin/env bash
# Run the edge vm-test on this machine: build the x86_64 .deb the way the
# edge pipeline does, then boot it in KVM with ci/vm-test.sh. A few minutes
# instead of a push and a CI round trip.
#
# Usage: ci/vm-test-local.sh [distro] [--prev <tag>]
#   distro       ubuntu-24.04 (default), debian-12 or rocky-9
#   --prev <tag> also test upgrading from that release (e.g. edge)
#
# Needs: /dev/kvm, qemu-system-x86_64, qemu-img, zig, cmake, protoc,
#        cargo-zigbuild, nfpm, envsubst, and cloud-localds or xorriso.
set -euo pipefail

distro=ubuntu-24.04 prev_tag=
while [ $# -gt 0 ]; do
  case "$1" in
    --prev) prev_tag=${2:?--prev needs a tag}; shift 2 ;;
    -*) echo "unknown flag $1" >&2; exit 2 ;;
    *) distro=$1; shift ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"
for tool in qemu-system-x86_64 qemu-img zig cmake protoc cargo-zigbuild nfpm envsubst; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done
[ -w /dev/kvm ] || { echo "/dev/kvm is not writable" >&2; exit 1; }

set -a; . ci/versions.env; set +a
base=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
export VERSION="$base.local.$(git rev-parse --short=8 HEAD)"
export NFPM_ARCH=amd64 target=x86_64-unknown-linux-musl
work=target/vm-local
export BIN_DIR=target/$target/release VENDOR_DIR=$work/vendor
mkdir -p "$work"

echo "== build tenantd $VERSION"
cargo zigbuild --release --locked --target "$target" -p tenantd

# Vendored runsc + CNI: fetched once per pinned version.
stamp="$VENDOR_DIR/.versions"
if [ "$(cat "$stamp" 2>/dev/null)" != "$RUNSC_VERSION $CNI_VERSION" ]; then
  echo "== fetch runsc $RUNSC_VERSION, CNI $CNI_VERSION"
  rm -rf "$VENDOR_DIR"
  ci/fetch-vendor.sh x86_64 "$VENDOR_DIR"
  echo "$RUNSC_VERSION $CNI_VERSION" > "$stamp"
fi

echo "== package"
rm -rf "$work/dist" "$work/prev"; mkdir -p "$work/dist" "$work/prev"
envsubst < packaging/nfpm.yaml.in > nfpm.yaml
envsubst < packaging/tenantd.toml.in > packaging/tenantd.toml
case "$distro" in
  rocky-9) fmt=rpm ;;
  *) fmt=deb ;;
esac
nfpm package -f nfpm.yaml -p "$fmt" -t "$work/dist/"

if [ -n "$prev_tag" ]; then
  echo "== previous release $prev_tag"
  gh release download "$prev_tag" -D "$work/prev" -p '*amd64.deb' -p '*x86_64.rpm'
fi

echo "== vm-test $distro"
ci/vm-test.sh "$distro" "$work/dist" "$work/prev"
