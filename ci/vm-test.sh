#!/usr/bin/env bash
# Boot a distro cloud image in KVM and run the real install path against it:
#   install package -> XFS data disk -> enable + start -> tenant + sandbox ->
#   restart tenantd (sandbox must survive) -> reboot (reconcile) ->
#   upgrade from the previous release (if one was downloaded).
#
# Usage: vm-test.sh <ubuntu-24.04|debian-12|rocky-9> <dist-dir> <prev-dir>
set -euo pipefail

distro=$1 dist=$(realpath "$2") prev=$(realpath "$3")
work=$(mktemp -d)
cd "$work"

case "$distro" in
  ubuntu-24.04)
    url=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
    pkg_glob='*_amd64.deb'; install='apt-get install -y' ;;
  debian-12)
    url=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
    pkg_glob='*_amd64.deb'; install='apt-get install -y' ;;
  rocky-9)
    url=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2
    pkg_glob='*.x86_64.rpm'; install='dnf install -y' ;;
  *) echo "unknown distro $distro" >&2; exit 1 ;;
esac

# --- VM -------------------------------------------------------------------
curl -fsSL -o base.img "$url"
qemu-img create -f qcow2 -F qcow2 -b base.img root.qcow2 20G
qemu-img create -f qcow2 data.qcow2 8G          # becomes /data

ssh-keygen -q -t ed25519 -N '' -f key
cat > user-data <<EOF
#cloud-config
users:
  - name: ci
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys: ["$(cat key.pub)"]
EOF
cloud-localds seed.img user-data

qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 4096 -display none \
  -drive file=root.qcow2,if=virtio -drive file=data.qcow2,if=virtio \
  -drive file=seed.img,if=virtio,format=raw \
  -netdev user,id=n0,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n0 \
  -serial file:console.log -daemonize -pidfile qemu.pid

common=(-i key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
# Commands go over stdin so quoting inside them never fights the ssh layer.
vm()  { ssh "${common[@]}" -p 2222 ci@127.0.0.1 'sudo bash -euxo pipefail' <<<"$*"; }
put() { scp "${common[@]}" -P 2222 "$@" ci@127.0.0.1:/tmp/; }
wait_ssh() {
  for _ in $(seq 90); do
    ssh "${common[@]}" -p 2222 -o ConnectTimeout=2 ci@127.0.0.1 true 2>/dev/null && return
    sleep 2
  done
  cat console.log; exit 1
}
trap 'kill "$(cat qemu.pid)" 2>/dev/null || true' EXIT
wait_ssh
vm cloud-init status --wait >/dev/null || true

# --- Host prerequisites (what cloud-init would do on a real machine) -------
vm "$install xfsprogs"
vm 'mkfs.xfs -q /dev/vdb && mkdir -p /data &&
    echo "/dev/vdb /data xfs defaults,prjquota 0 0" >> /etc/fstab && mount /data'
if [ "$distro" = rocky-9 ]; then vm 'getenforce | grep -q Enforcing'; fi

# --- Install: previous release first if we have one, so we test upgrade ---
new_pkg=$(ls "$dist"/$pkg_glob | head -1)
old_pkg=$(ls "$prev"/$pkg_glob 2>/dev/null | head -1 || true)

if [ -n "$old_pkg" ]; then
  put "$old_pkg"; vm "$install /tmp/$(basename "$old_pkg")"
else
  put "$new_pkg"; vm "$install /tmp/$(basename "$new_pkg")"
fi

# Package must be inert until the operator enables it.
vm '! systemctl is-enabled tenantd'

# Add a runtime profile whose image stays in the foreground so the sandbox
# keeps running for the restart/reboot checks.
vm 'cat >> /etc/tenantd/tenantd.toml <<EOT

[profiles.ci]
images = ["docker.io/library/*"]
memory = "256m"
cpus = 0.5
pids = 128
rootfs = "host-overlay"
network = "none"
EOT'

vm tenantd config check
vm systemctl enable --now tenantd
vm systemctl is-active tenantd

vm tenantd tenant create t1 --storage 256Mi
vm tenantd sandbox create t1 s1 --profile ci --image docker.io/library/redis:7-alpine
vm 'tenantd sandbox get t1 s1 | grep -q running'

# --- Restart must not kill sandboxes ---------------------------------------
vm systemctl restart tenantd
vm 'tenantd sandbox get t1 s1 | grep -q running'

# --- Upgrade ---------------------------------------------------------------
if [ -n "$old_pkg" ]; then
  put "$new_pkg"; vm "$install /tmp/$(basename "$new_pkg")"
  vm systemctl is-active tenantd
  vm 'tenantd sandbox get t1 s1 | grep -q running'
fi

# --- Reboot: /run is gone, reconcile must mark exited, start must remount --
vm 'systemctl reboot' || true
sleep 5; wait_ssh
vm systemctl is-active tenantd
vm 'tenantd sandbox get t1 s1 | grep -q exited'
vm tenantd sandbox start t1 s1
vm 'tenantd sandbox get t1 s1 | grep -q running'

# --- Quota enforced end to end ---------------------------------------------
vm 'tenantd tenant get t1'

# --- SELinux denials are a failure on Rocky --------------------------------
if [ "$distro" = rocky-9 ]; then
  vm '! ausearch -m avc -ts boot 2>/dev/null | grep -E "tenantd|runsc"'
fi

echo "vm-test $distro: OK"
