#!/usr/bin/env bash
# Boot a distro cloud image in KVM and run the real install path against it:
#   install package -> XFS data disk -> enable + start -> tenant + sandbox ->
#   restart tenantd (sandbox must survive) -> processes -> containers ->
#   files ->
#   volumes and FUSE ->
#   reboot (reconcile) -> upgrade from the previous release (if one was
#   downloaded).
#
# Usage: vm-test.sh <ubuntu-24.04|debian-12|rocky-9> <dist-dir> <prev-dir>
set -euo pipefail

distro=$1 dist=$(realpath "$2") prev=$(realpath "$3")
ci=$(dirname "$(realpath "$0")")
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
if command -v cloud-localds >/dev/null; then
  cloud-localds seed.img user-data
else  # e.g. Arch: build the NoCloud seed ISO by hand
  echo "instance-id: vm-test" > meta-data
  xorriso -as mkisofs -quiet -o seed.img -V cidata -J -r user-data meta-data
fi

qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 4096 -display none \
  -drive file=root.qcow2,if=virtio -drive file=data.qcow2,if=virtio \
  -drive file=seed.img,if=virtio,format=raw \
  -netdev user,id=n0,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n0 \
  -serial file:console.log -daemonize -pidfile qemu.pid

common=(-i "$work/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
# Commands go over stdin so quoting inside them never fights the ssh layer.
# Each one gets VM_TIMEOUT seconds: a hung step fails here, with pcheck's
# diagnostics, instead of eating the job's timeout and showing "cancelled".
vm() {
  local rc=0 start=$SECONDS
  timeout "${VM_TIMEOUT:-300}" ssh "${common[@]}" -p 2222 ci@127.0.0.1 \
    'sudo bash -euxo pipefail' <<<"$*" || rc=$?
  # 124 is also what a command inside can exit with (process wait does).
  if [ "$rc" = 124 ] && [ $((SECONDS - start)) -ge "${VM_TIMEOUT:-300}" ]; then
    echo "vm: timed out after ${VM_TIMEOUT:-300}s: $*" >&2
  fi
  return "$rc"
}
put() { scp "${common[@]}" -P 2222 "$@" ci@127.0.0.1:/tmp/; }
wait_ssh() {
  for _ in $(seq 90); do
    ssh "${common[@]}" -p 2222 -o ConnectTimeout=2 ci@127.0.0.1 true 2>/dev/null && return
    sleep 2
  done
  cat console.log; exit 1
}
# The unit is Type=simple: is-active goes green as soon as the process starts,
# but the API socket only appears after storage/runtime verification and the
# startup reconcile. Wait for it, and dump the journal if it never shows up.
wait_api() {
  vm 'for _ in $(seq 60); do
        if [ -S /run/tenantd/api.sock ]; then exit 0; fi
        sleep 1
      done
      echo "api socket never appeared" >&2
      systemctl --no-pager status tenantd || true
      journalctl --no-pager -u tenantd -n 200 || true
      exit 1'
}
# Assert the sandbox state; on mismatch show what the sandbox itself said.
expect_state() {
  vm "out=\$(tenantd sandbox get t1 s1)
      echo \"\$out\"
      if ! grep -q $1 <<<\"\$out\"; then
        tail -n 50 /var/lib/tenantd/runtime/logs/t1.s1+.* || true
        journalctl --no-pager -u tenantd -n 100 || true
        exit 1
      fi"
}
# VM_KEEP=1 leaves the VM running on exit so you can ssh in and look.
on_exit() {
  if [ "${VM_KEEP:-0}" = 1 ]; then
    echo "VM kept: ssh ${common[*]} -p 2222 ci@127.0.0.1" >&2
    echo "stop it: kill $(cat "$work/qemu.pid")" >&2
  else
    kill "$(cat "$work/qemu.pid")" 2>/dev/null || true
    cd / && rm -rf "$work"
  fi
}
trap on_exit EXIT
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
# keeps running for the restart/reboot checks. The redis entrypoint drops to
# the redis user with setpriv, which needs SETUID/SETGID.
vm 'cat >> /etc/tenantd/tenantd.toml <<EOT

[profiles.ci]
images = ["docker.io/library/*"]
memory = "256m"
cpus = 0.5
pids = 128
rootfs = "host-overlay"
network = "none"
capabilities = ["CAP_SETUID", "CAP_SETGID"]
EOT'

vm tenantd config check
vm systemctl enable --now tenantd
vm systemctl is-active tenantd
wait_api

vm tenantd tenant create t1 --storage 256Mi
vm tenantd sandbox create t1 s1 --profile ci --image docker.io/library/redis:7-alpine
expect_state running

# --- Restart must not kill sandboxes ---------------------------------------
vm systemctl restart tenantd
wait_api
expect_state running

# --- Upgrade ---------------------------------------------------------------
if [ -n "$old_pkg" ]; then
  put "$new_pkg"; vm "$install /tmp/$(basename "$new_pkg")"
  vm systemctl is-active tenantd
  wait_api
  # Breaking change while on edge: runtime handles gained a "+" terminator
  # (runsc resolves IDs by prefix), so reconcile can't own a sandbox the old
  # release started. It marks it exited and removes the old runsc container.
  # TODO: back to `expect_state running` once the previous release has "+".
  expect_state exited
  vm '! /usr/lib/tenantd/runsc/*/runsc --root /run/tenantd/runsc list | awk "{print \$1}" | grep -qx t1.s1'
  vm tenantd sandbox start t1 s1
  expect_state running
fi

# --- Processes: exec policy via SIGHUP, output limit, exit codes, restart --
# Added only now: an older release rejects the unknown exec table.
pcheck() {
  vm "$1" && return
  vm 'tenantd process ps t1 s1 || true
      for f in /data/tenants/t1/sandboxes/s1/processes/*/runsc.log; do
        echo "== $f"; tail -n 30 "$f" || true
      done
      journalctl --no-pager -u tenantd -n 100 || true' || true
  exit 1
}
vm 'cat >> /etc/tenantd/tenantd.toml <<EOT

[profiles.ci.exec]
enabled = true
output_limit = "4k"
EOT'
vm tenantd config check
vm systemctl reload tenantd
# The reload is asynchronous: starts are refused until it lands.
pcheck 'for _ in $(seq 10); do
          if out=$(tenantd exec --id hello t1 s1 -- echo hello); then break; fi
          sleep 1
        done
        test "$out" = hello'
pcheck 'rc=0
        tenantd exec t1 s1 -- sh -c "echo out; echo err >&2; exit 3" >/tmp/o 2>/tmp/e || rc=$?
        test $rc = 3 && grep -qx out /tmp/o && grep -qx err /tmp/e'
# 1 MB of output against a 4 KiB limit: the head is kept, the rest is
# punched out of the file (logical size stays, blocks are freed).
pcheck 'tenantd exec --id flood t1 s1 -- sh -c "yes x | head -c 1000000" >/tmp/flood
        grep -q "truncated: 995904 bytes dropped" /tmp/flood
        f=/data/tenants/t1/sandboxes/s1/processes/flood/stdout
        test "$(stat -c %s $f)" = 1000000
        test "$(du --block-size=1 $f | cut -f1)" -le 65536'
# A detached process survives a daemon restart and is re-watched.
pcheck 'tenantd exec -d --id sleeper t1 s1 -- sleep 600'
vm systemctl restart tenantd
wait_api
pcheck 'tenantd process get t1 s1 sleeper | grep -q running
        tenantd process kill t1 s1 sleeper --signal SIGTERM
        rc=0; tenantd process wait t1 s1 sleeper --timeout 30 || rc=$?
        test $rc = 143'
pcheck 'tenantd process rm t1 s1 hello
        ! tenantd exec --id hello t1 s1 -- echo again'

# --- Containers: sessions on their own roots in one gVisor sandbox -------
pcheck 'tenantd container create t1 s1 c1 -- sleep infinity
        tenantd container create t1 s1 c2 -- sleep infinity
        test "$(tenantd container list t1 s1 | grep -c " running")" = 2
        test "$(tenantd exec --container c1 t1 s1 -- sh -c "echo a >/mine; cat /mine")" = a
        ! tenantd exec --container c2 t1 s1 -- cat /mine
        ! tenantd exec t1 s1 -- cat /mine
        test "$(cat /data/tenants/t1/sandboxes/s1/containers/c1/upper/mine)" = a
        test "$(pgrep -c -f "^runsc-sandbox ")" = 1'
pcheck 'tenantd container rm t1 s1 c2
        ! test -e /data/tenants/t1/sandboxes/s1/containers/c2
        tenantd container get t1 s1 c1 | grep -q " running"'

# --- Files: the container's files over the API, seen at once inside -----
# c1 has the default: each call execs tenantd's helper inside, and runsc
# keeps its own file-access default. c3 opted into host access, the only one
# with --file-access=shared.
bundles=/var/lib/tenantd/runtime/bundles
pcheck 'tenantd container create --host-file-access t1 s1 c3 -- sleep infinity
        tenantd container get t1 s1 c3 | grep -q host-file-access
        grep -qx -- --file-access=shared '"$bundles"'/t1.s1.c3+/runsc.flags
        ! grep -q -- --file-access '"$bundles"'/t1.s1.c1+/runsc.flags
        tenantd exec --container c1 t1 s1 -- test -x /dev/.tenantd-files'
# Bigger than output_limit (4k) both ways.
for c in c1 c3; do
pcheck 'head -c 1000000 /dev/urandom > /tmp/big
        tenantd file put --parents t1 s1 '$c' /in/big < /tmp/big
        tenantd file cat t1 s1 '$c' /in/big | cmp - /tmp/big
        test "$(tenantd exec --container '$c' t1 s1 -- sha256sum /in/big | cut -d" " -f1)" = \
             "$(sha256sum /tmp/big | cut -d" " -f1)"
        tenantd exec --container '$c' t1 s1 -- sh -c "head -c 100000 /dev/zero > /in/out"
        test "$(tenantd file cat t1 s1 '$c' /in/out | wc -c)" = 100000
        tenantd file stat t1 s1 '$c' /in/big | grep -q " 1000000 0:0 /in/big"
        tenantd file ls t1 s1 '$c' /in | grep -q " out$"'
# A process inside keeps reading the file while it is replaced from outside.
pcheck 'echo first | tenantd file put t1 s1 '$c' /w/f --parents
        tenantd exec -d --id watcher-'$c' --container '$c' t1 s1 -- \
          sh -c "until grep -qx second /w/f; do sleep 0.1; done"
        sleep 1
        tenantd process get t1 s1 watcher-'$c' | grep -q running
        echo second | tenantd file put t1 s1 '$c' /w/f
        tenantd process wait t1 s1 watcher-'$c' --timeout 10'
# /tmp is runsc'"'"'s tmpfs over the image'"'"'s empty /tmp: the host never sees
# it, so host access serves it through the helper too.
pcheck 'echo x | tenantd file put t1 s1 '$c' /tmp/x
        test "$(tenantd exec --container '$c' t1 s1 -- cat /tmp/x)" = x
        ! test -e /data/tenants/t1/sandboxes/s1/containers/'$c'/upper/tmp/x'
done
# Renames across directories show inside, and so does a removal.
pcheck 'tenantd file put --parents t1 s1 c1 /other/keep </dev/null
        tenantd file mv t1 s1 c1 /w/f /other/f
        test "$(tenantd exec --container c1 t1 s1 -- cat /other/f)" = second
        ! tenantd exec --container c1 t1 s1 -- test -e /w/f
        ! tenantd file mv --no-replace t1 s1 c1 /other/f /other/keep
        tenantd file rm t1 s1 c1 /other/keep
        ! tenantd exec --container c1 t1 s1 -- test -e /other/keep
        ! tenantd file rm --dir t1 s1 c1 /other'
# An absolute symlink resolves in the container (alpine has a redis user,
# the host does not), and a put through a symlink replaces its target.
for c in c1 c3; do
pcheck 'tenantd exec --container '$c' t1 s1 -- ln -s /etc/passwd /w/pw
        tenantd file cat t1 s1 '$c' /w/pw | grep -q ^redis:
        ! grep -q ^redis: /etc/passwd
        tenantd file stat -L t1 s1 '$c' /w/pw | grep -q " /etc/passwd$"
        tenantd exec --container '$c' t1 s1 -- ln -s /w/f /w/link
        echo via-link | tenantd file put t1 s1 '$c' /w/link
        test "$(tenantd exec --container '$c' t1 s1 -- cat /w/f)" = via-link
        tenantd exec --container '$c' t1 s1 -- test -L /w/link'
done
# A put killed mid-body leaves the file as it was, and no temporary file.
pcheck '(echo partial; sleep 30) | timeout -s KILL 3 tenantd file put t1 s1 c1 /other/f || true
        sleep 1
        test "$(tenantd file cat t1 s1 c1 /other/f)" = second
        ! ls -a /data/tenants/t1/sandboxes/s1/containers/c1/upper/other | grep -q tenantd-write'
# Past the tenant quota (256Mi): ENOSPC (an XFS project quota's errno, as the
# container's own writes get), the target untouched, space back.
pcheck 'rc=0
        head -c 300M /dev/zero | tenantd file put t1 s1 c1 /huge 2>/tmp/q || rc=$?
        cat /tmp/q
        test $rc != 0 && grep -q "os error 28" /tmp/q  # ENOSPC
        ! tenantd file stat t1 s1 c1 /huge
        ! ls -a /data/tenants/t1/sandboxes/s1/containers/c1/upper | grep -q tenantd-write'
# As another user of exec.users: its permissions, its files.
vm 'sed -i "s/^output_limit = \"4k\"\$/&\nusers = [\"image\", \"redis\"]/" /etc/tenantd/tenantd.toml'
vm tenantd config check
vm systemctl reload tenantd
for c in c1 c3; do
pcheck 'for _ in $(seq 10); do
          if echo r | tenantd file put --user redis t1 s1 '$c' /data/r; then break; fi
          sleep 1
        done
        test "$(tenantd exec --container '$c' t1 s1 -- stat -c %U /data/r)" = redis
        ! echo x | tenantd file put --user redis t1 s1 '$c' /etc/nope
        ! tenantd file stat t1 s1 '$c' /etc/nope'
done
# A rough cost per call either way, for the log.
vm 'for c in c1 c3; do
      s=$(date +%s%N)
      for _ in $(seq 20); do tenantd file stat t1 s1 $c / >/dev/null; done
      echo "file stat on $c: $(( ($(date +%s%N) - s) / 20000000 ))ms per call"
    done'
pcheck 'tenantd container rm t1 s1 c3'

# --- Volumes and FUSE: a workspace shared by containers and the host, and a
# FUSE mount served from the host through ServeFuse ------------------------
# Added only now: an older release rejects the unknown slot tables.
vm 'cat >> /etc/tenantd/tenantd.toml <<EOT

[profiles.ci.volumes.workspace]
path = "/workspace"

[profiles.ci.fuse]
path = "/mnt"
EOT'
vm tenantd config check
vm systemctl reload tenantd
pcheck 'tenantd volume create t1 ws --mode 1777
        for _ in $(seq 10); do
          if tenantd container create t1 s1 v1 --volume workspace=ws -- sleep infinity; then break; fi
          sleep 1
        done
        tenantd container create t1 s1 v2 --volume workspace=ws -- sleep infinity
        tenantd exec --container v1 t1 s1 -- sh -c "echo shared > /workspace/note"
        test "$(tenantd exec --container v2 t1 s1 -- cat /workspace/note)" = shared
        test "$(cat /data/tenants/t1/volumes/ws/note)" = shared
        echo host > /data/tenants/t1/volumes/ws/from-host
        test "$(tenantd exec --container v1 t1 s1 -- cat /workspace/from-host)" = host
        ! tenantd volume rm t1 ws
        tenantd volume prune t1 ws --prefix note | grep -q "removed 1 entries"
        ! test -e /data/tenants/t1/volumes/ws/note
        ! tenantd exec --container v2 t1 s1 -- cat /workspace/note'
# A volume's files over the API, with or without a container: as its owner
# (root here), seen at once by the containers that bind it. A symlink
# resolves inside the volume, never on the host.
pcheck 'echo via-api | tenantd volume file put --parents t1 ws /d/f
        test "$(tenantd exec --container v1 t1 s1 -- cat /workspace/d/f)" = via-api
        tenantd volume file stat t1 ws /d/f | grep -q "^file .* 0:0 /d/f$"
        tenantd volume file mkdir --mode 750 t1 ws /d/sub
        tenantd volume file stat t1 ws /d/sub | grep -q "^dir    0750 "
        tenantd volume file mkdir -p t1 ws /d/sub/a/b
        tenantd volume file ln t1 ws /etc/passwd /d/pw
        test "$(tenantd volume file readlink t1 ws /d/pw)" = /etc/passwd
        ! tenantd volume file cat t1 ws /d/pw
        tenantd volume file chattr --mode 600 --mtime 1000000000 t1 ws /d/f
        test "$(stat -c "%a %Y" /data/tenants/t1/volumes/ws/d/f)" = "600 1000000000"
        tenantd volume file ls t1 ws /d | grep -q " pw$"
        tenantd volume file mv t1 ws /d/f /d/g
        tenantd volume file rm t1 ws /d/g
        ! test -e /data/tenants/t1/volumes/ws/d/g
        ! tenantd volume file stat t1 nope /'
pcheck 'mkdir /tmp/fsrc && echo "hello from the host" > /tmp/fsrc/hello
        tenantd container create t1 s1 f1 --fuse -- sleep infinity | grep -q " created"
        nohup tenantd container serve-fuse t1 s1 f1 --dir /tmp/fsrc --start \
          </dev/null >/tmp/fuse.log 2>&1 &
        for _ in $(seq 30); do
          if tenantd container get t1 s1 f1 | grep -q " running"; then break; fi
          sleep 1
        done
        cat /tmp/fuse.log
        test "$(tenantd exec --container f1 t1 s1 -- cat /mnt/hello)" = "hello from the host"
        tenantd exec --container f1 t1 s1 -- ls /mnt | grep -qx hello
        tenantd exec --container f1 t1 s1 -- sh -c "echo written > /mnt/new && mkdir /mnt/d && mv /mnt/new /mnt/d/moved"
        test "$(cat /tmp/fsrc/d/moved)" = written
        echo host-side > /tmp/fsrc/late
        for _ in $(seq 5); do
          if tenantd exec --container f1 t1 s1 -- cat /mnt/late 2>/dev/null | grep -q host-side; then break; fi
          sleep 1
        done
        test "$(tenantd exec --container f1 t1 s1 -- cat /mnt/late)" = host-side
        tenantd container rm t1 s1 f1
        for _ in $(seq 10); do
          if grep -q "connection ended" /tmp/fuse.log; then break; fi
          sleep 1
        done
        grep -q "connection ended" /tmp/fuse.log
        ! grep -q /run/tenantd/fuse /proc/self/mountinfo
        tenantd container rm t1 s1 v1
        tenantd container rm t1 s1 v2
        tenantd volume rm t1 ws
        ! test -e /data/tenants/t1/volumes/ws'

# --- Reboot: /run is gone, reconcile must mark exited, start must remount --
vm 'systemctl reboot' || true
sleep 5; wait_ssh
vm systemctl is-active tenantd
wait_api
expect_state exited
# Its container ended with it and kept its root until removed.
pcheck 'tenantd container get t1 s1 c1 | grep -q " exited"
        test -e /data/tenants/t1/sandboxes/s1/containers/c1/upper/mine
        tenantd container rm t1 s1 c1'
vm tenantd sandbox start t1 s1
expect_state running

# --- Quota enforced end to end ---------------------------------------------
vm 'tenantd tenant get t1'

# --- SELinux denials are a failure on Rocky --------------------------------
if [ "$distro" = rocky-9 ]; then
  vm '! ausearch -m avc -ts boot 2>/dev/null | grep -E "tenantd|runsc"'
fi

echo "vm-test $distro: OK"
