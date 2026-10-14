#!/usr/bin/env bash
# Create a loop-backed XFS filesystem mounted with project quota.
# Usage: setup-xfs.sh <mountpoint> <size>
set -euo pipefail

mnt=${1:?mountpoint}
size=${2:-4G}
img=/var/tmp/tenantd-xfs.img

truncate -s "$size" "$img"
mkfs.xfs -q -f "$img"
mkdir -p "$mnt"
mount -o loop,prjquota "$img" "$mnt"

# Fail loudly here rather than in a confusing test later.
xfs_quota -x -c 'state -p' "$mnt" | tee /dev/stderr | grep -q 'Enforcement: ON'
echo "XFS with project quota mounted at $mnt"
