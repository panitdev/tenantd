#!/bin/sh
# Stop on removal, not on upgrade. dpkg passes "remove"/"upgrade",
# rpm passes the remaining-install count (0 = removal).
set -e

case "$1" in
  remove|purge|0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now tenantd || true
    fi
    ;;
esac
