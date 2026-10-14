#!/bin/sh
# Inert install: enable IP forwarding for the egress profile, but never
# enable or start the service. The operator runs `tenantd service install`
# (or `systemctl enable --now tenantd`) once the storage root is in place.
set -e

if command -v sysctl >/dev/null 2>&1; then
  sysctl -q -p /usr/lib/sysctl.d/99-tenantd.conf || true
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  # On upgrade, restart only if it was already running. Safe because
  # sandboxes are separate runsc processes, outside this unit's cgroup.
  if systemctl is-active --quiet tenantd; then
    systemctl restart tenantd
  fi
fi
