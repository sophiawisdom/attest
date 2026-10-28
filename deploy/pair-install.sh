#!/usr/bin/env bash
# Install (or, without /etc/attest/pair.env, remove) the failover timer
# that runs deploy/pair.sh every 15 s. Called by deploy/run.sh, and by
# deploy/self-host.sh on the primary when a standby joins.
set -euo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
if [ ! -f /etc/attest/pair.env ]; then
  sudo systemctl disable --now attest-pair.timer >/dev/null 2>&1 || true
  exit 0
fi
sudo tee /etc/systemd/system/attest-pair.service >/dev/null <<UNIT
[Unit]
Description=attest pair failover check
After=attest-host.service

[Service]
Type=oneshot
ExecStart=$SRC/deploy/pair.sh
UNIT
sudo tee /etc/systemd/system/attest-pair.timer >/dev/null <<UNIT
[Unit]
Description=Check the attest pair every 15 seconds

[Timer]
OnBootSec=3min
OnUnitActiveSec=15s
AccuracySec=1s

[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now attest-pair.timer >/dev/null 2>&1
