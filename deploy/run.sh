#!/usr/bin/env bash
# Start (or restart) the attest enclave and host on a Nitro parent, from a
# checkout where build/build-eif.sh has run. Defaults match the allocator
# set by deploy/launch-graviton.sh (2 CPUs, 10 GiB).
#
#   CONFIG=/etc/attest/host.json deploy/run.sh
#
# host.json is handed to the enclave at boot, e.g.
#   {"public_ip": "1.2.3.4", "email_from": "you@example.com", "ses_region": "us-west-2", "operator": "...", "domain": null}
# (deploy/self-host.sh writes it.)
#
# The host daemon runs as a systemd service that restarts on failure (its
# restarts don't affect the enclave or stored files). A watchdog timer
# starts the enclave after a reboot or if it dies (deploy/watchdog.sh).
# Restarting the enclave ends every session; the new boot id is visible.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=$(pwd)
EIF=$(realpath "${EIF:-build/out/attest.eif}")
CPUS=${CPUS:-2}
MEM_MIB=${MEM_MIB:-10240}
CID=${CID:-16}
CONFIG=${CONFIG:-/etc/attest/host.json}
NAME=attest
LOG=$HOME/attest-host.log

# Hold the watchdog off while we replace things.
sudo systemctl stop attest-watchdog.timer 2>/dev/null || true
# An older run.sh started the daemon by hand.
sudo pkill -f "attest-host --enclave-cid" || true

sudo mkdir -p /etc/attest
printf 'EIF=%q\nCPUS=%q\nMEM_MIB=%q\nCID=%q\nNAME=%q\n' "$EIF" "$CPUS" "$MEM_MIB" "$CID" "$NAME" \
  | sudo tee /etc/attest/enclave.env >/dev/null

sudo tee /etc/systemd/system/attest-host.service >/dev/null <<EOF
[Unit]
Description=attest host daemon (untrusted parent side)
After=network-online.target nitro-enclaves-allocator.service
Wants=network-online.target

[Service]
ExecStart=$SRC/build/out/bin/attest-host --enclave-cid $CID --listen 0.0.0.0:443 --config $CONFIG
Restart=always
RestartSec=2
StandardOutput=append:$LOG
StandardError=append:$LOG

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/attest-watchdog.service >/dev/null <<EOF
[Unit]
Description=attest enclave watchdog
After=attest-host.service nitro-enclaves-allocator.service

[Service]
Type=oneshot
ExecStart=$SRC/deploy/watchdog.sh
EOF

sudo tee /etc/systemd/system/attest-watchdog.timer >/dev/null <<EOF
[Unit]
Description=Check the attest enclave every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
# The host must be up first: the enclave reads its config at boot.
sudo systemctl enable attest-host.service >/dev/null 2>&1
sudo systemctl restart attest-host.service
sleep 2

if nitro-cli describe-enclaves | grep -q "\"EnclaveName\": \"$NAME\""; then
  nitro-cli terminate-enclave --enclave-name "$NAME"
fi
# Never pass --debug-mode: it zeroes the PCRs and lets the parent read
# enclave memory. Verifiers reject zero PCRs.
nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$EIF" --cpu-count "$CPUS" --memory "$MEM_MIB" --enclave-cid "$CID"

echo 0 | sudo tee /run/attest-watchdog.fails >/dev/null
sudo systemctl enable --now attest-watchdog.timer >/dev/null 2>&1
echo "host log: $LOG"
