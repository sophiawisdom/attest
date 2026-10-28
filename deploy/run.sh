#!/usr/bin/env bash
# Start (or restart) the attest enclave and host on a Nitro parent, from a
# checkout where build/build-eif.sh has run. Defaults match the allocator
# set by deploy/launch-graviton.sh (2 CPUs, 10 GiB).
#
#   CONFIG=/etc/attest/host.json [S3_BUCKET=name S3_REGION=us-west-2] deploy/run.sh
#
# host.json is handed to the enclave at boot, e.g.
#   {"public_ip": "1.2.3.4", "email_from": "you@example.com", "ses_region": "us-west-2", "operator": "...", "domain": null}
# plus optional limits, "max_sessions" (default 100) and "session_memory_mib"
# (default 15% of enclave memory); deploy/limits.py changes them live.
# (deploy/self-host.sh writes it.) With S3_BUCKET the host keeps every
# sealed file in that bucket and its disk as a cache (instance role
# credentials; see deploy/self-host.sh).
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
S3_ARGS=""
if [ -n "${S3_BUCKET:-}" ]; then
  [[ "$S3_BUCKET" =~ ^[a-z0-9-]+$ ]] || { echo "bad S3_BUCKET" >&2; exit 2; }
  [[ "${S3_REGION:-}" =~ ^[a-z0-9-]+$ ]] || { echo "S3_REGION is required with S3_BUCKET" >&2; exit 2; }
  S3_ARGS="--s3-bucket $S3_BUCKET --s3-region $S3_REGION"
fi
NAME=attest
LOG=$HOME/attest-host.log

# Hold the watchdog (and a pair's failover check) off while we replace things.
sudo systemctl stop attest-watchdog.timer attest-pair.timer 2>/dev/null || true
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
ExecStart=$SRC/build/out/bin/attest-host --enclave-cid $CID --listen 0.0.0.0:443 --config $CONFIG $S3_ARGS
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
# The enclave it starts must outlive this run (systemd would otherwise
# stop every process the run left behind, the enclave included).
KillMode=process
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
# A machine of a failover pair also runs deploy/pair.sh.
"$SRC/deploy/pair-install.sh"
echo "host log: $LOG"
