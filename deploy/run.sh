#!/usr/bin/env bash
# Start (or restart) the attest enclave and host on a Nitro parent, from a
# checkout where build/build-eif.sh has run. Defaults match the allocator
# set by deploy/launch-graviton.sh (2 CPUs, 10 GiB).
#
#   CONFIG=/etc/attest/host.json deploy/run.sh
#
# host.json is handed to the enclave at boot, e.g.
#   {"domain": "attest.example.com", "email": {"resend_api_key": "...", "from": "attest <notify@example.com>"}}
#
# Restarting the enclave ends every session; the new boot id is visible.
set -euo pipefail
cd "$(dirname "$0")/.."
EIF=${EIF:-build/out/attest.eif}
CPUS=${CPUS:-2}
MEM_MIB=${MEM_MIB:-10240}
CID=${CID:-16}
CONFIG=${CONFIG:-/etc/attest/host.json}
NAME=attest

# The host must be up first: the enclave reads its config at boot.
sudo pkill -f "attest-host --enclave-cid" || true
sudo nohup build/out/bin/attest-host --enclave-cid "$CID" --listen 0.0.0.0:443 --config "$CONFIG" >> attest-host.log 2>&1 &
sleep 1

if nitro-cli describe-enclaves | grep -q "\"EnclaveName\": \"$NAME\""; then
  nitro-cli terminate-enclave --enclave-name "$NAME"
fi
# Never pass --debug-mode: it zeroes the PCRs and lets the parent read
# enclave memory. Verifiers reject zero PCRs.
nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$EIF" --cpu-count "$CPUS" --memory "$MEM_MIB" --enclave-cid "$CID"
echo "host log: $PWD/attest-host.log"
