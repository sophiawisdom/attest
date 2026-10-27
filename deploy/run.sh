#!/usr/bin/env bash
# Start (or restart) the attest enclave and host on a Nitro parent, from a
# tree where build/build-eif.sh has run. Defaults match the allocator set by
# deploy/launch-graviton.sh (2 CPUs, 10 GiB).
#
#   deploy/run.sh
#
# Restarting the enclave forgets in-flight runs and resets the run log; the
# new boot id is visible to everyone.
set -euo pipefail
cd "$(dirname "$0")/.."
EIF=${EIF:-build/out/attest.eif}
CPUS=${CPUS:-2}
MEM_MIB=${MEM_MIB:-10240}
CID=${CID:-16}
NAME=attest

nitro-cli describe-enclaves | grep -q "\"EnclaveName\": \"$NAME\"" && nitro-cli terminate-enclave --enclave-name "$NAME"
# Never pass --debug-mode: it zeroes the PCRs and lets the parent read
# enclave memory. Verifiers reject zero PCRs.
nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$EIF" --cpu-count "$CPUS" --memory "$MEM_MIB" --enclave-cid "$CID"

pkill -f "attest-host --enclave-cid" || true
nohup build/out/bin/attest-host --enclave-cid "$CID" --listen 0.0.0.0:8080 >> attest-host.log 2>&1 &
echo "host started (log: $PWD/attest-host.log)"
