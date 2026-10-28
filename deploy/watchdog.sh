#!/usr/bin/env bash
# Run every minute by attest-watchdog.timer (installed by deploy/run.sh).
# Starts the enclave if it isn't running (after an instance reboot, or if it
# died), and restarts it if it stops answering /healthz for five minutes in
# a row. A restart ends every session, so it's the last resort: the host
# daemon is restarted separately by systemd and doesn't need this.
set -euo pipefail
# shellcheck source=/dev/null
. /etc/attest/enclave.env   # EIF, CPUS, MEM_MIB, CID, NAME
FAILS=/run/attest-watchdog.fails

start() {
  logger -t attest-watchdog "starting enclave: $1"
  nitro-cli terminate-enclave --enclave-name "$NAME" >/dev/null 2>&1 || true
  nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$EIF" --cpu-count "$CPUS" \
    --memory "$MEM_MIB" --enclave-cid "$CID" >/dev/null
  echo 0 > "$FAILS"
}

if ! nitro-cli describe-enclaves | grep -q "\"EnclaveName\": \"$NAME\""; then
  start "not running"
  exit 0
fi
if curl -sk -m 10 https://127.0.0.1/healthz | grep -q '"ok":true'; then
  echo 0 > "$FAILS"
  exit 0
fi
n=$(( $(cat "$FAILS" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$FAILS"
logger -t attest-watchdog "healthz failed ($n in a row)"
if [ "$n" -ge 5 ]; then
  start "unresponsive for $n minutes"
fi
