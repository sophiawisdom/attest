#!/usr/bin/env bash
# Run every minute by attest-watchdog.timer (installed by deploy/run.sh).
#
# Starts the enclave only when it isn't running (after an instance reboot,
# or if it died). It never restarts a running enclave: that ends every
# session and loses their keys, and a failed health check here usually
# means the host daemon (which carries all traffic to the enclave) is the
# problem. So when /healthz keeps failing, it restarts the host daemon.
set -euo pipefail
# shellcheck source=/dev/null
. /etc/attest/enclave.env   # EIF, CPUS, MEM_MIB, CID, NAME
FAILS=/run/attest-watchdog.fails

if ! nitro-cli describe-enclaves | grep -q "\"EnclaveName\": \"$NAME\""; then
  logger -t attest-watchdog "enclave not running; starting it"
  nitro-cli run-enclave --enclave-name "$NAME" --eif-path "$EIF" --cpu-count "$CPUS" \
    --memory "$MEM_MIB" --enclave-cid "$CID" >/dev/null
  echo 0 > "$FAILS"
  exit 0
fi
if curl -sk -m 10 https://127.0.0.1/healthz | grep -q '"ok":true'; then
  echo 0 > "$FAILS"
  exit 0
fi
n=$(( $(cat "$FAILS" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$FAILS"
logger -t attest-watchdog "healthz failed ($n in a row)"
if [ "$n" -ge 3 ]; then
  logger -t attest-watchdog "restarting the host daemon (the enclave is left running)"
  systemctl restart attest-host
  echo 0 > "$FAILS"
fi
