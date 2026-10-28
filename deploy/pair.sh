#!/usr/bin/env bash
# Failover for a pair of machines (deploy/self-host.sh --standby-for).
# Run every 15 s by attest-pair.timer on both; /etc/attest/pair.env names
# the other machine (PEER, its private IP), the Elastic IP (ALLOC) and REGION.
#
# Each machine's host.json names the other as its peer with standby: true,
# so a restarted enclave (watchdog.sh) only ever rejoins as a standby of the
# other, never starts a new lineage.
#
# This enclave a standby:
#   the other machine's enclave unreachable for a minute -> promote this
#   one (the enclave itself also insists on 20 s without a heartbeat), then
#   move the Elastic IP here.
# This enclave the primary, but the Elastic IP is on the other machine:
#   the other is serving as primary -> it was promoted while this one was
#     cut off: stop this enclave (watchdog.sh restarts it as a standby).
#   else, if this enclave was promoted in the last 3 minutes -> take the
#     address (the move after a promotion, retried).
set -uo pipefail
# shellcheck source=/dev/null
. /etc/attest/pair.env
STATE=/var/lib/attest
mkdir -p "$STATE"
log() { logger -t attest-pair "$*"; }

health() { curl -sk -m 5 "https://$1/api/health"; }
field() { python3 -c "import json,sys
try: v = json.load(sys.stdin)[sys.argv[1]]
except Exception: v = ''
print(str(v).lower())" "$1"; }

LOCAL=$(health 127.0.0.1) || exit 0  # no local enclave: watchdog.sh starts it
L_STANDBY=$(field standby <<<"$LOCAL")
L_BOOT=$(field boot_id <<<"$LOCAL")
[ -n "$L_STANDBY" ] || exit 0
O_STANDBY=$(health "$PEER" | field standby)  # empty: unreachable

if [ "$L_STANDBY" = true ]; then
  if [ -n "$O_STANDBY" ]; then
    echo 0 > "$STATE/peer-fails"
    exit 0
  fi
  n=$(( $(cat "$STATE/peer-fails" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$STATE/peer-fails"
  log "the primary at $PEER is unreachable ($n)"
  [ "$n" -ge 4 ] || exit 0
  TOKEN=$(python3 -c 'import json; print(json.load(open("/etc/attest/host.json"))["handoff_token"])')
  R=$(TOKEN=$TOKEN python3 - <<'EOF'
import hashlib, hmac, json, os, ssl, struct, urllib.request, urllib.error
p = b"attest-replica-promote/1"
h = hashlib.sha256(struct.pack("<Q", len(p)) + p).digest()
mac = hmac.new(os.environ["TOKEN"].encode(), h, hashlib.sha256).hexdigest()
req = urllib.request.Request("https://127.0.0.1/api/internal/replica/promote", data=json.dumps({"mac": mac}).encode(),
                             headers={"Content-Type": "application/json"}, method="POST")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    print(urllib.request.urlopen(req, context=ctx, timeout=600).read().decode())
except urllib.error.HTTPError as e:
    print("HTTP %d %s" % (e.code, e.read().decode(errors="replace")))
except Exception as e:
    print("error %s" % e)
EOF
)
  log "promote: $R"
  if grep -q '"promoted":true' <<<"$R"; then
    echo "$L_BOOT $(date +%s)" > "$STATE/promoted"
    echo 0 > "$STATE/peer-fails"
    L_STANDBY=false
  else
    exit 0
  fi
fi

# This enclave is the primary.
echo 0 > "$STATE/peer-fails"
ME=$(TOK=$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60') \
  && curl -s -m 2 -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/instance-id) || exit 0
HOLDER=$(aws ec2 describe-addresses --region "$REGION" --allocation-ids "$ALLOC" --query 'Addresses[0].InstanceId' --output text 2>/dev/null) || exit 0
[ "$HOLDER" = "$ME" ] && exit 0
if [ "$O_STANDBY" = false ]; then
  log "the other machine serves as primary with the address; stopping this enclave to rejoin as its standby"
  . /etc/attest/enclave.env
  nitro-cli terminate-enclave --enclave-name "$NAME" >/dev/null
  exit 0
fi
read -r PB PT < "$STATE/promoted" 2>/dev/null || { PB=""; PT=0; }
if [ "$PB" = "$L_BOOT" ] && [ $(( $(date +%s) - PT )) -lt 180 ]; then
  if aws ec2 associate-address --region "$REGION" --allocation-id "$ALLOC" --instance-id "$ME" --allow-reassociation >/dev/null; then
    log "moved the Elastic IP here after promotion"
  else
    log "couldn't move the Elastic IP yet; retrying"
  fi
else
  log "primary without the Elastic IP (held by $HOLDER), not recently promoted; leaving it"
fi
