#!/usr/bin/env bash
# Fast dev deploy of the primary (about a minute). Cross-compiles the
# binaries on this machine, puts the new enclave binary on top of the last
# full image on the primary, builds the EIF there and restarts.
#
#   deploy/fast.sh [--name attest]
#
# Not reproducible: PCR0 won't match build/build-eif.sh, and no measurements
# are published, so `attest verify-service` / `attest open` can't check it.
# Deploys the working tree as is (no commit or push needed). The Python
# runtime and the agent jail come from the last full image, so changes to
# build/Dockerfile or build/pi need a full deploy/self-host.sh. Stops the
# standby (a new image starts a new lineage); a full deploy restores it.
#
# Needs: rustup target aarch64-unknown-linux-musl, cargo-zigbuild (and zig)
# on PATH, zstd.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=attest
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
STATE_DIR=${STATE_DIR:-$HOME/.config/attest}
IP=$( (source "$STATE_DIR/$NAME.env"; printf %s "$IP") )
BUCKET=$( (source "$STATE_DIR/$NAME.env"; printf %s "${BUCKET:-}") )
REGION=$( (source "$STATE_DIR/$NAME.env"; printf %s "${REGION:-us-west-2}") )
KEY="$STATE_DIR/$NAME-key.pem"
[ -f "$KEY" ] || KEY="$STATE_DIR/attest-key.pem"
SSH=(ssh -i "$KEY" -o UserKnownHostsFile="$STATE_DIR/$NAME.known_hosts" -o BatchMode=yes "ec2-user@$IP")
t0=$(date +%s)
step() { printf '[%3ds] %s\n' "$(( $(date +%s) - t0 ))" "$*"; }

SHA=$(git rev-parse HEAD)
[ -z "$(git status --porcelain --untracked-files=no)" ] || SHA="$SHA-dirty"
export PATH="$HOME/.local/zigvenv/bin:$PATH"
step "compiling $SHA for arm64"
ATTEST_GIT_SHA=$SHA RUSTFLAGS="-C target-feature=+crt-static" \
  cargo zigbuild -q --release --target aarch64-unknown-linux-musl -p attest-enclave -p attest-host
OUT=target/aarch64-unknown-linux-musl/release
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
zstd -q -3 -T0 "$OUT/attest-enclave" -o "$TMP/attest-enclave.zst"
zstd -q -3 -T0 "$OUT/attest-host" -o "$TMP/attest-host.zst"

step "uploading"
"${SSH[@]}" 'mkdir -p ~/fast'
scp -q -i "$KEY" -o UserKnownHostsFile="$STATE_DIR/$NAME.known_hosts" "$TMP"/*.zst "ec2-user@$IP:fast/"

# The standby holds the old lineage's keys and would take over while the
# primary restarts.
SB_STATE="$STATE_DIR/$NAME-standby.env"
if [ -f "$SB_STATE" ]; then
  SB_IP=$( (source "$SB_STATE"; printf %s "${IP:-}") )
  ssh -i "$KEY" -o UserKnownHostsFile="$STATE_DIR/$NAME-standby.known_hosts" -o ConnectTimeout=10 -o BatchMode=yes "ec2-user@$SB_IP" \
    'sudo systemctl disable --now attest-pair.timer attest-watchdog.timer >/dev/null 2>&1; nitro-cli terminate-enclave --all >/dev/null 2>&1; true' &
fi

step "building the EIF and restarting"
"${SSH[@]}" "set -euo pipefail
  cd ~/fast && zstd -q -d -f attest-enclave.zst attest-host.zst && chmod +x attest-enclave attest-host
  # The image to build on: the last full build's (self-host.sh records it).
  B=\$(cat ~/attest-src/build/out/built-commit 2>/dev/null || true)
  case \"\$B\" in fast-*|'') ;; *) echo \"\$B\" > base-commit ;; esac
  BASE=attest-enclave:\$(cat base-commit)
  docker image inspect \"\$BASE\" >/dev/null
  printf 'FROM %s\nCOPY attest-enclave /attest-enclave\n' \"\$BASE\" > Dockerfile
  docker build -q -t attest-enclave:fast . >/dev/null
  O=~/attest-src/build/out
  nitro-cli build-enclave --docker-uri attest-enclave:fast --output-file \$O/attest.eif > \$O/pcrs.json
  install -m 755 attest-host \$O/bin/attest-host
  echo 'fast-$SHA' > \$O/built-commit
  sudo rm -f /etc/attest/pair.env /var/lib/attest/promoted
  # Start as a lone primary, not by taking over from the (stopped) standby.
  sudo python3 -c 'import json; p=\"/etc/attest/host.json\"; c=json.load(open(p)); c.pop(\"peer\",None); c.pop(\"standby\",None); open(p,\"w\").write(json.dumps(c))'
  cd ~/attest-src && S3_BUCKET='$BUCKET' S3_REGION='$REGION' deploy/run.sh >/dev/null
  for i in \$(seq 30); do curl -sk -m 3 https://127.0.0.1/healthz | grep -q '\"ok\":true' && exit 0; sleep 1; done
  echo 'service did not come up; see ~/attest-host.log' >&2; exit 1"
wait
step "live: $SHA on https://$IP (standby stopped; deploy/self-host.sh --standby-for $NAME restores it)"
