#!/usr/bin/env bash
# Build the enclave image (EIF) reproducibly and print its PCRs.
#
# Needs Linux, docker with buildx, and (for the EIF step) nitro-cli. It does
# not need Nitro hardware, so auditors can run it to reproduce PCR0 and pin it
# with `attest verify --pcrs build/out/pcrs.json`.
#
#   build/build-eif.sh            binaries + EIF + pcrs.json
#   build/build-eif.sh --bins     binaries only (no nitro-cli needed)
#
# Rebuilds reuse compiled crates (a cache in the docker builder), so only
# what changed recompiles. FRESH=1 builds from scratch, with no cache: do
# that to check a release reproduces.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$PWD/build/out"
mkdir -p "$OUT/bin"

GIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo unknown)
if [ "$GIT_SHA" != unknown ] && [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "note: dirty working tree; PCRs will not match a clean checkout" >&2
  GIT_SHA="$GIT_SHA-dirty"
fi
TAG="attest-enclave:$GIT_SHA"

export DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=0
BUILDER=attest-builder
docker buildx inspect "$BUILDER" >/dev/null 2>&1 || docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
# Default to this machine's architecture: Graviton parents need arm64.
case "${ARCH:-$(uname -m)}" in
  x86_64|amd64) PLATFORM=linux/amd64 ;;
  aarch64|arm64) PLATFORM=linux/arm64 ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
echo "== platform $PLATFORM"
COMMON=(--builder "$BUILDER" --file build/Dockerfile --build-arg SOURCE_DATE_EPOCH=0 --build-arg "ATTEST_GIT_SHA=$GIT_SHA" --platform "$PLATFORM")
if [ -n "${FRESH:-}" ]; then
  COMMON+=(--no-cache --build-arg "CACHE_ID=fresh-$(date +%s)-$$")
  echo "== from scratch (no caches)"
fi

echo "== binaries"
docker buildx build "${COMMON[@]}" --target artifacts --output "type=local,dest=$OUT/bin" .
cat "$OUT/bin/SHA256SUMS"
[ "${1:-}" = "--bins" ] && exit 0

echo "== enclave image"
docker buildx build "${COMMON[@]}" --target enclave \
  --output "type=docker,name=$TAG,rewrite-timestamp=true,dest=$OUT/enclave-image.tar" .
docker load -i "$OUT/enclave-image.tar"

echo "== EIF"
# nitro-cli's kernel/init blobs are part of PCR0, so its version is pinned.
NITRO_CLI_EXPECTED=${NITRO_CLI_EXPECTED:-"Nitro CLI 1.5.0"}
V=$(nitro-cli --version 2>&1 | head -1)
[ "$V" = "$NITRO_CLI_EXPECTED" ] || { echo "error: $V installed, expected $NITRO_CLI_EXPECTED" >&2; exit 1; }
rm -f "$OUT/attest.eif"
nitro-cli build-enclave --docker-uri "$TAG" --output-file "$OUT/attest.eif" > "$OUT/pcrs.json"
cat "$OUT/pcrs.json"
cat > "$OUT/build-info.json" <<JSON
{"git_sha": "$GIT_SHA", "nitro_cli": "$V", "eif_sha256": "$(sha256sum "$OUT/attest.eif" | cut -d' ' -f1)"}
JSON
echo "== done: $OUT"
