# syntax=docker/dockerfile:1.7
#
# Reproducible build of the enclave (and host, CLI) as static musl binaries.
# Pinned: toolchain image by digest, Debian packages via snapshot.debian.org,
# crates via Cargo.lock + --locked, paths/timestamps via remap + SOURCE_DATE_EPOCH.
# Use build/build-eif.sh rather than building this by hand.

FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS builder

ARG DEBIAN_SNAPSHOT=20260801T000000Z
RUN set -eux; \
    printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s bookworm main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends gcc libc6-dev musl-tools unzip busybox-static curl ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# Static musl binary for the build platform: x86_64 for Intel/AMD Nitro
# parents, aarch64 for Graviton. Build natively on the parent's architecture,
# since nitro-cli's kernel blobs (part of PCR0) also differ per architecture.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac > /target-triple && rustup target add "$(cat /target-triple)"

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

ARG ATTEST_GIT_SHA=unknown
ENV ATTEST_GIT_SHA=$ATTEST_GIT_SHA \
    SOURCE_DATE_EPOCH=0 \
    CARGO_INCREMENTAL=0 \
    CARGO_HOME=/cargo \
    RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/cargo=/cargo-home --remap-path-prefix=/usr/local/rustup=/rustup -C target-feature=+crt-static"

# Compiled crates and downloads are kept in cache mounts between builds, so
# a rebuild recompiles only what changed. (Tests run before deploying, not
# here.) The target directory isn't part of the image, so the binaries are
# copied out in the same step.
# FRESH=1 build/build-eif.sh uses empty caches: a from-scratch build, to
# check a release reproduces.
ARG CACHE_ID=shared
RUN --mount=type=cache,id=attest-cargo-registry-$CACHE_ID,target=/cargo/registry \
    --mount=type=cache,id=attest-target-$TARGETARCH-$CACHE_ID,target=/src/target \
    T=$(cat /target-triple) \
 && cargo build --release --locked --target "$T" -p attest-enclave -p attest-host -p attest-cli \
 && mkdir -p /out \
 && cp target/$T/release/attest-enclave target/$T/release/attest-host target/$T/release/attest /out/

# CPython compiled to WASI, for the agent's python sandbox. Pinned by hash.
ADD --checksum=sha256:252e2e17fab9f51a51fbfc73d51e18805cb633e9f9200c9753b4b801c70ad32c \
    https://github.com/brettcannon/cpython-wasi-build/releases/download/v3.15.1/python-3.15.1-wasi_sdk-33.zip /tmp/python-wasi.zip
RUN mkdir -p /opt/python-wasi && cd /opt/python-wasi && unzip -q /tmp/python-wasi.zip \
 && find /opt/python-wasi -exec touch -h -d @0 {} +

RUN cd /out && sha256sum * > SHA256SUMS

# Jail image for the agent harnesses (Codex, Claude Code, pi): busybox and a
# static bash for the shell, each harness pinned by sha256 (pi through its npm lockfile),
# and the few glibc libraries Node and Claude Code load, copied from this
# digest-pinned base image. Built for both architectures so it can be tested
# on an x86 dev machine; enclaves on Graviton use arm64.
FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS jailroot
ARG DEBIAN_SNAPSHOT=20260801T000000Z
RUN set -eux; \
    printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s bookworm main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends busybox-static bash-static curl ca-certificates xz-utils; \
    rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
ARG CODEX_VERSION=0.164.0
ARG CLAUDE_CODE_VERSION=2.1.311
ARG NODE_VERSION=v24.22.0
COPY build/pi/package.json build/pi/package-lock.json /tmp/pi/
# `busybox --list` includes "busybox" itself, which must not be linked over
# the binary. Codex runs its exec tool through codex-code-mode-host.
RUN set -eux; J=/opt/jailroot; mkdir -p $J/bin $J/usr/bin $J/usr/lib $J/lib; \
    cp /bin/busybox $J/bin/busybox; \
    for a in $(/bin/busybox --list); do [ "$a" = busybox ] || ln -sf /bin/busybox $J/bin/$a; done; \
    $J/bin/busybox true; \
    rm -f $J/bin/bash; cp /bin/bash-static $J/bin/bash; $J/bin/bash -c true; \
    case "$TARGETARCH" in \
      arm64) T=aarch64-unknown-linux-musl; N=arm64; \
        CODEX_SHA=29a507a2a3fd8f6cd94b96b762d281d299d15d7902dee6132d314b78cf9108eb; \
        CMH_SHA=0e0bdde24d5b31b05519693635baa9c4f2dc4fe7eee31c67b92155f190dd32d2; \
        CC_SHA=804f385122f395d382cf3dec51e1bec1dd8e5c07078222781a1a251d46d236e5; \
        NODE_SHA=fef00bb4d36e1c50104a9775a10359beee98f162b4104dd12472c75065c6a143 ;; \
      amd64) T=x86_64-unknown-linux-musl; N=x64; \
        CODEX_SHA=90dd0b03b28afcb7fa733a4f73b413db2916a47347efd43fb669cc1c774ee8e4; \
        CMH_SHA=feade7026436baa4e82e898050c7ef82a8adbd98163dc504771275b5ef224f2f; \
        CC_SHA=4353c611f9a33063c5525348a15f1212bdc0085e4a7a81b8370b790003df1b56; \
        NODE_SHA=cc2f601cee82d9a5a233302fe307abc600727035fd7d2c3a3571755989e95008 ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    R=https://github.com/openai/codex/releases/download/rust-v${CODEX_VERSION}; \
    curl -fsSL -o /tmp/codex.tgz $R/codex-$T.tar.gz; \
    echo "$CODEX_SHA  /tmp/codex.tgz" | sha256sum -c; \
    tar -xzf /tmp/codex.tgz -C /tmp; mv /tmp/codex-$T $J/usr/bin/codex; \
    curl -fsSL -o /tmp/cmh.tgz $R/codex-code-mode-host-$T.tar.gz; \
    echo "$CMH_SHA  /tmp/cmh.tgz" | sha256sum -c; \
    tar -xzf /tmp/cmh.tgz -C /tmp; mv /tmp/codex-code-mode-host-$T $J/usr/bin/codex-code-mode-host; \
    curl -fsSL -o /tmp/cc.tgz https://registry.npmjs.org/@anthropic-ai/claude-code-linux-$N/-/claude-code-linux-$N-${CLAUDE_CODE_VERSION}.tgz; \
    echo "$CC_SHA  /tmp/cc.tgz" | sha256sum -c; \
    tar -xzf /tmp/cc.tgz -C /tmp; mv /tmp/package/claude $J/usr/bin/claude; rm -rf /tmp/package; \
    curl -fsSL -o /tmp/node.txz https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-$N.tar.xz; \
    echo "$NODE_SHA  /tmp/node.txz" | sha256sum -c; \
    mkdir -p /tmp/node && tar -xJf /tmp/node.txz -C /tmp/node --strip-components=1; \
    cp /tmp/node/bin/node $J/usr/bin/node; \
    cd /tmp/pi && PATH=/tmp/node/bin:$PATH npm ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error; \
    mkdir -p $J/usr/lib/pi; mv /tmp/pi/node_modules $J/usr/lib/pi/node_modules; \
    printf '#!/bin/sh\nexec /usr/bin/node /usr/lib/pi/node_modules/@mariozechner/pi-coding-agent/dist/cli.js "$@"\n' > $J/usr/bin/pi; \
    chmod 755 $J/usr/bin/*; \
    for b in $J/usr/bin/node $J/usr/bin/claude; do ldd $b; done \
      | awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\/.*ld-linux/ {print $1}' | sort -u > /tmp/libs; \
    cat /tmp/libs; \
    while read l; do case "$l" in */lib64/*) mkdir -p $J/lib64; cp -L "$l" $J/lib64/ ;; *) cp -L "$l" $J/lib/ ;; esac; done < /tmp/libs; \
    chroot $J /usr/bin/node --version; chroot $J /usr/bin/pi --version; \
    find $J -exec touch -h -d @0 {} +

FROM scratch AS artifacts
COPY --from=builder /out/ /

# The enclave image: one static binary, nothing else. The CA roots it uses
# for provider TLS are compiled in (webpki-roots), so they are in PCR0 too.
FROM scratch AS enclave
COPY --from=builder /out/attest-enclave /attest-enclave
COPY --from=builder /opt/python-wasi /opt/python-wasi
COPY --from=jailroot /opt/jailroot /opt/jailroot
ENTRYPOINT ["/attest-enclave"]
