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

RUN T=$(cat /target-triple) \
 && cargo build --release --locked --target "$T" -p attest-enclave -p attest-host -p attest-cli \
 && cargo test --release --locked --target "$T" -p attest-core -p attest-enclave

# CPython compiled to WASI, for the agent's python sandbox. Pinned by hash.
ADD --checksum=sha256:252e2e17fab9f51a51fbfc73d51e18805cb633e9f9200c9753b4b801c70ad32c \
    https://github.com/brettcannon/cpython-wasi-build/releases/download/v3.15.1/python-3.15.1-wasi_sdk-33.zip /tmp/python-wasi.zip
RUN mkdir -p /opt/python-wasi && cd /opt/python-wasi && unzip -q /tmp/python-wasi.zip \
 && find /opt/python-wasi -exec touch -h -d @0 {} +

# Jail image for real agent harnesses: static busybox for the shell, and the
# Codex CLI (static musl build, pinned by the release's published sha256).
ARG CODEX_VERSION=0.164.0
RUN set -eux; mkdir -p /opt/jailroot/bin /opt/jailroot/usr/bin; \
    cp /bin/busybox /opt/jailroot/bin/busybox; \
    for a in $(/bin/busybox --list); do ln -sf /bin/busybox /opt/jailroot/bin/$a; done; \
    if [ "$(cat /target-triple)" = aarch64-unknown-linux-musl ]; then \
      curl -fsSL -o /tmp/codex.tgz https://github.com/openai/codex/releases/download/rust-v${CODEX_VERSION}/codex-aarch64-unknown-linux-musl.tar.gz; \
      echo "29a507a2a3fd8f6cd94b96b762d281d299d15d7902dee6132d314b78cf9108eb  /tmp/codex.tgz" | sha256sum -c; \
      tar -xzf /tmp/codex.tgz -C /tmp; mv /tmp/codex-aarch64-unknown-linux-musl /opt/jailroot/usr/bin/codex; \
      chmod 755 /opt/jailroot/usr/bin/codex; \
    fi; \
    find /opt/jailroot -exec touch -h -d @0 {} +

RUN mkdir -p /out && \
    T=$(cat /target-triple) && \
    cp target/$T/release/attest-enclave target/$T/release/attest-host target/$T/release/attest /out/ && \
    cd /out && sha256sum * > SHA256SUMS

FROM scratch AS artifacts
COPY --from=builder /out/ /

# The enclave image: one static binary, nothing else. The CA roots it uses
# for provider TLS are compiled in (webpki-roots), so they are in PCR0 too.
FROM scratch AS enclave
COPY --from=builder /out/attest-enclave /attest-enclave
COPY --from=builder /opt/python-wasi /opt/python-wasi
COPY --from=builder /opt/jailroot /opt/jailroot
ENTRYPOINT ["/attest-enclave"]
