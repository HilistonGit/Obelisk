# syntax=docker/dockerfile:1.7
#
# Obelisk container image.
#
# Built with buildx for several architectures at once:
#
#   docker buildx build -f docker/Dockerfile \
#     --platform linux/amd64,linux/arm64,linux/arm/v7 \
#     -t obelisk:latest --load .
#
# The cores are baked in as a starting point but are never linked into Obelisk:
# they stay separate executables in /usr/local/bin, and "obelisk core update"
# installs newer ones into the /etc/obelisk volume, which takes precedence. That
# is what makes a core upgrade a file swap rather than an image rebuild.

ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.22

# ---------------------------------------------------------------------------
# Build the Obelisk binary for the target platform.
#
# The compiler runs natively on the build host and cross-compiles, which is far
# faster than emulating the target — and possible at all only because Obelisk is
# pure Go with CGO disabled.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    export CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}"; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
      armv5)          export GOARM=5 ;; \
      armv6)          export GOARM=6 ;; \
      armv7|arm)      export GOARM=7 ;; \
      mips|mipsle|mips64|mips64le) export GOMIPS=softfloat ;; \
    esac; \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/obelisk ./cmd/obelisk

# ---------------------------------------------------------------------------
# Fetch the cores for the target platform.
#
# This uses Obelisk's own core installer rather than hand-written curl calls, so
# the image is built by exactly the code path that will later update the cores in
# place — including checksum verification where the publisher offers one.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS cores

RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

# A host-native build, because this one has to actually run during the build.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /usr/local/bin/obelisk-host ./cmd/obelisk

ARG TARGETARCH
ARG TARGETVARIANT
# GITHUB_TOKEN is optional and only raises the API rate limit; anonymous builds
# work fine. Passed as a secret so it never lands in an image layer.
RUN --mount=type=secret,id=github_token,required=false \
    set -eux; \
    # The runtime image is Alpine, which is musl. sing-box publishes separate
    # builds per C library, and the default one fails to exec with ENOENT on
    # musl — so the target must say "musl" or the image ships a core that
    # cannot start.
    case "${TARGETARCH}${TARGETVARIANT}" in \
      armv5)      TARGET="linux/arm/5/musl" ;; \
      armv6)      TARGET="linux/arm/6/musl" ;; \
      armv7|arm)  TARGET="linux/arm/7/musl" ;; \
      mips)       TARGET="linux/mips/softfloat/musl" ;; \
      mipsle)     TARGET="linux/mipsle/softfloat/musl" ;; \
      *)          TARGET="linux/${TARGETARCH}/musl" ;; \
    esac; \
    if [ -f /run/secrets/github_token ]; then \
        GITHUB_TOKEN="$(cat /run/secrets/github_token)"; export GITHUB_TOKEN; \
    fi; \
    obelisk-host core install all -target "${TARGET}" -dir /cores

# ---------------------------------------------------------------------------
# Runtime image.
# ---------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION}

# nftables and iproute2 are what the transparent modes are built on; ca-
# certificates is needed to fetch subscriptions and core updates at all.
RUN apk add --no-cache \
        ca-certificates \
        tzdata \
        nftables \
        iptables \
        ip6tables \
        iproute2 \
    && rm -rf /var/cache/apk/*

COPY --from=build  /out/obelisk        /usr/local/bin/obelisk
COPY --from=cores  /cores/sing-box     /usr/local/bin/sing-box
COPY --from=cores  /cores/xray         /usr/local/bin/xray
COPY docker/entrypoint.sh              /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/obelisk \
             /usr/local/bin/sing-box \
             /usr/local/bin/xray \
             /usr/local/bin/entrypoint.sh

# Configuration, state and any updated cores live here. Mount it to keep them.
VOLUME ["/etc/obelisk"]
ENV OBELISK_DIR=/etc/obelisk

# The web interface, once it lands. The transparent-mode listeners are not
# exposed here because those modes require host networking anyway.
EXPOSE 24080

# Naming sing-box explicitly makes this strict: the command exits non-zero if the
# front core is missing or cannot report its own version. Xray is deliberately
# not checked — a subscription that needs no Xray-only protocol never installs
# it, and that is a healthy state, not a degraded one.
#
# This checks the cores rather than Obelisk's own liveness; it becomes a real
# health endpoint once the API lands.
HEALTHCHECK --interval=60s --timeout=15s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/obelisk", "core", "status", "sing-box", "-offline", "-dir", "/etc/obelisk/bin"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# The daemon is the product: it serves the web interface, exposes the API, and
# runs the cores from the stored configuration. Everything else the binary can do
# is a subcommand of the same image.
CMD ["daemon"]
