# docker build --pull --push --progress plain -t atcr.io/johnandersen777.bsky.social/policy-engine .

# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git curl bash

WORKDIR /src

# Download dependencies (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# BuildKit injects TARGETOS / TARGETARCH from --platform flag.
ARG TARGETOS
ARG TARGETARCH
ARG DENO_VERSION=v2.1.4

# Map Go arch names to Deno's triple naming, download the right zip.
RUN set -eux; \
    GOOS=${TARGETOS:-linux}; \
    GOARCH=${TARGETARCH:-amd64}; \
    case "${GOOS}-${GOARCH}" in \
      linux-amd64)   DENO_TRIPLE=x86_64-unknown-linux-gnu   ;; \
      linux-arm64)   DENO_TRIPLE=aarch64-unknown-linux-gnu  ;; \
      darwin-amd64)  DENO_TRIPLE=x86_64-apple-darwin        ;; \
      darwin-arm64)  DENO_TRIPLE=aarch64-apple-darwin        ;; \
      *) echo "unsupported platform ${GOOS}-${GOARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p common/deno_embedded; \
    curl -fsSL \
      "https://github.com/denoland/deno/releases/download/${DENO_VERSION}/deno-${DENO_TRIPLE}.zip" \
      -o "common/deno_embedded/deno-${GOOS}-${GOARCH}.zip"

# Build static binary with embedded Deno.
RUN set -eux; \
    GOOS=${TARGETOS:-linux}; \
    GOARCH=${TARGETARCH:-amd64}; \
    CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} \
    go build -tags embed_deno -ldflags="-s -w" \
      -o /build/policy-engine ./cmd/policy-engine

# Runtime stage
FROM debian:bookworm-slim

# Install sudo
RUN set -x \
  && apt-get update \
  && apt-get install -y \
       ca-certificates \
       jq \
       curl \
       git \
       sudo \
  && rm -rf /var/lib/apt/lists/*

# Create agent user
RUN useradd -m -s /bin/bash agent

# Setup passwordless sudo
RUN echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/agent && \
    chmod 0440 /etc/sudoers.d/agent

# Copy binary from builder
COPY --from=builder /build/policy-engine /usr/local/bin/policy-engine

# Bundled tangled-specific action replacements.
# Source lives at ../../../bundled-actions/ relative to policy_engine; copied here for build context.
# Mounted at /bundled-actions; spindle passes action_overrides pointing here.
COPY bundled-actions/ /bundled-actions/

# Set working directory
WORKDIR /home/agent

# Switch to agent user
USER agent

# Default command
ENTRYPOINT ["policy-engine"]
