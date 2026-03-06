# Policy Engine Makefile
#
# Supports building with embedded Deno binary for multi-arch/platform.
#
# Usage:
#   make build                        # Build without embedded Deno (downloads on first run)
#   make build-embed                  # Build with embedded Deno for current platform
#   make release-build                # goreleaser snapshot (local multi-platform build)
#   make download-deno-all            # Download Deno for ALL supported platforms
#   make test                         # Run tests
#
# Environment:
#   DENO_VERSION  - Deno version to download (default: v2.1.4)

DENO_VERSION ?= v2.1.4
BINARY_NAME  = policy_engine
EMBED_DIR    = common/deno_embedded

# Platform matrix: <goos>-<goarch> -> Deno release artifact
DENO_TARGETS = \
	linux-amd64=deno-x86_64-unknown-linux-gnu.zip \
	linux-arm64=deno-aarch64-unknown-linux-gnu.zip \
	darwin-amd64=deno-x86_64-apple-darwin.zip \
	darwin-arm64=deno-aarch64-apple-darwin.zip \
	windows-amd64=deno-x86_64-pc-windows-msvc.zip

DENO_BASE_URL = https://github.com/denoland/deno/releases/download/$(DENO_VERSION)

# Current platform for single-platform builds
HOST_GOOS   ?= $(shell go env GOOS)
HOST_GOARCH ?= $(shell go env GOARCH)

.PHONY: build build-embed release-build download-deno-all test clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

build: ## Build without embedded Deno (downloads on first run)
	go build -o $(BINARY_NAME) ./cmd/policy-engine/

build-embed: download-deno-all ## Build with embedded Deno for current platform
	go build -tags embed_deno -o $(BINARY_NAME) ./cmd/policy-engine/

release-build: download-deno-all ## goreleaser snapshot (local multi-platform build)
	goreleaser release --snapshot --clean

download-deno-all: ## Download Deno zips for ALL supported platforms (parallel-safe)
	@mkdir -p $(EMBED_DIR)
	@for entry in $(DENO_TARGETS); do \
		platform=$$(echo "$$entry" | cut -d= -f1); \
		artifact=$$(echo "$$entry" | cut -d= -f2); \
		dest="$(EMBED_DIR)/deno-$$platform.zip"; \
		if [ -f "$$dest" ]; then \
			echo "  [cached] $$dest"; \
		else \
			echo "  [fetch]  $(DENO_BASE_URL)/$$artifact -> $$dest"; \
			curl -fSL -o "$$dest" "$(DENO_BASE_URL)/$$artifact" || \
				{ echo "FAILED: $$dest"; rm -f "$$dest"; exit 1; }; \
		fi; \
	done
	@echo "All Deno platform zips ready in $(EMBED_DIR)/"

test: ## Run tests
	go test -count=1 -timeout 120s ./...

test-verbose: ## Run tests with verbose output
	go test -count=1 -timeout 120s -v ./...

clean: ## Remove build artifacts and downloaded Deno zips
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f $(EMBED_DIR)/deno-*.zip
	rm -rf dist/
	rm -rf .tempdir/ .cache/
