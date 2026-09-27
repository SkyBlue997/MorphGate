# MorphGate developer entry points. Run `make help` for the list.
# Works with the GNU Make 3.81 that ships with macOS (no .ONESHELL / .SHELLFLAGS).

.DEFAULT_GOAL := help
MAKEFLAGS += --no-builtin-rules

COMPOSE_FILE    := deploy/compose/docker-compose.yml
COMPOSE         := docker compose -f $(COMPOSE_FILE)
EDGE_DEV_CONFIG := edge/config/edge.dev.toml
WASM_TARGET     := wasm32-unknown-unknown

# The Edge uses BoringSSL (built from source by boring-sys, needs cmake + clang).
# If any crate ever pulls in openssl-sys instead, point it at Homebrew's
# OpenSSL on macOS unless the caller already set OPENSSL_DIR. Harmless otherwise.
ifeq ($(origin OPENSSL_DIR),undefined)
  BREW_OPENSSL := $(firstword $(wildcard /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3))
  ifneq ($(BREW_OPENSSL),)
    export OPENSSL_DIR := $(BREW_OPENSSL)
  endif
endif

.PHONY: help proto rust-check wasm-check go-check web-check adapters-check compose-check \
        docs-check check dev-up dev-down edge-run edge-smoke lab-egress-check

help: ## List targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z][a-z-]*:.*## / { printf "  %-17s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

proto: ## Regenerate Go protobuf code into control-plane/gen (Rust codegen runs in build.rs)
	scripts/gen-proto.sh

rust-check: ## cargo fmt --check, clippy -D warnings, cargo test (whole workspace)
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace

# Homebrew's rustc ships without the wasm target, so the check is skipped
# locally when the target's std is missing. CI sets MG_REQUIRE_WASM=1 so a
# missing target fails there instead of being skipped silently.
wasm-check: ## cargo check mg-core for wasm32-unknown-unknown (skips if the target is not installed)
	@if [ -d "$$(rustc --print sysroot)/lib/rustlib/$(WASM_TARGET)/lib" ]; then \
		echo "cargo check -p mg-core --target $(WASM_TARGET)"; \
		cargo check -p mg-core --target $(WASM_TARGET); \
	elif [ -n "$${MG_REQUIRE_WASM:-}" ]; then \
		echo "wasm-check: Rust target $(WASM_TARGET) is not installed (MG_REQUIRE_WASM is set)" >&2; \
		exit 1; \
	else \
		echo "wasm-check: SKIPPED - Rust target $(WASM_TARGET) is not installed for $$(rustc --version)."; \
		echo "            Install it (rustup target add $(WASM_TARGET)) to run locally; CI always runs it."; \
	fi

go-check: ## go vet + go test in control-plane and lab
	cd control-plane && go vet ./... && go test ./...
	cd lab && go vet ./... && go test ./...

web-check: ## Web SDK: pnpm install --frozen-lockfile, then its check script
	pnpm -C sdk/web install --frozen-lockfile
	pnpm -C sdk/web run check

# The Worker typecheck borrows sdk/web's pinned TypeScript, hence the install.
adapters-check: ## Cloudflare adapter templates: node:test suite + Worker typecheck
	pnpm -C sdk/web install --frozen-lockfile
	node --test adapters/cloudflare/test/adapters.test.mjs
	pnpm -C sdk/web exec tsc -p ../../adapters/cloudflare/worker/tsconfig.json

compose-check: ## Validate the dev docker-compose file (no Docker daemon needed)
	$(COMPOSE) config -q

docs-check: ## Check relative links and #anchors in README.md, CLAUDE.md, docs/
	python3 scripts/check_doc_links.py

check: rust-check wasm-check go-check web-check adapters-check compose-check docs-check ## All lint/test gates (CI also runs edge-smoke, lab-egress-check, proto drift)

# Optional services: COMPOSE_PROFILES=grafana,tunnel,lab make dev-up (or set it in deploy/compose/.env).
dev-up: ## Start the dev environment (Valkey, PostgreSQL, VictoriaMetrics/Logs, mock origin)
	$(COMPOSE) up -d

dev-down: ## Stop the dev environment, including optional profiles (volumes are kept)
	$(COMPOSE) --profile grafana --profile tunnel --profile lab down

edge-run: ## Run mg-edge with the dev config
	cargo run -p mg-edge -- --config $(EDGE_DEV_CONFIG)

edge-smoke: ## Start a throwaway origin + mg-edge on loopback and assert healthz/proxy/metrics
	scripts/edge-smoke.sh

# Needs a running Docker daemon, so it is not part of `check`; CI runs it.
lab-egress-check: ## Validation Lab: assert the allowlist holds at the tool and network-egress layers
	scripts/lab-egress-check.sh
