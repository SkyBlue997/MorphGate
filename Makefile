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
        docs-check check dev-up dev-down edge-run edge-smoke lab-egress-check lab-e2e audit fuzz fuzz-lock-check

help: ## List targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z][a-z0-9-]*:.*## / { printf "  %-17s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

proto: ## Regenerate Go protobuf code into control-plane/gen (Rust codegen runs in build.rs)
	scripts/gen-proto.sh

rust-check: ## cargo fmt --check, clippy -D warnings, cargo test (whole workspace)
	cargo fmt --all --check
	cargo fmt --check --manifest-path fuzz/Cargo.toml
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
adapters-check: ## Cloudflare adapter templates and the origin's MG-Origin-Auth check: node:test suites + Worker typecheck
	pnpm -C sdk/web install --frozen-lockfile
	node --test adapters/cloudflare/test/adapters.test.mjs adapters/origin/test/verify-origin-auth.test.mjs
	pnpm -C sdk/web exec tsc -p ../../adapters/cloudflare/worker/tsconfig.json

compose-check: ## Validate the dev docker-compose file (no Docker daemon needed)
	$(COMPOSE) config -q

docs-check: ## Check relative links and #anchors in README.md, CLAUDE.md, docs/; the Phase 2 vectors match their generator (I-47)
	python3 scripts/check_doc_links.py
	node testdata/phase2/gen/kat.mjs --check

check: rust-check wasm-check go-check web-check adapters-check compose-check docs-check ## All lint/test gates (CI also runs edge-smoke, lab-egress-check, proto drift)

# Optional services: COMPOSE_PROFILES=grafana,tunnel,lab make dev-up (or set it in deploy/compose/.env).
dev-up: ## Start the dev environment (Valkey, PostgreSQL, VictoriaMetrics/Logs, mock origin)
	$(COMPOSE) up -d

dev-down: ## Stop the dev environment, including optional profiles (volumes are kept)
	$(COMPOSE) --profile grafana --profile tunnel --profile lab down

# The dev config's cred:// names are the shared test key files (test use only);
# its file:// bundle root must be a readable directory (--check-config).
edge-run: ## Run mg-edge with the dev config (test credentials from testdata/phase1/keys)
	mkdir -p /tmp/morphgate-dev/publish/bundles /tmp/morphgate-dev/publish/artifacts
	CREDENTIALS_DIRECTORY=$(CURDIR)/testdata/phase1/keys cargo run -p mg-edge -- --config $(EDGE_DEV_CONFIG)

edge-smoke: ## Loopback end-to-end: throwaway origin + mg-edge (edge.toml v1, file bundle, local state)
	scripts/edge-smoke.sh

# Needs a running Docker daemon, so it is not part of `check`; CI runs it.
lab-egress-check: ## Validation Lab: assert the allowlist holds at the tool and network-egress layers
	scripts/lab-egress-check.sh

# Not part of `check` (it builds and runs mg-edge, Valkey and an origin); CI
# runs it in its own job with the rust job's mg-edge binary (MG_EDGE_BIN).
lab-e2e: ## Validation Lab Phase 1 scenarios end to end on loopback (mg-edge, valkey-server, mglab)
	scripts/lab-e2e.sh

# Versions match .github/workflows/audit.yml. Needs the network (RustSec
# advisory database, vuln.go.dev, the npm registry), so it is not part of
# `check`; CI runs it on every pull request and weekly.
CARGO_DENY_VERSION := 0.20.2
GOVULNCHECK_VERSION := v1.8.0
audit: ## Dependency audit: cargo-deny (deny.toml), govulncheck, pnpm audit
	@command -v cargo-deny >/dev/null || { echo "audit: install cargo-deny: cargo install cargo-deny --version $(CARGO_DENY_VERSION) --locked"; exit 1; }
	cargo deny --locked check --hide-inclusion-graph
	cd control-plane && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	cd lab && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	pnpm -C sdk/web audit

# Versions match .github/workflows/fuzz.yml. Needs a nightly toolchain and
# cargo-fuzz, so it is not part of `check`; CI runs it daily and on PRs that
# touch a parser crate. New inputs go to fuzz/corpus/<target>/ (ignored);
# fuzz/seeds/<target>/ is read only. A crash stops with its reproducer in
# fuzz/artifacts/<target>/: `cargo +$(FUZZ_TOOLCHAIN) fuzz run <target> <file>`.
FUZZ_TOOLCHAIN := nightly-2026-10-11
CARGO_FUZZ_VERSION := 0.13.2
FUZZ_SECONDS := 60
FUZZ_TARGETS := cf_headers request_limits bundle_verify paths_ret sealed_open clearance_token client_hello submission \
  mg_proof submission_v2 renew ix_telemetry refresh telemetry siteverify_response turnstile_keys

fuzz-lock-check: ## fuzz/Cargo.lock pins the same versions as Cargo.lock (plus the fuzzing crates)
	scripts/check-fuzz-lock.sh

fuzz: fuzz-lock-check ## Fuzz every parser target for FUZZ_SECONDS each (nightly + cargo-fuzz)
	@command -v cargo-fuzz >/dev/null || { echo "fuzz: install cargo-fuzz: cargo install cargo-fuzz --version $(CARGO_FUZZ_VERSION) --locked"; exit 1; }
	@for t in $(FUZZ_TARGETS); do \
	  mkdir -p fuzz/corpus/$$t fuzz/seeds/$$t; \
	  echo "== $$t ($(FUZZ_SECONDS) s)"; \
	  cargo +$(FUZZ_TOOLCHAIN) fuzz run -O $$t fuzz/corpus/$$t fuzz/seeds/$$t -- \
	    -max_total_time=$(FUZZ_SECONDS) -rss_limit_mb=2048 -print_final_stats=1 || exit 1; \
	done
