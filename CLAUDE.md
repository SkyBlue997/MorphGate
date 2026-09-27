# CLAUDE.md

MorphGate is a **defensive** bot-management platform. Its single owner runs it only in front of their own few websites: no tenants, no SaaS, no hosting it for others. Rust data plane (Pingora Edge + a pure Decision Core) and Go control plane; Cloudflare in front (Cloudflare → Tunnel → Edge on 127.0.0.1 → origin). Design docs are in Chinese; code, comments and commit messages are in English.

## Scope boundary (non-negotiable)

- Defensive only: detect, classify, challenge, rate-limit and audit traffic to the owner's own sites.
- Never write code, tests, fixtures or docs that attack, evade, spoof or bypass any bot protection, CAPTCHA or WAF, including Cloudflare's (Bot Fight Mode, Managed Challenge, Turnstile) and third-party solver services. Cloudflare work means configuring the owner's own zone through its documented APIs.
- The Validation Lab (`lab/`) sends traffic only to allowlisted targets (loopback, `*.test`, registered owner-controlled hosts). The allowlist is enforced in code (`lab/internal/guard`) and by the isolated `lab` compose network; never weaken or bypass either. Apart from the Lab, test traffic stays on the local machine: loopback tests (`scripts/edge-smoke.sh`, `edge/tests/`, Go `httptest`) and `scripts/lab-egress-check.sh` (local Docker networks only).
- Client-side signal collection is data-minimal (see [06 §7](docs/06-policy-console-observability.md#7-隐私与合规)).

## Layout

| Path | Contents |
|---|---|
| `Cargo.toml` | Rust workspace (edition 2024, MSRV 1.88): `core`, `challenge`, `intel`, `edge`, `proto/rust` |
| `core/` | `mg-core`: pure Decision Core. No I/O, threads, tokio or wall clock (time is passed in); must build for `wasm32-unknown-unknown` |
| `edge/` | `mg-edge`: Pingora (`=0.9.0`, BoringSSL) binary. All Pingora-specific code stays here. Dev config in `edge/config/edge.dev.toml` |
| `challenge/` | `mg-challenge` (Phase 1): sealed challenges, epoch keys, SHA-256 PoW, PASETO v4.local clearance tokens. No I/O; time and RNG are injected |
| `intel/` | `mg-intel` (Phase 1): IP prefix sets, GeoLite2 mmdb lookups, crawler registry + verification (DNS behind a trait), Cloudflare IP ranges |
| `proto/morphgate/v1/` | Shared protobuf contract. Rust: `proto/rust` (`mg-proto`, protox in build.rs). Go: generated into `control-plane/gen` and committed |
| `control-plane/` | Go module: `cmd/mgctl`, `cmd/mg-control`, `internal/...` |
| `lab/` | Go module: Validation Lab (`internal/guard` allowlist, `cmd/mglab`; `Dockerfile` for the isolated compose network) |
| `sdk/web/` | TypeScript Web SDK (`@morphgate/web-sdk`, pnpm, esbuild, vitest) |
| `adapters/cloudflare/` | Transform Rule, Cache Rule, WAF Skip, Snippet and Worker templates for the owner's zone |
| `deploy/compose/` | Dev environment: Valkey, PostgreSQL, VictoriaMetrics, VictoriaLogs (`vl-main` 30d, `vl-short` 7d), mock origin; optional profiles `grafana`, `tunnel` (cloudflared) and `lab` (Validation Lab on an internal network) |
| `deploy/systemd/` | `mg-edge.service` (Pingora graceful upgrade via `systemctl reload`) and `edge.toml.example`, kept in sync by `edge/tests/shipped_configs.rs` |
| `scripts/` | `gen-proto.sh`, `check_doc_links.py`, `edge-smoke.sh`, `lab-egress-check.sh` |
| `testdata/` | Cross-component fixtures: `phase1/kat.json` (crypto / PoW known-answer vectors), `policy-ir/` (Go ↔ Rust policy IR conformance) |

## Commands

| Command | What it does |
|---|---|
| `make check` | All lint/test gates: `rust-check wasm-check go-check web-check adapters-check compose-check docs-check`. CI additionally runs `edge-smoke`, `lab-egress-check`, the Pingora pin check and the `make proto` drift check |
| `make rust-check` | `cargo fmt --check`, `clippy -D warnings`, `cargo test` for the workspace |
| `make wasm-check` | `cargo check -p mg-core --target wasm32-unknown-unknown`; skipped locally when the target is not installed (Homebrew rustc), always run in CI |
| `make go-check` / `make web-check` | `go vet` + `go test` in `control-plane` and `lab`; Web SDK install + `check` script |
| `make adapters-check` | Cloudflare adapter templates: `node --test` suite + Worker typecheck |
| `make proto` | Regenerate Go protobuf code (commit the result; CI fails on drift) |
| `make compose-check` / `make docs-check` | Validate the compose file; check relative links and anchors in README, CLAUDE.md, docs/ |
| `make dev-up` / `make dev-down` | Start / stop the dev environment (`COMPOSE_PROFILES=grafana,tunnel,lab` for the optional services) |
| `make edge-run` / `make edge-smoke` | Run mg-edge with the dev config; loopback end-to-end smoke test |
| `make lab-egress-check` | Needs a Docker daemon (CI runs it): the Lab allowlist holds at the tool and network-egress layers |

## Design docs

- [README.md](README.md) indexes the design docs `docs/01`–`docs/10` and the ADRs in [docs/adr/](docs/adr/README.md). The threat model is [docs/10](docs/10-threat-model.md); the phase plan is [docs/07](docs/07-roadmap.md). Phase 0 is the skeleton; features start in Phase 1.
- The Phase 1 implementation spec is [docs/impl/phase1-spec.md](docs/impl/phase1-spec.md): work packages, file ownership and every cross-component contract. Change a contract there first, then in code.
- Other docs link to heading anchors, so keep heading text stable or fix every link (`make docs-check` catches breakage).

## Conventions

- Stubs compile and name the phase that implements them; no placeholder "implement everything" files.
- Every component ships meaningful tests. Keep `make check` green.
- Change `proto/` semantics only deliberately, then run `make proto` and update both languages.
- Pingora is 0.x and breaks on every minor release: bump it only on purpose, in `edge/` only.
- CI pins every action to a full commit SHA with the release in a comment, and checks downloaded tools against a SHA-256; keep both when bumping.
- The Edge decides `/__mg` ownership on the raw path and on Cloudflare's normalized forms (`edge/src/routes.rs`); keep it that way so Cloudflare's `/__mg/` skip and cache rules never apply to a request that reaches the origin.
