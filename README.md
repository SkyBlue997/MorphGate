# MorphGate

Defensive bot-management and traffic-security platform for owner-controlled web properties.

MorphGate sits behind an existing CDN (Cloudflare first) as a reverse proxy in front of web properties you operate. It combines a Rust/Pingora Edge, a pure decision core, a Go operations CLI and a first-party browser SDK. Phase 1 provides request risk scoring, policy enforcement, rate limiting, proof-of-work challenges, short-lived clearance tokens, crawler verification and audit logs. Phase 2 adds the Web SDK v1 with browser session keys and request proofs (`MG-Proof`), a self-built accessible interactive challenge (press and hold, single activation, or an automatic proof-of-work path), optional Cloudflare Turnstile with automatic fallback, silent clearance refresh, SDK telemetry and a near-line detection worker. Validation traffic is restricted to explicitly allowlisted targets.

[Getting started](docs/getting-started.md) · [Releases](https://github.com/SkyBlue997/MorphGate/releases) · [Security policy](SECURITY.md) · [Maintainers](MAINTAINERS.md) · [Apache-2.0](LICENSE)

**Status:** source preview. Phase 1 runs in monitor mode on a real Cloudflare zone while its acceptance checks are completed ([Phase 1 status](docs/impl/phase1-status.md)). The Phase 2 code is merged and every Phase 2 feature stays off until a site's bundle opts in: with `schema_version = 1` the new Edge behaves exactly as Phase 1 ([Phase 2 status](docs/impl/phase2-status.md)). CI validates the implementation and loopback integration, including the Validation Lab scenarios.

Browser assets are available as [`@ermiaodada/morphgate-web-sdk`](https://www.npmjs.com/package/@ermiaodada/morphgate-web-sdk): see the [npm installation guide](sdk/web/README.md) for the pinned preview version and Edge deployment instructions.

## Overview

| Area | Summary |
|---|---|
| Deployment | `Cloudflare → Cloudflare Tunnel → mg-edge (loopback) → origin`; without a CDN the Edge can terminate TLS itself ([08](docs/08-upstream-and-cloudflare.md)) |
| Data plane | `mg-edge` (Pingora 0.9, BoringSSL) evaluates every request with `mg-core`, a pure decision core that also builds for `wasm32-unknown-unknown` |
| Challenges and tokens | Sealed challenges, SHA-256 proof of work and PASETO v4.local clearance tokens served first-party under `/__mg/` ([04](docs/04-challenge-and-tokens.md)); Phase 2: interactive challenges with accessible paths, key-bound tokens, request proofs and refresh ([09](docs/09-interactive-challenge.md)) |
| Policy | Site YAML compiled by `mgctl` into a signed configuration bundle; per-route sensitivity, rate limits and challenge requirements ([06](docs/06-policy-console-observability.md)) |
| Intelligence | Crawler registry with forward-confirmed reverse DNS, Cloudflare IP ranges, GeoLite2 lookups |
| State and events | Valkey for replay and rate-limit state with a local fallback; decision events to VictoriaLogs; metrics to VictoriaMetrics; Phase 2: the `mg-nearline` worker reads the event stream and writes risk-raising verdicts |
| Footprint | Small deployments: 1–3 VMs, no Kafka or Kubernetes ([ADR-0007](docs/adr/0007-lean-deployment.md)) |
| Stack | Rust data plane and Go control plane ([ADR-0001](docs/adr/0001-tech-stack-rust-go.md)) |

## Scope

- MorphGate is defensive software: it detects, classifies, challenges, rate-limits and audits traffic to web properties its operator controls. It is not a hosted service. This engineering scope adds no restriction to the [Apache-2.0](LICENSE) license. The current build contains no JA4+ code; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [ADR-0009](docs/adr/0009-ja4-only-licensing.md) for third-party licensing.
- All security testing and validation run on local environments, owner-controlled test environments and owner-controlled sites. The Validation Lab enforces a target allowlist in code and through an isolated network, and refuses any other host.
- The project does not research, reproduce or provide ways around any third-party bot protection or CAPTCHA product, including Cloudflare and Turnstile. Mature products are referenced only through their public documentation.
- Client-side signal collection is data-minimal. Visitor data on protected sites remains subject to privacy law such as the PIPL; complete a privacy and compliance review before going live ([06 §7](docs/06-policy-console-observability.md#7-隐私与合规)).

## Design documents

The design documents and ADRs are written in Chinese; code, comments and commit messages are in English.

| Document | Contents |
|---|---|
| [01 Architecture](docs/01-architecture.md) | Design principles, layered architecture, components, integration modes, signal availability, deployment and technology choices |
| [02 Data flow](docs/02-data-flow.md) | Inline fast path, near-line and offline pipelines, configuration distribution, SDK telemetry, event pipeline, core data model |
| [03 Signals and risk scoring](docs/03-risk-scoring.md) | Signal taxonomy, scoring model, tiered actions, session and behaviour analysis, evaluation metrics |
| [04 Challenges and clearance tokens](docs/04-challenge-and-tokens.md) | Challenge types and flows, short-lived tokens and binding, proof of possession, replay protection, rate limiting |
| [05 AI agent policy](docs/05-ai-agent-policy.md) | Agent classification, Web Bot Auth, authorization registry, test authorization tickets, crawler policy |
| [06 Policy engine, console and audit](docs/06-policy-console-observability.md) | Policy model and CEL, release process, console, logs, metrics and audit, privacy and compliance, platform security |
| [07 Roadmap](docs/07-roadmap.md) | Phased milestones, deliverables and acceptance criteria |
| [08 Upstream integration and Cloudflare](docs/08-upstream-and-cloudflare.md) | UpstreamProfile, origin protection, trusted client IP, `x-mg-cf-*` signal forwarding, cache and Cloudflare bot feature coexistence, other CDN signal tables |
| [09 Interactive challenge](docs/09-interactive-challenge.md) | Press-and-hold verification, accessible path, sealed challenges, provider interface and Turnstile adapter, telemetry and server-side scoring |
| [10 Threat model](docs/10-threat-model.md) | STRIDE v1: assets, trust boundaries, per-component threats (including the Phase 2 components), platform abuse and false positives, residual risk |
| [Privacy notice template](docs/privacy-notice-template.md) | Template for the protected site's privacy notice: data processed by the security service, cookies and storage, retention, Turnstile; update it before any new client signal goes live |
| [Architecture decision records](docs/adr/README.md) | Technology stack, Edge and TLS, upstream model, origin protection, token and sealed-challenge formats, policy language, lean deployment, interactive challenge, JA4 licensing, operator model and key custody, local emergency monitor switch |

The design documents describe the target design for every phase and mark what Phase 1 and Phase 2 have implemented (errata dated 2026-09-28 and 2026-10-12).

## Implementation

| Document | Contents |
|---|---|
| [Phase 1 implementation spec](docs/impl/phase1-spec.md) | Phase 1 work packages, file ownership and every cross-component contract (IR, configuration, `/__mg/*`, Valkey keys, events, metrics, file formats); the integrator rulings at the top override the body |
| [Phase 1 status](docs/impl/phase1-status.md) | Stage status, current code state, known limitations and open items |
| [Stage 2 handoff](docs/impl/stage2-handoff.md) | Implementation and verification reports for the Phase 1 stage 2 work packages |
| [Phase 2 implementation spec](docs/impl/phase2-spec.md) | Phase 2 work packages and contracts: interactive challenges, session keys and `MG-Proof`, token v2 and refresh, telemetry, Turnstile, the near-line worker, events and metrics, and the owner's runbook; the integrator rulings at the top override the body |
| [Phase 2 status](docs/impl/phase2-status.md) | What each work package delivered, rulings, acceptance status, the owner's next steps and open items |

Phase 0, Phase 1 and Phase 2 (stages 1–3) are merged to `master`, with all CI jobs passing. See [Getting started](docs/getting-started.md) to build from source, and [CLAUDE.md](CLAUDE.md) for development commands and repository layout.

## License

MorphGate's own code is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and dependency-license boundaries.
