# MorphGate

Defensive bot management for websites you operate yourself.

MorphGate is a reverse proxy that sits behind your CDN (Cloudflare first) and in front of your origin. It scores each request, applies per-route policy and rate limits, challenges suspicious clients, verifies crawlers and logs every decision.

[Getting started](docs/getting-started.md) · [Releases](https://github.com/SkyBlue997/MorphGate/releases) · [Security policy](SECURITY.md) · [Maintainers](MAINTAINERS.md) · [Apache-2.0](LICENSE)

## Status

Source preview. Phase 1 runs in monitor mode on a real Cloudflare zone. Phase 2 is merged and off by default: a site turns it on through its configuration bundle. Details are in the [Phase 1 status](docs/impl/phase1-status.md) and [Phase 2 status](docs/impl/phase2-status.md).

## What it includes

- **Edge** (`mg-edge`): Rust on Pingora, with a pure decision core (`mg-core`).
- **Challenges**: proof of work, an accessible interactive challenge (press and hold) and optional Cloudflare Turnstile, followed by a short-lived clearance token. Everything is served first-party under `/__mg/`.
- **Policy**: site YAML that `mgctl` (Go) compiles into a signed bundle.
- **Web SDK**: [`@ermiaodada/morphgate-web-sdk`](https://www.npmjs.com/package/@ermiaodada/morphgate-web-sdk) on npm ([installation guide](sdk/web/README.md)).
- **Near-line worker** (`mg-nearline`): reads the event stream and raises the risk of detected scanners.
- **Validation Lab**: sends test traffic to allowlisted targets only.

A typical deployment is `Cloudflare → Cloudflare Tunnel → mg-edge → origin` on 1–3 VMs with Valkey. It needs no Kafka or Kubernetes.

## Scope

- MorphGate is defensive: it detects, classifies, challenges, rate-limits and audits traffic to sites its operator controls. It is not a hosted service. This scope adds no restriction to the [Apache-2.0](LICENSE) license.
- The project does not research, reproduce or provide ways around any third-party bot protection or CAPTCHA product, including Cloudflare and Turnstile.
- Testing runs on local and owner-controlled environments. The Validation Lab enforces its target allowlist in code and through an isolated network.
- Client-side signal collection is data-minimal. Complete a privacy and compliance review before going live ([06 §7](docs/06-policy-console-observability.md#7-隐私与合规)).

## Documentation

The design documents and ADRs are in Chinese. Code, comments and commit messages are in English.

- **Design**: [01 Architecture](docs/01-architecture.md) · [02 Data flow](docs/02-data-flow.md) · [03 Risk scoring](docs/03-risk-scoring.md) · [04 Challenges and tokens](docs/04-challenge-and-tokens.md) · [05 AI agent policy](docs/05-ai-agent-policy.md) · [06 Policy, console and audit](docs/06-policy-console-observability.md) · [07 Roadmap](docs/07-roadmap.md) · [08 Upstream and Cloudflare](docs/08-upstream-and-cloudflare.md) · [09 Interactive challenge](docs/09-interactive-challenge.md) · [10 Threat model](docs/10-threat-model.md) · [ADRs](docs/adr/README.md)
- **Implementation**: [Phase 1 spec](docs/impl/phase1-spec.md) · [Stage 2 handoff](docs/impl/stage2-handoff.md) · [Phase 2 spec](docs/impl/phase2-spec.md)
- **Running a site**: [Getting started](docs/getting-started.md) · [Cloudflare setup checklist](adapters/cloudflare/README.md) · [Privacy notice template](docs/privacy-notice-template.md)
- **Development**: [CLAUDE.md](CLAUDE.md) has the commands and the repository layout.

## License

MorphGate's own code is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) and the [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and dependency licenses.
