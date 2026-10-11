# @ermiaodada/morphgate-web-sdk

Browser challenge assets for MorphGate, a defensive bot-management and traffic-security platform for owner-controlled web properties.

## Install and deploy the npm assets

Version `0.2.0-preview.1` is compatible with **MorphGate Edge built from `master` at commit `710beea` or later** (`mg-edge --version` reports `0.1.0 (<commit>)`), which serves the `/__mg/v` entry that `MorphGate.fetch()` and `MorphGate.verify()` navigate to (spec I-39). With the Edge of [v0.1.0-preview.1](https://github.com/SkyBlue997/MorphGate/releases/tag/v0.1.0-preview.1), use `0.1.0-phase1`: the challenge page works with either version, but that Edge answers `/__mg/v` with 404. The Edge generates and verifies the sealed challenges. This package supplies the matching browser script and page template, consumed as a static asset directory; it has no Node.js import entry point.

Install the pinned package in your deployment project:

```sh
npm install --save-exact @ermiaodada/morphgate-web-sdk@0.2.0-preview.1
```

The package contains `dist/sdk/manifest.json`, `dist/sdk/challenge.html`, a content-hashed `dist/sdk/mg.<hex16>.js`, license/notice files and package documentation. Source files, tests and development scripts remain in the [source repository](https://github.com/SkyBlue997/MorphGate/tree/master/sdk/web).

Copy the complete `dist/sdk/` directory onto the Edge host. For example, on that host:

```sh
sudo mkdir -p /opt/morphgate/web-sdk-0.2.0-preview.1/sdk
sudo cp -R node_modules/@ermiaodada/morphgate-web-sdk/dist/sdk/. /opt/morphgate/web-sdk-0.2.0-preview.1/sdk/
sudo cp node_modules/@ermiaodada/morphgate-web-sdk/LICENSE node_modules/@ermiaodada/morphgate-web-sdk/NOTICE /opt/morphgate/web-sdk-0.2.0-preview.1/
```

Set the corresponding directory in the Edge configuration:

```toml
[sdk]
dir = "/opt/morphgate/web-sdk-0.2.0-preview.1/sdk"
```

Keep the hashed script, template and manifest together without editing their contents or names. Edge validates the manifest hashes and template when loading the directory. Validate the complete server configuration, with its credentials available, before starting or reloading:

```sh
mg-edge --check-config --config /etc/morphgate/edge.toml
```

Edge serves the script under `/__mg/s/` on the protected site's own origin and renders the challenge template itself. Serve these assets through that Edge route; do not use third-party CDN hostnames to host the challenge script. The Worker loads the same script URL and the challenge form submits to the same-origin `/__mg/c` endpoint.

For fresh deployment keys, configuration and the checked systemd reload procedure, see the [getting-started guide](https://github.com/SkyBlue997/MorphGate/blob/master/docs/getting-started.md) and [example service](https://github.com/SkyBlue997/MorphGate/blob/master/deploy/systemd/mg-edge.service). Package installation and configuration validation do not establish live Cloudflare acceptance, browser compatibility or production readiness; those owner-operated checks remain required.

## Challenged fetches (Edge with spec I-39)

A fetch from a page can receive the Edge's JSON challenge (`403`, `{"error":"mg_challenge",...}`). A script cannot solve it in place in Phase 1. Instead, the page navigates to `/__mg/v?ret=<its own path>`. The Edge challenges there, and the solved challenge returns to the page with a clearance that the fetch's route accepts. To use this, include the hashed script from `dist/sdk/manifest.json` on the site's pages and send requests through the SDK:

```html
<script data-cfasync="false" src="/__mg/s/mg.<hex16>.js"></script>
<script>
  const r = await window.MorphGate.fetch("/api/save", { method: "POST", body });
  // On a MorphGate challenge the page is already navigating to /__mg/v.
</script>
```

`MorphGate.verify()` sends the page there after the page's own response check, and `MorphGate.verifyUrl(ret)` builds the URL. Each page path navigates at most once per 60 s (sessionStorage `mg_verify:<path>`), so a fetch that is challenged again cannot loop the visitor.

## Developer reference

The sections below describe source-tree development. Build and test commands require a repository checkout; the npm asset package excludes their source and tooling.

This is MorphGate's first-party Web SDK. The design is in [docs/04 §7](https://github.com/SkyBlue997/MorphGate/blob/master/docs/04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk) and the Phase 1 contract in [the implementation spec §10–§11](https://github.com/SkyBlue997/MorphGate/blob/master/docs/impl/phase1-spec.md#11-web-sdk-phase-1wp-w1) (both in Chinese).

## Status: Phase 1 (`SDK_VERSION = "0.2.0-preview.1"`)

The Phase 1 SDK has only two effects on the network. On the challenge page the Edge serves, it completes the invisible challenge (SHA-256 proof of work) and submits `POST /__mg/c` with a form navigation. On a site's pages that use `MorphGate.fetch()`, a fetch that receives a JSON challenge navigates the page to `/__mg/v?ret=` (I-39). Telemetry upload, session keys, `MG-Proof` and solving a challenge in place come in Phase 2.

| Module | Phase 1 | Later |
|---|---|---|
| `index.ts` | Entry point. In a document: reads the configuration from the script tag's `data-mg-*` attributes, exposes a read-only `window.MorphGate` (`version`, `config`, `snapshot()`, `classifyResponse`, `fetch()`, `verify()`, `verifyUrl()`), and runs the challenge flow when the page has `#mg-challenge`. In a Worker (`self instanceof WorkerGlobalScope`): installs only the PoW message handler | Phase 2: silent refresh, telemetry |
| `config.ts` | `data-mg-*` parsing and path-prefix normalization (same-origin absolute paths only) | |
| `challenge.ts` | Challenge page client: reads and validates the `#mg-challenge` data attributes, SHA-256 self-test, Worker / main-thread PoW, submission JSON, hidden form submission, one automatic retry on the failure page, status text and retry link | Phase 2: interactive challenge, providers |
| `pow.ts` | `sha256-hashcash-v1`: prefix, midstate search, verification, Worker message protocol | |
| `sha256.ts` | Pure TypeScript SHA-256 (the compression function can start at any round, for midstate reuse) | |
| `env.ts` | Environment summary: UA and low-entropy Client Hints, languages, time zone, screen and viewport (quantized), core count, touch, storage availability. Truncation never splits a surrogate pair; a value with a lone surrogate becomes `null` (`JSON.stringify` would write it as `\udXXX`, and the Edge's strict JSON parser rejects the whole submission) | Phase 2: graphics stack family summary (family only, never the renderer string) |
| `automation.ts` | Reads only the standard `navigator.webdriver` | Phase 2: other automation signals |
| `behavior.ts` | Pure quantizers: `logBucket`, `roundToStep`, `clamp`, `logHistogram` | Phase 2: pointer / keyboard / scroll / touch collection |
| `crypto.ts` | WebCrypto ECDSA P-256 session key (`extractable: false`), RFC 7638 JWK thumbprint (`cnf.jkt`) | Phase 2: IndexedDB persistence, `MG-Proof` (ES256 JWS) |
| `verify.ts` | The verification entry for challenged fetches (I-39): `verifyUrl`, `startVerify` (each page path navigates at most once per 60 s, and never without sessionStorage), `isMgChallenge` (reads a clone of the response) | Phase 2: solving in place |
| `transport.ts` | Recognizes `cf-mitigated: challenge` as `upstream_challenge`; parses MorphGate JSON (`mg_challenge` and others); 429 / 425 | Phase 2: fetch / XHR wrappers, retries |
| `telemetry.ts` | Payload types, UTF-8 byte counts, 2 KB budget check and ordered trimming | Phase 2: session-key signatures, `POST /__mg/t` |

Privacy: no canvas, WebGL or audio rendering hashes, renderer strings, font or plugin lists, or high-entropy Client Hints are collected. A failure while collecting any value only makes that field `null` and never affects the page.

## Build output (§11.1)

`pnpm run build` runs esbuild (IIFE, minified, ES2020), then `scripts/build-dist.mjs`:

| File | Contents |
|---|---|
| `dist/mg.js` | The SDK bundle; the `size` step requires gzip ≤ 30,720 bytes (about 7.9 KB now) |
| `dist/sdk/mg.<hex16>.js` | Byte-identical to `dist/mg.js`; `hex16` is the first 16 hex digits of its SHA-256 |
| `dist/sdk/challenge.html` | The challenge page template (source `templates/challenge.html`) |
| `dist/sdk/manifest.json` | `{"v":1,"build":"<hex16>","sdk":"mg.<hex16>.js","files":{"mg.<hex16>.js":"<sha256>"},"templates":{"challenge.html":"<sha256>"}}` |

Copy the whole `dist/sdk/` directory to the Edge host and point `[sdk] dir` in `edge.toml` at it. The Edge serves only the `files` entries, under `/__mg/s/<name>`; it reads `templates` itself. It checks both hashes and the template rules again when it loads the directory.

`build-dist.mjs` exports the pure function `buildDist({ bundle, template }, outDir) -> manifest` (inputs in memory, written to the given directory, stale `mg.*.js` files removed) and `validateTemplate(template) -> string[]`. The build fails when the template breaks the contract below.

## Challenge page template contract (§11.2)

- The placeholders are exactly `{{lang}}` `{{nonce}}` `{{sdk_src}}` `{{prefix}}` `{{c}}` `{{type}}` `{{pow_bits}}` `{{ret}}` `{{request_id}}` `{{state}}`, each at least once, and no other `{{…}}`. The Edge escapes each value for an HTML attribute context (`&` `<` `>` `"` `'`) and substitutes it as plain text.
- Structure: `<html lang="{{lang}}">`; `<main id="mg-challenge">` with `data-mg-state` / `-c` / `-type` / `-pow-bits` / `-ret` / `-rid` / `-prefix`; `<p id="mg-status" role="status" aria-live="polite">`; `<a id="mg-retry" href="{{ret}}" hidden>`; `<noscript>`; `{{request_id}}` in the body text.
- UTF-8, ≤ 32 KiB, no external resources (no `http:` / `https:` or `//` URLs, no CSS `@import`). Every `<script>` and `<style>` carries `nonce="{{nonce}}"`. No inline event handlers or `style` attributes (a nonce-only CSP blocks them). The SDK `<script>` puts `data-cfasync="false"` before `src` (Rocket Loader).
- Placeholders may appear only in quoted attribute values or in plain text: never in unquoted attribute values, attribute or tag names, `<script>` / `<style>` content or HTML comments. The Edge's escaping (`&` `<` `>` `"` `'`) neutralizes markup only in those two contexts; elsewhere a value such as `ret = "/a/;alert(1)//"` would become script or markup.
- The page carries both the Chinese and the English text, and CSS shows one of them according to `<html lang>`. There is no animation under `prefers-reduced-motion`, and dark mode follows the system. The SDK sets `data-mg-phase` (`start` / `work` / `retry`) on `#mg-challenge`, which the template uses to show progress.

## Challenge flow (§11.3)

1. Read and validate the data attributes: `c` is base64url (≤ 1024 characters), `type` is `invisible` or `pow`, `pow_bits` is 0–32, and `ret` passes the client-side subset of §6.4 (starts with `/` but not `//`; no `\`, control characters or `#`; ≤ 512 bytes; the path is not `/__mg` or under `/__mg/`; the Edge's check is authoritative). The client must never be stricter than the Edge, or a challenge the Edge issued could never complete on the page: the reserved-path check is case-sensitive, like the raw-path rule of `mg_core::paths::is_reserved` (`/__MG/c` is an ordinary origin path). Anything invalid shows the retry link.
2. `state = failed`: with a new C, retry automatically at most once per `ret` (sessionStorage key `mg_retry:<ret>`; no automatic retry when storage fails); otherwise show the retry link (`href = ret`).
3. Self-test: pure-JS SHA-256 against known answers, the midstate search path against the generic path, and WebCrypto (when available) against pure JS. On any mismatch, do not start.
4. PoW: `prefix = "mg-pow-v1" ‖ 0x00 ‖ SHA-256(C)`; start a Worker from the current script URL. When the Worker cannot be created, reports an error, replies `mg-pow-err` or an invalid solution, or sends nothing within 2 s, fall back to the main thread in slices (50,000 hashes per slice, `setTimeout(0)` between slices). Stop after 60 s in total and show the retry link.
5. Build the submission JSON (key order `v, type, c, pow, ret, ts, build, env, auto`; `build` is the `hex16` from the script file name, or 16 `0`s when it cannot be read). When the URL-encoded body exceeds 8 KiB, drop `env`, then `auto`.
6. Create a hidden `<form method="POST" action="<prefix>c" enctype="application/x-www-form-urlencoded" accept-charset="UTF-8">` with the single field `mg`, append it to `body` and `submit()`. The browser follows the 303 back to `ret` with `__Host-mg_clr`.
7. No exception reaches the page: the status text changes to "verification failed, please retry" and the retry link is shown.

**Worker protocol** (the Worker and the page run the same SDK file):

```
page   -> worker  {t: "mg-pow", prefix: Uint8Array(42), bits}
worker -> page    {t: "mg-pow-ack"}                       sent as soon as a valid request arrives
worker -> page    {t: "mg-pow-ok", counter} | {t: "mg-pow-err"}
```

`mg-pow-ack` adds to spec §11.3: at high difficulty the Worker's search can take longer than 2 s, and without an acknowledgement the "no reply within 2 s" rule would mistake a working Worker for a dead one. The page cancels the 2 s timer on any message, and re-checks the Worker's result with the generic SHA-256 path before submitting.

The PoW search starts at 0 with an upper bound of `2^53 − 1`, one compression per attempt (the midstate of the first 10 rounds is precomputed, and message expansion and the round function share one loop): about 5 M attempts per second on Node 26 / Apple M-series.

## Embedding

```html
<script data-cfasync="false" src="/__mg/s/mg.<hex16>.js" nonce="..." data-mg-path-prefix="/__mg/"></script>
```

| Attribute | Default | Meaning |
|---|---|---|
| `data-mg-path-prefix` | `/__mg/` | Same-origin absolute paths only; invalid values (`//host/`, `..`, URLs) fall back to the default |
| `data-mg-site` | none | Site ID, for debugging only |
| `data-mg-debug` | `false` | `true` logs the snapshot to the console |

`data-cfasync="false"` keeps Cloudflare Rocket Loader from rewriting the script. The challenge page's CSP needs `worker-src 'self'` (the Worker starts from the same script URL) and `form-action 'self'`.

## Commands

```bash
pnpm install
pnpm run check      # typecheck && test && build && size && pack:check
pnpm run build      # esbuild -> dist/mg.js, then build-dist.mjs -> dist/sdk/
pnpm run size       # gzip(dist/mg.js) must be ≤ 30720 bytes
```

## Tests (§11.5)

| File | Contents |
|---|---|
| `test/sha256.test.ts` | NIST SHA-256 vectors (including one million `a`s); lengths 0–200 bytes against Node's SHA-256 |
| `test/pow.test.ts` | Every `pow` case of `testdata/phase1/kat.json` (prefix, `first_counter`, `digest_hex`), read directly; high counter bits and the `2^53 − 1` bound; the Worker message handler (called directly); random inputs never throw |
| `test/challenge.test.ts` | Data attribute parsing and `ret` validation; submission JSON shape, key order, no duplicate keys, nesting ≤ 16, the 8 KiB limit; form construction (fake DOM, a single `mg` field); the automatic retry quota; the self-test; the full flow (fake Worker and timers: the Worker path, every fallback, the 2 s / 60 s timers, exception handling); browser wiring |
| `test/template.test.ts` | Template placeholders, nonces, external resources, `data-cfasync` order, structure and both languages; Edge-style rendering; a counterexample for every rule; random inputs never throw |
| `test/build-dist.test.ts` | The manifest that `buildDist` writes to a temporary directory matches the file hashes and names; stale builds are removed; invalid templates and empty bundles are rejected |

The tests run in Node and do not depend on an existing `dist/`. The package has no `@types/node` (`src/` is browser code); the few Node built-ins the tests use are declared in `test/node-shim.d.ts`.
