# @ermiaodada/morphgate-web-sdk

Browser challenge assets for MorphGate, a defensive bot-management and traffic-security platform for owner-controlled web properties.

## Install and deploy the npm assets

Version `0.3.0` builds an SDK directory with manifest v2 and template v2 and is compatible with **`mg-edge` 0.2.0 or later** (`mg-edge --version` reports `0.2.0 (<commit>)`), which serves the interactive challenge, `/__mg/c/renew` and the stable alias `/__mg/s/mg.js`. With an older Edge, use `0.2.0-preview.1` (manifest v1). See the [compatibility table](#compatibility). The Edge generates and verifies the sealed challenges. This package supplies the matching browser script and page template, consumed as a static asset directory; it has no Node.js import entry point.

Install the pinned package in your deployment project:

```sh
npm install --save-exact @ermiaodada/morphgate-web-sdk@0.3.0
```

The package contains `dist/sdk/manifest.json`, `dist/sdk/challenge.html`, a content-hashed `dist/sdk/mg.<hex16>.js`, license/notice files and package documentation. Source files, tests and development scripts remain in the [source repository](https://github.com/SkyBlue997/MorphGate/tree/master/sdk/web).

Copy the complete `dist/sdk/` directory onto the Edge host. For example, on that host:

```sh
sudo mkdir -p /opt/morphgate/web-sdk-0.3.0/sdk
sudo cp -R node_modules/@ermiaodada/morphgate-web-sdk/dist/sdk/. /opt/morphgate/web-sdk-0.3.0/sdk/
sudo cp node_modules/@ermiaodada/morphgate-web-sdk/LICENSE node_modules/@ermiaodada/morphgate-web-sdk/NOTICE /opt/morphgate/web-sdk-0.3.0/
```

Set the corresponding directory in the Edge configuration:

```toml
[sdk]
dir = "/opt/morphgate/web-sdk-0.3.0/sdk"
```

Keep the hashed script, template and manifest together without editing their contents or names. Edge validates the manifest hashes and template when loading the directory. Validate the complete server configuration, with its credentials available, before starting or reloading:

```sh
mg-edge --check-config --config /etc/morphgate/edge.toml
```

Edge serves the script under `/__mg/s/` on the protected site's own origin and renders the challenge template itself. Serve these assets through that Edge route; do not use third-party CDN hostnames to host the challenge script. The Worker loads the same script URL and the challenge form submits to the same-origin `/__mg/c` endpoint. Keep the previous SDK directory on the host: switching `[sdk] dir` back and reloading is the emergency rollback (spec §19 step 10).

For fresh deployment keys, configuration and the checked systemd reload procedure, see the [getting-started guide](https://github.com/SkyBlue997/MorphGate/blob/master/docs/getting-started.md) and [example service](https://github.com/SkyBlue997/MorphGate/blob/master/deploy/systemd/mg-edge.service). Package installation and configuration validation do not establish live Cloudflare acceptance, browser compatibility or production readiness; those owner-operated checks remain required.

## Compatibility

| SDK | SDK directory | Edge | Notes |
|---|---|---|---|
| `0.1.0-phase1` | manifest v1 | `0.1.0-preview.1` and later | No `/__mg/v` on the oldest Edge |
| `0.2.0-preview.1` | manifest v1, template v1 | `0.1.0` from commit `710beea` | `MorphGate.fetch()` uses the verify entry (I-39) |
| `0.3.0` | manifest v2, template v2 | `mg-edge` ≥ `0.2.0` | Interactive challenge, in-place solving, `MG-Proof`, refresh, telemetry. `mg-edge` 0.2.x still accepts 0.2.x directories (manifest v1; no interactive challenge) |

The stable alias `/__mg/s/mg.js` exists from `mg-edge` 0.2.0 on, for both directory versions. A rollback to a Phase 1 Edge needs the hashed file name again (spec §19 step 9).

## Site integration contract (phase2-spec §12.1, §19 step 3b)

Include the SDK in the site's own templates, **before the site's own scripts**:

```html
<script data-cfasync="false" src="/__mg/s/mg.js" defer></script>
```

- `data-cfasync="false"` (before `src`) keeps Cloudflare Rocket Loader away. The alias may be cached for up to 300 s; the Worker reports its own SDK version, and a page whose Worker is of another build rebuilds it once from `/__mg/s/mg.js?sv=<SDK_VERSION>`.
- **Never assume `window.MorphGate` exists.** A blocked or failed script (cross-border packet loss, an extension, an Edge rollback) must leave the site working:

  ```js
  const mgFetch = (...a) => (window.MorphGate?.fetch ?? window.fetch)(...a);
  ```

- Module or `async` scripts that call the SDK at top level first `await window.MorphGate?.ready()` (it resolves once the key store is initialised and never rejects).
- XHR and axios: add the proof in an interceptor; `proofHeader` resolves to `null` when no proof applies:

  ```js
  axios.interceptors.request.use(async (config) => {
    const proof = await window.MorphGate?.proofHeader(config.method ?? "GET", config.url);
    if (proof) config.headers["MG-Proof"] = proof;
    return config;
  });
  ```

- `MorphGate.onBeforeNavigate(cb)`: the SDK calls `cb` synchronously (50 ms budget for all callbacks) before it leaves the page itself (`verify()`, the reload after an upstream challenge), for example to save a draft.
- Routes with `proof: required` should not answer with redirects: the browser would carry the proof to the redirect target, where `htu` no longer matches (GET / HEAD are retried once at the target).
- The site's CSP must allow same-origin scripts and `worker-src 'self'` (or allow it through `script-src`); otherwise in-place solving runs on the main thread in short slices.

| Attribute | Default | Meaning |
|---|---|---|
| `data-mg-path-prefix` | `/__mg/` | Same-origin absolute paths only; invalid values (`//host/`, `..`, URLs) fall back to the default |
| `data-mg-site` | none | Site ID, for debugging only |
| `data-mg-debug` | `false` | `true` logs the snapshot to the console |
| `data-mg-proof` | `auto` | `auto`: attach `MG-Proof` to same-origin `MorphGate.fetch` requests once the clearance is key-bound; `off`: never |
| `data-mg-refresh` | `auto` | `auto`: refresh a key-bound clearance before it expires (`POST /__mg/r`); `off`: never |
| `data-mg-telemetry` | none | `behavior` turns on the behaviour summary (§12.8). Off by default; update the privacy notice first |

`window.MorphGate` is frozen and has ten members: the seven of Phase 1 (`version`, `config`, `snapshot()`, `classifyResponse`, `verifyUrl()`, `verify()`, `fetch()`) and `ready()`, `proofHeader(method, url)`, `onBeforeNavigate(cb)`. A second copy of the script returns the first instance.

Browser floor: Chromium ≥ 80, Safari / iOS ≥ 14 and current WeChat XWeb / X5. Older browsers cannot parse the script; the challenge page shows a CSS-only notice after 10 s (`#mg-stuck`).

## Service Worker

A site's Service Worker must **not handle any request under `/__mg/`**: otherwise the challenge page, the SDK update and the endpoints break in ways the Edge cannot see.

```js
self.addEventListener("fetch", (event) => {
  if (new URL(event.request.url).pathname.startsWith("/__mg/")) return; // no respondWith
  // ... the site's own handling
});
```

With Workbox, set `navigateFallbackDenylist: [/^\/__mg\//]` and register no cache route for `/__mg/`. To check: with the Service Worker active, open `/__mg/v?ret=/`: the page must contain `#mg-challenge`, and in the developer tools `/__mg/s/mg.js` must not come "from ServiceWorker". When the SDK runs on a page under `/__mg/` that has no `#mg-challenge` (a Service Worker answered with a site page), it reports `sw_intercept` to `/__mg/t`, which the Edge counts as `mg_sw_intercept_reports_total`.

## Challenged fetches (phase2-spec §12.5)

`MorphGate.fetch(input, init)`:

1. **Proof.** Same-origin requests get `MG-Proof` when `data-mg-proof` is `auto`, a session key is persisted (IndexedDB or localStorage) and `__Host-mg_st` shows an unexpired, key-bound clearance. The proof is a compact ES256 JWS: header `{"alg":"ES256","typ":"mg-proof+jwt","jwk":{…}}` (cached per key), payload `{htm, htu, iat, jti}`. `htm` is the method as the browser sends it (fetch upper-cases only DELETE, GET, HEAD, OPTIONS, POST, PUT), `htu` is `https://<host><path>` without query (no proof above 2048 bytes), `iat` the estimated server time.
2. **Fetch.** A final `mg_proof_required` after a redirect is re-requested once at `response.url` with a new proof (GET / HEAD only).
3. **Answers.** Only a 403 / 429 with `MG-Error` or `MG-Challenge` is the Edge's; everything else, 429 included, is returned untouched.
   - `cf-mitigated: challenge`: an `upstream_challenge` report is queued in sessionStorage for the next page load, then `onBeforeNavigate` runs and the page reloads, once per path per 60 s (`mg_cfm:<path>`). Without sessionStorage: report only. The SDK's own background requests never reload; they report and stop.
   - `mg_challenge` `invisible` / `pow`: solved in place in a manifest v2 build (refused above 24 bits, or `k · 2^bits > 2^28` for v2), one solve per page at a time and across tabs (`navigator.locks` `mg-solve`, with a re-read of `__Host-mg_st`), submitted as JSON to `/__mg/c` (v2; v1 without WebCrypto), then the request is retried once when its body can be replayed (string, `URLSearchParams`, `Blob`, `ArrayBuffer`, `FormData`; not a stream). A manifest v1 build (stage 1) uses the verify entry instead, as in Phase 1.
   - `mg_challenge` `interactive`: `verify()` with `min=interactive` (`/__mg/v?ret=<page>&min=interactive`, D-58).
   - `mg_proof_required`: (1) when the answer's `now_ms` is more than 5 s from the estimated server time, the clock is corrected and the request retried once; (2) an attached `pow` C is solved in place and the request retried; (3) when the key lives only in memory (or there is no WebCrypto) the answer is returned and `key_unavailable` reported once; (4) otherwise `verify()`.

The verify entry is guarded: each page path navigates at most once per 60 s (sessionStorage `mg_verify:<path>`), and never without sessionStorage. The clock skew comes from `now_ms` in any MorphGate JSON answer and from the `Date` header of same-origin responses, and is kept in sessionStorage `mg_skew`.

**Refresh** (`data-mg-refresh="auto"` and `__Host-mg_st` with `b = 1`): while the page is visible, at `iat + 0.8 · (exp − iat)` but not before `exp − 600 s` and not after `exp − 60 s`; paused while hidden; one refresh across tabs (`mg-refresh` lock, then `exp` re-read); network failures retry after 30 s, at most 3 times; `mg_refresh_denied` stops refreshing that `exp` (`mg_rd:<exp>`); `mg_blocked` stops refresh and reports for the page.

## Session key (phase2-spec §12.4)

| Tier | Storage | `ks` |
|---|---|---|
| IndexedDB | database `mg-v1`, store `keys`, key `session`: `{pair, created_ms}`, private key not extractable; 1.5 s timeout per operation | `idb` |
| Fallback 1 | localStorage `mg_sk_v1`: an extractable key as JWK, shared by tabs | `local` |
| Fallback 2 | memory only: no `MG-Proof` (routes with `proof: required` are then unavailable) | `memory` |
| No WebCrypto | v1 submissions; the interactive challenge cannot complete | `none` |

The key is generated when first needed (the challenge page, or the first request that needs a proof), in one readwrite transaction that keeps a stored key, so tabs share one key (`navigator.locks` `mg-key` wraps it when available). It is replaced after 7 days, and when there is no valid clearance (`__Host-mg_st` missing or expired) and the key is at least 10 minutes old.

## Interactive challenge (phase2-spec §12.6)

On template v2 pages with `data-mg-type="interactive"` the SDK runs the control (`src/interactive.ts`): press and hold (submitted only on release inside the button after `hold_ms`, WCAG 2.5.2), single activation (a click, Space / Enter, a screen-reader activation or "Can't press and hold? Press once instead": the control completes `hold_ms` and the PoW by itself, D-65), "Verify automatically (slower)" (`pow_a11y`, a determinate progress bar) and Turnstile when the Edge offers it first (loaded from `challenges.cloudflare.com` only then; errors fall back to the next provider without consuming anything). An unbound C is renewed once to bind it to the session key before anything else (D-41); the C is renewed again after `iat + 480 s`. Every state text is written to `#mg-status` once per transition, busy states use `aria-disabled`, and focus never moves except from `#mg-alt-single` to `#mg-hold`. Submissions go out as JSON with `fetch`, never earlier than receipt + `min_ms` + 100 ms, never twice for one C; failures with a new C reset the control in place, everything else reloads the page.

Interaction telemetry (`t.ix`, §7.6) is quantized on the client (log buckets, 0.1 and 10 / 100 ms steps); with `env` and `auto` it must fit 2048 bytes (`ix.pre`, `ix.page`, `env`, `auto` are dropped in that order).

Privacy: no canvas, WebGL or audio rendering hashes, renderer strings, font or plugin lists, high-entropy Client Hints, raw coordinates, trajectories or key values are collected. The behaviour summary (§12.8) is off unless the tag says `data-mg-telemetry="behavior"`.

## Developer reference

The sections below describe source-tree development. Build and test commands require a repository checkout; the npm asset package excludes their source and tooling.

The design is in [docs/04 §7](https://github.com/SkyBlue997/MorphGate/blob/master/docs/04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk) and [docs/09](https://github.com/SkyBlue997/MorphGate/blob/master/docs/09-interactive-challenge.md); the contracts are in [the Phase 1 spec §10–§11](https://github.com/SkyBlue997/MorphGate/blob/master/docs/impl/phase1-spec.md#11-web-sdk-phase-1wp-w1) and [the Phase 2 spec §12](https://github.com/SkyBlue997/MorphGate/blob/master/docs/impl/phase2-spec.md#12-web-sdk-v1wp-w2) (both in Chinese).

| Module | Contents |
|---|---|
| `index.ts` | Entry point: configuration, `window.MorphGate`, background work (refresh, queued reports, the Service Worker check, the behaviour summary); in a Worker only the PoW handlers (`worker.ts`) |
| `config.ts` | `data-mg-*` parsing and path-prefix normalization |
| `version.ts` | `SDK_VERSION`; `BUILD_MANIFEST_VERSION` (the build's `MG_MANIFEST_VERSION`) |
| `runtime.ts` | Per-page runtime: key store, clock, proofs, `onBeforeNavigate`, `/__mg/t` reports and the off-page queue |
| `crypto.ts`, `keystore.ts`, `sig.ts`, `submit.ts` | WebCrypto P-256 keys and RFC 7638 thumbprints; the three storage tiers; `mg-sub-v2` / `mg-renew-v1` messages and ES256; signed v2 submission and renew bodies |
| `proof.ts` | `MG-Proof`, `__Host-mg_st`, clock skew |
| `transport.ts`, `fetch.ts`, `verify.ts`, `refresh.ts` | Response classification (§11.2), `MorphGate.fetch` (§12.5), the verify entry (I-39, D-58), refresh |
| `challenge.ts` | The challenge page: Phase 1 flow for `invisible` / `pow` (v2 submissions on template v2 pages), and the interactive control's browser wiring |
| `interactive.ts`, `copy.ts`, `turnstile.ts` | The interactive control, its zh-CN / en copy (§12.7) and Turnstile loading (§8.3) |
| `pow.ts`, `powv2.ts`, `worker.ts`, `sha256.ts` | `sha256-hashcash-v1` and `-v2`, the Worker protocols and runner, pure TypeScript SHA-256 |
| `telemetry.ts`, `behavior.ts`, `env.ts`, `automation.ts` | Budgets and report batching; quantizers and the behaviour collector; environment and automation summaries |
| `ui.ts` | `ui_params` (§6.3) for the known-answer tests; not part of the bundle |

## Build output (phase2-spec §2.1, §12.2)

`pnpm run build` runs `scripts/build-dist.mjs`: esbuild (IIFE, minified, ES2020, `MG_MANIFEST_VERSION` defined), then the SDK directory. `DEFAULT_MANIFEST_VERSION` in `build-dist.mjs` selects the template (`templates/challenge.html` for 1, `templates/challenge.v2.html` for 2), its validation rules and the manifest version. **It is 1 in stage 1**, because the Phase 1 Edge accepts only manifest v1; WP-E2a switches it to 2 together with the Edge. In-place solving (§12.5) is compiled in only when it is 2.

| File | Contents |
|---|---|
| `dist/mg.js` | The SDK bundle; the `size` step requires gzip ≤ 30,720 bytes |
| `dist/sdk/mg.<hex16>.js` | Byte-identical to `dist/mg.js`; `hex16` is the first 16 hex digits of its SHA-256 |
| `dist/sdk/challenge.html` | The template of the build's version |
| `dist/sdk/manifest.json` | `{"v":<1 or 2>,"build":"<hex16>","sdk":"mg.<hex16>.js","files":{"mg.<hex16>.js":"<sha256>"},"templates":{"challenge.html":"<sha256>"}}`; `files` never lists `mg.js` |

Copy the whole `dist/sdk/` directory to the Edge host and point `[sdk] dir` in `edge.toml` at it. Whenever the SDK changes, copy it into `edge/tests/fixtures/sdk/` too: CI and the publish workflow compare the two.

## Challenge page template v1 (phase1-spec §11.2)

- The placeholders are exactly `{{lang}}` `{{nonce}}` `{{sdk_src}}` `{{prefix}}` `{{c}}` `{{type}}` `{{pow_bits}}` `{{ret}}` `{{request_id}}` `{{state}}`, each at least once, and no other `{{…}}`. The Edge escapes each value for an HTML attribute context (`&` `<` `>` `"` `'`) and substitutes it as plain text.
- Structure: `<html lang="{{lang}}">`; `<main id="mg-challenge">` with `data-mg-state` / `-c` / `-type` / `-pow-bits` / `-ret` / `-rid` / `-prefix`; `<p id="mg-status" role="status" aria-live="polite">`; `<a id="mg-retry" href="{{ret}}" hidden>`; `<noscript>`; `{{request_id}}` in the body text.
- UTF-8, ≤ 32 KiB, no external resources (no `http:` / `https:` or `//` URLs, no CSS `@import`). Every `<script>` and `<style>` carries `nonce="{{nonce}}"`. No inline event handlers or `style` attributes (a nonce-only CSP blocks them). The SDK `<script>` puts `data-cfasync="false"` before `src` (Rocket Loader).
- Placeholders may appear only in quoted attribute values or in plain text: never in unquoted attribute values, attribute or tag names, `<script>` / `<style>` content or HTML comments.
- The page carries both the Chinese and the English text, and CSS shows one of them according to `<html lang>`. The SDK sets `data-mg-phase` (`start` / `work` / `retry`) on `#mg-challenge`.

## Challenge page template v2 (phase2-spec §12.3)

Every v1 rule, plus (`validateTemplate(template, 2)`; the Edge's loader checks the same rules):

- Placeholders: the ten of v1 and `{{ix}}`, `{{help_href}}`, `{{privacy_href}}`. `{{ix}}` appears exactly once, as `data-mg-ix="{{ix}}"` on `<main id="mg-challenge">` (empty on non-interactive pages). `{{help_href}}` and `{{privacy_href}}` appear only as the whole quoted value of an `href`.
- Each of these ids exactly once, on this element, inside `<main id="mg-challenge">`; the first six inside `#mg-ix`:

  | Element | Inside |
  |---|---|
  | `<div id="mg-ix" hidden>` | `<main>` |
  | `<p id="mg-purpose">` | `#mg-ix` |
  | `<button id="mg-hold" type="button" aria-describedby="mg-purpose">` with a text label and an `aria-hidden="true"` progress layer | `#mg-ix` |
  | `<button id="mg-alt-single" type="button">`, `<button id="mg-alt-pow" type="button">` | `#mg-ix` |
  | `<div id="mg-progress" role="progressbar" aria-labelledby="mg-purpose" hidden>` | `#mg-ix` |
  | `<div id="mg-turnstile" hidden>` | `#mg-ix` |
  | `<a id="mg-help" href="{{help_href}}">`, `<a id="mg-privacy" href="{{privacy_href}}">` | `<main>` |
  | `<p id="mg-stuck">` | `<main>` |

- Style rules, each with a template test: controls ≥ 24 × 24 CSS px and `#mg-hold` ≥ 44 × 44, visible `:focus-visible` rings; `touch-action`, `-webkit-touch-callout` and `user-select` only on `#mg-hold`; stepped progress without animation under `prefers-reduced-motion`; `Highlight` / system-colour borders under `forced-colors`; the button offset only through its margin, 16 px on both sides, no fixed height, no horizontal scroll at 320 px; AAA contrast in both colour schemes and no red text; `#mg-stuck` revealed by `animation: mg-reveal 0s 10s forwards` and hidden once the SDK sets `data-mg-phase`.

## Worker protocols

The Worker and the page run the same SDK file; `worker.ts` dispatches on `t`.

```
v1 (non-interactive challenges, in-place solving)
page   -> worker  {t: "mg-pow", prefix: Uint8Array(42), bits}
worker -> page    {t: "mg-pow-ack"}
worker -> page    {t: "mg-pow-ok", counter} | {t: "mg-pow-err"}

v2 (interactive, sha256-hashcash-v2)
page   -> worker  {t: "mg-pow2", prefix: Uint8Array(42), bits, k, sv, start?: number[k]}
worker -> page    {t: "mg-pow2-ack", sv}                at once, with the Worker's SDK_VERSION
worker -> page    {t: "mg-pow2-part", i, counter}       after each sub-puzzle
worker -> page    {t: "mg-pow2-ok", counters} | {t: "mg-pow2-err"}
```

Without an acknowledgement within 2 s the page computes on the main thread (v1: 50,000-hash slices; v2: slices of at most 8 ms, yielding with `scheduler.yield()` or a zero timeout). A v2 Worker that reports another `sv` is replaced once by `<prefix>s/mg.js?sv=<SDK_VERSION>`, then the main thread takes over. Parts are re-verified with the generic SHA-256. `start` (an addition to §12.6) lets a provider switch keep solved sub-puzzles that meet the new difficulty and continue the others.

## Commands

```bash
pnpm install
pnpm run check      # typecheck && test && build && size && pack:check
pnpm run build      # esbuild -> dist/mg.js, then dist/sdk/
pnpm run size       # gzip(dist/mg.js) must be ≤ 30720 bytes
```

## Tests (phase2-spec §12.10)

| File | Contents |
|---|---|
| `test/kat2.test.ts` | Every `pow_v2`, `jwk_thumbprint`, `es256` (verified with WebCrypto), `submission_message`, `renew_message`, `ui_params` and `mg_proof` vector of `testdata/phase2/kat.json`; a reference verifier of §6.7 (`test/proofref.ts`) agrees with all `mg_proof` vectors and accepts the proofs and signatures the SDK builds |
| `test/powv2.test.ts` | Worker protocol v2 (ack, part, ok, err), the 2 s fallback, the one rebuild on an `sv` mismatch, 8 ms main-thread slices, kept sub-puzzles on a provider switch |
| `test/keystore.test.ts` | A fake IndexedDB: tiers, timeouts, `onblocked`, two tabs generating at once, the `ConstraintError` branch, rotation |
| `test/fetch.test.ts`, `test/refresh.test.ts`, `test/runtime.test.ts` | Proof attachment, every answer class, replayable bodies, five concurrent challenges with one submission, the cross-tab lock, `cf-mitigated`, the four `mg_proof_required` steps, redirects, the clock; refresh timing and single flight; status cookie and reports |
| `test/interactive.test.ts`, `test/turnstile.test.ts` | The control with a fake DOM and clock: the four paths, every abort reason, WCAG 2.5.2, click classification, status writes, focus, binding and renewal, every submission outcome; Turnstile loading and every error class |
| `test/template-v2.test.ts`, `test/template.test.ts`, `test/build-dist.test.ts` | Both templates by file name, each v2 style rule, validator counterexamples, both manifest versions |
| `test/telemetry.test.ts`, `test/behavior-summary.test.ts`, `test/challenge-v2.test.ts`, `test/index.test.ts` | Budgets and samples of `testdata/phase2/samples/telemetry/`; v2 submissions on template v2 pages; `window.MorphGate`, `sw_intercept`, queued reports, the behaviour summary |
| Phase 1 suites | SHA-256, PoW v1, the challenge flow, configuration, transport, verify |

The tests run in Node and do not depend on an existing `dist/`. There is no CI job with a real browser; real browsers and assistive technology are checked by the owner (spec §19 step 5). The package has no `@types/node` (`src/` is browser code); the few Node built-ins the tests use are declared in `test/node-shim.d.ts`.

## Publishing (phase2-spec §12.9)

Releases are published by `.github/workflows/publish-sdk.yml`: run it manually on a `web-sdk-v<version>` tag whose version equals `package.json`. It runs `make web-check`, requires the build to equal `edge/tests/fixtures/sdk/` byte for byte, and publishes with npm trusted publishing and provenance (npm ≥ 11.5, no long-lived token; the repository and workflow are registered once on npmjs.com). `0.3.x` keeps the `preview` dist-tag; versions after the Phase 2 acceptance use `latest`.
