# Phase 1 shared fixtures

Read-only contract files for [docs/impl/phase1-spec.md](../../docs/impl/phase1-spec.md) (§2.3, §12, §16). Change the spec first, then regenerate. Every work package that writes or reads one of these formats tests against these files, so format differences surface in stage 1 instead of in the stage-3 end-to-end run.

| Path | Used by |
|---|---|
| `kat.json` | Known-answer vectors: epoch keys and accepted epochs, aad, binding / return-path hashes, entity and limiter keys, `ip` entities, PoW, bundle signature domain |
| `keys/*.json`, `keys/owner-test.pub` | Valid key files (§12.6, §12.7). Writers (WP-G2) must produce these bytes exactly from the inputs below; readers (WP-R2 `from_key_file`, WP-C2 owner keys, mg-edge credentials) must accept them |
| `keys/invalid/*` | Readers must reject every file (the name says why; `token.keys.site-shop.json` is invalid when loaded for site `blog`) |
| `artifacts/cloudflare-ips.json` | Valid §12.2 artifact. `mgctl cf ips sync` (WP-G3) must write these bytes for the matching API response and `fetched_at`; `mg_intel::parse_cloudflare_ips` (WP-R3) must accept it |
| `artifacts/crawler-registry.json`, `artifacts/crawler-registry.test.json` | Valid §12.3 artifacts (the second has `"test": true` and documentation ranges, for the Validation Lab). WP-G3 must round-trip them (parse, validate, re-encode to the same bytes); WP-R3 must accept them |
| `artifacts/datacenter-asns.txt`, `artifacts/tor-exits.txt` | Valid §12.4 lists |
| `artifacts/invalid/*` | Go (WP-G3) and Rust (WP-R3) validators must reject every file |

Values are illustrative, not authoritative crawler or Cloudflare data.

## Canonical JSON

Every JSON file above is canonical (§12.0): Go `encoding/json` with `SetIndent("", "  ")` and `SetEscapeHTML(false)`, object keys in the order the spec lists them, one trailing newline. Keys are base64url without padding.

## Generation inputs

Time `2026-09-27T10:00:00Z` (date `20260927`) unless a file shows another `created_at`. Random bytes, in the order a writer draws them:

| File | Random input |
|---|---|
| `keys/owner-test.key.json`, `keys/owner-test.pub` | seed = RFC 8032 §7.1 test 1 secret key `9d61b1…7f60` (public key `d75a98…511a`), kid `owner-test` |
| `keys/token.keys.json` | token key = bytes `0x20..0x3f`, then (same `GenerateSiteKeys` call) seal root = 32 × `0x01` |
| `keys/seal.root.json` | root = 32 × `0x01` (the `epoch_keys.root_hex` of `kat.json`) |
| `keys/token.keys.rotated.json` | `rotate-token` on `token.keys.json` at `2026-09-28T10:00:00Z` with key = bytes `0x40..0x5f` |
| `keys/seal.root.rotating.json` | second root 32 × `0x02` placed first (rotation step 2, §17) |
| `keys/pseudo.key.json` | key = bytes `0x00..0x1f` (the `entity_key.k_pseudo_hex` of `kat.json`) |
| `keys/upstream-keys.json` | value = bytes `0x60..0x7f` |
| `keys/upstream-keys.rotated.json` | `--rotate` on `upstream-keys.json` at `2026-09-28T10:00:00Z` with value = bytes `0x80..0x9f` |
