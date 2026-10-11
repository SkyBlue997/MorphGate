# Phase 2 shared fixtures

Read-only contract files for [docs/impl/phase2-spec.md](../../docs/impl/phase2-spec.md) (§0.4, §6.11). Every work package that writes or reads one of these formats tests against these files. Change the spec first, then the generator, then regenerate:

```sh
node testdata/phase2/gen/kat.mjs           # rewrite kat.json and samples/
node testdata/phase2/gen/kat.mjs --check   # fail if any file differs, is missing or is not generated
```

[`gen/kat.mjs`](gen/kat.mjs) uses Node built-ins only and is deterministic: fixed inputs, P-256 test keys derived from fixed labels, and ECDSA signatures with RFC 6979 nonces. It checks its helpers against [`../phase1/kat.json`](../phase1/kat.json), RFC 6979 A.2.5, RFC 7638 §3.1 and RFC 9449 §6.1, and has node:crypto verify every signature it writes. The ECDSA vectors are for verification only: consumers verify them, they never sign to reproduce them (WebCrypto signatures are randomized).

Values are illustrative: `example.com`, documentation addresses, test keys and test secrets.

## `kat.json`

| Section | Spec | Used by |
|---|---|---|
| `test_keys` | — | the P-256 keys (`jwk`, `jkt`) the other sections sign with |
| `accepted_epochs` | §6.1 | WP-R5 (`accepted_epochs`; replaces the Phase 1 section of the same name) |
| `ui_params` | §6.3 | WP-R5 (`ui_params`), WP-W2 |
| `pow_v2` | §6.4 | WP-R5 (`pow_verify_v2`, `pow_solve_v2`), WP-W2 (the worker) |
| `jwk_thumbprint` | §6.5 | WP-R5 (`SessionKey::thumbprint`), WP-W2 |
| `es256` | §6.5 | WP-R5 (`SessionKey::verify_es256`), WP-W2 (WebCrypto verify) |
| `submission_message`, `renew_message` | §6.6 | WP-R5 (`submission_message`, `renew_message`), WP-W2 |
| `mg_proof` | §6.7 | WP-R5 (`verify_proof`: every case, with the first failing check of §6.7 as `expect`), WP-W2 (the proofs it builds pass the same rules) |
| `cdata`, `idempotency_key`, `bind_jkt` | §6.9, §6.5 | WP-R5 (`turnstile_cdata`, `idempotency_key`), WP-C6 (the idempotency key it sends) |

Byte strings are lower-case hex (`_hex`) or unpadded base64url (`_b64url`); `ui_seed` is a decimal string because a u64 does not fit a JSON number read as a double.

Readings of the spec that the vectors fix (each is the obvious one, listed so that implementations agree):

- `mg_proof`: the signature segment must be valid unpadded base64url at step 1 (`proof.malformed`); a decoded length other than 64 bytes (for example DER) fails at step 7 (`proof.sig`), like a wrong signature. An `htu` with an explicit port never matches, because the normalized request host has none (`htu_host_with_port`). The request `path` is the raw path without the query; `expected_jkt` is `null` when the request has no valid clearance with `cnf.jkt`.
- `/__mg/c` samples: the presence and type of `jwk` and `sig` are body rules (step 3, `ic.body`); the JWK members and the signature itself are checked at step 8 (`ic.sig`).

## `samples/`

Each directory has a `cases.json` that lists every file with its expected result.

| Path | Spec | Contents | Used by |
|---|---|---|---|
| `keys/` | §8.7 | `mg-turnstile-keys` files: `valid/` (canonical JSON, the bytes `mgctl turnstile` must write) and `invalid/` (rejected; `site-mismatch.json` is well-formed but names site `shop`) | WP-G4 (writer and reader), WP-E2c (Edge reader) |
| `siteverify/` | §8.4, §8.5 | siteverify response bodies and their outcome and reason for a fixed expectation (host, hostnames, action, `cdata`, `C.iat`, now); `malformed/` are responses that do not fit §8.4 | WP-C6 |
| `proof/` | §6.7 | `MG-Proof` header values (one line each) and their result; the full set is `kat.json` `mg_proof` | WP-E2b, WP-W2 |
| `submissions/` | §7.4, §7.5 | `POST /__mg/c` v2 and `POST /__mg/c/renew` bodies: valid ones, body errors (`ic.body`) and signature errors (`ic.sig`). `c` is a placeholder that is never opened | WP-E2a, WP-W2 |
| `telemetry/t/` | §7.5, §7.6 | the content of the `t` string of a submission (`env`, `auto`, `ix`): valid, `ix` rejected, whole `t` rejected | WP-C5 (the single decoder of §15.2), WP-W2 |
| `telemetry/behavior/` | §12.8 | behavior summaries: valid and rejected | WP-C5, WP-W2 |
| `telemetry/report/` | §9.4 | `POST /__mg/t` bodies: valid, one report dropped, request rejected (400) | WP-C5, WP-E2b, WP-W2 |
| `mg-ev-v2.txt` | §13.1 | `mg:ev` v2 entries: decision entries (every `ct`, `pf`, `xs`, `tk`, `bt` value, an unknown client IP, IPv6) and feedback entries (`pass`, `fail`, `unavailable`, `renew_rebind`) | WP-C5 (field order of the writer), WP-N1 (parser) |
| `mg-ev-v1.txt` | Phase 1 §13.6 | `mg:ev` v1 entries, which the worker still accepts | WP-N1 |

`mg:ev` files: one entry per line; fields and values alternate, separated by TAB, in `XADD` order; an empty value is the empty string. `ipk` and `pfk` are `kh` keys and `ph` the path hash of §13.1, all under the `K_pseudo` of `../phase1/kat.json` (`ipk` of `203.0.113.7` is its `entity_key` case).

Telemetry samples are one JSON text per file plus a trailing newline that is not part of it. `hold.offset` is taken to lie in −1.0..1.0 (the spec gives only its 0.1 step), like `straight` and `pressure`.
