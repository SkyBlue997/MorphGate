#!/usr/bin/env node
// Generator of the Phase 2 shared test data (docs/impl/phase2-spec.md §0.4, §6.11):
// testdata/phase2/kat.json and everything under testdata/phase2/samples/.
//
//   node testdata/phase2/gen/kat.mjs           rewrite the files
//   node testdata/phase2/gen/kat.mjs --check   exit 1 if any file differs or is missing
//
// Node built-ins only (node:crypto, node:fs, node:path, node:url). Deterministic:
// fixed inputs, test keys derived from fixed labels, and ECDSA signatures with
// RFC 6979 deterministic nonces (computed here with BigInt arithmetic and checked
// against node:crypto, which verifies every signature this script emits). The
// ECDSA vectors are for verification only: consumers verify, they never sign to
// reproduce them. Every formula is the spec's; the script asserts its helpers
// against testdata/phase1/kat.json and against the published RFC examples.

import { createECDH, createHash, createHmac, createPublicKey, hkdfSync, verify as nodeVerify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..'); // testdata/phase2
const PHASE1_KAT = JSON.parse(readFileSync(join(ROOT, '..', 'phase1', 'kat.json'), 'utf8'));

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

const utf8 = (s) => Buffer.from(s, 'utf8');
const ascii = (s) => Buffer.from(s, 'latin1');
const cat = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
const sha256 = (b) => createHash('sha256').update(b).digest();
const hmac = (key, b) => createHmac('sha256', key).update(b).digest();
const hex = (b) => Buffer.from(b).toString('hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const u8 = (n) => Buffer.from([n]);
const u16be = (n) => {
  if (n > 0xffff) throw new Error(`lp: ${n} bytes`);
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const u64be = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
/** lp(x) = u16be(len(x)) ‖ x (Phase 2 spec §6.6). */
const lp = (x) => {
  const b = Buffer.isBuffer(x) ? x : utf8(x);
  return cat(u16be(b.length), b);
};
const assertEq = (got, want, what) => {
  if (got !== want) throw new Error(`self-check failed: ${what}: got ${got}, want ${want}`);
};

// ---------------------------------------------------------------------------
// Phase 1 formulas reused by Phase 2 (checked against testdata/phase1/kat.json)
// ---------------------------------------------------------------------------

/** bind_hash(kind, value) = SHA-256('mg-bind-v1' ‖ 0x00 ‖ kind ‖ 0x00 ‖ value)[0..16]. */
const bindHash = (kind, value) => sha256(cat(utf8('mg-bind-v1'), u8(0), utf8(kind), u8(0), utf8(value))).subarray(0, 16);
for (const c of PHASE1_KAT.bind.cases) assertEq(b64u(bindHash(c.kind, c.value)), c.hash_b64url, `bind ${c.kind}`);

/** HKDF-SHA256(salt = empty, ikm = root, info = label ‖ 0x00 ‖ site ‖ 0x00 ‖ u64be(epoch), 32). */
const epochKey = (label, root, site, epoch) =>
  Buffer.from(hkdfSync('sha256', root, Buffer.alloc(0), cat(utf8(label), u8(0), utf8(site), u8(0), u64be(epoch)), 32));
{
  const root = Buffer.from(PHASE1_KAT.epoch_keys.root_hex, 'hex');
  for (const c of PHASE1_KAT.epoch_keys.cases) {
    const label = c.key === 'k_epoch' ? 'mg-seal-v1' : 'mg-bind-v1';
    assertEq(hex(epochKey(label, root, c.site, c.epoch_no)), c.okm_hex, `epoch key ${c.key}`);
  }
}

/** kh(domain, type, value) = lower_hex(HMAC-SHA256(K_pseudo, domain ‖ 0x00 ‖ type ‖ 0x00 ‖ value))[0..32]. */
const K_PSEUDO = Buffer.from(PHASE1_KAT.entity_key.k_pseudo_hex, 'hex');
const kh = (domain, type, value) => hex(hmac(K_PSEUDO, cat(utf8(domain), u8(0), utf8(type), u8(0), utf8(value)))).slice(0, 32);
for (const c of PHASE1_KAT.entity_key.cases) assertEq(kh(c.domain, c.type, c.value), c.key_hex, `entity key ${c.type}`);

const leadingZeroBits = (d) => {
  let n = 0;
  for (const byte of d) {
    if (byte === 0) {
      n += 8;
      continue;
    }
    n += Math.clz32(byte) - 24;
    break;
  }
  return n;
};

// ---------------------------------------------------------------------------
// P-256 ECDSA with RFC 6979 nonces (deterministic signing for the vectors)
// ---------------------------------------------------------------------------

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const A = P - 3n;
const G = [
  0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
];
const mod = (a, m) => ((a % m) + m) % m;
const inv = (a, m) => {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return mod(s0, m);
};
const ptAdd = (p1, p2) => {
  if (!p1) return p2;
  if (!p2) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  let l;
  if (x1 === x2) {
    if (mod(y1 + y2, P) === 0n) return null;
    l = mod((3n * x1 * x1 + A) * inv(2n * y1, P), P);
  } else {
    l = mod((y2 - y1) * inv(x2 - x1, P), P);
  }
  const x3 = mod(l * l - x1 - x2, P);
  return [x3, mod(l * (x1 - x3) - y1, P)];
};
const ptMul = (k, pt) => {
  let acc = null;
  for (let add = pt; k > 0n; k >>= 1n, add = ptAdd(add, add)) if (k & 1n) acc = ptAdd(acc, add);
  return acc;
};
const toInt = (b) => (b.length ? BigInt(`0x${hex(b)}`) : 0n);
const to32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');

function rfc6979Nonce(d, h1) {
  const x = to32(d);
  const h = to32(mod(toInt(h1), N));
  let V = Buffer.alloc(32, 1);
  let K = Buffer.alloc(32, 0);
  K = hmac(K, cat(V, u8(0), x, h));
  V = hmac(K, V);
  K = hmac(K, cat(V, u8(1), x, h));
  V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = toInt(V);
    if (k >= 1n && k < N) return k;
    K = hmac(K, cat(V, u8(0)));
    V = hmac(K, V);
  }
}

/** ES256 over msg: { r, s } with the RFC 6979 nonce; s is not normalized. */
function ecdsaSign(d, msg) {
  const h1 = sha256(msg);
  const k = rfc6979Nonce(d, h1);
  const r = mod(ptMul(k, G)[0], N);
  const s = mod(inv(k, N) * (toInt(h1) + r * d), N);
  return { r, s };
}
const p1363 = ({ r, s }) => cat(to32(r), to32(s));
const derInt = (n) => {
  let b = Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
  while (b.length > 1 && b[0] === 0 && b[1] < 0x80) b = b.subarray(1);
  if (b[0] >= 0x80) b = cat(u8(0), b);
  return cat(u8(0x02), u8(b.length), b);
};
const der = ({ r, s }) => {
  const body = cat(derInt(r), derInt(s));
  return cat(u8(0x30), u8(body.length), body);
};

// RFC 6979 A.2.5 (P-256, SHA-256, message "sample").
{
  const d = 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721n;
  const { r, s } = ecdsaSign(d, utf8('sample'));
  assertEq(r.toString(16), 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716', 'RFC 6979 r');
  assertEq(s.toString(16), 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8', 'RFC 6979 s');
}

/** A test key: d from a fixed label; the public point checked against node:crypto. */
function testKey(label) {
  const d = mod(toInt(sha256(utf8(label))), N - 1n) + 1n;
  const [x, y] = ptMul(d, G);
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(to32(d));
  assertEq(hex(ecdh.getPublicKey()), `04${hex(to32(x))}${hex(to32(y))}`, `public key of ${label}`);
  const jwk = { kty: 'EC', crv: 'P-256', x: b64u(to32(x)), y: b64u(to32(y)) };
  return { label, d, jwk, jkt: thumbprintEc(jwk) };
}

/** RFC 7638 thumbprint of a P-256 JWK (members in lexicographic order, no whitespace). */
function thumbprintEc(jwk) {
  return b64u(sha256(utf8(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`)));
}

/** node:crypto's verdict on an ES256 signature (P1363 r‖s), false for unusable keys. */
function nodeVerifies(jwk, msg, sig) {
  let key;
  try {
    key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: 'jwk' });
  } catch {
    return false;
  }
  try {
    return nodeVerify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}

/** Signs msg with key and checks the result with node:crypto. */
function es256(key, msg) {
  const sig = p1363(ecdsaSign(key.d, msg));
  if (!nodeVerifies(key.jwk, msg, sig)) throw new Error('node:crypto rejected a generated signature');
  return sig;
}

const KEYS = [0, 1, 2, 3].map((i) => testKey(`mg-phase2-kat-key-${i}`));

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const DAY_MS = 86_400_000;
const EPOCH = 20_736; // 2026-10-10
const DAY_START_MS = EPOCH * DAY_MS;
const NOW_S = 1_790_000_000; // 2026-09-21T14:13:20Z
const NOW_MS = NOW_S * 1000;
const HOST = 'example.com';
const SITE = 'blog';
const SEAL_ROOT = Buffer.from(PHASE1_KAT.epoch_keys.root_hex, 'hex'); // 0x01 × 32
const SEAL_ROOT_2 = Buffer.alloc(32, 2);
const NONCE = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const NONCE_2 = Buffer.from('f0e1d2c3b4a5968778695a4b3c2d1e0f', 'hex');
const C_SAMPLE = 'AAECAwQFBgcICQoLDA0ODw'; // a placeholder C: never opened by the parsers that read the samples
const BUILD = '0123456789abcdef';
const jtiOf = (label) => b64u(sha256(utf8(`mg-phase2-kat-jti-${label}`)).subarray(0, 16));

// ---------------------------------------------------------------------------
// §6.1 accepted epochs
// ---------------------------------------------------------------------------

function acceptedEpochs(nowMs) {
  const e = Math.floor(nowMs / DAY_MS);
  const d = nowMs - e * DAY_MS;
  return { min_epoch: d <= 605_000 ? e - 1 : e, max_epoch: DAY_MS - d <= 5_000 ? e + 1 : e };
}

const acceptedEpochsSection = {
  formula:
    'e = floor(now_ms / 86400000), d = now_ms - e*86400000; accept e; also e-1 iff d <= 605000 (600 s interactive lifetime + 5 s skew); also e+1 iff 86400000 - d <= 5000; one window for every challenge type (spec §6.1, D-42). Replaces the Phase 1 accepted_epochs vectors',
  cases: [
    ['day_start', DAY_START_MS],
    ['after_125_001_s', DAY_START_MS + 125_001],
    ['after_605_000_s', DAY_START_MS + 605_000],
    ['after_605_001_s', DAY_START_MS + 605_001],
    ['midday', DAY_START_MS + DAY_MS / 2],
    ['before_end_5_001_s', DAY_START_MS + DAY_MS - 5_001],
    ['before_end_5_000_s', DAY_START_MS + DAY_MS - 5_000],
  ].map(([name, now_ms]) => ({ name, now_ms, ...acceptedEpochs(now_ms) })),
};

// ---------------------------------------------------------------------------
// §6.3 ui_params
// ---------------------------------------------------------------------------

function uiParams(seed) {
  const u = sha256(cat(utf8('mg-ui-v1'), u8(0), u64be(seed)));
  return {
    u_hex: hex(u),
    required_hold_ms: 1200 + (u.readUInt16BE(0) % 1301),
    offset_x_px: (u[2] % 33) - 16,
    offset_y_px: (u[3] % 17) - 8,
  };
}

const uiParamsSection = {
  formula:
    "u = SHA-256('mg-ui-v1' || 0x00 || u64be(ui_seed)); required_hold_ms = 1200 + (u16be(u[0..2]) mod 1301); offset_x_px = (u[2] mod 33) - 16; offset_y_px = (u[3] mod 17) - 8. ui_seed is a decimal string (u64)",
  cases: [1n, 2n, 42n, 0xdeadbeefn, 1_790_000_000_123n, 1n << 53n, 1n << 63n, (1n << 64n) - 1n].map((seed) => ({
    ui_seed: seed.toString(),
    ...uiParams(seed),
  })),
};

// ---------------------------------------------------------------------------
// §6.4 PoW v2
// ---------------------------------------------------------------------------

const powPrefixV2 = (c) => cat(utf8('mg-pow-v2'), u8(0), sha256(ascii(c)));
const powDigestV2 = (prefix, i, counter) => sha256(cat(prefix, u8(i), u64be(counter)));

function powSolveV2(c, d, k) {
  const prefix = powPrefixV2(c);
  const out = [];
  for (let i = 0; i < k; i++) {
    for (let counter = 0; ; counter++) {
      const digest = powDigestV2(prefix, i, counter);
      if (leadingZeroBits(digest) >= d) {
        out.push({ i, counter, digest_hex: hex(digest), leading_zero_bits: leadingZeroBits(digest) });
        break;
      }
    }
  }
  return { prefix_hex: hex(prefix), counters: out.map((o) => o.counter), sub_puzzles: out };
}

const powV2Section = {
  formula:
    "prefix2 = 'mg-pow-v2' || 0x00 || SHA-256(C as ASCII) (42 bytes); digest_i = SHA-256(prefix2 || u8(i) || u64be(counter_i)), i = 0..k-1; solved iff every leading_zero_bits(digest_i) >= d and counter_i < 2^53; the canonical counter of each sub-puzzle is the smallest one, searched from 0 (spec §6.4, D-43)",
  cases: [
    ['mg-test-c-1', 8, 1],
    ['mg-test-c-1', 8, 2],
    ['mg-test-c-2', 10, 3],
    ['mg-test-c-2', 12, 4],
  ].map(([c, d, k]) => ({ c, d, k, ...powSolveV2(c, d, k) })),
};

// ---------------------------------------------------------------------------
// §6.5 JWK thumbprints and ES256
// ---------------------------------------------------------------------------

const RFC7638_N =
  '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
const rfc7638Input = `{"e":"AQAB","kty":"RSA","n":"${RFC7638_N}"}`;
assertEq(b64u(sha256(utf8(rfc7638Input))), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', 'RFC 7638 §3.1');
const RFC9449_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
  y: '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA',
};
assertEq(thumbprintEc(RFC9449_JWK), '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I', 'RFC 9449 §6.1');

const jwkThumbprintSection = {
  formula:
    'jkt = base64url_nopad(SHA-256(\'{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}\')): RFC 7638 with the members in lexicographic order and no whitespace; 43 characters (spec §6.5)',
  rfc7638_example: {
    note: 'RFC 7638 §3.1 (an RSA key): checks the formula only; MorphGate accepts P-256 keys only',
    canonical_json: rfc7638Input,
    thumbprint: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
  },
  cases: [
    { name: 'rfc9449_example', jwk: RFC9449_JWK, thumbprint: thumbprintEc(RFC9449_JWK) },
    ...KEYS.map((k, i) => ({
      name: `test_key_${i}`,
      jwk: k.jwk,
      canonical_json: `{"crv":"P-256","kty":"EC","x":"${k.jwk.x}","y":"${k.jwk.y}"}`,
      thumbprint: k.jkt,
    })),
  ],
};

const es256Section = (() => {
  const key = KEYS[0];
  const msg = utf8('mg-phase2-kat-es256');
  const sig = ecdsaSign(key.d, msg);
  const high = sig.s > N / 2n ? sig : { r: sig.r, s: N - sig.s };
  const low = sig.s > N / 2n ? { r: sig.r, s: N - sig.s } : sig;
  const changed = Buffer.from(msg);
  changed[changed.length - 1] ^= 0x01;
  const offCurve = { ...key.jwk, y: b64u(to32(mod(toInt(Buffer.from(key.jwk.y, 'base64url')) + 1n, P))) };
  const cases = [
    { name: 'valid_low_s', jwk: key.jwk, msg_hex: hex(msg), sig_b64url: b64u(p1363(low)), valid: true },
    {
      name: 'valid_high_s',
      note: 'the same signature with s replaced by n - s; WebCrypto does not normalize s, so it must be accepted',
      jwk: key.jwk,
      msg_hex: hex(msg),
      sig_b64url: b64u(p1363(high)),
      valid: true,
    },
    { name: 'message_changed', jwk: key.jwk, msg_hex: hex(changed), sig_b64url: b64u(p1363(low)), valid: false },
    {
      name: 'der_encoded',
      note: 'the valid signature in DER form: only the 64-byte IEEE P1363 r || s form is accepted',
      jwk: key.jwk,
      msg_hex: hex(msg),
      sig_b64url: b64u(der(low)),
      valid: false,
    },
    {
      name: 'point_not_on_curve',
      note: 'y + 1: the point is checked when verifying, with the same result as a bad signature',
      jwk: offCurve,
      msg_hex: hex(msg),
      sig_b64url: b64u(p1363(low)),
      valid: false,
    },
    {
      name: 'other_key',
      jwk: KEYS[1].jwk,
      msg_hex: hex(msg),
      sig_b64url: b64u(p1363(low)),
      valid: false,
    },
  ];
  for (const c of cases) {
    const ok = nodeVerifies(c.jwk, Buffer.from(c.msg_hex, 'hex'), Buffer.from(c.sig_b64url, 'base64url'));
    if (ok !== c.valid) throw new Error(`es256 case ${c.name}: node:crypto says ${ok}`);
  }
  return {
    formula:
      'ECDSA P-256 with SHA-256; the signature is the 64-byte IEEE P1363 r || s, sent as unpadded base64url (86 characters); DER is rejected; high-S is accepted; the public point is 0x04 || x || y (spec §6.5)',
    cases,
  };
})();

// ---------------------------------------------------------------------------
// §6.6 submission and renew messages
// ---------------------------------------------------------------------------

function submissionMessage(f) {
  return cat(
    utf8('mg-sub-v2'),
    u8(0),
    lp(f.c),
    lp(f.type),
    lp(f.p),
    lp(sha256(utf8(f.pp))),
    lp(sha256(utf8(f.t))),
    lp(f.counters.join(',')),
    lp(f.ret),
    u64be(f.ts),
    lp(f.build),
  );
}
const renewMessage = (c, ts) => cat(utf8('mg-renew-v1'), u8(0), lp(c), u64be(ts));

const T_IX_HOLD = JSON.stringify({
  ix: {
    v: 1,
    mode: 'hold',
    modality: 'mouse',
    locale: 'zh-CN',
    ks: 'idb',
    sv: '0.3.0',
    fallback: null,
    trusted: 3,
    act_ms: 2300,
    pre: { moves: 5, path_px: 9, straight: 0.7, speed_mean: 6, speed_sd: 4, dir_changes: 3, render_to_input_ms: 11, to_target_ms: 9 },
    hold: { ms: 1910, offset: [0.1, -0.2], jitter_px: 2, moves: 3, cancels: 0, pressure: 0.5, pressure_var: 0, contact_var: 0 },
    page: { vis: 0, vis_during: 0, focus: 0, frame_mean: 4, frame_sd: 1 },
    pow: { ms: 8, worker: true, impl: 'js' },
  },
});

const SUBMISSIONS = [
  {
    name: 'interactive_self_hold',
    key: 0,
    fields: {
      c: C_SAMPLE,
      type: 'interactive',
      p: 'self_hold',
      pp: '',
      t: T_IX_HOLD,
      counters: [12, 3401, 77, 912, 4005, 18, 230, 6600],
      ret: '/account/login',
      ts: 1_790_000_000_123,
      build: BUILD,
    },
  },
  {
    name: 'interactive_turnstile',
    key: 1,
    fields: {
      c: C_SAMPLE,
      type: 'interactive',
      p: 'turnstile',
      pp: 'kat.turnstile.token.0000000000000000',
      t: JSON.stringify({ ix: { v: 1, mode: 'external', modality: 'mouse', locale: 'en', ks: 'local', sv: '0.3.0', fallback: null, trusted: 3, act_ms: 1500 } }),
      counters: [3, 141],
      ret: '/signup',
      ts: 1_790_000_100_000,
      build: BUILD,
    },
  },
  {
    name: 'pow_non_interactive',
    key: 2,
    fields: { c: C_SAMPLE, type: 'pow', p: '', pp: '', t: '', counters: [38467], ret: '/', ts: 0, build: BUILD },
  },
];

const submissionSection = {
  formula:
    "'mg-sub-v2' || 0x00 || lp(c) || lp(type) || lp(p) || lp(H(pp)) || lp(H(t)) || lp(counters) || lp(ret) || u64be(ts) || lp(build); lp(x) = u16be(len(x)) || x; H = SHA-256 over the UTF-8 bytes of the string fields pp and t (empty when absent); counters = decimal counters joined by ',' (spec §6.6)",
  cases: SUBMISSIONS.map(({ name, key, fields }) => {
    const msg = submissionMessage(fields);
    return {
      name,
      fields: { ...fields, counters: fields.counters },
      counters_text: fields.counters.join(','),
      message_hex: hex(msg),
      jwk: KEYS[key].jwk,
      sig_b64url: b64u(es256(KEYS[key], msg)),
    };
  }),
};

const RENEWS = [
  { name: 'renew', key: 0, c: C_SAMPLE, ts: 1_790_000_480_000 },
  { name: 'renew_ts_zero', key: 3, c: 'mg-test-c-renew', ts: 0 },
];
const renewSection = {
  formula: "'mg-renew-v1' || 0x00 || lp(c) || u64be(ts) (spec §6.6)",
  cases: RENEWS.map(({ name, key, c, ts }) => {
    const msg = renewMessage(c, ts);
    return { name, c, ts, message_hex: hex(msg), jwk: KEYS[key].jwk, sig_b64url: b64u(es256(KEYS[key], msg)) };
  }),
};

// ---------------------------------------------------------------------------
// §6.7 MG-Proof
// ---------------------------------------------------------------------------

const PROOF_REQUEST = { method: 'POST', scheme: 'https', host: HOST, path: '/api/save', now_s: NOW_S, expected_jkt: KEYS[0].jkt };

function buildProof({ key = 0, header, payload, headerText, payloadText, sig }) {
  const k = KEYS[key];
  const h = headerText ?? JSON.stringify(header ?? { alg: 'ES256', typ: 'mg-proof+jwt', jwk: k.jwk });
  const p = payloadText ?? JSON.stringify({ htm: 'POST', htu: `https://${HOST}/api/save`, iat: NOW_S, jti: jtiOf('valid'), ...payload });
  const input = `${b64u(utf8(h))}.${b64u(utf8(p))}`;
  const s = sig ? sig(input, k) : b64u(es256(k, ascii(input)));
  return `${input}.${s}`;
}
const defaultJwk = KEYS[0].jwk;
const flipLastByte = (input, k) => {
  const b = es256(k, ascii(input));
  b[b.length - 1] ^= 0x01;
  return b64u(b);
};

const PROOF_CASES = [
  // Valid proofs.
  { name: 'valid', proof: {}, expect: 'valid' },
  { name: 'valid_iat_minus_30', proof: { payload: { iat: NOW_S - 30 } }, expect: 'valid' },
  { name: 'valid_iat_plus_5', proof: { payload: { iat: NOW_S + 5 } }, expect: 'valid' },
  {
    name: 'valid_high_s',
    proof: {
      sig: (input, k) => {
        const s = ecdsaSign(k.d, ascii(input));
        const high = s.s > N / 2n ? s : { r: s.r, s: N - s.s };
        return b64u(p1363(high));
      },
    },
    expect: 'valid',
  },
  {
    name: 'valid_members_reordered',
    proof: {
      headerText: JSON.stringify({ jwk: { y: defaultJwk.y, x: defaultJwk.x, crv: 'P-256', kty: 'EC' }, typ: 'mg-proof+jwt', alg: 'ES256' }),
      payloadText: JSON.stringify({ jti: jtiOf('valid'), iat: NOW_S, htu: `https://${HOST}/api/save`, htm: 'POST' }),
    },
    expect: 'valid',
  },
  { name: 'valid_query_and_fragment_ignored', proof: { payload: { htu: `https://${HOST}/api/save?draft=1#top` } }, expect: 'valid' },
  { name: 'valid_host_upper_case', proof: { payload: { htu: 'https://EXAMPLE.com/api/save' } }, expect: 'valid' },
  { name: 'valid_host_trailing_dot', proof: { payload: { htu: 'https://example.com./api/save' } }, expect: 'valid' },
  {
    name: 'valid_dot_segments',
    note: 'both paths are compared through mg_core::paths::cloudflare_view, which removes dot segments',
    proof: { payload: { htu: `https://${HOST}/api/v1/../save` } },
    expect: 'valid',
  },
  {
    name: 'valid_percent_hex_case',
    note: 'cloudflare_view upper-cases the hex digits of escapes it keeps',
    proof: { payload: { htu: `https://${HOST}/api%2fsave` } },
    request: { path: '/api%2Fsave' },
    expect: 'valid',
  },
  {
    name: 'valid_percent_encoded_non_ascii',
    proof: { payload: { htu: `https://${HOST}/caf%c3%a9` } },
    request: { path: '/caf%C3%A9' },
    expect: 'valid',
  },
  { name: 'valid_ip_literal', proof: { payload: { htu: 'https://203.0.113.10/api/save' } }, request: { host: '203.0.113.10' }, expect: 'valid' },
  {
    name: 'valid_lower_case_patch',
    note: 'fetch upper-cases only DELETE GET HEAD OPTIONS POST PUT; a lower-case patch is sent as is',
    proof: { payload: { htm: 'patch' } },
    request: { method: 'patch' },
    expect: 'valid',
  },
  // 1. proof.malformed
  { name: 'header_duplicate_key', proof: { headerText: `{"alg":"ES256","alg":"ES256","typ":"mg-proof+jwt","jwk":${JSON.stringify(defaultJwk)}}` }, expect: 'proof.malformed' },
  {
    name: 'payload_duplicate_key',
    proof: { payloadText: `{"htm":"POST","htm":"POST","htu":"https://${HOST}/api/save","iat":${NOW_S},"jti":"${jtiOf('valid')}"}` },
    expect: 'proof.malformed',
  },
  { name: 'header_unknown_member', proof: { header: { alg: 'ES256', typ: 'mg-proof+jwt', jwk: defaultJwk, kid: 'k1' } }, expect: 'proof.malformed' },
  { name: 'payload_unknown_member', proof: { payload: { nonce: 'n' } }, expect: 'proof.malformed' },
  { name: 'payload_missing_jti', proof: { payloadText: JSON.stringify({ htm: 'POST', htu: `https://${HOST}/api/save`, iat: NOW_S }) }, expect: 'proof.malformed' },
  { name: 'jwk_extra_ext', proof: { header: { alg: 'ES256', typ: 'mg-proof+jwt', jwk: { ...defaultJwk, ext: true } } }, expect: 'proof.malformed' },
  {
    name: 'jwk_extra_key_ops',
    proof: { header: { alg: 'ES256', typ: 'mg-proof+jwt', jwk: { ...defaultJwk, key_ops: ['verify'] } } },
    expect: 'proof.malformed',
  },
  {
    name: 'jwk_x_31_bytes',
    proof: { header: { alg: 'ES256', typ: 'mg-proof+jwt', jwk: { ...defaultJwk, x: b64u(Buffer.from(defaultJwk.x, 'base64url').subarray(1)) } } },
    expect: 'proof.malformed',
  },
  { name: 'jwk_crv_p384', proof: { header: { alg: 'ES256', typ: 'mg-proof+jwt', jwk: { ...defaultJwk, crv: 'P-384' } } }, expect: 'proof.malformed' },
  { name: 'alg_es384', proof: { header: { alg: 'ES384', typ: 'mg-proof+jwt', jwk: defaultJwk } }, expect: 'proof.malformed' },
  { name: 'typ_dpop', proof: { header: { alg: 'ES256', typ: 'dpop+jwt', jwk: defaultJwk } }, expect: 'proof.malformed' },
  { name: 'jti_21_chars', proof: { payload: { jti: jtiOf('valid').slice(0, 21) } }, expect: 'proof.malformed' },
  { name: 'iat_not_integer', proof: { payload: { iat: NOW_S + 0.5 } }, expect: 'proof.malformed' },
  { name: 'iat_string', proof: { payload: { iat: String(NOW_S) } }, expect: 'proof.malformed' },
  { name: 'htm_33_bytes', proof: { payload: { htm: 'P'.repeat(33) } }, request: { method: 'P'.repeat(33) }, expect: 'proof.malformed' },
  { name: 'htu_2049_bytes', proof: { payload: { htu: `https://${HOST}/${'a'.repeat(2049 - `https://${HOST}/`.length)}` } }, expect: 'proof.malformed' },
  { name: 'padded_base64', raw: (v) => v.replace('.', '=.'), expect: 'proof.malformed' },
  { name: 'two_segments', raw: (v) => v.split('.').slice(0, 2).join('.'), expect: 'proof.malformed' },
  { name: 'longer_than_4096', raw: () => `${'A'.repeat(2000)}.${'A'.repeat(2000)}.${'A'.repeat(95)}`, expect: 'proof.malformed' },
  // 2. proof.unbound
  { name: 'unbound', proof: {}, request: { expected_jkt: null }, expect: 'proof.unbound' },
  { name: 'unbound_before_sig', proof: { sig: flipLastByte }, request: { expected_jkt: null }, expect: 'proof.unbound' },
  { name: 'malformed_before_unbound', proof: { payload: { nonce: 'n' } }, request: { expected_jkt: null }, expect: 'proof.malformed' },
  // 3. proof.jkt
  { name: 'jkt_mismatch', proof: {}, request: { expected_jkt: KEYS[1].jkt }, expect: 'proof.jkt' },
  { name: 'jkt_before_htu', proof: { payload: { htu: 'https://other.example/api/save' } }, request: { expected_jkt: KEYS[1].jkt }, expect: 'proof.jkt' },
  // 4. proof.htm
  { name: 'htm_mismatch', proof: { payload: { htm: 'GET' } }, expect: 'proof.htm' },
  { name: 'htm_upper_case_patch', proof: { payload: { htm: 'PATCH' } }, request: { method: 'patch' }, expect: 'proof.htm' },
  { name: 'htm_lower_case_patch', proof: { payload: { htm: 'patch' } }, request: { method: 'PATCH' }, expect: 'proof.htm' },
  { name: 'htm_before_iat_and_sig', proof: { payload: { htm: 'GET', iat: NOW_S - 31 }, sig: flipLastByte }, expect: 'proof.htm' },
  // 5. proof.htu
  { name: 'htu_http_scheme', proof: { payload: { htu: `http://${HOST}/api/save` } }, expect: 'proof.htu' },
  { name: 'htu_request_over_http', proof: {}, request: { scheme: 'http' }, expect: 'proof.htu' },
  { name: 'htu_other_host', proof: { payload: { htu: 'https://www.example.com/api/save' } }, expect: 'proof.htu' },
  {
    name: 'htu_host_with_port',
    note: 'the port is compared as is; the normalized request host never has one',
    proof: { payload: { htu: `https://${HOST}:443/api/save` } },
    expect: 'proof.htu',
  },
  { name: 'htu_userinfo', proof: { payload: { htu: `https://user@${HOST}/api/save` } }, expect: 'proof.htu' },
  { name: 'htu_ip_literal_for_name', proof: { payload: { htu: 'https://203.0.113.10/api/save' } }, expect: 'proof.htu' },
  { name: 'htu_other_path', proof: { payload: { htu: `https://${HOST}/api/delete` } }, expect: 'proof.htu' },
  {
    name: 'htu_encoded_slash',
    note: 'cloudflare_view keeps %2F encoded, so /api%2Fsave is not /api/save',
    proof: { payload: { htu: `https://${HOST}/api%2Fsave` } },
    expect: 'proof.htu',
  },
  {
    name: 'htu_dot_segments_elsewhere',
    proof: { payload: { htu: `https://${HOST}/api/../admin/save` } },
    expect: 'proof.htu',
  },
  {
    name: 'htu_raw_non_ascii_path',
    note: 'the browser sends /caf%C3%A9; a raw UTF-8 path in htu does not match',
    proof: { payload: { htu: `https://${HOST}/café` } },
    request: { path: '/caf%C3%A9' },
    expect: 'proof.htu',
  },
  { name: 'htu_relative', proof: { payload: { htu: '/api/save' } }, expect: 'proof.htu' },
  // 6. proof.iat
  { name: 'iat_minus_31', proof: { payload: { iat: NOW_S - 31 } }, expect: 'proof.iat' },
  { name: 'iat_plus_6', proof: { payload: { iat: NOW_S + 6 } }, expect: 'proof.iat' },
  { name: 'iat_before_sig', proof: { payload: { iat: NOW_S - 31 }, sig: flipLastByte }, expect: 'proof.iat' },
  // 7. proof.sig
  { name: 'sig_changed', proof: { sig: flipLastByte }, expect: 'proof.sig' },
  { name: 'sig_by_other_key', proof: { sig: (input) => b64u(es256(KEYS[1], ascii(input))) }, expect: 'proof.sig' },
  {
    name: 'sig_der',
    note: 'well-formed base64url but not 64 bytes: a signature failure, not a format failure',
    proof: { sig: (input, k) => b64u(der(ecdsaSign(k.d, ascii(input)))) },
    expect: 'proof.sig',
  },
  {
    name: 'sig_point_not_on_curve',
    proof: {
      header: {
        alg: 'ES256',
        typ: 'mg-proof+jwt',
        jwk: { ...defaultJwk, y: b64u(to32(mod(toInt(Buffer.from(defaultJwk.y, 'base64url')) + 1n, P))) },
      },
    },
    request: {},
    expect: 'proof.sig',
  },
];

const mgProofSection = (() => {
  const cases = PROOF_CASES.map((c) => {
    let value = buildProof(c.proof ?? {});
    if (c.raw) value = c.raw(buildProof({}));
    const request = { ...PROOF_REQUEST, ...(c.request ?? {}) };
    // The off-curve key's thumbprint is what the token would carry if it had been bound to it.
    if (c.name === 'sig_point_not_on_curve') request.expected_jkt = thumbprintEc(c.proof.header.jwk);
    const out = { name: c.name };
    if (c.note) out.note = c.note;
    out.mg_proof = value;
    out.request = request;
    out.expect = c.expect;
    if (c.expect === 'valid') {
      const payload = JSON.parse(Buffer.from(value.split('.')[1], 'base64url').toString('utf8'));
      out.jti_hex = hex(Buffer.from(payload.jti, 'base64url'));
      out.iat = payload.iat;
    }
    return out;
  });
  return {
    format:
      "MG-Proof = B64(header) '.' B64(payload) '.' B64(sig), unpadded base64url, <= 4096 bytes; header exactly {alg: ES256, typ: mg-proof+jwt, jwk}; payload exactly {htm, htu, iat, jti}; the signature input is the ASCII of B64(header) '.' B64(payload) (spec §6.7)",
    order:
      'proof.malformed (format, size, JSON with duplicate keys or unknown members, JWK members and lengths) -> proof.unbound (no expected_jkt) -> proof.jkt -> proof.htm (case-sensitive) -> proof.htu (https on both sides; RFC 3986 host without userinfo, normalized like the request host, port compared as is; path before ? or # compared through mg_core::paths::cloudflare_view on both sides) -> proof.iat (now - 30 <= iat <= now + 5) -> proof.sig (64-byte r || s, point on the curve); the first failure is the reason',
    request_fields:
      'method, scheme and path are the request\'s (path without the query); host is the normalized request host; expected_jkt is the cnf.jkt of the request\'s valid clearance, null when there is none',
    cases,
  };
})();

// ---------------------------------------------------------------------------
// §6.9 Turnstile cData, idempotency key; bind.jkt
// ---------------------------------------------------------------------------

const turnstileCdata = (root, site, epoch, nonce) =>
  b64u(hmac(epochKey('mg-bind-v1', root, site, epoch), cat(utf8('mg-ts-cdata-v1'), u8(0), lp(site), lp(nonce))));

function uuidV4Format(b16) {
  const b = Buffer.from(b16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const idempotencyKey = (nonce, previous) =>
  uuidV4Format(sha256(cat(utf8('mg-ts-idem-v1'), u8(0), nonce, previous ? u8(1) : Buffer.alloc(0))).subarray(0, 16));

const cdataSection = {
  formula:
    "k_bind = HKDF-SHA256(salt = empty, ikm = root, info = 'mg-bind-v1' || 0x00 || site_id || 0x00 || u64be(epoch of C.kid), 32); cdata = base64url_nopad(HMAC-SHA256(k_bind, 'mg-ts-cdata-v1' || 0x00 || lp(site_id) || lp(nonce))), 43 characters (spec §6.9)",
  cases: [
    ['root_1', SEAL_ROOT, SITE, EPOCH, NONCE],
    ['root_1_next_epoch', SEAL_ROOT, SITE, EPOCH + 1, NONCE],
    ['root_1_other_nonce', SEAL_ROOT, SITE, EPOCH, NONCE_2],
    ['root_1_other_site', SEAL_ROOT, 'shop', EPOCH, NONCE],
    ['root_2', SEAL_ROOT_2, SITE, EPOCH, NONCE],
  ].map(([name, root, site, epoch, nonce]) => ({
    name,
    root_hex: hex(root),
    site,
    epoch,
    nonce_hex: hex(nonce),
    k_bind_hex: hex(epochKey('mg-bind-v1', root, site, epoch)),
    cdata: turnstileCdata(root, site, epoch, nonce),
  })),
};

const idempotencySection = {
  formula:
    "idempotency_key = uuid_v4_format(SHA-256('mg-ts-idem-v1' || 0x00 || nonce)[0..16]); with the previous secret: uuid_v4_format(SHA-256('mg-ts-idem-v1' || 0x00 || nonce || 0x01)[0..16]); uuid_v4_format sets the high 4 bits of byte 6 to 0100 and the high 2 bits of byte 8 to 10, then prints 8-4-4-4-12 lower-case hex (spec §6.9)",
  cases: [NONCE, NONCE_2, Buffer.alloc(16, 0xff)].map((nonce) => ({
    nonce_hex: hex(nonce),
    idempotency_key: idempotencyKey(nonce, false),
    idempotency_key_previous_secret: idempotencyKey(nonce, true),
  })),
};

const bindJktSection = {
  formula: "bind.jkt = bind_hash('jkt', <43-character thumbprint>) = SHA-256('mg-bind-v1' || 0x00 || 'jkt' || 0x00 || jkt)[0..16] (Phase 1 spec §6.4; Phase 2 spec §6.5)",
  cases: [RFC9449_JWK, ...KEYS.map((k) => k.jwk)].map((jwk) => {
    const jkt = thumbprintEc(jwk);
    return { jkt, hash_hex: hex(bindHash('jkt', jkt)), hash_b64url: b64u(bindHash('jkt', jkt)) };
  }),
};

// ---------------------------------------------------------------------------
// kat.json
// ---------------------------------------------------------------------------

const kat = {
  version: 1,
  about:
    'Shared known-answer vectors for Phase 2 (docs/impl/phase2-spec.md §6.11). Read-only for every work package; generated by gen/kat.mjs, change the spec before changing them. Byte strings are lower-case hex (_hex) or unpadded base64url (_b64url); u64 values that do not fit a double are decimal strings.',
  test_keys: {
    about:
      "P-256 test keys: d = (SHA-256(label) mod (n - 1)) + 1. Their signatures here use RFC 6979 nonces; consumers verify them and never need d",
    keys: KEYS.map((k) => ({ label: k.label, jwk: k.jwk, jkt: k.jkt })),
  },
  accepted_epochs: acceptedEpochsSection,
  ui_params: uiParamsSection,
  pow_v2: powV2Section,
  jwk_thumbprint: jwkThumbprintSection,
  es256: es256Section,
  submission_message: submissionSection,
  renew_message: renewSection,
  mg_proof: mgProofSection,
  cdata: cdataSection,
  idempotency_key: idempotencySection,
  bind_jkt: bindJktSection,
};

// ---------------------------------------------------------------------------
// Samples
// ---------------------------------------------------------------------------

const files = new Map(); // path relative to testdata/phase2 -> content
const json2 = (v) => `${JSON.stringify(v, null, 2)}\n`;
const put = (path, content) => files.set(path, content);

files.set('kat.json', json2(kat));

// samples/keys: mg-turnstile-keys (§8.7). Canonical files: two-space JSON, one trailing newline.
{
  const current = '0x4AAAAAAAkat-test-secret-current-00000000';
  const previous = '0x4AAAAAAAkat-test-secret-previous-0000000';
  const file = (values, extra = {}) => ({ v: 1, kind: 'mg-turnstile-keys', site: SITE, values, ...extra });
  const valid = {
    'one-value.json': json2(file([current])),
    'two-values.json': json2(file([current, previous])),
    'printable-edges.json': json2(file([`!${'~'.repeat(254)}!`, '!'])),
  };
  const invalid = {
    'not-json.json': '{"v": 1, "kind": "mg-turnstile-keys",\n',
    'top-level-array.json': json2([file([current])]),
    'wrong-version.json': json2({ ...file([current]), v: 2 }),
    'wrong-kind.json': json2({ ...file([current]), kind: 'mg-origin-keys' }),
    'missing-site.json': json2({ v: 1, kind: 'mg-turnstile-keys', values: [current] }),
    'missing-values.json': json2({ v: 1, kind: 'mg-turnstile-keys', site: SITE }),
    'zero-values.json': json2(file([])),
    'three-values.json': json2(file([current, previous, 'x'])),
    'empty-value.json': json2(file([''])),
    'value-257-chars.json': json2(file(['a'.repeat(257)])),
    'value-with-space.json': json2(file(['0x4AAAAAAA kat'])),
    'value-non-ascii.json': json2(file(['0x4AAAAAAAkät'])),
    'value-not-string.json': json2(file([42])),
    'unknown-field.json': json2(file([current], { note: 'x' })),
    'duplicate-key.json': `{\n  "v": 1,\n  "kind": "mg-turnstile-keys",\n  "site": "${SITE}",\n  "site": "${SITE}",\n  "values": [\n    "${current}"\n  ]\n}\n`,
  };
  const contextual = { 'site-mismatch.json': json2({ ...file([current]), site: 'shop' }) };
  for (const [n, c] of Object.entries(valid)) put(`samples/keys/valid/${n}`, c);
  for (const [n, c] of Object.entries(invalid)) put(`samples/keys/invalid/${n}`, c);
  for (const [n, c] of Object.entries(contextual)) put(`samples/keys/invalid/${n}`, c);
  put(
    'samples/keys/cases.json',
    json2({
      about:
        'mg-turnstile-keys files (spec §8.7) for [[sites]] id "blog". valid/ parse; invalid/ are rejected (--check-config fails). site-mismatch.json is well-formed but names another site. The 64 KiB size cap is not sampled (tests build an oversized file)',
      site: SITE,
      valid: Object.keys(valid).map((f) => ({ file: `valid/${f}`, values: JSON.parse(valid[f]).values.length })),
      invalid: [...Object.keys(invalid), ...Object.keys(contextual)].map((f) => ({ file: `invalid/${f}` })),
    }),
  );
}

// samples/siteverify: siteverify response bodies (§8.4, §8.5).
{
  const nonce = NONCE;
  const cIatMs = NOW_MS;
  const nowMs = NOW_MS + 60_000;
  const cdata = turnstileCdata(SEAL_ROOT, SITE, Math.floor(cIatMs / DAY_MS), nonce);
  const iso = (ms) => new Date(ms).toISOString();
  const ok = { success: true, challenge_ts: iso(NOW_MS + 30_000), hostname: HOST, 'error-codes': [], action: 'login', cdata };
  const fail = (codes) => ({ success: false, 'error-codes': codes });
  const cases = [
    ['pass', ok, 'pass', null],
    ['pass-extra-fields', { ...ok, metadata: { ephemeral_id: 'x:kat0000000000000000' }, extra: [1, 2] }, 'pass', null],
    ['pass-challenge-ts-at-c-iat-minus-5s', { ...ok, challenge_ts: iso(cIatMs - 5_000) }, 'pass', null],
    ['hostname-mismatch', { ...ok, hostname: 'www.example.com' }, 'fail', 'ic.ts_hostname'],
    ['hostname-not-configured', { ...ok, hostname: 'evil.example' }, 'fail', 'ic.ts_hostname'],
    ['action-mismatch', { ...ok, action: 'signup' }, 'fail', 'ic.ts_action'],
    ['cdata-mismatch', { ...ok, cdata: turnstileCdata(SEAL_ROOT, SITE, Math.floor(cIatMs / DAY_MS), NONCE_2) }, 'fail', 'ic.ts_cdata'],
    ['challenge-ts-before-c-iat', { ...ok, challenge_ts: iso(cIatMs - 5_001) }, 'fail', 'ic.ts_time'],
    ['challenge-ts-in-future', { ...ok, challenge_ts: iso(nowMs + 5_001) }, 'fail', 'ic.ts_time'],
    ['challenge-ts-older-than-300s', ok, 'fail', 'ic.ts_time', { now_ms: NOW_MS + 30_000 + 300_001 }],
    ['pass-challenge-ts-300s-old', ok, 'pass', null, { now_ms: NOW_MS + 30_000 + 300_000 }],
    ['invalid-input-response', fail(['invalid-input-response']), 'fail', 'ic.ts_fail'],
    ['missing-input-response', fail(['missing-input-response']), 'fail', 'ic.ts_fail'],
    ['timeout-or-duplicate', fail(['timeout-or-duplicate']), 'fail', 'ic.ts_dup'],
    ['bad-request', fail(['bad-request']), 'unavailable', 'ic.provider_unavailable'],
    ['internal-error', fail(['internal-error']), 'unavailable', 'ic.provider_unavailable'],
    ['invalid-input-secret', fail(['invalid-input-secret']), 'misconfigured', 'ic.provider_misconfigured'],
    ['missing-input-secret', fail(['missing-input-secret']), 'misconfigured', 'ic.provider_misconfigured'],
  ];
  const malformed = {
    'not-json': '{"success": true,',
    'top-level-array': '[{"success": true}]\n',
    'success-not-bool': json2({ ...ok, success: 'true' }),
    'success-missing': json2({ hostname: HOST, 'error-codes': [] }),
    'challenge-ts-not-rfc3339': json2({ ...ok, challenge_ts: '1790000030' }),
    'error-codes-9': json2(fail(Array.from({ length: 9 }, () => 'internal-error'))),
    'error-codes-not-array': json2({ success: false, 'error-codes': 'internal-error' }),
    'larger-than-16-kib': json2({ ...ok, padding: 'x'.repeat(16 * 1024) }),
  };
  for (const [name, body] of cases) put(`samples/siteverify/${name}.json`, json2(body));
  for (const [name, body] of Object.entries(malformed)) put(`samples/siteverify/malformed/${name}.json`, body);
  put(
    'samples/siteverify/cases.json',
    json2({
      about:
        'Turnstile siteverify response bodies (HTTP 200, application/json) and the outcome of spec §8.5 for the expectation below (a case may override now_ms). malformed/ are responses that do not fit §8.4 (Unavailable, ic.provider_unavailable). Retries (§8.4) are the client\'s: internal-error is retried once with the same idempotency key, invalid-input-secret once with the previous secret when there is one; the outcomes here are after the retries, without a previous secret',
      expect: {
        host: HOST,
        hostnames: [HOST, 'www.example.com'],
        action: 'login',
        cdata,
        cdata_from: { root_hex: hex(SEAL_ROOT), site: SITE, epoch: Math.floor(cIatMs / DAY_MS), nonce_hex: hex(nonce) },
        c_iat_ms: cIatMs,
        now_ms: nowMs,
      },
      cases: [
        ...cases.map(([name, , outcome, reason, override]) => ({ file: `${name}.json`, ...(override ?? {}), outcome, reason })),
        ...Object.keys(malformed).map((name) => ({ file: `malformed/${name}.json`, outcome: 'unavailable', reason: 'ic.provider_unavailable' })),
      ],
    }),
  );
}

// samples/proof: a few MG-Proof header values; the full set with reasons is kat.json mg_proof.
{
  const pick = ['valid', 'valid_high_s', 'jwk_extra_ext', 'jkt_mismatch', 'htu_encoded_slash', 'iat_minus_31', 'sig_changed'];
  const chosen = mgProofSection.cases.filter((c) => pick.includes(c.name));
  for (const c of chosen) put(`samples/proof/${c.name.replaceAll('_', '-')}.txt`, `${c.mg_proof}\n`);
  put(
    'samples/proof/cases.json',
    json2({
      about: 'MG-Proof header values (one line each, without the header name) and their result; the same cases with every other reason are in kat.json mg_proof',
      cases: chosen.map((c) => ({ file: `${c.name.replaceAll('_', '-')}.txt`, request: c.request, expect: c.expect })),
    }),
  );
}

// samples/submissions: POST /__mg/c v2 and POST /__mg/c/renew request bodies (§7.4, §7.5).
{
  const body = (s, extra = {}) => {
    const f = s.fields;
    const msg = submissionMessage(f);
    const sig = b64u(es256(KEYS[s.key], msg));
    return {
      v: 2,
      type: f.type,
      c: f.c,
      p: f.p,
      pp: f.pp,
      t: f.t,
      pow: { counters: f.counters },
      ret: f.ret,
      ts: f.ts,
      build: f.build,
      jwk: KEYS[s.key].jwk,
      sig,
      ...extra,
    };
  };
  const [ixHold, ixTurnstile, powSub] = SUBMISSIONS;
  const a11y = {
    key: 3,
    fields: { c: C_SAMPLE, type: 'interactive', p: 'pow_a11y', pp: '', t: '', counters: [1, 2, 3, 4, 5, 6, 7, 8], ret: '/account/login', ts: 1_790_000_000_500, build: BUILD },
  };
  const valid = {
    'interactive-self-hold.json': body(ixHold),
    'interactive-turnstile.json': body(ixTurnstile),
    'interactive-pow-a11y-without-ix.json': body(a11y),
    'pow.json': body(powSub),
    'unknown-top-level-field.json': body(ixHold, { extra: { ignored: true } }),
  };
  // Invalid bodies: step 3 (ic.body) unless noted; signatures are over the body's own fields.
  const withFields = (base, change) => {
    const s = { key: base.key, fields: { ...base.fields, ...change } };
    return body(s);
  };
  const drop = (obj, key) => {
    const o = { ...obj };
    delete o[key];
    return o;
  };
  const bodyError = {
    'v-3.json': { ...body(ixHold), v: 3 },
    'interactive-v1.json': { ...body(ixHold), v: 1 },
    'missing-jwk.json': drop(body(ixHold), 'jwk'),
    'missing-sig.json': drop(body(ixHold), 'sig'),
    'jwk-not-object.json': { ...body(ixHold), jwk: 'x' },
    'counters-0.json': withFields(ixHold, { counters: [] }),
    'counters-9.json': withFields(ixHold, { counters: [1, 2, 3, 4, 5, 6, 7, 8, 9] }),
    'counter-2-pow-53.json': { ...body(ixHold), pow: { counters: [9007199254740992] } },
    'counter-negative.json': { ...body(ixHold), pow: { counters: [-1] } },
    'ts-negative.json': { ...body(ixHold), ts: -1 },
    'ts-2-pow-53-plus-1.json': { ...body(ixHold), ts: 9007199254740993 },
    'ts-float.json': { ...body(ixHold), ts: 1790000000123.5 },
    't-not-string.json': { ...body(ixHold), t: JSON.parse(ixHold.fields.t) },
    't-not-object.json': withFields(ixHold, { t: '[]' }),
    't-duplicate-key.json': withFields(ixHold, { t: '{"ix":{"v":1},"ix":{"v":1}}' }),
    'pp-4097-bytes.json': withFields(ixTurnstile, { pp: 'a'.repeat(4097) }),
  };
  // A t of exactly 2049 bytes.
  {
    const head = '{"pad":"';
    const tail = '"}';
    const t = head + 'x'.repeat(2049 - head.length - tail.length) + tail;
    bodyError['t-2049-bytes.json'] = withFields(ixHold, { t });
  }
  const rawBodyError = {
    'duplicate-top-level-key.json': JSON.stringify(body(ixHold)).replace('{"v":2,', '{"v":2,"v":2,'),
    'larger-than-8-kib.json': JSON.stringify({ ...body(ixHold), extra: 'x'.repeat(8 * 1024) }),
    'not-json.json': '{"v":2,"type":"interactive",',
  };
  const sigError = {
    'sig-other-message.json': { ...body(ixHold), ret: '/' },
    'sig-other-key.json': { ...body(ixHold), jwk: KEYS[1].jwk },
    'jwk-extra-ext.json': { ...body(ixHold), jwk: { ...KEYS[0].jwk, ext: true } },
    'sig-der.json': {
      ...body(ixHold),
      sig: b64u(der(ecdsaSign(KEYS[ixHold.key].d, submissionMessage(ixHold.fields)))),
    },
  };
  for (const [n, b] of Object.entries(valid)) put(`samples/submissions/valid/${n}`, json2(b));
  for (const [n, b] of Object.entries(bodyError)) put(`samples/submissions/invalid/${n}`, json2(b));
  for (const [n, b] of Object.entries(rawBodyError)) put(`samples/submissions/invalid/${n}`, `${b}\n`);
  for (const [n, b] of Object.entries(sigError)) put(`samples/submissions/invalid/${n}`, json2(b));

  const renewBody = (r, extra = {}) => {
    const msg = renewMessage(r.c, r.ts);
    return { v: 2, c: r.c, jwk: KEYS[r.key].jwk, ts: r.ts, sig: b64u(es256(KEYS[r.key], msg)), ...extra };
  };
  const renewValid = { 'renew.json': renewBody(RENEWS[0]) };
  const renewBodyError = {
    'renew-missing-jwk.json': drop(renewBody(RENEWS[0]), 'jwk'),
    'renew-v-1.json': { ...renewBody(RENEWS[0]), v: 1 },
    'renew-ts-float.json': { ...renewBody(RENEWS[0]), ts: 1.5 },
  };
  const renewSigError = { 'renew-sig-other-ts.json': { ...renewBody(RENEWS[0]), ts: RENEWS[0].ts + 1 } };
  for (const [n, b] of Object.entries(renewValid)) put(`samples/submissions/valid/${n}`, json2(b));
  for (const [n, b] of Object.entries(renewBodyError)) put(`samples/submissions/invalid/${n}`, json2(b));
  for (const [n, b] of Object.entries(renewSigError)) put(`samples/submissions/invalid/${n}`, json2(b));

  put(
    'samples/submissions/cases.json',
    json2({
      about:
        'Request bodies (application/json) of POST /__mg/c v2 (spec §7.5) and POST /__mg/c/renew (spec §7.4). c is a placeholder, never opened: these samples exercise the body rules (step 3, ic.body) and the signature (step 8 / renew step 6, ic.sig) only. Signatures are ES256 over the message of spec §6.6 built from the body itself',
      cases: [
        ...Object.keys(valid).map((f) => ({ file: `valid/${f}`, endpoint: '/__mg/c', expect: 'ok' })),
        ...Object.keys(renewValid).map((f) => ({ file: `valid/${f}`, endpoint: '/__mg/c/renew', expect: 'ok' })),
        ...[...Object.keys(bodyError), ...Object.keys(rawBodyError)].map((f) => ({ file: `invalid/${f}`, endpoint: '/__mg/c', expect: 'ic.body' })),
        ...Object.keys(sigError).map((f) => ({ file: `invalid/${f}`, endpoint: '/__mg/c', expect: 'ic.sig' })),
        ...Object.keys(renewBodyError).map((f) => ({ file: `invalid/${f}`, endpoint: '/__mg/c/renew', expect: 'ic.body' })),
        ...Object.keys(renewSigError).map((f) => ({ file: `invalid/${f}`, endpoint: '/__mg/c/renew', expect: 'ic.sig' })),
      ],
    }),
  );
}

// samples/telemetry: the t string of a submission (§7.5, §7.6), /__mg/t bodies (§9.4) and
// behavior summaries (§12.8).
{
  const ix = JSON.parse(T_IX_HOLD).ix;
  const env = {
    v: 1,
    ua: { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', brands: [{ brand: 'Chromium', version: '131' }], mobile: false, platform: 'macOS' },
    languages: ['zh-CN', 'en'],
    timeZone: 'Asia/Shanghai',
    utcOffsetMin: -480,
    dpr: 2,
  };
  const auto = { v: 1, webdriver: false };
  const single = { v: 1, mode: 'single', modality: 'keyboard', locale: 'en', ks: 'local', sv: '0.3.0', fallback: null, trusted: 3, act_ms: 2000, single: { wait_ms: 1880 }, page: { vis: 1, vis_during: 0, focus: 2, frame_mean: 4, frame_sd: 1 }, pow: { ms: 9, worker: true, impl: 'wasm' } };
  const powOnly = { v: 1, mode: 'pow_only', modality: 'none', locale: 'zh-CN', ks: 'memory', sv: '0.3.0', fallback: 'ts_load_timeout', trusted: 0, act_ms: 4100, pow: { ms: 11, worker: false, impl: 'js' } };
  const tValid = {
    'hold.json': { env, auto, ix },
    'single.json': { ix: single },
    'pow-only.json': { ix: powOnly },
    'external.json': { ix: { v: 1, mode: 'external', modality: 'touch', locale: 'en', ks: 'idb', sv: '0.3.0', fallback: null, trusted: 3, act_ms: 1500 } },
    'empty.json': {},
    'env-auto-only.json': { env, auto },
    'unknown-fields-dropped.json': { ix: { ...single, future: 1, single: { wait_ms: 1880, extra: true } }, other: { x: 1 } },
    'bounds.json': { ix: { ...ix, sv: '1.2.3-rc.1+b.20', act_ms: 600000, hold: { ...ix.hold, ms: 60000, offset: [-1, 1], cancels: 15, pressure: 1, pressure_var: 1, contact_var: 1 }, page: { ...ix.page, vis: 31, vis_during: 15 }, pow: { ms: 31, worker: false, impl: 'wasm' } } },
  };
  const ixInvalid = {
    'ix-v-2.json': { ix: { ...ix, v: 2 } },
    'ix-mode-unknown.json': { ix: { ...ix, mode: 'drag' } },
    'ix-modality-unknown.json': { ix: { ...ix, modality: 'eye' } },
    'ix-locale-unknown.json': { ix: { ...ix, locale: 'zh-cn' } },
    'ix-ks-unknown.json': { ix: { ...ix, ks: 'cookie' } },
    'ix-fallback-unknown.json': { ix: { ...ix, fallback: 'ts_other' } },
    'ix-sv-invalid.json': { ix: { ...ix, sv: '0.3.0 beta' } },
    'ix-sv-17-chars.json': { ix: { ...ix, sv: '1'.repeat(17) } },
    'ix-trusted-4.json': { ix: { ...ix, trusted: 4 } },
    'ix-act-ms-over-cap.json': { ix: { ...ix, act_ms: 600100 } },
    'ix-act-ms-not-100ms.json': { ix: { ...ix, act_ms: 2350 } },
    'ix-hold-ms-over-cap.json': { ix: { ...ix, hold: { ...ix.hold, ms: 60010 } } },
    'ix-hold-ms-not-10ms.json': { ix: { ...ix, hold: { ...ix.hold, ms: 1915 } } },
    'ix-hold-cancels-16.json': { ix: { ...ix, hold: { ...ix.hold, cancels: 16 } } },
    'ix-hold-offset-out-of-range.json': { ix: { ...ix, hold: { ...ix.hold, offset: [1.1, 0] } } },
    'ix-hold-pressure-negative.json': { ix: { ...ix, hold: { ...ix.hold, pressure: -0.1 } } },
    'ix-pre-straight-1-1.json': { ix: { ...ix, pre: { ...ix.pre, straight: 1.1 } } },
    'ix-pre-bucket-32.json': { ix: { ...ix, pre: { ...ix.pre, moves: 32 } } },
    'ix-page-vis-during-16.json': { ix: { ...ix, page: { ...ix.page, vis_during: 16 } } },
    'ix-pow-impl-unknown.json': { ix: { ...ix, pow: { ...ix.pow, impl: 'gpu' } } },
    'ix-not-object.json': { ix: 'hold' },
  };
  const tInvalidRaw = {
    'not-object.json': '[]',
    'not-json.json': '{"ix":',
    'duplicate-key.json': '{"ix":{"v":1},"ix":{"v":1}}',
    'nested-17.json': `${'{"a":'.repeat(16)}{}${'}'.repeat(16)}`,
    'larger-than-2048-bytes.json': JSON.stringify({ env, auto, ix, pad: 'x'.repeat(1200) }),
  };
  for (const [n, v] of Object.entries(tValid)) put(`samples/telemetry/t/valid/${n}`, `${JSON.stringify(v)}\n`);
  for (const [n, v] of Object.entries(ixInvalid)) put(`samples/telemetry/t/invalid/${n}`, `${JSON.stringify(v)}\n`);
  for (const [n, v] of Object.entries(tInvalidRaw)) put(`samples/telemetry/t/invalid/${n}`, `${v}\n`);
  for (const [n, v] of Object.entries(tValid)) {
    const len = utf8(JSON.stringify(v)).length;
    if (len > 2048) throw new Error(`valid t sample ${n} is ${len} bytes`);
  }

  // Behavior summary (§12.8).
  const counts = (n, f) => Array.from({ length: n }, (_, i) => f(i));
  const summary = {
    v: 1,
    ptr: { speed: counts(16, (i) => (i * 7) % 13), curv: counts(16, (i) => (i * 3) % 5), pauses: 4 },
    keys: { iki: counts(16, (i) => (i % 4 === 0 ? 2 : 0)) },
    scroll: { dist: 9, speed: counts(8, (i) => i) },
    touch: { area_var: 0, pressure_var: 0 },
    focus: 1,
    vis: 2,
    form: { fill_ms: 12, paste: 0 },
  };
  const bValid = {
    'full.json': summary,
    'minimal.json': { v: 1 },
    'unknown-fields-dropped.json': { ...summary, future: [1], ptr: { ...summary.ptr, extra: 1 } },
    'bounds.json': { ...summary, ptr: { ...summary.ptr, speed: counts(16, () => 65535), pauses: 31 }, touch: { area_var: 1, pressure_var: 1 } },
  };
  const bInvalid = {
    'v-2.json': { ...summary, v: 2 },
    'speed-17-counts.json': { ...summary, ptr: { ...summary.ptr, speed: counts(17, () => 1) } },
    'scroll-speed-9-counts.json': { ...summary, scroll: { ...summary.scroll, speed: counts(9, () => 1) } },
    'count-65536.json': { ...summary, keys: { iki: counts(16, (i) => (i === 0 ? 65536 : 0)) } },
    'bucket-32.json': { ...summary, focus: 32 },
    'area-var-2.json': { ...summary, touch: { area_var: 2, pressure_var: 0 } },
    'count-negative.json': { ...summary, ptr: { ...summary.ptr, curv: counts(16, (i) => (i === 3 ? -1 : 0)) } },
    'larger-than-2048-bytes.json': { ...summary, ptr: { ...summary.ptr, speed: counts(16, () => 65535), curv: counts(16, () => 65535) }, pad: 'x'.repeat(1800) },
  };
  for (const [n, v] of Object.entries(bValid)) put(`samples/telemetry/behavior/valid/${n}`, `${JSON.stringify(v)}\n`);
  for (const [n, v] of Object.entries(bInvalid)) put(`samples/telemetry/behavior/invalid/${n}`, `${JSON.stringify(v)}\n`);

  // /__mg/t bodies (§9.4).
  const rUp = { kind: 'upstream_challenge', scope: 'protected_fetch', path: '/api/save', count: 1 };
  const rCache = { kind: 'cache_hit', path: '/__mg/c' };
  const rBehavior = { kind: 'behavior', page: '/articles', summary };
  const rSw = { kind: 'sw_intercept', path: '/__mg/v' };
  const rKey = { kind: 'key_unavailable', reason: 'no_idb' };
  const reports = (...r) => ({ v: 1, reports: r });
  const rValid = {
    'upstream-challenge.json': reports(rUp),
    'cache-hit.json': reports(rCache),
    'behavior.json': reports(rBehavior),
    'sw-intercept.json': reports(rSw),
    'key-unavailable.json': reports(rKey, { kind: 'key_unavailable', reason: 'no_webcrypto' }),
    'eight-reports.json': reports(rUp, rCache, rBehavior, rSw, rKey, rKey, rBehavior, rSw),
    'unknown-report-field-dropped.json': reports({ ...rUp, extra: 'x' }),
  };
  const rReportInvalid = { 'cache-hit-static.json': reports({ kind: 'cache_hit', path: '/__mg/s/mg.js' }) };
  const rBad = {
    'v-2.json': { ...reports(rUp), v: 2 },
    'no-reports.json': { v: 1 },
    'nine-reports.json': reports(rKey, rKey, rKey, rKey, rKey, rKey, rKey, rKey, rKey),
    'two-upstream-challenge.json': reports(rUp, rUp),
    'two-cache-hit.json': reports(rCache, rCache),
    'unknown-kind.json': reports({ kind: 'mouse_trail', path: '/' }),
    'scope-unknown.json': reports({ ...rUp, scope: 'iframe' }),
    'count-0.json': reports({ ...rUp, count: 0 }),
    'count-101.json': reports({ ...rUp, count: 101 }),
    'path-with-query.json': reports({ ...rUp, path: '/api/save?x=1' }),
    'path-513-bytes.json': reports({ ...rUp, path: `/${'a'.repeat(512)}` }),
    'cache-hit-not-mg.json': reports({ kind: 'cache_hit', path: '/api/save' }),
    'key-unavailable-reason-unknown.json': reports({ kind: 'key_unavailable', reason: 'no_cookies' }),
    'behavior-summary-invalid.json': reports({ ...rBehavior, summary: bInvalid['bucket-32.json'] }),
  };
  const rBadRaw = { 'duplicate-key.json': '{"v":1,"v":1,"reports":[]}', 'larger-than-16-kib.json': JSON.stringify({ ...reports(rUp), pad: 'x'.repeat(16 * 1024) }) };
  for (const [n, v] of Object.entries(rValid)) put(`samples/telemetry/report/valid/${n}`, `${JSON.stringify(v)}\n`);
  for (const [n, v] of Object.entries(rReportInvalid)) put(`samples/telemetry/report/valid/${n}`, `${JSON.stringify(v)}\n`);
  for (const [n, v] of Object.entries(rBad)) put(`samples/telemetry/report/invalid/${n}`, `${JSON.stringify(v)}\n`);
  for (const [n, v] of Object.entries(rBadRaw)) put(`samples/telemetry/report/invalid/${n}`, `${v}\n`);

  put(
    'samples/telemetry/cases.json',
    json2({
      about:
        'Telemetry samples, one JSON text per file (the trailing newline is not part of it). t/: the content of the t string of a /__mg/c v2 submission (spec §7.5, §7.6). behavior/: the summary of a behavior report (spec §12.8). report/: POST /__mg/t request bodies (spec §9.4). The single edge-core decoder (spec §15.2) and the SDK both test against them',
      expectations: {
        ok: 'decodes; unknown fields are dropped; for t, ix becomes a mg_core::IxTelemetry within its bounds',
        t_rejected: 'the whole t is rejected: the submission fails at step 3 (ic.body)',
        ix_rejected: 't decodes but its ix does not fit spec §7.6: no IxTelemetry (the submission then has no ix)',
        summary_rejected: 'the behavior summary does not fit spec §12.8',
        report_dropped: 'the request is accepted (204) but this report is dropped and counted as invalid',
        bad_request: 'the request is rejected: 400 mg_bad_request',
      },
      cases: [
        ...Object.keys(tValid).map((f) => ({ file: `t/valid/${f}`, expect: 'ok' })),
        ...Object.keys(ixInvalid).map((f) => ({ file: `t/invalid/${f}`, expect: 'ix_rejected' })),
        ...Object.keys(tInvalidRaw).map((f) => ({ file: `t/invalid/${f}`, expect: 't_rejected' })),
        ...Object.keys(bValid).map((f) => ({ file: `behavior/valid/${f}`, expect: 'ok' })),
        ...Object.keys(bInvalid).map((f) => ({ file: `behavior/invalid/${f}`, expect: 'summary_rejected' })),
        ...Object.keys(rValid).map((f) => ({ file: `report/valid/${f}`, expect: 'ok' })),
        ...Object.keys(rReportInvalid).map((f) => ({ file: `report/valid/${f}`, expect: 'report_dropped' })),
        ...[...Object.keys(rBad), ...Object.keys(rBadRaw)].map((f) => ({ file: `report/invalid/${f}`, expect: 'bad_request' })),
      ],
    }),
  );
}

// samples/mg-ev-v2.txt and mg-ev-v1.txt (§13.1; Phase 1 spec §13.6): one entry per line,
// field and value separated by TAB, an empty value is the empty string.
{
  const ipk = (ip) => kh('mg-ent-v1', 'ip', ip);
  const pfk = (prefix) => kh('mg-ent-v1', 'prefix', prefix);
  const ph = (site, p) => hex(hmac(K_PSEUDO, cat(utf8('mg-path-v1'), u8(0), utf8(site), u8(0), utf8(p)))).slice(0, 16);
  const rid = (i) => hex(sha256(utf8(`mg-phase2-kat-rid-${i}`))).slice(0, 32);
  const sub = (i) => b64u(sha256(utf8(`mg-phase2-kat-sub-${i}`)).subarray(0, 16));
  const line = (pairs) => pairs.map(([k, v]) => `${k}\t${v}`).join('\t');
  const decision = (o) =>
    line([
      ['v', 2], ['kind', 'decision'], ['site', o.site ?? SITE], ['ts', o.ts], ['rid', o.rid], ['sess', o.sess ?? ''],
      ['route', o.route], ['action', o.action], ['dry', o.dry ?? 0], ['class', o.class], ['score', o.score],
      ['ipk', o.ipk ?? ''], ['pfk', o.pfk ?? ''], ['asn', o.asn ?? 0], ['status', o.status ?? 0],
      ['m', o.m], ['ph', o.ph ?? ''], ['ct', o.ct ?? ''], ['bt', o.bt ?? 0], ['xs', o.xs ?? 0], ['tk', o.tk ?? 0],
      ['pf', o.pf ?? '-'], ['uf', o.uf ?? ''], ['fam', o.fam ?? ''], ['ctype', o.ctype ?? ''],
    ]);
  const feedback = (o) =>
    line([
      ['v', 2], ['kind', 'feedback'], ['site', o.site ?? SITE], ['ts', o.ts], ['rid', o.rid], ['route', o.route],
      ['outcome', o.outcome], ['type', o.type], ['pfk', o.pfk ?? ''], ['asn', o.asn ?? 0],
      ['p', o.p ?? ''], ['ipk', o.ipk ?? ''], ['sess', o.sess ?? ''], ['lvl', o.lvl ?? ''],
    ]);
  const ip4 = '203.0.113.7';
  const pf4 = '203.0.113.0/24';
  const ip6 = '2001:db8:abcd:12::/64';
  const pf6 = '2001:db8:abcd::/48';
  const t0 = NOW_MS + 123;
  const v2 = [
    decision({ ts: t0, rid: rid(1), route: 'default', action: 'allow', class: 'human_likely', score: 12, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 200, m: 'GET', ph: ph(SITE, '/articles/hello'), ct: 'h', uf: 'chrome', fam: 4 }),
    decision({ ts: t0 + 1, rid: rid(2), sess: sub(1), route: 'api', action: 'allow', class: 'human_likely', score: 8, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 200, m: 'POST', ph: ph(SITE, '/api/save'), ct: 'j', tk: 1, pf: 'v', uf: 'chrome', fam: 4 }),
    decision({ ts: t0 + 2, rid: rid(3), route: 'login', action: 'challenge', class: 'automation_likely', score: 71, ipk: ipk(ip6), pfk: pfk(pf6), asn: 64501, status: 403, m: 'GET', ph: ph(SITE, '/account/login'), uf: 'headless_chrome', fam: 6, ctype: 'interactive' }),
    decision({ ts: t0 + 3, rid: rid(4), route: 'default', action: 'block', class: 'scanner', score: 96, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 403, m: 'GET', ph: ph(SITE, '/.env'), bt: 1, uf: 'other', fam: 4 }),
    decision({ ts: t0 + 4, rid: rid(5), route: 'default', action: 'allow', dry: 1, class: 'unknown', score: 40, status: 429, m: 'GET', ph: ph(SITE, '/'), uf: 'other' }),
    decision({ ts: t0 + 5, rid: rid(6), route: 'reset', action: 'log', class: 'human_likely', score: 20, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 200, m: 'GET', ph: ph(SITE, '/reset'), ct: 'h', uf: 'firefox', fam: 4 }),
    decision({ ts: t0 + 6, rid: rid(7), route: 'default', action: 'allow', class: 'human_likely', score: 15, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 200, m: 'GET', ph: ph(SITE, '/assets/app.css'), ct: 'a', xs: 1, uf: 'safari', fam: 4 }),
    decision({ ts: t0 + 7, rid: rid(8), route: 'api', action: 'challenge', class: 'unknown', score: 30, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 403, m: 'DELETE', ph: ph(SITE, '/api/item/7'), tk: 1, pf: 'u', uf: 'chrome', fam: 4, ctype: 'pow' }),
    decision({ ts: t0 + 8, rid: rid(9), sess: sub(2), route: 'api', action: 'allow', class: 'unknown', score: 33, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 403, m: 'PUT', ph: ph(SITE, '/api/save'), ct: '', tk: 1, pf: 'j', uf: 'chrome', fam: 4 }),
    decision({ ts: t0 + 9, rid: rid(10), sess: sub(1), route: 'api', action: 'allow', class: 'unknown', score: 35, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 403, m: 'POST', ph: ph(SITE, '/api/save'), tk: 1, pf: 'r', uf: 'chrome', fam: 4 }),
    decision({ ts: t0 + 10, rid: rid(11), route: 'api', action: 'rate_limit', class: 'automation_likely', score: 77, ipk: ipk(ip4), pfk: pfk(pf4), asn: 64500, status: 429, m: 'patch', ph: ph(SITE, '/api/save'), ct: 'o', pf: 'x', uf: 'other', fam: 4 }),
    feedback({ ts: t0 + 20, rid: rid(20), route: 'login', outcome: 'pass', type: 'interactive', pfk: pfk(pf4), asn: 64500, p: 'self_hold', ipk: ipk(ip4), sess: sub(3), lvl: 'interactive' }),
    feedback({ ts: t0 + 21, rid: rid(21), route: 'login', outcome: 'fail', type: 'interactive', pfk: pfk(pf6), asn: 64501, p: 'pow_a11y', ipk: ipk(ip6) }),
    feedback({ ts: t0 + 22, rid: rid(22), route: 'signup', outcome: 'pass', type: 'interactive', pfk: pfk(pf4), asn: 64500, p: 'turnstile', ipk: ipk(ip4), sess: sub(4), lvl: 'interactive_ext:turnstile' }),
    feedback({ ts: t0 + 23, rid: rid(23), route: 'default', outcome: 'pass', type: 'pow', pfk: pfk(pf4), asn: 64500, ipk: ipk(ip4), sess: sub(5), lvl: 'pow' }),
    feedback({ ts: t0 + 24, rid: rid(24), route: 'login', outcome: 'renew_rebind', type: 'interactive', pfk: pfk(pf6), asn: 64501, p: 'self_hold', ipk: ipk(ip6) }),
    feedback({ ts: t0 + 25, rid: rid(25), route: 'login', outcome: 'unavailable', type: 'interactive', pfk: pfk(pf4), asn: 64500, p: 'turnstile', ipk: ipk(ip4) }),
  ];
  const v1 = [
    line([['v', 1], ['kind', 'decision'], ['site', SITE], ['ts', t0], ['rid', rid(30)], ['sess', ''], ['route', 'default'], ['action', 'allow'], ['dry', 0], ['class', 'human_likely'], ['score', 10], ['ipk', ipk(ip4)], ['pfk', pfk(pf4)], ['asn', 64500], ['status', 200]]),
    line([['v', 1], ['kind', 'decision'], ['site', SITE], ['ts', t0 + 1], ['rid', rid(31)], ['sess', sub(6)], ['route', 'login'], ['action', 'challenge'], ['dry', 1], ['class', 'unknown'], ['score', 55], ['ipk', ''], ['pfk', ''], ['asn', 0], ['status', 0]]),
    line([['v', 1], ['kind', 'feedback'], ['site', SITE], ['ts', t0 + 2], ['rid', rid(32)], ['route', 'login'], ['outcome', 'pass'], ['type', 'pow'], ['pfk', pfk(pf4)], ['asn', 64500]]),
  ];
  put('samples/mg-ev-v2.txt', `${v2.join('\n')}\n`);
  put('samples/mg-ev-v1.txt', `${v1.join('\n')}\n`);
}

// ---------------------------------------------------------------------------
// Write or check
// ---------------------------------------------------------------------------

function listFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? listFiles(p) : [p];
  });
}

const check = process.argv.includes('--check');
const generated = new Set(files.keys());
let problems = 0;
for (const [rel, content] of files) {
  const path = join(ROOT, rel);
  if (check) {
    if (!existsSync(path) || readFileSync(path, 'utf8') !== content) {
      console.error(`kat: ${rel} differs from the generator output`);
      problems++;
    }
  } else {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
}
for (const path of listFiles(join(ROOT, 'samples'))) {
  const rel = relative(ROOT, path).split('\\').join('/');
  if (!generated.has(rel)) {
    console.error(`kat: ${rel} is not produced by the generator (remove it or add it here)`);
    problems++;
  }
}
if (problems) process.exit(1);
console.log(`kat: ${check ? 'checked' : 'wrote'} ${files.size} files`);
