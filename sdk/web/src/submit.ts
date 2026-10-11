/**
 * `POST /__mg/c` v2 and `POST /__mg/c/renew` bodies (docs/impl/phase2-spec.md
 * §7.4, §7.5, §6.6), signed with the session key.
 *
 * Submission key order: v, type, c, p, pp, t, pow, ret, ts, build, jwk, sig
 * (the order of `testdata/phase2/samples/submissions/`). `t` carries `env`,
 * `auto` and `ix` as a JSON string (§7.5); the Edge reads `env` / `auto` of a
 * v2 submission only from there. `p` and `pp` are empty strings for
 * non-interactive submissions.
 */

import type { EcP256PublicJwk } from "./crypto";
import type { SessionKey } from "./keystore";
import { es256Sign, renewMessage, submissionMessage, type SubmissionFields } from "./sig";

export interface SubmissionV2 {
  v: 2;
  type: string;
  c: string;
  p: string;
  pp: string;
  t: string;
  pow: { counters: number[] };
  ret: string;
  ts: number;
  build: string;
  jwk: EcP256PublicJwk;
  sig: string;
}

export interface RenewBody {
  v: 2;
  c: string;
  jwk: EcP256PublicJwk;
  ts: number;
  sig: string;
}

function publicJwk(key: SessionKey): EcP256PublicJwk {
  return { kty: "EC", crv: "P-256", x: key.jwk.x, y: key.jwk.y };
}

/** Build and sign a v2 submission. `ts` is the client clock in ms (a feature only). */
export async function signedSubmission(
  subtle: SubtleCrypto,
  key: SessionKey,
  fields: Omit<SubmissionFields, "ts"> & { ts: number },
): Promise<SubmissionV2> {
  const ts = Math.max(0, Math.floor(fields.ts));
  const sig = await es256Sign(subtle, key.privateKey, submissionMessage({ ...fields, ts }));
  return {
    v: 2,
    type: fields.type,
    c: fields.c,
    p: fields.p,
    pp: fields.pp,
    t: fields.t,
    pow: { counters: fields.counters.slice() },
    ret: fields.ret,
    ts,
    build: fields.build,
    jwk: publicJwk(key),
    sig,
  };
}

/** Build and sign a renew body (`mg-renew-v1`). */
export async function signedRenew(subtle: SubtleCrypto, key: SessionKey, c: string, tsMs: number): Promise<RenewBody> {
  const ts = Math.max(0, Math.floor(tsMs));
  const sig = await es256Sign(subtle, key.privateKey, renewMessage(c, ts));
  return { v: 2, c, jwk: publicJwk(key), ts, sig };
}
