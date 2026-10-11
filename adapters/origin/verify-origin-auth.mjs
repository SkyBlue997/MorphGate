// Reference check of MG-Origin-Auth for an origin behind mg-edge
// (docs/impl/phase1-spec.md I-38). Copy it into the origin; it needs only
// node:crypto. Until a request passes, trust none of its MG-* headers.
//
//   import { loadOriginKeys, verifyOriginAuth } from "./verify-origin-auth.mjs";
//   const keys = loadOriginKeys(readFileSync("/run/credentials/app/mg-origin-keys"));
//   // per request (Node http / Express):
//   const ok = verifyOriginAuth({
//     value: req.headers["mg-origin-auth"],
//     method: req.method,
//     target: req.url,                // the request target as received
//     header: (name) => req.headers[name],
//     keys,
//   });
//
// A proxy between the Edge and this code must forward the request target and
// the MG-* headers unchanged (nginx: proxy_pass without a URI part).
import { createHmac, timingSafeEqual } from "node:crypto";

/** The MG-* headers the signature covers, in signing order. */
export const COVERED = [
  "mg-client-ip",
  "mg-request-id",
  "mg-bot-score",
  "mg-bot-class",
  "mg-verified",
  "mg-session",
  "mg-tags",
  "mg-reasons",
];

/** The clock difference accepted, in seconds. */
export const MAX_SKEW_S = 60;

const VALUE = /^v1;t=([0-9]{1,19});sig=([A-Za-z0-9_-]{43})$/;

/**
 * The HMAC keys of an origin-keys.json file (kind mg-origin-keys, 1-2
 * values of 32 bytes in unpadded base64url). Throws on anything else.
 */
export function loadOriginKeys(json) {
  const file = JSON.parse(typeof json === "string" ? json : json.toString("utf8"));
  if (file.v !== 1 || file.kind !== "mg-origin-keys" || !Array.isArray(file.values)) {
    throw new Error("not a v1 mg-origin-keys file");
  }
  if (file.values.length < 1 || file.values.length > 2) {
    throw new Error("values must have 1-2 entries");
  }
  return file.values.map((v) => {
    if (typeof v !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(v)) {
      throw new Error("a value is not 43 characters of unpadded base64url");
    }
    return Buffer.from(v, "base64url");
  });
}

/** The signing input for timestamp `t`. `header(name)` returns a value or undefined. */
export function originAuthMessage(t, method, target, header) {
  let msg = `mg-origin-auth-v1\n${t}\n${method}\n${target}\n`;
  for (const name of COVERED) {
    const value = header(name);
    if (typeof value === "string") {
      msg += `${name}:${value}\n`;
    } else if (value !== undefined) {
      return null; // repeated header: never signed by the Edge
    }
  }
  return Buffer.from(msg, "latin1");
}

/**
 * True when `value` is a fresh MG-Origin-Auth over this request made with
 * one of `keys`. `now` is unix seconds (defaults to the clock).
 */
export function verifyOriginAuth({ value, method, target, header, keys, now }) {
  if (typeof value !== "string") return false;
  const m = VALUE.exec(value);
  if (!m) return false;
  const t = Number(m[1]);
  const clock = now ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(t) || Math.abs(clock - t) > MAX_SKEW_S) return false;
  const sig = Buffer.from(m[2], "base64url");
  const msg = originAuthMessage(m[1], method, target, header);
  if (msg === null || sig.length !== 32) return false;
  let ok = false;
  for (const key of keys) {
    const mac = createHmac("sha256", key).update(msg).digest();
    ok = timingSafeEqual(mac, sig) || ok;
  }
  return ok;
}
