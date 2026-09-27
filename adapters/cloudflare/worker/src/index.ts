/**
 * MorphGate Tier 1 signals: Cloudflare Worker variant for Free zones, where
 * Snippets are unavailable. Behaviour matches snippet/mg-signals.js:
 *
 *   x-mg-cf-priority        <- request.cf.requestPriority
 *   x-mg-cf-accept-encoding <- request.cf.clientAcceptEncoding
 *   x-mg-cf-as-org          <- request.cf.asOrganization (percent-encoded UTF-8)
 *   x-mg-cf-t1              <- "worker"
 *
 * Each header is set from Cloudflare's value or deleted. The Worker never
 * touches x-real-ip / CF-Connecting-IP: on same-zone subrequests Cloudflare
 * derives CF-Connecting-IP from x-real-ip, so altering it would let the
 * Worker spoof the client IP.
 *
 * Deploy on NARROW routes only (HTML pages and /__mg/*): every request on a
 * route is billed and counts against the Free plan's daily limit. When the
 * limit is hit with "fail open", requests skip the Worker and reach the origin
 * without Tier 1 headers; MorphGate records those signals as MISSING (neither
 * a pass nor a failure, no alarm). Stateless, no bindings, no secrets.
 */

/** The request.cf properties this Worker reads (all plans). */
export interface MgCfProperties {
  requestPriority?: string;
  clientAcceptEncoding?: string;
  asOrganization?: string;
}

export type Tier1Source = "worker" | "snippet";

const MAX_LEN = 256;
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

function put(headers: Headers, name: string, value: unknown, encode: boolean): void {
  try {
    const text = typeof value === "string" ? (encode ? encodeURIComponent(value) : value) : "";
    if (text.length > 0 && text.length <= MAX_LEN && PRINTABLE_ASCII.test(text)) {
      headers.set(name, text);
      return;
    }
  } catch {
    // Lone surrogates make encodeURIComponent throw; drop the header.
  }
  headers.delete(name);
}

/** Return a copy of `incoming` with the Tier 1 headers set from `cf` (or removed). */
export function withMgSignals(incoming: Headers, cf: MgCfProperties | undefined, source: Tier1Source): Headers {
  const headers = new Headers(incoming);
  const props = cf ?? {};
  put(headers, "x-mg-cf-priority", props.requestPriority, false);
  put(headers, "x-mg-cf-accept-encoding", props.clientAcceptEncoding, false);
  put(headers, "x-mg-cf-as-org", props.asOrganization, true);
  headers.set("x-mg-cf-t1", source);
  return headers;
}

export default {
  async fetch(request: Request): Promise<Response> {
    let forwarded = request;
    try {
      const cf = (request as Request & { cf?: MgCfProperties }).cf;
      forwarded = new Request(request, { headers: withMgSignals(request.headers, cf, "worker") });
    } catch {
      // Fail open: no Tier 1 headers reach the Edge, which records them as MISSING.
    }
    return fetch(forwarded);
  },
};
