// MorphGate Tier 1 signals: Cloudflare Snippet (Pro and above).
//
// Forwards request.cf values that Transform Rules cannot read:
//   x-mg-cf-priority        <- request.cf.requestPriority (browser HTTP/2 priority)
//   x-mg-cf-accept-encoding <- request.cf.clientAcceptEncoding (Cloudflare rewrites Accept-Encoding)
//   x-mg-cf-as-org          <- request.cf.asOrganization (percent-encoded UTF-8)
//   x-mg-cf-t1              <- "snippet" (which Tier 1 forwarder ran)
// Every header is set from Cloudflare's value or deleted, never passed through
// from the client. Keep this file tiny: Snippets allow 5 ms CPU and 32 KB.
// Same logic as worker/src/index.ts; adapters/cloudflare/test checks both.

const MAX_LEN = 256;

function put(headers, name, value, encode) {
  try {
    const text = typeof value === "string" ? (encode ? encodeURIComponent(value) : value) : "";
    if (text.length > 0 && text.length <= MAX_LEN && /^[\x20-\x7e]+$/.test(text)) {
      headers.set(name, text);
      return;
    }
  } catch {
    // Lone surrogates make encodeURIComponent throw; drop the header.
  }
  headers.delete(name);
}

export default {
  async fetch(request) {
    let forwarded = request;
    try {
      const cf = request.cf || {};
      const headers = new Headers(request.headers);
      put(headers, "x-mg-cf-priority", cf.requestPriority, false);
      put(headers, "x-mg-cf-accept-encoding", cf.clientAcceptEncoding, false);
      put(headers, "x-mg-cf-as-org", cf.asOrganization, true);
      headers.set("x-mg-cf-t1", "snippet");
      forwarded = new Request(request, { headers });
    } catch {
      // Fail open: no Tier 1 headers reach the Edge, which records them as MISSING.
    }
    return fetch(forwarded);
  },
};
