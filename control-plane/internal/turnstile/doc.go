// Package turnstile is the minimal client of Cloudflare's Turnstile widget API
// used by `mgctl turnstile`: list the owner's widgets and rotate a widget
// secret, always sending invalidate_immediately explicitly
// (docs/impl/phase2-spec.md §1.3, §8.7, §16).
//
// Phase 2, WP-G4. It only manages the owner's own widgets through the
// documented API; it never solves or calls the siteverify endpoint (the Edge
// does that, spec §8.4), and its tests use net/http/httptest only.
package turnstile
