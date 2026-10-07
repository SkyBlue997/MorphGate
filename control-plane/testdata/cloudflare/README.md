# `mgctl cf audit` fixtures

Fake Cloudflare API v4 responses for `internal/cfaudit` and `internal/cfapi`
(docs/impl/phase1-spec.md §14.3). Nothing here talks to Cloudflare.

- Each directory is a scenario. `site.yaml` is the site configuration the audit
  reads; `api/<request path>.json` is the response body for `GET
  /client/v4/<request path>` (HTTP 200); `api/<request path>.403.json` and
  `.404.json` answer with that status instead. Unlisted paths answer 404.
- A scenario with a `base` file holds only the files that differ from the
  scenario named in it (`green`: Pro zone behind a Tunnel; `green-free-aop`:
  Free zone behind zone-level Authenticated Origin Pulls).
- Rule fixtures embed the templates of `adapters/cloudflare/`; the
  `x-mg-upstream-key` value in `green` is a fixed test string, not a secret.
