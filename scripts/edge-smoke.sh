#!/usr/bin/env bash
# End-to-end smoke test for mg-edge with an edge.toml v1. Loopback only.
#
#   1. Prepares a temp dir: test credentials (a copy of testdata/phase1/keys,
#      mode 0600) as $CREDENTIALS_DIRECTORY, an empty file:// bundle root and
#      state_dir, and a v1 config with one `cloudflare` loopback listener,
#      the local state mode and a JSONL event file.
#   2. Starts a throwaway origin on 127.0.0.1:18081 (python3 http.server that
#      serves a unique marker file and logs the MG-Client-IP it receives).
#   3. Runs `mg-edge --check-config`, then `mg-edge -d` (daemon mode, as the
#      systemd unit does) on 127.0.0.1:18080 (metrics on 127.0.0.1:19901);
#      the process forks, the parent exits, the daemon writes its pid file.
#   4. Asserts that
#        - the daemon runs apart from the process that was started, and the
#          site starts in bootstrap (no bundle yet);
#        - after daemonizing, the poll loop still works (§9.1.1 item 5): WP-G2's
#          golden bundle for site "blog" (signed with the owner test key,
#          monitor mode), published into the bundle root only now, is applied
#          (site active, mg_config_version = its version) and persisted;
#        - GET /__mg/healthz is answered by the Edge: 200 "ok", Cache-Control
#          no-store and private, never seen by the origin;
#        - GET /__mg/s/<sdk file> serves the SDK build from the [sdk] dir
#          (immutable, byte for byte), and an unknown name there is 404;
#        - GET /smoke/marker.txt (Host example.com) is proxied: 200 with the
#          origin's bytes, and the origin received MG-Client-IP;
#        - the origin's 404 passes through;
#        - a spelling Cloudflare's rules treat as /__mg/ is answered by the
#          Edge, not proxied;
#        - an unknown Host gets 404, a foreign-zone CF-Worker gets 403;
#        - after daemonizing, the event flusher still writes (§9.1.1 item 5):
#          the event file receives the access record of the proxied request;
#        - /metrics serves a request counter >= 1.
#   5. Stops both processes and removes the temp dir on every exit path.
#
# Environment overrides:
#   MG_EDGE_BIN            use this mg-edge binary instead of `cargo build -p mg-edge`
#   MG_SMOKE_EDGE_PORT     default 18080
#   MG_SMOKE_ORIGIN_PORT   default 18081
#   MG_SMOKE_METRICS_PORT  default 19901
#   MG_SMOKE_TIMEOUT       seconds to wait for each listener / condition, default 30
#   MG_SMOKE_KEEP=1        keep the temp dir (config, logs) for debugging
#
# Every request goes to 127.0.0.1; the host is not configurable on purpose.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="127.0.0.1"
EDGE_PORT="${MG_SMOKE_EDGE_PORT:-18080}"
ORIGIN_PORT="${MG_SMOKE_ORIGIN_PORT:-18081}"
METRICS_PORT="${MG_SMOKE_METRICS_PORT:-19901}"
TIMEOUT="${MG_SMOKE_TIMEOUT:-30}"
GOLDEN="$ROOT/control-plane/testdata/sites/golden/golden-norules.bundle"
GOLDEN_VERSION=1790000000
SITE_HOST="example.com"

tmp=""
edge_pid=""
origin_pid=""

log() { printf 'edge-smoke: %s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

for port in "$EDGE_PORT" "$ORIGIN_PORT" "$METRICS_PORT" "$TIMEOUT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || fail "port/timeout values must be numeric, got '$port'"
done
for tool in curl python3; do
  command -v "$tool" >/dev/null || fail "$tool not found in PATH"
done
[[ -f "$GOLDEN" ]] || fail "golden bundle not found: $GOLDEN"

# stop PID NAME SIGNAL: send SIGNAL, then SIGKILL if still alive after 5 s.
# mg-edge gets SIGINT (Pingora's immediate stop; SIGTERM would wait for the
# grace period). The origin gets SIGTERM: background jobs of a non-interactive
# shell start with SIGINT ignored, and Python keeps it ignored.
stop() {
  local pid="$1" name="$2" sig="$3" i
  [[ -n "$pid" ]] || return 0
  kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null; return 0; }
  kill "-$sig" "$pid" 2>/dev/null
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    log "$name did not exit after SIG$sig; sending SIGKILL"
    kill -KILL "$pid" 2>/dev/null
  fi
  wait "$pid" 2>/dev/null
  return 0
}

cleanup() {
  local rc=$?
  set +e
  stop "$edge_pid" mg-edge INT
  stop "$origin_pid" origin TERM
  if [[ -n "$tmp" && -d "$tmp" ]]; then
    if [[ "$rc" -ne 0 ]]; then
      for f in edge.log origin.log; do
        [[ -s "$tmp/$f" ]] || continue
        log "---- last lines of $f ----"
        tail -n 40 "$tmp/$f" >&2
      done
    fi
    if [[ -n "${MG_SMOKE_KEEP:-}" ]]; then
      log "kept $tmp"
    else
      rm -rf "$tmp"
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

port_open() { (exec 3<>"/dev/tcp/$HOST/$1") 2>/dev/null; }

wait_for_port() {
  local name="$1" port="$2" pid="$3" deadline=$((SECONDS + TIMEOUT))
  until port_open "$port"; do
    kill -0 "$pid" 2>/dev/null || fail "$name exited before listening on $HOST:$port"
    ((SECONDS < deadline)) || fail "timed out after ${TIMEOUT}s waiting for $name on $HOST:$port"
    sleep 0.2
  done
}

# http_get URL NAME [curl args...] -> prints the status code; headers/body land
# in $tmp/NAME.headers and $tmp/NAME.body. --noproxy keeps a system HTTP proxy
# (http_proxy / all_proxy) from intercepting loopback requests.
http_get() {
  local url="$1" name="$2"
  shift 2
  : >"$tmp/$name.headers"
  : >"$tmp/$name.body"
  # On connection errors curl still prints 000 for %{http_code}; the caller's
  # status assertion then fails with a readable message.
  curl -sS --noproxy '*' --max-time 5 "$@" \
    -D "$tmp/$name.headers" -o "$tmp/$name.body" -w '%{http_code}' "$url" || true
}

# site_get PATH NAME [curl args...]: a request as cloudflared would forward it.
site_get() {
  local path="$1" name="$2"
  shift 2
  http_get "http://$HOST:$EDGE_PORT$path" "$name" -H "Host: $SITE_HOST" \
    -H "CF-Connecting-IP: 198.51.100.7" -H 'CF-Visitor: {"scheme":"https"}' "$@"
}

header_value() { # header_value NAME HEADER -> lower-cased value(s), CR stripped
  grep -i "^$2:" "$tmp/$1.headers" | cut -d: -f2- | tr -d '\r' | tr '[:upper:]' '[:lower:]'
}

# metric SERIES -> the sample value of an exact series (empty if absent).
metric() {
  curl -sS --noproxy '*' --max-time 5 "http://$HOST:$METRICS_PORT/metrics" 2>/dev/null \
    | awk -v s="$1" 'index($0, s " ") == 1 { print $2; exit }'
}

# --- preflight ---------------------------------------------------------------
for port in "$EDGE_PORT" "$ORIGIN_PORT" "$METRICS_PORT"; do
  if port_open "$port"; then
    fail "$HOST:$port is already in use; stop that process or set MG_SMOKE_*_PORT"
  fi
done

tmp="$(mktemp -d "${TMPDIR:-/tmp}/mg-edge-smoke.XXXXXX")"
mkdir -p "$tmp/www/smoke" "$tmp/creds" "$tmp/state" "$tmp/publish/bundles" "$tmp/publish/artifacts" "$tmp/run"
marker="morphgate-edge-smoke-$$-$RANDOM"
printf '%s\n' "$marker" >"$tmp/www/smoke/marker.txt"

keys="$ROOT/testdata/phase1/keys"
install -m 0600 "$keys/token.keys.json" "$tmp/creds/mg-blog-token-keys"
install -m 0600 "$keys/seal.root.json" "$tmp/creds/mg-blog-seal-root"
install -m 0600 "$keys/pseudo.key.json" "$tmp/creds/mg-pseudo-key"
cat >"$tmp/edge.toml" <<EOF
# Generated by scripts/edge-smoke.sh; removed on exit.
config_version = 1
edge_id = "edge-smoke"
metrics_listen = "$HOST:$METRICS_PORT"
state_dir = "$tmp/state"

[server]
threads = 1
pid_file = "$tmp/run/mg-edge.pid"
upgrade_sock = "$tmp/run/mg-edge-upgrade.sock"
grace_period_seconds = 0
graceful_shutdown_timeout_seconds = 1

[trust]
owner_keys = ["$keys/owner-test.pub"]

[[listeners]]
name = "cf-tunnel"
bind = "$HOST:$EDGE_PORT"
profile = "cloudflare"

[[sites]]
id = "blog"
hosts = ["example.com", "www.example.com", "staging.example.com"]
listeners = ["cf-tunnel"]
origin = "$HOST:$ORIGIN_PORT"
bundle_root = "file://$tmp/publish/"
bundle_poll_seconds = 2
token_keys = "cred://mg-blog-token-keys"
seal_root = "cred://mg-blog-seal-root"

[pseudo]
key = "cred://mg-pseudo-key"

[valkey]
mode = "local"

[events]
file = "$tmp/events.jsonl"
flush_interval_ms = 200

[sdk]
dir = "$ROOT/edge/tests/fixtures/sdk"
EOF

# --- build -------------------------------------------------------------------
if [[ -n "${MG_EDGE_BIN:-}" ]]; then
  edge_bin="$MG_EDGE_BIN"
else
  log "building mg-edge (cargo build -p mg-edge)"
  (cd "$ROOT" && cargo build -p mg-edge)
  target_dir="${CARGO_TARGET_DIR:-target}"
  [[ "$target_dir" = /* ]] || target_dir="$ROOT/$target_dir"
  edge_bin="$target_dir/debug/mg-edge"
fi
[[ -x "$edge_bin" ]] || fail "mg-edge binary not found at $edge_bin"
export CREDENTIALS_DIRECTORY="$tmp/creds"

"$edge_bin" --check-config --config "$tmp/edge.toml" >"$tmp/check.log" 2>&1 \
  || { cat "$tmp/check.log" >&2; fail "mg-edge --check-config rejected the smoke config"; }
log "ok: mg-edge --check-config"

# --- start origin and edge -----------------------------------------------------
# http.server with the MG-Client-IP it receives in each log line.
cat >"$tmp/origin.py" <<'PY'
import functools, http.server, sys
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s mg-client-ip=%s\n" % (fmt % args, self.headers.get("MG-Client-IP", "-")))
port, directory = int(sys.argv[1]), sys.argv[2]
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Handler, directory=directory))
server.serve_forever()
PY
python3 -u "$tmp/origin.py" "$ORIGIN_PORT" "$tmp/www" >"$tmp/origin.log" 2>&1 &
origin_pid=$!
wait_for_port origin "$ORIGIN_PORT" "$origin_pid"
log "origin up on $HOST:$ORIGIN_PORT (pid $origin_pid)"

# Daemon mode (-d): Pingora forks before it creates any runtime; the parent
# exits at once and the daemon writes server.pid_file (§9.1.1).
#
# macOS only (production is Linux / systemd): Pingora 0.9 starts its timer
# thread just before fork() (fast_timeout::pause_for_fork), so the Objective-C
# runtime treats the daemon as the child of a multithreaded fork and aborts it
# as soon as a system framework initializes a class there (hickory reads the
# DNS configuration through SystemConfiguration). Apple's documented switch
# turns that check off for this test process.
if [[ "$(uname -s)" == Darwin ]]; then
  export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
fi
pid_file="$tmp/run/mg-edge.pid"
RUST_LOG="${RUST_LOG:-info}" "$edge_bin" -d --config "$tmp/edge.toml" >"$tmp/edge.log" 2>&1 &
launcher=$!
wait "$launcher" || fail "mg-edge -d exited with status $? before daemonizing"
deadline=$((SECONDS + TIMEOUT))
until [[ -s "$pid_file" ]]; do
  ((SECONDS < deadline)) || fail "mg-edge -d wrote no pid file ($pid_file)"
  sleep 0.1
done
edge_pid="$(tr -d '[:space:]' <"$pid_file")"
[[ "$edge_pid" =~ ^[0-9]+$ ]] || fail "unexpected pid file content: '$edge_pid'"
[[ "$edge_pid" != "$launcher" ]] || fail "mg-edge -d did not fork (pid $edge_pid)"
wait_for_port mg-edge "$EDGE_PORT" "$edge_pid"
wait_for_port "mg-edge metrics" "$METRICS_PORT" "$edge_pid"
log "mg-edge daemon up on $HOST:$EDGE_PORT, metrics on $HOST:$METRICS_PORT (pid $edge_pid, launcher $launcher exited)"

# --- assertions ----------------------------------------------------------------
[[ "$(metric 'mg_site_state{site="blog",state="bootstrap_open"}')" == 1 ]] \
  || fail "site blog did not start in bootstrap (no bundle published yet)"
# Published only now: the daemon's poll loop must pick it up.
cp "$GOLDEN" "$tmp/publish/bundles/blog.bundle.tmp"
mv "$tmp/publish/bundles/blog.bundle.tmp" "$tmp/publish/bundles/blog.bundle"
deadline=$((SECONDS + TIMEOUT))
until [[ "$(metric 'mg_config_version{site="blog"}')" == "$GOLDEN_VERSION" ]]; do
  ((SECONDS < deadline)) || fail "the daemon did not apply the published bundle (mg_config_version{site=\"blog\"} = '$(metric 'mg_config_version{site="blog"}')')"
  sleep 0.2
done
[[ "$(metric 'mg_site_state{site="blog",state="active"}')" == 1 ]] || fail "site blog is not active"
[[ -s "$tmp/state/bundles/blog.bundle" ]] || fail "the applied bundle was not persisted as the LKG"
log "ok: bundle published after daemonizing was polled and applied (version $GOLDEN_VERSION), LKG written"

code="$(site_get /__mg/healthz healthz)"
[[ "$code" == 200 ]] || fail "GET /__mg/healthz returned $code, want 200"
[[ "$(cat "$tmp/healthz.body")" == "ok" ]] || fail "GET /__mg/healthz body is '$(head -c 200 "$tmp/healthz.body")', want 'ok'"
cache_control="$(header_value healthz cache-control)"
[[ "$cache_control" == *no-store* && "$cache_control" == *private* ]] \
  || fail "GET /__mg/healthz Cache-Control is '$cache_control', want no-store and private"
log "ok: /__mg/healthz -> 200 ok, Cache-Control:$cache_control"

sdk_dir="$ROOT/edge/tests/fixtures/sdk"
sdk_file="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["sdk"])' "$sdk_dir/manifest.json")"
code="$(site_get "/__mg/s/$sdk_file" sdkfile)"
[[ "$code" == 200 ]] || fail "GET /__mg/s/$sdk_file returned $code, want 200"
cmp -s "$tmp/sdkfile.body" "$sdk_dir/$sdk_file" || fail "GET /__mg/s/$sdk_file did not serve the SDK file byte for byte"
cache_control="$(header_value sdkfile cache-control)"
[[ "$cache_control" == *immutable* ]] || fail "GET /__mg/s/$sdk_file Cache-Control is '$cache_control', want immutable"
code="$(site_get /__mg/s/manifest.json sdkmissing)"
[[ "$code" == 404 ]] || fail "GET /__mg/s/manifest.json returned $code, want 404 (only manifest files are served)"
log "ok: /__mg/s/$sdk_file served from the SDK dir (immutable), other names 404"

code="$(site_get /smoke/marker.txt proxied)"
[[ "$code" == 200 ]] || fail "GET /smoke/marker.txt via mg-edge returned $code, want 200"
[[ "$(cat "$tmp/proxied.body")" == "$marker" ]] || fail "proxied body does not match the origin's marker file"
log "ok: /smoke/marker.txt proxied to the origin"

code="$(site_get /smoke/missing.txt missing)"
[[ "$code" == 404 ]] || fail "GET /smoke/missing.txt via mg-edge returned $code, want the origin's 404"
log "ok: origin 404 passed through"

# Cloudflare's rules see this path as /__mg/.. (skip bot checks, bypass cache),
# while this origin (python http.server) decodes %2F and would serve
# /smoke/marker.txt. The Edge must answer it itself (edge/src/routes.rs).
code="$(site_get "/%5F%5Fmg/..%2Fsmoke/marker.txt" disguised)"
[[ "$code" == 404 ]] || fail "GET /%5F%5Fmg/..%2Fsmoke/marker.txt returned $code, want the Edge's 404"
if grep -q "$marker" "$tmp/disguised.body"; then
  fail "an encoded /__mg/ path was proxied and the origin served the marker"
fi
log "ok: encoded /__mg/ spelling answered by the Edge, not proxied"

code="$(http_get "http://$HOST:$EDGE_PORT/" unknown -H "Host: unknown.invalid")"
[[ "$code" == 404 && "$(cat "$tmp/unknown.body")" == "unknown site" ]] || fail "an unknown Host got $code, want 404 unknown site"
code="$(site_get / worker -H "CF-Worker: attacker.example")"
[[ "$code" == 403 ]] || fail "a foreign-zone CF-Worker got $code, want 403"
log "ok: unknown Host -> 404, foreign CF-Worker -> 403"

# The origin logs every request it serves: the proxied paths must be there
# with the Edge's MG-Client-IP, the Edge's own answers must not.
sleep 0.2
grep -q "GET /smoke/marker.txt.*mg-client-ip=198.51.100.7" "$tmp/origin.log" \
  || fail "origin never saw GET /smoke/marker.txt with MG-Client-IP"
grep -q "GET /smoke/missing.txt" "$tmp/origin.log" || fail "origin never saw GET /smoke/missing.txt"
if grep -q -i -e "/__mg/" -e "%5F%5Fmg" "$tmp/origin.log"; then
  fail "a /__mg/ request reached the origin; the Edge must answer it itself"
fi
if grep -q -e "unknown.invalid" "$tmp/origin.log"; then
  fail "a request for an unknown host reached the origin"
fi
log "ok: origin saw the proxied requests (with MG-Client-IP) and none of the Edge's answers"

# The daemon's event flusher writes the access record of the proxied request.
deadline=$((SECONDS + TIMEOUT))
until grep -q '"kind":"access".*"path":"/smoke/marker.txt"' "$tmp/events.jsonl" 2>/dev/null; do
  ((SECONDS < deadline)) || fail "no access record for /smoke/marker.txt in the event file after daemonizing"
  sleep 0.2
done
grep -q '"kind":"access".*"path":"/__mg/healthz".*"route":"__mg"' "$tmp/events.jsonl" \
  || fail "no access record for /__mg/healthz in the event file"
log "ok: the daemon's event flusher wrote access records ($(wc -l <"$tmp/events.jsonl" | tr -d ' ') lines)"

code="$(http_get "http://$HOST:$METRICS_PORT/metrics" metrics)"
[[ "$code" == 200 ]] || fail "GET /metrics returned $code, want 200"
# Require a Prometheus counter whose name mentions "request" with a sample >= 1
# (the requests above must have been counted).
if ! awk '
  $1 == "#" && $2 == "TYPE" && $4 == "counter" && tolower($3) ~ /request/ { counters[$3] = 1; next }
  $1 !~ /^#/ && NF >= 2 {
    # Sample line: name{labels} value [timestamp]; label values may hold spaces.
    name = $1; sub(/\{.*/, "", name)
    rest = $0; sub(/^[^ {]+(\{[^}]*\})?[ \t]+/, "", rest); split(rest, fields, /[ \t]+/)
    base = name; sub(/_total$/, "", base)
    if ((name in counters || base in counters) && fields[1] + 0 >= 1) { found = 1 }
  }
  END { exit found ? 0 : 1 }
' "$tmp/metrics.body"; then
  fail "no Prometheus request counter >= 1 in /metrics (first lines: $(head -c 400 "$tmp/metrics.body" | tr '\n' ' '))"
fi
log "ok: /metrics exposes a request counter"

log "PASS"
