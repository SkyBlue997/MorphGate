#!/usr/bin/env bash
# Validation Lab end-to-end run: the Phase 1 acceptance scenarios of
# docs/impl/phase1-spec.md §15 WP-L1 / §18 against a real mg-edge in enforce
# mode. Loopback only.
#
#   1. Builds mgctl and mglab (go build), and mg-edge unless MG_EDGE_BIN names
#      one (CI passes the rust job's release binary); picks the Web SDK
#      directory (MG_LAB_SDK_DIR, else a fresh `pnpm run build` of sdk/web
#      when pnpm and node are installed, else edge/tests/fixtures/sdk). The
#      Edge runs from private copies of its binary and SDK directory.
#   2. In a temp dir, with throwaway test keys (MGCTL_PASSPHRASE_FILE,
#      MGCTL_AGE_WORK_FACTOR=10, --insecure-test-key; audit log in the temp
#      dir): owner signing key, pseudonymisation key and the site keys of site
#      "lab", exported with `mgctl keys export --out` as the Edge's credential
#      files. Builds, signs and publishes an enforce bundle from
#      lab/testdata/e2e/site.yaml (host site.lab.test, test crawler registry
#      with documentation ranges) into a file:// bundle root.
#   3. Starts a temporary valkey-server on a unix socket in the temp dir (or
#      uses MG_TEST_VALKEY_URL, which must be local), a python3 origin,
#      and mg-edge with a `cloudflare` loopback listener, Valkey state, the
#      static rDNS table lab/testdata/e2e/dns.json and a JSONL event file;
#      waits until the Edge applied the bundle.
#   4. Runs the scenarios through mglab (every request passes the Lab guard;
#      site.lab.test is mapped to 127.0.0.1 with -map-host):
#        lab/testdata/scenarios/phase1-impersonator.yaml
#        lab/testdata/scenarios/phase1-nonjs-clearance.yaml
#   5. Checks the event file with `mglab events` (D-22: 100 % of the settled
#      impersonator requests classified impersonator; no challenge submission
#      passed, nothing on the protected route forwarded) and the origin's
#      request log, then prints a PASS / FAIL summary.
#   6. Stops every process and removes the temp dir on every exit path.
#
# Environment:
#   MG_EDGE_BIN            use this mg-edge binary instead of `cargo build -p mg-edge`
#   MG_TEST_VALKEY_URL     use this Valkey (redis://<loopback>[:port][/db] or
#                          unix:///<socket>) instead of starting valkey-server;
#                          keys carry the site id "lab", nothing is flushed
#   MG_LAB_SDK_DIR         Web SDK directory (manifest.json + files) to serve
#   MG_LAB_SDK=fixture     use edge/tests/fixtures/sdk instead of building sdk/web
#   MG_LAB_E2E_REQUIRE=1   a missing dependency fails the run instead of skipping it (CI)
#   MG_LAB_E2E_TIMEOUT     seconds to wait for each process / condition, default 60
#   MG_LAB_E2E_KEEP=1      keep the temp dir (config, logs, events) for debugging
#
# Exit status: 0 all checks passed (or skipped for a missing dependency),
# 1 a check or the setup failed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="127.0.0.1"
SITE="lab"
SITE_HOST="site.lab.test"
BUNDLE_VERSION=1
TIMEOUT="${MG_LAB_E2E_TIMEOUT:-60}"
SCENARIOS="$ROOT/lab/testdata/scenarios"
E2E="$ROOT/lab/testdata/e2e"

# Numbers the scenarios are built around (see the scenario files).
IMPERSONATOR_SETTLED=13
CRAWLER_VERIFIED=6
CHALLENGE_SUBMISSIONS=3

tmp=""
edge_pid=""
origin_pid=""
valkey_pid=""
results=()
failed=0

log() { printf 'lab-e2e: %s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
skip() {
  if [[ -n "${MG_LAB_E2E_REQUIRE:-}" ]]; then
    fail "$* (MG_LAB_E2E_REQUIRE is set)"
  fi
  log "SKIPPED: $*"
  exit 0
}
# record NAME STATUS: one line of the final summary.
record() {
  results+=("$2  $1")
  [[ "$2" == PASS ]] || failed=1
}

[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || fail "MG_LAB_E2E_TIMEOUT must be numeric, got '$TIMEOUT'"

# --- dependencies ----------------------------------------------------------------
for tool in python3 go curl; do
  command -v "$tool" >/dev/null || skip "$tool not found in PATH"
done
if [[ -n "${MG_TEST_VALKEY_URL:-}" ]]; then
  # Only a Valkey on this machine: the Lab's traffic stays on loopback.
  [[ "$MG_TEST_VALKEY_URL" =~ ^redis://(127\.[0-9]+\.[0-9]+\.[0-9]+|localhost|\[::1\])(:[0-9]+)?(/[0-9]*)?$ \
     || "$MG_TEST_VALKEY_URL" =~ ^unix:///[^[:space:]]+$ ]] \
    || fail "MG_TEST_VALKEY_URL must be redis://<loopback address>[:port][/db] (no credentials) or unix:///<socket>, got '$MG_TEST_VALKEY_URL'"
  valkey_url="$MG_TEST_VALKEY_URL"
else
  valkey_bin="$(command -v valkey-server || command -v redis-server || true)"
  [[ -n "$valkey_bin" ]] || skip "no valkey-server (set MG_TEST_VALKEY_URL or install valkey)"
fi
if [[ -z "${MG_EDGE_BIN:-}" ]]; then
  command -v cargo >/dev/null || skip "cargo not found in PATH (or set MG_EDGE_BIN)"
fi

# stop PID NAME SIGNAL: send SIGNAL, then SIGKILL if still alive after 5 s.
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
  stop "$valkey_pid" valkey-server TERM
  if [[ -n "$tmp" && -d "$tmp" ]]; then
    if [[ "$rc" -ne 0 ]]; then
      for f in edge.log origin.log valkey.log build.log; do
        [[ -s "$tmp/$f" ]] || continue
        log "---- last lines of $f ----"
        tail -n 40 "$tmp/$f" >&2
      done
    fi
    if [[ -n "${MG_LAB_E2E_KEEP:-}" ]]; then
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

# metric SERIES -> the sample value of an exact series (empty if absent).
metric() {
  curl -sS --noproxy '*' --max-time 5 "http://$HOST:$METRICS_PORT/metrics" 2>/dev/null \
    | awk -v s="$1" 'index($0, s " ") == 1 { print $2; exit }'
}

wait_for_metric() { # wait_for_metric SERIES VALUE WHAT
  local deadline=$((SECONDS + TIMEOUT))
  until [[ "$(metric "$1")" == "$2" ]]; do
    kill -0 "$edge_pid" 2>/dev/null || fail "mg-edge exited while waiting for $3"
    ((SECONDS < deadline)) || fail "timed out after ${TIMEOUT}s waiting for $3 ($1 = '$(metric "$1")', want $2)"
    sleep 0.2
  done
}

tmp_base="${TMPDIR:-/tmp}"
tmp="$(mktemp -d "${tmp_base%/}/mg-lab-e2e.XXXXXX")"
umask 077
mkdir -p "$tmp/bin" "$tmp/keys" "$tmp/creds" "$tmp/out" "$tmp/publish" "$tmp/state" "$tmp/run" "$tmp/valkey"

# Three free loopback ports, held open together so they differ.
read -r EDGE_PORT ORIGIN_PORT METRICS_PORT < <(python3 - <<'PY'
import socket
socks = []
for _ in range(3):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    socks.append(s)
print(" ".join(str(s.getsockname()[1]) for s in socks))
for s in socks:
    s.close()
PY
)
RUN="r$(date +%s)$$"

# --- build -------------------------------------------------------------------------
log "building mgctl and mglab"
(cd "$ROOT" && go build -o "$tmp/bin/mgctl" ./control-plane/cmd/mgctl && go build -o "$tmp/bin/mglab" ./lab/cmd/mglab) \
  || fail "go build failed"
MGLAB="$tmp/bin/mglab"
mgctl() { "$tmp/bin/mgctl" --audit-log "$tmp/audit.jsonl" "$@"; }

if [[ -n "${MG_EDGE_BIN:-}" ]]; then
  edge_bin="$MG_EDGE_BIN"
else
  log "building mg-edge (cargo build -p mg-edge)"
  (cd "$ROOT" && cargo build -p mg-edge)
  target_dir="${CARGO_TARGET_DIR:-target}"
  [[ "$target_dir" = /* ]] || target_dir="$ROOT/$target_dir"
  edge_bin="$target_dir/debug/mg-edge"
fi
[[ -x "$edge_bin" ]] || fail "mg-edge binary not found or not executable at $edge_bin"
# Run a private copy, so a concurrent cargo build cannot swap the binary
# between the config check and the start.
cp "$edge_bin" "$tmp/bin/mg-edge"
edge_src="$edge_bin"
edge_bin="$tmp/bin/mg-edge"

if [[ -n "${MG_LAB_SDK_DIR:-}" ]]; then
  sdk_dir="$MG_LAB_SDK_DIR"
elif [[ "${MG_LAB_SDK:-}" != fixture ]] && command -v pnpm >/dev/null && command -v node >/dev/null; then
  log "building the Web SDK (pnpm -C sdk/web run build)"
  { pnpm -C "$ROOT/sdk/web" install --frozen-lockfile && pnpm -C "$ROOT/sdk/web" run build; } >"$tmp/build.log" 2>&1 \
    || fail "the Web SDK build failed (MG_LAB_SDK=fixture uses edge/tests/fixtures/sdk instead)"
  sdk_dir="$ROOT/sdk/web/dist/sdk"
else
  sdk_dir="$ROOT/edge/tests/fixtures/sdk"
  log "using the SDK test fixture $sdk_dir (no pnpm / node, or MG_LAB_SDK=fixture)"
fi
[[ -f "$sdk_dir/manifest.json" ]] || fail "no manifest.json in the SDK directory $sdk_dir"
# The Edge reads a private copy: a later rebuild of sdk/web/dist (another
# checkout, make web-check) cannot change the files under a running Edge.
cp -R "$sdk_dir" "$tmp/sdk"
sdk_dir="$tmp/sdk"

# --- keys and bundle ---------------------------------------------------------------
# Test-only keys: a low age work factor, a passphrase in a temp file.
printf 'lab-e2e throwaway passphrase %s\n' "$RUN" >"$tmp/passphrase"
export MGCTL_PASSPHRASE_FILE="$tmp/passphrase" MGCTL_AGE_WORK_FACTOR=10
# step ARGS...: one mgctl command, output into mgctl.log; stops at the first failure.
step() {
  mgctl "$@" >>"$tmp/mgctl.log" 2>&1 || { cat "$tmp/mgctl.log" >&2; fail "mgctl $1 $2 failed"; }
}
step keys gen --kid lab-owner --out-dir "$tmp/keys" --insecure-test-key
step keys gen-pseudo --out "$tmp/keys/pseudo.key.json.age" --insecure-test-key
# --date matches token.active_kid (lab-t-20260927) in lab/testdata/e2e/site.yaml.
step site keys gen --site "$SITE" --out-dir "$tmp/keys/$SITE" --date 20260927 --insecure-test-key
step keys export --in "$tmp/keys/$SITE/token.keys.json.age" --out "$tmp/creds/mg-$SITE-token-keys"
step keys export --in "$tmp/keys/$SITE/seal.root.json.age" --out "$tmp/creds/mg-$SITE-seal-root"
step keys export --in "$tmp/keys/pseudo.key.json.age" --out "$tmp/creds/mg-pseudo-key"
step bundle build --site-config "$E2E/site.yaml" --out-dir "$tmp/out" --version "$BUNDLE_VERSION"
step bundle sign --in "$tmp/out/$SITE.sitebundle.pb" --key "$tmp/keys/lab-owner.key.age" --out "$tmp/out/$SITE.bundle"
step bundle publish --in "$tmp/out/$SITE.bundle" --artifacts "$tmp/out/artifacts" --dest "$tmp/publish" \
  --pub "$tmp/keys/lab-owner.pub" --confirm "$SITE"
step audit verify
log "ok: test keys, enforce bundle for $SITE ($SITE_HOST) signed and published (version $BUNDLE_VERSION)"

# --- valkey, origin, edge ----------------------------------------------------------
if [[ -z "${valkey_url:-}" ]]; then
  # Unix socket only (no TCP port), as the Edge tests' Valkey fixture (§16).
  sock="$tmp/valkey/v.sock"
  "$valkey_bin" --port 0 --unixsocket "$sock" --unixsocketperm 700 --save "" --appendonly no \
    --dir "$tmp/valkey" >"$tmp/valkey.log" 2>&1 &
  valkey_pid=$!
  deadline=$((SECONDS + TIMEOUT))
  until [[ -S "$sock" ]]; do
    kill -0 "$valkey_pid" 2>/dev/null || fail "valkey-server exited before creating $sock"
    ((SECONDS < deadline)) || fail "timed out after ${TIMEOUT}s waiting for valkey-server on $sock"
    sleep 0.1
  done
  valkey_url="unix://$sock"
  log "valkey-server up on $sock (pid $valkey_pid)"
else
  log "using Valkey at $valkey_url"
fi

# Answers every request itself (200) and logs what the Edge forwarded, with
# the Edge's classification headers.
cat >"$tmp/origin.py" <<'PY'
import http.server, sys

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = ("lab-e2e-origin %s %s\n" % (self.command, self.path)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = answer

    def log_message(self, fmt, *args):
        h = self.headers
        sys.stderr.write("ORIGIN %s %s class=%s verified=%s\n" % (
            self.command, self.path, h.get("MG-Bot-Class", "-"), h.get("MG-Verified", "-")))

http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
python3 -u "$tmp/origin.py" "$ORIGIN_PORT" >"$tmp/origin.log" 2>&1 &
origin_pid=$!
wait_for_port origin "$ORIGIN_PORT" "$origin_pid"

cat >"$tmp/edge.toml" <<EOF
# Generated by scripts/lab-e2e.sh; removed on exit.
config_version = 1
edge_id = "lab-e2e"
metrics_listen = "$HOST:$METRICS_PORT"
state_dir = "$tmp/state"

[server]
threads = 2
pid_file = "$tmp/run/mg-edge.pid"
upgrade_sock = "$tmp/run/mg-edge-upgrade.sock"
grace_period_seconds = 0
graceful_shutdown_timeout_seconds = 1

[trust]
owner_keys = ["$tmp/keys/lab-owner.pub"]

[[listeners]]
name = "cf-tunnel"
bind = "$HOST:$EDGE_PORT"
profile = "cloudflare"

[[sites]]
id = "$SITE"
hosts = ["$SITE_HOST"]
listeners = ["cf-tunnel"]
origin = "$HOST:$ORIGIN_PORT"
bundle_root = "file://$tmp/publish/"
bundle_poll_seconds = 2
bootstrap = "closed"
token_keys = "cred://mg-$SITE-token-keys"
seal_root = "cred://mg-$SITE-seal-root"

[pseudo]
key = "cred://mg-pseudo-key"

[valkey]
mode = "valkey"
url = "$valkey_url"
timeout_ms = 250
connect_timeout_ms = 1000

[events]
file = "$tmp/events.jsonl"
flush_interval_ms = 200

[intel]
dns_resolver = "static:$E2E/dns.json"
dns_timeout_ms = 500

[sdk]
dir = "$sdk_dir"
EOF

export CREDENTIALS_DIRECTORY="$tmp/creds"
"$edge_bin" --check-config --config "$tmp/edge.toml" >"$tmp/check.log" 2>&1 \
  || { cat "$tmp/check.log" >&2; fail "mg-edge --check-config rejected the Lab config"; }
RUST_LOG="${RUST_LOG:-info}" "$edge_bin" --config "$tmp/edge.toml" >"$tmp/edge.log" 2>&1 &
edge_pid=$!
wait_for_port mg-edge "$EDGE_PORT" "$edge_pid"
wait_for_port "mg-edge metrics" "$METRICS_PORT" "$edge_pid"
wait_for_metric "mg_config_version{site=\"$SITE\"}" "$BUNDLE_VERSION" "the published bundle"
wait_for_metric "mg_site_state{site=\"$SITE\",state=\"active\"}" 1 "site $SITE to become active"
wait_for_metric 'mg_state_mode{mode="valkey"}' 1 "the Valkey state layer"
log "ok: mg-edge on $HOST:$EDGE_PORT (pid $edge_pid), site $SITE active in enforce mode with Valkey state"

# --- scenarios -----------------------------------------------------------------------
target="http://$SITE_HOST:$EDGE_PORT"
if "$MGLAB" check -map-host "$SITE_HOST=$HOST" -resolve "$target/" >"$tmp/guard.log" 2>&1 \
  && ! "$MGLAB" check http://example.com/ >>"$tmp/guard.log" 2>&1; then
  record "Lab guard: admits $SITE_HOST -> $HOST, refuses a target outside the allowlist" PASS
else
  cat "$tmp/guard.log" >&2
  record "Lab guard: admits $SITE_HOST -> $HOST, refuses a target outside the allowlist" FAIL
fi

sent_total=0
# replay NAME FILE: runs one scenario through mglab and the guard.
replay() {
  local name="$1" file="$2" out="$tmp/$1.out" sent
  log "replaying $name (run $RUN)"
  if "$MGLAB" replay -rps 20 -map-host "$SITE_HOST=$HOST" -base "$target" -var "run=$RUN" "$file" >"$out" 2>&1; then
    record "scenario $name: every response as expected" PASS
  else
    record "scenario $name: every response as expected" FAIL
  fi
  sed 's/^/    /' "$out" >&2
  sent="$(awk '/^done: / { print $2 }' "$out")"
  sent_total=$((sent_total + ${sent:-0}))
}
replay phase1-impersonator "$SCENARIOS/phase1-impersonator.yaml"
replay phase1-nonjs-clearance "$SCENARIOS/phase1-nonjs-clearance.yaml"

# Every request the Edge answered writes one access record (§13.4); wait
# until the flusher wrote them all.
deadline=$((SECONDS + TIMEOUT))
while :; do
  written="$(grep -c '"kind":"access"' "$tmp/events.jsonl" 2>/dev/null || true)"
  ((${written:-0} >= sent_total)) && break
  ((SECONDS < deadline)) || { log "only ${written:-0} of $sent_total access records were written"; break; }
  sleep 0.2
done

# --- event and origin checks -----------------------------------------------------
# events CHECK-NAME ARGS...: mglab events, output into the log.
events_check() {
  local name="$1"
  shift
  if "$MGLAB" events "$@" "$tmp/events.jsonl" >"$tmp/events-$1.out" 2>&1; then
    record "$name" PASS
  else
    record "$name" FAIL
  fi
  sed 's/^/    /' "$tmp/events-$1.out" >&2
}
events_check "events: 100% of settled impersonator requests classified impersonator (D-22)" \
  impersonator -site "$SITE" -impersonators "/lab/impersonator/$RUN/" -crawlers "/lab/crawler/$RUN/" \
  -want-settled "$IMPERSONATOR_SETTLED" -want-verified "$CRAWLER_VERIFIED"
events_check "events: no clearance for the non-JS client (no feedback pass, nothing forwarded)" \
  clearance -site "$SITE" -protected "/lab/members/$RUN/" -want-feedback "$CHALLENGE_SUBMISSIONS"

# The origin must never see the protected route, /__mg/*, or a settled
# impersonator request (only the pending warm-ups, and never with
# MG-Verified: D-22); it must see the genuine crawlers, marked verified by the
# Edge.
leaks="$(grep -E "^ORIGIN [A-Z]+ (/lab/members/|/__mg|/lab/impersonator/$RUN/[^ ]*/[0-9]+ )|^ORIGIN [A-Z]+ /lab/impersonator/[^ ]* class=[^ ]* verified=[^-]" "$tmp/origin.log" || true)"
if [[ -z "$leaks" ]]; then
  record "origin: no protected, /__mg or settled impersonator request forwarded, no impersonator marked verified" PASS
else
  printf '    forwarded but should not have been:\n%s\n' "$leaks" | sed 's/^ORIGIN/      ORIGIN/' >&2
  record "origin: no protected, /__mg or settled impersonator request forwarded, no impersonator marked verified" FAIL
fi
verified_seen="$(grep -cE "^ORIGIN GET /lab/crawler/$RUN/[^ ]*/[0-9]+ class=verified_crawler verified=crawler:" "$tmp/origin.log" || true)"
if [[ "$verified_seen" == "$CRAWLER_VERIFIED" ]]; then
  record "origin: $CRAWLER_VERIFIED genuine crawler requests arrived with MG-Verified" PASS
else
  record "origin: ${verified_seen:-0} genuine crawler requests arrived with MG-Verified, want $CRAWLER_VERIFIED" FAIL
fi

# --- summary --------------------------------------------------------------------------
printf '\nlab-e2e summary (run %s, site %s, mg-edge %s):\n' "$RUN" "$SITE_HOST" "$edge_src" >&2
for line in "${results[@]}"; do
  printf '  %s\n' "$line" >&2
done
if ((failed)); then
  log "FAIL (MG_LAB_E2E_KEEP=1 keeps the config, logs and events)"
  exit 1
fi
log "PASS"
