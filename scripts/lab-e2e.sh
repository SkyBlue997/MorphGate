#!/usr/bin/env bash
# Validation Lab end-to-end run on loopback against a real mg-edge in enforce
# mode: the Phase 1 acceptance scenarios of docs/impl/phase1-spec.md §15
# WP-L1 / §18 and the Phase 2 ones of docs/impl/phase2-spec.md §17 WP-L2 /
# §18 / §20, with mg-nearline. Fixed requests only: nothing here solves a
# challenge (D-59), and every target is loopback.
#
#   1. Builds mgctl, mg-nearline and mglab (go build), and mg-edge unless
#      MG_EDGE_BIN names one (CI passes the rust job's release binary); picks
#      the Web SDK directory (MG_LAB_SDK_DIR, else a fresh `pnpm run build`
#      of sdk/web when pnpm and node are installed, else
#      edge/tests/fixtures/sdk). The Edge runs from private copies of its
#      binary and SDK directory.
#   2. In a temp dir, with throwaway test keys (MGCTL_PASSPHRASE_FILE,
#      MGCTL_AGE_WORK_FACTOR=10, --insecure-test-key; audit log in the temp
#      dir): owner signing key, pseudonymisation key, origin keys (`mgctl keys
#      gen-origin`) and the site keys of two sites, exported with `mgctl keys
#      export --out` as the Edge's credential files, and a placeholder
#      Turnstile secret file. Builds, signs and publishes two enforce bundles
#      into a file:// bundle root:
#        lab/testdata/e2e/site.yaml     site "lab", host site.lab.test, a
#                                       Phase 1 bundle (schema_version 1)
#        lab/testdata/e2e/site-p2.yaml  site "labp2", host p2.lab.test,
#                                       interactive challenges and Turnstile
#                                       (schema_version 2)
#   3. Starts a temporary valkey-server on a unix socket in the temp dir (or
#      uses MG_TEST_VALKEY_URL, which must be local), a Node origin that
#      answers only requests whose MG-Origin-Auth passes the reference check
#      (adapters/origin/verify-origin-auth.mjs, spec I-38) and 401 otherwise,
#      a Node sink that stands in for VictoriaLogs (mg-nearline's kind=verdict
#      lines) and for Turnstile's siteverify (a mock that logs every call;
#      MG_EDGE_TEST_OUTBOUND=1, D-52), and mg-edge with a `cloudflare`
#      loopback listener, both sites, origin_keys, Valkey state, the static
#      rDNS table lab/testdata/e2e/dns.json and a JSONL event file; waits
#      until the Edge applied both bundles and interactive challenges are
#      available on labp2.
#   4. Runs the scenarios through mglab (every request passes the Lab guard;
#      both site names are mapped to 127.0.0.1 with -map-host):
#        lab/testdata/scenarios/phase1-impersonator.yaml
#        lab/testdata/scenarios/phase1-nonjs-clearance.yaml
#        lab/testdata/scenarios/phase1-route-modes.yaml
#        lab/testdata/scenarios/phase2-challenge-page.yaml
#        lab/testdata/scenarios/phase2-submissions.yaml
#      and sends an unsigned and a forged request straight to the origin.
#   5. Near line: starts mg-nearline (its own consumer group on mg:ev, the
#      sink as vl_main) with the scanner detector in shadow, replays
#      phase2-nearline-baits.yaml from one address and waits for the shadow
#      verdict; restarts it in enforce, replays the baits from a second
#      address and waits for the written verdict; then, after the Edge's 2 s
#      verdict cache, replays phase2-nearline-after.yaml.
#   6. Checks the event file with `mglab events` (D-22: 100 % of the settled
#      impersonator requests classified impersonator; no challenge
#      submission or renewal passed, nothing on a protected route forwarded,
#      on both sites; Turnstile only offered to the allowed countries; the
#      near-line shadow verdict not written, the enforce verdict written
#      within 10 s of its trigger and raising the scanner's next request to
#      a challenge, never a block), the route-mode decisions (I-36, I-37:
#      challenges on the monitor and never_challenge routes recorded as dry
#      runs), the origin's request log (only the two direct requests refused,
#      nothing protected forwarded) and the siteverify mock (no call), then
#      prints a PASS / FAIL summary.
#   7. Stops every process and removes the temp dir on every exit path.
#
# Environment:
#   MG_EDGE_BIN            use this mg-edge binary instead of `cargo build -p mg-edge`
#   MG_TEST_VALKEY_URL     use this Valkey (redis://<loopback>[:port][/db] or
#                          unix:///<socket>) instead of starting valkey-server;
#                          keys carry the site ids "lab" and "labp2", nothing
#                          is flushed, and mg-nearline leaves its consumer
#                          group lab-<run id> on mg:ev
#   MG_LAB_SDK_DIR         Web SDK directory (manifest.json + files) to serve;
#                          the Phase 2 scenarios need a manifest v2 directory
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
# The Phase 2 site (lab/testdata/e2e/site-p2.yaml): interactive challenges and
# Turnstile, a schema_version 2 bundle next to the Phase 1 site's.
P2_SITE="labp2"
P2_HOST="p2.lab.test"
BUNDLE_VERSION=1
TIMEOUT="${MG_LAB_E2E_TIMEOUT:-60}"
SCENARIOS="$ROOT/lab/testdata/scenarios"
E2E="$ROOT/lab/testdata/e2e"

# Numbers the scenarios are built around (see the scenario files).
IMPERSONATOR_SETTLED=13
CRAWLER_VERIFIED=6
CHALLENGE_SUBMISSIONS=3
# phase2-submissions: submissions to /__mg/c that reach the Edge's checks
# (the foreign CF-Worker's is refused before); phase2-challenge-page:
# interactive challenges on route "login" with and without Turnstile.
P2_SUBMISSIONS=8
TURNSTILE_OFFERED=3
TURNSTILE_WITHHELD=7

tmp=""
edge_pid=""
origin_pid=""
valkey_pid=""
sink_pid=""
nl_pid=""
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
for tool in python3 go curl node; do
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
  stop "$nl_pid" mg-nearline TERM
  stop "$edge_pid" mg-edge INT
  stop "$origin_pid" origin TERM
  stop "$sink_pid" sink TERM
  stop "$valkey_pid" valkey-server TERM
  if [[ -n "$tmp" && -d "$tmp" ]]; then
    if [[ "$rc" -ne 0 ]]; then
      for f in edge.log origin.log sink.log nearline.log valkey.log build.log; do
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

# Five free loopback ports, held open together so they differ.
read -r EDGE_PORT ORIGIN_PORT METRICS_PORT SINK_PORT NL_METRICS_PORT < <(python3 - <<'PY'
import socket
socks = []
for _ in range(5):
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
log "building mgctl, mg-nearline and mglab"
(cd "$ROOT" && go build -o "$tmp/bin/mgctl" ./control-plane/cmd/mgctl \
  && go build -o "$tmp/bin/mg-nearline" ./control-plane/cmd/mg-nearline \
  && go build -o "$tmp/bin/mglab" ./lab/cmd/mglab) \
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
step keys export --in "$tmp/keys/pseudo.key.json.age" --out "$tmp/creds/mg-pseudo-key"
# Both sites forward to the one origin, which checks MG-Origin-Auth with these keys.
step keys gen-origin --out "$tmp/keys/origin-keys.json.age" --insecure-test-key
step keys export --in "$tmp/keys/origin-keys.json.age" --out "$tmp/creds/mg-origin-keys"
# site_keys_and_bundle SITE CONFIG: the site's token and seal keys as
# credential files, and its bundle built, signed and published. --date
# matches token.active_kid (<site>-t-20260927) in the site's YAML.
site_keys_and_bundle() {
  local site="$1" config="$2"
  step site keys gen --site "$site" --out-dir "$tmp/keys/$site" --date 20260927 --insecure-test-key
  step keys export --in "$tmp/keys/$site/token.keys.json.age" --out "$tmp/creds/mg-$site-token-keys"
  step keys export --in "$tmp/keys/$site/seal.root.json.age" --out "$tmp/creds/mg-$site-seal-root"
  step bundle build --site-config "$config" --out-dir "$tmp/out" --version "$BUNDLE_VERSION"
  step bundle sign --in "$tmp/out/$site.sitebundle.pb" --key "$tmp/keys/lab-owner.key.age" --out "$tmp/out/$site.bundle"
  step bundle publish --in "$tmp/out/$site.bundle" --artifacts "$tmp/out/artifacts" --dest "$tmp/publish" \
    --pub "$tmp/keys/lab-owner.pub" --confirm "$site"
}
site_keys_and_bundle "$SITE" "$E2E/site.yaml"
site_keys_and_bundle "$P2_SITE" "$E2E/site-p2.yaml"
step audit verify
# The Phase 2 site's Turnstile secret (§8.7 file format): a placeholder that
# only the loopback mock siteverify below ever sees.
printf '{"v":1,"kind":"mg-turnstile-keys","site":"%s","values":["lab-e2e-test-secret-%s"]}\n' "$P2_SITE" "$RUN" \
  >"$tmp/creds/mg-$P2_SITE-turnstile-keys"
log "ok: test keys, enforce bundles for $SITE ($SITE_HOST) and $P2_SITE ($P2_HOST) signed and published (version $BUNDLE_VERSION)"

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

# Answers every request itself (200) once its MG-Origin-Auth passes the
# reference check (spec I-38), 401 otherwise, and logs what the Edge
# forwarded, with the Edge's classification headers.
cat >"$tmp/origin.mjs" <<'JS'
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [verifier, keyFile, port] = process.argv.slice(2);
const { loadOriginKeys, verifyOriginAuth } = await import(pathToFileURL(verifier).href);
const keys = loadOriginKeys(readFileSync(keyFile));

createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    const h = (name) => req.headers[name];
    const ok = verifyOriginAuth({ value: h("mg-origin-auth"), method: req.method, target: req.url, header: h, keys });
    const line = ok
      ? `ORIGIN ${req.method} ${req.url} class=${h("mg-bot-class") ?? "-"} verified=${h("mg-verified") ?? "-"}`
      : `ORIGIN-REJECT ${req.method} ${req.url}`;
    process.stderr.write(line + "\n");
    const body = ok ? `lab-e2e-origin ${req.method} ${req.url}\n` : "origin auth failed\n";
    res.writeHead(ok ? 200 : 401, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "private, no-store",
      "Content-Length": Buffer.byteLength(body),
    });
    res.end(req.method === "HEAD" ? undefined : body);
  });
}).listen(Number(port), "127.0.0.1");
JS
node "$tmp/origin.mjs" "$ROOT/adapters/origin/verify-origin-auth.mjs" "$tmp/creds/mg-origin-keys" "$ORIGIN_PORT" \
  >"$tmp/origin.log" 2>&1 &
origin_pid=$!
wait_for_port origin "$ORIGIN_PORT" "$origin_pid"

# The loopback sink of mg-nearline's kind=verdict lines (VictoriaLogs'
# jsonline insert API, verdict_events.vl_main) and the Edge's mock Turnstile
# siteverify (D-52). Every siteverify call is logged: none is expected, as no
# scenario submission gets past opening its C.
cat >"$tmp/sink.mjs" <<'JS'
import { createServer } from "node:http";
import { appendFileSync } from "node:fs";

const [port, verdicts] = process.argv.slice(2);
createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf8");
    const path = req.url.split("?")[0];
    let status = 404, reply = "not found\n", type = "text/plain";
    if (req.method === "POST" && path === "/insert/jsonline") {
      appendFileSync(verdicts, body.endsWith("\n") || body === "" ? body : body + "\n");
      process.stderr.write(`SINK verdict lines=${body.split("\n").filter(Boolean).length}\n`);
      status = 200;
      reply = "";
    } else if (req.method === "POST" && path === "/siteverify") {
      process.stderr.write("SITEVERIFY\n");
      status = 200;
      type = "application/json";
      reply = JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] });
    } else {
      process.stderr.write(`SINK-UNKNOWN ${req.method} ${path}\n`);
    }
    res.writeHead(status, { "Content-Type": type, "Content-Length": Buffer.byteLength(reply) });
    res.end(reply);
  });
}).listen(Number(port), "127.0.0.1");
JS
: >"$tmp/verdicts.jsonl"
node "$tmp/sink.mjs" "$SINK_PORT" "$tmp/verdicts.jsonl" >"$tmp/sink.log" 2>&1 &
sink_pid=$!
wait_for_port sink "$SINK_PORT" "$sink_pid"

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
origin_keys = "cred://mg-origin-keys"

[[sites]]
id = "$P2_SITE"
hosts = ["$P2_HOST"]
listeners = ["cf-tunnel"]
origin = "$HOST:$ORIGIN_PORT"
bundle_root = "file://$tmp/publish/"
bundle_poll_seconds = 2
bootstrap = "closed"
token_keys = "cred://mg-$P2_SITE-token-keys"
seal_root = "cred://mg-$P2_SITE-seal-root"
origin_keys = "cred://mg-origin-keys"
turnstile_keys = "cred://mg-$P2_SITE-turnstile-keys"

[pseudo]
key = "cred://mg-pseudo-key"

# The loopback mock (sink.mjs); accepted only with MG_EDGE_TEST_OUTBOUND=1.
[outbound]
turnstile_siteverify_url = "http://$HOST:$SINK_PORT/siteverify"

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

export CREDENTIALS_DIRECTORY="$tmp/creds" MG_EDGE_TEST_OUTBOUND=1
"$edge_bin" --check-config --config "$tmp/edge.toml" >"$tmp/check.log" 2>&1 \
  || { cat "$tmp/check.log" >&2; fail "mg-edge --check-config rejected the Lab config"; }
RUST_LOG="${RUST_LOG:-info}" "$edge_bin" --config "$tmp/edge.toml" >"$tmp/edge.log" 2>&1 &
edge_pid=$!
wait_for_port mg-edge "$EDGE_PORT" "$edge_pid"
wait_for_port "mg-edge metrics" "$METRICS_PORT" "$edge_pid"
wait_for_metric "mg_config_version{site=\"$SITE\"}" "$BUNDLE_VERSION" "the published bundle"
wait_for_metric "mg_site_state{site=\"$SITE\",state=\"active\"}" 1 "site $SITE to become active"
wait_for_metric "mg_config_version{site=\"$P2_SITE\"}" "$BUNDLE_VERSION" "the published bundle of $P2_SITE"
wait_for_metric "mg_site_state{site=\"$P2_SITE\",state=\"active\"}" 1 "site $P2_SITE to become active"
wait_for_metric 'mg_state_mode{mode="valkey"}' 1 "the Valkey state layer"
# §5.1: the Phase 2 site's bundle enables interactive challenges and the SDK
# directory is manifest v2.
wait_for_metric "mg_interactive_available{site=\"$P2_SITE\"}" 1 "interactive challenges on $P2_SITE"
log "ok: mg-edge on $HOST:$EDGE_PORT (pid $edge_pid), sites $SITE and $P2_SITE active in enforce mode with Valkey state"

# --- scenarios -----------------------------------------------------------------------
target="http://$SITE_HOST:$EDGE_PORT"
p2_target="http://$P2_HOST:$EDGE_PORT"
if "$MGLAB" check -map-host "$SITE_HOST=$HOST" -resolve "$target/" >"$tmp/guard.log" 2>&1 \
  && "$MGLAB" check -map-host "$P2_HOST=$HOST" -resolve "$p2_target/" >>"$tmp/guard.log" 2>&1 \
  && ! "$MGLAB" check http://example.com/ >>"$tmp/guard.log" 2>&1; then
  record "Lab guard: admits $SITE_HOST and $P2_HOST -> $HOST, refuses a target outside the allowlist" PASS
else
  cat "$tmp/guard.log" >&2
  record "Lab guard: admits $SITE_HOST and $P2_HOST -> $HOST, refuses a target outside the allowlist" FAIL
fi

sent_total=0
# replay NAME BASE FILE [-var name=value]...: runs one scenario through mglab
# and the guard.
replay() {
  local name="$1" base="$2" file="$3" out="$tmp/$1.out" sent
  shift 3
  log "replaying $name (run $RUN)"
  if "$MGLAB" replay -rps 20 -map-host "$SITE_HOST=$HOST" -map-host "$P2_HOST=$HOST" -base "$base" \
    -var "run=$RUN" "$@" "$file" >"$out" 2>&1; then
    record "scenario $name: every response as expected" PASS
  else
    record "scenario $name: every response as expected" FAIL
  fi
  sed 's/^/    /' "$out" >&2
  sent="$(awk '/^done: / { print $2 }' "$out")"
  sent_total=$((sent_total + ${sent:-0}))
}
replay phase1-impersonator "$target" "$SCENARIOS/phase1-impersonator.yaml"
replay phase1-nonjs-clearance "$target" "$SCENARIOS/phase1-nonjs-clearance.yaml"
replay phase1-route-modes "$target" "$SCENARIOS/phase1-route-modes.yaml"
replay phase2-challenge-page "$p2_target" "$SCENARIOS/phase2-challenge-page.yaml"
replay phase2-submissions "$p2_target" "$SCENARIOS/phase2-submissions.yaml"

# --- mg-nearline (Phase 2 spec §13, §17 WP-L2) ----------------------------------------
# The worker consumes the Edge's mg:ev stream from the same Valkey (default
# user, no ACL) in its own consumer group, and sends its kind=verdict lines
# to the loopback sink. Its scanner detector runs first in shadow, then in
# enforce, each time against a fresh round of bait requests from another
# address (phase2-nearline-baits.yaml): the windows live in the worker's
# memory and start empty after the restart.
NL_SHADOW_IP=203.0.113.120
NL_ENFORCE_IP=203.0.113.121
NL_FRESH_IP=203.0.113.122
# The worker accepts only IP literals for a TCP Valkey (§13.5).
nl_valkey_url="$valkey_url"
[[ "$nl_valkey_url" == redis://localhost* ]] && nl_valkey_url="redis://127.0.0.1${nl_valkey_url#redis://localhost}"
nl_metric() {
  curl -sS --noproxy '*' --max-time 5 "http://$HOST:$NL_METRICS_PORT/metrics" 2>/dev/null \
    | awk -v s="$1" 'index($0, s " ") == 1 { print $2; exit }'
}
# nl_start MODE: mg-nearline with the scanner detector in MODE (the other
# detectors stay in shadow); waits until it reads the stream.
nl_start() {
  local mode="$1" cfg="$tmp/nearline-$1.yaml" deadline
  cat >"$cfg" <<NLCFG
# Generated by scripts/lab-e2e.sh; removed on exit.
version: 1
valkey: {url: "$nl_valkey_url"}
stream: {key: "mg:ev", group: "lab-$RUN"}
sites: [$P2_SITE]
verdict_events: {vl_main: "http://$HOST:$SINK_PORT"}
metrics_listen: "$HOST:$NL_METRICS_PORT"
detectors:
  scanner: {mode: $mode, risk: 100}
NLCFG
  "$tmp/bin/mg-nearline" --check-config --config "$cfg" >>"$tmp/nearline.log" 2>&1 \
    || fail "mg-nearline --check-config rejected the Lab config ($mode)"
  "$tmp/bin/mg-nearline" --config "$cfg" >>"$tmp/nearline.log" 2>&1 &
  nl_pid=$!
  wait_for_port mg-nearline "$NL_METRICS_PORT" "$nl_pid"
  deadline=$((SECONDS + TIMEOUT))
  until [[ "$(nl_metric mg_nl_last_batch_timestamp_seconds)" =~ ^[1-9] ]]; do
    kill -0 "$nl_pid" 2>/dev/null || fail "mg-nearline exited before reading the stream"
    ((SECONDS < deadline)) || fail "timed out after ${TIMEOUT}s waiting for mg-nearline to read the stream"
    sleep 0.2
  done
  log "ok: mg-nearline (pid $nl_pid) consuming mg:ev, scanner in $mode"
}
# nl_wait_verdict MODE: until the scanner reported a verdict in MODE and its
# kind=verdict line reached the sink; 1 on timeout.
nl_wait_verdict() {
  local mode="$1" deadline=$((SECONDS + TIMEOUT)) n
  while :; do
    n="$(nl_metric "mg_nl_verdicts_total{site=\"$P2_SITE\",detector=\"scanner\",mode=\"$mode\"}")"
    if [[ "${n:-0}" =~ ^[1-9] ]] && grep -q "\"detector\":\"scanner\",\"mode\":\"$mode\"" "$tmp/verdicts.jsonl"; then
      return 0
    fi
    kill -0 "$nl_pid" 2>/dev/null || { log "mg-nearline exited"; return 1; }
    ((SECONDS < deadline)) || { log "no $mode scanner verdict after ${TIMEOUT}s"; return 1; }
    sleep 0.2
  done
}

nl_start shadow
replay phase2-nearline-baits-shadow "$p2_target" "$SCENARIOS/phase2-nearline-baits.yaml" -var "ip=$NL_SHADOW_IP"
if nl_wait_verdict shadow; then
  record "mg-nearline: scanner in shadow reported a verdict (kind=verdict line, log)" PASS
else
  record "mg-nearline: scanner in shadow reported a verdict (kind=verdict line, log)" FAIL
fi
stop "$nl_pid" mg-nearline TERM
nl_pid=""

nl_start enforce
replay phase2-nearline-baits-enforce "$p2_target" "$SCENARIOS/phase2-nearline-baits.yaml" -var "ip=$NL_ENFORCE_IP"
if nl_wait_verdict enforce; then
  record "mg-nearline: scanner in enforce wrote a verdict" PASS
else
  record "mg-nearline: scanner in enforce wrote a verdict" FAIL
fi
# The Edge caches each entity's verdict lookup for 2 s (§13.4): the bait
# requests looked the enforce address up before the verdict existed.
sleep 2.5
replay phase2-nearline-after "$p2_target" "$SCENARIOS/phase2-nearline-after.yaml" \
  -var "enforce_ip=$NL_ENFORCE_IP" -var "shadow_ip=$NL_SHADOW_IP" -var "fresh_ip=$NL_FRESH_IP"
stop "$nl_pid" mg-nearline TERM
nl_pid=""

# Straight to the origin, past the Edge (both loopback): without a valid
# MG-Origin-Auth the origin refuses the request and its MG-* headers (I-38).
origin_direct() { # origin_direct PATH [HEADER...] -> HTTP status
  local path="$1" args=() h
  shift
  for h in "$@"; do args+=(-H "$h"); done
  curl -sS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' "${args[@]}" \
    "http://$HOST:$ORIGIN_PORT$path" 2>/dev/null || true
}
unsigned="$(origin_direct "/lab/direct/$RUN/unsigned" "MG-Client-IP: 203.0.113.80" "MG-Bot-Class: human")"
forged="$(origin_direct "/lab/direct/$RUN/forged" "MG-Client-IP: 203.0.113.81" \
  "MG-Origin-Auth: v1;t=$(date +%s);sig=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")"
if [[ "$unsigned" == 401 && "$forged" == 401 ]]; then
  record "origin: unsigned and forged MG-Origin-Auth sent past the Edge refused (401)" PASS
else
  record "origin: unsigned / forged requests past the Edge answered $unsigned / $forged, want 401" FAIL
fi

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
# events CHECK-NAME ARGS...: mglab events (ARGS end with the event files),
# output into the log.
events_n=0
events_check() {
  local name="$1" out
  shift
  events_n=$((events_n + 1))
  out="$tmp/events-$events_n-$1.out"
  if "$MGLAB" events "$@" >"$out" 2>&1; then
    record "$name" PASS
  else
    record "$name" FAIL
  fi
  sed 's/^/    /' "$out" >&2
}
events_check "events: 100% of settled impersonator requests classified impersonator (D-22)" \
  impersonator -site "$SITE" -impersonators "/lab/impersonator/$RUN/" -crawlers "/lab/crawler/$RUN/" \
  -want-settled "$IMPERSONATOR_SETTLED" -want-verified "$CRAWLER_VERIFIED" "$tmp/events.jsonl"
events_check "events: no clearance for the non-JS client (no feedback pass, nothing forwarded)" \
  clearance -site "$SITE" -protected "/lab/members/$RUN/" -want-feedback "$CHALLENGE_SUBMISSIONS" "$tmp/events.jsonl"
events_check "events: no interactive clearance or renewal from recorded, tampered or mismatched submissions (D-59)" \
  clearance -site "$P2_SITE" -protected "/p2/" -want-feedback "$P2_SUBMISSIONS" "$tmp/events.jsonl"
events_check "events: Turnstile never offered to a denied or unknown country, offered to the others (§5.4)" \
  providers -site "$P2_SITE" -route login -offer US,DE \
  -want-offered "$TURNSTILE_OFFERED" -want-withheld "$TURNSTILE_WITHHELD" "$tmp/events.jsonl"
events_check "events: near-line scanner verdict raises the risk to a challenge, never a block (D-53)" \
  nearline -site "$P2_SITE" -after "/nl/$RUN/" -shadow-ip "$NL_SHADOW_IP" -enforce-ip "$NL_ENFORCE_IP" \
  -fresh-ip "$NL_FRESH_IP" -max-latency-ms 10000 "$tmp/events.jsonl" "$tmp/verdicts.jsonl"

# The route-mode decisions (I-36, I-37): the marked request on the
# never_challenge route and both requests on the monitor route were decided
# CHALLENGE as a dry run (and forwarded, which the scenario checks).
if python3 - "$tmp/events.jsonl" "$RUN" >"$tmp/route-modes.out" 2>&1 <<'PY'
import json, sys
path, run = sys.argv[1], sys.argv[2]
want = {f"/lab/beacon/{run}/1", f"/lab/trial/{run}/home", f"/lab/trial/{run}/data.json"}
seen, bad = set(), []
for line in open(path):
    e = json.loads(line)
    p = ((e.get("ctx") or {}).get("http") or {}).get("path")
    if e.get("kind") != "decision" or p not in want:
        continue
    seen.add(p)
    d = e.get("decision") or {}
    if d.get("action") != "challenge" or d.get("dry_run") is not True:
        bad.append(f"{p}: action={d.get('action')} dry_run={d.get('dry_run')}")
missing = sorted(want - seen)
print(f"route modes: {len(seen)} of {len(want)} decisions found, {len(bad)} not a dry-run challenge")
for b in bad + [f"{m}: no decision event" for m in missing]:
    print("  " + b)
sys.exit(1 if bad or missing else 0)
PY
then
  record "events: monitor and never_challenge routes recorded the challenges as dry runs (I-36, I-37)" PASS
else
  record "events: monitor and never_challenge routes recorded the challenges as dry runs (I-36, I-37)" FAIL
fi
sed 's/^/    /' "$tmp/route-modes.out" >&2

# Every request the Edge forwarded carried a valid MG-Origin-Auth: the only
# requests the origin refused are the two sent past the Edge.
rejected="$(grep -c '^ORIGIN-REJECT ' "$tmp/origin.log" || true)"
rejected_edge="$(grep '^ORIGIN-REJECT ' "$tmp/origin.log" | grep -v " /lab/direct/$RUN/" || true)"
if [[ "$rejected" == 2 && -z "$rejected_edge" ]]; then
  record "origin: every request from the Edge passed the MG-Origin-Auth check (I-38)" PASS
else
  printf '    refused:\n%s\n' "$(grep '^ORIGIN-REJECT ' "$tmp/origin.log")" >&2
  record "origin: every request from the Edge passed the MG-Origin-Auth check (I-38)" FAIL
fi

# The origin must never see the protected route, /__mg/*, or a settled
# impersonator request (only the pending warm-ups, and never with
# MG-Verified: D-22); it must see the genuine crawlers, marked verified by the
# Edge.
leaks="$(grep -E "^ORIGIN [A-Z]+ (/lab/members/|/p2/|/__mg|/lab/impersonator/$RUN/[^ ]*/[0-9]+ )|^ORIGIN [A-Z]+ /lab/impersonator/[^ ]* class=[^ ]* verified=[^-]" "$tmp/origin.log" || true)"
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
# phase2-nearline-after: only the two control requests reached the origin;
# the scanner with the enforce verdict was challenged.
nl_seen="$(grep -c "^ORIGIN GET /nl/$RUN/page " "$tmp/origin.log" || true)"
if [[ "$nl_seen" == 2 ]]; then
  record "origin: after the near-line verdict, only the 2 control requests forwarded" PASS
else
  record "origin: ${nl_seen:-0} requests of phase2-nearline-after forwarded, want 2" FAIL
fi

# No scenario submission gets past opening its C, so the Edge never called
# the (mock) siteverify; nothing could have reached Cloudflare (D-52).
siteverify_calls="$(grep -c '^SITEVERIFY' "$tmp/sink.log" || true)"
unknown_sink="$(grep -c '^SINK-UNKNOWN' "$tmp/sink.log" || true)"
if [[ "$siteverify_calls" == 0 && "$unknown_sink" == 0 ]]; then
  record "siteverify: the loopback mock received no call" PASS
else
  record "siteverify: the loopback mock received $siteverify_calls call(s) ($unknown_sink unknown request(s)), want 0" FAIL
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
