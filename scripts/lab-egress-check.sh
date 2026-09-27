#!/usr/bin/env bash
# Validation Lab isolation check (docs/07-roadmap.md, Phase 0 acceptance: a
# request to a target outside the allowlist is refused, at the tool layer and
# at the egress layer). Needs a running Docker daemon.
#
# Uses the "lab" profile of deploy/compose/docker-compose.yml under its own
# compose project (mg-lab-check), so it never touches a running `make dev-up`
# environment. All traffic stays on this machine: between containers on the
# internal `lab` network, and to one listener this script starts on the host.
#
#   1. Starts a throwaway HTTP listener on the host address that containers
#      reach as host.docker.internal (Linux: the default bridge gateway;
#      Docker Desktop: 127.0.0.1), serving a unique marker file.
#   2. Positive control: a container on Docker's default network fetches the
#      marker. If that fails, the egress result below would prove nothing.
#   3. Tool layer: mglab (on the lab network) replays a scenario against the
#      in-network lab-origin (allowed), and refuses example.com and the host
#      listener before any connection is made.
#   4. Egress layer: lab-probe, a plain HTTP client on the lab network that
#      bypasses the guard, cannot reach the host listener. On Linux, the host
#      also has no address inside the lab network's subnet: an internal
#      network normally gives the host its gateway address, through which lab
#      containers would reach every host service bound to 0.0.0.0 (the compose
#      file sets inhibit_ipv4 to prevent that).
#   5. The host listener saw exactly one request (the positive control).
#
# Environment overrides:
#   MG_LAB_CHECK_PORT   host listener port, default 18099
#   MG_LAB_CHECK_BIND   host listener address (default: detected, see step 1)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${MG_LAB_CHECK_PORT:-18099}"
PROBE_IMAGE="busybox:1.37.0" # same image as the lab-probe service
COMPOSE=(docker compose -p mg-lab-check -f "$ROOT/deploy/compose/docker-compose.yml" --profile lab)

tmp=""
listener_pid=""
started=""

log() { printf 'lab-egress-check: %s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

[[ "$PORT" =~ ^[0-9]+$ ]] || fail "MG_LAB_CHECK_PORT must be numeric, got '$PORT'"
command -v docker >/dev/null || fail "docker not found in PATH"
command -v python3 >/dev/null || fail "python3 not found in PATH"

cleanup() {
  local rc=$?
  if [[ -n "$listener_pid" ]]; then
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
  fi
  if [[ -n "$started" ]]; then
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  [[ -n "$tmp" ]] && rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# `docker info` hangs for a long time when the daemon socket exists but nobody
# answers, so bound the wait.
docker info >/dev/null 2>&1 &
info_pid=$!
for _ in $(seq 1 40); do
  kill -0 "$info_pid" 2>/dev/null || break
  sleep 0.25
done
if kill -0 "$info_pid" 2>/dev/null; then
  kill "$info_pid" 2>/dev/null || true
  fail "Docker daemon did not answer within 10 s (start Docker and retry)"
fi
wait "$info_pid" || fail "Docker daemon is not reachable (start Docker and retry)"

# --- 1. host listener --------------------------------------------------------
if [[ -n "${MG_LAB_CHECK_BIND:-}" ]]; then
  BIND="$MG_LAB_CHECK_BIND"
elif [[ "$(uname -s)" == "Linux" ]]; then
  # host-gateway resolves to the default bridge's gateway on Linux.
  BIND="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
else
  # Docker Desktop forwards host.docker.internal to the host's loopback.
  BIND="127.0.0.1"
fi
[[ "$BIND" =~ ^[0-9.]+$ ]] || fail "could not determine the host listener address (got '$BIND')"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/mg-lab-check.XXXXXX")"
mkdir -p "$tmp/www"
token="mg-lab-check-$$-$RANDOM$RANDOM"
printf '%s\n' "$token" >"$tmp/www/marker.txt"
python3 -m http.server "$PORT" --bind "$BIND" --directory "$tmp/www" >"$tmp/listener.log" 2>&1 &
listener_pid=$!
sleep 1
kill -0 "$listener_pid" 2>/dev/null || { cat "$tmp/listener.log" >&2; fail "host listener did not start on $BIND:$PORT"; }
log "host listener on $BIND:$PORT"

requests_seen() { grep -c '"GET /marker.txt' "$tmp/listener.log" || true; }

# --- 2. positive control -----------------------------------------------------
got="$(docker run --rm --add-host host.docker.internal:host-gateway "$PROBE_IMAGE" \
  wget -q -T 5 -O - "http://host.docker.internal:$PORT/marker.txt" 2>&1 || true)"
[[ "$got" == "$token" ]] ||
  fail "positive control: a container on the default network cannot reach $BIND:$PORT either ($got); the egress check would prove nothing"
log "ok: a container on the default network reaches the host listener (control)"

# --- 3. tool layer -----------------------------------------------------------
started=1
log "building mglab and starting lab-origin"
"${COMPOSE[@]}" build --quiet mglab
"${COMPOSE[@]}" up -d --quiet-pull lab-origin

ready=""
for _ in $(seq 1 20); do
  if "${COMPOSE[@]}" run -T --rm lab-probe wget -q -T 2 -O /dev/null http://origin.lab.test:8081/health >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ -n "$ready" ]] || fail "lab-origin did not become reachable on the lab network"

"${COMPOSE[@]}" run -T --rm mglab replay -config /etc/mglab/lab.yaml /lab/testdata/scenarios/lab-origin.yaml ||
  fail "mglab could not replay against the in-network lab-origin"
log "ok: mglab replays against the in-network origin"

for target in "http://example.com/" "http://host.docker.internal:$PORT/marker.txt"; do
  set +e
  "${COMPOSE[@]}" run -T --rm mglab check -config /etc/mglab/lab.yaml "$target"
  rc=$?
  set -e
  [[ "$rc" -eq 1 ]] || fail "mglab check $target: exit $rc, want 1 (denied)"
done
set +e
"${COMPOSE[@]}" run -T --rm mglab replay -config /etc/mglab/lab.yaml \
  -base "http://host.docker.internal:$PORT" /lab/testdata/scenarios/lab-origin.yaml
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "mglab replay against the host listener: exit $rc, want 1 (denied)"
log "ok: mglab refuses targets outside the allowlist"

# --- 4. egress layer ---------------------------------------------------------
set +e
out="$("${COMPOSE[@]}" run -T --rm lab-probe wget -q -T 5 -O - "http://host.docker.internal:$PORT/marker.txt" 2>&1)"
rc=$?
set -e
if [[ "$rc" -eq 0 || "$out" == *"$token"* ]]; then
  fail "egress layer: a container on the lab network reached the host listener"
fi
log "ok: the lab network cannot reach the host listener (${out:-no output})"

if [[ "$(uname -s)" == "Linux" ]]; then
  lab_net="$(docker network ls -q \
    --filter label=com.docker.compose.project=mg-lab-check \
    --filter label=com.docker.compose.network=lab)"
  [[ -n "$lab_net" && "$lab_net" != *$'\n'* ]] || fail "could not identify the lab network (got '$lab_net')"
  subnets="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$lab_net")"
  subnets="${subnets% }"
  [[ -n "${subnets// /}" ]] || fail "lab network $lab_net has no IPAM subnet"
  # shellcheck disable=SC2046 # one argument per host address
  leaked="$(python3 - "$subnets" $(ip -o addr show | awk '{print $4}') <<'PY'
import ipaddress, sys
nets = [ipaddress.ip_network(s, strict=False) for s in sys.argv[1].split()]
for arg in sys.argv[2:]:
    addr = ipaddress.ip_interface(arg).ip
    if any(addr.version == n.version and addr in n for n in nets):
        print(addr)
PY
)"
  if [[ -n "$leaked" ]]; then
    fail "egress layer: the host has address(es) ${leaked//$'\n'/ } on the lab network ($subnets); lab containers can reach host services bound to 0.0.0.0 through it"
  fi
  log "ok: the host has no address on the lab network ($subnets)"
else
  log "note: host-address check skipped ($(uname -s)): Docker Desktop keeps bridges inside its VM"
fi

# --- 5. listener log ---------------------------------------------------------
seen="$(requests_seen)"
[[ "$seen" -eq 1 ]] || { cat "$tmp/listener.log" >&2; fail "host listener saw $seen requests, want 1 (the control)"; }

log "PASS"
