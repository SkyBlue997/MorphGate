#!/usr/bin/env bash
# The daily check of docs/impl/phase2-spec.md §19 step 8 for a host without
# VictoriaMetrics (with it, load deploy/vmalert/mg-phase2.rules.yml instead).
#
# Each run reads mg-edge's /metrics and its systemd MainPID, compares them
# with the snapshot the previous run left in the state file, prints the
# increments and ratios, and flags every condition of §19 step 8 that it can
# see plus the cf audit check 18 evidence of docs/01 §8 ("单机形态"):
#
#   - mg_double_challenge_total increased by more than 10;
#   - mg_endpoint_cache_hit_reports_total, mg_sw_intercept_reports_total,
#     mg_token_ruc_total, mg_state_local_overflow_total or
#     mg_challenge_renew_total{result="unavailable"} increased at all;
#   - mg_site_forced_monitor is 1 (D-60: it must not stay on);
#   - mg_interactive_available is 0 for a site listed in --interactive-sites;
#   - more than 5 % of the MG-Proof verifications failed (excluding
#     `unchecked`): visitors looping on proof: required routes;
#   - interactive challenges issued / GET navigations above 0.1 % (§20,
#     an upper bound: /__mg/v counts twice);
#   - with --nearline-url / --nearline-file: mg_nl_backlog > 10000 or
#     mg_nl_lag_seconds > 600;
#   - with --valkey-cli: used_memory / maxmemory > 0.8 (`INFO memory`);
#   - with --vl-url: ic.too_fast, ic.hold_short, ic.no_trusted_input above 5 %
#     of the interactive kind=feedback events of the last 24 h;
#   - cf audit check 18: no CF-Connecting-IP misses, bad upstream keys or
#     foreign Workers, and the worst Cloudflare signal (hdr-names excluded)
#     missing on less than 1 % of mg_requests_total.
#
# Counters restart at 0 whenever mg-edge restarts or reloads (a new
# MainPID): such a run only reports the change and starts over.
#
# Usage:
#   scripts/mg-daily-check.sh [--metrics-url URL | --metrics-file FILE]
#       [--state FILE] [--pid PID] [--interactive-sites a,b]
#       [--nearline-url URL | --nearline-file FILE] [--valkey-cli "CMD ARGS"]
#       [--vl-url URL]
# Defaults: --metrics-url http://127.0.0.1:9901/metrics, --state
# /var/lib/morphgate/daily-check.state, the PID from `systemctl show -p
# MainPID --value mg-edge`, --interactive-sites from $MG_INTERACTIVE_SITES.
# Run it daily from cron or a systemd timer as a user that may read the
# state directory; keep its output with the cf audit evidence.
#
# Exit codes: 0 nothing flagged, 1 at least one ALERT, 2 usage or input
# error. Read-only towards mg-edge, Valkey and VictoriaLogs.
set -euo pipefail

metrics_url="http://127.0.0.1:9901/metrics"
metrics_file=""
state="/var/lib/morphgate/daily-check.state"
pid=""
interactive_sites="${MG_INTERACTIVE_SITES:-}"
nearline_url=""
nearline_file=""
valkey_cli=""
vl_url=""

die() { echo "mg-daily-check: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-url) metrics_url="${2?missing value}"; shift 2 ;;
    --metrics-file) metrics_file="${2?missing value}"; shift 2 ;;
    --state) state="${2?missing value}"; shift 2 ;;
    --pid) pid="${2?missing value}"; shift 2 ;;
    --interactive-sites) interactive_sites="${2?missing value}"; shift 2 ;;
    --nearline-url) nearline_url="${2?missing value}"; shift 2 ;;
    --nearline-file) nearline_file="${2?missing value}"; shift 2 ;;
    --valkey-cli) valkey_cli="${2?missing value}"; shift 2 ;;
    --vl-url) vl_url="${2?missing value}"; shift 2 ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # fetch URL FILE OUT: the samples of a /metrics page (no comments)
  local url="$1" file="$2" out="$3"
  if [[ -n "$file" ]]; then
    [[ -r "$file" ]] || die "cannot read $file"
    grep -v '^#' "$file" | grep -v '^[[:space:]]*$' > "$out" || true
  else
    curl -fsS --noproxy '*' --max-time 10 "$url" | grep -v '^#' | grep -v '^[[:space:]]*$' > "$out" \
      || die "cannot fetch $url"
  fi
}

fetch "$metrics_url" "$metrics_file" "$tmp/cur"
if [[ -z "$pid" ]]; then
  pid="$(systemctl show -p MainPID --value mg-edge 2>/dev/null || true)"
  [[ -n "$pid" && "$pid" != 0 ]] || die "cannot read mg-edge's MainPID (pass --pid)"
fi
now="$(date +%s)"

save() {
  mkdir -p "$(dirname "$state")"
  { echo "pid $pid ts $now"; cat "$tmp/cur"; } > "$state.new"
  mv "$state.new" "$state"
}

if [[ ! -s "$state" ]]; then
  save
  echo "INFO first snapshot saved (MainPID $pid); run again in about 24 h to compare"
  exit 0
fi
read -r _ prev_pid _ prev_ts < "$state"
if [[ "$prev_pid" != "$pid" ]]; then
  save
  echo "INFO mg-edge MainPID changed ($prev_pid -> $pid): its counters restarted at 0; snapshot replaced, nothing compared"
  exit 0
fi
tail -n +2 "$state" > "$tmp/prev"
hours=$(( (now - prev_ts + 1800) / 3600 ))
echo "INFO comparing with the snapshot of $(( (now - prev_ts) / 60 )) min ago (MainPID $pid)"

# delta REGEX: the sum of (current - previous) over the series whose
# `name{labels}` matches REGEX (a counter that went down counts from 0).
delta() {
  awk -v re="$1" '
    NR == FNR { prev[$1] = $2; next }
    $1 ~ re { d = $2 - (($1 in prev) ? prev[$1] : 0); if (d < 0) d = $2; s += d }
    END { printf "%.0f\n", s + 0 }' "$tmp/prev" "$tmp/cur"
}
# current REGEX: the sum of the current values of the matching series.
current() {
  awk -v re="$1" '$1 ~ re { s += $2 } END { printf "%.0f\n", s + 0 }' "$tmp/cur"
}
# ratio A B: A / B with four decimals ("-" when B is 0).
ratio() { awk -v a="$1" -v b="$2" 'BEGIN { if (b > 0) printf "%.4f\n", a / b; else print "-" }'; }
# above R LIMIT: whether a ratio is above the limit; at_least: or equal.
above() { [[ "$1" != "-" ]] && awk -v r="$1" -v l="$2" 'BEGIN { exit !(r > l) }'; }
at_least() { [[ "$1" != "-" ]] && awk -v r="$1" -v l="$2" 'BEGIN { exit !(r >= l) }'; }

alerts=0
alert() { echo "ALERT $*"; alerts=$((alerts + 1)); }
ok() { echo "OK    $*"; }

# §19 step 8: the counters that must not grow.
d="$(delta '^mg_double_challenge_total[{]')"
if (( d > 10 )); then alert "mg_double_challenge_total +$d (> 10): Cloudflare challenges in front of protected requests"; else ok "mg_double_challenge_total +$d"; fi
for family in mg_endpoint_cache_hit_reports_total mg_sw_intercept_reports_total mg_token_ruc_total mg_state_local_overflow_total; do
  d="$(delta "^${family}([{]| )")"
  if (( d > 0 )); then alert "$family +$d"; else ok "$family +0"; fi
done
d="$(delta '^mg_challenge_renew_total[{]result="unavailable"[}]')"
if (( d > 0 )); then alert "mg_challenge_renew_total{result=\"unavailable\"} +$d"; else ok "mg_challenge_renew_total{result=\"unavailable\"} +0"; fi

# D-60: force_monitor is an emergency switch.
forced="$(awk '$1 ~ /^mg_site_forced_monitor[{]/ && $2 == 1 { print $1 }' "$tmp/cur")"
if [[ -n "$forced" ]]; then alert "force_monitor is on: $(echo "$forced" | tr '\n' ' ')"; else ok "no site forced to monitor"; fi

# §5.1: interactive challenges enabled but not available (manifest v1 SDK).
# Site ids are [a-z0-9_-]: splitting on commas and blanks is safe.
for site in ${interactive_sites//,/ }; do
  v="$(current "^mg_interactive_available[{]site=\"${site}\"[}]")"
  if [[ "$v" != 1 ]]; then alert "mg_interactive_available{site=\"$site\"} = $v: interactive challenges run as pow"; else ok "interactive available on $site"; fi
done

# §9.1: visitors looping on proof: required routes.
bad="$(delta '^mg_proof_verify_total[{]result="(missing|malformed|unbound|jkt|htm|htu|iat|sig|replay)"[}]')"
all="$(delta '^mg_proof_verify_total[{]')"
r="$(ratio "$bad" "$all")"
if above "$r" 0.05; then alert "MG-Proof failures $bad / $all = $r (> 5 %)"; else ok "MG-Proof failures $bad / $all = $r"; fi

# §20: human friction, request level (an upper bound).
issued="$(delta '^mg_challenge_total[{]provider="[a-z_]+",result="issued",type="interactive"[}]')"
navigations="$(delta '^mg_navigations_total[{]')"
r="$(ratio "$issued" "$navigations")"
if above "$r" 0.001; then alert "interactive challenges / navigations $issued / $navigations = $r (> 0.1 %)"; else ok "interactive challenges / navigations $issued / $navigations = $r"; fi

# mg-nearline (optional).
if [[ -n "$nearline_url" || -n "$nearline_file" ]]; then
  fetch "$nearline_url" "$nearline_file" "$tmp/nl"
  backlog="$(awk '$1 ~ /^mg_nl_backlog([{ ]|$)/ { s += $2 } END { printf "%.0f\n", s + 0 }' "$tmp/nl")"
  lag="$(awk '$1 ~ /^mg_nl_lag_seconds([{ ]|$)/ { if ($2 > m) m = $2 } END { printf "%.0f\n", m + 0 }' "$tmp/nl")"
  if (( backlog > 10000 || lag > 600 )); then alert "mg-nearline backlog $backlog, lag ${lag}s"; else ok "mg-nearline backlog $backlog, lag ${lag}s"; fi
fi

# Valkey memory (optional): `--valkey-cli "valkey-cli --user owner --askpass"`.
if [[ -n "$valkey_cli" ]]; then
  # shellcheck disable=SC2086 # the command line is split on purpose
  info="$($valkey_cli INFO memory 2>/dev/null | tr -d '\r')" || info=""
  used="$(echo "$info" | awk -F: '$1 == "used_memory" { print $2 }')"
  max="$(echo "$info" | awk -F: '$1 == "maxmemory" { print $2 }')"
  if [[ -z "$used" ]]; then
    echo "INFO valkey: no INFO memory answer"
  else
    r="$(ratio "$used" "${max:-0}")"
    if [[ "$r" == "-" ]]; then alert "valkey maxmemory is not set (§19 step 1b)"
    elif above "$r" 0.8; then alert "valkey used_memory / maxmemory = $r (> 0.8)"
    else ok "valkey used_memory / maxmemory = $r"; fi
  fi
fi

# kind=feedback hard-check failures (optional, VictoriaLogs).
if [[ -n "$vl_url" ]]; then
  q() {
    curl -fsS --noproxy '*' --max-time 20 "${vl_url%/}/select/logsql/query" \
      --data-urlencode "query=$1 | stats count() n" 2>/dev/null \
      | sed -n 's/.*"n":"\{0,1\}\([0-9][0-9]*\).*/\1/p' | head -n 1
  }
  total="$(q '_time:24h kind:=feedback type:=interactive')"
  failing="$(q '_time:24h kind:=feedback type:=interactive (reason_codes:"ic.too_fast" or reason_codes:"ic.hold_short" or reason_codes:"ic.no_trusted_input")')"
  if [[ -z "$total" || -z "$failing" ]]; then
    echo "INFO VictoriaLogs at $vl_url did not answer"
  else
    r="$(ratio "$failing" "$total")"
    if above "$r" 0.05; then alert "interactive hard-check failures $failing / $total = $r (> 5 %): SDK or page regression"; else ok "interactive hard-check failures $failing / $total = $r"; fi
  fi
fi

# cf audit check 18 (docs/01 §8): the counters that must stay 0, and the
# worst missing Cloudflare signal (hdr-names excluded) per request.
for series in '^mg_cf_connecting_ip_missing_total[{]' '^mg_upstream_auth_failures_total[{].*reason="bad_secret_header"' '^mg_cf_foreign_worker_total[{]'; do
  d="$(delta "$series")"
  name="${series#^}"; name="${name%%[[]*}"
  if (( d > 0 )); then alert "cf audit 18: $name +$d"; else ok "cf audit 18: $name +0"; fi
done
requests="$(delta '^mg_requests_total[{]')"
worst="$(awk '
  NR == FNR { prev[$1] = $2; next }
  $1 ~ /^mg_upstream_signal_missing_total[{]profile="cloudflare",signal="/ && $1 !~ /signal="hdr-names"/ {
    d = $2 - (($1 in prev) ? prev[$1] : 0); if (d < 0) d = $2; if (d > m) { m = d; s = $1 }
  }
  END { printf "%.0f %s\n", m + 0, s }' "$tmp/prev" "$tmp/cur")"
missing="${worst%% *}"
if (( requests == 0 )); then
  echo "INFO cf audit 18: mg_requests_total +0 in ${hours} h: no traffic (or the wrong Edge), no evidence"
else
  r="$(ratio "$missing" "$requests")"
  if at_least "$r" 0.01; then alert "cf audit 18: worst missing signal $missing / $requests requests = $r (>= 1 %) ${worst#* }"; else ok "cf audit 18: worst missing signal $missing / $requests requests = $r"; fi
fi

save
if (( alerts > 0 )); then
  echo "mg-daily-check: $alerts alert(s)"
  exit 1
fi
echo "mg-daily-check: ok"
