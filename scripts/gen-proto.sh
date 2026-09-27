#!/usr/bin/env bash
# Generate Go code for the shared protobuf contract (proto/morphgate/v1/*.proto)
# into control-plane/gen/morphgate/v1. The output is committed.
#
# Rust does not use this script: crate mg-proto compiles the same .proto files
# in its build.rs with protox + prost-build.
#
# Usage:
#   scripts/gen-proto.sh           regenerate in place
#   scripts/gen-proto.sh --check   regenerate into a temp dir and fail if the
#                                  committed code differs (for CI)
#
# Requirements: go, protoc (override with PROTOC=/path/to/protoc).
set -euo pipefail

# Pinned generator. Keep equal to google.golang.org/protobuf in control-plane/go.mod
# (checked below) so generated code and runtime library always match.
PROTOC_GEN_GO_VERSION="v1.36.12"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTOC="${PROTOC:-protoc}"
MODULE="morphgate/control-plane"

mode="write"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
  *) echo "gen-proto: unknown argument: $1" >&2; exit 2 ;;
esac

die() { echo "gen-proto: $*" >&2; exit 1; }

command -v go >/dev/null || die "go not found in PATH"
command -v "$PROTOC" >/dev/null || die "protoc not found (set PROTOC=/path/to/protoc)"

runtime_version="$(awk '$1 == "google.golang.org/protobuf" { print $2 }' "$ROOT/control-plane/go.mod")"
if [[ -n "$runtime_version" && "$runtime_version" != "$PROTOC_GEN_GO_VERSION" ]]; then
  die "control-plane/go.mod uses google.golang.org/protobuf $runtime_version but the generator is pinned to $PROTOC_GEN_GO_VERSION; update one of them"
fi

GOBIN_DIR="$(go env GOBIN)"
[[ -n "$GOBIN_DIR" ]] || GOBIN_DIR="$(go env GOPATH)/bin"
PLUGIN="$GOBIN_DIR/protoc-gen-go"

installed=""
if [[ -x "$PLUGIN" ]]; then
  installed="$("$PLUGIN" --version 2>/dev/null | awk '{ print $2 }')"
fi
if [[ "$installed" != "$PROTOC_GEN_GO_VERSION" ]]; then
  echo "gen-proto: installing protoc-gen-go $PROTOC_GEN_GO_VERSION into $GOBIN_DIR" >&2
  GOBIN="$GOBIN_DIR" go install "google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION"
fi

cd "$ROOT"
protos=(proto/morphgate/v1/*.proto)

generate() {
  local out="$1"
  "$PROTOC" -I proto \
    --plugin=protoc-gen-go="$PLUGIN" \
    --go_out="$out" --go_opt=module="$MODULE" \
    "${protos[@]}"
}

if [[ "$mode" == "write" ]]; then
  rm -f control-plane/gen/morphgate/v1/*.pb.go
  generate control-plane
  echo "gen-proto: wrote $(ls control-plane/gen/morphgate/v1/*.pb.go | wc -l | tr -d ' ') files to control-plane/gen/morphgate/v1" >&2
else
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  generate "$tmp"
  # The header records the protoc version; compare everything else so a
  # different local protoc patch release does not count as drift.
  strip() { grep -v '^//[[:space:]]*protoc[[:space:]]' "$1"; }
  drift=0
  for f in "$tmp"/gen/morphgate/v1/*.pb.go; do
    committed="control-plane/gen/morphgate/v1/$(basename "$f")"
    if [[ ! -f "$committed" ]] || ! diff -q <(strip "$f") <(strip "$committed") >/dev/null; then
      echo "gen-proto: $committed is out of date" >&2
      drift=1
    fi
  done
  for f in control-plane/gen/morphgate/v1/*.pb.go; do
    [[ -f "$tmp/gen/morphgate/v1/$(basename "$f")" ]] || { echo "gen-proto: stale file $f" >&2; drift=1; }
  done
  [[ "$drift" == 0 ]] || die "generated code is out of date; run scripts/gen-proto.sh"
  echo "gen-proto: generated code is up to date" >&2
fi
