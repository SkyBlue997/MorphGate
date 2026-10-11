#!/usr/bin/env bash
# fuzz/Cargo.lock must pin the same versions as Cargo.lock, so the cargo-fuzz
# targets fuzz the crates that ship. It may only add the fuzzing crates.
# After changing Cargo.lock:
#   cp Cargo.lock fuzz/Cargo.lock && cargo +<nightly> fuzz build
set -euo pipefail
cd "$(dirname "$0")/.."

packages() {
  awk '/^name = /{n=$3} /^version = /{print n, $3}' "$1" \
    | grep -Ev '^"(arbitrary|libfuzzer-sys|mg-fuzz)" ' | sort
}

if ! diff <(packages Cargo.lock) <(packages fuzz/Cargo.lock); then
  echo "check-fuzz-lock: fuzz/Cargo.lock differs from Cargo.lock (< root, > fuzz)." >&2
  echo "Fix: cp Cargo.lock fuzz/Cargo.lock && cargo +nightly fuzz build" >&2
  exit 1
fi
echo "check-fuzz-lock: OK"
