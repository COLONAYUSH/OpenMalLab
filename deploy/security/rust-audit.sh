#!/usr/bin/env bash
# The Rust supply-chain gate. Runs cargo-audit over the locked workspace tree
# and fails on any RustSec advisory that is not explicitly accepted in
# cargo-audit-allow.txt. Accepted ids are unfixed upstream and outside our
# threat model, each with a written reason and a date; see that file. Anything
# new fails here. Sibling of the Go gate in vulncheck.sh.
#
#   deploy/security/rust-audit.sh
#
# Needs cargo. Installs cargo-audit if it is not already available.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ALLOW="$HERE/cargo-audit-allow.txt"

if ! command -v cargo-audit >/dev/null 2>&1 && ! cargo audit --version >/dev/null 2>&1; then
  echo "== installing cargo-audit"
  cargo install cargo-audit --locked
fi

# Build the --ignore list from the accepted advisories (RustSec ids carry no
# spaces, so the first token per non-comment line is the id).
IGNORE=()
while IFS= read -r raw || [ -n "$raw" ]; do
  id="${raw%%#*}"
  read -r id <<< "$id" || true
  [ -n "$id" ] && IGNORE+=(--ignore "$id")
done < "$ALLOW"

echo "== auditing ($ROOT), accepting ${#IGNORE[@]} advisory(ies)"
cd "$ROOT"
# cargo-audit exits non-zero on any un-ignored vulnerability; that is the gate.
cargo audit ${IGNORE[@]+"${IGNORE[@]}"}
echo "RUST VULN GATE PASSED: no un-accepted advisories."
