#!/usr/bin/env bash
# LIVE proof of mal-static-die (Detect It Easy: the packed/compiler/crypto engine
# and the packed/unanalyzed gate). It builds the base engines plus the DIE image,
# turns DIE on (MAL_DIE_IMAGE), submits a benign ELF, and asserts DIE actually ran
# (a mal-static-die finding came back) and stayed CONTAINED (DIE alone never drives
# the verdict above SUSPICIOUS).
#
# RUN THIS ON A CLEAN NETWORK (or your personal laptop). Building the DIE image
# fetches Detect It Easy from its GitHub release; a corporate proxy that firewalls
# the BuildKit sandbox cannot do that. The DIE image is intentionally kept out of
# the default `build` profile for exactly this reason, so it is built here with an
# explicit `--profile build-die`. See docs/DIE-HANDOFF.md (pin the release first).
#
# Needs docker compose, curl, python3.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BASE="${BASE:-http://localhost:8080}"
COMPOSE=(-f "$HERE/../compose.yaml")
# turn the engine on for this run (the compose default is empty = off).
export MAL_DIE_IMAGE="${MAL_DIE_IMAGE:-openmallab/mal-static-die:m0}"

say()  { echo "== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"; }

say "building the base engine images (ident/yara/extract/capa/broker the ELF flows through)"
MAL_PIP_CONF="${MAL_PIP_CONF:-/dev/null}" docker compose "${COMPOSE[@]}" --profile build build
say "building the DIE image (separate profile: it fetches Detect It Easy from a release)"
MAL_PIP_CONF="${MAL_PIP_CONF:-/dev/null}" docker compose "${COMPOSE[@]}" --profile build-die build

say "bringing up the stack with DIE enabled (MAL_DIE_IMAGE=$MAL_DIE_IMAGE)"
docker compose "${COMPOSE[@]}" up -d
if [ "${KEEP_UP:-0}" != "1" ]; then
  trap 'docker compose "${COMPOSE[@]}" stop gateway orchestrator >/dev/null 2>&1 || true' EXIT
fi
say "waiting for the gateway"
for i in $(seq 1 90); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; [ "$i" = 90 ] && fail "gateway never came up"; sleep 1; done

# a benign dynamically-linked x86-64 ELF from a stock image (nothing committed).
# DIE identifies its compiler/linker (UNKNOWN provenance). To exercise the packed
# gate instead, `upx -9` this before submitting and expect SUSPICIOUS + a
# packed-unanalyzed finding + incomplete.
say "staging a benign x86-64 ELF"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' RETURN 2>/dev/null || true
cid=$(docker create --platform linux/amd64 debian:12 2>/dev/null); docker cp "$cid:/bin/echo" "$TMP/sample" >/dev/null 2>&1; docker rm "$cid" >/dev/null 2>&1
[ -s "$TMP/sample" ] || fail "could not stage the sample"

say "submitting the ELF (DIE runs automatically on executables when enabled)"
ID=$(curl -fsS -F "file=@$TMP/sample" "$BASE/v1/submissions" | jget submission_id)
[ -n "$ID" ] || fail "no submission id"

say "awaiting the verdict + the mal-static-die finding ($ID)"
BODY=""
for i in $(seq 1 "${DIE_TIMEOUT:-180}"); do
  BODY=$(curl -fsS "$BASE/v1/submissions/$ID" 2>/dev/null || echo '{}')
  if [ -n "$(echo "$BODY" | jget verdict)" ] && echo "$BODY" | python3 -c 'import json,sys; sys.exit(0 if any(f.get("engine")=="mal-static-die" for f in json.load(sys.stdin).get("findings",[])) else 1)' 2>/dev/null; then
    break
  fi
  sleep 1
done

say "asserting DIE ran AND stayed contained"
echo "$BODY" | python3 -c '
import json, sys
d = json.load(sys.stdin)
rank = {"BENIGN":0,"UNKNOWN":1,"SUSPICIOUS":2,"MALICIOUS":3}
die = [f for f in d.get("findings", []) if f.get("engine") == "mal-static-die"]
assert die, "no mal-static-die findings: DIE did not run (image built with --profile build-die? MAL_DIE_IMAGE set?)"
assert any(f["type"] == "die-summary" for f in die), "no die-summary: DIE produced no report"
# DIE is evidence, not authority: nothing it emits may exceed SUSPICIOUS.
for f in die:
    assert rank.get(f["verdict"], 0) <= rank["SUSPICIOUS"], "DIE finding exceeded SUSPICIOUS: %s" % f
# and DIE alone must never drive the rolled-up verdict above SUSPICIOUS.
other = [f for f in d["findings"] if f["engine"] != "mal-static-die"]
other_max = max([rank.get(f["verdict"],0) for f in other] + [0])
assert rank.get(d["verdict"],0) <= max(other_max, rank["SUSPICIOUS"]), "verdict inflated past the DIE cap: %s" % d["verdict"]
print("  DIE ran: %d mal-static-die finding(s), all <= SUSPICIOUS; rolled-up verdict=%s" % (len(die), d["verdict"]))
' || fail "DIE ran but a containment assertion failed: $BODY"

echo ""
echo "DIE PROOF PASSED"
echo "  $ID -> Detect It Easy ran under the jail, reported provenance, and stayed contained."
echo "  Packed-gate check: upx -9 a benign binary and resubmit; expect SUSPICIOUS + packed-unanalyzed + incomplete."
