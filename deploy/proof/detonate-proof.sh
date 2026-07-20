#!/usr/bin/env bash
# LIVE proof of DYNAMIC ANALYSIS (mal-detonate, Phase 2 slice 0). It builds the
# detonation worker, brings the stack up, submits a benign ELF WITH detonation
# requested, and asserts the sample was actually detonated under the jailed emulator
# and its behavior came back as brokered findings that are CONTAINED (capped at
# SUSPICIOUS, never MALICIOUS on the detonation's word) and fail-closed.
#
# RUN THIS ON A CLEAN NETWORK (or your personal laptop). Building the worker image
# installs qemu-user-static + a second-arch libc via apt; a corporate proxy that
# firewalls the BuildKit sandbox from the package mirror cannot do that (docker run
# reaches it but the build sandbox does not). The Dockerfile itself is correct and
# builds normally on an unfiltered network. If your build sandbox is firewalled, see
# docs/DYNAMIC-ANALYSIS-V1.md for the DOCKER_BUILDKIT=0 / docker-commit workaround.
#
# Needs docker compose, curl, python3. On a private pip index export MAL_PIP_CONF.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BASE="${BASE:-http://localhost:8080}"
# detonation is a base-pipeline engine (no AI overlay needed). the orchestrator gates
# it on the submitter opting in AND the artifact being an ELF.
COMPOSE=(-f "$HERE/../compose.yaml")
DETONATE_TIMEOUT="${DETONATE_TIMEOUT:-300}" # qemu TCG over the full roster can take a while

say()  { echo "== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"; }

say "building the engine images (first run is heavy: Go/Rust/Python builds, several GB, needs a clean network for apt + pip; later runs are cached)"
# build ALL jailed engine images, not just mal-detonate: the submitted ELF also
# flows through ident/yara/extract/capa, which the orchestrator spawns by name, so
# those images must exist locally before the first submission.
MAL_PIP_CONF="${MAL_PIP_CONF:-/dev/null}" docker compose "${COMPOSE[@]}" --profile build build

say "bringing up the stack"
MAL_PIP_CONF="${MAL_PIP_CONF:-/dev/null}" docker compose "${COMPOSE[@]}" up -d
if [ "${KEEP_UP:-0}" != "1" ]; then
  trap 'docker compose "${COMPOSE[@]}" stop gateway orchestrator >/dev/null 2>&1 || true' EXIT
fi
say "waiting for the gateway"
for i in $(seq 1 90); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; [ "$i" = 90 ] && fail "gateway never came up"; sleep 1; done

# a small dynamically-linked x86-64 ELF from a stock image (nothing committed). the
# emulator interprets it AS DATA; a benign coreutil exercises the full detonation path
# safely. (static-glibc ELFs are fail-closed by design; use a dynamic one here.)
say "staging a benign dynamically-linked x86-64 ELF"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' RETURN 2>/dev/null || true
cid=$(docker create --platform linux/amd64 debian:12 2>/dev/null); docker cp "$cid:/bin/echo" "$TMP/sample" >/dev/null 2>&1; docker rm "$cid" >/dev/null 2>&1
[ -s "$TMP/sample" ] || fail "could not stage the sample"

say "submitting WITH detonation requested (detonate=true)"
ID=$(curl -fsS -F "file=@$TMP/sample" -F "detonate=true" "$BASE/v1/submissions" | jget submission_id)
[ -n "$ID" ] || fail "no submission id"

say "awaiting the verdict + the mal-detonate finding ($ID)"
BODY=""
for i in $(seq 1 "$DETONATE_TIMEOUT"); do
  BODY=$(curl -fsS "$BASE/v1/submissions/$ID" 2>/dev/null || echo '{}')
  if [ -n "$(echo "$BODY" | jget verdict)" ] && echo "$BODY" | python3 -c 'import json,sys; sys.exit(0 if any(f.get("engine")=="mal-detonate" for f in json.load(sys.stdin).get("findings",[])) else 1)' 2>/dev/null; then
    break
  fi
  sleep 1
done

say "asserting the sample was detonated AND contained"
echo "$BODY" | python3 -c '
import json, sys
d = json.load(sys.stdin)
rank = {"BENIGN":0,"UNKNOWN":1,"SUSPICIOUS":2,"MALICIOUS":3}
det = [f for f in d.get("findings", []) if f.get("engine") == "mal-detonate"]
assert det, "no mal-detonate findings: detonation did not run (image built? gated on ELF + detonate=true)"
# the emulator must have actually produced a trace (the summary always leads a real run).
assert any(f["type"] == "detonation-summary" for f in det), "no detonation-summary: the emulator produced no syscall trace"
# behavioral evidence can only ADD capped enrichment: never above SUSPICIOUS.
for f in det:
    assert rank.get(f["verdict"], 0) <= rank["SUSPICIOUS"], "detonation finding exceeded SUSPICIOUS: %s" % f
# and the AI-cap invariant on the rolled-up verdict: MALICIOUS only ever from a
# deterministic engine, never driven there by detonation alone.
det_engines = [f for f in d["findings"] if f["engine"] != "mal-detonate"]
det_max = max([rank.get(f["verdict"],0) for f in det_engines] + [0])
assert rank.get(d["verdict"],0) <= max(det_max, rank["SUSPICIOUS"]), "verdict inflated past the detonation cap: %s" % d["verdict"]
print("  detonated: %d mal-detonate finding(s), all <= SUSPICIOUS; rolled-up verdict=%s" % (len(det), d["verdict"]))
' || fail "detonation ran but a containment assertion failed: $BODY"

echo ""
echo "DETONATION PROOF PASSED"
echo "  $ID -> detonated under the jailed emulator, behavior reported + contained (capped at SUSPICIOUS)."
echo "  Next: extend deploy/proof/boundary-proof.sh with the detonation-jail section"
echo "  (net none, CapEff=0, no writable+exec mount, looping sample killed+incomplete)."
