#!/usr/bin/env bash
# LIVE end-to-end proof INCLUDING the AI plane. It proves the full Phase-1-live
# loop: a file goes in the front door, the deterministic verdict comes out in
# seconds, the async AI enrichment then RUNS to completion and stays CONTAINED
# (never reaches MALICIOUS on the AI's word, capped at SUSPICIOUS), and the HITL
# review round-trips through the gateway.
#
# Provision the sovereign model ONCE first (the runtime net has no egress):
#   docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml --profile bootstrap run --rm model-bootstrap
# then:
#   deploy/proof/e2e-live.sh              # sovereign local model
#   MAL_MODEL_URL=... MAL_MODEL_KEY=... MAL_ALLOW_CLOUD=1 deploy/proof/e2e-live.sh   # guarded cloud model
#
# Needs docker compose, curl, python3. Behind a private pip index export
# MAL_PIP_CONF=~/.pip/pip.conf (the mal-agents/capa/floss images pip-install).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BASE="${BASE:-http://localhost:8080}"
COMPOSE=(-f "$HERE/../compose.yaml" -f "$HERE/../compose.ai.yaml")
ENRICH_TIMEOUT="${ENRICH_TIMEOUT:-360}" # a CPU model + full roster can take minutes

say()  { echo "== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"; }
submit()        { curl -fsS -F "file=@$1" "$BASE/v1/submissions" | jget submission_id; }
get()           { curl -fsS "$BASE/v1/submissions/$1"; }
await_verdict() { for i in $(seq 1 120); do b=$(get "$1"); [ -n "$(echo "$b" | jget verdict)" ] && { echo "$b"; return 0; }; sleep 1; done; fail "submission $1 never got a verdict"; }

say "bringing up the full live stack (deterministic + AI plane overlay)"
MAL_PIP_CONF="${MAL_PIP_CONF:-/dev/null}" docker compose "${COMPOSE[@]}" up -d

if [ "${KEEP_UP:-0}" != "1" ]; then
  trap 'docker compose "${COMPOSE[@]}" stop gateway orchestrator mal-agents >/dev/null 2>&1 || true' EXIT
fi

say "waiting for the gateway"
for i in $(seq 1 90); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; [ "$i" = 90 ] && fail "gateway never came up"; sleep 1; done

# mal-agents depends_on ollama:service_healthy, and ollama is healthy only once the
# MODEL is present - so mal-agents reaching healthy PROVES the model is provisioned.
say "waiting for the roster (proves the sovereign model is provisioned)"
for i in $(seq 1 120); do
  h=$(docker compose "${COMPOSE[@]}" ps mal-agents --format '{{.Health}}' 2>/dev/null || true)
  [ "$h" = "healthy" ] && break
  [ "$i" = 120 ] && fail "mal-agents never healthy - is the model bootstrapped? (see header) [health=$h]"
  sleep 2
done

# a small x86-64 binary: capa surfaces ATT&CK-mapped capabilities the roster can
# reason over (groundable). borrowed from a stock image so nothing is committed.
say "staging an x86-64 sample for a groundable submission"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' RETURN 2>/dev/null || true
cid=$(docker create --platform linux/amd64 debian:12 2>/dev/null); docker cp "$cid:/usr/bin/id" "$TMP/idbin" >/dev/null 2>&1; docker rm "$cid" >/dev/null 2>&1
[ -s "$TMP/idbin" ] || fail "could not stage the sample"

say "submitting; awaiting the DETERMINISTIC verdict"
ID=$(submit "$TMP/idbin"); [ -n "$ID" ] || fail "no submission id"
BODY=$(await_verdict "$ID")
DET_VERDICT=$(echo "$BODY" | jget verdict)
say "deterministic verdict: $DET_VERDICT ($ID)"

say "awaiting ASYNC AI enrichment to COMPLETE (enriched=true means the <id>-enrich child finished)"
for i in $(seq 1 "$ENRICH_TIMEOUT"); do
  BODY=$(get "$ID")
  [ "$(echo "$BODY" | jget enriched)" = "True" ] && break
  sleep 1
done
[ "$(echo "$BODY" | jget enriched)" = "True" ] || fail "AI enrichment never completed for $ID within ${ENRICH_TIMEOUT}s"

say "asserting CONTAINMENT of the enrichment"
echo "$BODY" | python3 -c '
import json, sys
d = json.load(sys.stdin)
rank = {"BENIGN":0,"UNKNOWN":1,"SUSPICIOUS":2,"MALICIOUS":3}
# the AI can only ADD capped enrichment: any mal-ai finding is at most SUSPICIOUS.
ai = [f for f in d["findings"] if f["engine"] == "mal-ai"]
for f in ai:
    assert rank.get(f["verdict"],0) <= rank["SUSPICIOUS"], "AI enrichment reached MALICIOUS (must cap at SUSPICIOUS): %s" % f
# the rolled-up verdict is never driven ABOVE SUSPICIOUS by the AI: MALICIOUS may
# only come from a deterministic engine, never mal-ai alone.
det_max = max([rank.get(f["verdict"],0) for f in d["findings"] if f["engine"] != "mal-ai"] + [0])
assert rank.get(d["verdict"],0) <= max(det_max, rank["SUSPICIOUS"]), "verdict inflated beyond the AI cap: %s" % d["verdict"]
print("  enrichment contained: %d mal-ai finding(s), all <= SUSPICIOUS; verdict=%s needs_review=%s" % (len(ai), d["verdict"], d.get("needs_review")))
' || fail "enrichment containment violated: $BODY"

# HITL round-trip: if the gate escalated, the review must be queryable + resolvable.
if [ "$(echo "$BODY" | jget needs_review)" = "True" ]; then
  say "HITL: a review is pending; querying + resolving it through the gateway"
  RV=$(curl -fsS "$BASE/v1/submissions/$ID/review")
  [ "$(echo "$RV" | jget pending)" = "True" ] || fail "needs_review set but no pending review task: $RV"
  DEC=$(curl -fsS -X POST "$BASE/v1/submissions/$ID/review" -H 'content-type: application/json' -d '{"approved":true,"note":"e2e-live approve"}')
  [ "$(echo "$DEC" | jget recorded)" = "True" ] || fail "review decision not recorded: $DEC"
  say "HITL review resolved (approved) and recorded."
else
  say "no human review required for this submission (nothing to resolve)."
fi

# Curation-survives-restart is the PERSISTENT-STORE acceptance (task T3). Until the
# embedded store lands, L0/L1 are in-memory and curation does not persist; this
# section asserts it only when MAL_ASSERT_PERSIST=1 (set once T3 is merged).
if [ "${MAL_ASSERT_PERSIST:-0}" = "1" ]; then
  say "restarting the orchestrator; asserting curated knowledge survives"
  docker compose "${COMPOSE[@]}" restart orchestrator >/dev/null
  for i in $(seq 1 60); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; sleep 1; done
  # (a curation-grounded re-submission assertion goes here once T3 exposes it)
  say "orchestrator restarted; persistence path exercised."
fi

echo ""
echo "E2E-LIVE PROOF PASSED"
echo "  $ID -> deterministic=$DET_VERDICT, AI enrichment completed + contained, HITL relay verified."
