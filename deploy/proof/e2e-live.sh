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
# extra overlay(s), space-separated, appended in order. e.g.
# EXTRA_COMPOSE=compose.cloud.yaml proves the loop against the guarded CLOUD model
# instead of the sovereign local one (no local weight download needed).
if [ -n "${EXTRA_COMPOSE:-}" ]; then for f in $EXTRA_COMPOSE; do COMPOSE+=(-f "$HERE/../$f"); done; fi
ENRICH_TIMEOUT="${ENRICH_TIMEOUT:-360}" # a CPU model + full roster can take minutes

say()  { echo "== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"; }
submit()        { curl -fsS -F "file=@$1" "$BASE/v1/submissions" | jget submission_id; }
get()           { curl -fsS "$BASE/v1/submissions/$1"; }
# bytes in the persistent L0 store on its volume (0 if absent). the orchestrator
# image is scratch (no shell), so peek at the volume through a throwaway helper.
db_bytes()      { docker run --rm -v openmallab-knowledge:/k debian:12 sh -c 'wc -c < /k/l0.db 2>/dev/null || echo 0' | tr -cd '0-9'; }
await_verdict() { for i in $(seq 1 120); do b=$(get "$1"); [ -n "$(echo "$b" | jget verdict)" ] && { echo "$b"; return 0; }; sleep 1; done; fail "submission $1 never got a verdict"; }

say "bringing up the full live stack (deterministic + AI plane overlay)"
MAL_PIP_CONF="${MAL_PIP_CONF:-/dev/null}" docker compose "${COMPOSE[@]}" up -d

if [ "${KEEP_UP:-0}" != "1" ]; then
  trap 'docker compose "${COMPOSE[@]}" stop gateway orchestrator mal-agents >/dev/null 2>&1 || true' EXIT
fi

say "waiting for the gateway"
for i in $(seq 1 90); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; [ "$i" = 90 ] && fail "gateway never came up"; sleep 1; done

# on the sovereign path mal-agents depends_on ollama:service_healthy (healthy only
# once the MODEL is present), so reaching healthy proves the model is provisioned; on
# the cloud path it just means the roster service itself is up and answering.
say "waiting for the roster to report healthy"
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

# Await enrichment, resolving the HITL review inline if the gate escalates. An
# escalated submission NEVER reaches enriched=true until its review is answered, so
# polling enriched alone would hang - we watch for needs_review and approve it, then
# the child finishes and enriched flips. (needs_review is surfaced WHILE the child
# waits by the gateway; a non-escalated submission just flips enriched on its own.)
say "awaiting ASYNC AI enrichment; resolving the HITL review inline if the gate escalates"
RESOLVED=0
for i in $(seq 1 "$ENRICH_TIMEOUT"); do
  BODY=$(get "$ID")
  [ "$(echo "$BODY" | jget enriched)" = "True" ] && break
  if [ "$RESOLVED" = 0 ] && [ "$(echo "$BODY" | jget needs_review)" = "True" ]; then
    RV=$(curl -fsS "$BASE/v1/submissions/$ID/review")
    if [ "$(echo "$RV" | jget pending)" = "True" ]; then
      say "HITL: gate escalated, a review is pending - approving it through the gateway"
      DEC=$(curl -fsS -X POST "$BASE/v1/submissions/$ID/review" -H 'content-type: application/json' -d '{"approved":true,"note":"e2e-live approve"}')
      [ "$(echo "$DEC" | jget recorded)" = "True" ] || fail "review decision not recorded: $DEC"
      RESOLVED=1
      say "HITL review approved + recorded; awaiting the enrichment child to finish"
    fi
  fi
  sleep 1
done
[ "$(echo "$BODY" | jget enriched)" = "True" ] || fail "AI enrichment never completed for $ID within ${ENRICH_TIMEOUT}s (needs_review=$(echo "$BODY" | jget needs_review) resolved=$RESOLVED)"

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

# HITL round-trip verification. If the gate escalated we already approved the review
# inline (above); assert it now reports NOT pending - the enrichment child has closed,
# so a query on it must no longer replay a stale pending request (regression guard for
# the gateway gating "pending" on the child actually being RUNNING).
if [ "$RESOLVED" = 1 ]; then
  say "HITL round-trip: review was queried, approved, recorded, and the child finished"
  RV=$(curl -fsS "$BASE/v1/submissions/$ID/review")
  [ "$(echo "$RV" | jget pending)" = "False" ] || fail "review STILL pending after resolution + completion (stale-query regression): $RV"
  say "post-resolution /review correctly reports pending=false."
else
  say "no human review required for this submission (the gate did not escalate)."
fi

# Curation-survives-restart is the PERSISTENT-STORE acceptance (task T3). With the
# embedded BoltDB store wired (MAL_KNOWLEDGE_DB on the openmallab-knowledge volume),
# the curated L0 outlives the process: assert the store file is present and non-empty
# (the seed + any curation landed durably), restart the orchestrator, and assert it is
# still there and no smaller. asserted only when MAL_ASSERT_PERSIST=1.
if [ "${MAL_ASSERT_PERSIST:-0}" = "1" ]; then
  say "PERSISTENCE: asserting the curated L0 store survives an orchestrator restart"
  before=$(db_bytes)
  [ "${before:-0}" -gt 0 ] 2>/dev/null || fail "L0 store /knowledge/l0.db missing or empty BEFORE restart (${before:-0} bytes) - is MAL_KNOWLEDGE_DB wired + the volume mounted?"
  say "  L0 store before restart: ${before} bytes on the openmallab-knowledge volume"
  docker compose "${COMPOSE[@]}" restart orchestrator >/dev/null
  for i in $(seq 1 60); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; [ "$i" = 60 ] && fail "gateway did not recover after orchestrator restart"; sleep 1; done
  after=$(db_bytes)
  [ "${after:-0}" -ge "${before:-0}" ] 2>/dev/null || fail "L0 store shrank or vanished across restart (before=${before} after=${after}) - curation did NOT persist"
  say "  L0 store after restart: ${after} bytes (>= before) - curated knowledge survived."
fi

echo ""
echo "E2E-LIVE PROOF PASSED"
echo "  $ID -> deterministic=$DET_VERDICT, AI enrichment completed + contained, HITL relay verified."
