#!/usr/bin/env bash
# End-to-end proof: eicar in at the front door, MALICIOUS out of the api,
# with the scan running inside the jailed worker and the verdict crossing
# the broker. Also proves the honest negative: a benign file rolls up
# UNKNOWN in M0 (no engine has earned the right to say BENIGN yet), with
# incomplete=false.
#
#   deploy/proof/e2e.sh          # builds images, starts the stack, proves it
#   KEEP_UP=1 deploy/proof/e2e.sh  # leave the stack running afterwards
#
# Needs docker compose, curl, python3.

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
COMPOSE="$HERE/../compose.yaml"
BASE="${BASE:-http://localhost:8080}"

say()  { echo "== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

say "building images (stack + jailed images behind the build profile)"
docker compose -f "$COMPOSE" --profile build build
say "starting the stack"
docker compose -f "$COMPOSE" up -d

if [ "${KEEP_UP:-0}" != "1" ]; then
  trap 'docker compose -f "$COMPOSE" stop gateway orchestrator >/dev/null 2>&1 || true' EXIT
fi

say "waiting for the gateway"
for i in $(seq 1 90); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then break; fi
  [ "$i" = "90" ] && fail "gateway never came up"
  sleep 1
done

# json field extraction without jq: python3 is everywhere we run this.
jget() { # key, json on stdin
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"
}

submit() { # path -> submission id
  curl -fsS -F "file=@$1" "$BASE/v1/submissions" | jget submission_id
}

await_verdict() { # id -> final json
  for i in $(seq 1 120); do
    local body
    body=$(curl -fsS "$BASE/v1/submissions/$1")
    if [ -n "$(echo "$body" | jget verdict)" ]; then
      echo "$body"
      return 0
    fi
    sleep 1
  done
  fail "submission $1 never finished"
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; if [ "${KEEP_UP:-0}" != "1" ]; then docker compose -f "$COMPOSE" stop gateway orchestrator >/dev/null 2>&1 || true; fi' EXIT

# the canonical eicar test string, assembled from halves at runtime so the
# contiguous signature never sits in this file.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar.com"
printf 'a plain text file with nothing interesting in it\n' > "$TMP/benign.txt"

say "submitting eicar"
ID=$(submit "$TMP/eicar.com")
[ -n "$ID" ] || fail "no submission id"
say "submission $ID accepted, waiting for the verdict"
BODY=$(await_verdict "$ID")

VERDICT=$(echo "$BODY" | jget verdict)
INCOMPLETE=$(echo "$BODY" | jget incomplete)
[ "$VERDICT" = "MALICIOUS" ] || fail "eicar verdict $VERDICT, want MALICIOUS: $BODY"
[ "$INCOMPLETE" = "False" ] || fail "eicar incomplete=$INCOMPLETE, want false: $BODY"
echo "$BODY" | python3 -c '
import json, sys
d = json.load(sys.stdin)
f = [x for x in d["findings"] if x["engine"] == "mal-static-yara" and x["detail"] == "eicar_test_file"]
assert f, "no mal-static-yara eicar finding: %s" % d["findings"]
assert f[0]["verdict"] == "MALICIOUS", f
assert f[0]["attck"] == "T1204", f
' || fail "eicar findings wrong: $BODY"
say "eicar -> MALICIOUS with the mal-static-yara finding. the jail spoke, the broker validated."

say "submitting a benign file"
ID2=$(submit "$TMP/benign.txt")
BODY2=$(await_verdict "$ID2")
V2=$(echo "$BODY2" | jget verdict)
I2=$(echo "$BODY2" | jget incomplete)
[ "$V2" = "UNKNOWN" ] || fail "benign verdict $V2, want UNKNOWN (honest: no engine earns BENIGN yet): $BODY2"
[ "$I2" = "False" ] || fail "benign incomplete=$I2, want false: $BODY2"
say "benign -> UNKNOWN, complete. nothing is benign by omission."

echo ""
echo "E2E PROOF PASSED"
echo "  eicar:  $ID -> MALICIOUS (mal-static-yara: eicar_test_file, T1204)"
echo "  benign: $ID2 -> UNKNOWN"
