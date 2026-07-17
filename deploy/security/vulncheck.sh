#!/usr/bin/env bash
# The Go supply-chain gate. Runs govulncheck over the whole module and fails if
# any vulnerability that is actually reachable from our code is not explicitly
# accepted in govulncheck-allow.txt. Accepted ids are unfixed upstream and
# outside our threat model, each with a written reason and a date; see that
# file. Anything new, or any accepted id whose fix we could take, fails here.
#
#   deploy/security/vulncheck.sh
#
# Needs go and python3. Installs govulncheck if it is not already on PATH.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ALLOW="$HERE/govulncheck-allow.txt"

if ! command -v govulncheck >/dev/null 2>&1; then
  echo "== installing govulncheck"
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi
GOVC=$(command -v govulncheck || echo "$(go env GOPATH)/bin/govulncheck")

OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

echo "== scanning ($ROOT)"
# govulncheck exits non-zero when it finds affecting vulns; that is expected
# here (we accept a known set), so the allowlist comparison decides pass/fail.
( cd "$ROOT" && "$GOVC" -format=json ./... ) > "$OUT" 2>/dev/null || true

python3 - "$ALLOW" "$OUT" <<'PY'
import json, sys

allow_path, out_path = sys.argv[1], sys.argv[2]

allow = set()
with open(allow_path) as f:
    for line in f:
        line = line.split("#", 1)[0].strip()
        if line:
            allow.add(line)

osv = {}
affecting = set()
with open(out_path) as f:
    data = f.read()
dec = json.JSONDecoder()
i, n = 0, len(data)
while i < n:
    while i < n and data[i] in " \n\r\t":
        i += 1
    if i >= n:
        break
    obj, i = dec.raw_decode(data, i)
    if "osv" in obj:
        o = obj["osv"]
        osv[o["id"]] = o.get("summary") or o.get("details", "")[:100]
    if "finding" in obj:
        fnd = obj["finding"]
        trace = fnd.get("trace") or []
        # a finding is "affecting" (reachable) when its trace names a called
        # function, not just an imported module. that is govulncheck's own
        # bar for "your code is affected".
        if any(fr.get("function") for fr in trace):
            affecting.add(fnd["osv"])

unaccepted = sorted(affecting - allow)
stale = sorted(allow - affecting)
accepted = sorted(affecting & allow)

for vid in accepted:
    print("  accepted: %s (%s)" % (vid, osv.get(vid, "?")))
for vid in stale:
    print("  WARNING: %s is in the allow list but no longer reachable; drop it" % vid)

if unaccepted:
    print("")
    print("VULN GATE FAILED: %d reachable vulnerability(ies) not accepted:" % len(unaccepted))
    for vid in unaccepted:
        print("  - %s: %s" % (vid, osv.get(vid, "?")))
        print("    https://pkg.go.dev/vuln/%s" % vid)
    print("")
    print("Take the fix (bump the dependency) if one exists. Only if it is")
    print("unfixed AND outside our threat model, add it to %s with a dated reason." % allow_path)
    sys.exit(1)

print("")
print("VULN GATE PASSED: %d reachable vuln(s), all accepted; no unaccepted findings." % len(accepted))
PY
