#!/usr/bin/env bash
# The Go supply-chain gate. Runs govulncheck over the whole module and fails if
# any vulnerability reachable from our code is not explicitly accepted in
# govulncheck-allow.txt. Accepted ids are unfixed upstream and outside our
# threat model, each with a written reason and a date; see that file.
#
# Fails CLOSED: if govulncheck cannot run (air-gapped, crash, missing binary)
# it produces no findings, and a gate that read that as "0 vulns, pass" would
# be worse than no gate. So we require proof it actually scanned (its json
# always opens with a `config` message) and check its exit code; no evidence of
# a real scan is a failure, not a pass.
#
#   deploy/security/vulncheck.sh            # scan and gate
#   deploy/security/vulncheck.sh --selftest # test the gate's own logic
#
# Needs go and python3. Installs govulncheck if it is not already on PATH.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ALLOW="$HERE/govulncheck-allow.txt"

# decide(allow_file, json_file): parse a govulncheck json stream and exit
# 0 = pass, 1 = an unaccepted reachable vuln, 2 = no evidence the scan ran.
decide() {
	python3 - "$1" "$2" <<'PY'
import json, sys

allow_path, out_path = sys.argv[1], sys.argv[2]

allow = set()
with open(allow_path) as f:
    for line in f:
        line = line.split("#", 1)[0].strip()
        if line:
            allow.add(line)

osv, affecting = {}, set()
saw_config = False
objects = 0
with open(out_path) as f:
    data = f.read()
dec = json.JSONDecoder()
i, n = 0, len(data)
try:
    while i < n:
        while i < n and data[i] in " \n\r\t":
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(data, i)
        objects += 1
        if "config" in obj:
            saw_config = True
        if "osv" in obj:
            o = obj["osv"]
            osv[o["id"]] = o.get("summary") or o.get("details", "")[:100]
        if "finding" in obj:
            fnd = obj["finding"]
            trace = fnd.get("trace") or []
            if any(fr.get("function") for fr in trace):
                affecting.add(fnd["osv"])
except (ValueError, KeyError) as e:
    print("VULN GATE FAILED: could not parse govulncheck output (%s)" % e)
    sys.exit(2)

# fail closed: govulncheck always emits a config message first. no config (or
# no objects at all) means it never really scanned -> not a pass.
if not saw_config or objects == 0:
    print("VULN GATE FAILED: no evidence govulncheck actually scanned "
          "(%d objects, config=%s). failing closed." % (objects, saw_config))
    sys.exit(2)

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
    print("unfixed AND outside our threat model, add it to the allow file with a dated reason.")
    sys.exit(1)

print("VULN GATE PASSED: %d reachable vuln(s), all accepted; no unaccepted findings." % len(accepted))
PY
}

# selftest exercises the decision logic on fixtures, including the fail-closed
# path, so the gate itself cannot silently rot.
if [ "${1:-}" = "--selftest" ]; then
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	printf 'GO-0001\n# a comment\n' > "$tmp/allow.txt"
	cfg='{"config":{"protocol_version":"v1.0.0"}}'
	osv='{"osv":{"id":"GO-0001","summary":"accepted vuln"}}'
	osv2='{"osv":{"id":"GO-0002","summary":"new vuln"}}'
	reach='{"finding":{"osv":"GO-0001","trace":[{"function":"F","package":"p"}]}}'
	reach2='{"finding":{"osv":"GO-0002","trace":[{"function":"G","package":"p"}]}}'
	imp='{"finding":{"osv":"GO-0002","trace":[{"package":"p"}]}}'

	check() { # want_rc, label, json
		printf '%s' "$3" > "$tmp/out.json"
		set +e; decide "$tmp/allow.txt" "$tmp/out.json" >/dev/null 2>&1; local rc=$?; set -e
		if [ "$rc" != "$1" ]; then echo "SELFTEST FAIL: $2 -> rc=$rc want $1"; exit 1; fi
		echo "  ok: $2 (rc=$1)"
	}
	check 0 "config + accepted reachable vuln"        "$cfg$osv$reach"
	check 1 "config + unaccepted reachable vuln"      "$cfg$osv2$reach2"
	check 0 "config + unaccepted but only imported"   "$cfg$osv2$imp"
	check 0 "config, no findings"                     "$cfg"
	check 2 "empty output (scanner did not run)"      ""
	check 2 "findings but no config framing"          "$osv2$reach2"
	echo "vulncheck selftest ok"
	exit 0
fi

if ! command -v govulncheck >/dev/null 2>&1; then
	echo "== installing govulncheck"
	go install golang.org/x/vuln/cmd/govulncheck@latest
fi
GOVC=$(command -v govulncheck || echo "$(go env GOPATH)/bin/govulncheck")

OUT=$(mktemp)
ERR=$(mktemp)
trap 'rm -f "$OUT" "$ERR"' EXIT

echo "== scanning ($ROOT)"
rc=0
( cd "$ROOT" && "$GOVC" -format=json ./... ) >"$OUT" 2>"$ERR" || rc=$?
# govulncheck exits 0 (no vulns) or 3 (vulns found) on a real scan; anything
# else (1, 2, ...) means it failed to run. fail closed.
if [ "$rc" != "0" ] && [ "$rc" != "3" ]; then
	echo "VULN GATE FAILED: govulncheck did not complete (exit $rc):"
	sed -n '1,20p' "$ERR" >&2
	exit 1
fi
decide "$ALLOW" "$OUT"
