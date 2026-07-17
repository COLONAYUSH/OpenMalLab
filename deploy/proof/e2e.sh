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
# Needs docker compose, curl, python3. Behind a private pip index, export
# MAL_PIP_CONF=~/.pip/pip.conf so the capa image builds (it pip-installs capa);
# on a clean network the capa build uses public PyPI and no export is needed.

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
trap 'rm -rf "$TMP"; docker rm -f malfloss-pe-build >/dev/null 2>&1 || true; if [ "${KEEP_UP:-0}" != "1" ]; then docker compose -f "$COMPOSE" stop gateway orchestrator >/dev/null 2>&1 || true; fi' EXIT

# the canonical eicar test string, assembled from halves at runtime so the
# contiguous signature never sits in this file.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar.com"
printf 'a plain text file with nothing interesting in it\n' > "$TMP/benign.txt"
# a zip that hides eicar two levels down a directory, to prove recursive
# extraction: the gateway never sees the eicar bytes, only a zip.
python3 - "$TMP/eicar.com" "$TMP/nested.zip" <<'PY'
import zipfile, sys
with open(sys.argv[1], 'rb') as f:
    eicar = f.read()
with zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('payloads/inner/eicar.com', eicar)
    z.writestr('readme.txt', b'nothing to see here')
PY

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
# both engines ran in parallel: magika identified the file type as evidence.
ident = [x for x in d["findings"] if x["engine"] == "mal-ident" and x["type"] == "file-type"]
assert ident, "no mal-ident file-type finding: %s" % d["findings"]
assert d["file_type"], "submission carries no rolled-up file_type: %s" % d
' || fail "eicar findings wrong: $BODY"
FT=$(echo "$BODY" | jget file_type)
say "eicar -> MALICIOUS (yara) and identified as '$FT' (magika), both jailed, both brokered."

say "submitting a benign file"
ID2=$(submit "$TMP/benign.txt")
BODY2=$(await_verdict "$ID2")
V2=$(echo "$BODY2" | jget verdict)
I2=$(echo "$BODY2" | jget incomplete)
FT2=$(echo "$BODY2" | jget file_type)
[ "$V2" = "UNKNOWN" ] || fail "benign verdict $V2, want UNKNOWN (honest: no engine earns BENIGN yet): $BODY2"
[ "$I2" = "False" ] || fail "benign incomplete=$I2, want false: $BODY2"
[ -n "$FT2" ] || fail "benign carries no file_type: $BODY2"
say "benign -> UNKNOWN, complete, identified as '$FT2'. nothing is benign by omission."

say "submitting a zip that hides eicar two directories deep"
ID3=$(submit "$TMP/nested.zip")
BODY3=$(await_verdict "$ID3")
V3=$(echo "$BODY3" | jget verdict)
[ "$V3" = "MALICIOUS" ] || fail "nested-zip verdict $V3, want MALICIOUS (eicar is inside): $BODY3"
echo "$BODY3" | python3 -c '
import json, sys
d = json.load(sys.stdin)
# the root was identified as a zip.
assert d["file_type"] in ("zip",), "root not identified as zip: %s" % d["file_type"]
# recursion found the eicar child and yara hit it, with a breadcrumb path.
hit = [x for x in d["findings"]
       if x["engine"] == "mal-static-yara" and x["detail"] == "eicar_test_file"]
assert hit, "no eicar finding from inside the zip: %s" % d["findings"]
assert hit[0].get("path"), "eicar finding carries no breadcrumb path: %s" % hit[0]
assert "eicar.com" in hit[0]["path"], "breadcrumb does not name the nested file: %s" % hit[0]["path"]
print("  breadcrumb:", hit[0]["path"])
' || fail "nested-zip recursion wrong: $BODY3"
say "nested zip -> MALICIOUS: recursion unpacked it, scanned the child, kept the trail."

# a small, dynamically-linked x86-64 program: capa reads its imports fast and
# reports ATT&CK-mapped capabilities. we borrow a stock system binary so no
# executable is committed to the repo. amd64 on purpose: capa/vivisect targets
# x86/x64, and a capa worker disassembles the sample's arch regardless of host.
say "extracting a small x86-64 binary for capability analysis"
cid=$(docker create --platform linux/amd64 debian:12 2>/dev/null)
docker cp "$cid:/usr/bin/id" "$TMP/idbin" >/dev/null 2>&1
docker rm "$cid" >/dev/null 2>&1
[ -s "$TMP/idbin" ] || fail "could not stage the x86-64 capa sample"

say "submitting an executable; capa should surface ATT&CK-mapped capabilities"
ID4=$(submit "$TMP/idbin")
BODY4=$(await_verdict "$ID4")
echo "$BODY4" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["file_type"] == "elf", "not identified as elf: %s" % d["file_type"]
capa = [x for x in d["findings"] if x["engine"] == "mal-capa"]
assert capa, "capa did not run on the executable: %s" % sorted(set(f["engine"] for f in d["findings"]))
caps = [x for x in capa if x["type"] == "capability"]
assert caps, "capa surfaced no capabilities: %s" % capa
attcks = sorted({x["attck"] for x in caps if x.get("attck")})
assert attcks, "capa capabilities carry no ATT&CK/MBC ids: %s" % caps
print("  capa: %d capabilities, techniques %s" % (len(caps), attcks))
' || fail "capa analysis wrong: $BODY4"
say "executable -> capa surfaced ATT&CK-mapped capabilities, jailed and brokered."

# a real PE for FLOSS string recovery. FLOSS decodes PE only, so an ELF will
# not do; we cross-compile a tiny one with mingw at test time rather than
# commit a Windows binary. strings are embedded so static recovery has signal.
# built inside a throwaway amd64 container, then copied out (nothing committed).
say "cross-compiling a tiny PE for FLOSS string recovery (mingw, amd64)"
PESRC='int puts(const char*);
static const char *probe = "openmallab-floss-probe alpha bravo charlie delta echo";
int main(void){ puts(probe); return 0; }'
PEB64=$(printf '%s' "$PESRC" | base64 | tr -d '\n')
docker rm -f malfloss-pe-build >/dev/null 2>&1 || true
docker run --name malfloss-pe-build --platform linux/amd64 debian:12 sh -c "
  set -e
  apt-get update -qq
  apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null
  printf '%s' '$PEB64' | base64 -d > /t.c
  x86_64-w64-mingw32-gcc /t.c -o /hello.exe -s
" >/dev/null 2>&1 || fail "could not cross-compile the PE sample (mingw)"
docker cp malfloss-pe-build:/hello.exe "$TMP/hello.exe" >/dev/null 2>&1
docker rm malfloss-pe-build >/dev/null 2>&1
[ -s "$TMP/hello.exe" ] || fail "could not stage the PE FLOSS sample"

say "submitting a PE; FLOSS should recover strings and magika should call it pebin"
ID5=$(submit "$TMP/hello.exe")
BODY5=$(await_verdict "$ID5")
echo "$BODY5" | python3 -c '
import json, sys
d = json.load(sys.stdin)
# magika calls a PE "pebin" (its own label; there is no "pe"). the FLOSS gate
# keys on exactly this, and regressed once by checking a label magika never emits.
assert d["file_type"] == "pebin", "PE not identified as pebin: %s" % d["file_type"]
# every engine completed. this guards the capa-on-PE regression: capa needs
# FLIRT signatures to analyze a PE and used to fail closed (SUSPICIOUS+incomplete)
# on every PE because none were vendored. a clean, complete PE run proves the fix.
assert d["incomplete"] is False, "PE run came back incomplete (an engine failed): %s" % d["findings"]
floss = [x for x in d["findings"] if x["engine"] == "mal-floss"]
assert floss, "FLOSS did not run on the PE: %s" % sorted(set(f["engine"] for f in d["findings"]))
summ = [x for x in floss if x["type"] == "floss-summary"]
assert summ, "FLOSS produced no summary: %s" % floss
# FLOSS evidence is strings, never a verdict: everything it emits stays UNKNOWN.
assert all(x["verdict"] == "UNKNOWN" for x in floss), "FLOSS emitted a non-UNKNOWN verdict: %s" % floss
# a PE is also an executable, so capa analyzed it too: it must surface real
# capabilities (not just an error finding), which only works with the sigs.
caps = [x for x in d["findings"] if x["engine"] == "mal-capa" and x["type"] == "capability"]
assert caps, "capa surfaced no capabilities on the PE (sigs missing?): %s" % [x for x in d["findings"] if x["engine"] == "mal-capa"]
attcks = sorted({x["attck"] for x in caps if x.get("attck")})
assert attcks, "capa PE capabilities carry no ATT&CK/MBC ids: %s" % caps
print("  floss: %s" % summ[0]["detail"])
print("  capa:  %d capabilities on the PE, techniques %s" % (len(caps), attcks))
' || fail "FLOSS/capa PE analysis wrong: $BODY5"
say "PE -> FLOSS recovered strings (UNKNOWN evidence) and capa surfaced capabilities, complete, jailed, brokered."

echo ""
echo "E2E PROOF PASSED"
echo "  eicar:      $ID -> MALICIOUS (yara: eicar_test_file, T1204; magika: $FT)"
echo "  benign:     $ID2 -> UNKNOWN (magika: $FT2)"
echo "  nested zip: $ID3 -> MALICIOUS (recursive extract found the buried eicar)"
echo "  executable: $ID4 -> capa surfaced ATT&CK-mapped capabilities"
echo "  pe:         $ID5 -> FLOSS strings + capa capabilities, complete (magika: pebin)"
