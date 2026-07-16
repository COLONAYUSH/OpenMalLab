#!/usr/bin/env bash
# Boundary proof for the jailed worker recipe.
#
# Runs the real mal-static-yara image under the exact isolation recipe the
# orchestrator uses, scans an EICAR sample, then proves the jail held:
# no network, no capabilities, no credentials, read-only rootfs, noexec
# scratch, non-root, hard resource caps. Also proves the broker rejects
# malformed worker output while jailed itself.
#
# CI runs this as the topology-conformance gate. Locally:
#   docker compose -f deploy/compose.yaml --profile build build
#   deploy/proof/boundary-proof.sh
#
# Needs docker and the built images. Creates and removes its own scratch
# volume; touches nothing else.

set -euo pipefail

WORKER_IMAGE="${WORKER_IMAGE:-openmallab/mal-static-yara:m0}"
IDENT_IMAGE="${IDENT_IMAGE:-openmallab/mal-ident:m0}"
EXTRACT_IMAGE="${EXTRACT_IMAGE:-openmallab/mal-extract:m0}"
BROKER_IMAGE="${BROKER_IMAGE:-openmallab/mal-broker:m0}"
PROBE_IMAGE="${PROBE_IMAGE:-busybox:1.36}"

VOL="openmallab-boundary-proof"
OUTVOL="openmallab-boundary-out"
WORKER="openmallab-boundary-worker"
EXTRACTOR="openmallab-boundary-extractor"

# The canonical EICAR test string, assembled at runtime from two halves so no
# file in this repo carries the contiguous signature.
E1='X5O!P%@AP[4\PZX54(P^)7CC)7}$'
E2='EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
EICAR_SHA="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

N=0
pass() { N=$((N + 1)); echo "PASS $N: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  docker rm -f "$WORKER" "$EXTRACTOR" >/dev/null 2>&1 || true
  docker volume rm -f "$VOL" "$OUTVOL" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The jail. One documented recipe, expressed here as docker run flags and in
# services/mal-orchestrator/jail.go as api fields; the conformance unit test
# pins the two to each other.
JAIL=(
  --network none
  --cap-drop ALL
  --security-opt no-new-privileges
  --security-opt seccomp=builtin
  --read-only
  --tmpfs /scratch:rw,noexec,nosuid,nodev,size=64m
  --user 65534:65534
  --memory 512m
  --memory-swap 512m
  --cpus 1
  --pids-limit 128
  --cgroupns private
  --log-driver none
)

docker image inspect "$WORKER_IMAGE" >/dev/null 2>&1 \
  || fail "worker image $WORKER_IMAGE not built; run: docker compose -f deploy/compose.yaml --profile build build"
docker image inspect "$IDENT_IMAGE" >/dev/null 2>&1 \
  || fail "ident image $IDENT_IMAGE not built; run: docker compose -f deploy/compose.yaml --profile build build"
docker image inspect "$EXTRACT_IMAGE" >/dev/null 2>&1 \
  || fail "extract image $EXTRACT_IMAGE not built; run: docker compose -f deploy/compose.yaml --profile build build"
docker image inspect "$BROKER_IMAGE" >/dev/null 2>&1 \
  || fail "broker image $BROKER_IMAGE not built; run: docker compose -f deploy/compose.yaml --profile build build"

cleanup

# ---- stage the sample: content-addressed, owned by nobody, 0600 ------------

SHA=$(docker run --rm -v "$VOL:/vault" "$PROBE_IMAGE" sh -c "
  printf '%s%s' '$E1' '$E2' > /vault/stage
  sha=\$(sha256sum /vault/stage | cut -d' ' -f1)
  mv /vault/stage /vault/\$sha
  chown 65534:65534 /vault/\$sha
  chmod 0600 /vault/\$sha
  echo \$sha")
[ "$SHA" = "$EICAR_SHA" ] || fail "staged sample hash mismatch: $SHA"
pass "eicar staged content-addressed at vault/$SHA"

# ---- the jailed scan --------------------------------------------------------

OUT=$(docker run --name "$WORKER" "${JAIL[@]}" \
  --mount "type=volume,src=$VOL,dst=/in/sample,volume-subpath=$SHA,ro" \
  "$WORKER_IMAGE")
echo "$OUT" | grep -q '"verdict":"MALICIOUS"' || fail "worker did not return MALICIOUS: $OUT"
echo "$OUT" | grep -q 'eicar_test_file' || fail "worker did not name the rule: $OUT"
pass "jailed worker scanned eicar and returned MALICIOUS (rule eicar_test_file)"

# ---- inspect the exited container: the jail as the daemon recorded it -------

expect() { # label, inspect template, want
  local got
  got=$(docker inspect -f "$2" "$WORKER")
  [ "$got" = "$3" ] || fail "$1: got '$got' want '$3'"
  pass "$1"
}

expect "network mode is none"            '{{.HostConfig.NetworkMode}}'                 'none'

# engines render an unset ip differently: "" on v28, "invalid IP" on v29.
# either way the property is the same: one none endpoint, no address.
EP=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}:{{$v.IPAddress}}{{end}}' "$WORKER")
echo "$EP" | grep -Eq '^none:(invalid IP)?$' || fail "unexpected endpoints: $EP"
pass "single none endpoint, no ip"
expect "exactly one mount"               '{{len .Mounts}}'                             '1'
expect "mount is the sample"             '{{(index .Mounts 0).Destination}}'           '/in/sample'
expect "mount is read-only"              '{{(index .Mounts 0).RW}}'                    'false'
expect "all capabilities dropped"        '{{json .HostConfig.CapDrop}}'                '["ALL"]'
expect "read-only rootfs"                '{{.HostConfig.ReadonlyRootfs}}'              'true'
expect "not privileged"                  '{{.HostConfig.Privileged}}'                  'false'
expect "runs as nobody"                  '{{.Config.User}}'                            '65534:65534'
expect "pids capped"                     '{{.HostConfig.PidsLimit}}'                   '128'
expect "memory capped"                   '{{.HostConfig.Memory}}'                      '536870912'
expect "swap capped to memory"           '{{.HostConfig.MemorySwap}}'                  '536870912'
expect "one cpu"                         '{{.HostConfig.NanoCpus}}'                    '1000000000'
expect "private cgroup namespace"        '{{.HostConfig.CgroupnsMode}}'                'private'
expect "worker exited clean"             '{{.State.ExitCode}}'                         '0'

SECOPT=$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$WORKER")
echo "$SECOPT" | grep -q 'no-new-privileges' || fail "no-new-privileges missing: $SECOPT"
echo "$SECOPT" | grep -q 'seccomp=builtin' || fail "builtin seccomp missing: $SECOPT"
echo "$SECOPT" | grep -qv 'unconfined' || fail "unconfined found: $SECOPT"
pass "no-new-privileges and builtin seccomp, never unconfined"

ENVJSON=$(docker inspect -f '{{json .Config.Env}}' "$WORKER")
echo "$ENVJSON" | grep -Eq '^\["PATH=[^"]*"\]$' || fail "worker env is not just PATH: $ENVJSON"
pass "no environment beyond PATH: no store creds, no tokens, nothing"

# ---- runtime probe: what a process inside the jail can actually see ---------

PROBE=$(docker run --rm "${JAIL[@]}" "$PROBE_IMAGE" sh -c '
  [ "$(ip -o link | wc -l)" = "1" ] && ip -o link | grep -q ": lo:" && echo M_ONLY_LO
  [ -z "$(ip route 2>/dev/null)" ] && echo M_NO_ROUTES
  [ "$(id -u)" = "65534" ] && echo M_NOBODY
  [ "$(env | grep -cvE "^(PATH|HOME|PWD|SHLVL|HOSTNAME|OLDPWD|TERM)=")" = "0" ] && echo M_CLEAN_ENV
  grep -q "^CapEff:[[:space:]]*0000000000000000$" /proc/self/status && echo M_CAPEFF_ZERO
  grep -q "^NoNewPrivs:[[:space:]]*1$" /proc/self/status && echo M_NNP
  grep -q "^Seccomp:[[:space:]]*2$" /proc/self/status && echo M_SECCOMP_FILTER
  touch /forbidden 2>/dev/null || echo M_ROOTFS_RO
  touch /scratch/w 2>/dev/null && echo M_SCRATCH_RW
  cp /bin/busybox /scratch/x 2>/dev/null
  /scratch/x true 2>/dev/null || echo M_SCRATCH_NOEXEC
  true')

probe_has() {
  echo "$PROBE" | grep -q "$1" || fail "probe missing $1 ($2)"
  pass "$2"
}
probe_has M_ONLY_LO        "only loopback exists inside the jail"
probe_has M_NO_ROUTES      "route table is empty: no path to anywhere"
probe_has M_NOBODY         "process runs as uid 65534"
probe_has M_CLEAN_ENV      "process env carries no secrets"
probe_has M_CAPEFF_ZERO    "effective capability set is zero"
probe_has M_NNP            "no_new_privs is set"
probe_has M_SECCOMP_FILTER "seccomp filter mode is active"
probe_has M_ROOTFS_RO      "rootfs write refused"
probe_has M_SCRATCH_RW     "scratch tmpfs writable"
probe_has M_SCRATCH_NOEXEC "scratch tmpfs refuses exec"

# ---- nothing to pivot to -----------------------------------------------------

if docker run --rm "${JAIL[@]}" --entrypoint /bin/sh "$WORKER_IMAGE" -c true >/dev/null 2>&1; then
  fail "worker image has a shell"
fi
pass "worker image has no shell, no coreutils, nothing but the binary"

# ---- the magika ident engine, same jail -------------------------------------
# a second engine on a heavier runtime (onnx) proves the recipe is not
# yara-specific: no network, all caps dropped, read-only, and clean stdout the
# broker accepts. the sample is a tiny python snippet (benign, not eicar).

IDENT_OUT=$(docker run --rm "${JAIL[@]}" \
  --mount "type=volume,src=$VOL,dst=/in/sample,volume-subpath=$SHA,ro" \
  "$IDENT_IMAGE" 2>/dev/null)
echo "$IDENT_OUT" | grep -q '"engine":"mal-ident"' || fail "ident produced no report: $IDENT_OUT"
echo "$IDENT_OUT" | grep -q '"type":"file-type"' || fail "ident produced no file-type finding: $IDENT_OUT"
pass "jailed magika ident ran with no network and identified the sample"

# its stdout must be exactly what the broker accepts: the onnx runtime's
# diagnostics go to stderr, never polluting the one json line.
echo "$IDENT_OUT" | docker run --rm -i "${JAIL[@]}" "$BROKER_IMAGE" >/dev/null \
  || fail "broker rejected ident output (stdout not clean?)"
pass "jailed broker accepts the ident output: engine stdout is clean"

if docker run --rm "${JAIL[@]}" --entrypoint /bin/sh "$IDENT_IMAGE" -c true >/dev/null 2>&1; then
  fail "ident image has a shell"
fi
pass "ident image has no shell despite its glibc closure: binary and runtime only"

# ---- the extract engine: the same jail plus one writable /out ---------------
# the extractor is the only worker granted a writable mount. prove that even
# with /out it stays network-dead and cap-less, writes children ONLY under
# /out (never the read-only rootfs or the read-only sample), and that a zip of
# eicar yields a child the broker-validated manifest names.

# build a zip containing eicar (assembled from halves so no contiguous
# signature sits on disk in this repo). write it to a file, never a shell var,
# since zip bytes contain NULs. stage it content-addressed in the vault, with
# the hash computed in-container so this works on any host.
ZIPF=$(mktemp)
python3 - "$ZIPF" <<'PY'
import zipfile, sys
eicar = ('X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').encode()
with zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('nested/eicar.com', eicar)
PY
ZIP_SHA=$(docker run --rm -i -v "$VOL:/vault" "$PROBE_IMAGE" sh -c '
  cat > /vault/.ztmp
  sha=$(sha256sum /vault/.ztmp | cut -d" " -f1)
  mv /vault/.ztmp /vault/$sha
  chown 65534:65534 /vault/$sha && chmod 0600 /vault/$sha
  echo $sha' < "$ZIPF")
rm -f "$ZIPF"

# a fresh, empty, nobody-owned output volume for the extractor's /out.
docker volume create "$OUTVOL" >/dev/null
docker run --rm -v "$OUTVOL:/out" "$PROBE_IMAGE" chown 65534:65534 /out

EXTRACT_OUT=$(docker run --name "$EXTRACTOR" "${JAIL[@]}" \
  --mount "type=volume,src=$VOL,dst=/in/sample,volume-subpath=$ZIP_SHA,ro" \
  --mount "type=volume,src=$OUTVOL,dst=/out" \
  "$EXTRACT_IMAGE" 2>/dev/null)
echo "$EXTRACT_OUT" | grep -q '"engine":"mal-extract"' || fail "extractor produced no report: $EXTRACT_OUT"
echo "$EXTRACT_OUT" | grep -q '"children"' || fail "extractor manifest has no children: $EXTRACT_OUT"
pass "jailed extractor unpacked a zip with no network and emitted a manifest"

# the child bytes must actually be staged under /out, addressed by hash.
CHILD_SHA=$(echo "$EXTRACT_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["children"][0]["sha256"])')
echo "$CHILD_SHA" | grep -Eq '^[a-f0-9]{64}$' || fail "child sha malformed: $CHILD_SHA"
docker run --rm -v "$OUTVOL:/out" "$PROBE_IMAGE" test -f "/out/$CHILD_SHA" \
  || fail "extractor did not stage the child at /out/$CHILD_SHA"
pass "extractor wrote the child content-addressed under /out, and nowhere else"

expect2() { # label, inspect template, want (against the extractor container)
  local got
  got=$(docker inspect -f "$2" "$EXTRACTOR")
  [ "$got" = "$3" ] || fail "$1: got '$got' want '$3'"
  pass "$1"
}
expect2 "extract jail: network none"      '{{.HostConfig.NetworkMode}}'    'none'
expect2 "extract jail: caps dropped"      '{{json .HostConfig.CapDrop}}'  '["ALL"]'
expect2 "extract jail: read-only rootfs"  '{{.HostConfig.ReadonlyRootfs}}' 'true'
expect2 "extract jail: runs as nobody"    '{{.Config.User}}'              '65534:65534'
expect2 "extract jail: two mounts only"   '{{len .Mounts}}'               '2'

# exactly one of the two mounts is writable, and it is /out.
RW=$(docker inspect -f '{{range .Mounts}}{{if not .RW}}{{else}}{{.Destination}} {{end}}{{end}}' "$EXTRACTOR")
[ "$RW" = "/out " ] || fail "the only writable mount must be /out, got '$RW'"
pass "extract jail: the sample is read-only; only /out is writable"

echo "$EXTRACT_OUT" | docker run --rm -i "${JAIL[@]}" "$BROKER_IMAGE" >/dev/null \
  || fail "broker rejected the extract manifest"
pass "jailed broker accepts the extract manifest: children validated"

if docker run --rm "${JAIL[@]}" --entrypoint /bin/sh "$EXTRACT_IMAGE" -c true >/dev/null 2>&1; then
  fail "extract image has a shell"
fi
pass "extract image has no shell: static binary on scratch"

# ---- the broker gate, itself jailed -----------------------------------------

VALID='{"engine":"mal-static-yara","findings":[{"engine":"mal-static-yara","type":"yara","detail":"eicar_test_file","attck":"T1204","verdict":"MALICIOUS"}],"verdict":"MALICIOUS","incomplete":false}'
echo "$VALID" | docker run --rm -i "${JAIL[@]}" "$BROKER_IMAGE" | grep -q '"verdict":"MALICIOUS"' \
  || fail "broker refused a valid report"
pass "jailed broker passes a valid report through"

reject() { # label, payload
  if printf '%s' "$2" | docker run --rm -i "${JAIL[@]}" "$BROKER_IMAGE" >/dev/null 2>&1; then
    fail "broker accepted: $1"
  fi
  pass "broker rejects $1"
}

reject "an invented verdict" '{"engine":"x","findings":[],"verdict":"TRUST_ME","incomplete":false}'
reject "unknown fields" '{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false,"smuggled":1}'
reject "trailing data after one result" '{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}{"second":true}'

BIG=$( { printf '{"engine":"'; head -c 1200000 /dev/zero | tr '\0' 'x'; printf '"}'; } )
if printf '%s' "$BIG" | docker run --rm -i "${JAIL[@]}" "$BROKER_IMAGE" >/dev/null 2>&1; then
  fail "broker accepted oversized input"
fi
pass "broker rejects oversized input past the 1MiB cap"

echo ""
echo "BOUNDARY PROOF: all $N checks passed."
echo "worker image: $WORKER_IMAGE"
echo "broker image: $BROKER_IMAGE"
