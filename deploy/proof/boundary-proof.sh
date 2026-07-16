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
BROKER_IMAGE="${BROKER_IMAGE:-openmallab/mal-broker:m0}"
PROBE_IMAGE="${PROBE_IMAGE:-busybox:1.36}"

VOL="openmallab-boundary-proof"
WORKER="openmallab-boundary-worker"

# The canonical EICAR test string, assembled at runtime from two halves so no
# file in this repo carries the contiguous signature.
E1='X5O!P%@AP[4\PZX54(P^)7CC)7}$'
E2='EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
EICAR_SHA="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

N=0
pass() { N=$((N + 1)); echo "PASS $N: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  docker rm -f "$WORKER" >/dev/null 2>&1 || true
  docker volume rm -f "$VOL" >/dev/null 2>&1 || true
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
