# Boundary proof: the jailed worker holds

Date: 2026-07-16. Engine: docker 29.5.2 (linux/arm64). Images:
openmallab/mal-static-yara:m0, openmallab/mal-broker:m0.

This is the receipt for the single most important property in the design:
a worker that parses hostile bytes runs with nothing to steal, nowhere to go,
and no way for its output to reach a trusted decoder unvalidated. We do not
claim it. We run it and check.

Re-run it yourself any time:

    docker compose -f deploy/compose.yaml --profile build build
    deploy/proof/boundary-proof.sh

CI runs the same script as the topology-conformance gate, so this proof
cannot silently rot.

## The recipe

Every analysis worker is a single-use container spawned with:

    --network none
    --cap-drop ALL
    --security-opt no-new-privileges
    --security-opt seccomp=builtin
    --read-only
    --tmpfs /scratch:rw,noexec,nosuid,nodev,size=64m
    --user 65534:65534
    --memory 512m --memory-swap 512m
    --cpus 1
    --pids-limit 128
    --cgroupns private
    --log-driver none

plus exactly one mount: the sample, read-only, at /in/sample, addressed by
its sha256 inside the vault volume (volume-subpath, so the worker sees one
file, never the vault). No environment beyond PATH. No store credentials
exist in the worker at all, so no compromise of the worker can leak them.

The result leaves as one bounded json line on stdout. It is piped into
mal-broker, which runs under the same jail and enforces: one document, known
fields only, verdicts from the fixed lattice, 1 MiB input cap, 1000 findings
cap, 8192-byte string cap. The orchestrator decodes only what the broker
re-emits. Any violation exits nonzero and the node floors to SUSPICIOUS.

A note on "empty" network namespaces: the kernel always creates loopback, so
the honest claim is not "no interfaces". It is: only lo, an empty main route
table, and no way to reach another kernel socket. That is what gets asserted.

## The transcript

Output of deploy/proof/boundary-proof.sh, unedited:

    PASS 1: eicar staged content-addressed at vault/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    PASS 2: jailed worker scanned eicar and returned MALICIOUS (rule eicar_test_file)
    PASS 3: network mode is none
    PASS 4: single none endpoint, no ip
    PASS 5: exactly one mount
    PASS 6: mount is the sample
    PASS 7: mount is read-only
    PASS 8: all capabilities dropped
    PASS 9: read-only rootfs
    PASS 10: not privileged
    PASS 11: runs as nobody
    PASS 12: pids capped
    PASS 13: memory capped
    PASS 14: swap capped to memory
    PASS 15: one cpu
    PASS 16: private cgroup namespace
    PASS 17: worker exited clean
    PASS 18: no-new-privileges and builtin seccomp, never unconfined
    PASS 19: no environment beyond PATH: no store creds, no tokens, nothing
    PASS 20: only loopback exists inside the jail
    PASS 21: route table is empty: no path to anywhere
    PASS 22: process runs as uid 65534
    PASS 23: process env carries no secrets
    PASS 24: effective capability set is zero
    PASS 25: no_new_privs is set
    PASS 26: seccomp filter mode is active
    PASS 27: rootfs write refused
    PASS 28: scratch tmpfs writable
    PASS 29: scratch tmpfs refuses exec
    PASS 30: worker image has no shell, no coreutils, nothing but the binary
    PASS 31: jailed broker passes a valid report through
    PASS 32: broker rejects an invented verdict
    PASS 33: broker rejects unknown fields
    PASS 34: broker rejects trailing data after one result
    PASS 35: broker rejects oversized input past the 1MiB cap

    BOUNDARY PROOF: all 35 checks passed.
    worker image: openmallab/mal-static-yara:m0
    broker image: openmallab/mal-broker:m0

## The evidence line

The exact bytes the jailed worker emitted for the eicar sample:

    {"engine":"mal-static-yara","findings":[{"engine":"mal-static-yara","type":"yara","detail":"eicar_test_file","attck":"T1204","verdict":"MALICIOUS"}],"verdict":"MALICIOUS","incomplete":false}

## What is deliberately NOT proven here

- The orchestrator side of the boundary (spawning these jails through the
  docker api and refusing to decode raw worker bytes) is pinned by its own
  conformance unit test against the same recipe.
- seccomp uses the engine's builtin default profile for M0. Never unconfined.
  A bespoke tighter profile is M1 work.
- The images run one kernel away from the control plane, not on a separate
  detonation node. That separation is phase 2 and applies to dynamic
  analysis, not these static workers.
