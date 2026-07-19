# Dynamic Analysis v1 (mal-detonate)

The first dynamic-analysis engine for OpenMalLab. It detonates a Linux ELF and
reports the behavior it observed, on the same containment model as every other
engine: jailed, brokered, fail-closed. This document is the design of record for
slice 0 (shipped) and the plan for the slices after it.

## The containment idea

Every sandbox faces one paradox: to observe behavior you must execute the sample,
and execution is what you are trying to contain. The usual answer is a heavy VM
with an in-guest agent, which the malware can detect and evade, or a host the
sample can escape onto.

mal-detonate takes a different route. The sample is **never made executable** and
the host kernel **never runs it**. A trusted, image-resident emulator,
`qemu-<arch>-static`, opens the sample as read-only DATA at `/in/sample` and
interprets its instructions, translating each guest syscall into a host syscall
that the jail still fully constrains. Consequences:

- Detonation adds **no new capability** over the static jails (no ptrace, no
  CAP_BPF, no eBPF) and **no writable-and-executable surface** anywhere.
- The only thing the host executes is the trusted emulator, on the read-only
  rootfs. The malware bytes stay data.
- Instrumentation is **out-of-guest**: `qemu -strace` is emitted by the emulator
  itself, so there is no in-guest agent for the sample to detect or unhook. This
  is the property that makes VMRay strong, reached without a hypervisor.

## Isolation model

The detonation jail IS the existing recipe (`services/mal-orchestrator/jail.go`):
`--network none`, all caps dropped, `no-new-privileges`, `seccomp=builtin`,
read-only rootfs, non-root (uid 65534), private cgroup/ipc namespaces, single-use
and reaped, one read-only sample mount. Detonation only layers the same
security-preserving overrides capa/floss already use (raised memory + scratch,
`HOME=/scratch`), through `applyOverrides()`, which is pinned to never loosen a
security flag.

Deltas versus a static engine, and how the boundary proof should test them:

| Property | Detonation v1 | Boundary-proof assertion |
|---|---|---|
| Sample | interpreted by qemu, still ro `/in/sample`, never `+x` | sample mount ReadOnly=true; **no writable+exec mount exists** |
| Capabilities | ALL dropped (qemu + file read need none) | reuse CapEff=0 probe |
| seccomp | `builtin` | reuse `Seccomp:2`, never unconfined |
| Exec surface | qemu on ro rootfs; `/scratch` stays noexec | exec of a file in `/scratch` is denied |
| Network | `--network none` (v1) | reuse only-lo / empty-routes probe |
| Runtime | bounded; wrapper self-timeout < jail wall < activity timeout | a looping sample is killed and floors incomplete, never benign |

Honest limitation, foregrounded: v1 is **one kernel away**, container-based, not
the physically-segregated detonation node of the long-term design. It runs live
malware behind the proven jail on the shared kernel. That is acceptable for a
research/dev v1 and is documented as such; production dynamic analysis moves to a
segregated node (phase 3). The dev box (Colima) additionally sits under a VM, which
is incidental defense in depth, never a designed control.

## Instrumentation and evidence

`qemu-<arch>-static -L / -strace <sample>` runs the guest with the image's own libc
as the sysroot. The wrapper detects the guest arch from the ELF header (e_machine:
x86-64 or aarch64), runs the matching emulator under a hard wall clock with a bounded
capture of the syscall log, and folds the trace into a small set of findings:

| Behavior | Finding type | Verdict | ATT&CK |
|---|---|---|---|
| process/exec (dropped-payload exec) | `proc-exec` | UNKNOWN / SUSPICIOUS | T1204 |
| write to a persistence path | `persistence` | SUSPICIOUS | T1547 |
| outbound connect / sendto | `net-connect` | SUSPICIOUS | T1071 |
| file write / delete | `file-write` / `file-delete` | UNKNOWN | T1070 |
| many sleeps | `evasive-sleep` | UNKNOWN | T1497 |
| privileged syscall (contained) | `syscall-privileged` | UNKNOWN | T1497 |
| ran clean, or timed out / errored | `detonation-*` | UNKNOWN or SUSPICIOUS+incomplete | - |

A `detonation-summary` finding always leads (syscall/file/net/exec/sleep counts), so
even a silent run is visible in the evidence tree. Behavioral evidence caps at
SUSPICIOUS; only deterministic engines may reach MALICIOUS. A run that saw nothing is
UNKNOWN, never benign: dynamic silence is not innocence (the sample may be dormant,
evasive, or wrong-arch).

**Dynamic-first, not static-first.** qemu-user 7.x traces dynamically-linked ELFs
cleanly (the loader + libc syscalls are real behavior) but cannot reliably run
static-glibc binaries; the wrapper detects a static ELF and fails it closed with a
clear reason. Most real-world Linux malware is dynamically linked.

## Pipeline integration

- `DetonateActivity` runs the worker through the broker on the heavy context
  (`MaximumAttempts: 1`; a retry would just burn another live run for a different
  result), with raised memory/scratch and `HOME=/scratch`.
- The workflow gates it with `isELF(identRep)` AND `in.Detonate` AND `item.Depth == 0`:
  ELF only, opt-in only, root artifact only. Detonation EXECUTES the sample, so it is
  never automatic in v1, and never runs on extracted children (an unbounded risk +
  budget explosion).
- Findings fold through the same fail-closed lattice; `ConfidenceFor` scores
  behavioral hits at medium.
- The gateway exposes the opt-in as the `detonate=true` form field on
  `POST /v1/submissions`.

## Building the image

Canonical build (clean network / CI):

    docker compose -f deploy/compose.yaml --profile build build mal-detonate

The image is `debian:12` + `qemu-user-static` + a second-arch libc (the qemu sysroot)
+ the stdlib-only Python wrapper, with a build-time `--selftest` that asserts both
emulators run and the syscall->finding->verdict mapping is correct.

On a network that firewalls the BuildKit sandbox from the package mirror (some
corporate proxies do, while `docker run` containers still reach it), build with the
legacy builder, `DOCKER_BUILDKIT=0 docker build ...`, or install into a `docker run`
container and `docker commit`. The Dockerfile itself is unchanged and correct; this
is only a network workaround.

## Roadmap

- **Slice 0 (shipped):** detonate a dynamic ELF, `--network none`, brokered
  behavioral findings, fail-closed. C2 shows up as captured connect intent.
- **Slice 1:** richer process-tree + persistence mapping, finer ATT&CK.
- **Slice 2:** a jailed sinkhole on an internal, no-egress network so C2 domains,
  URLs, and first payload bytes are observed live, still with no route off the box.
- **Slice 3:** dropped files re-hashed and pushed back through the static engines
  (reuse the extractor's `ingestChild` path).
- **Slice 4:** auto-gate on ELF with a per-submission detonation budget (needs a
  human sign-off on the risk posture, since it means executing samples automatically).
- **Phase 3:** a physically-segregated detonation node with a one-way data pump,
  full-system guests, Windows/macOS targets, hypervisor-grade out-of-guest monitoring.

## Non-goals for v1

Windows/PE and Mach-O guests; GUI/interactive detonation; kernel/rootkit visibility;
real network egress; full sinkhole feature-completeness; snapshot orchestration;
memory forensics; and any claim to defeat anti-emulation (qemu-user is fingerprintable,
and v1 makes no stealth claim).
