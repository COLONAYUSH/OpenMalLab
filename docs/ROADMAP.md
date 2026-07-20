# OpenMalLab Roadmap and Delivery Plan

The build guide from Alpha to a best-in-class, generally-available product. This is
the canonical plan; every build slice should trace back to a phase here, and each
slice ships only when it is green under the quality gates in the Testing Strategy.

- Status legend: `[DONE]` shipped + proven, `[WIP]` built, live-proof pending,
  `[NEXT]` designed, next up, `[PLANNED]` designed, later.
- Last updated: 2026-07-20.

---

## 1. North Star

The best open-source, air-gapped-first, sovereign, hybrid-AI malware-analysis
platform. The self-hostable choice for banks, defense labs, national CERTs, and
critical-infrastructure teams that legally cannot send live samples to a cloud
sandbox and refuse to trust a verdict they cannot audit.

We do not try to out-telemetry VirusTotal or out-depth VMRay/Joe on day one. We win
the ground the cloud giants cannot stand on: sovereignty, provable containment,
transparent grounded AI, and open extensibility.

## 2. Current state: ALPHA

Phase 1 (sovereign static + AI core) is feature-complete and proven live end to end
on a single box via the guarded-cloud model connector. Phase 2 (dynamic analysis)
has its first slice built and wired; its live proof is one clean-network run away.
Not yet GA: no external users, no multi-tenant/scale hardening, no production
detonation node.

## 3. Guiding principles (non-negotiable)

1. Containment first. Every engine that touches hostile bytes runs in a single-use,
   network-less, capability-dropped, read-only, non-root, seccomp-confined, bounded
   jail. Containment is proven as CI-asserted invariants, never assumed.
2. Fail closed. Nothing is benign by omission. A crash, timeout, or gap floors to
   SUSPICIOUS + incomplete and is surfaced, never silence.
3. The broker is the only trust boundary. All worker output is strictly schema-
   validated and size-capped before any trusted code reads it.
4. The AI enriches, never disposes. A downgrade-only gate accepts a hypothesis only
   when it cites a verified fact, else escalates to a human. Confidence never
   promotes a verdict; MALICIOUS is deterministic-engine-only.
5. Sovereign by construction. The analysis plane has no route off the box. Samples
   and telemetry never leave.
6. Every change is adversarially audited and proven before it is called done.

## 4. Quality and testing strategy (cross-cutting, applies to every slice)

A slice is not done until ALL of these are green:

- Unit + logic tests for new code (`go test ./...`, `cargo test`, worker
  `--selftest`, Python checks), including a test that would have caught the bug/gap
  the slice addresses.
- `go build ./...`, `go vet ./...`, `gofmt -l` clean; `cargo build`, `cargo fmt
  --check`, `cargo clippy` clean; ASCII-only source; no secrets in history.
- Broker fuzz for any worker whose output shape changed.
- Boundary proof extended for any new jail: the full envelope (net none, caps
  dropped, read-only, non-root, seccomp, no writable+exec mount, bounded), asserted
  live in CI. A new engine adds a documented set of PASS assertions.
- An end-to-end proof script (submit -> jailed run -> broker -> lattice -> verdict)
  that a reviewer can run with one command.
- The standing multi-lens adversarial quality audit run over the change; confirmed
  findings fixed or explicitly deferred with a reason.
- CI green across every job (go, rust, fuzz, boundary-proof, python, vuln, license,
  invariant-traceability) on the target arch.
- No silent caps: any truncation/limit is logged and surfaced as incomplete.

Definition of "live" for a capability: it runs in the jailed pipeline, its output
crosses the broker, folds into the fail-closed lattice, is visible in the console,
and is covered by a boundary proof + an e2e proof that pass in CI.

---

## 5. Phase 1 - Sovereign static + AI core  [DONE]

Proven live (via cloud model) on a single box. Recap of what is shipped:

- Containment: one jail recipe + broker, 48+ CI-asserted invariants, fuzz-tested.
- Static engines (5), jailed + brokered: content typing, YARA-X signatures (matched
  strings + offsets + ATT&CK evidence), capa capability detection, FLOSS string
  recovery, decompression-bomb/zip-slip-safe recursive unpacking.
- Fusion: fail-closed severity lattice + confidence-weighted triage score;
  per-artifact content hashes surfaced.
- Agentic AI plane: 9-agent Pydantic-AI roster, downgrade-only confidence gate,
  4-tier knowledge graph (exact/fuzzy/relational/semantic), persistent (restart-
  surviving) L0 store, HITL review, poisoning-gated learning, per-category autonomy
  graduation. Validated live against a real model; injection-resistant; red-teamed.
- Analyst console (ranked queue + recursive evidence tree, inert rendering).
- Sovereign deployment: one-command bring-up; sovereign-local or guarded-cloud model.

Residual for Phase 1 hardening (roll into GA): DIE packer/compiler-ID engine (#16),
L1 graph persistence (currently in-memory), actions off Node20.

---

## 6. Phase 2 - Dynamic analysis (detonation)  [WIP]

The make-or-break differentiator. Detonate a sample and report behavior, on the same
containment model as every static engine. Slices ship independently.

### Slice 0 - Detonate a dynamic ELF  [WIP: built, live-proof pending]
- Built: the `mal-detonate` worker runs an ELF as DATA under a jailed
  `qemu-<arch>-static -strace` emulator (out-of-guest instrumentation, no in-guest
  agent, zero new privilege), mines syscalls into brokered behavioral findings,
  caps at SUSPICIOUS, fails closed. Orchestrator gating (ELF + opt-in + root-only),
  ConfidenceFor policy, gateway flag, compose entry - all committed, unit-verified.
- Remaining: build the worker image + run the live proof on a clean network
  (`deploy/proof/detonate-proof.sh`); this box's proxy blocks the image build.
- Acceptance: detonate-proof passes; behavior reported + contained.

### Slice 1 - Detonation fidelity  [NEXT]
- Full process/exec tree with parent-child lineage; classified file operations
  (create/modify/delete/rename); richer persistence detection (cron, systemd,
  autostart, shell-init); finer ATT&CK mapping; sleep-as-evidence with optional
  sleep-patching; in-jail evidence summarization budget.
- Acceptance: unit tests for each mapping; e2e on a benign behavioral sample;
  boundary proof unchanged (same jail).

### Slice 2 - Contained network sinkhole  [NEXT]
- A jailed `mal-sinkhole` (minimal DNS + TCP responder) on a Docker `internal`,
  no-egress network; guest DNS points at the sink so C2 domains, requested URLs, and
  first payload bytes are observed live with no route off the box.
- Acceptance: new boundary-proof section (internal net has no NAT/gateway/host/LAN/
  internet route, IPv6/link-local blocked, DNS resolves only via sink); e2e shows a
  captured C2 IOC; sink output crosses the broker like any worker.

### Slice 3 - Dropped-artifact recursion  [NEXT]
- Files the sample drops are written to a per-run writable mount, re-hashed and
  ingested via the existing content-addressed path, and recursed back through every
  static engine (and detonation, budget-permitting).
- Acceptance: e2e where a dropped payload is independently flagged; reuses the
  extractor's writable-mount boundary proof + ingest re-hash tests.

### Slice 4 - Auto-gating with a detonation budget  [NEXT, needs sign-off]
- Flip detonation from on-request to auto on ELF (later PE) with a per-submission
  detonation budget and a bounded concurrent-detonation pool.
- Blocked on product-owner decision: should the platform ever execute live malware
  automatically, and on what samples.
- Acceptance: budget enforced + tested; the on-request path preserved as a mode.

### Slice 5 - Native-exec fidelity increment  [PLANNED]
- Optional higher-fidelity native execution (aarch64) under ptrace with a W^X exec
  surface, each new capability added as its own boundary assertion. Emulator path
  stays the default.

Phase 2 exit (Beta of the differentiator): slices 0-3 live + proven; a real analyst
can submit a Linux sample, get behavioral evidence + IOCs, and trust the containment.

---

## 7. Phase 3 - Production detonation range  [PLANNED]

Container detonation is a research/dev v1 (one kernel away). Production dynamic
analysis of the hardest samples needs real isolation. Requires hardware.

- A physically-segregated detonation node with a one-way data pump (submit in,
  evidence out, no interactive path back).
- Full-system guests via KVM/microVM (Firecracker) or full QEMU, with an in-guest
  collection agent and snapshot/restore for clean, fast runs.
- Windows guest support (licensing, base image, agent, GUI automation for installer
  flows), then macOS.
- Hypervisor-grade out-of-guest monitoring (altp2m/DRAKVUF-class) for anti-evasion.
- Acceptance: the segregated-node boundary proof (no path from guest to the control
  plane except the pump); Windows + Linux behavioral parity on a labelled corpus.

## 8. Phase 4 - Reporting, interop, and API  [PLANNED]

Make the verdict usable by the rest of the SOC.

- STIX 2.1 and MISP export of verdicts + IOCs; a copyable IOC panel (hashes,
  domains, IPs, URLs, ATT&CK) in the console.
- Stable public REST API + OpenAPI spec; webhook/callback on verdict.
- Batch/bulk submission and a submission-history search.
- Connectors: TheHive/Cortex, generic SIEM forwarding.
- Acceptance: round-trip export validated against STIX/MISP schemas; API contract
  tests; docs.

## 9. Phase 5 - Intelligence and learning at scale  [PLANNED]

Deepen the moat that compounds: the knowledge graph and the learning loop.

- L1 graph persistence (BoltGraph) so learned relationships survive restarts.
- Curated-corpus growth pipeline + trust-tiered ingestion from vetted OSINT
  (abuse.ch/ThreatFox-class) with provenance and poisoning gates.
- Learning tier 2 (DSPy prompt optimization) and tier 3 (LoRA fine-tune) as offline,
  gated, evaluated jobs; promotion only on a held-out set beating the incumbent.
- Calibration + drift monitoring; expanded golden set + red-team suite.
- Acceptance: every promotion is gated by an eval that runs in CI; no autonomy is
  granted without a track record.

## 10. Phase 6 - Productization and GA  [PLANNED]

Turn the platform into something an operator can run in production.

- Multi-submission throughput, a work queue, and resource governance (bounded
  concurrent jails, backpressure, per-tenant quotas).
- AuthN/AuthZ, RBAC, audit log; optional multi-tenant isolation.
- Packaging: hardened compose profiles + a Helm chart; a signed release; an upgrade
  and data-migration path; SBOM.
- Operability: health/readiness, metrics, alerting, backup/restore of the vault +
  knowledge store; runbooks.
- Performance + soak testing; an external security review; a first pilot deployment.
- Acceptance: a documented one-operator install on clean infra; a pilot user runs a
  real workload; GA checklist below is fully green.

## 11. Cross-cutting tracks (run continuously)

- Security: keep the boundary proof ahead of every new jail; periodic red-team;
  dependency + vuln scanning; supply-chain (pinned deps, SBOM, no secrets).
- Observability: self-hosted tracing/metrics; per-engine timing + failure rates.
- Performance: wall-clock + memory budgets per engine; regression guardrails.
- Docs: architecture, operator guide, analyst guide, contribution guide - kept live.

## 12. Open product-owner decisions (gate specific slices)

1. Auto-detonation vs on-request (gates Phase 2 Slice 4).
2. Whether the platform ever detonates real (non-lab) malware, and on what samples.
3. Sinkhole in v1 vs deferred (currently Slice 2).
4. Windows-guest priority vs deepening Linux dynamic first (gates Phase 3 ordering).
5. Cloud-model connector posture for shops that allow a guarded egress vs strict
   air-gap only.
6. Positioning/GTM: pure open-source vs open-core with a supported edition.

---

## 13. Delivery plan: build sessions and timeline

### How to build it perfectly (the session discipline)

- One session = one focused, shippable increment (usually one slice) that ENDS at:
  CI green + boundary/e2e proof + quality-audit clean + memory updated + pushed.
  Never leave a session with red or unverified work on the branch.
- Start every session by reading MEMORY.md + this roadmap + the target slice's
  acceptance criteria. End by updating both.
- Use sub-agents WITHIN a session for parallel or throwaway work (research, red-team,
  independent file sets in worktrees); keep the security-critical core in-session.
- Gate between phases on the open decisions above; do not build a gated slice until
  its decision is made.
- Anything that builds an image, downloads models/packages, or needs real hardware
  runs on a CLEAN network (or the target infra), not the proxied dev box. Prove those
  slices there and fold results back.

### Why more than one session

Context limits (a session holds only a few slices before it must summarize), natural
review gates (you steer between phases), external dependencies that pause work (a
clean-network run, hardware procurement, a product-owner decision), and the value of
ending each session at a clean, proven, pushed checkpoint.

### Session-by-session plan (estimate)

Each row is one focused session ending green. Estimates are solo-pace and will move
with the open decisions and the environment; the biggest variances are Phase 3
(needs hardware) and Phase 6 (needs non-code work).

| # | Session scope | Phase | Gated on | Exit criteria |
|---|---|---|---|---|
| S1 | Slice 0 live proof + detonation boundary-proof section | 2 | clean laptop | detonate-proof + boundary proof green in CI |
| S2 | Slice 1 detonation fidelity (proc tree, file ops, persistence, ATT&CK) | 2 | S1 | unit + e2e green |
| S3 | Slice 2 contained sinkhole (mal-sinkhole + internal net + boundary) | 2 | S1 | sinkhole boundary + C2-IOC e2e green |
| S4 | Slice 3 dropped-file recursion + Slice 4 auto-gate | 2 | decision #1,#2 | recursion e2e + budget test green |
| S5 | DIE engine (#16) + STIX/MISP export + IOC panel | 4 | clean build | engine boundary proof + export schema tests |
| S6 | Public API + OpenAPI + webhooks + batch submit | 4 | S5 | API contract tests green |
| S7 | L1 graph persistence + curated-corpus/OSINT ingest pipeline | 5 | none | persistence + poisoning-gate tests green |
| S8 | Learning tier 2 (DSPy) + eval-gated promotion | 5 | S7 | promotion eval in CI |
| S9 | Learning tier 3 (LoRA) offline pipeline + eval | 5 | S8, GPU | held-out eval beats incumbent |
| S10-S13 | Phase 3 detonation range: node + pump + full-system Linux guest | 3 | hardware, decision #4 | segregated-node boundary proof; Linux full-sys e2e |
| S14-S16 | Phase 3: Windows guest (image, agent, automation) + monitoring | 3 | S10-13, licensing | Windows behavioral e2e |
| S17 | Throughput, work queue, resource governance | 6 | none | soak + backpressure tests |
| S18 | AuthN/AuthZ, RBAC, audit log, multi-tenant isolation | 6 | none | authz tests + audit coverage |
| S19 | Packaging (compose profiles + Helm), SBOM, release + upgrade path | 6 | none | one-operator install verified |
| S20 | Perf/soak + external security review remediation + pilot bring-up | 6 | pilot infra | GA checklist green |

### Timeline summary (assumptions: steady solo work, clean-network access when needed)

- Phase 2 Beta of the differentiator (dynamic analysis live + useful): S1-S4,
  roughly 4-6 sessions. This is the highest-leverage next stretch.
- Reporting/interop + intelligence at scale (Phases 4-5): S5-S9, roughly 5-7
  sessions, mostly buildable on a clean network without special hardware.
- Production detonation range (Phase 3): S10-S16, roughly 6-9 sessions PLUS hardware
  procurement, a Windows licensing decision, and infra setup that is not coding
  work. This is the long pole.
- GA hardening (Phase 6): S17-S20, roughly 4-6 sessions PLUS non-code work (pilot
  user, external security review, docs polish).

Totals: about 20-25 focused build sessions to GA, front-loaded so that after ~4-6
sessions you have a demonstrable Beta of the sovereign static+AI+dynamic
platform. Phase 3 and the pilot are the items most bounded by things outside the
editor (hardware, licensing, a real user), so treat their calendar time as driven by
procurement and feedback, not build effort.

### GA definition of done

- All Phase 2-4 acceptance criteria green; Phase 3 at least Linux full-system live.
- One-operator install on clean infra, documented and reproduced by someone else.
- A pilot user runs a real workload air-gapped and signs off.
- Security review remediated; SBOM + signed release; backup/restore proven.
- The full test + boundary + e2e + audit gate green in CI on the release commit.
