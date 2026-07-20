# OpenMalLab - Components and Code Map

This is the "what actually runs today" map. It reflects the code on `main`, links
each component to its source, and tells a new contributor where to look first. If
this doc and a design doc disagree about what is built, this doc wins; if this doc
and the code disagree, the code wins (and this doc is a bug).

For the design intent behind the pieces, see [`ARCHITECTURE.md`](ARCHITECTURE.md)
(the original grand design, with an as-built banner at the top) and
[`ROADMAP.md`](ROADMAP.md) (the freshest phase-by-phase status). For the AI plane
in depth see [`AI-PLANE-INTEGRATION.md`](AI-PLANE-INTEGRATION.md).

- Status legend: **Live** = shipping and proven on `main`; **WIP** = built and
  wired but its live proof is pending; **Roadmap** = designed, not built on `main`.

---

## 1. The shape of the system

A submission crosses three trust zones. The gateway content-addresses the bytes
and never parses them. The orchestrator, a Temporal worker, walks the submission
as an artifact tree and is the only process that talks to the Docker socket. Every
engine that touches hostile bytes runs in a single-use jail; nothing an engine
emits is trusted until a separately-jailed broker validates it. Findings fold on a
fail-closed lattice, and a caged AI plane can enrich the result off the critical
path but can never move the deterministic verdict.

Diagrams: [`diagrams/pipeline.dot`](diagrams/pipeline.dot) (end to end) and
[`diagrams/agentic-plane.dot`](diagrams/agentic-plane.dot) (the AI plane).

```
analyst -> mal-gateway -> vault (content-addressed)
                       -> mal-orchestrator (Temporal) -> [jailed engines] -> mal-broker -> lattice+score
                                                       -> AgentGraphWorkflow (ABANDON child) -> HITL
        <- mal-web console / read API <----------------- verdict
```

---

## 2. Control plane (trusted; never parses hostile bytes in-process)

| Component | Code | Language | Role | Status |
|---|---|---|---|---|
| **mal-gateway** | [`services/mal-gateway/main.go`](../services/mal-gateway/main.go) | Go | Front door. Streams the upload through `sha256`, content-addresses it into the vault, starts `SubmissionWorkflow`, serves the read + queue + review API. Never inspects bytes. | Live |
| **mal-orchestrator** | [`services/mal-orchestrator/`](../services/mal-orchestrator/) | Go | The Temporal worker. `SubmissionWorkflow` walks the artifact tree, spawns every jail, re-hashes extracted children, folds findings fail-closed. The only process with the Docker socket. | Live |
| **mal-broker** | [`services/mal-broker/`](../services/mal-broker/) | Go | The single trust boundary. Strictly validates and size-caps every worker's stdout before any trusted code reads it. Runs jailed itself, with zero mounts and zero network. | Live |
| **mal-web** | [`services/mal-web/main.go`](../services/mal-web/main.go) | Go | The read-only console. Embeds a single-file SPA, reverse-proxies `/v1/*` to the gateway as one origin, sends a locked-down CSP. Holds no credentials. | Live |

Key files inside the orchestrator, worth reading in order:

- [`workflow.go`](../services/mal-orchestrator/workflow.go) - `SubmissionWorkflow`: the
  BFS tree walk (depth <= 8, <= 200 artifacts), the parallel engine dispatch, the
  content-type gating, the `fold()` that maxes severity over every finding, and the
  cross-node ingest budget.
- [`jail.go`](../services/mal-orchestrator/jail.go) - the one jail recipe
  (`jailedHostConfig`), the per-engine overrides that can only tighten, the
  create/attach/start/wait/kill/remove lifecycle, and the leaked-jail reaper.
- [`activity.go`](../services/mal-orchestrator/activity.go) - `runWorkerThroughBroker`
  (the one and only decode path: worker stdout piped as stdin into a jailed broker)
  and `ingestChild` (Lstat + regular-file + size + `O_NOFOLLOW` + re-hash before a
  byte lands in the vault).
- [`agentgraph.go`](../services/mal-orchestrator/agentgraph.go),
  [`enrichment.go`](../services/mal-orchestrator/enrichment.go),
  [`hitl.go`](../services/mal-orchestrator/hitl.go),
  [`learn.go`](../services/mal-orchestrator/learn.go) - the AI-plane workflows,
  the human-review signal/query, and the learning writeback.
- [`main.go`](../services/mal-orchestrator/main.go) - worker registration and the two
  env gates (`MAL_MODEL_URL`, `MAL_AGENTS_URL`) that wire the AI plane.

The shared verdict contract lives in
[`internal/pipeline/types.go`](../internal/pipeline/types.go): the fail-closed
`Verdict` lattice (`BENIGN < UNKNOWN < SUSPICIOUS < MALICIOUS`, monotone `Max`),
the orthogonal `Confidence` axis assigned only by trusted policy (`ConfidenceFor`),
and `ScoreFindings` (the 0-100 triage score).

---

## 3. The engines (data plane; parse hostile bytes, never execute them)

Every engine is single-use, credential-less, and jailed on the same recipe
(network none, all caps dropped, read-only root, non-root `65534`, seccomp,
bounded wall-clock and memory). Each emits one broker-validated JSON document and
fails closed: a crash or timeout floors the node to SUSPICIOUS + incomplete, never
BENIGN by omission.

| Engine | Code | Upstream | Detects | ATT&CK / mapping | Status |
|---|---|---|---|---|---|
| **mal-ident** | [`services/mal-ident/src/main.rs`](../services/mal-ident/src/main.rs) | Google Magika (ONNX, in-process) | Content-based file type; never trusts the extension | none (pure evidence; UNKNOWN unless the worker errors) | Live |
| **mal-static-yara** | [`services/mal-static-yara/src/main.rs`](../services/mal-static-yara/src/main.rs); rules in [`rules/first-party/`](../services/mal-static-yara/rules/first-party/) | VirusTotal YARA-X | Signature matches; self-describing rules carry `verdict` + `attck`; evidence includes matched strings, offsets, tags | 10 first-party rules covering T1003.001, T1027, T1027.002, T1059.001, T1059.004, T1071.001, T1204, T1505.003 | Live |
| **mal-extract** | [`services/mal-extract/src/main.rs`](../services/mal-extract/src/main.rs) | pure-Rust zip/tar/flate2 | Recursive one-level archive unpacking (zip/tar/gzip/tar.gz) | none; feeds children back for re-scan. Zip-Slip is structurally impossible (children content-addressed by sha256, entry name never used as a path); bombs capped | Live |
| **mal-capa** | [`services/mal-capa/wrapper.py`](../services/mal-capa/wrapper.py) | Mandiant capa (vivisect backend) | Capability detection; only suspicious namespaces escalate to SUSPICIOUS, and it never emits MALICIOUS alone | full ATT&CK + MBC set per match | Live |
| **mal-floss** | [`services/mal-floss/wrapper.py`](../services/mal-floss/wrapper.py) | Mandiant FLOSS (vivisect) | Static + stack/tight/decoded string recovery from PEs (two-phase budget) | none; strings are leads, always UNKNOWN, defanged downstream | Live |
| **mal-detonate** | [`services/mal-detonate/wrapper.py`](../services/mal-detonate/wrapper.py) | `qemu-<arch>-static -strace` | Dynamic behavior mined from the emulator's syscall trace (proc-exec, persistence writes, net-connect, file-delete, evasive/privileged syscalls); caps at SUSPICIOUS; a clean run is UNKNOWN | T1204, T1547, T1071, T1070, T1497 | WIP |
| mal-static-die | not created | Detect It Easy | Packer/compiler/crypto fingerprinting | T1027.002 | Roadmap |
| config extraction | not created | MACO + configextractor-py | Normalized family config / C2 extraction | - | Roadmap |

Dispatch gating (in `workflow.go`): ident and YARA run on everything in parallel;
capa runs iff the artifact is executable (`isExecutable`); FLOSS runs iff it is a PE
(`isPE`); extract always runs unless the ingest cap tripped; detonate runs iff
`detonate=true` **and** the artifact is a root ELF (`in.Detonate && Depth==0 &&
isELF`) - opt-in, root-artifact-only, ELF-only.

The `mal-detonate` worker, orchestrator wiring, `detonate=true` gateway flag, and
compose entry are all committed and unit-tested. What is pending (environment, not
code) is building the worker image on a clean network and running the live proof
(`deploy/proof/detonate-proof.sh`); this box's proxy blocks the image build. The
boundary proof does not yet have a detonation section. See
[`DYNAMIC-ANALYSIS-V1.md`](DYNAMIC-ANALYSIS-V1.md) and
[`DETONATE-HANDOFF.md`](DETONATE-HANDOFF.md).

`rules/community/` is an intentionally empty, documented slot so operators can drop
their own packs without vendoring copyleft rules into the Apache core.

---

## 4. The containment model

One recipe, defined once in
[`jail.go`](../services/mal-orchestrator/jail.go) (`jailedHostConfig` /
`jailedConfig`), reused for every engine and for the broker:

- `NetworkMode: none`; `CapDrop: [ALL]`; `SecurityOpt: no-new-privileges,
  seccomp=builtin` (never `unconfined`); `ReadonlyRootfs: true`.
- One `tmpfs` at `/scratch` (`rw,noexec,nosuid,nodev,size=64m`); `Memory` and
  `MemorySwap` both 512 MiB (zero swap headroom); `NanoCPUs` 1 CPU; `PidsLimit`
  128; private cgroup and IPC namespaces; `User: 65534:65534`; empty `Env`.
- Exactly one mount for a scan: the content-addressed sample, read-only, via
  volume-subpath at `/in/sample`. Only `mal-extract` also gets a writable `/out`.
- Per-engine overrides can only add env vars and raise memory/scratch - never
  loosen network, caps, rootfs, seccomp, user, or noexec.

The enforcement path with no exceptions (`runWorkerThroughBroker` in
[`activity.go`](../services/mal-orchestrator/activity.go)): run the jailed worker,
pipe its raw stdout as stdin into a second, separately-jailed `mal-broker`, and
strict-decode **only** the broker's stdout. The orchestrator is architecturally
incapable of decoding a worker's raw bytes directly.

The proof: [`deploy/proof/boundary-proof.sh`](../deploy/proof/boundary-proof.sh)
runs the actual built images under the jail recipe and asserts the boundary live
(48 checks across `mal-static-yara`, `mal-ident`, `mal-extract`, and `mal-broker`);
`TestJailRecipePinsTheBoundaryProof` pins the Go container-API fields to the shell
flags so the two cannot drift. CI runs it as the topology-conformance gate. The
committed receipt [`BOUNDARY-PROOF.md`](BOUNDARY-PROOF.md) is an older 35-check
snapshot and is a known doc-refresh item.

---

## 5. The AI plane (caged, untrusted analyst)

North star, enforced structurally: the AI proposes; a deterministic gate + the
lattice dispose. Turn it off (`MAL_AGENTS_URL` unset) and verdicts are identical.

| Component | Code | Role | Status |
|---|---|---|---|
| **Agent roster** | [`services/mal-agents/malagents/agents/`](../services/mal-agents/malagents/) | FastAPI + Pydantic-AI. Router + specialists (correlator, capability reasoner, IOC extractor, family hypothesizer, novelty detector, adversarial verifier, report writer, escalation) plus a legacy single-shot analyst. Speaks an OpenAI-compatible API to a local model. | Live |
| **Evidence contract + validator** | [`internal/aiplane/contract.go`](../internal/aiplane/contract.go) | `EvidenceFrom` builds the bounded, defanged projection the model sees; `Validate` is the broker-analogue for the model's proposal (bounded, unknown-field reject, closed vocabulary, malformed citations rejected). | Live |
| **Confidence gate** | [`internal/aiplane/gate.go`](../internal/aiplane/gate.go) | Inverted and downgrade-only. Accept requires an exact citation to a curated L0 fact **and** an allow-listed hypothesis kind (`capability`, `behavior`, `technique`, `ioc-context`) **and**, if graduation is wired, an earned autonomous category. Accept caps at SUSPICIOUS. | Live |
| **Autonomy graduation** | [`internal/aiplane/graduation.go`](../internal/aiplane/graduation.go) | Per-category mode: supervised -> autonomous (earned) -> shadow (auto-demoted on bad accuracy). | Live |
| **Calibration** | [`internal/aiplane/calibration.go`](../internal/aiplane/calibration.go) | Overrides the model's self-reported confidence downward; feeds the gate. | Live |
| **Ledger** | [`internal/aiplane/ledger.go`](../internal/aiplane/ledger.go) | Append-only, hash-chained handshake per interaction; `VerifyAgainst(count, head)` is the persistence-safe check. | Live |
| **Provider** | [`internal/aiplane/httpprovider.go`](../internal/aiplane/) | Sovereign-network provider; guarded-cloud requires both a non-sovereign `MAL_MODEL_URL` and `MAL_ALLOW_CLOUD=1`. | Live |

Workflows (in the orchestrator): `AgentGraphWorkflow` is the live, wired path,
started as an ABANDON child of every `SubmissionWorkflow` when `MAL_AGENTS_URL` is
set. `EnrichmentWorkflow` (single-provider, no roster) is registered and unit-tested
but is **not started automatically anywhere** - it looks superseded by the roster
path. If you are tracing the auto path, follow `AgentGraphWorkflow`, not
`EnrichmentWorkflow`.

HITL: an escalation raises a Temporal query (`pending-review`) and durably awaits a
signal (`review-decision`) for up to 7 days; the gateway relays it via
`/v1/submissions/{id}/review`. Note the `reviewSignalName`/`reviewQueryName` and
the request/decision shapes are **mirrored** (redeclared, not imported) between
[`hitl.go`](../services/mal-orchestrator/hitl.go) and the gateway - kept in sync by
convention, not a shared package. A refactor here should touch both.

Learning: [`learn.go`](../services/mal-orchestrator/learn.go) runs on every
`AgentGraphWorkflow` completion. A human `Approved` decision writes curated facts;
everything else writes only low-trust observed facts. The graph's atomic merge means
an unconfirmed auto-ingest can never overwrite a curated fact. Learning tiers 2/3
(DSPy prompt-opt, LoRA fine-tune) have the promotion gate built
([`services/mal-agents/malagents/learning.py`](../services/mal-agents/malagents/))
but the optimizer/trainer themselves are not built (see [`ASK.md`](../ASK.md)).

---

## 6. The knowledge base (deterministic memory)

[`internal/knowledge/`](../internal/knowledge/) - the AI plane's memory and the
source of truth citations are verified against.

| Tier | Code | Mechanism | Status |
|---|---|---|---|
| **L0** exact-key registry | [`registry.go`](../internal/knowledge/registry.go) | sha256-derived fact IDs, curated-vs-ingest trust tiers, atomic poisoning-guarded merge, 11 kinds. `VerifyCitation` binds a fact ID to its claimed `(kind,key)` content, fail-closed. | Live; persistent via embedded BoltDB ([`persist.go`](../internal/knowledge/persist.go)) when `MAL_KNOWLEDGE_DB` is set, else in-memory |
| **L0.5** fuzzy similarity | [`similarity.go`](../internal/knowledge/similarity.go) | 64-lane MinHash over character bigrams; reproducible, no LLM | Live |
| **L1** relational graph | [`graph.go`](../internal/knowledge/graph.go) | Bounded BFS attribution graph; `PathCurated` from a curated-only walk | Live in-memory (`MemGraph`); restart-surviving persistence is Roadmap (Phase 5) |
| **L2** semantic fallback | [`semantic.go`](../internal/knowledge/semantic.go) | Cosine nearest-neighbour; non-citable by type; confidence-lowering only | Live with a deterministic hash embedder; a real embedding model is an open ask |

Seed corpus: [`seeddata/starter.json`](../internal/knowledge/seeddata/starter.json)
- 208 curated facts (135 ATT&CK, 51 families, 22 packers), loaded by
[`seed.go`](../internal/knowledge/seed.go).

---

## 7. The console

[`services/mal-web/`](../services/mal-web/): a Go `go:embed` static server serving a
single-file SPA. A ranked triage queue (verdict then score), a recursive evidence
tree with breadcrumb paths and ATT&CK chips, a circular score gauge, and the HITL
review panel. Every specimen-derived string is inert-rendered and defanged because
the console is itself a hostile-content surface; strict CSP, no external fonts,
scripts, or calls; theme-aware. Live via `/v1/queue` and `/v1/submissions/{id}`.

---

## 8. Deployment

- [`deploy/compose.yaml`](../deploy/compose.yaml) - the control node: Postgres 16,
  Temporal (`auto-setup:1.24`), SeaweedFS and OpenBao (provisioned, not yet wired
  into a code path on `main` - the vault is still local disk), a one-shot
  `vault-init`, the hardened gateway and web, the root-only orchestrator (root only
  for the Docker socket and vault ownership), and the jailed engine images behind
  `profiles: [build]` (never `up`'d; the orchestrator spawns them per submission).
- [`deploy/compose.ai.yaml`](../deploy/compose.ai.yaml) - the opt-in AI overlay:
  `ollama` (sovereign local model server) and `mal-agents` on an `internal: true`
  no-egress network. `ollama`'s healthcheck asserts the model is present, and a
  one-time `model-bootstrap` pulls weights on the egress network before the sealed
  runtime network exists. `MAL_KNOWLEDGE_DB` on a named volume gives persistent
  curated L0 across restarts.
- Proofs in [`deploy/proof/`](../deploy/proof/): `boundary-proof.sh` (containment),
  `e2e.sh` (deterministic submit -> verdict), `e2e-live.sh` (with the AI plane and a
  model), and `detonate-proof.sh` (built, not yet run - see WIP note in section 3).

---

## 9. Where a new contributor should start

- To understand the guarantees: read [`internal/pipeline/types.go`](../internal/pipeline/types.go)
  (the lattice), then [`jail.go`](../services/mal-orchestrator/jail.go) and
  [`activity.go`](../services/mal-orchestrator/activity.go) (containment), then run
  `deploy/proof/boundary-proof.sh`.
- To add an engine: copy an existing worker's contract (one JSON document to stdout),
  add a jailed compose entry behind `profiles: [build]`, wire an activity and a
  dispatch gate in `workflow.go`, and extend the boundary proof with a documented set
  of PASS assertions. The recipe is engine-agnostic by design.
- To work on the AI plane: [`AI-PLANE-INTEGRATION.md`](AI-PLANE-INTEGRATION.md),
  then [`internal/aiplane/gate.go`](../internal/aiplane/gate.go) and
  [`internal/knowledge/registry.go`](../internal/knowledge/registry.go).
