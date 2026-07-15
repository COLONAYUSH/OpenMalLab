# MalAnalyzer - Design Audit, Round 2 (containment completeness & diagram fidelity)

> **Why this exists.** Before committing a *canonical diagram set* to the repo, the design was put through a second, independent adversarial audit whose single mandate was to **break the seven core safety claims** - not to re-review style, but to find a concrete bypass, an unstated assumption, a boundary the narrative never examines, or two documents that disagree. A diagram that depicts a lapse makes the lapse look designed-in; so the rule was: *fix the design first, then draw the truth.*
>
> Round 1 (`ARCHITECTURE.md section 8`, four-lens audit) hardened the design from v0->v1. Round 2 (this document) attacks v1. It found **four items that defeat a headline claim with a concrete mechanism** and **two internal contradictions inside single documents** - none of which were among the round-1 residuals. All are dispositioned below and reflected in the diagram set (`docs/diagrams/`).
>
> **Honesty stance (unchanged):** "no room for mistake/lapse/workaround" does not mean *zero risk* - VM escape and prompt injection are not fully solvable. It means **no unaddressed or silent path**: every finding below is either closed by a design change, or explicitly owned as a residual that names the external validation required to close it.

Disposition key: **[x] Accepted** (real gap/contradiction - design changed), **[~] Accepted-refined** (real, but narrower than stated / partially owned already), **[no] Rejected** (not a defect, with reason). Each accepted item names the **adopted resolution**, the **doc change**, and the **diagram** that makes it reviewable.

> **Superseded in part by Round-3 (`docs/ARCHITECTURE-REVIEW.md`).** A subsequent 8-lens review found that several Round-2 resolutions here were incomplete or introduced regressions: **A3** (management plane) left the job-*ingress* direction contradictory and put the detonation lease on Valkey-alone (fixed -> RC-3/RC-4); **A5** relocated the worker credential but left the worker->broker parse unhardened (-> RC-2); **A2** put out-of-band trust on the host it assumes compromised (-> RH-2); **A6/A7** transport rules contradict each other (-> RH-9, reconciled below); and the verdict lattice underlying **A2** was mis-ordered (-> RC-1, fixed). Where this document and `ARCHITECTURE-REVIEW.md` differ, **the Round-3 review wins.**

---

## 0. Verdict summary - what Round 2 changed

1. **The dead-end is a *topology* property, not a universal one.** As written, single-node Phase-1 co-locates detonation with the control plane on one kernel - so boundary (3) *does not exist there*. Now stated honestly and drawn per-tier. **(A1)**
2. **The result pump guarantees *parse-safety, not honesty*.** A compromised detonation host can forge a schema-valid *benign* result. Verdict trust now derives from **out-of-band** observation (network tap / VMI / attestation), never the in-guest agent's self-report; escape/anomaly indicators floor the run. **(A2)**
3. **The VM management/lifecycle plane is now a first-class, dead-ended channel.** Dispatch, heartbeat, lease, reconcile, and VM-kill were an unexamined second control<->detonation path. They are now detonation-plane-local and surfaced to control only by pull, so no live inbound connection or control credential exists on the detonation side. **(A3)**
4. **The pump is two processes with an owned compromise-residual.** An untrusted transport mover + a network-dead validator, each with a named, minimal credential set; pump compromise now has a residual (R8). **(A4)**
5. **Two internal contradictions fixed**: data-plane workers hold **no** store credentials (artifact in via read-only mounted fd, results out via UDS, persistence brokered by the orchestrator) **(A5/A6)**; and **copyleft workers use a GPL-compatible transport** (CLI/pipe or BSD protobuf-over-UDS), never Apache-licensed gRPC - with a **bidirectional** CI license gate **(A7)**.

---

## 1. Critical

### A1 [x] - The detonation "dead-end" does not exist at the single-node topology the whole thesis is asserted for
- **Attack/gap.** `PHASE1 section 9` brings up `mal-detonator` + live KVM VMs as `docker-compose`/Podman services on the **same host and kernel** as the gateway, orchestrator, WORM vault, and OpenBao; `section 5.2` puts QEMU on "a bare-metal or **nested-capable** host." A guest->host escape - the exact `CVE-2026-53359` nested-virt class the docs cite - lands **directly on the control plane and its keys**. This flatly contradicts `ADR-006/016` ("physically separate cluster... no route... the post-escape host can reach nothing") and `THREAT-MODEL R1` ("reach nothing trusted"). Round-1 gestured at tiering (`ADR-017`, "no `/dev/kvm` on laptops") but **no document states that all-in-one single-node provides zero escape-containment**, and R1's blast-radius claim is asserted for a Phase-1 that cannot deliver it.
- **Assessment.** Correct and important. This is the platform's central promise failing silently at its most common deployment.
- **Adopted resolution.** The dead-end is documented and drawn as a **per-topology** property:
  - **Escape-containment requires the detonation plane to be a *separate physical node/cluster*** (own kernel, own management network, no route/creds to control). This holds at **Team** (>=1 dedicated bare-metal detonation node) and **Enterprise** (out-of-band detonation controller).
  - **All-in-one single-node is dev/eval or Tier-1-emulation/`simulated`-net only** - it is explicitly labelled **not escape-contained**, and its use for escape-risk samples is a documented operator decision, not a silent default. Phase-1's *reference* deployment is therefore "**single control node + one separate detonation host**," not one box.
- **Doc change.** `ADR-017` amendment; `PHASE1 section 0/section 9` caveat; `THREAT-MODEL R1`/new **R10**. **Diagram:** `08-deployment-tiers` (per-tier overlay: at Solo/all-in-one, control+detonation share one kernel and boundary (3) is absent).

### A2 [x] - A compromised detonation host forges a schema-valid *benign* result -> false clean verdict (the pump checks shape, not honesty)
- **Attack/gap.** `R1` already concedes an escaped sample owns the detonation host until reflash. That host writes the run's canonical result into the det-local store the pump pulls. `mal-pump` validates size/type/regex/field-allow-list/artifact-hash-exists (`PHASE1 section 2.2`) - **none of which is an authenticity check**. The owned host authors a fully benign, schema-valid result for its `run_id`; the pump faithfully delivers the lie; the orchestrator trusts that node's local verdict in its monotone-max. For a **static-clean sample whose only malice is dynamic** (packed dropper), this finalizes **BENIGN**. Fail-closed floors on crash/timeout/truncation - **not** on "completed, quietly benign." Verdict integrity (asset A2) was never linked to a detonation escape.
- **Assessment.** Correct, and the sharpest finding. Monotone-max prevents a benign result from *masking* an already-flagged malicious node, but it does **not** protect the case where detonation is the *only* possible signal and that signal is attacker-authored.
- **Adopted resolution - out-of-band trust:**
  - **A detonation run's self-reported (in-guest agent) result is advisory, from an untrusted producer.** Authoritative behavioral evidence is **out-of-band**: the **passive network tap / sim-net appliance** (in its own namespace, not guest-writable), **Tier-3 agentless VMI** (DRAKVUF), and **host attestation / snapshot-diff**. These an escaped guest cannot forge.
  - **Any escape/anomaly/anti-analysis indicator floors the run to `MALICIOUS`** (and floors **co-resident concurrent runs** to `SUSPICIOUS` - see A9). A "completed benign" run carrying escape indicators is **never benign**.
  - **A benign in-guest result cannot *lower* a verdict.** For a static-inconclusive sample, an uncorroborated benign detonation yields **`UNKNOWN` + `analysis_incomplete`**, not `BENIGN`. Only out-of-band-corroborated benignity contributes benign.
  - **Phase-1 honesty:** with Tier-2 in-guest only (no VMI), behavioral trust rests on the **network tap + host integrity**; a clean escape that also suppresses network activity is a **named residual (R9)**, closed by Tier-3 VMI in Phase-2 and by pen-test validation.
- **Doc change.** `ADR-003/006/010` amendments; `PHASE1 section 5.2/section 5.3/section 7`; new **R9**. **Diagram:** `04-result-pump-pipeline` (result inherits producer trust) and `06-dag-aggregation` (escape-indicator floor; benign never lowers).

---

## 2. High

### A3 [x] - The VM management/lifecycle plane bypassed the pump and was never security-specified
- **Attack/gap.** Dispatch, Temporal **heartbeats** (`section 3`), kill-hung-VM, the **reconciler** ("Valkey leases <-> live libvirt domains," `section 5.2`), and the **slot lease/semaphore** imply control<->detonation channels that do **not** traverse the pump. Either (a) the detonation-side activity worker holds a **Temporal/Valkey credential or route** -> "no route/no creds" violated outright; or (b) it is control-side and a compromised `libvirtd`/guest-agent attacks the control plane's **libvirt RPC client** - a rich parser - **outside** the pump's sandbox. The threat model draws only the dispatch edge.
- **Assessment.** Correct - the single biggest blind spot. The containment story protected the *result path* and silently omitted the *management path*.
- **Adopted resolution - dead-end the control loop too:**
  - The **detonation plane runs its own control loop**: a detonation-plane-resident controller/supervisor with its **own** lease store (its own Valkey) and its **own** libvirt clients. **No control-plane process holds a libvirt/Temporal/Valkey credential or route into detonation, and none is held on the detonation side into control.**
  - **Cross-plane interaction is exclusively store-and-forward through the pump:** control enqueues a job to the pump's **outbound spool**; the detonation controller **pulls** it. Progress/heartbeat/slot-state/results are written to the **det-local store**; control **pulls** a validated projection via the pump. "Heartbeat" becomes *"detonation writes liveness to its local store; control pulls status"* - **no live inbound connection into control, ever.**
  - The **reconciler runs detonation-side** (reconciles det-local leases <-> det-local libvirt). Control's view of slots is a pulled, schema-validated projection, not a live query.
- **Doc change.** `ADR-006/007/016` amendments; `PHASE1 section 3/section 5.2` rewritten to detonation-local orchestration; `THREAT-MODEL` boundary (3) expanded. **Diagram:** `03-detonation-deadend` draws **every** control<->detonation edge (dispatch, heartbeat, lease, reconcile, kill) with initiator/direction/credential and "through-pump-or-not"; any live inbound would be drawn barred.

### A4 [x] - The pump is a single straddling component with credentials on both planes; compromise had no residual, and "network-dead yet emits to the orchestrator" is self-contradictory
- **Attack/gap.** The pump reads the detonation store, **writes the control WORM vault**, and emits to the orchestrator - while `section 5.3` calls it a "network-dead process." That is only reconcilable if the pump is **two** processes; the split was never drawn. If the single pump falls to a parser bug fuzzing missed, it pushes arbitrary schema-valid records **and** lands bytes in the vault. Boundary (4) lists "RCE prevented by validation," never the **blast radius if prevention fails**.
- **Assessment.** Correct.
- **Adopted resolution - two processes, least privilege, owned residual:**
  - **Mover (untrusted transport):** speaks to the det-local store to **pull** bytes into a **quarantine spool**; holds **no** control-plane credential and **cannot** reach the orchestrator or vault. Its only output is "bytes written to the quarantine spool."
  - **Validator (network-dead):** reads the quarantine spool over a local pipe/fd, validates in an **unprivileged, seccomp-strict, no-network** sandbox, and on success emits the canonical record to the orchestrator and copies artifact bytes to WORM - **after** validation. It has no route back to detonation.
  - **Blast radius if the validator falls** is an **owned residual (R8)**: continuous fuzzing + the two-process split + strict schema keep it bounded; a hardware diode remains the highest-assurance option.
- **Doc change.** `ADR-007` amendment; `PHASE1 section 5.3` split; new **R8**. **Diagram:** `04-result-pump-pipeline` draws mover vs validator, each credential, and the "if validator compromised" annotation.

### A5 [x] - Internal contradiction: workers have direct write-edges to Postgres/vault, yet the contract puts them in an empty netns with no credentials
- **Attack/gap.** `PHASE1 section 1` draws `ID & EX & ST --> PG` and `--> OBJ`, but `section 2.1` says a worker "may **never** open the network, write outside its scratch" and `section 5.1` joins every worker to an **empty netns (no loopback)**. A libarchive/7-Zip/unrar RCE (expected per `ADR-004`) in a worker holding vault/PG creds could tamper `findings`, **poison the content-hash-keyed decompiler cache** (`ADR-011`) to downgrade future re-analysis, or fill the vault. No data-plane-worker-escape residual existed.
- **Assessment.** Correct - a genuine contradiction with a real consequence, and the diagram edges are physically impossible under the stated sandbox.
- **Adopted resolution.** **Workers hold no control-plane store credentials.** All findings/children persistence is **brokered by the orchestrator**: a worker returns `AnalyzeResult` over a **mounted Unix domain socket** to an orchestrator-side broker, which performs all writes. The `section 1` worker->PG / worker->OBJ edges are deleted. New residual for worker escape (**R12**) bounded by single-use + tenant-partition + no-creds.
- **Doc change.** `PHASE1 section 1` diagram corrected; `ADR-005` amendment. **Diagram:** `10-phase1-components` (no worker->store edges; broker writes) and `01-system-planes` (worker store access is *read-one-artifact* only).

### A6 [x] - "Empty netns" is irreconcilable with a gRPC contract + "signed fetch URL" as written; the byte-in/result-out mechanism was undefined
- **Attack/gap.** `section 2.1` has every worker implement `service Engine` over **gRPC** and take `artifact_ref = "signed fetch URL"`; `section 5.1` gives them **no network interface at all**. A no-network worker cannot resolve a URL or serve gRPC over TCP.
- **Assessment.** Correct - under-specified I/O at the most security-sensitive boundary.
- **Adopted resolution.** The artifact arrives as a **read-only mounted file descriptor** (a sidecar in a *different* namespace fetches the content-addressed bytes and mounts them; the worker never resolves a URL); the transport is **gRPC/protobuf over a mounted Unix domain socket**, not TCP. The "signed single-use URL" is a **sidecar-facing** handle, never worker-facing.
- **Doc change.** `ADR-004/005`, `PHASE1 section 2.1/section 5.1` clarified. **Diagram:** `10-phase1-components` (mounted-fd in, UDS out).

### A7 [x] - The uniform gRPC contract collides with copyleft isolation; the CI license gate is one-directional
- **Attack/gap.** gRPC-core / grpc-go are **Apache-2.0**. `ADR-019` forbids copyleft workers from linking Apache helpers *because Apache-2.0 <-> GPLv2 is incompatible* - yet `ADR-004/section 2.1` mandate the **same gRPC contract for every worker**, including GPLv2 engines (Qiling; Speakeasy->Unicorn). The gate only fails on "disallowed license entering the **core**" - it would **not** catch **Apache (gRPC) entering a GPLv2 worker** (incompatibility is bidirectional). Compounding: Phase-1 shellcode analysis (P0) cites **Speakeasy**, pulling **Unicorn GPLv2 into Phase-1**, a phase treated as copyleft-light.
- **Assessment.** Correct. (Verified: gRPC = Apache-2.0; protobuf = BSD-3; FSF lists Apache-2.0 incompatible with GPLv2.) `ADR-004` already offers an HTTP/JSON alternative - but never says copyleft workers **must** use it and never makes the gate bidirectional.
- **Adopted resolution.**
  - **Transport per license class:** the permissive core uses Apache gRPC; **copyleft workers use a GPL-compatible transport** - CLI/pipe (subprocess + bytes/JSON on stdio) or **hand-framed protobuf-over-UDS message-only, no gRPC `service` stubs** (protobuf runtime is BSD-3), **never** Apache gRPC. This *strengthens* the process-separation/aggregation argument. **R3 RH-9:** this is an explicit *exception* to A6's "uniform gRPC contract" (`PHASE1 section 2.1`) - the uniform-`service`-over-gRPC rule applies to **permissive workers only**; the copyleft seam is deliberately non-uniform. Diagrams 09 (copyleft = "NOT Apache gRPC") and 10 (worker results "via UDS") must be read with this split; a developer must not reach for `grpcio`/`grpc-go` (Apache) in a GPLv2 worker. Moot for Phase-1 if emulation is deferred (rec (i)).
  - **CI gate is bidirectional:** it fails on copyleft entering the core **and** on Apache/incompatible licences entering a copyleft-isolated worker.
  - **Phase-1 Speakeasy/Unicorn:** flagged as a **scoping decision (needs your call + counsel):** either (i) Phase-1 shellcode analysis avoids emulation-via-Unicorn (permissive static/heuristic only) and defers Speakeasy/Qiling emulation to when the GPLv2-isolated worker + transport exist, **or** (ii) ship the emulation worker as a GPLv2-isolated component *from Phase-1* with the GPL-safe transport. Recommendation: **(i)** - it keeps Phase-1 genuinely copyleft-light and matches the "Tier-1 emulation is Phase-1.5+" intent.
- **Doc change.** `ADR-004/019`, `LICENSING-BRIEF section 3` (add the transport question to Q2), `PHASE1 section 0` non-goal note. **Diagram:** `09-licensing-isolation` (transport per class; bidirectional gate).

---

## 3. Medium

### A8 [~] - The "detonation warranted?" gate is undefined and can lock in a false BENIGN
- **Gap.** `PHASE1 section 3` has a `detonation warranted?` branch with no policy. A sample that evades **static** analysis (overlay/appended data past the archive EOCD, stego, an unrecognized container the extractor parses cleanly **with no truncation flag**) produces no malicious node, is deemed "not warranted," and finalizes clean. Fail-closed covers crash/timeout/truncation/cap - **not** "extractor completed successfully but surfaced nothing." Adjacent to `R5` (zero-signal) but distinct: signal **structurally suppressed by an extractor blind spot** with no flag.
- **Assessment.** Correct; partially adjacent to R5.
- **Adopted resolution - fail-toward-detonation on doubt.** The warranting gate is fail-closed: **static-inconclusive (`UNKNOWN`, or any not-clearly-benign) routes to dynamic analysis**, subject to slot admission; if a slot is unavailable the submission is stamped `analysis_incomplete`, never silently closed benign. An **`unanalyzed_region`** flag (overlay / high-entropy tail / unrecognized container) is a **distinct suspicion signal** separate from `truncation`.
- **Doc change.** `ADR-003`, `PHASE1 section 3`. **Diagram:** `05-dataflow-lifecycle` (warranting as explicit fail-closed gate; `unanalyzed_region` flag).

### A9 [x] - Concurrent detonation runs' mutual isolation was unspecified (cross-run result poisoning)
- **Gap.** "Own object store **wiped between runs**" reads as **one shared** store, yet the slot semaphore is "sized to physical VM slots" (plural, concurrent). A shared det store / shared bridge lets one escaped run read or overwrite a peer run's artifacts/results before the pump pulls them - feeding A2.
- **Adopted resolution.** **Per-run isolation inside detonation:** each slot gets its **own** result-store prefix/dataset and its **own** network bridge/netns; no concurrent run can reach another's storage or network. "Wiped between runs" applies per-slot. A run's escape indicators floor its **co-resident** runs to `SUSPICIOUS` (A2).
- **Doc change.** `ADR-006`, `PHASE1 section 5.2`. **Diagram:** `03-detonation-deadend` (per-run store + per-run bridge).

### A10 [x] - Phase-1's only tier (Tier-2 in-guest) is the sandbox the platform itself criticizes; no floor for a dormant run; guest-agent unhardened
- **Gap.** `FEATURE-SPEC` condemns in-guest hooking; Phase-1 ships exactly that with VMI escalation deferred. A sample that detects Tier-2 and no-ops yields a `completed`, benign run. The in-guest agent ("inject sample," `section 5.2`) is an explicit guest->host channel of unspecified hardening.
- **Adopted resolution.** A **fail-closed floor for anti-analysis:** a run that is suspiciously quiet / exits immediately / trips known sandbox-detection heuristics is floored to **`SUSPICIOUS` + `potential_evasion`**, never benign. The **guest agent is a named guest->host attack surface**: minimal, one-way command channel, no host filesystem/clipboard, treated as untrusted; its host-side endpoint is in the detonation plane (dead-ended per A3). Residual **R9** owns the in-guest-trust limitation until Tier-3 VMI.
- **Doc change.** `ADR-006`, `PHASE1 section 5.2/section 7`. **Diagram:** `03-detonation-deadend` (guest-agent surface) and `06-dag-aggregation` (low-activity floor).

### A11 [~] - "Never deserialized in the orchestrator" is over-claimed; Temporal deserializes the canonical schema on every replay
- **Gap.** The validated record is a Temporal activity input/output persisted in history (Postgres-backed) and deserialized by the SDK in the control plane repeatedly. It is *safe* (bounded, no pickle/`Any`) but the invariant wording is wrong. Also unspecified: a schema-valid-but-**oversize** record vs. Temporal's payload/history limits.
- **Assessment.** Correct wording defect; the security property holds, the claim was imprecise.
- **Adopted resolution.** Invariant #4 reworded: *"Only the bounded canonical schema crosses, and it is **safely deserialized** (flat, size-capped, no pickle / no protobuf `Any` / no nested arbitrary objects) - never a complex-object deserialization."* The **schema's caps are set <= Temporal's payload limit**; an oversize canonical record is a **validation failure -> fail-closed** (run flagged, not truncated-and-accepted).
- **Doc change.** `PHASE1 section 7` (#4), `section 2.2`, `ADR-007`. **Diagram:** `04-result-pump-pipeline` (canonical record -> Temporal history; size cap <= Temporal limit).

### A12 [x] - Air-gapped signature/key **revocation** was unaddressed
- **Gap.** `ADR-020` threshold/witness co-signing prevents single-key **forgery**, but a validly-issued signing key that later **leaks** cannot be revoked to air-gapped sites (no reachable CRL/OCSP); until a sneakernet update arrives, bundles signed with the leaked key verify cleanly. `R6` covers dependency/model poisoning, not offline revocation propagation.
- **Adopted resolution.** The **trust root and a signed revocation list are first-class, sneakernet-delivered artifacts** with their own verification and a **monotonic epoch**; deployments **fail-closed** on bundles signed older than their latest known revocation epoch, and enforce a **max-staleness** policy (refuse updates if the revocation feed is too old). New residual **R11** (propagation latency is bounded, not zero).
- **Doc change.** `ADR-020`; new **R11**. **Diagram:** `11-supply-chain-offline` (revocation/trust-root as a signed sneakernet artifact; fail-closed on epoch).

### A13 [~] - AI quarantine: the quarantined model's output still steers the planner; "deterministic entailment" under-specified
- **Gap.** The planner never sees raw bytes but consumes **schema-constrained values derived from** hostile content (C2 domains, config keys); those values choose which per-case tools run on which arguments. The real control is the **blast-radius cap** (no cross-case/tenant/egress tools), not "planner uninfluenced." A truly *deterministic* entailment verifier over free-form NL is hard; if it degrades to string-matching it is evadable.
- **Assessment.** Blast-radius already owned (`R4`/`ADR-010`); the *framing* ("planner never sees bytes => safe") over-claims, and the entailment mechanism is under-specified.
- **Adopted resolution.** Reframe: quarantine **caps blast radius**; it does not make the planner uninfluenced. The quarantined->planner channel carries **attacker-influenced schema values**, so the planner's authority (tool set) is the control - drawn as a **strict subset** with cross-case/tenant/egress tools **visibly absent**. The entailment verifier is specified as **structured** (claim->cited-evidence must match on typed fields/spans), not free-form NL inference, and "cited-but-unsupported" is rejected. (Phase-2; ships only after its own adversarial eval - `R4`.)
- **Doc change.** `ADR-010` clarification. **Diagram:** `07-ai-quarantine`.

### A14 [~] - Forced truncation downgrades `MALICIOUS`->`SUSPICIOUS`, evading automation keyed on `MALICIOUS`
- **Gap.** "Never BENIGN" holds, but if a malicious payload sits in a cap-blown branch, that branch floors at `SUSPICIOUS`, not `MALICIOUS`; downstream auto-blocking keyed only on `MALICIOUS` is evaded.
- **Adopted resolution.** `analysis_incomplete: potential_evasion` is defined as a **blocking-severity signal in its own right** - `SUSPICIOUS`-by-truncation is **not** "allow pending review." Response-policy coupling stays out of scope, but the floor semantics are now explicit.
- **Doc change.** `ADR-003`, `PHASE1 section 7`. **Diagram:** `06-dag-aggregation`.

## 4. Low

### A15 [~] - Detonation host L3 presence on the sim-net bridge was unspecified
- **Gap.** If the host holds an interface on the malware-facing bridge to run `mal-simnet`/capture, the VM may reach the host at L3 - contradicting "no route to the host."
- **Adopted resolution.** `mal-simnet` runs as a **separate netns/appliance** with **no L3-reachable host presence** on the malware-facing bridge; capture is a **passive tap** (out-of-band, guest-unwritable - this is also the trustworthy evidence channel for A2).
- **Doc change.** `PHASE1 section 5.2`. **Diagram:** `03-detonation-deadend`.

---

## 5. Cross-document inconsistencies corrected

| # | Inconsistency | Fix |
|---|---|---|
| 1 | Workers write PG/vault (`PHASE1 section 1`) vs. empty-netns/no-creds (`section 2.1/section 5.1`) | Delete worker->store edges; orchestrator brokers writes (A5). |
| 2 | gRPC-for-all-workers (`ADR-004/section 2.1`) vs. "copyleft may not link Apache" (`ADR-019`) | Transport per license class; bidirectional gate (A7). |
| 3 | `FEATURE-SPEC` still states deleted anti-patterns: **UI-parity / "whole platform over MCP"** (section 3.8/section 4), **"explicit per-case consent"** cloud routing (section 4), **"VLAN'd" analysis net** (section 5) | Corrected in-place to match `ADR-010/014/007` (MCP = smaller per-case subset; two-person "accepted exfiltration," not a consent click; air-gap = no route, not a toggle). |
| 4 | Detonation "own bus" (`ARCH`) absent in Phase-1 `section 1` (pump dispatches straight to `mal-detonator`) | Phase-1 uses detonation-local orchestration; "own bus" property labelled Team/Enterprise (A1/A3). |
| 5 | `THREAT-MODEL` boundary diagram draws only the dispatch edge, never the result-pull or management channels | Boundary (3) expanded to all channels (A3). |
| 6 | "Pump is network-dead yet emits to orchestrator" (`section 5.3`) | Two-process split makes it literally true (A4). |

---

## 6. Updated residual-risk register (Round-2 additions)

| ID | Risk | Sev | Owner control | Needs (external validation) |
|----|------|-----|---------------|------------------------------|
| **R8** | `mal-pump` **validator** compromise -> forged records + vault writes | High | two-process split, least-privilege, continuous fuzz, schema caps | pen test of the pump; hardware-diode option for highest assurance |
| **R9** | Phase-1 **in-guest** detonation trust: clean escape that suppresses network activity yields no signal | High | out-of-band tap + host integrity, anti-analysis floor, benign never lowers verdict | Tier-3 VMI (P2); red-team of escape-with-quiet-network |
| **R10** | **All-in-one single-node** has no escape-containment (shared kernel) | High | documented not-contained; reference deploy = separate detonation host | operator guidance; block escape-risk samples on all-in-one |
| **R11** | **Offline key revocation** latency (leaked valid key usable until sneakernet update) | Med | signed revocation list + monotonic epoch + max-staleness fail-closed | revocation-propagation runbook + drill |
| **R12** | **Data-plane worker** escape (C-lib parser RCE) | Med | single-use, tenant-partitioned, empty netns, no store creds, brokered writes | continuous fuzz (section 11); worker-escape red-team |

*(R1-R7 remain as in `THREAT-MODEL.md`; R1 is narrowed by A1 - its "reaches nothing" claim now scoped to the separate-node topology.)*

---

## 7. Decisions that need your sign-off or external validation

1. **Phase-1 detonation topology (A1).** Adopted: reference deployment is *control node + one separate detonation host*; all-in-one single-node is dev/eval/Tier-1-sim only. **Confirm** this is acceptable for Phase-1 (it raises the minimum hardware footprint).
2. **Phase-1 shellcode emulation (A7).** Recommended: **drop Speakeasy/Unicorn from Phase-1** (permissive static/heuristic shellcode only; emulation -> Phase-1.5 with GPLv2 isolation). **Confirm** vs. shipping a GPLv2-isolated emulation worker from Phase-1.
3. **Already-known external validations (unchanged, now reinforced):** independent **pen test / red team** of the escape->pivot path (R1/R9), **legal counsel** on `LICENSING-BRIEF` (now incl. the gRPC/transport question), **tested DR restore** (R7), **AI adversarial eval** before Phase-2 AI (R4).

**Net:** the round-1 containment narrative was strong on the two boundaries it featured (result pull-path and parser sandbox). Round 2 closed the boundary it *didn't* examine (**the VM management/lifecycle plane**), corrected a place where a guarantee was trusted for a property it never provided (**verdict honesty from a compromised detonation host**), and made the **topology-dependence of the dead-end** explicit. The diagram set (`docs/diagrams/`) is drawn against this corrected design - it depicts what is true, including where a boundary is *absent*.
