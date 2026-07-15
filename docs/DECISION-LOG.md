# MalAnalyzer - Decision Log (build kickoff)

> The point of this file: **stop reviewing, start building.** It records the decisions that turn three rounds of design into a buildable, usable static-analysis product for a tiny team. Decisions here are ratified and in force; where they change a design doc, this log wins until the doc is updated. Dated 2026-07-14.
>
> Method note: architecture-shaping *technical* calls (e.g. D7) are put to an **independent master-practitioner agent, unbiased and outside this design context**, and the decision is recorded here - not re-litigated in another review round.

---

## D0 - Freeze the design; no Round-4. *(the #1 project-killer is the review loop)*
The single most likely way this project dies in the next 6 months is **death by review-loop + a 15-person architecture on a 1-2-person team** (master's call). Markdown has infinite surface area and no ground truth - you cannot fuzz a doc. **Moratorium: no further broad design-review rounds until running code has been used by a real analyst.** Focused expert-agent consults for a specific super-technical decision are allowed; another sweeping audit is not.

## D1 - Ratify the four M0 pins, but **pin != build**
- **ADR-021 (trust domains / per-domain dedup / domain-scoped keys)** - ratified as **schema scaffolding**: every row carries `domain_id`, `samples` PK = `(domain_id, sha256)`, Phase-1 runs **one** domain. Build the columns; **do not** build per-domain dedup machinery or the cross-domain sharing layer yet.
- **ADR-022 (DEKs in OpenBao, not WORM)** - ratified and **built** (near-free, and it's the crypto-shred/rotation lever).
- **ADR-023 (tamper-evident audit + erasure-capable derived stores)** - ratified as a **decision**; the *mechanism* (hash-chained WORM-mirrored audit, crypto-shred sweep across derived stores) is **deferred** - it serves multi-tenant/regulated/court/GDPR futures with **zero users today**. Keep the schema shape open (a `prev_hash`/`entry_hash` column can be added later without migration pain); do not build the machinery in M0.
- **ADR-024 (release engineering is its own track)** - ratified; in M0 this is **only** a 2-day reproducible-build determinism spike, not a program.

*Rationale: "do it right, not fat" means pinning the decisions that are expensive to reverse (the schema shape) while refusing to build compliance mechanisms for a product with no users. Getting the schema right != implementing every future guarantee now.*

## D2 - Re-scope Phase-1 to the **static wedge only**; detonation -> Phase-2
Phase-1 = **submit -> Magika ident -> recursive sandboxed unpack -> FLOSS/capa/DIE/YARA-X static -> MACO-normalized config/family extraction -> deterministic explainable evidence tree -> score-driven triage queue -> REST/OIDC/tamper-evident audit -> single-node containerized.** It is **copyleft-clean** (all engines Apache/BSD; no GPLv2 emulator - DESIGN-AUDIT A7 rec (i)) and has **no AI, no detonation, no network egress** by construction (removing the three hardest risk classes from v1).

**Detonation (Tier-2 KVM), the result pump, and the separate detonation node move to Phase-2.** Reason (master + Round-3 RH-14): Tier-2 in-guest is the #1 program risk, the *least* differentiated capability (everyone detonates; our own docs call it "trivially detectable"), and it's gated on a specialist and hardware we don't have. Shipping a worse open-source detonator converts nobody.

## D3 - The differentiator is **MACO config/family extraction**, pulled *into* Phase-1 - and only that
Not five features. Config/family extraction is the single highest-"aha" feature that makes CAPE sticky, it's the real "unify the scattered field" thesis, it serves the RE *and* SOC personas, and it's copyleft-clean. We do **not** reposition as a "compliance appliance" (RH-14's alternative) - that targets the slowest, smallest market, poison for adoption velocity.

## D4 - Build **hostile-boundary-first**, not spine-first
The credential-less, empty-netns worker + the bounded-schema sub-process **broker boundary** are in the **first commit**, not a later milestone. Round-3's through-line was "rigor applied to one boundary, not propagated"; we bake the containment posture in from commit 1 and thicken outward. (Repairs the M0-ordering the lead originally proposed.)

## D5 - **Minimum stateful set** for the tiny team
Postgres + Temporal (dev-server, single binary) + SeaweedFS + OpenBao + the worker. **Not** Qdrant / JanusGraph / OpenSearch / a NATS cluster yet - each is added only when a feature that needs it lands. (Postgres-FTS before OpenSearch; no vector/graph store until hunting/attribution in a later phase.)

## D6 - Kill the parallel hire / counsel / procure track *(for now)*
For a copyleft-clean static wedge with no code, no users, and no commercial edition, all three are premature spend and re-import the 15-person assumption:
- **Legal counsel** = a **ship-gate**, re-engaged when a copyleft engine (detonation/emulation/Volatility) or a commercial edition enters - not now.
- **Detonation specialist** = a **Phase-2** hire.
- **Separate detonation node** = **Phase-2** capex.
They remain named gates in `ARCHITECTURE-REVIEW.md section 8`; they are not this month's work.

## D7 - Assemblyline-4 adopt-vs-build -> **GREENFIELD (C)** *(independent master consult complete; 2-day spike to refute)*
**Decision:** build the static-wedge pipeline fresh on the already-chosen **Temporal + NATS + Postgres** substrate; **adopt the analysis engines *and MACO + `configextractor-py`* as MIT/BSD libraries** (the same upstreams AL4 itself wraps); use **Assemblyline 4 / Strelka as design references only** (extractor limit values, stateless-worker pattern, result-tree modeling) - inherit **no** platform code.
**Why (decisive):** AL4's worker has exactly two modes - *Standard* (holds a service-server credential, needs network) and *Privileged* (holds direct Redis/Datastore/Filestore credentials); **both violate invariant #5** (credential-less, empty-netns worker, orchestrator-brokered results). Adopting AL4 = forking its load-bearing core to invert its trust model **and** inheriting hard-pinned **Elasticsearch 8** (open option AGPLv3 - the stack `LICENSING-BRIEF section 6` avoids). The credential-less/empty-netns/bounded-schema-broker worker is **novel to MalAnalyzer**, so it is build-regardless - *that fact is the decision*. The differentiator (MACO/`configextractor-py`, **MIT, standalone**) is a library embed, not a reason to adopt. Durable orchestration - the real "don't reinvent it" - is supplied by Temporal (ADR-002), so greenfield here is **configuration, not invention**.
**Licensing (verified 2026-07):** AL4 = MIT, Strelka = Apache-2.0, Karton = BSD-3, MACO + `configextractor-py` = MIT (adoptable standalone; use MIT backends only, exclude CAPE-GPL parsers). All permissive/open-core-safe; the *code* is clean, but AL4's *runtime stack* (ES8/Redis/MinIO) is not - and it rides along only if you adopt, which we are not.
**Guardrail (biggest risk = under-hardened extractor / yak-shaving past 6 weeks):** never write extractors - wrap libarchive/7z/unrar with cgroup + Temporal depth/entry/size/time limits, reading AL4's MIT extract service purely as the spec for limit values; keep orchestration on Temporal (no hand-rolled durable DAG); run the section 11 extraction corpus + `mal-extract`/`mal-ident`/broker fuzzing in CI **from commit 1**; time-box Phase-1 to the common format set (the corpus defines "done").
**The 2-day spike (M0, designed to *refute* this):** Day 1 - try honestly to run a stock AL4 service `--network none` + credential-less (it cannot fetch a task); confirm the ES8 hard-pin. Day 2 - stand up the greenfield boundary-first spine and pull a MACO config from a known-family sample. *Overturn rule:* if any AL4 service runs netns-empty **and** credential-less -> revisit; if the greenfield spine can't reach a recursive explainable verdict with a credential-less/netns-empty worker in ~1 day -> reconsider vendoring AL4's extractor as a reference-port. Otherwise -> **C confirmed.** *(See `M0-FIRST-COMMIT.md`.)*

---

## Target
**A real analyst runs a real sample end-to-end within ~6 weeks.** Everything above is chosen to serve that, on a 1-2-person team, without long-term regret.
