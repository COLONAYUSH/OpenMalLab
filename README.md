```
 #####  ####   ##### #   #    #   #  #####  #      #      #####  ####
 #   #  #   #  #     ##  #    ## ##  #   #  #      #      #   #  #   #
 #   #  ####   ####  # # #    # # #  #####  #      #      #####  ####
 #   #  #      #     #  ##    #   #  #   #  #      #      #   #  #   #
 #####  #      ##### #   #    #   #  #   #  #####  #####  #   #  ####

              [ Open Mal Lab ]

           open source, air-gap-first malware analysis
              built containment-first, from commit one
```

OpenMalLab takes a suspicious file and tells you what it really is, with the evidence to back every word, without ever letting the file touch anything it shouldn't. It runs fully offline, it is self-hostable, and it is built so that the malware you are studying can never reach out of the box you put it in.

Most of what you need to analyze malware already exists. The problem is it lives in thirty different tools, half of them cloud-only and priced for enterprises, the other half single-purpose open source projects you have to stitch together yourself. Nobody has put deep static analysis, config extraction, and an explainable verdict into one self-hostable product that you can actually run in an air-gapped lab with a containment story you would stake your network on. That is what we are building.

> Status: pre-M0, scaffolding. The design is done and frozen. We are starting to build. This README is the plan.

---

## What ships first (Phase 1, the static wedge)

No detonation, no AI, no network egress. That is a deliberate choice, not a limitation. Those three are the hardest things to get right and the easiest to get wrong, so we ship a complete, useful product without them first, and add them once there is a team to run them safely.

Here is the whole Phase 1 flow:

```
  you submit a file
         |
         v
  +---------------------------------------------------------------+
  |  CONTROL PLANE   (trusted, never parses raw hostile bytes)    |
  |                                                               |
  |    gateway  ---->  orchestrator (Temporal)  ---->  broker     |
  |    auth, audit     workflows, caps, verdict      decodes      |
  +---------------------------------------------------------------+
        |  dispatch                          ^  results come back as a
        v                                    |  bounded schema over a unix
  +--------------------------------+         |  socket, decoded inside an
  |  DATA PLANE                    |---------+  unprivileged sandbox, never
  |  single-use workers            |            in a trusted process
  |  no credentials                |
  |  empty network namespace       |
  |  capa  FLOSS  DIE  YARA-X  MACO |
  +--------------------------------+

  Phase 2 adds a DETONATION PLANE that is physically dead-ended:
  its own kernel, its own network, no route or credentials back to control.
```

1. Submit a file through the API.
2. Identify what it actually is with Magika, never trusting the extension.
3. Recursively unpack it inside a sandbox (archives, embedded objects, dropped payloads), with hard limits so a zip bomb or a traversal trick goes nowhere.
4. Run the static engines: capa for capabilities mapped to ATT&CK, FLOSS for hidden strings, DIE for packer and format fingerprinting, YARA-X for rules.
5. Pull the config and family out with MACO-normalized extraction. This is the part that makes it worth switching to.
6. Roll everything up into a deterministic verdict where every single point links back to the finding, the engine, and the ATT&CK technique that earned it.
7. Land it in a score-driven triage queue with an evidence tree you can actually read.

---

## Why it is different

- **Air-gap-first, not air-gap-eventually.** The whole pipeline runs with zero internet. Every external call is opt-in and audited, never a dependency. Uploading a sample to a cloud service tips off the adversary and leaks your data, so we just do not.
- **Containment is the product, not a setting.** Every worker that touches hostile bytes is single-use, holds no credentials, and lives in an empty network namespace with no interfaces at all. The file arrives as a read-only mounted fd. Results leave as a bounded schema over a unix socket and get parsed by an unprivileged sandboxed sub-process, never by a trusted one.
- **Fail closed, always.** No input ever comes back clean just because analysis got interrupted, truncated, or capped. Unknown is not benign. A crash raises suspicion, it does not lower it.
- **Explainable by construction.** There are no black-box scores. Every point in a verdict cites at least one piece of evidence. If we cannot show you why, we do not claim it.
- **One platform, not thirty.** Deep static analysis, config extraction, and case-ready verdicts in a single self-hostable thing, on hardware you control.

---

## Architecture

Three strongly isolated planes. A control plane that is trusted and never runs or parses raw hostile bytes in a privileged process. A data plane that parses hostile bytes but cannot execute them and cannot reach the network. And, in Phase 2, a detonation plane that actually runs malware and is dead-ended so that a full escape reaches nothing.

![System planes and trust architecture](docs/diagrams/render/01-system-planes.png)

The rule we hold ourselves to: if a path is not drawn, it is not reachable. The diagrams are the spec, and there are conformance tests that fail the build if the running system grows an edge the diagrams do not show.

Full, rendered, audited diagrams live in [docs/diagrams/](docs/diagrams/):

| Diagram | What it shows |
|---------|---------------|
| [System planes](docs/diagrams/render/01-system-planes.svg) | The master map and every legitimate crossing |
| [Trust boundaries](docs/diagrams/render/02-trust-boundaries.svg) | All eight boundaries with STRIDE threats and controls |
| [Detonation dead-end](docs/diagrams/render/03-detonation-deadend.svg) | Phase-2 containment and the management plane |
| [Result pump](docs/diagrams/render/04-result-pump-pipeline.svg) | The two-process, write-only result path |
| [Sample lifecycle](docs/diagrams/render/05-dataflow-lifecycle.svg) | End to end, with a fail-closed gate at every step |
| [Verdict aggregation](docs/diagrams/render/06-dag-aggregation.svg) | Why no input can turn a malicious sample clean |
| [AI quarantine](docs/diagrams/render/07-ai-quarantine.svg) | The Phase-2 dual-LLM design |
| [Deployment tiers](docs/diagrams/render/08-deployment-tiers.svg) | Solo, team, enterprise, and where containment holds |
| [Licensing isolation](docs/diagrams/render/09-licensing-isolation.svg) | How the Apache core stays clean |
| [Phase-1 components](docs/diagrams/render/10-phase1-components.svg) | The buildable static wedge |
| [Supply chain](docs/diagrams/render/11-supply-chain-offline.svg) | Offline builds, signing, revocation |

---

## The security model

This is a tool that eats hostile input for a living, so its own security is the first feature, not the last.

- **Single-use workers.** One artifact per worker, then it dies. A worker compromised by one sample never sees another.
- **No credentials in the blast radius.** Workers hold no store credentials. All persistence is brokered by the orchestrator. A worker that gets popped cannot write to the vault, the database, or anything else.
- **Empty network namespace.** Not a firewall rule, not a filtered egress. The worker has no network interface at all, not even loopback. Network access is impossible, not merely blocked.
- **A bounded boundary, parsed safely.** Results cross as a flat, size-capped, allow-listed schema. No arbitrary object deserialization. The orchestrator-side broker decodes it in an unprivileged, seccomp-strict, network-dead sub-process before anything trusted sees a byte.
- **Fail closed everywhere.** Crash, timeout, truncation, cap hit, or a malformed result all floor the outcome to suspicious or unknown, never clean.
- **Tamper-evident audit.** The audit log is hash-chained and mirrored to write-once storage, so a privileged insider cannot quietly rewrite history.

The full threat model, with STRIDE per boundary and attack trees, is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). The design was put through three rounds of adversarial review, including an eight-lens one that tried hard to break it; the findings and how each was handled are in [docs/ARCHITECTURE-REVIEW.md](docs/ARCHITECTURE-REVIEW.md). We do not claim it is bulletproof. We claim there is no silent path, every residual risk is named and owned, and the big claims are gated behind an external pen test before we make them.

---

## The AI layer (Phase 2)

AI here assists, it never decides. When it lands, it is built so that a prompt-injection buried in a sample cannot turn it into an exfiltration tool or a false verdict.

- A quarantined model reads the hostile content and returns only schema-constrained values. A separate privileged planner drives tools but works from those constrained values.
- The planner's authority is deliberately smaller than a human's. No cross-case, cross-tenant, global, or egress tools in any context that has touched sample bytes. That is what actually caps the blast radius.
- Local-first by default so samples never leave. Any cloud call is a logged, two-person, out-of-band action, and it is impossible at all in air-gap mode.
- The AI output is never a field in the scored verdict. Deterministic engines alone produce the verdict. The AI writes advisory notes next to the evidence, clearly labeled.

Design detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (ADR-010) and [docs/diagrams/render/07-ai-quarantine.svg](docs/diagrams/render/07-ai-quarantine.svg).

---

## Roadmap

We build in phases, and each phase is a real product on its own.

**Phase 1, the static wedge (now).** Ingest, identify, recursive sandboxed unpack, the static engines, MACO config extraction, a deterministic explainable verdict, and a triage queue. Single node, single tenant, fully offline. This is what we are building first.

**Phase 1.5.** Ghidra as a crash-isolated service, full Volatility memory forensics, an interactive analyst view, full-text search at scale, and the first quarantined local-AI extraction.

**Phase 2.** The detonation plane: multi-tier, anti-evasion, physically dead-ended. Hunting and retrohunt over your own corpus, code-reuse attribution, the threat-intel graph, case management, the guardrailed AI assistant, and hard multi-tenancy.

**Phase 3.** The frontier stuff: sound LLM-plus-IR script deobfuscation, a generic unpacker, symbolic execution, a STIX knowledge graph, and a natural-language investigation agent scoped tightly to a single case.

The reasoning behind the cut (why detonation is Phase 2 and not Phase 1, why the static wedge is the right first product) is in [docs/DECISION-LOG.md](docs/DECISION-LOG.md).

---

## Tech stack

Chosen for correctness, offline operability, and a permissive-license core.

- **Orchestration:** Temporal for durable workflows, retries, timeouts, and safe recursion. It does the genuinely hard distributed-systems work so we do not hand-roll it.
- **Languages:** Rust at the hostile-input boundary (identification, extraction), Go for the control plane, Python for the analysis engines, TypeScript and React for the UI.
- **Engines:** Magika, capa, FLOSS, DIE, YARA-X, and MACO with configextractor-py, all wrapped as libraries, all permissively licensed.
- **State (kept deliberately small):** PostgreSQL, Temporal, SeaweedFS for object storage, and OpenBao for secrets. No message-bus cluster, no vector or graph store, until a feature actually needs one.
- **Crypto:** per-sample keys wrapped by a per-domain key, so key rotation is cheap and lawful erasure is actually possible.

---

## Repo layout

```
services/
  mal-gateway/       Go    submit API, OIDC, OPA, tamper-evident audit
  mal-orchestrator/  Go    Temporal workflows, recursion caps, aggregation, the result broker
  mal-ident/         Rust  Magika file identification
  mal-extract/       Rust  recursive path-safe unpack (wraps libarchive, 7z, unrar)
  mal-static/        Py    capa, FLOSS, DIE, YARA-X, MACO config extraction
  mal-web/           TS    triage queue, evidence tree, safe rendering
proto/               the cross-boundary contracts (AnalyzeResult)
deploy/              docker-compose for the minimum stateful set
test/corpus/         the adversarial test corpus (synthetic, never live malware)
docs/                the full, frozen design
```

---

## Getting started

The build is just starting, so there is no one-command install yet. That is the first milestone (M0), and you can follow it in [docs/M0-FIRST-COMMIT.md](docs/M0-FIRST-COMMIT.md). The short version of how to run it, once M0 lands:

```
git clone https://github.com/COLONAYUSH/OpenMalLab
cd OpenMalLab
docker compose -f deploy/compose.yaml up      # Postgres, Temporal, SeaweedFS, OpenBao
# then submit a file and watch it round-trip to an explainable verdict
```

If you want to build against it now, start with the design docs below. They are the source of truth.

---

## The full plan (design docs)

Everything here is frozen and reviewed. This is the whole thing, written down.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): the 24 ADRs. The three-plane model, containment, orchestration, storage, licensing, plus the full audit trail.
- [docs/PHASE1-TECHNICAL-DESIGN.md](docs/PHASE1-TECHNICAL-DESIGN.md): the buildable Phase 1. Component contracts, the fail-closed invariants, and the adversarial test corpus.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md): STRIDE per boundary, attack trees, and an honest residual-risk register.
- [docs/ARCHITECTURE-REVIEW.md](docs/ARCHITECTURE-REVIEW.md): the round-3 eight-lens adversarial review and every disposition.
- [docs/DECISION-LOG.md](docs/DECISION-LOG.md): the build decisions, including why we greenfield and why detonation is Phase 2.
- [docs/M0-FIRST-COMMIT.md](docs/M0-FIRST-COMMIT.md): the start-here build spec.
- [docs/LICENSING-BRIEF.md](docs/LICENSING-BRIEF.md): how the Apache core stays clean next to copyleft engines.
- [docs/diagrams/](docs/diagrams/): all the rendered diagrams and how to rebuild them.

---

## Status and how we work

We build in the open, in phases, and we do not overclaim. If a capability is Phase 2, the README says Phase 2, and the competitive-sounding lines wait until they are true. The design earned its ambition through three review rounds; now it has to earn it by running in front of a real analyst. That is the next milestone, not another doc.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Sign your commits (DCO). The one rule that does not bend: build the hostile boundary first, and never weaken it.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md). Report privately, never attach live samples, reference by hash.

## License

Apache-2.0 for the core. Copyleft engines, when they arrive in later phases, run as process-isolated, separately-licensed components, never linked into the core. See [docs/LICENSING-BRIEF.md](docs/LICENSING-BRIEF.md).
