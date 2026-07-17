<p align="center">
  <img src="docs/brand/openmallab-logo.png" alt="OpenMalLab" width="300" />
</p>

<h1 align="center">OpenMalLab</h1>

<p align="center">
  <b>The sovereign, all-in-one malware analysis platform.</b><br />
  Air-gap-first. Containment-first. Every verdict backed by evidence you can read.
</p>

<p align="center">
  <a href="https://github.com/COLONAYUSH/OpenMalLab/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/COLONAYUSH/OpenMalLab/ci.yml?branch=main&style=flat-square&label=ci" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-1f9d63?style=flat-square" alt="License" /></a>
  <img src="https://img.shields.io/badge/deploy-air--gap--first-ff5c5c?style=flat-square" alt="Air-gap first" />
  <img src="https://img.shields.io/badge/phase%201-building-ffb340?style=flat-square" alt="Status" />
  <br />
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Rust-1.9x-000000?style=flat-square&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/orchestration-Temporal-7a5cff?style=flat-square" alt="Temporal" />
  <img src="https://img.shields.io/badge/PRs-welcome-aebccd?style=flat-square" alt="PRs welcome" />
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &nbsp;.&nbsp;
  <a href="#how-it-works">How it works</a> &nbsp;.&nbsp;
  <a href="#the-containment-model">Containment</a> &nbsp;.&nbsp;
  <a href="#the-engines">Engines</a> &nbsp;.&nbsp;
  <a href="#roadmap">Roadmap</a> &nbsp;.&nbsp;
  <a href="docs/ARCHITECTURE.md">Design docs</a>
</p>

---

OpenMalLab takes a suspicious file and tells you what it really is, with the evidence to back every word, without ever letting the file touch anything it should not. It runs fully offline, it is self-hostable, and it is built so that the malware you are studying can never reach out of the box you put it in.

Most of what you need to analyze malware already exists. The problem is it lives in thirty different tools, half of them cloud-only and priced for enterprises, the other half single-purpose open source projects you stitch together yourself. Uploading a sample to a cloud service tips off the adversary and leaks your data. Nobody has fused deep static analysis, capability detection, and an explainable verdict into one self-hostable product you can run in an air-gapped lab, with a containment story you would stake your network on. That is what we are building, and the static core already runs.

We do not reinvent the engines. We take the best open tools in the world (Google's Magika, VirusTotal's YARA-X, Mandiant's capa) and fuse them into one platform, each running inside a zero-trust jail we built around them. Best-of-breed detection, sovereign plumbing.

---

## Highlights

- **Containment is the product, not a setting.** Every engine that touches hostile bytes runs as a single-use container with no network, no capabilities, a read-only root, a non-root user, and exactly one file mounted read-only. A 48-check boundary proof runs in CI and fails the build if the jail ever loosens.
- **Best-of-breed engines, fused.** Magika for content-based identification, YARA-X for signatures, capa for ATT&CK-mapped capabilities, and a recursive archive unpacker, all behind one contract.
- **Fail closed, always.** No file ever comes back clean because analysis got interrupted, capped, or crashed. Unknown is not benign. A crash raises suspicion, it never lowers it.
- **A verdict you can rank and read.** Severity and confidence are separate axes, so a real signature hit outranks a crashed engine even though both are "suspicious." Every point of the score traces to the finding that earned it.
- **Recursive by design.** A zip inside a zip inside an email is walked to the bottom, each artifact re-analyzed, every finding tagged with the breadcrumb path back to the root.
- **Air-gap-first, not air-gap-eventually.** Zero mandatory external calls. Every image builds hermetically; every model and rule set is pinned by hash into the image.

---

## Quickstart

Requires Docker with the Compose plugin. Everything runs locally, offline.

```bash
git clone https://github.com/COLONAYUSH/OpenMalLab
cd OpenMalLab

# build the jailed engine images and bring up the control node
docker compose -f deploy/compose.yaml --profile build build
docker compose -f deploy/compose.yaml up -d

# submit a file and get a verdict back
curl -s -F "file=@/path/to/sample" http://localhost:8080/v1/submissions
# -> {"submission_id":"sub-...","sha256":"...","status":"accepted"}

curl -s http://localhost:8080/v1/submissions/sub-xxxxxxxx | jq
```

A real round-trip, from the end-to-end proof (`deploy/proof/e2e.sh`):

```jsonc
{
  "verdict": "MALICIOUS",
  "score": 95,
  "confidence": "HIGH",
  "file_type": "php",
  "findings": [
    { "engine": "mal-ident",       "type": "file-type", "detail": "php",                            "verdict": "UNKNOWN" },
    { "engine": "mal-static-yara", "type": "yara",      "detail": "webshell_php_eval_superglobal", "verdict": "MALICIOUS", "attck": "T1505.003", "confidence": "HIGH" }
  ]
}
```

Submit a zip that hides EICAR two directories deep and it comes back `MALICIOUS` with the breadcrumb `payloads/inner/eicar.com`. Submit a benign text file and it comes back `UNKNOWN`, score `0`, because nothing has earned the right to call it clean.

---

## How it works

A submission is walked as a tree, breadth-first, under hard depth and count caps. Each artifact is identified, scanned, and unpacked in parallel jails; executables also get capability analysis. Nothing an engine emits is trusted until a jailed broker has validated it, and the whole thing rolls up on a fail-closed lattice.

```mermaid
flowchart LR
  A([analyst]) -- submit --> GW[mal-gateway]
  GW -- content-address --> V[(vault)]
  GW -- start workflow --> OR[mal-orchestrator<br/>Temporal]

  subgraph JAIL [single-use jails: no network, no caps, read-only, non-root]
    ID[mal-ident<br/>Magika]
    YA[mal-static-yara<br/>YARA-X]
    EX[mal-extract<br/>recursive unpack]
    CA[mal-capa<br/>capa capabilities]
  end

  OR -- one file, read-only --> ID & YA & EX & CA
  ID & YA & EX & CA -- raw bytes --> BR[mal-broker<br/>validate under caps]
  BR -- validated only --> OR
  EX -- children --> OR
  OR -- fail-closed lattice<br/>+ confidence + score --> GW
  GW --> CON([analyst console])
```

1. **Identify** what the file actually is with Magika, never trusting the extension.
2. **Scan** it with YARA-X against a curated, self-describing rule pack.
3. **Unpack** it recursively (zip, tar, gzip), with streaming caps so a decompression bomb stops cold and a Zip Slip goes nowhere, then re-submit every child through the whole pipeline.
4. **Characterize** executables with capa, mapping behavior to MITRE ATT&CK and MBC.
5. **Validate** every engine's raw output inside a jailed broker before a single byte reaches a trusted decoder.
6. **Roll up** a deterministic verdict on the lattice, with an orthogonal confidence and a 0-100 triage score, every point tracing to its evidence.

---

## The containment model

This is a tool that eats hostile input for a living, so its own security is the first feature, not the last. The jail below is enforced by the orchestrator on every engine and pinned, field by field, to a live boundary proof (`deploy/proof/boundary-proof.sh`) that runs in CI.

| Control | What it means |
|---|---|
| `--network none` | No interface but loopback, no routes. Network access is impossible, not merely blocked. |
| `--cap-drop ALL` + `no-new-privileges` | Zero Linux capabilities, no privilege escalation. |
| `--read-only` root + `noexec` scratch | The worker cannot write its root or execute anything it drops in scratch. |
| non-root (`65534`) | Nothing runs as root inside the jail. |
| one file, read-only | The sample is the only thing mounted, addressed by its sha256. |
| the broker | Raw engine output is validated (one document, known fields, hard caps) inside its own jail before any trusted process decodes it. |
| fail closed | A crash, timeout, cap, or malformed result floors the node to SUSPICIOUS and flags it incomplete, never clean. |
| re-hash on ingest | Extracted children are re-hashed by the trusted side; a worker can never smuggle bytes under a hash they do not match. |

The full threat model (STRIDE per boundary, attack trees, and an honest residual-risk register) is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). The design survived three rounds of adversarial review; the findings and dispositions are in [docs/ARCHITECTURE-REVIEW.md](docs/ARCHITECTURE-REVIEW.md).

---

## The engines

Each engine is a best-of-breed open tool, wrapped as a jailed worker that speaks one bounded contract. We integrate; we do not reimplement.

| Engine | Tool | Does | License | Status |
|---|---|---|---|---|
| `mal-ident` | [Magika](https://github.com/google/magika) (Google) | Content-based file identification, never the extension | Apache-2.0 | Live |
| `mal-static-yara` | [YARA-X](https://github.com/VirusTotal/yara-x) (VirusTotal) | Signatures via a curated, self-describing rule pack | BSD-3 | Live |
| `mal-extract` | pure-Rust `zip` / `tar` / `flate2` | Recursive, bomb-safe, Zip-Slip-proof unpacking | MIT / Apache-2.0 | Live |
| `mal-capa` | [capa](https://github.com/mandiant/capa) (Mandiant) | ATT&CK / MBC capability detection (vivisect backend) | Apache-2.0 | Live |
| `mal-static-die` | [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) | Packer / compiler / crypto fingerprinting | MIT | Next |
| `mal-static-floss` | [FLOSS](https://github.com/mandiant/flare-floss) (Mandiant) | Deobfuscated and decoded strings | Apache-2.0 | Next |
| config extraction | [MACO](https://github.com/CybercentreCanada/maco) + configextractor-py | Normalized family config / C2 extraction | MIT | Planned |

Rules and models are vendored into each image and pinned by hash, so the image digest pins the exact detection content and nothing is fetched at run time. Operators drop their own rule packs into a documented slot for offline builds.

---

## The analyst console

A dark, forensic, read-only triage front end: a severity-striped queue ranked by verdict then score, and a detail pane with a circular score gauge over the recursive evidence tree (breadcrumb paths, findings grouped by engine, ATT&CK chips). It is fully self-contained and air-gap-clean (no external fonts, scripts, or calls), theme-aware, and every specimen-derived string is inert-rendered and defanged, because the console is itself a hostile-content surface. Source in [`services/mal-web/`](services/mal-web/).

---

## Roadmap

We build in phases, and each phase is a real product on its own.

**Phase 1, the static wedge (now, and largely running).** Ingest, content-based identification, recursive sandboxed unpacking, the static engines, a deterministic and explainable verdict with a confidence-weighted triage score, and the analyst console. Single node, single tenant, fully offline.

- Done and running: the containment model, the broker, the fail-closed lattice, Magika, YARA-X with real rules, recursive extraction, capa, the confidence and score axis, the read-only console.
- Next in Phase 1: DIE and FLOSS, MACO config extraction, real vault crypto and WORM audit, OIDC and policy, persistence and the live queue API.

**Phase 1.5.** Ghidra as a crash-isolated service, full Volatility memory forensics, an interactive analyst view, full-text search at scale, and the first quarantined local-AI extraction.

**Phase 2.** The detonation plane: multi-tier, anti-evasion, and physically dead-ended so a full escape reaches nothing. Hunting and retrohunt over your own corpus, code-reuse attribution, a threat-intel graph, case management, a guardrailed AI assistant, and hard multi-tenancy.

**Phase 3.** The frontier: sound LLM-plus-IR script deobfuscation, a generic unpacker, symbolic execution, a STIX knowledge graph, and a natural-language investigation agent scoped tightly to one case.

Why detonation is Phase 2 and not Phase 1, and why the static wedge is the right first product, is in [docs/DECISION-LOG.md](docs/DECISION-LOG.md).

---

## Tech stack

Chosen for correctness, offline operability, and a permissive-license core.

- **Orchestration:** Temporal for durable workflows, retries, timeouts, and safe recursion.
- **Languages:** Rust at the hostile-input boundary (identification, extraction), Go for the control plane, Python for the heavier analysis engines, HTML/CSS/JS for the console.
- **State, kept deliberately small:** PostgreSQL, Temporal, SeaweedFS for object storage, OpenBao for secrets.
- **Isolation:** every engine is a jailed, single-use sibling container spawned per submission; the orchestrator is the only writer of the stores.

---

## Repo layout

```
services/
  mal-gateway/       Go    submit + read API, content-addressed vault
  mal-orchestrator/  Go    Temporal workflows, the jail spawner, recursion caps, aggregation
  mal-ident/         Rust  Magika file identification
  mal-extract/       Rust  recursive, bomb-safe, path-safe unpacking
  mal-static-yara/   Rust  YARA-X with a self-describing rule pack
  mal-capa/          Py    capa capability detection (vivisect)
  mal-broker/        Go    the trust-boundary validator
  mal-web/           web   the read-only analyst console
internal/pipeline/   the shared verdict lattice, confidence, and score
deploy/              docker compose for the control node + the boundary and e2e proofs
docs/                the full, frozen, reviewed design
```

---

## Design docs

Everything here is frozen and reviewed. This is the whole plan, written down.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - the ADRs: the three-plane model, containment, orchestration, storage, licensing.
- [docs/PHASE1-TECHNICAL-DESIGN.md](docs/PHASE1-TECHNICAL-DESIGN.md) - the buildable Phase 1: component contracts, fail-closed invariants, the adversarial corpus.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) - STRIDE per boundary, attack trees, residual-risk register.
- [docs/ARCHITECTURE-REVIEW.md](docs/ARCHITECTURE-REVIEW.md) - the round-3 eight-lens adversarial review and every disposition.
- [docs/DECISION-LOG.md](docs/DECISION-LOG.md) - the build decisions and why we cut Phase 1 the way we did.
- [docs/diagrams/](docs/diagrams/) - the rendered system diagrams.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The one rule that does not bend: build the hostile boundary first, and never weaken it. Every change to the jail has to keep the boundary proof green.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md). Report privately, never attach live samples, reference by hash.

## License

Apache-2.0 for the core. Copyleft engines, when they arrive in later phases, run as process-isolated, separately-licensed components, never linked into the core. See [docs/LICENSING-BRIEF.md](docs/LICENSING-BRIEF.md).

---

## Star history

<p align="center">
  <a href="https://star-history.com/#COLONAYUSH/OpenMalLab&Date">
    <img src="https://api.star-history.com/svg?repos=COLONAYUSH/OpenMalLab&type=Date" alt="Star history chart" width="620" />
  </a>
</p>

<p align="center"><sub>Built in the open. Containment-first, from commit one.</sub></p>
