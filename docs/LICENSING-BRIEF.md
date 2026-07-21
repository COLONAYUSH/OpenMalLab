# MalAnalyzer - Licensing & IP Brief (for legal counsel)

> **Purpose:** give counsel the engineering facts and the specific questions needed to bless (or correct) MalAnalyzer's open-source licensing model before public release. **This is an engineering brief to inform legal review - not legal advice.** Prepared 2026-07-14; verify all upstream licenses at review time (several have changed 2023-2026).

## 1. Business context
- MalAnalyzer is an **open-source** malware-analysis platform, **air-gapped-capable**, distributed as an **offline OCI bundle** (images + model weights + rule/corpus data).
- Intended core license: **Apache-2.0**, to maximize adoption and **preserve an optional future commercial ("open-core") edition**.
- It **integrates many third-party engines**, several under copyleft (GPL/AGPL) and one bespoke copyleft (Volatility VSL). The central legal question is whether our integration model keeps the Apache core clean.

## 2. How we use each dependency (the fact pattern that drives the analysis)
Integration modes: **[NET]** separate process over gRPC/HTTP with a normalized JSON/proto schema; **[CLI]** invoked as a subprocess; **[IMPORT]** linked/imported in-process; **[SVC]** long-running network service.

| Dependency | License (verify) | How we use it | Mode |
|---|---|---|---|
| Ghidra | Apache-2.0 | RE engine (Phase-1.5) | NET/CLI |
| YARA-X | BSD-3 | scanning/hunt | IMPORT (safe) |
| capa, FLOSS, Magika | Apache-2.0 | capability/strings/ident | CLI/IMPORT (safe) |
| Detect It Easy (diec) | MIT | packer/compiler/crypto fingerprinting (P1) | CLI (safe) |
| CAPE / capemon technique | GPLv3 | detonation/anti-evasion | **NET, or clean-room** |
| Qiling | GPLv2 | emulation (Phase-2) | **IMPORT -> must isolate** |
| Unicorn | GPLv2 | emulation core (also pulled by Speakeasy) | **IMPORT -> must isolate** |
| Speakeasy | MIT **but loads Unicorn GPLv2 in-process** | emulation | **IMPORT -> GPLv2 attaches** |
| Volatility 3 | **VSL (bespoke copyleft; "wrapper" clause)** | memory forensics (P1.5) | **NET, isolate, publish source** |
| MemProcFS | AGPLv3 | memory triage (P1.5) | **NET/SVC -> AGPL section 13** |
| MISP | AGPLv3 | intel sharing (P2) | **SVC -> AGPL section 13** |
| radare2 core | LGPLv3 | optional RE | IMPORT (LGPL relink terms) |
| Grafana, Loki | AGPLv3 | observability | **SVC, ship unmodified** |
| PostgreSQL | PostgreSQL (permissive) | store | SVC |
| OpenSearch, SeaweedFS, Qdrant, NATS, Keycloak, vLLM | Apache-2.0 | infra/AI | SVC/IMPORT (safe) |
| Valkey | BSD-3 | cache | SVC |
| OpenBao | MPL-2.0 | secrets | SVC (file-level copyleft) |
| Temporal | Apache-2.0 | orchestration | SVC |
| JanusGraph / Neo4j-CE | Apache-2.0 / GPLv3 | graph (P2) | SVC (Neo4j-CE isolate) |

**Model weights:** open-weight LLMs ship in the bundle - licenses vary per model (Apache-2.0, Llama Community, Qwen, etc.), several with **use restrictions / acceptable-use terms** that are *not* classic OSS licenses.

## 3. Proposed compliance architecture (for counsel to bless or correct)
1. **Apache-2.0 core**; the core links **only** permissive (Apache/BSD/MIT/MPL-file-level) code.
2. **Each copyleft engine is its own separately-licensed component** (GPLv2/GPLv3/AGPLv3/VSL), running as a **separate process** behind the normalized schema, **inheriting its upstream license**, shipped with that license text + a **written source offer**.
3. **No copyleft code is `import`ed into the Apache core, and copyleft workers do not link Apache-licensed shared helper libs** (to respect Apache<->GPLv2 incompatibility).
4. **CI license gate**, per-component, with **transitive** resolution (must flag e.g. Speakeasy->Unicorn), failing the build on a disallowed license entering the core.
5. **AGPL components shipped unmodified** (config-only); CI blocks source patches to them.
6. **Offline-bundle source-provision:** copyleft component **source travels in the bundle** (or a durable written offer) so air-gapped redistribution still satisfies source obligations.
7. Contributions under **DCO or CLA** (question Q7); trademark policy for the name/brand.

## 4. Questions for counsel (the asks)
- **Q1 - Aggregation vs. derivative.** Given mode **[NET]** with a documented, normalized data schema (no shared internal data structures), are our GPL/AGPL engine workers "mere aggregation" with the Apache core, or combined works? Does it matter, given each worker is *itself* separately licensed under its upstream copyleft? Where is the boundary genuinely risky?
- **Q2 - Apache-2.0 <-> GPLv2 incompatibility.** Confirm that isolating GPLv2 engines (Qiling/Unicorn/Speakeasy-via-Unicorn) as separate processes that do **not** link Apache code lets us **distribute them in the same bundle** lawfully, and specify any labeling/source requirements.
- **Q3 - AGPL section 13 (network-service clause).** For MemProcFS/MISP/Grafana/Loki offered over a network, what triggers the obligation to provide Corresponding Source to remote users? Does "ship unmodified, config-only" avoid modification obligations? What exactly must we offer, and does an air-gapped deployment change it?
- **Q4 - Volatility VSL.** The VSL's share-alike reaches "software designed to execute the software and parse its results, such as a wrapper." What does our (isolated, [NET]) memory-forensics worker owe, and does isolation limit the reach to just that component?
- **Q5 - iOS / DMCA section 1201.** Confirm that **not** shipping any iOS virtualization/emulation - offering only **static analysis + Frida on user-supplied jailbroken devices** - avoids the anti-circumvention exposure implicated in the Corellium matter.
- **Q6 - macOS SLA.** Confirm that a **self-hosted, bring-your-own-Apple-hardware** macOS detonation pool is permissible, that the <=2-VM-per-host and non-"service-bureau" terms are respected, and that a **hosted commercial** macOS-detonation service would violate the SLA.
- **Q7 - Our own licensing & governance.** (a) Apache-2.0 core - right choice vs. a weak-copyleft (MPL) core to deter proprietary forks while keeping open-core viable? (b) DCO vs. CLA for contributions, given a possible future commercial edition. (c) Trademark strategy for the project name. (d) The clean open-core boundary (which features may ever be commercial-only without clawing back released OSS).
- **Q8 - Model-weight licenses.** Several bundled open-weight models carry **acceptable-use / field-of-use restrictions** (not OSI licenses). Can we redistribute them in an offline bundle, must we surface per-model terms to users, and do any restrictions conflict with a security/dual-use tool or a commercial edition?
- **Q9 - Patents.** Any concern combining Apache-2.0's patent grant with GPLv2 components' lack of one, in a single distribution?

## 5. What we need back from counsel
1. A ruling on **Q1-Q2** (the core-cleanliness question) - the whole open-core strategy depends on it.
2. A concrete **AGPL section 13 compliance checklist** (Q3).
3. Sign-off or corrections on **VSL (Q4)**, **iOS/DMCA (Q5)**, **macOS SLA (Q6)**.
4. A recommendation on **core license + CLA/DCO + trademark + open-core boundary (Q7)**.
5. Guidance on **model-weight redistribution (Q8)**.
6. A short **per-component license-compliance matrix** we can encode into the CI gate and ship in the bundle.

## 6. Appendix - verified license notes (2026-07)
- Volatility 3 = **VSL**, not BSD (correcting an earlier internal error). radare2 core = **LGPLv3** (link-safe). Elasticsearch (2024) and Redis 8 (2025) **re-added AGPLv3** - we still avoid them because AGPL is unsuitable for a permissive core, not because they are closed. MinIO community edition was **gutted through 2025** - avoided in favor of SeaweedFS. HashiCorp Vault -> **BUSL**; we use **OpenBao** (MPL-2.0). Grafana **and Loki** are AGPLv3.
