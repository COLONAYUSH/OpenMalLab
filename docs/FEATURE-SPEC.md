# MalAnalyzer - The Definitive Feature Specification

> **The world's best malware-analysis platform: open-source, air-gapped-first, hybrid-AI, all-in-one - engineered to make even the toughest malware a breeze for every kind of analyst, inside a maximally secure isolated environment.**

**Status:** v0 - synthesized from a deep landscape review of the commercial + open-source ecosystem (2024-2026).
**Scope locked:** open-source (commercial offering possible later), air-gapped/on-prem first, cloud optional, hybrid AI (local-first, guardrailed cloud), all analyst personas, every artifact type.

> **[!] Post-audit note (v1):** several claims below were revised after a ruthless four-lens audit - see `docs/ARCHITECTURE.md` section 8 for the full reconciliation. Most-affected: iOS/macOS detonation (over-promised), the AI layer's injection/agent model (re-architected), the function-identity server (scoped to open formats), and the Phase-1 roadmap (recut). Where this spec and ARCHITECTURE.md v1 differ, **ARCHITECTURE.md wins.**

---

## 0. How to read this document

Every feature is tagged with a **priority tier** and, where relevant, the incumbent tool(s) that inspired it - so the lineage the research uncovered is explicit.

| Tier | Meaning |
|------|---------|
| **P0, Foundation** | Table stakes. Must exist for the platform to be credible. This is the MVP core. |
| **P1, Differentiator** | Where we clearly beat any *single* existing tool. The reason people switch. |
| **P2, Frontier** | Category-defining bets. The reason people call it *the best in the world*. |

`(cf. X)` = "credit / prior art: tool X." We are standing on the shoulders of the whole field and unifying it.

---

## 1. Vision & Strategic Positioning

### The thesis
Every capability below already exists *somewhere* - but it is scattered across 30+ tools, split between eye-wateringly expensive cloud-only commercial suites and powerful-but-fragmented open-source projects that each solve one slice. **No one has unified deep analysis + threat-intel graph + hunting + case management into a single, self-hostable, air-gap-capable product with a genuinely useful, genuinely safe AI layer.** That is the wedge. MalAnalyzer is that unification.

### The nine gaps we exploit
Each is a place an entire market segment is currently underserved:

1. **No unified self-hosted platform.** VirusTotal/Intezer/ReversingLabs give you TI + analysis but only in the cloud; MISP/OpenCTI give you the graph but not deep analysis; Assemblyline gives you orchestration but not hunting/case-management. *We unify all four, on-prem.*
2. **Air-gap is a second-class citizen everywhere.** The best commercial engines (Zscaler, WildFire, Defender, VT) are cloud-only - a non-starter for sensitive samples and classified/regulated environments. Uploading to VT also *tips off the adversary*. *We are air-gapped-first; the network is opt-in.*
3. **OSS sandboxes are trivially detectable.** In-guest hooking (Cuckoo/CAPE) leaves fingerprints; modern malware (LummaC2 mouse-trigonometry, Blitz VM checks) walks right past it. *We default to agentless hypervisor monitoring and auto-escalate evasive samples.*
4. **No mature, native, local AI layer exists in open source.** Commercial AI (Code Insight, Sidekick) is cloud-hosted - a privacy landmine for malware - and prompt-injectable. *We ship a local-first, guardrailed, MCP-native AI layer that assists rather than dictates.*
5. **Verdicts are opaque.** Most tools emit "suspicious" or a signature-hit list with no explanation. *Every verdict we produce cites its evidence chain and links to the exact code/behavior.*
6. **Interactivity is rare.** Only ANY.RUN nails real-time human-in-the-loop detonation, and it's a paid cloud service. *We make interactive + autonomous detonation open-source.*
7. **macOS/IoT/multi-arch detonation are underserved in OSS.** *We cover Linux/IoT multi-arch, and offer macOS on **bring-your-own Apple hardware** (self-host only, per Apple's SLA). iOS **detonation** is not lawfully shippable in OSS (DMCA section 1201) - we do iOS **static + Frida on BYO jailbroken devices** instead.*
8. **Generic unpacking is an unsolved OSS problem** (no open UnpacMe). *We make dynamic-informed unpack-to-OEP + config extraction a first-class engine.*
9. **Open-source governance keeps betraying its community** (the TheHive license rug-pull). *We commit to a real, durable OSS governance model from day one.*

---

## 2. Non-Negotiable Design Principles

1. **Air-gap-first.** The full analysis pipeline runs with zero internet. Every external call (TI feeds, cloud AI, sample sharing) is an explicit, auditable opt-in - never a dependency.
2. **Assume the sample is trying to escape *and* trying to lie.** Anti-evasion and containment are defaults, not options.
3. **The analyzed content is hostile input to *us*, including our AI.** Sample strings, HTML, filenames, and decompiled text are untrusted and rendered inert; the AI layer is hardened against prompt injection (cf. the EchoLeak zero-click Copilot exploit).
4. **AI assists; it never silently decides.** Every AI output is labeled, grounded in cited evidence, and separable from deterministic verdicts. No hallucinated names/behavior in the authoritative record.
5. **Explainability over black boxes.** Every score links to the evidence and the implementing code/behavior, tagged to ATT&CK/MBC.
6. **One platform, pluggable everything.** A clean service/plugin contract so the community extends it without forking.
7. **Open interchange by default.** We emit and ingest standard formats (STIX 2.1, MISP, YARA-X, BinExport2, MACO, ATT&CK/MBC) so analysis flows in and out freely.
8. **Real open-source governance.** Permissive-enough license, public roadmap, no bait-and-switch. Trust is a feature.

---

## 3. Capability Pillars

### 3.1 Ingestion, Identification & Triage
The front door. Fast, recursive, and safe.

- **P0** Universal file-type identification via a local deep-learning model (cf. Google **Magika** - ~1 MB, 200+ types, ms on CPU) as the first-stage router; never trust the extension.
- **P0** **Recursive decompose -> analyze -> score -> rescore** tree - every extracted child (archive member, embedded PE, dropped payload, OLE stream) re-enters the full pipeline (cf. **Assemblyline 4**, ReversingLabs TitaniumCore recursive unpacking of ~4,800 formats).
- **P0** In-memory **container transforms** - ZIP/7z/IMG4/CaRT/email/ISO/OneNote extraction without touching disk (cf. Binary Ninja container transforms).
- **P0** **Hash-addressed, encrypted sample vault** - immutable originals, per-sample encryption, deduped by hash, full chain-of-custody audit log (cf. malware-sharing best practices; 7z encrypted-filename storage).
- **P1** **Fast static ML pre-verdict** - a local, explainable gradient-boosted scorer with feature-importance output (cf. **EMBER2024** LightGBM baseline, ROC-AUC 0.997; SOREL-20M) for instant triage before any detonation.
- **P1** **Tiered verdict for patient-zero** - high-confidence instant verdict returns in seconds; deep analysis continues async (cf. Zscaler AI Instant Verdict).
- **P1** **Similarity/reputation lookup at ingest** - imphash / TLSH / ssdeep / RHA-style functional-similarity buckets against the local corpus (cf. ReversingLabs RHA1 <5 ms buckets).

### 3.2 Static Analysis & Reverse Engineering
Make deep RE fast, collaborative, and AI-assisted - without leaking bytes.

- **P0** Multi-architecture disassembly + decompilation across 45+ ISAs, headless and GUI (cf. **Ghidra 12** decompiler + PyGhidra; IDA-class output as the north star).
- **P0** **Capability tagging as a layer** - `capa`-style capability detection rendered inline in the decompiler, mapped to **ATT&CK + MBC**, clickable straight to the implementing function, across **static AND dynamic** backends (cf. **capa v9** with CAPE/DRAKVUF/VMRay trace backends).
- **P0** **Advanced string recovery** - emulation-driven stack/tight/decoded strings, including struct-aware **Go and Rust** (non-NUL-terminated) extraction (cf. **FLOSS v3**).
- **P0** PE/ELF/Mach-O anatomy + packer/compiler/obfuscator fingerprinting (cf. **Detect It Easy**, PEStudio, APKiD for Android).
- **P1** **Self-hostable, air-gapped function-identity server** - a shared on-prem knowledge base built on **Ghidra BSim** (decompiler-feature similarity) + **Binary Ninja WARP** (open GUID signatures) + MCRIT-style MinHash, so the community shares *function knowledge without ever shipping bytes*. (FLIRT/Lumina are Hex-Rays proprietary and not self-hostable - we at most *apply* user-supplied FLIRT sigs; revised post-audit - see ARCHITECTURE.md section 8 M-IDENTITY.)
- **P1** **Binary diffing & code similarity** with open interchange - adopt/emit **BinExport2** and WARP signatures (cf. **BinDiff**, Diaphora, Ghidra Version Tracking).
- **P1** **Pluggable inline deobfuscation** - custom string/constant renderers that surface decoded values directly in pseudocode (cf. Binary Ninja renderers).
- **P1** **MCP-native RE by design** - expose disassembler/decompiler/xref/rename/search over a stable **Model Context Protocol** server so any *local* LLM or agent can drive analysis (cf. the 2025 GhidraMCP / ida-pro-mcp / pyghidra-mcp explosion).
- **P1** **Real-time collaborative markup** - live shared names/comments/types with versioning (cf. Ghidra multi-user, but live - something even IDA lacks).
- **P2** **Symbolic/concolic execution** for path discovery, dormant-branch triggering, and constraint solving (cf. **angr**, Triton, Ghidra's experimental Z3 emulator).
- **P2** **Generic dynamic-informed unpacker** - break-on-OEP, dump, rebuild IAT, auto-classify - the open answer to the missing UnpacMe (cf. x64dbg + Scylla loop, CAPE unpacking).

### 3.3 Dynamic Analysis & Sandboxing
The anti-evasion crown jewel. This is where we most decisively beat both camps.

- **P0** **Hybrid multi-tier instrumentation, evasion-routed:**
  - **Tier 1 - Emulation fast-lane:** shellcode / drivers / multi-arch & IoT binaries emulated with no VM in seconds (cf. Mandiant **Speakeasy**, **Qiling/Unicorn2** COW snapshots).
  - **Tier 2 - In-guest hooking:** fast, rich API/behavior capture for the common case (cf. **CAPE** `capemon`, **Cuckoo3**).
  - **Tier 3 - Agentless hypervisor VMI:** samples that trip anti-analysis signals auto-escalate to stealthy out-of-guest monitoring the malware cannot see (cf. **DRAKVUF** Xen VMI/altp2m, **VMRay** Intelligent Monitoring). *Default posture for evasive samples.*
- **P1** **YARA-programmable hardware-breakpoint debugger** - live control-flow manipulation (`skip`/`wret`/`setcf`) driven by YARA rules *during detonation* to defeat anti-sandbox/timing/anti-VM traps (cf. **CAPE**'s debugger - a genuinely brilliant technique).
- **P1** **Config & payload extraction SDK** - pure-Python, pluggable, community family library with `extract_config(data)` contract; auto-dump configs/C2/keys; normalize via **MACO** (cf. CAPE 70+ extractors, Recorded Future Triage ~150 families, CERT.pl **malduck**).
- **P1** **Real-time interactive detonation** - live desktop/VNC view, click installers, reboot, solve CAPTCHAs, walk human-gated steps (cf. **ANY.RUN**, Cisco Glovebox).
- **P1** **Autonomous kill-chain walking** - automatically follow multi-stage chains: QR-code URLs, rewritten/smart links, password-protected archives, staged downloaders (cf. ANY.RUN Automated Interactivity / Smart Content Analysis).
- **P1** **Multi-OS detonation:** Windows, Linux, **Android**, and **macOS** (on bring-your-own Apple hardware, self-host only - Apple SLA limits). **iOS detonation is not offered** (no lawful OSS iOS virtualization; DMCA section 1201); iOS is covered by static + Frida on BYO jailbroken devices. (cf. Joe Sandbox breadth; revised post-audit - see ARCHITECTURE.md section 8 H-IOS-MACOS.)
- **P1** **Network containment with selectable egress modes:** `none` -> **INetSim/FakeNet-NG simulated internet** -> filtered real egress (VPN/Tor exit, residential/geo proxy to defeat geofenced malware) - all air-gap-toggleable (cf. INetSim, FakeNet-NG 3.x, ANY.RUN geo proxy, OPSWAT geolocation spoofing).
- **P1** **TLS decryption without a detectable proxy** - hypervisor/guest **TLS key extraction** (cf. DRAKVUF) in addition to optional MITM.
- **P1** **Ephemeral, disposable detonation** - containerized QEMU-KVM / disposable VMs, clean snapshot per run, self-destructing (cf. Qubes disposable VMs, pokiSEC ephemeral QEMU/KVM).
- **P1** **VM anti-detection hardening presets** - realistic hardware IDs, user artifacts, uptime, "wear-and-tear," plus optional bare-metal detonation profile (cf. commercial bare-metal, the 2025 ~20% rise in evasion T1497).
- **P2** **CPU/exploit-phase instruction tracing** - catch shellcode/exploits *before* anti-analysis logic runs (cf. Check Point CPU-level detection).
- **P2** **Hybrid code analysis** - surface dormant/logic-bomb branches not hit at runtime (cf. Joe Sandbox Hybrid Code Analysis).

### 3.4 Memory & Runtime Forensics

- **P0** Full **Volatility 3** engine integration (ISF symbol tables; `windows.malware.*` plugins) for process/DLL/injection/registry/network artifacts.
- **P1** **Memory-as-filesystem + auto "FindEvil" triage** - mount any dump (or live/VMI target) as a browsable FS; auto-flag PE-in-private-memory, unlinked modules, patched pages, APC injection, hollowing, with per-region threat scoring (cf. **MemProcFS** + FindEvil, Volatility 2025 PEScan/APCWatch plugins).
- **P1** **Sandbox<->memory fusion** - every detonation auto-captures memory snapshots that flow straight into the forensic engine and capability tagging.
- **P0** Acquisition helpers for offline/host analysis (cf. WinPmem, AVML, Velociraptor at scale).

### 3.5 Specialized Artifact Analysis
Every file type, deobfuscated, with structured output - not just a flag.

- **P0** **Maldocs:** OLE/RTF/VBA with automatic deobfuscation and **VBA-stomping / p-code mismatch** detection; Excel-4/XLM emulation (cf. **oletools** `olevba`, **ViperMonkey**, **XLMMacroDeobfuscator**, Didier Stevens suite).
- **P0** **Malicious scripts:** JS/WScript sandboxing with ActiveX/WScript object stubbing -> JSON IOCs; PowerShell dynamic deobfuscation (cf. **box-js**, PowerPeeler, Assemblyline jsjaws).
- **P0** **PDF, LNK, HTA, OneNote, email (.msg/.eml)** structural analysis and payload extraction.
- **P0** **Shellcode emulation** - 32/64-bit, user+kernel (cf. **scdbg**, Speakeasy).
- **P1** **Mobile:** Android - full static + Frida-driven dynamic, SSL-unpinning, behavior-based weighted scoring that **points to the exact bytecode** and emits ATT&CK/CWE. iOS - static analysis + Frida on bring-your-own jailbroken devices (best-effort; no OSS iOS detonation). (cf. **MobSF**, **Androguard**, **quark-engine**.)
- **P1** **Embedded chained-recipe engine with auto-detect** - a built-in CyberChef-style "Magic" transform lab for ad-hoc decode/decrypt inside the platform (cf. **CyberChef**).
- **P1** **Emulation-based deobfuscation as a first-class pipeline** - macros -> JS -> shellcode all chained, with the recovered payload + IOCs captured as **structured JSON**, never just a boolean.

### 3.6 Threat Intelligence, Hunting & Attribution
The platform layer nobody has unified on-prem.

- **P1** **Local Retrohunt + Livehunt as first-class primitives** - **YARA-X** over your own corpus (retro), streaming matches on new arrivals (live), with match/IOC streams (cf. VirusTotal Retrohunt/Livehunt, Kaspersky **Klara**, abuse.ch **YARAify**).
- **P1** **Bundled goodware corpus** for instant (<1 min) false-positive testing of any rule before deployment (cf. VT's 1M-file goodware set, ReversingLabs goodware corpus).
- **P1** **Offline code-reuse / "genetic" attribution** - function-level MinHash similarity against a curated family corpus, with **auto-generated family YARA rules** from family-unique code - an open, air-gapped Intezer (cf. **MCRIT + Malpedia**, Intezer genes).
- **P1** **Faceted query DSL + similarity pivots** - VT-grade search: `behaviour:`, `imphash:`, `similar-to:`, TLSH/RHA buckets, and 40+ modifiers over local data (cf. VirusTotal search).
- **P1** **Visual pivot canvas** - graph link-analysis across samples, IOCs, infrastructure, and campaigns (cf. **VT Graph**, **Maltego** transforms).
- **P1** **STIX 2.1 / TAXII + MISP-native sync** - bidirectional sharing, sharing groups, feeds (cf. **MISP 2.5**, **OpenCTI 7**).
- **P1** **Built-in IOC decay** - indicators age out automatically on configurable rules (cf. ThreatFox 6-month expiry, OpenCTI decay rules).
- **P2** **STIX knowledge graph** of actors/campaigns/TTPs/infrastructure with a GraphQL API (cf. OpenCTI).

### 3.7 Detection Engineering
Detection-as-code, first-class.

- **P0** **YARA-X-first** authoring, compilation, and scanning (memory-safe, fast; classic YARA now maintenance-only) (cf. **YARA-X 1.0**).
- **P1** **Assisted rule generation** - auto-extract candidate strings/features from an analyzed sample (minus goodware), then LLM-cleanup into a tuned rule (cf. **yarGen** + Code-Insight-style refinement).
- **P1** **CI rule-testing harness** as a built-in feature - syntax lint -> FP test against goodware corpus -> hit test against known-bad corpus -> **ATT&CK coverage dashboard** - gate before deploy (cf. SCYTHE sigma-regression-testing, **droid** + Atomic Red Team).
- **P1** **Sigma authoring + multi-SIEM export** (pySigma) and, optionally, telemetry-correlation rules (cf. **SigmaHQ**, Chronicle **YARA-L 2.0**).
- **P0** **capa rule authoring & management** integrated with the capability layer.

### 3.8 Orchestration, Scale & Automation

- **P0** **Distributed, horizontally-scalable pipeline** - queue-driven task routing across worker fleets; K8s node+pod autoscaling; proven-at-scale patterns (cf. **Assemblyline** ~14M files/day, **Strelka** ~250M/day, CERT.pl **Karton**).
- **P0** **Clean service/plugin contract** - per-service scoring, safelisting, versioning; community services drop in without forking.
- **P0** **API-first / UI-parity (REST only)** - everything in the UI is in the REST API; headless-everything (cf. idalib, Ghidra headless, r2pipe). **UI-parity does *not* extend to MCP:** the agent's MCP surface is a deliberately smaller, per-case, capability-scoped subset - never equal to a human's authority *(corrected R2 - `docs/DESIGN-AUDIT.md` A13; `ARCHITECTURE.md` ADR-014)*.
- **P1** **SOAR & enrichment bus** - uniform analyzer/responder contract (cf. **Cortex** 100+ analyzers) with connectors to XSOAR/TheHive/DFIR-IRIS and inline-blocking hooks (EDR/NGFW/SIEM).
- **P1** **MACO-normalized config output** across all extractors for machine-consumable configs.

### 3.9 Case Management, Collaboration & Reporting
Where the analyst actually lives. This is the "analyst-friendly" promise.

- **P1** **Native case model** - `sample <-> case <-> IOCs <-> tasks <-> evidence <-> assets`, fully API-driven (cf. **DFIR-IRIS**, TheHive case templates).
- **P1** **Shared inline annotations** on every artifact - the thing sandboxes universally lack.
- **P1** **Verdict workflow with analyst override + full audit trail** - human-in-the-loop, defensible, reproducible.
- **P1** **Evidence-linked, expandable analysis tree** - click any score to see exactly why it was assigned (cf. Assemblyline evidence tree).
- **P1** **One-click, multi-format export** - STIX 2.1 bundle, Markdown/PDF report, YARA/Sigma pack, MISP event - with **all IOCs defanged** by default.
- **P1** **Embedded notebook environment** - Jupyter with platform-native helpers (ATT&CK data, entity pivots, timelines, process trees) for bespoke investigation (cf. **msticpy**).
- **P1** **Analysis history & diffable reports** - re-open past runs; diff two reports (killing the "100-page undiffable report" pain).
- **P0** **Role-based workflows** - tuned surfaces for SOC/IR (fast verdict + triage queue), RE (decompiler-centric), TI/hunting (pivot canvas + retrohunt), detection eng (rule lab). Same data, different lenses.

---

## 4. The AI Layer (cross-cutting)
Hybrid, local-first, guardrailed, and *useful* - the single biggest thing missing from open source today.

- **P1** **Local-first, hybrid routing** - open-weight models (via a local runtime, e.g. Ollama-class) handle everything by default; only **structural derivatives** of hard cases route to a guardrailed frontier model. Sending raw bytes is an explicit, logged, **two-person "accepted exfiltration"** gated by data classification - **not a consent click** - and impossible in air-gap mode *(corrected R2 - `ARCHITECTURE.md` ADR-010)*.
- **P1** **AI as assist, pinned to evidence** - per-file/per-function natural-language summaries surfaced *next to* the decompiled code or behavior, clearly labeled AI-generated, never overwriting the authoritative record (cf. **VT Code Insight**, Joe Sandbox AI, Binary Ninja **Sidekick** Notebook).
- **P1** **Grounded verdicts only** - every AI verdict/summary cites its evidence chain (cf. Intezer/Assemblyline evidence-based verdicts). No uncited claims in reports.
- **P1** **MCP-native agent surface (scoped subset, not a mirror)** - RE/sandbox/TI/hunting tools are exposed over MCP as a **deliberately smaller, per-case, capability-scoped** surface so a local agent can conduct multi-step investigations; **cross-case / cross-tenant / global-retrohunt / egress tools are excluded** and stay human-initiated (breaks the lethal trifecta) *(corrected R2 - `ARCHITECTURE.md` ADR-010/014; `docs/DESIGN-AUDIT.md` A13)*.
- **P1** **Natural-language investigation** - ask questions of a sample/case in plain language; the agent picks tools, runs them, and shows its work.
- **P1** **AI-assisted report generation** - audience-tuned (SOC one-pager vs. RE deep-dive vs. exec summary), always analyst-editable (cf. OpenCTI "Ask Ariane," Joe Sandbox).
- **P1** **FP adjudication assist** - AI proposes true/false-positive calls with rationale; analyst confirms (cf. Code Insight FP surfacing).
- **P2** **Hybrid LLM + deterministic-IR deobfuscation for scripts** - the LLM identifies structure and a **compiler/IR performs the sound rewrite** so there is *zero hallucinated code* (cf. Google **CASCADE** - Gemini + JSIR). This is the right pattern for **JavaScript/script/VBA** deobfuscation specifically; **native** RE gets soundness from emulation (Speakeasy/Qiling) and symbolic execution, with the LLM only *labeling* recovered artifacts (revised post-audit - see ARCHITECTURE.md section 8 H-CASCADE).
- **P2** **Assisted rule/script generation** feeding directly into the detection-engineering and CyberChef-recipe layers.

### AI guardrails (see also section 5)
- **Prompt-injection hardening is mandatory** - sample-derived text (strings, HTML, decompiled comments, filenames) is treated as hostile input to the model; strict input framing, output validation, and no autonomous high-impact actions without confirmation (cf. **EchoLeak** zero-click Copilot exploit; MCP-RE-agent injection research).
- AI output is always flagged as untrusted/advisory and segregated from deterministic findings.
- Local-model default guarantees no sample exfiltration; cloud routing is logged, minimized, and revocable.

---

## 5. Security, Isolation & Trust Architecture (cross-cutting)
"Most secure" is a design stance, enforced everywhere.

- **P0** **Air-gapped-first deployment** - full pipeline works offline; every egress path is opt-in and audited.
- **P0** **Layered isolation** - hypervisor/VM isolation for detonation, disposable per-run VMs (**each with its own result store + network bridge**), clean-snapshot reversion; optional bare-metal pool. **Air-gap is enforced at the network layer (no route exists), not a VLAN/software toggle**, and escape-containment requires a **physically separate detonation node** *(corrected R2 - `ARCHITECTURE.md` ADR-007/017; `docs/DESIGN-AUDIT.md` A1/A9)*.
- **P0** **Default-deny detonation networking** with the egress modes from section 3.3.
- **P0** **Hostile-content boundary in the UI/analyst plane** - sample strings, HTML, URLs, and filenames are rendered inert/defanged; no live links; the analyst UI is treated as an attack surface for the sample.
- **P0** **Encrypted, hash-addressed sample vault** with strict handling: one sample per encrypted archive, encrypted filenames, immutable originals, defanged IOCs in all outputs, full audit log (cf. malware-sharing best practices).
- **P0** **RBAC, SSO, and complete audit logging** - who ran what, on which sample, when, and every verdict override.
- **P1** **Platform supply-chain security** - signed releases, SBOM, reproducible builds, pinned/vetted dependencies (we are a security tool; we must be exemplary).
- **P1** **Tenant/analyst isolation** - separate case data, need-to-know access, and safe multi-team operation.

---

## 6. Analyst UX Principles (cross-cutting)
Distilled from what practitioners *love* vs. *hate* across every tool reviewed.

**Emulate (loved):** real-time visibility during detonation, one-glance verdict + extracted config up front, pivot-everywhere from any indicator, permalink-able, shareable results, API parity with the UI, capability->code "jump to evidence", minutes-to-verdict fast triage, notebook-driven deep dives.

**Eliminate (hated):** 100-page undiffable reports, no shared annotations, ambiguous verdicts with no rationale, re-running analysis just to see history, walled-garden exports, stitching 10+ CLIs with inconsistent output, setup that takes days (DRAKVUF's "here be dragons").

**Therefore:**
- **P0** A guided, opinionated installer/deployment (containers + one-command bring-up) - beat the notorious OSS setup pain.
- **P0** A **score-driven triage queue** as the SOC landing page; evidence tree one click away.
- **P1** Consistent, normalized output schema across every engine and plugin.
- **P1** Progressive disclosure - verdict -> summary -> evidence -> raw - so novices and experts share one tool.

---

## 7. Interoperability & Standards

| Standard | Use |
|----------|-----|
| **MITRE ATT&CK** | Tag every behavior/verdict. Coverage dashboards. |
| **MBC (Malware Behavior Catalog)** | Finer-grained malware behavior tagging (capa-native). |
| **STIX 2.1 / TAXII** | Primary intel exchange; emit bundles, run a TAXII server. |
| **MISP core format** | Bidirectional sync, feeds, sharing groups. |
| **YARA-X** | Detection + retro/live hunt engine. |
| **Sigma** | Telemetry detection authoring/export. |
| **BinExport2** | Binary diffing / cross-engine interchange. |
| **WARP** | Function-signature sharing. |
| **MACO** | Normalized malware-config output. |
| **OpenIOC** | Legacy import (read-only compatibility). |

---

## 8. Governance & Open-Source Model
The TheHive rug-pull fractured a community. We will not repeat it.

- A permissive-enough, durable license chosen up front and committed to.
- Public roadmap, open RFC process, and a plugin ecosystem with a stable contract.
- Clear, honest boundary if a commercial edition ever exists (open core done *right*, no clawing back existing OSS features).
- Security disclosure policy and a hardened build/release pipeline from day one.

---

## 9. Phased Roadmap

**Phase 1 - the true wedge (control node + one separate detonation host).** Ingestion + Magika routing + recursive extraction (sandboxed) + envelope-encrypted vault; static triage (DIE/PE anatomy, FLOSS, capa+ATT&CK); **Tier-2 KVM detonation only** (INetSim, disposable VMs, write-only result pump); maldoc/script/shellcode analyzers; YARA-X scanning; score-driven triage queue + evidence tree; RBAC/OIDC/audit; containerized deploy (Postgres-FTS before OpenSearch). **Deferred to Phase 1.5:** full Volatility 3, Ghidra headless service, interactive noVNC, OpenSearch, Jupyter, local-AI extraction. **Goal: a credible, self-hostable, safe wedge - not five products at once (revised post-audit - see ARCHITECTURE.md section 8 H-SCOPE).** [!] **R2 scoping decisions (`docs/DESIGN-AUDIT.md` section 7):** (a) escape-containment requires the detonation host to be a *physically separate node* - all-in-one single-node is dev/eval or Tier-1-sim only (A1); (b) shellcode **emulation via Speakeasy pulls Unicorn GPLv2** - Phase-1 either drops emulation-based shellcode (permissive static only) or ships a GPLv2-isolated worker (A7).

**Phase 2 - Differentiators (P1).** Tier-3 agentless VMI escalation + CAPE-style YARA HW-breakpoint debugger; config-extraction SDK; interactive + autonomous detonation; macOS/Android/iOS; local Retrohunt/Livehunt + goodware corpus; MCRIT-style attribution; pivot canvas; MISP/STIX sync; case management + collaboration; local-first AI assist (summaries, report gen, MCP surface); function-identity server; detection-eng rule lab with CI harness. **Goal: clearly better than any single tool.**

**Phase 3 - Frontier (P2).** CASCADE-style hybrid LLM+IR deobfuscation; generic unpacker; symbolic execution; CPU/exploit-phase tracing; STIX knowledge graph; full natural-language autonomous investigation agent. **Goal: category-defining.**

---

## 10. Competitive Differentiation Summary

| Incumbent | What they're best at | How MalAnalyzer wins |
|-----------|----------------------|----------------------|
| **VirusTotal / GTI** | Global corpus, retro/live hunt, Code Insight | Same hunting primitives **on-prem/air-gapped**; you don't tip off adversaries; unified with analysis + cases |
| **Joe Sandbox / VMRay** | Agentless deep sandbox, breadth | Same hypervisor anti-evasion, **open-source & self-hosted**, plus interactive + hunting + RE in one |
| **ANY.RUN** | Interactive real-time detonation | Interactivity **open-source and air-gap-capable**, with autonomous fallback |
| **Intezer** | Genetic code-reuse attribution | **Offline** MCRIT/Malpedia genes, evidence-linked, no cloud |
| **Assemblyline** | Scalable recursive orchestration | Same engine **plus** hunting, TI graph, case mgmt, and AI |
| **MISP / OpenCTI** | Intel sharing & graph | The graph **fused with deep analysis + detonation** in one product |
| **IDA / Ghidra / Binja** | Reverse engineering | RE **inside** the platform, MCP-native local AI, live collaboration, capability-tagged from static *and* dynamic |
| **CAPE / DRAKVUF / Cuckoo3** | OSS detonation | Unified multi-tier engine + native AI + hunting + cases; beat their setup pain and evasion gaps |

---

## Appendix - Primary research sources
Landscape synthesized (2024-2026) from, among others: Joe Security, VMRay, ANY.RUN, Recorded Future Triage, CrowdStrike/Hybrid Analysis, Palo Alto WildFire, Check Point, Zscaler; CAPEv2, Cuckoo3, DRAKVUF, Qiling/Unicorn, Speakeasy, INetSim, FakeNet-NG, Qubes, CERT.pl Karton/malduck; IDA 9.2, Ghidra 12, Binary Ninja 5.2, radare2/rizin/Cutter, x64dbg, WinDbg TTD, capa v9, FLOSS v3, Diaphora, BinDiff, angr; VirusTotal/GTI, Intezer, ReversingLabs, MISP 2.5, OpenCTI 7, abuse.ch, Malpedia/MCRIT, Assemblyline 4, Strelka, DFIR-IRIS, Cortex, Maltego; Volatility 3, MemProcFS, MobSF, Androguard, quark-engine, oletools, ViperMonkey, box-js, CyberChef, Didier Stevens suite; Magika, EMBER2024, YARA-X, Sigma, YARA-L, capa/MBC, CASCADE, GhidraMCP/aidapal, MITRE ATT&CK, STIX 2.1/TAXII, MACO. Full URL list retained in the research notes backing this spec.
