# MalAnalyzer - M0 First-Commit Spec (start-here)

> The build starts here. Greenfield on Temporal (D7), **hostile-boundary-first** (D4), static wedge only (D2). This doc is a builder's spec, not a design essay - it says exactly what commit 1 is, the security posture that is non-negotiable in commit 1, the 2-day spike, and the build order to a usable product in ~6 weeks. If it isn't here, it's a later milestone.

## Stack (per ADR-004; minimum stateful set per D5, trimmed further at M0)
- **mal-gateway** - Go - REST submit, OIDC, OPA, audit intake.
- **mal-orchestrator** - Go + **Temporal** - `SubmissionWorkflow` + recursive `ArtifactWorkflow`, recursion caps, monotone-max aggregation, **the persistence broker** (the only writer of Postgres/vault) incl. the `AnalyzeResult` sub-process decoder.
- **mal-ident** - Rust - Magika (ONNX).
- **mal-extract** - Rust - recursive unarchive wrapping libarchive/7z/unrar (safety from the sandbox, not the Rust shell).
- **mal-static-\*** - Python - DIE, FLOSS, capa, YARA-X (M1); **mal-static-config** embedding `configextractor-py` + `Maco` (M2 differentiator).
- **mal-web** - TS/React - triage queue, evidence tree, inert render.
- **Stateful set (M0): Postgres + Temporal (dev-server single binary) + SeaweedFS + OpenBao.** **No NATS, no Valkey, no Qdrant/graph/OpenSearch** - dispatch rides Temporal task queues; recursion caps use a **durable Postgres counter** (`UPDATE ... SET n=n-1 WHERE n>0 RETURNING`), which also closes RM-6 (never-Valkey-alone) and RM-21 (no second async system). Add NATS only if throughput later demands it.

## Commit 1 = the walking skeleton (one real engine, not a stub)
```
submit -> mal-gateway (auth + audit) -> SeaweedFS vault (per-sample DEK, wrapped in OpenBao)
       -> Temporal SubmissionWorkflow -> Identify activity (Magika)
       -> mal-extract WORKER  -- artifact in via READ-ONLY MOUNTED FD (sidecar-fetched; worker resolves no URL)
                              -- AnalyzeResult proto OUT via MOUNTED UDS
       -> orchestrator BROKER decodes AnalyzeResult in an unprivileged seccomp sub-process -> writes PG/vault
       -> recursive ArtifactWorkflow per child (depth / dup / total-node caps via the Postgres counter)
       -> monotone-max aggregation -> verdict tree -> mal-web
```
Run **one real engine in commit 1 - capa or DIE**, not a stub (the boundary must carry real hostile-derived output from day one).

## Non-negotiable in commit 1 (the boundary-first posture - this is the product)
1. **Worker isolation:** joined to an **empty network namespace** (no interfaces, not even loopback), `--cap-drop=ALL`, `no-new-privileges`, **seccomp allow-list**, read-only rootfs, scratch on `tmpfs noexec,nosuid,nodev`, cgroup mem/CPU/`pids` limits + wall-clock kill, **single-use** (one artifact then exit), **zero store credentials**.
2. **Artifact in:** read-only mounted fd (a sidecar in another namespace fetches the content-addressed bytes and mounts them). The worker never holds a URL or a socket.
3. **Result out -> broker:** `AnalyzeResult` (bounded schema - array/string/total caps, field allow-list, no `Any`/`Struct`/nesting) over a **mounted UDS**; the **orchestrator-side broker decodes it in an unprivileged, seccomp-strict, network-dead sub-process** before any DB/vault write; **fail-closed** on malformed (node -> `SUSPICIOUS`). The broker, not the worker, writes stores.
4. **Extractor safety:** reject `..` / absolute paths / symlinks; entry-count, compression-ratio, and total-decompressed-size caps; **re-hash producer bytes** (`SHA256(bytes)==claimed`) before any WORM write (RM-3).
5. **Verdict lattice:** `BENIGN=0 < UNKNOWN=1 < SUSPICIOUS=2 < MALICIOUS=3`; `node_verdict = max(own, max(unique children))`; fail-closed (crash/timeout/truncation -> `SUSPICIOUS`, never `BENIGN`).
6. **Schema scaffolding (pin != build, D1):** every row carries `domain_id`; `samples` PK = `(domain_id, sha256)`; DEKs live in OpenBao (not WORM). Do **not** build per-domain dedup, the crypto-shred sweep, or the hash-chained-audit *mechanism* yet - leave the columns/shape open.
7. **CI from commit 1:** the section 11 extraction corpus (zip bombs, traversal, malformed archives) + continuous fuzz of `mal-extract` / `mal-ident` / the **broker** + the verdict-lattice 4x4 property test + the **invariant->test traceability gate** (build fails if any invariant/residual lacks a linked test).

**Commit-1 acceptance:** a real nested ZIP round-trips to an explainable verdict tree, the worker demonstrably has **no network interface and no store credential**, on a **reproducible build**, fully audited.

## The 2-day spike (M0 week 1 - designed to *refute* greenfield, D7)
- **Day 1 (attack adopt):** mirror AL4 images offline, stand up its compose appliance on the single node (measure RAM/disk/container-count/time-to-first-scan). Then try to run a stock AL4 service `--network none` **and** credential-less (Standard mode can't reach `/api/v1/task/`; Privileged needs Redis/Datastore creds). Confirm the Elasticsearch-8 hard-pin. *Overturn rule:* if any AL4 service runs netns-empty **and** credential-less -> revisit adoption.
- **Day 2 (prove greenfield - this IS commit 1):** stand up the walking skeleton above; embed `configextractor-py` + `Maco` (MIT backends only) in a static worker and pull a config from one known-family sample. *Confirm rule:* a credential-less/netns-empty worker reaches a recursive explainable verdict in ~1 day -> **C confirmed, proceed.** If not -> reconsider vendoring AL4's extractor as a reference-port only.

## Build order (re-scoped; ~6 weeks to a used product)
| Milestone | Content | Accept |
|---|---|---|
| **M0** (~1-2 wk) | Boundary-first spine + 1 real engine + repro-build spike + AL spike | commit-1 acceptance above |
| **M1** (~2 wk) | Full static wedge: Magika + extract + DIE + FLOSS + capa + YARA-X; recursive DAG; fail-closed caps; aggregation | section 11 static adversarial corpus passes |
| **M2** (~2 wk) | **Differentiator:** MACO config/family extraction (starter family set) + triage queue + evidence tree + inert render + defanged export | **a real analyst triages a real sample end-to-end and pulls a config** |
| **M3** | Hardening & release: OPA policy tests, mTLS, tamper-evident-audit *mechanism*, SBOM, signed offline bundle, full section 11 + traceability gate | full suite + repro-build + offline-install |

Detonation (Tier-2 KVM + pump + separate node), AI, hunting/graph, multi-tenancy = **Phase-2+** (D2). The extractor is the top build risk - **wrap, never write**; read AL4's MIT extract service for limit values; the section 11 corpus defines "done."
