# ASK - resources & infrastructure I need from you

This is the living list of everything I need **from you** to take the agentic build
all the way to live operation. It is maintained end-to-end.

**How this works**
- I build **everything** against interfaces with deterministic mocks, so a missing
  key or endpoint never blocks the *build* - only *live operation*. I do not change
  the plan while waiting; I wire a placeholder and keep going.
- Each item has a **criticality**: `BLOCKING` (I genuinely cannot make progress
  without it - I will stop and ask), `LIVE` (needed only to run against real
  models/infra; build+tests proceed with mocks), or `NICE` (optional).
- When you provide something, tell me the value (or that it is set in the
  environment) and I will flip its status to `PROVIDED` and wire it in.
- Placeholders use env vars; nothing secret is ever committed (same
  `--mount=type=secret` / env pattern the capa/floss workers already use).

**Legend** - status: `OPEN` | `PROVIDED` | `DEFERRED` | criticality: `BLOCKING` | `LIVE` | `NICE`

---

## 1. LLM inference (the local model behind the agents)

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| LLM-1 | Local LLM served OpenAI-compatible (vLLM/Ollama). Which open-weight model (design suggests Qwen/Llama-class, quantized)? | every agent's reasoning call | `MAL_MODEL_URL` (loopback), `MAL_MODEL_NAME` | LIVE | OPEN - plane LIVE-VALIDATED end-to-end against a real OpenAI-compatible endpoint; only the *local* model choice remains |
| LLM-2 | Is there a GPU host for vLLM, or CPU-only? affects model size + latency budgets | sizing timeouts / model choice | n/a | LIVE | OPEN |
| LLM-3 | Guarded **cloud** LLM adapter - IMPLEMENTED: a non-loopback `MAL_MODEL_URL` is refused unless `MAL_ALLOW_CLOUD=1` is set, then evidence is minimized on egress (hash + paths dropped) and TLS uses the OS trust store | cloud fallback behind the egress gate | `MAL_MODEL_URL` (non-loopback) + `MAL_MODEL_KEY` + `MAL_ALLOW_CLOUD=1` | NICE | PROVIDED - a test key was supplied out-of-band for live validation; not stored in-repo |

> **Live validation done.** The full nine-agent roster, both HTTP endpoints
> (`/v1/analyze`, `/v1/agent/{name}`), and the Go orchestrator seam
> (`RunRosterActivity` -> gate) have all been run end-to-end against a real
> OpenAI-compatible model. To reproduce: set `MAL_MODEL_URL` / `MAL_MODEL_NAME` /
> `MAL_MODEL_KEY` / `MAL_ALLOW_CLOUD=1`, run `uvicorn malagents.app:app`, then
> `MAL_LIVE_ROSTER_URL=<url> go test -run TestLiveRosterSeam ./services/mal-orchestrator/`.
> The offline default (TestModel + gate mocks) still exercises everything with zero egress.

## 2. Embeddings (for L2 semantic / GraphRAG novelty fallback)

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| EMB-1 | Local embedding model + endpoint (sovereign: prefer a local server, e.g. an embeddings-capable vLLM or a small local model) | L2 semantic retrieval vectors | `MAL_EMBED_URL`, `MAL_EMBED_MODEL` | LIVE | OPEN |
| EMB-2 | Embedding dimension of the chosen model | vector-store schema | `MAL_EMBED_DIM` | LIVE | OPEN |

## 3. Graph / vector store (persistent knowledge behind L1 / L2)

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| STORE-1 | Persistent graph store choice + connection (Neo4j / Memgraph / other). In-memory `MemGraph` is the default until this lands | L1 attribution graph across restarts | `MAL_GRAPH_URL`, creds via secret | LIVE | OPEN |
| STORE-2 | Vector store for L2 (Qdrant / pgvector / other) + connection | L2 semantic nearest-neighbour | `MAL_VECTOR_URL`, creds via secret | LIVE | OPEN |

## 4. Observability

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| OBS-1 | Self-hosted **Langfuse** instance URL + public/secret keys | trace every agent decision/prompt/gate outcome (design sec 10/sec 11) | `MAL_LANGFUSE_URL`, `MAL_LANGFUSE_PUBLIC_KEY`, `MAL_LANGFUSE_SECRET_KEY` (secret) | LIVE | OPEN |

## 5. Corpora / threat-intel for L0 pre-seeding (design sec 08)

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| SEED-1 | ATT&CK + MBC + capa metadata | curated L0 facts on day one | bundled in-repo (no ask) | LIVE | RESOLVED (bundled) |
| SEED-2 | **Malpedia** API key (family names/aliases) - or confirm we skip it | richer curated family facts | `MAL_MALPEDIA_KEY` (secret) | NICE | OPEN |
| SEED-3 | **abuse.ch** (URLhaus/ThreatFox) Auth-Key - or confirm we skip it | curated known-C2 facts | `MAL_ABUSECH_KEY` (secret) | NICE | OPEN |

## 6. Learning tiers 2 & 3 (design sec 09)

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| LEARN-1 | Compute for **LoRA** fine-tuning (tier-3): GPU host or a training service | offline, human-approved model adaptation | `MAL_TRAIN_HOST` | LIVE | OPEN |
| LEARN-2 | Confirm the **DSPy** tier-2 prompt-optimization may run offline in CI against the golden set | tune prompts/routing on validated data | n/a | LIVE | OPEN |

## 7. Deployment / infra

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| INFRA-1 | Confirm the deployment can add a **Python agent service** container (jailed, same broker pattern as capa/floss) | host the Pydantic-AI roster | n/a | LIVE | OPEN |
| INFRA-2 | pip via Artifactory index (secret `pip.conf`) - reuse the existing capa/floss pattern | build the Python agent service image | `MAL_PIP_CONF` (secret) | LIVE | RESOLVED (pattern known) |

## 8. Test / evaluation data (design sec 11)

| id | what | why | placeholder | crit | status |
|----|------|-----|-------------|------|--------|
| EVAL-1 | A labeled **golden set** of samples (verdict + family + TTPs), if you have one; else I build a synthetic/EICAR-based set | regression + calibration evals | `deploy/eval/golden/` | NICE | OPEN |

---

## Resolved / historical asks

- **Corp TLS (Zscaler) interception** - resolved: build stages append optional
  `deploy/certs/*.pem` (gitignored); runtime images are scratch. No action needed on clean nets.
- **Artifactory pip index** - resolved pattern: `--mount=type=secret,id=pip_conf`;
  `MAL_PIP_CONF=$HOME/.pip/pip.conf` at build; unset -> public PyPI in CI.
- **Logo assets** - provided by you, committed under `docs/brand/`.

---

## Nothing here is blocking the build right now

Every item above is `LIVE` or `NICE`. I am building the full design with mocks
(a deterministic test LLM, in-memory graph, hash-based test embedder, no-op
tracer) and real interfaces, so it is all coded, tested, and edge-cased offline.
When you drop in the real endpoints/keys, it goes live by config alone. I will
add any new ask here the moment it arises and flag it if it ever becomes
`BLOCKING`.
