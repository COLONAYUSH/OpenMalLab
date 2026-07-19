# OpenMalLab - Phase 1 live runbook (sovereign, air-gapped)

Bring the whole platform up on one box: the deterministic engine pipeline **and**
the AI-analyst plane, with a **local model** on a no-egress network. Submit a file,
get a verdict in the console, watch the AI enrich it and escalate for review.

## Prerequisites
- Docker (or Colima) running, with enough disk for the model (~2 GB) and images.
- `curl`, `python3` (for the proof script).
- Corporate pip index: set `MAL_PIP_CONF` (see `.env.example`) so the Python images
  build. Clean network: leave it unset (public PyPI).

## One command
```
cp .env.example .env      # optional; edit MAL_MODEL_NAME etc.
make live                 # build images -> provision the model -> bring the stack up
make e2e-live             # prove the full loop end to end
```
`make live` runs three steps in order (they can also be run individually):
1. `make build` - build all images.
2. `make bootstrap-model` - pull the model **once** into a named volume. This is the
   only step that needs egress; the runtime model server is air-gapped and cannot
   pull, so the volume must be filled first.
3. `make up` - bring the stack up.

Console: <http://localhost:8090> &nbsp; API: <http://localhost:8080>

## What "live" looks like
- Submit a file (console, or `curl -F file=@sample http://localhost:8080/v1/submissions`).
- The **deterministic verdict** appears in seconds (YARA / capa / FLOSS / ident / extract).
- The **AI plane** then enriches asynchronously (it never blocks or changes the
  deterministic verdict): a groundable sample gains a capped `mal-ai` finding and,
  when the gate escalates, a **"needs review"** item in the console.
- Resolve the review in the console (Approve + curate / Reject) - the decision is a
  gold label that curates the analysis facts.

## Sovereignty
The model runs in a container on the `aiplane` network, which is `internal: true`
(no route off the box). Evidence never leaves. To use a **guarded cloud model**
instead, set `MAL_MODEL_URL` (a public endpoint) + `MAL_MODEL_KEY` +
`MAL_ALLOW_CLOUD=1` in `.env`; evidence is minimized before egress. A container or
private-network model host needs **no** opt-in - only a public host does.

## Troubleshooting
- **`mal-agents` never becomes healthy / `make e2e-live` says the model is not
  provisioned** - run `make bootstrap-model` first. The Ollama healthcheck asserts
  the model is *present* (not just the server), and `mal-agents` waits on it, so the
  plane will not come up half-provisioned.
- **Python image build fails with an SSL error** - you are on a proxied network and
  need `MAL_PIP_CONF` pointed at your credentialed pip index.
- **Enrichment is slow** - a CPU model + the full roster can take minutes. The
  deterministic verdict is instant regardless; enrichment is async and capped.

## Deferred to Phase 2
Dynamic analysis / sandbox detonation, the DIE packer gate, scale stores
(Neo4j/Qdrant) + live L2 vectors, the DSPy/LoRA learning tiers, OIDC/authz.
