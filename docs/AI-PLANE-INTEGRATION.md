# AI plane integration seam

The AI-analyst plane (`internal/aiplane`) is built, tested, and self-contained.
This document specifies exactly how it wires into the running platform, and why
the wiring is shaped the way it is. It is a seam spec: the code surface exists and
is proven; lighting it up requires model + knowledge-store infrastructure the
operator provides.

## The one law

`agents propose, the spine disposes`. The deterministic `SubmissionWorkflow`
computes the verdict with a fail-closed, only-up lattice (`pipeline.Max`). The AI
plane must never sit inside that path. It runs AFTER a verdict exists, as
enrichment, and it is caged: `AIPlane.Enrich` never fails the pipeline, and its
output can only add `mal-ai` findings capped at `SUSPICIOUS` (via
`EnrichmentVerdict`) plus a human-review flag. It can never reach `MALICIOUS`
alone, never lower a verdict, and never block a submission from completing.

## Shape: an async enrichment workflow, not an inline activity

Enrichment is a SEPARATE workflow (its own task queue and worker), started after
`SubmissionWorkflow` returns. This keeps three properties:

- the deterministic verdict is durable and returned to the caller with zero added
  latency from the model;
- an air-gapped deployment with no model simply never starts the enrichment
  worker - nothing to disable, nothing dormant in the hot path;
- the model call, which is slow and untrusted, is isolated with its own timeouts,
  retries, and blast radius.

```
SubmissionWorkflow (deterministic) --> verdict persisted --> caller
        |
        \--(signal / parent-close policy ABANDON)--> EnrichmentWorkflow
                                                        |
                                     aiplane.AIPlane.Enrich(ctx, result)
                                                        |
                              GateResult + Handshake (hash-chained ledger)
                                                        |
                          accepted -> res.Findings += EnrichmentFindings()  (capped)
                          NeedsHuman -> review queue
```

## The hook (the entire trusted-side code)

In the enrichment worker's activity, given the finalized `pipeline.SubmissionResult`:

```go
gr, hs, err := plane.Enrich(ctx, result)
// err is DIAGNOSTIC ONLY. never fail the submission on it; the verdict stands.
_ = hs // sealed into plane.Ledger(); persist alongside the submission for audit
if err == nil {
    result.Findings = append(result.Findings, gr.EnrichmentFindings()...) // mal-ai, <= SUSPICIOUS
    if gr.NeedsHuman {
        result.NeedsReview = true // route to the analyst queue
    }
}
```

`EnrichmentFindings()` returns only ACCEPTED hypotheses, each tagged engine
`mal-ai`, confidence `LOW`, verdict capped at `SUSPICIOUS`. Re-folding them through
the same lattice can only raise the stored verdict by one bounded step, so the
enrichment is subject to the identical fail-closed rule as every engine.

## Constructing the plane (worker startup)

```go
reg := knowledge.NewRegistry(store)            // L0, seeded from bundled corpora
gate := aiplane.NewGate(reg)                    // citations verified against L0
prov, err := aiplane.NewLocalProvider(os.Getenv("OPENMALLAB_MODEL_URL"), model)
// NewLocalProvider REFUSES a non-loopback host. cloud egress is a separate,
// explicit opt-in: aiplane.NewCloudProvider, which an air-gapped build never calls.
plane := aiplane.NewAIPlane(prov, gate)
```

If `OPENMALLAB_MODEL_URL` is unset, the enrichment worker is not started and the
platform runs deterministic-only. This is the air-gapped default.

## Compose services (only when enrichment is enabled)

- `vllm` - the local model server, bound to `127.0.0.1`, exposing the
  OpenAI-compatible `/v1/chat/completions` API `HTTPProvider` speaks. No egress.
- `langfuse` - self-hosted observability for the model calls (traces, evals).
  Self-hosted so no telemetry leaves the boundary.
- graph/knowledge store - the persistent backend behind the `knowledge.Store`
  interface (L0/L0.5/L1). Must implement `Merge` as a serializable upsert so the
  poisoning guard stays atomic (see `internal/knowledge`).

## What must remain true (verified by the eval corpus)

`aiplane.Corpus()` is the standing regression gate. Any change here must keep it
green: grounded+allow-listed accepts (including a C2-url key, which must survive
the contract byte-for-byte and NOT be defanged into a non-matching handle),
high-stakes and confident-ungrounded escalations, ungrounded noise dropped,
ingest-only treated as context, forged citations refused grounding, and every
hostile input failing closed at the contract.

The handshake ledger must `Verify()` after every run. When the ledger is
persisted, the reload MUST use `VerifyAgainst(count, head)` with the entry count
and head hash held in an out-of-band anchor (the durable Temporal history or an
operator signature): the chain is unkeyed, so plain `Verify()` alone cannot catch
a store-writer who tail-truncates or wholesale re-seals it. The human-review flag
rides back on `pipeline.SubmissionResult.NeedsReview` (set only by this seam,
never by an engine).
