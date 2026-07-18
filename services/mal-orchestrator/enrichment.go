package main

// the AI-analyst plane wired into the durable spine as an ASYNC, post-verdict
// step. it is a SEPARATE workflow from the deterministic SubmissionWorkflow,
// which it never touches: EnrichmentWorkflow takes that workflow's finalized
// result and returns an enriched copy. this preserves the one law - agents
// propose, the spine disposes - structurally: the deterministic verdict is
// computed and durable before any model is consulted, and the enrichment can only
// add capped mal-ai findings and raise a review flag, never move the verdict down
// or block a submission. it is air-gapped by default (no model -> a no-op) and
// caged at every layer (a provider or contract failure returns the result
// unchanged).

import (
	"context"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// the model call is slow (local vLLM on CPU can take minutes); a timeout is
// deterministic for a given evidence set, so a single attempt - a retry only
// burns the same wait again.
const enrichmentActivityTimeout = 5 * time.Minute

// AIEnrichment is the AI plane's contribution to a submission. it is additive
// evidence, never a ruling: Findings are capped-SUSPICIOUS mal-ai findings and
// NeedsReview is a one-way escalation flag. Outcome/Provider/LedgerHead carry the
// audit trail (the ledger head is the anchor a persistence layer verifies).
type AIEnrichment struct {
	Enabled     bool
	Findings    []pipeline.Finding
	NeedsReview bool
	Provider    string
	Outcome     string // gated | rejected | provider-error | disabled
	LedgerHead  string
}

// EnrichWithAIActivity runs the caged AI plane over a finalized deterministic
// result. it is a no-op when no model is configured (the air-gapped default), and
// it NEVER returns a fatal error: the plane is caged, so any provider or contract
// failure yields an empty (but ledgered) enrichment and the deterministic verdict
// stands untouched.
func (a *Analyzer) EnrichWithAIActivity(ctx context.Context, res pipeline.SubmissionResult) (AIEnrichment, error) {
	if a == nil || a.aiplane == nil {
		return AIEnrichment{Enabled: false, Outcome: "disabled"}, nil
	}
	gr, hs, err := a.aiplane.Enrich(ctx, res)
	out := AIEnrichment{
		Enabled:    true,
		Provider:   hs.Provider,
		Outcome:    hs.Outcome,
		LedgerHead: a.aiplane.Ledger().Head(),
	}
	if err != nil {
		// caged: the failure is recorded in the ledger, but is not fatal - this run
		// simply contributes no enrichment.
		return out, nil
	}
	out.Findings = gr.EnrichmentFindings()
	out.NeedsReview = gr.NeedsHuman
	return out, nil
}

// applyEnrichment folds an enrichment into a result under the SAME fail-closed
// lattice as every engine: verdicts are joined (raise-only - the findings are
// capped at SUSPICIOUS by construction, so this can never reach MALICIOUS on the
// AI's word or lower anything), findings are appended, and the review flag is a
// one-way raise. the triage Score/Confidence are deliberately left as the
// deterministic values, so AI enrichment can flag and escalate but never re-weight
// the queue priority.
func applyEnrichment(res pipeline.SubmissionResult, enr AIEnrichment) pipeline.SubmissionResult {
	for _, f := range enr.Findings {
		res.Verdict = pipeline.Max(res.Verdict, f.Verdict)
		res.Findings = append(res.Findings, f)
	}
	if enr.NeedsReview {
		res.NeedsReview = true
	}
	return res
}

// EnrichmentWorkflow is the async, post-verdict enrichment step, started after
// SubmissionWorkflow has produced and durably recorded its verdict. it returns an
// enriched copy of that result; if the plane is disabled or fails, it returns the
// result unchanged. the deterministic verdict is authoritative and self-sufficient
// with or without this workflow ever running.
func EnrichmentWorkflow(ctx workflow.Context, res pipeline.SubmissionResult) (pipeline.SubmissionResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: enrichmentActivityTimeout,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var a *Analyzer // nil receiver: the activity resolves by name
	var enr AIEnrichment
	if err := workflow.ExecuteActivity(ctx, a.EnrichWithAIActivity, res).Get(ctx, &enr); err != nil {
		// caged at the workflow boundary too: an enrichment failure never fails the
		// submission - return the deterministic result unchanged.
		return res, nil
	}
	return applyEnrichment(res, enr), nil
}
