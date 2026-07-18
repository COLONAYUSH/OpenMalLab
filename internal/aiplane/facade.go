package aiplane

// AIPlane is the single, caged entrypoint the trusted pipeline calls. it ties the
// provider, the strict contract, the confidence gate, and the tamper-evident
// ledger into one flow with one hard rule: the AI plane can never fail the
// pipeline. a provider that errors, a response that fails Validate, a gate that
// escalates - all are recorded and returned, but the deterministic verdict stands
// on its own. agents propose; the spine disposes.

import (
	"context"
	"fmt"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// AIPlane wires a provider + gate + an append-only handshake ledger.
type AIPlane struct {
	provider Provider
	gate     *Gate
	ledger   *Ledger
}

// NewAIPlane builds the plane over a provider and gate with a fresh ledger.
func NewAIPlane(p Provider, g *Gate) *AIPlane {
	return &AIPlane{provider: p, gate: g, ledger: NewLedger()}
}

// Ledger exposes the handshake ledger for verification and audit.
func (a *AIPlane) Ledger() *Ledger { return a.ledger }

// Enrich runs the full gated flow for a deterministic result and seals a
// tamper-evident handshake. it NEVER fails the pipeline: the returned error is
// diagnostic only - on any provider or contract failure the caller keeps the
// deterministic verdict and simply gets no enrichment. every path (gated,
// rejected, provider-error) is recorded in the ledger, so the absence of
// enrichment is itself auditable.
func (a *AIPlane) Enrich(ctx context.Context, res pipeline.SubmissionResult) (GateResult, Handshake, error) {
	ev := EvidenceFrom(res)
	h := Handshake{
		SubmissionID: ev.SubmissionID,
		EvidenceHash: hashJSON(ev),
	}
	if a.provider == nil || a.gate == nil {
		h.Provider = "none"
		h.Outcome = "provider-error"
		return GateResult{}, a.ledger.Append(h), fmt.Errorf("aiplane: not configured")
	}
	h.Provider = a.provider.Name()

	raw, err := a.provider.Analyze(ctx, ev)
	if err != nil {
		h.Outcome = "provider-error"
		return GateResult{}, a.ledger.Append(h), fmt.Errorf("aiplane: provider %q: %w", a.provider.Name(), err)
	}
	h.ProposalHash = hashBytes(raw)

	prop, err := Validate(raw)
	if err != nil {
		h.Outcome = "rejected"
		return GateResult{}, a.ledger.Append(h), fmt.Errorf("aiplane: invalid model output: %w", err)
	}

	gr := a.gate.Evaluate(ev, prop)
	h.Outcome = "gated"
	h.NeedsHuman = gr.NeedsHuman
	for _, gh := range gr.Hypotheses {
		if gh.Disposition == DispAccept {
			h.Accepted++
		}
	}
	return gr, a.ledger.Append(h), nil
}

// EnrichmentFindings projects the ACCEPTED hypotheses into deterministic findings
// the pipeline can fold under its verdict lattice. each is tagged as engine
// "mal-ai", carries LOW confidence, and is capped at SUSPICIOUS via
// EnrichmentVerdict - so AI enrichment can only ever raise a verdict by one
// bounded step and can never reach MALICIOUS or lower anything. escalations and
// drops contribute no findings; escalations surface through NeedsHuman instead.
func (gr GateResult) EnrichmentFindings() []pipeline.Finding {
	var fs []pipeline.Finding
	for _, gh := range gr.Hypotheses {
		if gh.Disposition != DispAccept {
			continue
		}
		fs = append(fs, pipeline.Finding{
			Engine:     "mal-ai",
			Type:       "ai-" + gh.Kind,
			Detail:     gh.Claim, // already defanged by Validate
			Verdict:    EnrichmentVerdict(gh.Disposition),
			Confidence: pipeline.ConfLow,
		})
	}
	return fs
}
