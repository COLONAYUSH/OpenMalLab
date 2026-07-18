package aiplane

import (
	"context"
	"fmt"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

func TestAIPlaneEnrichAccepts(t *testing.T) {
	r := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := r.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(fmt.Sprintf(
		`{"summary":"x","hypotheses":[{"kind":"technique","claim":"process injection","confidence":"LOW","citations":[{"fact_id":%q,"kind":"attck","key":"T1055"}]}]}`,
		f.ID))
	plane := NewAIPlane(MockProvider{Raw: raw}, NewGate(r))

	gr, hs, err := plane.Enrich(context.Background(), pipeline.SubmissionResult{SubmissionID: "s"})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if hs.Outcome != "gated" || hs.Accepted != 1 || hs.EvidenceHash == "" || hs.ProposalHash == "" {
		t.Fatalf("handshake not recorded correctly: %+v", hs)
	}
	// retrieval provenance: the ledger records which fact the grounding rested on.
	if len(hs.CitedFactIDs) != 1 || hs.CitedFactIDs[0] != f.ID || len(hs.RetrievalTiers) != 1 || hs.RetrievalTiers[0] != "L0" {
		t.Fatalf("retrieval provenance not recorded: %+v", hs)
	}
	if err := plane.Ledger().Verify(); err != nil {
		t.Fatalf("ledger must verify: %v", err)
	}
	// the accepted hypothesis becomes a capped, tagged finding.
	fs := gr.EnrichmentFindings()
	if len(fs) != 1 {
		t.Fatalf("want 1 enrichment finding, got %d", len(fs))
	}
	if fs[0].Engine != "mal-ai" || fs[0].Type != "ai-technique" ||
		fs[0].Verdict != pipeline.Suspicious || fs[0].Confidence != pipeline.ConfLow {
		t.Fatalf("enrichment finding not capped/tagged: %+v", fs[0])
	}
}

func TestAIPlaneCagedOnProviderError(t *testing.T) {
	plane := NewAIPlane(MockProvider{Err: fmt.Errorf("model down")}, NewGate(knowledge.NewRegistry(knowledge.NewMemStore())))
	gr, hs, err := plane.Enrich(context.Background(), pipeline.SubmissionResult{SubmissionID: "s"})
	if err == nil {
		t.Fatal("provider error should be surfaced (diagnostically)")
	}
	if hs.Outcome != "provider-error" || len(gr.Hypotheses) != 0 {
		t.Fatalf("caged failure not recorded cleanly: %+v", hs)
	}
	// the failure is still auditable and the chain intact.
	if err := plane.Ledger().Verify(); err != nil {
		t.Fatalf("ledger must verify even on failure: %v", err)
	}
	if len(gr.EnrichmentFindings()) != 0 {
		t.Fatal("a caged failure must contribute no findings")
	}
}

func TestAIPlaneCagedOnInvalidOutput(t *testing.T) {
	plane := NewAIPlane(MockProvider{Raw: []byte("{not json")}, NewGate(knowledge.NewRegistry(knowledge.NewMemStore())))
	_, hs, err := plane.Enrich(context.Background(), pipeline.SubmissionResult{SubmissionID: "s"})
	if err == nil {
		t.Fatal("invalid output should be surfaced")
	}
	if hs.Outcome != "rejected" || hs.ProposalHash == "" {
		t.Fatalf("rejection not recorded (raw was received): %+v", hs)
	}
}

func TestAIPlaneNotConfigured(t *testing.T) {
	plane := NewAIPlane(nil, nil)
	_, hs, err := plane.Enrich(context.Background(), pipeline.SubmissionResult{SubmissionID: "s"})
	if err == nil || hs.Outcome != "provider-error" {
		t.Fatalf("unconfigured plane must fail closed and be recorded: %+v (err=%v)", hs, err)
	}
}

func TestEnrichmentFindingsOnlyAccepted(t *testing.T) {
	gr := GateResult{Hypotheses: []GatedHypothesis{
		{Hypothesis: Hypothesis{Kind: "technique", Claim: "a"}, Disposition: DispAccept},
		{Hypothesis: Hypothesis{Kind: "family", Claim: "b"}, Disposition: DispEscalate},
		{Hypothesis: Hypothesis{Kind: "capability", Claim: "c"}, Disposition: DispDrop},
	}}
	fs := gr.EnrichmentFindings()
	if len(fs) != 1 || fs[0].Type != "ai-technique" || fs[0].Verdict != pipeline.Suspicious {
		t.Fatalf("only the accepted hypothesis should enrich, capped at SUSPICIOUS: %+v", fs)
	}
}
