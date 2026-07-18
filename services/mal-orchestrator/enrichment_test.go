package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/aiplane"
	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

func TestApplyEnrichmentRaisesOnly(t *testing.T) {
	// raise: an accepted SUSPICIOUS enrichment lifts UNKNOWN to SUSPICIOUS and
	// flags review.
	got := applyEnrichment(
		pipeline.SubmissionResult{Verdict: pipeline.Unknown},
		AIEnrichment{Enabled: true, NeedsReview: true, Findings: []pipeline.Finding{
			{Engine: "mal-ai", Type: "ai-technique", Verdict: pipeline.Suspicious, Confidence: pipeline.ConfLow},
		}})
	if got.Verdict != pipeline.Suspicious || len(got.Findings) != 1 || !got.NeedsReview {
		t.Fatalf("enrichment not folded: %+v", got)
	}

	// never lower: a SUSPICIOUS enrichment cannot pull a MALICIOUS verdict down.
	got = applyEnrichment(
		pipeline.SubmissionResult{Verdict: pipeline.Malicious},
		AIEnrichment{Enabled: true, Findings: []pipeline.Finding{{Verdict: pipeline.Suspicious}}})
	if got.Verdict != pipeline.Malicious {
		t.Fatalf("enrichment must never lower a verdict: %v", got.Verdict)
	}

	// disabled/empty enrichment leaves the result untouched.
	base := pipeline.SubmissionResult{Verdict: pipeline.Unknown}
	if got = applyEnrichment(base, AIEnrichment{Enabled: false}); got.Verdict != pipeline.Unknown || len(got.Findings) != 0 || got.NeedsReview {
		t.Fatalf("disabled enrichment must be a no-op: %+v", got)
	}
}

func TestEnrichActivityDisabledWhenNoPlane(t *testing.T) {
	enr, err := (&Analyzer{}).EnrichWithAIActivity(context.Background(), pipeline.SubmissionResult{SubmissionID: "s"})
	if err != nil || enr.Enabled || enr.Outcome != "disabled" {
		t.Fatalf("no plane must be a disabled no-op: %+v (err=%v)", enr, err)
	}
}

func TestEnrichActivityCagedOnProviderError(t *testing.T) {
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	a := &Analyzer{aiplane: aiplane.NewAIPlane(aiplane.MockProvider{Err: fmt.Errorf("model down")}, aiplane.NewGate(reg))}
	enr, err := a.EnrichWithAIActivity(context.Background(), pipeline.SubmissionResult{SubmissionID: "s"})
	if err != nil {
		t.Fatalf("the plane is caged: a provider error must NOT fail the activity: %v", err)
	}
	if !enr.Enabled || enr.Outcome != "provider-error" || len(enr.Findings) != 0 {
		t.Fatalf("caged failure not recorded cleanly: %+v", enr)
	}
}

func TestEnrichActivityGroundedProducesCappedFinding(t *testing.T) {
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(fmt.Sprintf(
		`{"summary":"x","hypotheses":[{"kind":"technique","claim":"process injection","confidence":"LOW","citations":[{"fact_id":%q,"kind":"attck","key":"T1055"}]}]}`,
		f.ID))
	a := &Analyzer{aiplane: aiplane.NewAIPlane(aiplane.MockProvider{Raw: raw}, aiplane.NewGate(reg))}

	enr, err := a.EnrichWithAIActivity(context.Background(), pipeline.SubmissionResult{SubmissionID: "s"})
	if err != nil {
		t.Fatalf("activity: %v", err)
	}
	if enr.Outcome != "gated" || len(enr.Findings) != 1 {
		t.Fatalf("grounded hypothesis should yield one enrichment finding: %+v", enr)
	}
	if enr.Findings[0].Engine != "mal-ai" || enr.Findings[0].Verdict != pipeline.Suspicious || enr.Findings[0].Confidence != pipeline.ConfLow {
		t.Fatalf("enrichment finding not tagged/capped: %+v", enr.Findings[0])
	}
}

func TestEnrichmentWorkflowFolds(t *testing.T) {
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	a := &Analyzer{}
	env.OnActivity(a.EnrichWithAIActivity, mock.Anything, mock.Anything).Return(
		AIEnrichment{Enabled: true, NeedsReview: true, Findings: []pipeline.Finding{
			{Engine: "mal-ai", Type: "ai-technique", Verdict: pipeline.Suspicious, Confidence: pipeline.ConfLow},
		}}, nil)

	env.ExecuteWorkflow(EnrichmentWorkflow, pipeline.SubmissionResult{SubmissionID: "s", Verdict: pipeline.Unknown})
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete cleanly: %v", env.GetWorkflowError())
	}
	var res pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatal(err)
	}
	if res.Verdict != pipeline.Suspicious || !res.NeedsReview || len(res.Findings) != 1 {
		t.Fatalf("workflow did not fold the enrichment: %+v", res)
	}
}

func TestEnrichmentWorkflowCagedOnActivityError(t *testing.T) {
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	a := &Analyzer{}
	env.OnActivity(a.EnrichWithAIActivity, mock.Anything, mock.Anything).Return(AIEnrichment{}, fmt.Errorf("boom"))

	in := pipeline.SubmissionResult{SubmissionID: "s", Verdict: pipeline.Malicious, Findings: []pipeline.Finding{{Engine: "mal-static-yara", Verdict: pipeline.Malicious}}}
	env.ExecuteWorkflow(EnrichmentWorkflow, in)
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("a caged enrichment failure must not fail the workflow: %v", env.GetWorkflowError())
	}
	var res pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatal(err)
	}
	// the deterministic result is returned unchanged.
	if res.Verdict != pipeline.Malicious || len(res.Findings) != 1 || res.NeedsReview {
		t.Fatalf("failed enrichment must return the deterministic result unchanged: %+v", res)
	}
}
