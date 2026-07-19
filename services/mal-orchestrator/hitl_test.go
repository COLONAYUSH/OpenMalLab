package main

import (
	"strings"
	"testing"
	"time"

	"github.com/COLONAYUSH/OpenMalLab/internal/aiplane"
	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/testsuite"
)

func TestAgentGraphHITLApprovalCurates(t *testing.T) {
	// a grounded FAMILY hypothesis is high-stakes: the gate escalates it to a human
	// (never auto-accepts). the workflow awaits; an approving signal promotes the
	// analysis facts to CURATED memory - the gold label that trains the next run.
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := reg.Curate(knowledge.KindFamily, "emotet", "Emotet", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	resp := map[string][]byte{
		"router":              []byte(`{"agents":["family_hypothesizer","verifier"]}`),
		"family_hypothesizer": []byte(`{"family":"emotet","confidence":"HIGH","citations":[{"fact_id":"` + f.ID + `","kind":"family","key":"emotet"}]}`),
		"verifier":            []byte(`{"real":true,"reason":"supported"}`),
	}
	a := &Analyzer{
		agents:      mockCaller{resp: resp},
		gate:        aiplane.NewGate(reg),
		agentLedger: aiplane.NewLedger(),
		graph:       knowledge.NewGraph(knowledge.NewMemGraph()),
	}

	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	env.RegisterActivity(a.RunRosterActivity)
	env.RegisterActivity(a.GateActivity)
	env.RegisterActivity(a.IngestLearningActivity)
	// the analyst approves shortly after the workflow raises the review task.
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(reviewSignalName, ReviewDecision{Approved: true, Note: "confirmed emotet"})
	}, time.Millisecond)

	sha := strings.Repeat("d", 64)
	env.ExecuteWorkflow(AgentGraphWorkflow, pipeline.SubmissionResult{SubmissionID: "s", SHA256: sha, Verdict: pipeline.Unknown})
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete cleanly: %v", env.GetWorkflowError())
	}
	var out pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatal(err)
	}
	if !out.NeedsReview {
		t.Fatal("a high-stakes family hypothesis must be flagged for review")
	}
	// approval curated the sample (working-index would be TrustIngest).
	node, ok := a.graph.Node(knowledge.NodeSample, sha)
	if !ok || node.Trust != knowledge.TrustCurated {
		t.Fatalf("an approved review must curate the analysis as a gold label: %+v ok=%v", node, ok)
	}
}

func TestAgentGraphHITLTimeoutLeavesWorkingIndex(t *testing.T) {
	// no analyst responds: the review times out (fired instantly by the test clock),
	// the deterministic verdict stands, and the facts stay in the low-trust working
	// index - never auto-promoted to curated without a human.
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, _ := reg.Curate(knowledge.KindFamily, "emotet", "Emotet", nil, "seed")
	resp := map[string][]byte{
		"router":              []byte(`{"agents":["family_hypothesizer","verifier"]}`),
		"family_hypothesizer": []byte(`{"family":"emotet","confidence":"HIGH","citations":[{"fact_id":"` + f.ID + `","kind":"family","key":"emotet"}]}`),
		"verifier":            []byte(`{"real":true}`),
	}
	a := &Analyzer{agents: mockCaller{resp: resp}, gate: aiplane.NewGate(reg), agentLedger: aiplane.NewLedger(), graph: knowledge.NewGraph(knowledge.NewMemGraph())}
	sha := strings.Repeat("e", 64)
	out := runGraph(t, a, pipeline.SubmissionResult{SubmissionID: "s", SHA256: sha, Verdict: pipeline.Unknown})
	if !out.NeedsReview {
		t.Fatal("escalation should still flag review even if no human responds")
	}
	if node, ok := a.graph.Node(knowledge.NodeSample, sha); !ok || node.Trust != knowledge.TrustIngest {
		t.Fatalf("without approval the analysis must stay in the working index: %+v ok=%v", node, ok)
	}
}
