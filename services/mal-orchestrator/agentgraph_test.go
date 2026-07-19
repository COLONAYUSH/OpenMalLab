package main

import (
	"context"
	"strings"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/aiplane"
	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
	"go.temporal.io/sdk/testsuite"
)

// mockCaller stands in for the Python roster service: canned bytes per agent name
// (a missing name returns nil, which the roster activity simply skips).
type mockCaller struct{ resp map[string][]byte }

func (m mockCaller) call(_ context.Context, name string, _ agentReq) ([]byte, error) {
	return m.resp[name], nil
}

func seededGate(t *testing.T) (*aiplane.Gate, string) {
	t.Helper()
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	return aiplane.NewGate(reg), f.ID
}

func runGraph(t *testing.T, a *Analyzer, in pipeline.SubmissionResult) pipeline.SubmissionResult {
	t.Helper()
	var ts testsuite.WorkflowTestSuite
	env := ts.NewTestWorkflowEnvironment()
	env.RegisterActivity(a.RunRosterActivity)
	env.RegisterActivity(a.GateActivity)
	env.RegisterActivity(a.IngestLearningActivity)
	env.RegisterActivity(a.RecordOutcomeActivity)
	env.ExecuteWorkflow(AgentGraphWorkflow, in)
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete cleanly: %v", env.GetWorkflowError())
	}
	var out pipeline.SubmissionResult
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAgentGraphFoldsAcceptedEnrichment(t *testing.T) {
	gate, factID := seededGate(t)
	// router -> capability_reasoner (technique citing the curated T1055) -> verifier real.
	resp := map[string][]byte{
		"router":              []byte(`{"agents":["capability_reasoner","verifier"]}`),
		"capability_reasoner": []byte(`{"behaviors":[{"ttp":"T1055","why":"injects into a remote process","citations":[{"fact_id":"` + factID + `","kind":"attck","key":"T1055"}]}]}`),
		"verifier":            []byte(`{"real":true,"reason":"evidence supports it"}`),
	}
	a := &Analyzer{agents: mockCaller{resp: resp}, gate: gate, agentLedger: aiplane.NewLedger()}

	out := runGraph(t, a, pipeline.SubmissionResult{SubmissionID: "s", Verdict: pipeline.Unknown})
	if out.Verdict != pipeline.Suspicious {
		t.Fatalf("grounded+verified enrichment must raise the verdict to SUSPICIOUS, got %v", out.Verdict)
	}
	found := false
	for _, f := range out.Findings {
		if f.Engine == "mal-ai" && f.Verdict == pipeline.Suspicious {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a capped mal-ai enrichment finding: %+v", out.Findings)
	}
}

func TestAgentGraphVerifierRefutalBlocksEnrichment(t *testing.T) {
	gate, factID := seededGate(t)
	// same grounded hypothesis, but the adversarial verifier REFUTES it: the gate
	// must not accept it (no enrichment finding) and must escalate to a human.
	resp := map[string][]byte{
		"router":              []byte(`{"agents":["capability_reasoner","verifier"]}`),
		"capability_reasoner": []byte(`{"behaviors":[{"ttp":"T1055","why":"injects into a remote process","citations":[{"fact_id":"` + factID + `","kind":"attck","key":"T1055"}]}]}`),
		"verifier":            []byte(`{"real":false,"reason":"the evidence does not actually support injection"}`),
	}
	a := &Analyzer{agents: mockCaller{resp: resp}, gate: gate, agentLedger: aiplane.NewLedger()}

	out := runGraph(t, a, pipeline.SubmissionResult{SubmissionID: "s", Verdict: pipeline.Unknown})
	for _, f := range out.Findings {
		if f.Engine == "mal-ai" {
			t.Fatalf("a refuted hypothesis must not become enrichment: %+v", f)
		}
	}
	if out.Verdict != pipeline.Unknown {
		t.Fatalf("a refuted hypothesis must not move the verdict, got %v", out.Verdict)
	}
	if !out.NeedsReview {
		t.Fatal("a grounded-but-refuted hypothesis should escalate to a human")
	}
}

func TestAgentGraphUnconfiguredIsNoOp(t *testing.T) {
	a := &Analyzer{} // no agent caller: the graph is disabled
	in := pipeline.SubmissionResult{
		SubmissionID: "s", Verdict: pipeline.Malicious,
		Findings: []pipeline.Finding{{Engine: "mal-static-yara", Verdict: pipeline.Malicious}},
	}
	out := runGraph(t, a, in)
	if out.Verdict != pipeline.Malicious || len(out.Findings) != 1 || out.NeedsReview {
		t.Fatalf("an unconfigured graph must return the deterministic result unchanged: %+v", out)
	}
}

func TestRetrievePriorsFromKB(t *testing.T) {
	// the spine-side Correlator: an ATT&CK technique in the evidence that is a known
	// L0 fact is returned as a CITABLE prior (with the real fact id the gate checks).
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	a := &Analyzer{registry: reg}
	ev := aiplane.EvidenceFrom(pipeline.SubmissionResult{
		Findings: []pipeline.Finding{{Engine: "mal-capa", Attck: "T1055"}, {Engine: "mal-yara", Attck: "T9999"}},
	})
	raw := a.retrievePriors(ev)
	if raw == nil {
		t.Fatal("a known ATT&CK technique in the evidence must produce a prior")
	}
	// the known technique resolves to its real fact id; the unknown one does not.
	s := string(raw)
	if !strings.Contains(s, f.ID) || !strings.Contains(s, "T1055") {
		t.Fatalf("prior missing the curated fact id: %s", s)
	}
	if strings.Contains(s, "T9999") {
		t.Fatalf("an unknown technique must not become a prior: %s", s)
	}
	// no KB wired -> no priors, never a panic.
	if (&Analyzer{}).retrievePriors(ev) != nil {
		t.Fatal("no registry must yield no priors")
	}
}

func TestGroundIOCsDropsFabricated(t *testing.T) {
	// B2: only IOCs actually present in the trusted evidence survive; a fabricated
	// one is dropped, never accepted from the agent's paraphrase.
	ev := aiplane.EvidenceFrom(pipeline.SubmissionResult{
		Findings: []pipeline.Finding{{Engine: "mal-floss", Detail: "beacon to acme-c2.example/gate"}},
	})
	kept := groundIOCs([]aiplane.ProposedIOC{
		{Type: "domain", Value: "acme-c2.example"},      // in the evidence -> kept
		{Type: "domain", Value: "totally-invented.bad"}, // fabricated -> dropped
	}, ev)
	if len(kept) != 1 || kept[0].Value != "acme-c2.example" {
		t.Fatalf("only evidence-grounded IOCs may survive: %+v", kept)
	}
}

func TestGateActivityCagedOnInvalidProposal(t *testing.T) {
	gate, _ := seededGate(t)
	led := aiplane.NewLedger()
	a := &Analyzer{gate: gate, agentLedger: led}
	out, err := a.GateActivity(context.Background(), GateInput{
		Result:   pipeline.SubmissionResult{SubmissionID: "s"},
		Proposal: []byte("{not json"),
	})
	if err != nil {
		t.Fatalf("caged: an invalid proposal must not error the activity: %v", err)
	}
	if len(out.Findings) != 0 || out.NeedsReview {
		t.Fatalf("an invalid proposal must yield no enrichment: %+v", out)
	}
	entries := led.Entries()
	if len(entries) != 1 || entries[0].Outcome != "rejected" {
		t.Fatalf("the rejection must be ledgered: %+v", entries)
	}
}
