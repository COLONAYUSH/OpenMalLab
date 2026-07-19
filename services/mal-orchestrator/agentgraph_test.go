package main

import (
	"context"
	"encoding/json"
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

// graduatedGate is a seeded gate wired to graduation with `category` already
// EARNED autonomous, so a grounded accept folds through the real production path
// (NewGateWithGraduation) rather than the day-one auto-accept of a bare gate.
func graduatedGate(t *testing.T, category string) (*aiplane.Gate, string) {
	t.Helper()
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	grad := aiplane.NewGraduation()
	for i := 0; i < 20; i++ {
		grad.Record(category, true) // clean track record -> earned autonomous
	}
	return aiplane.NewGateWithGraduation(reg, grad), f.ID
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
	// production wires the gate to graduation, so a fold is EARNED: the "technique"
	// category is graduated to autonomous first, then a grounded+verified hypothesis
	// folds through the real production accept path (not a day-one auto-accept).
	gate, factID := graduatedGate(t, "technique")
	// router -> capability_reasoner (technique citing the curated T1055) -> verifier real.
	resp := map[string][]byte{
		"router":              []byte(`{"agents":["capability_reasoner","verifier"]}`),
		"capability_reasoner": []byte(`{"behaviors":[{"ttp":"T1055","why":"injects into a remote process","citations":[{"fact_id":"` + factID + `","kind":"attck","key":"T1055"}]}]}`),
		"verifier":            []byte(`{"real":true,"reason":"evidence supports it"}`),
	}
	a := &Analyzer{agents: mockCaller{resp: resp}, gate: gate, agentLedger: aiplane.NewLedger()}

	out := runGraph(t, a, pipeline.SubmissionResult{SubmissionID: "s", Verdict: pipeline.Unknown})
	if out.Verdict != pipeline.Suspicious {
		t.Fatalf("grounded+verified enrichment in an earned category must raise the verdict to SUSPICIOUS, got %v", out.Verdict)
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

func TestAgentGraphFreshCategoryEscalatesNotFolds(t *testing.T) {
	// the production bootstrap: a FRESH category is supervised, so even a grounded,
	// verifier-confirmed hypothesis is NOT auto-folded - it escalates to a human and
	// the verdict does not move. this is exactly the day-one behavior finding HIGH #1
	// was about (the autonomous fold must be EARNED via the HITL loop, never free).
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	gate := aiplane.NewGateWithGraduation(reg, aiplane.NewGraduation()) // fresh -> supervised
	resp := map[string][]byte{
		"router":              []byte(`{"agents":["capability_reasoner","verifier"]}`),
		"capability_reasoner": []byte(`{"behaviors":[{"ttp":"T1055","why":"injects into a remote process","citations":[{"fact_id":"` + f.ID + `","kind":"attck","key":"T1055"}]}]}`),
		"verifier":            []byte(`{"real":true,"reason":"evidence supports it"}`),
	}
	a := &Analyzer{agents: mockCaller{resp: resp}, gate: gate, agentLedger: aiplane.NewLedger()}

	out := runGraph(t, a, pipeline.SubmissionResult{SubmissionID: "s", Verdict: pipeline.Unknown})
	for _, fnd := range out.Findings {
		if fnd.Engine == "mal-ai" {
			t.Fatalf("a fresh (un-earned) category must not fold enrichment: %+v", fnd)
		}
	}
	if out.Verdict != pipeline.Unknown {
		t.Fatalf("a supervised hypothesis must not move the deterministic verdict, got %v", out.Verdict)
	}
	if !out.NeedsReview {
		t.Fatal("a grounded hypothesis in a not-yet-earned category must escalate to a human")
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
	raw, tiers := a.retrievePriors(ev)
	if raw == nil {
		t.Fatal("a known ATT&CK technique in the evidence must produce a prior")
	}
	if len(tiers) != 1 || tiers[0] != "L0" {
		t.Fatalf("an exact curated hit must report the L0 tier, got %v", tiers)
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
	if raw, _ := (&Analyzer{}).retrievePriors(ev); raw != nil {
		t.Fatal("no registry must yield no priors")
	}
}

func TestNoveltyOfMeasuredFromL0(t *testing.T) {
	// #14: novelty is measured deterministically from L0 knowledge, not the model.
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	if _, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed"); err != nil {
		t.Fatal(err)
	}
	a := &Analyzer{registry: reg}
	mk := func(attcks ...string) aiplane.Evidence {
		var fs []pipeline.Finding
		for _, at := range attcks {
			fs = append(fs, pipeline.Finding{Engine: "mal-capa", Attck: at})
		}
		return aiplane.EvidenceFrom(pipeline.SubmissionResult{Findings: fs})
	}
	if n := a.noveltyOf(mk("T1055", "T9999")); n != 0.5 {
		t.Fatalf("one known + one unknown technique should be novelty 0.5, got %v", n)
	}
	if n := a.noveltyOf(mk("T1055")); n != 0 {
		t.Fatalf("an all-known artifact should be novelty 0, got %v", n)
	}
	if n := a.noveltyOf(mk("T9999", "T8888")); n != 1 {
		t.Fatalf("an all-unknown artifact should be novelty 1, got %v", n)
	}
	if n := a.noveltyOf(mk()); n != 0 {
		t.Fatalf("no ATT&CK signal is uncertainty, not novelty: want 0, got %v", n)
	}
	if n := (&Analyzer{}).noveltyOf(mk("T1055")); n != 0 {
		t.Fatalf("no registry wired must yield 0 (no false novelty), got %v", n)
	}
}

func TestRetrievePriorsL05SubTechniqueParent(t *testing.T) {
	// #12/#24: a sub-technique with no exact L0 hit resolves to its curated PARENT as
	// an L0.5 lead (non-citable: no fact id), and the tier is reported as L0.5.
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	f, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed")
	if err != nil {
		t.Fatal(err)
	}
	a := &Analyzer{registry: reg}
	ev := aiplane.EvidenceFrom(pipeline.SubmissionResult{
		Findings: []pipeline.Finding{{Engine: "mal-capa", Attck: "T1055.001"}},
	})
	raw, tiers := a.retrievePriors(ev)
	if raw == nil {
		t.Fatal("a sub-technique of a curated parent must produce an L0.5 lead")
	}
	s := string(raw)
	if !strings.Contains(s, "T1055") || !strings.Contains(s, "L0.5") {
		t.Fatalf("expected an L0.5 lead to the parent T1055: %s", s)
	}
	if strings.Contains(s, f.ID) {
		t.Fatalf("an L0.5 lead must NOT carry a fact id (non-citable): %s", s)
	}
	if len(tiers) != 1 || tiers[0] != "L0.5" {
		t.Fatalf("tiers must report L0.5 (a near match, not exact), got %v", tiers)
	}
}

func TestGateActivityRecordsRetrievalTiers(t *testing.T) {
	// #24: the ledger records the ACTUAL tiers the retrieval consulted, not "L0".
	gate, factID := seededGate(t)
	led := aiplane.NewLedger()
	a := &Analyzer{gate: gate, agentLedger: led}
	prop := []byte(`{"hypotheses":[{"kind":"technique","claim":"x","confidence":"LOW","citations":[{"fact_id":"` + factID + `","kind":"attck","key":"T1055"}]}]}`)
	if _, err := a.GateActivity(context.Background(), GateInput{
		Result:         pipeline.SubmissionResult{SubmissionID: "s"},
		Proposal:       prop,
		RetrievalTiers: []string{"L0", "L0.5"},
	}); err != nil {
		t.Fatal(err)
	}
	entries := led.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected one ledger entry, got %d", len(entries))
	}
	if got := entries[0].RetrievalTiers; len(got) != 2 || got[0] != "L0" || got[1] != "L0.5" {
		t.Fatalf("ledger must record the actual retrieval tiers, got %v", got)
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

func TestCleanCitesDropsMalformedNotJustEmpty(t *testing.T) {
	good := aiplane.Citation{FactID: "kf_abc123", Kind: "attck", Key: "T1055"}
	cs := []aiplane.Citation{
		good,
		{FactID: "kf_x", Kind: "attck", Key: "T1\x00055"},              // control byte -> malformed
		{FactID: "", Kind: "attck", Key: "T1071"},                      // empty fact_id -> malformed
		{FactID: "kf_z", Kind: strings.Repeat("A", 100000), Key: "T1"}, // over-long -> malformed
	}
	out := cleanCites(cs)
	if len(out) != 1 || out[0] != good {
		t.Fatalf("cleanCites must keep only well-formed citations, got %+v", out)
	}

	// the survivor validates cleanly...
	clean := aiplane.Proposal{Hypotheses: []aiplane.Hypothesis{{Kind: "technique", Claim: "x", Confidence: "LOW", Citations: out}}}
	cj, _ := json.Marshal(clean)
	if _, err := aiplane.Validate(cj); err != nil {
		t.Fatalf("a proposal with only well-formed citations must validate: %v", err)
	}
	// ...and this is load-bearing: WITHOUT cleaning, the malformed citation makes
	// Validate reject the WHOLE proposal (fail-closed), discarding the good one too.
	dirty := aiplane.Proposal{Hypotheses: []aiplane.Hypothesis{{Kind: "technique", Claim: "x", Confidence: "LOW", Citations: cs}}}
	dj, _ := json.Marshal(dirty)
	if _, err := aiplane.Validate(dj); err == nil {
		t.Fatal("expected Validate to reject a proposal carrying a malformed citation (proves cleanCites is load-bearing)")
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
