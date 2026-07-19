package aiplane

import (
	"os"
	"strings"
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// TestValidateAndGateRealModelProposal adjudicates a proposal captured from a REAL
// model (gpt-oss:120b, via the live roster run against Ollama Cloud) - not the
// offline TestModel. It proves the Go adjudicator is robust to the quirks a real
// model actually emits (lowercase confidence, free-form/near-miss kinds, a
// re-fanged C2 URL, and an embedded prompt-injection string the model quoted back)
// and - the load-bearing property - that a confident but UNCITED real proposal
// earns nothing autonomously: it cannot auto-accept and cannot move the verdict.
// Containment holds against a real model, not just the mock.
func TestValidateAndGateRealModelProposal(t *testing.T) {
	raw, err := os.ReadFile("testdata/live_proposal_gptoss120b.json")
	if err != nil {
		t.Fatal(err)
	}

	prop, err := Validate(raw)
	if err != nil {
		t.Fatalf("real model output must validate (defanged + normalized), got: %v", err)
	}
	// lowercase "medium"/"low" from the model normalized to the canonical set.
	for _, h := range prop.Hypotheses {
		if !validConfidence[h.Confidence] {
			t.Fatalf("confidence not normalized to a canonical token: %q", h.Confidence)
		}
	}

	// seed the registry so grounding is POSSIBLE (T1055 is curated). the point is
	// that it is still not GRANTED, because the model cited nothing.
	reg := knowledge.NewRegistry(knowledge.NewMemStore())
	if _, err := reg.Curate(knowledge.KindAttck, "T1055", "Process Injection", nil, "seed"); err != nil {
		t.Fatal(err)
	}
	res := NewGate(reg).Evaluate(Evidence{SubmissionID: "live-0001", Verdict: "SUSPICIOUS"}, prop)

	// 1. no auto-accept: every hypothesis here is uncited (and the kinds "behavioral"
	//    / "family" are off the exact-match allow-list anyway), so a confident real
	//    proposal earns nothing without a spine-verified curated citation.
	for _, gh := range res.Hypotheses {
		if gh.Disposition == DispAccept {
			t.Fatalf("an uncited real-model hypothesis must never auto-accept: %+v", gh)
		}
	}
	// 2. the model set needs_review; the gate honors that as a one-way raise.
	if !res.NeedsHuman {
		t.Fatal("the proposal set needs_review; the gate must force human review")
	}
	// 3. defang held on real output: the model had RE-FANGED the C2 URL to a live
	//    http:// scheme; the gate's surfaced fields must carry no live, clickable
	//    scheme (defang wraps the separator as "[://]", which breaks auto-linking).
	blob := res.Summary
	for _, l := range res.Leads {
		blob += " " + l.Value
	}
	for _, live := range []string{"http://", "https://", "ftp://"} {
		if strings.Contains(blob, live) {
			t.Fatalf("a live URL scheme %q survived defang in a surfaced field: %q", live, blob)
		}
	}
	if !strings.Contains(blob, "[://]") {
		t.Fatalf("expected the re-fanged C2 URL to be defanged to a bracketed scheme, got: %q", blob)
	}
	// 4. the enrichment cap holds: nothing this proposal produces can exceed
	//    SUSPICIOUS, and here nothing is accepted at all.
	for _, gh := range res.Hypotheses {
		if EnrichmentVerdict(gh.Disposition) != pipeline.Unknown {
			t.Fatalf("no hypothesis was accepted, so none may contribute verdict influence: %+v", gh)
		}
	}
}
