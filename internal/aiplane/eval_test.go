package aiplane

import (
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
)

func TestCorpusAllPass(t *testing.T) {
	cases := Corpus()
	passed, results := RunCorpus(cases)
	for _, r := range results {
		if !r.Passed {
			t.Errorf("corpus case %q FAILED: %s", r.Name, r.Detail)
		}
	}
	if passed != len(cases) {
		t.Fatalf("%d/%d corpus cases passed", passed, len(cases))
	}
}

// the corpus must keep its breadth: at least one case of each outcome, so it can
// never silently erode to a trivial always-green set.
func TestCorpusCoversTheMatrix(t *testing.T) {
	cases := Corpus()
	if len(cases) < 10 {
		t.Fatalf("corpus shrank to %d cases", len(cases))
	}
	var reject, accept, escalate, drop bool
	for _, c := range cases {
		if c.ExpectReject {
			reject = true
			continue
		}
		for _, d := range c.ExpectDispositions {
			switch d {
			case DispAccept:
				accept = true
			case DispEscalate:
				escalate = true
			case DispDrop:
				drop = true
			}
		}
	}
	if !reject || !accept || !escalate || !drop {
		t.Fatalf("corpus missing an outcome: reject=%v accept=%v escalate=%v drop=%v", reject, accept, escalate, drop)
	}
}

// the harness must actually verify outcomes: a case with a deliberately wrong
// expectation must be reported as failed, not vacuously passed.
func TestRunCaseDetectsMismatch(t *testing.T) {
	bad := Case{
		Name:    "wrong-expectation",
		Curated: []FactSpec{{Kind: knowledge.KindAttck, Key: "T1055", Label: "x"}},
		Build: func(cite func(knowledge.Kind, string) Citation) []byte {
			c := cite(knowledge.KindAttck, "T1055")
			return jsonProposal(`{"summary":"x","hypotheses":[{"kind":"technique","claim":"x","confidence":"LOW","citations":[{"fact_id":"` +
				c.FactID + `","kind":"attck","key":"T1055"}]}]}`)
		},
		ExpectDispositions: []Disposition{DispDrop}, // WRONG: this grounds+accepts
	}
	if RunCase(bad).Passed {
		t.Fatal("harness passed a case whose expectation did not match reality")
	}
}
