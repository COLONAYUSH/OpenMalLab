package main

import (
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// mapReport is the trusted decode from broker-validated bytes onto the pipeline
// lattice. It holds two guarantees the live verdict depends on: an unparseable
// verdict (top-level OR per-finding) floors the report to incomplete + Suspicious
// so nothing is benign-by-omission, and each finding's confidence is assigned by
// trusted policy, not taken from the worker. Every workflow_test.go case mocks the
// activities that call mapReport, so without this test the whole fail-closed decode
// is 0% covered and a refactor dropping the incomplete floor would stay green.
func TestMapReportFailsClosedAndScoresConfidence(t *testing.T) {
	// an unparseable TOP verdict must fail closed: incomplete + floored to Suspicious.
	rep := mapReport(&brokerReport{Engine: "mal-x", Verdict: "NOT-A-VERDICT"})
	if !rep.Incomplete {
		t.Fatal("an invalid top verdict must set Incomplete")
	}
	if rep.Verdict != pipeline.Suspicious {
		t.Fatalf("fail-closed top verdict = %v, want Suspicious", rep.Verdict)
	}

	// an unparseable FINDING verdict must also fail the whole report closed.
	rep = mapReport(&brokerReport{
		Engine:   "mal-x",
		Verdict:  "UNKNOWN",
		Findings: []brokerFinding{{Engine: "mal-x", Type: "t", Verdict: "BOGUS"}},
	})
	if !rep.Incomplete {
		t.Fatal("an invalid finding verdict must set Incomplete")
	}

	// a well-formed yara MALICIOUS finding: parsed clean (not incomplete), verdict
	// preserved, and confidence assigned by policy (a signature hit is ConfHigh).
	rep = mapReport(&brokerReport{
		Engine:   "mal-static-yara",
		Verdict:  "MALICIOUS",
		Findings: []brokerFinding{{Engine: "mal-static-yara", Type: "yara", Verdict: "MALICIOUS"}},
	})
	if rep.Incomplete {
		t.Fatal("a fully-valid report must not be marked incomplete")
	}
	if rep.Verdict != pipeline.Malicious {
		t.Fatalf("top verdict = %v, want Malicious", rep.Verdict)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(rep.Findings))
	}
	if got := rep.Findings[0].Confidence; got != pipeline.ConfHigh {
		t.Fatalf("yara MALICIOUS confidence = %v, want ConfHigh", got)
	}
	// children are ingested (re-hashed) by the caller, never by mapReport.
	if len(rep.Children) != 0 {
		t.Fatalf("mapReport must not populate Children, got %d", len(rep.Children))
	}
}
