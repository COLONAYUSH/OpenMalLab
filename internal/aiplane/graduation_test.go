package aiplane

import (
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
)

func TestGraduationPromotesWithTrackRecord(t *testing.T) {
	g := NewGraduation()
	if g.Mode("technique") != ModeShadow {
		t.Fatal("a fresh category must start in shadow")
	}
	for i := 0; i < 5; i++ {
		g.Record("technique", true)
	}
	if g.Mode("technique") != ModeSupervised {
		t.Fatalf("5 clean observations should reach supervised, got %s", g.Mode("technique"))
	}
	for i := 0; i < 15; i++ {
		g.Record("technique", true) // total 20, all correct
	}
	if g.Mode("technique") != ModeAutonomous {
		t.Fatalf("20 observations at 100%% should reach autonomous, got %s", g.Mode("technique"))
	}
}

func TestGraduationDemotesOnRegression(t *testing.T) {
	g := NewGraduation()
	for i := 0; i < 20; i++ {
		g.Record("technique", true)
	}
	if g.Mode("technique") != ModeAutonomous {
		t.Fatal("should be autonomous after a clean record")
	}
	for i := 0; i < 10; i++ {
		g.Record("technique", false) // 20/30 = 0.67, below the 0.9 floor
	}
	if g.Mode("technique") != ModeSupervised {
		t.Fatalf("an accuracy drop must demote out of autonomous, got %s", g.Mode("technique"))
	}
}

func TestGraduationLowAccuracyNeverAutonomous(t *testing.T) {
	g := NewGraduation()
	for i := 0; i < 40; i++ {
		g.Record("technique", i%2 == 0) // ~50% accuracy over many observations
	}
	if g.Mode("technique") == ModeAutonomous {
		t.Fatal("50%% accuracy must never be autonomous, however many observations")
	}
}

func groundedTechnique(t *testing.T) (*knowledge.Registry, Proposal) {
	t.Helper()
	r := regWith(t)
	c := curatedCite(t, r, knowledge.KindAttck, "T1055")
	return r, Proposal{Hypotheses: []Hypothesis{{Kind: "technique", Claim: "process injection", Confidence: "LOW", Citations: []Citation{c}}}}
}

func TestGateShadowDropsEvenGrounded(t *testing.T) {
	r, p := groundedTechnique(t)
	grad := NewGraduation() // "technique" is fresh -> shadow
	res := NewGateWithGraduation(r, grad).Evaluate(Evidence{}, p)
	if res.Hypotheses[0].Disposition != DispDrop {
		t.Fatalf("shadow mode must drop even a grounded hypothesis, got %s", res.Hypotheses[0].Disposition)
	}
	if res.NeedsHuman {
		t.Fatal("shadow is observe-only, never an escalation")
	}
}

func TestGateSupervisedEscalatesGrounded(t *testing.T) {
	r, p := groundedTechnique(t)
	grad := NewGraduation()
	for i := 0; i < 5; i++ {
		grad.Record("technique", true) // supervised
	}
	res := NewGateWithGraduation(r, grad).Evaluate(Evidence{}, p)
	if res.Hypotheses[0].Disposition != DispEscalate {
		t.Fatalf("supervised must escalate a grounded hypothesis, never accept, got %s", res.Hypotheses[0].Disposition)
	}
	if !res.NeedsHuman {
		t.Fatal("supervised escalation must set NeedsHuman")
	}
}

func TestGateAutonomousAcceptsGrounded(t *testing.T) {
	r, p := groundedTechnique(t)
	grad := NewGraduation()
	for i := 0; i < 20; i++ {
		grad.Record("technique", true) // earned autonomous
	}
	res := NewGateWithGraduation(r, grad).Evaluate(Evidence{}, p)
	if res.Hypotheses[0].Disposition != DispAccept {
		t.Fatalf("an earned-autonomous, grounded hypothesis should accept, got %s", res.Hypotheses[0].Disposition)
	}
}
