package aiplane

import (
	"testing"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// regWith builds a registry and returns it; helpers below curate/ingest facts
// and hand back the citation that points at them.
func regWith(t *testing.T) *knowledge.Registry {
	t.Helper()
	return knowledge.NewRegistry(knowledge.NewMemStore())
}

func curatedCite(t *testing.T, r *knowledge.Registry, kind knowledge.Kind, key string) Citation {
	t.Helper()
	f, err := r.Curate(kind, key, "label", nil, "seed")
	if err != nil {
		t.Fatalf("curate: %v", err)
	}
	return Citation{FactID: f.ID, Kind: string(kind), Key: key}
}

func ingestCite(t *testing.T, r *knowledge.Registry, kind knowledge.Kind, key string) Citation {
	t.Helper()
	f, err := r.Ingest(kind, key, "label", "seed")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return Citation{FactID: f.ID, Kind: string(kind), Key: key}
}

func TestGateAcceptsGroundedAllowlisted(t *testing.T) {
	r := regWith(t)
	c := curatedCite(t, r, knowledge.KindAttck, "T1055")
	p := Proposal{Hypotheses: []Hypothesis{{
		Kind: "technique", Claim: "injects into a remote process", Confidence: "LOW",
		Citations: []Citation{c},
	}}}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "sub-9"}, p)

	if res.SubmissionID != "sub-9" {
		t.Fatalf("submission id not taken from evidence: %q", res.SubmissionID)
	}
	gh := res.Hypotheses[0]
	if gh.Disposition != DispAccept {
		t.Fatalf("grounded+allowlisted should accept, got %s (%v)", gh.Disposition, gh.Reasons)
	}
	if gh.VerifiedCitations != 1 {
		t.Fatalf("verified count = %d, want 1", gh.VerifiedCitations)
	}
	// even accepted, confidence was LOW - acceptance came from grounding, NOT
	// confidence. and the accept is capped at SUSPICIOUS enrichment.
	if EnrichmentVerdict(gh.Disposition) != pipeline.Suspicious {
		t.Fatalf("accepted enrichment must cap at SUSPICIOUS, got %v", EnrichmentVerdict(gh.Disposition))
	}
	if res.NeedsHuman {
		t.Fatal("a clean autonomous accept should not force human review")
	}
}

func TestGateEscalatesGroundedHighStakes(t *testing.T) {
	r := regWith(t)
	c := curatedCite(t, r, knowledge.KindFamily, "emotet")
	// kind "family" is high-stakes: NOT on the autonomy allow-list, so even a
	// verified curated citation escalates rather than auto-accepts.
	p := Proposal{Hypotheses: []Hypothesis{{
		Kind: "family", Claim: "emotet", Confidence: "HIGH", Citations: []Citation{c},
	}}}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "s"}, p)
	if res.Hypotheses[0].Disposition != DispEscalate {
		t.Fatalf("high-stakes kind should escalate, got %s", res.Hypotheses[0].Disposition)
	}
	if !res.NeedsHuman {
		t.Fatal("escalation must set NeedsHuman")
	}
}

func TestGateEscalatesUngroundedButConfident(t *testing.T) {
	r := regWith(t)
	p := Proposal{Hypotheses: []Hypothesis{{
		Kind: "capability", Claim: "novel anti-vm trick", Confidence: "HIGH",
	}}}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "s"}, p)
	if res.Hypotheses[0].Disposition != DispEscalate {
		t.Fatalf("ungrounded+confident should escalate (possible novel TP), got %s", res.Hypotheses[0].Disposition)
	}
	// confidence escalated it - but did NOT promote it to accept.
	if res.Hypotheses[0].Disposition == DispAccept {
		t.Fatal("confidence must never promote to accept")
	}
}

func TestGateDropsUngroundedLowConfidence(t *testing.T) {
	r := regWith(t)
	p := Proposal{Hypotheses: []Hypothesis{{
		Kind: "capability", Claim: "maybe something", Confidence: "LOW",
	}}}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "s"}, p)
	if res.Hypotheses[0].Disposition != DispDrop {
		t.Fatalf("ungrounded+low should drop, got %s", res.Hypotheses[0].Disposition)
	}
	if res.NeedsHuman {
		t.Fatal("a lone dropped hypothesis should not force review")
	}
	if EnrichmentVerdict(res.Hypotheses[0].Disposition) != pipeline.Unknown {
		t.Fatal("a dropped hypothesis must contribute no verdict influence")
	}
}

func TestGateIngestCitationIsNotGrounding(t *testing.T) {
	r := regWith(t)
	// an INGEST fact verifies (it exists and binds) but is NOT curated, so it can
	// never ground an autonomous accept: it is context, not authority.
	c := ingestCite(t, r, knowledge.KindFamily, "somefam")
	p := Proposal{Hypotheses: []Hypothesis{{
		Kind: "capability", Claim: "x", Confidence: "LOW", Citations: []Citation{c},
	}}}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "s"}, p)
	if res.Hypotheses[0].VerifiedCitations != 0 {
		t.Fatalf("ingest citation must not count as curated-verified, got %d", res.Hypotheses[0].VerifiedCitations)
	}
	if res.Hypotheses[0].Disposition != DispDrop {
		t.Fatalf("ingest-only grounding with low confidence should drop, got %s", res.Hypotheses[0].Disposition)
	}
}

func TestGateMismatchedCitationIsNotGrounding(t *testing.T) {
	r := regWith(t)
	real := curatedCite(t, r, knowledge.KindAttck, "T1055")
	// cite the real fact ID but claim it is about a DIFFERENT key: must not verify.
	forged := Citation{FactID: real.FactID, Kind: "attck", Key: "T1071"}
	p := Proposal{Hypotheses: []Hypothesis{{
		Kind: "technique", Claim: "x", Confidence: "HIGH", Citations: []Citation{forged},
	}}}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "s"}, p)
	if res.Hypotheses[0].VerifiedCitations != 0 {
		t.Fatalf("mismatched citation must not verify, got %d", res.Hypotheses[0].VerifiedCitations)
	}
	// falls through to confident-ungrounded -> escalate, never accept.
	if res.Hypotheses[0].Disposition == DispAccept {
		t.Fatal("a forged citation must never yield accept")
	}
}

func TestGateNilVerifierFailsClosed(t *testing.T) {
	// no verifier: even a well-formed citation on an allow-listed kind cannot be
	// grounded, so it can never be accepted.
	p := Proposal{Hypotheses: []Hypothesis{{
		Kind: "capability", Claim: "x", Confidence: "LOW",
		Citations: []Citation{{FactID: "kf_whatever", Kind: "attck", Key: "T1055"}},
	}}}
	res := NewGate(nil).Evaluate(Evidence{SubmissionID: "s"}, p)
	if res.Hypotheses[0].Disposition == DispAccept {
		t.Fatal("nil verifier must never accept")
	}
	if res.Hypotheses[0].VerifiedCitations != 0 {
		t.Fatal("nil verifier must verify nothing")
	}
}

func TestGateModelReviewRequestForcesHuman(t *testing.T) {
	r := regWith(t)
	c := curatedCite(t, r, knowledge.KindAttck, "T1055")
	// a clean autonomous accept, but the model asked for review: the request is a
	// one-way raise the gate honors.
	p := Proposal{
		Hypotheses:  []Hypothesis{{Kind: "technique", Claim: "x", Confidence: "LOW", Citations: []Citation{c}}},
		NeedsReview: true, ReviewReason: "low sample coverage",
	}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "s"}, p)
	if res.Hypotheses[0].Disposition != DispAccept {
		t.Fatalf("hypothesis should still accept, got %s", res.Hypotheses[0].Disposition)
	}
	if !res.NeedsHuman {
		t.Fatal("model review request must force NeedsHuman")
	}
}

func TestGateCarriesLeadsAndSummary(t *testing.T) {
	r := regWith(t)
	p := Proposal{
		Summary: "a downloader",
		IOCs:    []ProposedIOC{{Type: "url", Value: "hxxp[://]c2"}, {Type: "mutex", Value: "m"}},
	}
	res := NewGate(r).Evaluate(Evidence{SubmissionID: "s"}, p)
	if len(res.Leads) != 2 || res.Summary != "a downloader" {
		t.Fatalf("leads/summary not carried: %+v", res)
	}
}

func TestEnrichmentVerdictAndDispositionString(t *testing.T) {
	if EnrichmentVerdict(DispAccept) != pipeline.Suspicious {
		t.Fatal("accept caps at SUSPICIOUS")
	}
	if EnrichmentVerdict(DispEscalate) != pipeline.Unknown || EnrichmentVerdict(DispDrop) != pipeline.Unknown {
		t.Fatal("non-accept contributes nothing")
	}
	for d, want := range map[Disposition]string{DispAccept: "accept", DispEscalate: "escalate", DispDrop: "drop"} {
		if d.String() != want {
			t.Fatalf("Disposition(%d).String()=%q want %q", d, d.String(), want)
		}
	}
}

func TestGateSignalsBlockAcceptButNeverPromote(t *testing.T) {
	r := regWith(t)
	c := curatedCite(t, r, knowledge.KindAttck, "T1055")
	grounded := Proposal{Hypotheses: []Hypothesis{{Kind: "technique", Claim: "x", Confidence: "LOW", Citations: []Citation{c}}}}
	g := NewGate(r)

	// baseline: grounded + allow-listed + no signals -> accept.
	if d := g.EvaluateWithSignals(Evidence{}, grounded, nil).Hypotheses[0].Disposition; d != DispAccept {
		t.Fatalf("baseline should accept, got %s", d)
	}
	// each stop signal blocks the accept and sends it to a human.
	for name, sig := range map[string]GateSignals{
		"refuted":         {Refuted: true},
		"novelty":         {Novelty: 0.9},
		"low-consistency": {SelfConsistency: 0.3},
		"calibrated-low":  {CalibratedConfidence: "LOW"},
	} {
		got := g.EvaluateWithSignals(Evidence{}, grounded, []GateSignals{sig}).Hypotheses[0].Disposition
		if got != DispEscalate {
			t.Fatalf("%s: a stop signal must block accept -> escalate, got %s", name, got)
		}
	}
	// an UNMEASURED self-consistency (zero value) must not be read as "low".
	if d := g.EvaluateWithSignals(Evidence{}, grounded, []GateSignals{{SelfConsistency: 0}}).Hypotheses[0].Disposition; d != DispAccept {
		t.Fatalf("unmeasured self-consistency must not block, got %s", d)
	}
}

func TestGateSignalsNeverPromoteUngrounded(t *testing.T) {
	r := regWith(t)
	// ungrounded, allow-listed kind, every positive signal maxed: still not accept.
	p := Proposal{Hypotheses: []Hypothesis{{Kind: "technique", Claim: "x", Confidence: "HIGH"}}}
	sig := []GateSignals{{SelfConsistency: 1.0, Novelty: 0.0, CalibratedConfidence: "HIGH"}}
	if d := NewGate(r).EvaluateWithSignals(Evidence{}, p, sig).Hypotheses[0].Disposition; d == DispAccept {
		t.Fatal("no positive signal may promote an ungrounded hypothesis to accept")
	}
}

func TestGateNoFPInflationWithoutGrounding(t *testing.T) {
	// edge-check #2 (verdict-inflation guard): a confident but UNGROUNDED claim on a
	// benign submission must never be accepted - accepting it would let the AI
	// inflate a benign file toward SUSPICIOUS enrichment (a false-positive DoS).
	r := regWith(t)
	p := Proposal{Hypotheses: []Hypothesis{{Kind: "capability", Claim: "definitely malicious", Confidence: "HIGH"}}}
	res := NewGate(r).Evaluate(Evidence{Verdict: "BENIGN"}, p)
	for _, gh := range res.Hypotheses {
		if gh.Disposition == DispAccept {
			t.Fatal("an ungrounded claim must never be accepted (no FP inflation without a curated citation)")
		}
	}
	// and even an accept can never reach MALICIOUS - enrichment is capped.
	if EnrichmentVerdict(DispAccept) == pipeline.Malicious {
		t.Fatal("AI enrichment must never reach MALICIOUS")
	}
}

func TestGateSignalsRefutedUngroundedDrops(t *testing.T) {
	r := regWith(t)
	// refuted + ungrounded drops even at HIGH confidence: the verifier kills it.
	p := Proposal{Hypotheses: []Hypothesis{{Kind: "capability", Claim: "x", Confidence: "HIGH"}}}
	got := NewGate(r).EvaluateWithSignals(Evidence{}, p, []GateSignals{{Refuted: true}}).Hypotheses[0].Disposition
	if got != DispDrop {
		t.Fatalf("refuted+ungrounded should drop, got %s", got)
	}
}
