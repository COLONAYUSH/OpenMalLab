package pipeline

import (
	"encoding/json"
	"testing"
)

var all = []Verdict{Benign, Unknown, Suspicious, Malicious}

// the lattice is tiny, so we do not sample properties, we prove them: all
// sixteen pairs, every law the design leans on.
func TestMaxIsTheLatticeJoin(t *testing.T) {
	for _, a := range all {
		for _, b := range all {
			got := Max(a, b)
			if got < a || got < b {
				t.Fatalf("Max(%v,%v)=%v is below an input", a, b, got)
			}
			if got != a && got != b {
				t.Fatalf("Max(%v,%v)=%v invented a verdict", a, b, got)
			}
			if got != Max(b, a) {
				t.Fatalf("Max(%v,%v) is not commutative", a, b)
			}
			for _, c := range all {
				if Max(Max(a, b), c) != Max(a, Max(b, c)) {
					t.Fatalf("Max not associative at (%v,%v,%v)", a, b, c)
				}
			}
		}
	}
}

func TestNothingMasksAndNothingBenignByOmission(t *testing.T) {
	if !(Benign < Unknown && Unknown < Suspicious && Suspicious < Malicious) {
		t.Fatal("lattice order broken")
	}
	for _, a := range all {
		if Max(a, Malicious) != Malicious {
			t.Fatalf("MALICIOUS masked by %v", a)
		}
		if Max(a, Benign) != a {
			t.Fatalf("BENIGN is not neutral against %v", a)
		}
		if Max(a, a) != a {
			t.Fatalf("Max not idempotent at %v", a)
		}
	}
}

func TestParseVerdictRoundTripsAndFailsClosed(t *testing.T) {
	for _, v := range all {
		got, ok := ParseVerdict(v.String())
		if !ok || got != v {
			t.Fatalf("round trip broke for %v", v)
		}
	}
	for _, s := range []string{"", "benign", "TRUST_ME", "MALICIOUS ", "4", "BENIGN\n"} {
		got, ok := ParseVerdict(s)
		if ok {
			t.Fatalf("accepted junk verdict %q", s)
		}
		if got != Suspicious {
			t.Fatalf("junk verdict %q parsed to %v, want SUSPICIOUS (fail closed)", s, got)
		}
	}
}

func TestVerdictJSONSpeaksStrings(t *testing.T) {
	b, err := json.Marshal(Malicious)
	if err != nil || string(b) != `"MALICIOUS"` {
		t.Fatalf("marshal: %s %v", b, err)
	}
	var v Verdict
	if err := json.Unmarshal([]byte(`"SUSPICIOUS"`), &v); err != nil || v != Suspicious {
		t.Fatalf("unmarshal string: %v %v", v, err)
	}
	// legacy integer histories still decode
	if err := json.Unmarshal([]byte(`1`), &v); err != nil || v != Unknown {
		t.Fatalf("unmarshal legacy int: %v %v", v, err)
	}
	// junk does not
	for _, junk := range []string{`"TRUST_ME"`, `7`, `-1`, `true`, `null`, `{}`} {
		if err := json.Unmarshal([]byte(junk), &v); err == nil {
			t.Fatalf("accepted junk verdict json %s", junk)
		}
	}
}

func TestFindingJSONShape(t *testing.T) {
	f := Finding{Engine: "mal-static-yara", Type: "yara", Detail: "eicar_test_file", Attck: "T1204", Verdict: Malicious, Confidence: ConfHigh}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"engine":"mal-static-yara","type":"yara","detail":"eicar_test_file","attck":"T1204","verdict":"MALICIOUS","confidence":"HIGH"}`
	if string(b) != want {
		t.Fatalf("finding wire shape drifted:\n got %s\nwant %s", b, want)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil || back != f {
		t.Fatalf("finding round trip: %+v %v", back, err)
	}
}

func TestConfidenceRoundTripsAndFailsClosed(t *testing.T) {
	for _, c := range []Confidence{ConfLow, ConfMedium, ConfHigh} {
		got, ok := ParseConfidence(c.String())
		if !ok || got != c {
			t.Fatalf("round trip broke for %v", c)
		}
		b, err := json.Marshal(c)
		if err != nil || string(b) != `"`+c.String()+`"` {
			t.Fatalf("marshal %v: %s %v", c, b, err)
		}
	}
	for _, s := range []string{"", "low", "certain", "4"} {
		if got, ok := ParseConfidence(s); ok || got != ConfLow {
			t.Fatalf("junk confidence %q parsed to %v ok=%v, want LOW fail-closed", s, got, ok)
		}
	}
	// legacy integer decodes; junk json does not.
	var c Confidence
	if err := json.Unmarshal([]byte(`2`), &c); err != nil || c != ConfHigh {
		t.Fatalf("legacy int: %v %v", c, err)
	}
	for _, junk := range []string{`5`, `-1`, `"certain"`, `true`} {
		if err := json.Unmarshal([]byte(junk), &c); err == nil {
			t.Fatalf("accepted junk confidence json %s", junk)
		}
	}
}

func TestConfidenceForPolicy(t *testing.T) {
	// gaps and fail-closed floors are never more than tentative.
	for _, ft := range []string{"error", "recursion-cap", "ingest-rejected",
		"decompression-bomb", "path-traversal-name", "skipped-symlink",
		"entry-truncated", "entry-unreadable", "extraction-error", "findings-cap-hit"} {
		if c := ConfidenceFor("mal-extract", ft, Suspicious); c != ConfLow {
			t.Fatalf("floor type %q got %v, want LOW", ft, c)
		}
	}
	// a yara signature match is firm.
	if c := ConfidenceFor("mal-static-yara", "yara", Malicious); c != ConfHigh {
		t.Fatalf("yara match got %v, want HIGH", c)
	}
	// informational identification carries no confidence weight.
	if c := ConfidenceFor("mal-ident", "file-type", Unknown); c != ConfLow {
		t.Fatalf("ident file-type got %v, want LOW", c)
	}
	// a generic real detection defaults to medium.
	if c := ConfidenceFor("some-future-engine", "capability", Suspicious); c != ConfMedium {
		t.Fatalf("generic detection got %v, want MEDIUM", c)
	}
	// capa capabilities are behavioral inference: medium when suspicious, and
	// low (score-zero) when merely informational UNKNOWN.
	if c := ConfidenceFor("mal-capa", "capability", Suspicious); c != ConfMedium {
		t.Fatalf("suspicious capa capability got %v, want MEDIUM", c)
	}
	if c := ConfidenceFor("mal-capa", "capability", Unknown); c != ConfLow {
		t.Fatalf("informational capa capability got %v, want LOW", c)
	}
	// mal-detonate: a genuine OBSERVED behavior is medium, but a detonation-timeout is
	// a fail-closed GAP - it floors severity via incomplete yet must stay LOW so it
	// does not inflate the triage score like a real detection.
	if c := ConfidenceFor("mal-detonate", "net-connect", Suspicious); c != ConfMedium {
		t.Fatalf("observed detonation behavior got %v, want MEDIUM", c)
	}
	if c := ConfidenceFor("mal-detonate", "detonation-timeout", Suspicious); c != ConfLow {
		t.Fatalf("detonation-timeout gap got %v, want LOW", c)
	}
}

// helper to build a findings slice tersely.
func fs(specs ...[2]int) []Finding {
	out := make([]Finding, 0, len(specs))
	for _, s := range specs {
		out = append(out, Finding{Verdict: Verdict(s[0]), Confidence: Confidence(s[1])})
	}
	return out
}

func TestScoreDiscriminatesRealHitsFromFailClosedFloors(t *testing.T) {
	// the whole point of the axis: a definitive malicious hit must massively
	// outrank a crash that merely floored a node to SUSPICIOUS, even though
	// both may share the SUSPICIOUS-or-worse severity band.
	realHit, realConf := ScoreFindings(fs([2]int{int(Malicious), int(ConfHigh)}))
	crashFloor, crashConf := ScoreFindings(fs([2]int{int(Suspicious), int(ConfLow)}))
	if !(realHit > crashFloor) {
		t.Fatalf("a real hit (%d) must outrank a crash floor (%d)", realHit, crashFloor)
	}
	if realConf != ConfHigh {
		t.Fatalf("a signature hit should be HIGH confidence, got %v", realConf)
	}
	if crashConf != ConfLow {
		t.Fatalf("a crash floor should be LOW confidence, got %v", crashConf)
	}
	// concretely: the eicar-shaped submission.
	eicar, conf := ScoreFindings([]Finding{
		{Verdict: Unknown, Confidence: ConfLow},    // ident file-type
		{Verdict: Unknown, Confidence: ConfLow},    // ident mime
		{Verdict: Malicious, Confidence: ConfHigh}, // yara eicar
	})
	if eicar < 90 || conf != ConfHigh {
		t.Fatalf("eicar submission should score high/HIGH, got %d/%v", eicar, conf)
	}
}

func TestScoreIsZeroWhenNothingIsReal(t *testing.T) {
	// benign / unknown-only submissions carry no triage weight and no confidence.
	score, conf := ScoreFindings([]Finding{
		{Verdict: Unknown, Confidence: ConfLow},
		{Verdict: Benign, Confidence: ConfHigh},
	})
	if score != 0 {
		t.Fatalf("unknown/benign should score 0, got %d", score)
	}
	if conf != ConfLow {
		t.Fatalf("nothing real means LOW confidence, got %v", conf)
	}
	if s, _ := ScoreFindings(nil); s != 0 {
		t.Fatalf("no findings should score 0, got %d", s)
	}
}

func TestScoreConfidenceScalesAndCorroborationDiminishes(t *testing.T) {
	// confidence scales a single finding's contribution monotonically.
	low, _ := ScoreFindings(fs([2]int{int(Malicious), int(ConfLow)}))
	med, _ := ScoreFindings(fs([2]int{int(Malicious), int(ConfMedium)}))
	high, _ := ScoreFindings(fs([2]int{int(Malicious), int(ConfHigh)}))
	if !(low < med && med < high) {
		t.Fatalf("confidence must scale contribution: low=%d med=%d high=%d", low, med, high)
	}
	// corroboration raises the score but with diminishing weight, and never
	// past the cap.
	one, _ := ScoreFindings(fs([2]int{int(Malicious), int(ConfHigh)}))
	two, _ := ScoreFindings(fs([2]int{int(Malicious), int(ConfHigh)}, [2]int{int(Malicious), int(ConfHigh)}))
	if !(two > one) {
		t.Fatalf("a second corroborating hit should raise the score: one=%d two=%d", one, two)
	}
	if two-one >= one {
		t.Fatalf("corroboration must diminish: first added %d, second added %d", one, two-one)
	}
	// a flood of findings still caps at 100.
	many := make([]Finding, 200)
	for i := range many {
		many[i] = Finding{Verdict: Malicious, Confidence: ConfHigh}
	}
	if s, _ := ScoreFindings(many); s != 100 {
		t.Fatalf("score must cap at 100, got %d", s)
	}
}

func TestScoreIsOrthogonalToSeverity(t *testing.T) {
	// a low-confidence MALICIOUS still scores less than a high-confidence one:
	// the severity band is the same, the triage priority differs. (severity
	// itself is the caller's Max over verdicts; ScoreFindings never touches it.)
	loMal, _ := ScoreFindings(fs([2]int{int(Malicious), int(ConfLow)}))
	hiSus, _ := ScoreFindings(fs([2]int{int(Suspicious), int(ConfHigh)}))
	// a firm suspicious can even outrank a shaky malicious in the queue, which
	// is exactly the point: confidence ranks within the fail-closed floor.
	if loMal == 0 || hiSus == 0 {
		t.Fatalf("both should contribute: loMal=%d hiSus=%d", loMal, hiSus)
	}
}
