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
	f := Finding{Engine: "mal-static-yara", Type: "yara", Detail: "eicar_test_file", Attck: "T1204", Verdict: Malicious}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"engine":"mal-static-yara","type":"yara","detail":"eicar_test_file","attck":"T1204","verdict":"MALICIOUS"}`
	if string(b) != want {
		t.Fatalf("finding wire shape drifted:\n got %s\nwant %s", b, want)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil || back != f {
		t.Fatalf("finding round trip: %+v %v", back, err)
	}
}
