package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const goodReport = `{"engine":"mal-static-yara","findings":[{"engine":"mal-static-yara","type":"yara","detail":"eicar_test_file","attck":"T1204","verdict":"MALICIOUS"}],"verdict":"MALICIOUS","incomplete":false}`

func TestValidateAcceptsARealWorkerReport(t *testing.T) {
	out, err := validate(strings.NewReader(goodReport))
	if err != nil {
		t.Fatalf("rejected a good report: %v", err)
	}
	var rep report
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("emitted unparseable output: %v", err)
	}
	if rep.Verdict != "MALICIOUS" || len(rep.Findings) != 1 || rep.Findings[0].Detail != "eicar_test_file" {
		t.Fatalf("mangled the report: %+v", rep)
	}
	// trailing newline from the worker is fine; it is whitespace, not data.
	if _, err := validate(strings.NewReader(goodReport + "\n")); err != nil {
		t.Fatalf("rejected trailing newline: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]string{
		"empty input":         ``,
		"not json":            `hostile garbage`,
		"invented verdict":    `{"engine":"x","findings":[],"verdict":"TRUST_ME","incomplete":false}`,
		"lowercase verdict":   `{"engine":"x","findings":[],"verdict":"benign","incomplete":false}`,
		"bad finding verdict": `{"engine":"x","findings":[{"engine":"x","type":"t","detail":"d","attck":"","verdict":"NOPE"}],"verdict":"UNKNOWN","incomplete":false}`,
		"unknown field":       `{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false,"smuggled":1}`,
		"unknown sub-field":   `{"engine":"x","findings":[{"engine":"x","type":"t","detail":"d","attck":"","verdict":"UNKNOWN","extra":true}],"verdict":"UNKNOWN","incomplete":false}`,
		"trailing document":   `{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}{"second":true}`,
		"wrong types":         `{"engine":7,"findings":[],"verdict":"UNKNOWN","incomplete":false}`,
	}
	for name, in := range cases {
		if out, err := validate(strings.NewReader(in)); err == nil {
			t.Fatalf("%s: accepted %q -> %s", name, in, out)
		}
	}
}

func TestValidateCaps(t *testing.T) {
	// oversized total input
	big := `{"engine":"` + strings.Repeat("x", maxInputBytes) + `"}`
	if _, err := validate(strings.NewReader(big)); err == nil {
		t.Fatal("accepted input past the byte cap")
	}
	// a string field past its cap, inside a small document
	long := `{"engine":"` + strings.Repeat("y", maxStringLen+1) + `","findings":[],"verdict":"UNKNOWN","incomplete":false}`
	if _, err := validate(strings.NewReader(long)); err == nil {
		t.Fatal("accepted an oversized string field")
	}
	// too many findings
	one := `{"engine":"e","type":"t","detail":"d","attck":"","verdict":"UNKNOWN"}`
	var b bytes.Buffer
	b.WriteString(`{"engine":"x","findings":[`)
	for i := 0; i <= maxFindings; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(one)
	}
	b.WriteString(`],"verdict":"UNKNOWN","incomplete":false}`)
	if _, err := validate(&b); err == nil {
		t.Fatal("accepted too many findings")
	}
	// exactly at the cap is fine
	pad := `{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}`
	padded := pad + strings.Repeat(" ", maxInputBytes-len(pad))
	if _, err := validate(strings.NewReader(padded)); err != nil {
		t.Fatalf("rejected input exactly at the cap: %v", err)
	}
}

func TestValidateIsIdempotent(t *testing.T) {
	out, err := validate(strings.NewReader(goodReport))
	if err != nil {
		t.Fatal(err)
	}
	again, err := validate(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("broker rejects its own output: %v", err)
	}
	if !bytes.Equal(out, again) {
		t.Fatal("broker output is not a fixed point")
	}
}

// FuzzValidate hammers the trust boundary with arbitrary bytes. the invariants:
// never panic, never emit anything on reject, and anything accepted must
// re-validate to the same bytes with every cap and lattice rule holding.
func FuzzValidate(f *testing.F) {
	f.Add([]byte(goodReport))
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}`))
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"TRUST_ME","incomplete":false}`))
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false,"smuggled":1}`))
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}{"second":true}`))
	f.Add([]byte(``))
	f.Add([]byte(`[[[[[[`))
	f.Add([]byte("{\"engine\":\"\\u0000\",\"findings\":[],\"verdict\":\"BENIGN\",\"incomplete\":true}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := validate(bytes.NewReader(data))
		if err != nil {
			if out != nil {
				t.Fatal("emitted bytes on reject")
			}
			return
		}
		if len(out) == 0 || out[len(out)-1] != '\n' {
			t.Fatal("accepted output must be one newline-terminated document")
		}
		var rep report
		dec := json.NewDecoder(bytes.NewReader(out))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rep); err != nil {
			t.Fatalf("accepted output does not re-decode: %v", err)
		}
		if !validVerdict(rep.Verdict) {
			t.Fatalf("accepted a bad top-level verdict %q", rep.Verdict)
		}
		if len(rep.Findings) > maxFindings {
			t.Fatal("accepted too many findings")
		}
		if len(rep.Engine) > maxStringLen {
			t.Fatal("accepted an oversized engine string")
		}
		for _, fd := range rep.Findings {
			if !validVerdict(fd.Verdict) {
				t.Fatalf("accepted a bad finding verdict %q", fd.Verdict)
			}
			for _, s := range []string{fd.Engine, fd.Type, fd.Detail, fd.Attck} {
				if len(s) > maxStringLen {
					t.Fatal("accepted an oversized finding string")
				}
			}
		}
		// idempotence: our own output must be a fixed point.
		again, err := validate(bytes.NewReader(out))
		if err != nil || !bytes.Equal(out, again) {
			t.Fatalf("output is not a fixed point: %v", err)
		}
	})
}
