package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

const goodReport = `{"engine":"mal-static-yara","findings":[{"engine":"mal-static-yara","type":"yara","detail":"eicar_test_file","attck":"T1204","verdict":"MALICIOUS"}],"verdict":"MALICIOUS","incomplete":false}`

const (
	goodSHA  = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	upperHex = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
	nonHex   = "zzza021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)

const goodExtract = `{"engine":"mal-extract","findings":[{"engine":"mal-extract","type":"archive","detail":"zip","attck":"","verdict":"UNKNOWN"}],"children":[{"sha256":"` + goodSHA + `","size":42,"name":"dir/inner.exe"}],"verdict":"UNKNOWN","incomplete":false}`

func TestValidateAcceptsAnExtractManifest(t *testing.T) {
	out, err := validate(strings.NewReader(goodExtract))
	if err != nil {
		t.Fatalf("rejected a good extract manifest: %v", err)
	}
	var rep report
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("emitted unparseable output: %v", err)
	}
	if len(rep.Children) != 1 || rep.Children[0].SHA256 != goodSHA || rep.Children[0].Size != 42 {
		t.Fatalf("mangled the children: %+v", rep.Children)
	}
	if rep.Children[0].Name != "dir/inner.exe" {
		t.Fatalf("child name not preserved: %q", rep.Children[0].Name)
	}
}

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

func TestValidateOutputStaysSymmetric(t *testing.T) {
	// an extract manifest padded with '<'-heavy child names: default HTML-escaping
	// (json.Marshal) would balloon each '<' to 6 bytes and push the re-encoded
	// output past the same 1 MiB cap the orchestrator applies to our stdout,
	// discarding the whole in-cap report and suppressing recursion into the
	// subtree. with SetEscapeHTML(false) the output stays symmetric and survives.
	name := strings.Repeat("<", 256)
	kid := `{"sha256":"` + goodSHA + `","size":1,"name":"` + name + `"}`
	kids := make([]string, 700)
	for i := range kids {
		kids[i] = kid
	}
	in := `{"engine":"mal-extract","findings":[],"children":[` + strings.Join(kids, ",") + `],"verdict":"UNKNOWN","incomplete":false}`
	if len(in) >= 1<<20 {
		t.Fatalf("test input must be under the input cap, got %d", len(in))
	}
	out, err := validate(strings.NewReader(in))
	if err != nil {
		t.Fatalf("an in-cap manifest was rejected (re-encode must stay symmetric): %v", err)
	}
	if len(out) > 1<<20 {
		t.Fatalf("re-encoded output exceeded the 1 MiB cap: %d bytes", len(out))
	}
	// with escaping disabled the '<' survive verbatim; had they been escaped to a
	// 6-byte form each, the output would have blown the cap and been rejected
	// above. so a literal '<' present here proves the re-encode stayed symmetric.
	if !bytes.Contains(out, []byte("<")) {
		t.Fatal("child names not preserved verbatim: the re-encode is still HTML-escaping")
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
		"short child sha":     `{"engine":"x","findings":[],"children":[{"sha256":"abc","size":1,"name":"a"}],"verdict":"UNKNOWN","incomplete":false}`,
		"uppercase child sha": `{"engine":"x","findings":[],"children":[{"sha256":"` + upperHex + `","size":1,"name":"a"}],"verdict":"UNKNOWN","incomplete":false}`,
		"non-hex child sha":   `{"engine":"x","findings":[],"children":[{"sha256":"` + nonHex + `","size":1,"name":"a"}],"verdict":"UNKNOWN","incomplete":false}`,
		"unknown child field": `{"engine":"x","findings":[],"children":[{"sha256":"` + goodSHA + `","size":1,"name":"a","path":"/etc"}],"verdict":"UNKNOWN","incomplete":false}`,
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

func TestValidateStrictTrailingBytes(t *testing.T) {
	base := `{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}`
	// dec.More() alone tolerates stray close-brackets after the document; the
	// contract is whitespace-only to EOF. every one of these must be thrown out.
	for _, tail := range []string{"}", "]", "]]]}", "{", ",", "x", "\x00", " }", "\n]", "null", `""`, "\n{\"a\":1}"} {
		if out, err := validate(strings.NewReader(base + tail)); err == nil {
			t.Fatalf("accepted trailing %q -> %s", tail, out)
		}
	}
	// whitespace after the document is not data.
	for _, tail := range []string{"", "\n", " \t\r\n", strings.Repeat(" ", 4096)} {
		if _, err := validate(strings.NewReader(base + tail)); err != nil {
			t.Fatalf("rejected benign whitespace tail %q: %v", tail, err)
		}
	}
}

func TestValidateByteCapBoundary(t *testing.T) {
	doc := `{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}`
	at := doc + strings.Repeat(" ", maxInputBytes-len(doc))
	if _, err := validate(strings.NewReader(at)); err != nil {
		t.Fatalf("rejected input exactly at the byte cap: %v", err)
	}
	if _, err := validate(strings.NewReader(at + " ")); err == nil {
		t.Fatal("accepted input one byte past the cap")
	}
}

func TestValidateSHA256Shape(t *testing.T) {
	wrap := func(sha string) string {
		return `{"engine":"x","findings":[],"children":[{"sha256":"` + sha + `","size":1,"name":"a"}],"verdict":"UNKNOWN","incomplete":false}`
	}
	rejects := map[string]string{
		"63 hex":             goodSHA[:63],
		"65 hex":             goodSHA + "a",
		"one uppercase":      goodSHA[:10] + "A" + goodSHA[11:],
		"non-hex letter":     "g" + goodSHA[1:],
		"empty":              "",
		"newline as 64th":    goodSHA[:63] + `\n`,
		"trailing newline":   goodSHA + `\n`,
		"cyrillic homoglyph": "\u0430" + goodSHA[1:], // U+0430 renders like 'a', is not hex
		"leading space":      " " + goodSHA[:63],
	}
	for name, sha := range rejects {
		if _, err := validate(strings.NewReader(wrap(sha))); err == nil {
			t.Fatalf("%s: accepted sha %q", name, sha)
		}
	}
	// json escapes that DECODE to 64 lowercase hex are fine: the decoded value
	// is what keys the vault, and the shape check runs on exactly that.
	out, err := validate(strings.NewReader(wrap(`\u0032` + goodSHA[1:]))) // \u0032 decodes to '2'
	if err != nil {
		t.Fatalf("rejected an escaped-but-valid sha: %v", err)
	}
	var rep report
	if err := json.Unmarshal(out, &rep); err != nil || rep.Children[0].SHA256 != goodSHA {
		t.Fatalf("escaped sha did not normalize to its decoded value: %+v (%v)", rep, err)
	}
}

func TestValidateHostileNamesArePreservedInertly(t *testing.T) {
	names := []string{
		"nul\u0000mid",                // NUL inside the string
		"esc\u001b[31mred",            // ANSI escape
		"rtlo\u202egpj.exe",           // bidi override display spoof
		"zw\u200b\u200djoin",          // zero-width space and joiner
		"ls\u2028ps\u2029end",         // JS line and paragraph separators
		"bell\u0007tab\u0009nl\u000a", // legacy control characters
	}
	for _, n := range names {
		nb, _ := json.Marshal(n)
		in := `{"engine":"x","findings":[],"children":[{"sha256":"` + goodSHA + `","size":1,"name":` + string(nb) + `}],"verdict":"UNKNOWN","incomplete":false}`
		out, err := validate(strings.NewReader(in))
		if err != nil {
			t.Fatalf("rejected a schema-valid hostile name %q: %v", n, err)
		}
		var rep report
		if err := json.Unmarshal(out, &rep); err != nil || len(rep.Children) != 1 {
			t.Fatalf("bad round-trip for %q: %v", n, err)
		}
		// display strings are the console's problem; the broker's contract is to
		// preserve the value exactly and keep the byte stream inert.
		if rep.Children[0].Name != n {
			t.Fatalf("name mangled: %q -> %q", n, rep.Children[0].Name)
		}
		for i, b := range out {
			if b < 0x20 && !(i == len(out)-1 && b == '\n') {
				t.Fatalf("raw control byte 0x%02x at offset %d in output for %q", b, i, n)
			}
		}
		if !utf8.Valid(out) {
			t.Fatalf("output for %q is not valid utf-8", n)
		}
	}
}

// go's decoder matches keys case-insensitively and lets a later duplicate win.
// neither can smuggle anything past the boundary: validation runs on the final
// decoded value, and the re-encode emits exactly one canonical lowercase key,
// so no two downstream readers can ever disagree about what was accepted.
func TestValidateDuplicateAndCaseVariantFields(t *testing.T) {
	dup := `{"engine":"x","findings":[],"verdict":"BENIGN","verdict":"MALICIOUS","incomplete":false}`
	out, err := validate(strings.NewReader(dup))
	if err != nil {
		t.Fatalf("dup-key doc rejected: %v", err)
	}
	if n := bytes.Count(out, []byte(`"verdict"`)); n != 1 {
		t.Fatalf("output must carry exactly one verdict key, got %d: %s", n, out)
	}
	var rep report
	if err := json.Unmarshal(out, &rep); err != nil || rep.Verdict != "MALICIOUS" {
		t.Fatalf("expected the winning duplicate to be validated, got %+v (%v)", rep, err)
	}
	// and it is the WINNING duplicate that faces the lattice check.
	bad := `{"engine":"x","findings":[],"verdict":"BENIGN","verdict":"TRUST_ME","incomplete":false}`
	if _, err := validate(strings.NewReader(bad)); err == nil {
		t.Fatal("accepted a doc whose winning duplicate verdict is invalid")
	}
	caseVar := `{"Engine":"x","FINDINGS":[],"Verdict":"UNKNOWN","Incomplete":true}`
	out, err = validate(strings.NewReader(caseVar))
	if err != nil {
		t.Fatalf("case-variant keys rejected: %v", err)
	}
	if !bytes.Contains(out, []byte(`"verdict":"UNKNOWN"`)) {
		t.Fatalf("case-variant keys not canonicalized: %s", out)
	}
}

func TestValidateCountCapExactBoundary(t *testing.T) {
	one := `{"engine":"e","type":"t","detail":"d","attck":"","verdict":"UNKNOWN"}`
	var b bytes.Buffer
	b.WriteString(`{"engine":"x","findings":[`)
	for i := 0; i < maxFindings; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(one)
	}
	b.WriteString(`],"verdict":"UNKNOWN","incomplete":false}`)
	if _, err := validate(&b); err != nil {
		t.Fatalf("rejected exactly maxFindings findings: %v", err)
	}
	kid := `{"sha256":"` + goodSHA + `","size":1,"name":"k"}`
	mk := func(n int) *bytes.Buffer {
		var b bytes.Buffer
		b.WriteString(`{"engine":"x","findings":[],"children":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(kid)
		}
		b.WriteString(`],"verdict":"UNKNOWN","incomplete":false}`)
		return &b
	}
	if _, err := validate(mk(maxChildren)); err != nil {
		t.Fatalf("rejected exactly maxChildren children: %v", err)
	}
	if _, err := validate(mk(maxChildren + 1)); err == nil {
		t.Fatal("accepted one child past the cap")
	}
}

func TestValidateStringLenBoundary(t *testing.T) {
	mk := func(engine string) string {
		return `{"engine":"` + engine + `","findings":[],"verdict":"UNKNOWN","incomplete":false}`
	}
	if _, err := validate(strings.NewReader(mk(strings.Repeat("e", maxStringLen)))); err != nil {
		t.Fatalf("rejected a string exactly at the cap: %v", err)
	}
	if _, err := validate(strings.NewReader(mk(strings.Repeat("e", maxStringLen+1)))); err == nil {
		t.Fatal("accepted a string one byte past the cap")
	}
	// the cap counts DECODED bytes: 2731 bidi overrides decode to 3 bytes each,
	// 8193 in total, one over. 2730 of them plus two ascii land exactly on it.
	if _, err := validate(strings.NewReader(mk(strings.Repeat("\u202e", 2731)))); err == nil {
		t.Fatal("accepted a multibyte string past the byte cap")
	}
	if _, err := validate(strings.NewReader(mk(strings.Repeat("\u202e", 2730) + "aa"))); err != nil {
		t.Fatalf("rejected a multibyte string exactly at the byte cap: %v", err)
	}
}

// raw invalid utf-8 inside input strings decodes to U+FFFD (1 byte in, 3 bytes
// out), the one residual way a sub-cap input can re-encode bigger than it
// arrived. the output-side cap must catch it: reject, never emit past the cap.
func TestValidateDecodeExpansionFailsClosed(t *testing.T) {
	badName := bytes.Repeat([]byte{0x80}, 2730) // decodes to 8190 bytes, inside the string cap
	kid := append([]byte(`{"sha256":"`+goodSHA+`","size":1,"name":"`), badName...)
	kid = append(kid, []byte(`"}`)...)
	var in bytes.Buffer
	in.WriteString(`{"engine":"x","findings":[],"children":[`)
	for i := 0; i < 150; i++ {
		if i > 0 {
			in.WriteByte(',')
		}
		in.Write(kid)
	}
	in.WriteString(`],"verdict":"UNKNOWN","incomplete":false}`)
	if in.Len() > maxInputBytes {
		t.Fatalf("test bug: input must be under the cap, got %d", in.Len())
	}
	out, err := validate(&in)
	if err == nil {
		t.Fatalf("accepted an input whose re-encode must exceed the cap (out=%d bytes)", len(out))
	}
	if out != nil {
		t.Fatal("emitted bytes on reject")
	}
	// one such child stays well under the cap and is accepted with the invalid
	// bytes normalized to U+FFFD: the reject above is the size check firing,
	// not the bytes themselves being refused.
	var small bytes.Buffer
	small.WriteString(`{"engine":"x","findings":[],"children":[`)
	small.Write(kid)
	small.WriteString(`],"verdict":"UNKNOWN","incomplete":false}`)
	out, err = validate(&small)
	if err != nil {
		t.Fatalf("rejected a sub-cap report with invalid utf-8 in a name: %v", err)
	}
	var rep report
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Children[0].Name != strings.Repeat("\ufffd", 2730) {
		t.Fatal("invalid utf-8 was not normalized to U+FFFD")
	}
}

func TestValidateWholeDocumentShapes(t *testing.T) {
	for name, in := range map[string]string{
		"null":            `null`,
		"empty object":    `{}`,
		"array":           `[]`,
		"bare string":     `"report"`,
		"bare number":     `7`,
		"bare bool":       `true`,
		"bom prefix":      "\ufeff" + `{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}`,
		"missing verdict": `{"engine":"x","findings":[],"incomplete":false}`,
	} {
		if _, err := validate(strings.NewReader(in)); err == nil {
			t.Fatalf("%s: accepted %q", name, in)
		}
	}
}

func TestValidateNumericFieldStrictness(t *testing.T) {
	wrap := func(size string) string {
		return `{"engine":"x","findings":[],"children":[{"sha256":"` + goodSHA + `","size":` + size + `,"name":"a"}],"verdict":"UNKNOWN","incomplete":false}`
	}
	for _, bad := range []string{`-1`, `1.5`, `1e5`, `"1"`, `18446744073709551616`} {
		if _, err := validate(strings.NewReader(wrap(bad))); err == nil {
			t.Fatalf("accepted size %s", bad)
		}
	}
	// full uint64 range is representable and round-trips unmangled. size is a
	// worker CLAIM either way; the orchestrator re-verifies content by hash.
	if out, err := validate(strings.NewReader(wrap(`18446744073709551615`))); err != nil {
		t.Fatalf("rejected max uint64 size: %v", err)
	} else if !bytes.Contains(out, []byte(`18446744073709551615`)) {
		t.Fatalf("max uint64 mangled: %s", out)
	}
	// json null into a uint64 is a decode no-op in go: it reads as size 0. the
	// re-encode pins that 0 explicitly, so downstream sees one unambiguous value.
	out, err := validate(strings.NewReader(wrap(`null`)))
	if err != nil {
		t.Fatalf("null size: %v", err)
	}
	if !bytes.Contains(out, []byte(`"size":0`)) {
		t.Fatalf("null size did not normalize to 0: %s", out)
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
	f.Add([]byte(goodExtract))
	f.Add([]byte(`{"engine":"x","findings":[],"children":[{"sha256":"abc","size":1,"name":"a"}],"verdict":"UNKNOWN","incomplete":false}`))
	// trailing close-bracket garbage that dec.More() alone would wave through.
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}]`))
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}}`))
	// duplicate and case-variant keys: last-wins, canonicalized on re-encode.
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"BENIGN","verdict":"MALICIOUS","incomplete":false}`))
	f.Add([]byte(`{"Engine":"x","FINDINGS":[],"Verdict":"UNKNOWN","Incomplete":true}`))
	// hostile display strings: bidi override, escapes, max uint64 size.
	f.Add([]byte(`{"engine":"x","findings":[],"children":[{"sha256":"` + goodSHA + `","size":18446744073709551615,"name":"rtlo\u202egpj.exe"}],"verdict":"UNKNOWN","incomplete":false}`))
	f.Add([]byte(`{"engine":"x","findings":[],"children":[{"sha256":"` + goodSHA + `","size":1.5,"name":"a"}],"verdict":"UNKNOWN","incomplete":false}`))
	// raw invalid utf-8 inside a string: decodes to U+FFFD, expands 1 -> 3 bytes.
	f.Add(append(append([]byte(`{"engine":"`), bytes.Repeat([]byte{0x80}, 8)...),
		[]byte(`","findings":[],"verdict":"UNKNOWN","incomplete":false}`)...))
	f.Add([]byte(`null`))
	f.Add([]byte("{\"findings\":" + strings.Repeat("[", 512)))
	f.Add([]byte(`{"engine":"x","findings":[],"verdict":"UNKNOWN","incomplete":false}` + "\n \t\r\n"))

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
		if len(out) > maxInputBytes {
			t.Fatalf("emitted %d bytes, past the byte cap", len(out))
		}
		// inertness: valid utf-8, and no raw control byte anywhere in the
		// emitted stream except the single terminating newline.
		if !utf8.Valid(out) {
			t.Fatal("emitted invalid utf-8")
		}
		for i, b := range out {
			if b < 0x20 && !(i == len(out)-1 && b == '\n') {
				t.Fatalf("emitted a raw control byte 0x%02x at offset %d", b, i)
			}
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
		if len(rep.Children) > maxChildren {
			t.Fatal("accepted too many children")
		}
		for _, c := range rep.Children {
			// the single most important child invariant: whatever is accepted,
			// its sha256 is safe to splice into a vault path upstream.
			if !childSHA.MatchString(c.SHA256) {
				t.Fatalf("accepted a malformed child sha256 %q", c.SHA256)
			}
			if len(c.Name) > maxStringLen {
				t.Fatal("accepted an oversized child name")
			}
		}
		// idempotence: our own output must be a fixed point.
		again, err := validate(bytes.NewReader(out))
		if err != nil || !bytes.Equal(out, again) {
			t.Fatalf("output is not a fixed point: %v", err)
		}
	})
}
