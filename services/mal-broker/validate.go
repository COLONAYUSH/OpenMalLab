package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const (
	maxInputBytes = 1 << 20 // 1 MiB, well under the durable-store payload limit
	maxFindings   = 1000
	maxChildren   = 1000 // an extractor manifest lists at most this many children
	maxStringLen  = 8192
)

// a child's sha256 is about to key a vault path upstream; it must be exactly
// 64 lowercase hex, nothing else.
var childSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

type finding struct {
	Engine  string `json:"engine"`
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Attck   string `json:"attck"`
	Verdict string `json:"verdict"`
}

// child is one artifact an extractor pulled out of a container. its sha256 is
// the content address the orchestrator will re-verify and key the vault on;
// name is display-only (the path inside the archive), never a filesystem path.
type child struct {
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
	Name   string `json:"name"`
}

type report struct {
	Engine     string    `json:"engine"`
	Findings   []finding `json:"findings"`
	Children   []child   `json:"children,omitempty"`
	Verdict    string    `json:"verdict"`
	Incomplete bool      `json:"incomplete"`
}

func validVerdict(v string) bool {
	switch v {
	case "BENIGN", "UNKNOWN", "SUSPICIOUS", "MALICIOUS":
		return true
	}
	return false
}

// countingReader lets validate enforce the cap on the TOTAL bytes consumed,
// not just on what the decoder happened to buffer.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// validate reads exactly one worker report from r under hard caps and returns
// the re-encoded validated bytes. the contract: accept if and only if the
// entire stream is one json document with known fields, verdicts from the
// fixed lattice, within all caps, followed by nothing but whitespace, and no
// larger than maxInputBytes in total. anything else is an error and nothing
// is emitted. pure function so tests and the fuzzer hit the real thing.
func validate(r io.Reader) ([]byte, error) {
	// read one byte past the cap so oversize is detectable, never decodable.
	cr := &countingReader{r: io.LimitReader(r, maxInputBytes+1)}
	dec := json.NewDecoder(cr)
	// reject unknown fields so a compromised worker cannot smuggle extra
	// structure past us.
	dec.DisallowUnknownFields()

	var rep report
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	// dec.More() is too forgiving for a trust boundary: it answers false for a
	// stray '}' or ']' after the document, so close-bracket garbage would ride
	// along unseen. enforce the actual contract instead: after the one document
	// there is nothing but whitespace until EOF. a second decode reports pure
	// whitespace as io.EOF; any other byte, however innocent, is trailing data.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after one result")
	}
	if cr.n > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	if !validVerdict(rep.Verdict) {
		return nil, fmt.Errorf("bad top-level verdict %q", rep.Verdict)
	}
	if len(rep.Findings) > maxFindings {
		return nil, fmt.Errorf("too many findings: %d", len(rep.Findings))
	}
	if err := checkStr("engine", rep.Engine); err != nil {
		return nil, err
	}
	for i, f := range rep.Findings {
		if !validVerdict(f.Verdict) {
			return nil, fmt.Errorf("finding %d has bad verdict %q", i, f.Verdict)
		}
		for _, c := range []struct{ field, s string }{
			{"finding.engine", f.Engine},
			{"finding.type", f.Type},
			{"finding.detail", f.Detail},
			{"finding.attck", f.Attck},
		} {
			if err := checkStr(c.field, c.s); err != nil {
				return nil, err
			}
		}
	}

	if len(rep.Children) > maxChildren {
		return nil, fmt.Errorf("too many children: %d", len(rep.Children))
	}
	for i, c := range rep.Children {
		// the sha keys a vault path upstream; enforce its shape here, at the
		// boundary, so no trusted code ever splices a hostile string into a path.
		if !childSHA.MatchString(c.SHA256) {
			return nil, fmt.Errorf("child %d has a malformed sha256 %q", i, c.SHA256)
		}
		if err := checkStr("child.name", c.Name); err != nil {
			return nil, err
		}
	}

	// validated: re-encode the typed result. this, and only this, is what a
	// trusted process reads. re-encode WITHOUT HTML-escaping: the default
	// json.Marshal rewrites < > & to \u00xx (6 bytes each), so an in-cap worker
	// report (validated <= maxInputBytes) could balloon PAST that same cap, which
	// the orchestrator also applies to our stdout - truncating and discarding the
	// whole report. that is a cheap, honest-path evasion: pad an archive manifest
	// with '<'-heavy child names and the broker's own re-encoding suppresses
	// recursion into the subtree. disabling HTML-escaping keeps the cap symmetric;
	// the explicit output check makes it fail closed for any residual expansion
	// (e.g. control-byte escaping) rather than silently overflowing downstream.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&rep); err != nil { // Encode appends the trailing newline
		return nil, fmt.Errorf("encode: %w", err)
	}
	if buf.Len() > maxInputBytes {
		return nil, fmt.Errorf("re-encoded output exceeds %d bytes", maxInputBytes)
	}
	return buf.Bytes(), nil
}

func checkStr(field, s string) error {
	if len(s) > maxStringLen {
		return fmt.Errorf("%s exceeds %d bytes", field, maxStringLen)
	}
	return nil
}
