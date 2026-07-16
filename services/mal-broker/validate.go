package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxInputBytes = 1 << 20 // 1 MiB, well under the durable-store payload limit
	maxFindings   = 1000
	maxStringLen  = 8192
)

type finding struct {
	Engine  string `json:"engine"`
	Type    string `json:"type"`
	Detail  string `json:"detail"`
	Attck   string `json:"attck"`
	Verdict string `json:"verdict"`
}

type report struct {
	Engine     string    `json:"engine"`
	Findings   []finding `json:"findings"`
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
	if dec.More() {
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

	// validated: re-encode the typed result. this, and only this, is what a
	// trusted process reads.
	out, err := json.Marshal(&rep)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	return append(out, '\n'), nil
}

func checkStr(field, s string) error {
	if len(s) > maxStringLen {
		return fmt.Errorf("%s exceeds %d bytes", field, maxStringLen)
	}
	return nil
}
