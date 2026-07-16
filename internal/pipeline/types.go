// package pipeline holds the shared contract between the control-plane services:
// the verdict lattice, the submission input, and the rolled-up result. keeping
// these in one place is what makes the recursive pipeline and the explainable
// verdict stay consistent. see docs/PHASE1-TECHNICAL-DESIGN.md.
package pipeline

import (
	"encoding/json"
	"fmt"
)

// Verdict is ordered so "most suspicious wins" is a plain integer max, and
// BENIGN is the optimistic bottom. a benign result can never mask UNKNOWN,
// SUSPICIOUS, or MALICIOUS, and nothing is BENIGN by omission. this is the
// fail-closed lattice from the design.
type Verdict int

const (
	Benign     Verdict = iota // 0
	Unknown                   // 1
	Suspicious                // 2
	Malicious                 // 3
)

func (v Verdict) String() string {
	switch v {
	case Benign:
		return "BENIGN"
	case Suspicious:
		return "SUSPICIOUS"
	case Malicious:
		return "MALICIOUS"
	default:
		return "UNKNOWN"
	}
}

// ParseVerdict maps the wire form back into the lattice. fail-closed: an
// unrecognized string parses as SUSPICIOUS with ok=false, never as anything
// milder, so a corrupted or hostile verdict can only make us more paranoid.
func ParseVerdict(s string) (Verdict, bool) {
	switch s {
	case "BENIGN":
		return Benign, true
	case "UNKNOWN":
		return Unknown, true
	case "SUSPICIOUS":
		return Suspicious, true
	case "MALICIOUS":
		return Malicious, true
	}
	return Suspicious, false
}

// MarshalJSON writes the string form so api responses and workflow histories
// read as words, not magic integers.
func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// UnmarshalJSON accepts the string form and, for histories recorded before
// verdicts learned to speak, the legacy integer form.
func (v *Verdict) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, ok := ParseVerdict(s)
		if !ok {
			return fmt.Errorf("unknown verdict %q", s)
		}
		*v = parsed
		return nil
	}
	var i int
	if err := json.Unmarshal(b, &i); err == nil {
		if i < int(Benign) || i > int(Malicious) {
			return fmt.Errorf("verdict %d outside the lattice", i)
		}
		*v = Verdict(i)
		return nil
	}
	return fmt.Errorf("verdict must be a string or a legacy integer")
}

// Max returns the more suspicious of two verdicts (the lattice join).
func Max(a, b Verdict) Verdict {
	if a > b {
		return a
	}
	return b
}

// SubmissionInput is what the gateway hands to the workflow. the worker never
// sees this; it gets only the bytes of one file, mounted read-only by the
// orchestrator.
type SubmissionInput struct {
	SubmissionID string `json:"submission_id"`
	DomainID     string `json:"domain_id"` // one trust domain in phase 1, present from day one
	SHA256       string `json:"sha256"`
	ScratchPath  string `json:"scratch_path"` // vault-local path to the stored bytes
}

// Finding is one piece of evidence-linked signal from an engine.
type Finding struct {
	Engine  string  `json:"engine"`
	Type    string  `json:"type"`
	Detail  string  `json:"detail"`
	Attck   string  `json:"attck,omitempty"` // mitre att&ck technique, when the engine maps one
	Verdict Verdict `json:"verdict"`
}

// EngineReport is one engine's validated contribution: its findings and its
// local rolled-up verdict. the orchestrator only ever builds this from
// broker-validated bytes, then re-rolls the submission verdict itself.
type EngineReport struct {
	Engine     string    `json:"engine"`
	Findings   []Finding `json:"findings"`
	Verdict    Verdict   `json:"verdict"`
	Incomplete bool      `json:"incomplete"`
}

// SubmissionResult is the rolled-up, explainable outcome. every finding carries
// the engine that produced it, so a verdict can always be traced back.
type SubmissionResult struct {
	SubmissionID string    `json:"submission_id"`
	SHA256       string    `json:"sha256"`
	FileType     string    `json:"file_type,omitempty"`
	Verdict      Verdict   `json:"verdict"`
	Findings     []Finding `json:"findings"`
	Incomplete   bool      `json:"incomplete"` // set if anything was truncated or an engine failed (fail-closed)
}
