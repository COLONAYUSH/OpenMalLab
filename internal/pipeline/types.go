// package pipeline holds the shared contract between the control-plane services:
// the verdict lattice, the submission input, and the rolled-up result. keeping
// these in one place is what makes the recursive pipeline and the explainable
// verdict stay consistent. see docs/PHASE1-TECHNICAL-DESIGN.md.
package pipeline

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

// Max returns the more suspicious of two verdicts (the lattice join).
func Max(a, b Verdict) Verdict {
	if a > b {
		return a
	}
	return b
}

// SubmissionInput is what the gateway hands to the workflow. the worker never
// sees this; it gets only the bytes, on a read-only mounted fd, later on.
type SubmissionInput struct {
	SubmissionID string
	DomainID     string // one trust domain in phase 1, present from day one
	SHA256       string
	ScratchPath  string // local path to the stored bytes (the real vault comes next)
}

// Finding is one piece of evidence-linked signal from an engine.
type Finding struct {
	Engine  string
	Type    string
	Detail  string
	Verdict Verdict
}

// SubmissionResult is the rolled-up, explainable outcome. every finding carries
// the engine that produced it, so a verdict can always be traced back.
type SubmissionResult struct {
	SubmissionID string
	SHA256       string
	FileType     string
	Verdict      Verdict
	Findings     []Finding
	Incomplete   bool // set if anything was truncated or an engine failed (fail-closed)
}
