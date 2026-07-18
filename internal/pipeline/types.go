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

// Confidence is how much we trust a verdict, and it is ORTHOGONAL to severity.
// The severity lattice fails closed: an engine crash or a gap floors a node to
// SUSPICIOUS. But a floored node is LOW confidence, while a signature hit is
// HIGH. Triage ranks on (severity, then score), and score is confidence-
// weighted, so a wall of fail-closed SUSPICIOUS never buries a real detection.
// Severity is never lowered by low confidence; the two axes move independently.
type Confidence int

const (
	ConfLow    Confidence = iota // a fail-closed floor, a gap, an incomplete run
	ConfMedium                   // a heuristic or behavioral signal
	ConfHigh                     // a definitive signature or extracted artifact
)

func (c Confidence) String() string {
	switch c {
	case ConfHigh:
		return "HIGH"
	case ConfMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ParseConfidence maps the wire form back. fail-closed like the verdict: an
// unrecognized value reads as LOW (we are not confident in what we cannot
// parse), never as a higher confidence.
func ParseConfidence(s string) (Confidence, bool) {
	switch s {
	case "LOW":
		return ConfLow, true
	case "MEDIUM":
		return ConfMedium, true
	case "HIGH":
		return ConfHigh, true
	}
	return ConfLow, false
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Confidence) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, ok := ParseConfidence(s)
		if !ok {
			return fmt.Errorf("unknown confidence %q", s)
		}
		*c = parsed
		return nil
	}
	var i int
	if err := json.Unmarshal(b, &i); err == nil {
		if i < int(ConfLow) || i > int(ConfHigh) {
			return fmt.Errorf("confidence %d outside range", i)
		}
		*c = Confidence(i)
		return nil
	}
	return fmt.Errorf("confidence must be a string or a legacy integer")
}

// ConfidenceFor is the control-plane policy that assigns a confidence to a
// finding from its engine, type, and verdict. it lives in trusted code, never
// in a hostile-input worker: the worker reports what it saw, the orchestrator
// decides how much that is worth. gaps and fail-closed floors are indicators,
// not detections, so they stay LOW and raise severity without inflating score.
func ConfidenceFor(engine, findingType string, v Verdict) Confidence {
	switch findingType {
	case "error", "recursion-cap", "ingest-rejected", "extraction-cap-hit",
		"decompression-bomb", "high-compression-ratio", "entry-too-large",
		"entry-count-cap", "skipped-symlink", "skipped-link", "skipped-special",
		"path-traversal-name":
		return ConfLow
	}
	// a yara signature match is a definitive identification.
	if engine == "mal-static-yara" && findingType == "yara" {
		return ConfHigh
	}
	// capa reports behavioral capabilities: real signal, but inference from
	// static features, so medium at most. (its UNKNOWN capabilities fall through
	// to the low branch below and score zero.)
	if engine == "mal-capa" && findingType == "capability" && v >= Suspicious {
		return ConfMedium
	}
	// informational output (identification, archive typing, behavioral context)
	// carries an UNKNOWN verdict and scores zero regardless; keep it out of the
	// confidence axis.
	if v <= Unknown {
		return ConfLow
	}
	return ConfMedium
}

// base is a finding's raw triage weight by severity, before confidence scaling.
func base(v Verdict) int {
	switch v {
	case Malicious:
		return 95
	case Suspicious:
		return 55
	default:
		return 0 // UNKNOWN and BENIGN carry no triage weight
	}
}

// contribution is what one finding adds to the triage score: its severity
// weight scaled by confidence. a definitive malicious hit dominates; a
// fail-closed floor (low confidence) contributes little.
func contribution(v Verdict, c Confidence) int {
	b := base(v)
	switch c {
	case ConfHigh:
		return b
	case ConfMedium:
		return b * 6 / 10
	default:
		return b * 3 / 10
	}
}

// ScoreFindings derives the 0-100 triage score and the aggregate confidence
// from a submission's findings. deterministic integer math (safe inside a
// workflow) and fully explainable: every point traces to a finding, so the
// score cites its own evidence. the strongest signal dominates and each
// further signal corroborates with halving weight, so many weak signals add up
// without a single crash-floor ever ranking like a real detection.
func ScoreFindings(findings []Finding) (int, Confidence) {
	contribs := make([]int, 0, len(findings))
	agg := ConfLow
	hasReal := false
	for _, f := range findings {
		if c := contribution(f.Verdict, f.Confidence); c > 0 {
			contribs = append(contribs, c)
		}
		if f.Verdict >= Suspicious {
			hasReal = true
			if f.Confidence > agg {
				agg = f.Confidence
			}
		}
	}
	if !hasReal {
		agg = ConfLow // nothing at or above SUSPICIOUS: not confident in anything
	}
	// strongest first, then diminishing corroboration.
	sortDesc(contribs)
	score, div := 0, 1
	for _, c := range contribs {
		score += c / div
		if div < 8 {
			div *= 2
		}
	}
	if score > 100 {
		score = 100
	}
	return score, agg
}

// sortDesc is a tiny insertion sort: finding counts are small and it keeps this
// package dependency-free and obviously deterministic.
func sortDesc(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] > a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// SubmissionInput is what the gateway hands to the workflow. the worker never
// sees this; it gets only the bytes of one file, mounted read-only by the
// orchestrator.
type SubmissionInput struct {
	SubmissionID string `json:"submission_id"`
	DomainID     string `json:"domain_id"` // one trust domain in phase 1, present from day one
	SHA256       string `json:"sha256"`
	ScratchPath  string `json:"scratch_path"`       // vault-local path to the stored bytes
	Filename     string `json:"filename,omitempty"` // the submitted name, hostile: display-only, always defanged
}

// Finding is one piece of evidence-linked signal from an engine. It is the
// atom of evidence: the score is a pure function of the findings, so every
// point of the verdict traces back to the finding that produced it.
type Finding struct {
	Engine  string  `json:"engine"`
	Type    string  `json:"type"`
	Detail  string  `json:"detail"`
	Attck   string  `json:"attck,omitempty"` // mitre att&ck technique, when the engine maps one
	Verdict Verdict `json:"verdict"`
	// Confidence is how much this finding is trusted, orthogonal to its
	// verdict. the orchestrator assigns it by policy (ConfidenceFor); a hostile
	// worker never gets to declare how sure we are.
	Confidence Confidence `json:"confidence"`
	// Path is the breadcrumb from the root submission to the artifact this
	// finding came from, e.g. "outer.zip!dir/inner.exe". the orchestrator
	// (trusted) sets it while folding recursive results; engines never emit it.
	Path string `json:"path,omitempty"`
}

// Child is one artifact an extractor pulled out of a container. SHA256 is the
// content address; Name is display-only (the path inside the archive). the
// orchestrator re-hashes the staged bytes before trusting SHA256.
type Child struct {
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
	Name   string `json:"name"`
}

// EngineReport is one engine's validated contribution: its findings, any
// children it extracted, and its local rolled-up verdict. the orchestrator
// only ever builds this from broker-validated bytes, then re-rolls the
// submission verdict itself.
type EngineReport struct {
	Engine     string    `json:"engine"`
	Findings   []Finding `json:"findings"`
	Children   []Child   `json:"children,omitempty"`
	Verdict    Verdict   `json:"verdict"`
	Incomplete bool      `json:"incomplete"`
}

// SubmissionResult is the rolled-up, explainable outcome. every finding carries
// the engine that produced it, so a verdict can always be traced back.
//
// Verdict is the fail-closed severity floor; Score (0-100) and Confidence are
// the orthogonal triage axis. A queue sorts by (Verdict, Score) so a real
// detection outranks a crash-floored SUSPICIOUS even though both share a
// severity.
type SubmissionResult struct {
	SubmissionID string     `json:"submission_id"`
	SHA256       string     `json:"sha256"`
	Filename     string     `json:"filename,omitempty"` // the submitted name, hostile: display-only, always defanged
	FileType     string     `json:"file_type,omitempty"`
	Verdict      Verdict    `json:"verdict"`
	Score        int        `json:"score"`      // 0-100 triage priority, confidence-weighted
	Confidence   Confidence `json:"confidence"` // aggregate confidence in the verdict
	Findings     []Finding  `json:"findings"`
	Incomplete   bool       `json:"incomplete"`             // set if anything was truncated or an engine failed (fail-closed)
	NeedsReview  bool       `json:"needs_review,omitempty"` // a human should look: set by the AI-plane escalation seam, never by an engine
}
