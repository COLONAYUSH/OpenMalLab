// package aiplane is the contained boundary of the AI-analyst plane. the AI is
// an UNTRUSTED analyst: it reasons over a DEFANGED, structured projection of a
// submission (Evidence) and returns a typed Proposal, and Validate strictly
// checks that proposal - bounded, known-fields-only, fail-closed - before any
// trusted process reads it.
//
// this is the broker-analogue for the AI plane, mirroring mal-broker's
// discipline: hostile, attacker-controlled text is carried as DATA in
// delimited, defanged fields (never concatenated into an instruction), and the
// model's output is never trusted on its face - it is validated here, then the
// confidence gate + the fail-closed lattice decide. the AI can only propose.
package aiplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

const (
	maxProposalBytes = 1 << 20 // like the broker's input cap
	maxSummaryLen    = 8192
	maxClaimLen      = 2048
	maxFieldLen      = 512  // kind / key / type / value / reason / id
	maxDetailLen     = 8192 // evidence detail / path (matches the broker per-field cap)
	maxHypotheses    = 64
	maxIOCs          = 256
	maxCitations     = 32 // per hypothesis
	maxEvidenceItems = 2000
)

// validConfidence are the only confidence tokens the gate understands. anything
// else is floored to LOW (the model's self-report is advisory; fail low).
var validConfidence = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true}

// -------- Evidence: the pipeline -> AI plane projection --------

// EvidenceItem is one defanged finding the AI reasons over.
type EvidenceItem struct {
	Engine     string `json:"engine"`
	Type       string `json:"type"`
	Detail     string `json:"detail"` // DEFANGED
	Attck      string `json:"attck,omitempty"`
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence,omitempty"`
	Path       string `json:"path,omitempty"` // DEFANGED breadcrumb
}

// Evidence is the defanged, bounded, structured view of a submission handed to
// the AI plane. the deterministic verdict/score/confidence are the ground truth
// the AI must not contradict; every attacker-controlled string is defanged.
type Evidence struct {
	SubmissionID string         `json:"submission_id"`
	SHA256       string         `json:"sha256"`
	FileType     string         `json:"file_type,omitempty"`
	Verdict      string         `json:"verdict"`
	Score        int            `json:"score"`
	Confidence   string         `json:"confidence"`
	Incomplete   bool           `json:"incomplete"`
	Items        []EvidenceItem `json:"items"`
}

// EvidenceFrom projects a deterministic result into the defanged evidence the AI
// plane reasons over. findings are capped, and every hostile-derived string
// (details, breadcrumb paths, file type) is defanged first.
func EvidenceFrom(res pipeline.SubmissionResult) Evidence {
	ev := Evidence{
		SubmissionID: res.SubmissionID, // trusted: our own id
		SHA256:       res.SHA256,       // validated hex upstream
		FileType:     clean(res.FileType, maxFieldLen),
		Verdict:      res.Verdict.String(),
		Score:        res.Score,
		Confidence:   res.Confidence.String(),
		Incomplete:   res.Incomplete,
	}
	// clean EVERY hostile-derived field (not just detail/path): engine/type/attck
	// reach here through a broker that only length-checks them, so a compromised
	// worker could otherwise smuggle control bytes or live links into evidence.
	for i := range res.Findings {
		if i >= maxEvidenceItems {
			ev.Incomplete = true // a truncated projection must never look complete to the model
			break
		}
		f := res.Findings[i]
		ev.Items = append(ev.Items, EvidenceItem{
			Engine:     clean(f.Engine, maxFieldLen),
			Type:       clean(f.Type, maxFieldLen),
			Detail:     clean(f.Detail, maxDetailLen),
			Attck:      clean(f.Attck, maxFieldLen),
			Verdict:    f.Verdict.String(),    // trusted enum
			Confidence: f.Confidence.String(), // trusted enum
			Path:       clean(f.Path, maxDetailLen),
		})
	}
	return ev
}

// -------- Proposal: the AI plane -> pipeline output --------

// Citation is a fact the agent cites for a claim. the confidence gate verifies
// it against the L0 registry; Validate only checks it is well-formed.
type Citation struct {
	FactID string `json:"fact_id"`
	Kind   string `json:"kind"`
	Key    string `json:"key"`
}

// Hypothesis is one proposed conclusion. Confidence is the model's SELF-report
// (advisory; the gate recalibrates against measured per-task reliability).
type Hypothesis struct {
	Kind       string     `json:"kind"`
	Claim      string     `json:"claim"`
	Confidence string     `json:"confidence"`
	Citations  []Citation `json:"citations,omitempty"`
}

// ProposedIOC is an indicator the agent surfaces. it is a lead, not a verdict.
type ProposedIOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Proposal is the AI plane's typed, UNTRUSTED output. it deliberately carries no
// submission id: the caller knows which submission it dispatched, so the model
// cannot misattribute its output to a different one (confused deputy).
type Proposal struct {
	Summary      string        `json:"summary"`
	Hypotheses   []Hypothesis  `json:"hypotheses,omitempty"`
	IOCs         []ProposedIOC `json:"iocs,omitempty"`
	NeedsReview  bool          `json:"needs_review"`
	ReviewReason string        `json:"review_reason,omitempty"`
}

// Validate strictly decodes and bounds the model's raw output, failing closed on
// anything malformed, oversized, or carrying unknown fields. it cleans (defangs
// + truncates) every free-text field, floors an unrecognized confidence to LOW,
// and rejects the whole proposal if a citation is not well-formed. the returned
// Proposal is safe for a trusted process to read - but is still only a proposal.
func Validate(raw []byte) (Proposal, error) {
	if len(raw) == 0 {
		return Proposal{}, fmt.Errorf("aiplane: empty proposal")
	}
	if len(raw) > maxProposalBytes {
		return Proposal{}, fmt.Errorf("aiplane: proposal exceeds %d bytes", maxProposalBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Proposal
	if err := dec.Decode(&p); err != nil {
		return Proposal{}, fmt.Errorf("aiplane: proposal decode: %w", err)
	}
	// dec.More() is too forgiving for a trust boundary: it answers false for a
	// stray '}' or ']' after the document, so close-bracket garbage would ride
	// along unseen. mirror the broker (services/mal-broker/validate.go): after the
	// one proposal there must be nothing but whitespace until EOF. a second decode
	// reports pure whitespace as io.EOF; any other byte is trailing data.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Proposal{}, fmt.Errorf("aiplane: trailing data after proposal")
	}
	if len(p.Hypotheses) > maxHypotheses {
		return Proposal{}, fmt.Errorf("aiplane: too many hypotheses (%d)", len(p.Hypotheses))
	}
	if len(p.IOCs) > maxIOCs {
		return Proposal{}, fmt.Errorf("aiplane: too many iocs (%d)", len(p.IOCs))
	}

	out := Proposal{
		Summary:      clean(p.Summary, maxSummaryLen),
		NeedsReview:  p.NeedsReview,
		ReviewReason: clean(p.ReviewReason, maxSummaryLen),
	}
	for _, h := range p.Hypotheses {
		if len(h.Citations) > maxCitations {
			return Proposal{}, fmt.Errorf("aiplane: too many citations (%d)", len(h.Citations))
		}
		ch := Hypothesis{
			Kind:       clean(h.Kind, maxFieldLen),
			Claim:      clean(h.Claim, maxClaimLen),
			Confidence: normConfidence(h.Confidence),
		}
		if ch.Kind == "" || ch.Claim == "" {
			return Proposal{}, fmt.Errorf("aiplane: hypothesis missing kind or claim")
		}
		for _, c := range h.Citations {
			// a citation is a content-bound lookup handle the gate re-verifies
			// against L0, so it must be passed BYTE-FOR-BYTE, never defanged:
			// defanging a key (e.g. the "://" in a C2 url) would change the fact id
			// it resolves to and silently break grounding for a genuinely curated
			// fact. we only bound and reject it - a hostile citation fails closed.
			fid, ok1 := citationToken(c.FactID, maxFieldLen)
			kind, ok2 := citationToken(c.Kind, maxFieldLen)
			key, ok3 := citationToken(c.Key, maxFieldLen)
			if !ok1 || !ok2 || !ok3 {
				return Proposal{}, fmt.Errorf("aiplane: malformed citation")
			}
			ch.Citations = append(ch.Citations, Citation{FactID: fid, Kind: kind, Key: key})
		}
		out.Hypotheses = append(out.Hypotheses, ch)
	}
	for _, i := range p.IOCs {
		t, v := clean(i.Type, maxFieldLen), clean(i.Value, maxFieldLen)
		if t == "" || v == "" {
			return Proposal{}, fmt.Errorf("aiplane: malformed ioc")
		}
		out.IOCs = append(out.IOCs, ProposedIOC{Type: t, Value: v})
	}
	// a proposal must contain SOMETHING after cleaning: a wholly-empty object, a
	// null, or a summary that defangs away to nothing is not a valid "nothing to
	// report" - it fails closed. checked on the CLEANED output (not the raw decode)
	// so a control/format-only summary cannot slip past and be logged as a usable
	// analysis in the audit ledger.
	if out.Summary == "" && len(out.Hypotheses) == 0 && len(out.IOCs) == 0 && !out.NeedsReview {
		return Proposal{}, fmt.Errorf("aiplane: empty proposal")
	}
	return out, nil
}

// normConfidence upper-cases the model's confidence token and floors anything
// unrecognized to LOW.
func normConfidence(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	if validConfidence[c] {
		return c
	}
	return "LOW"
}

// clean defangs a string and truncates it to at most maxBytes on a UTF-8 rune
// boundary, so a hostile or runaway field cannot carry control bytes or blow a
// downstream cap.
func clean(s string, maxBytes int) string {
	s = defang(s)
	if len(s) <= maxBytes {
		return s
	}
	b := s[:maxBytes]
	for len(b) > 0 && !utf8.ValidString(b) {
		b = b[:len(b)-1]
	}
	return b
}

// citationToken bounds a citation field WITHOUT defanging it. a citation is a
// content-bound handle the gate re-verifies against L0 byte-for-byte, so it must
// not be mutated: it is rejected (not cleaned) if empty, over-long, not valid
// UTF-8, or carrying a control byte (a real curated key never has one). scheme
// tokens ("://") and format chars are preserved, because a legitimately curated
// key may contain them (canonically, a C2 url).
func citationToken(s string, maxBytes int) (string, bool) {
	if s == "" || len(s) > maxBytes || !utf8.ValidString(s) || hasControlChars(s) {
		return "", false
	}
	return s, true
}

// CitationWellFormed reports whether a citation would survive Validate's per-field
// citation check (all of FactID/Kind/Key non-empty, bounded, valid UTF-8, no
// control bytes). Validate rejects the WHOLE proposal on a single malformed
// citation (fail-closed), so a caller assembling a proposal from untrusted agent
// output should drop citations that fail this FIRST - otherwise one junk citation
// the model emitted would discard every good hypothesis alongside it.
func CitationWellFormed(c Citation) bool {
	if _, ok := citationToken(c.FactID, maxFieldLen); !ok {
		return false
	}
	if _, ok := citationToken(c.Kind, maxFieldLen); !ok {
		return false
	}
	_, ok := citationToken(c.Key, maxFieldLen)
	return ok
}

// hasControlChars reports whether s carries a C0/C1 control or DEL - exactly the
// bytes the L0 registry refuses in a key, so a citation carrying one could never
// match a stored fact regardless.
func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// dangerScheme matches the dangerous scheme-only forms (no authority) that carry
// no "://"; \b avoids mangling words like "metadata:". case-insensitive.
var dangerScheme = regexp.MustCompile(`(?i)\b(javascript|data|vbscript|file):`)

// protoRelURL matches a protocol-relative URL start ("//host") - which carries no
// "://" and so escapes the scheme defang, yet still renders as a live link that
// adopts the viewer's scheme. it matches "//" at a boundary (start, or a non-word,
// non-colon char, so an already-bracketed "[://]" and a mid-path "x//y" are left
// alone) followed by a host character. neutralized to "[//]".
var protoRelURL = regexp.MustCompile(`(^|[^\w:])//(\w)`)

// defang makes a hostile-derived string inert for any consumer that renders or
// logs it: it drops C0/C1 controls, DEL, Unicode format chars (bidi overrides,
// zero-widths, BOM), line/paragraph separators, and variation selectors (the
// carrier for emoji/tag ASCII-smuggling of hidden data) - all of which can inject
// formatting, spoof rendered text (Trojan-source), hide payloads, or corrupt logs
// - and
// neutralizes live URL schemes generically and case-agnostically (any
// scheme://authority, plus javascript:/data:/vbscript:/file:). it is a DLP /
// inertness control, NOT the injection defense - that is the structured contract
// plus the fact that the model's output is validated and gated, never trusted.
func defang(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Variation_Selector, r) ||
			unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
			unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
			// also drop default-ignorable code points (invisible Hangul/other fillers
			// used to spoof filenames) and combining marks (Mn/Me - the zalgo and
			// enclosing-mark carriers that corrupt rendered text). the citation path
			// stays byte-for-byte; this is only for rendered prose.
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	out = strings.ReplaceAll(out, "://", "[://]") // neutralizes every scheme://host, any case
	out = dangerScheme.ReplaceAllString(out, "$1[:]")
	out = protoRelURL.ReplaceAllString(out, "${1}[//]${2}") // protocol-relative //host
	return out
}
