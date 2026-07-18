package aiplane

// the confidence gate is the deterministic checkpoint between the UNTRUSTED AI
// analyst and the trusted pipeline. it is INVERTED and DOWNGRADE-ONLY: it does
// not look for reasons to believe the model, it looks for reasons to STOP it.
// a hypothesis is accepted as autonomous, trusted enrichment ONLY when it is
// grounded in a spine-verified CURATED fact AND its kind is on a static autonomy
// allow-list; everything else escalates to a human or is dropped as noise.
//
// three of the design's edge-checks are enforced structurally here:
//
//   - nouns, not verbs: acceptance requires a verified curated CITATION (a fact),
//     never a confident CLAIM. the model's self-reported confidence can only
//     escalate an ungrounded hypothesis to a human; it can NEVER promote one to
//     accepted. high confidence is not evidence.
//   - AI never disposes: a GateResult carries NO verdict. the deterministic
//     fail-closed lattice owns the verdict; the gate only dispositions the AI's
//     proposed enrichment. EnrichmentVerdict caps an accepted hypothesis's
//     influence at SUSPICIOUS - the AI can never drive a verdict to MALICIOUS
//     on its own, and can never LOWER one.
//   - FP-inflation guard: because acceptance needs a curated citation, the AI
//     cannot inflate a benign file to SUSPICIOUS on an unsupported hunch; it can
//     only raise severity when it points at spine-verified truth, and only by
//     one bounded step.

import (
	"fmt"
	"strings"

	"github.com/COLONAYUSH/OpenMalLab/internal/knowledge"
	"github.com/COLONAYUSH/OpenMalLab/internal/pipeline"
)

// gate thresholds for the non-grounding axes. deliberately conservative: they can
// only ADD a reason to stop, never create acceptance.
const (
	noveltyEscalateThreshold = 0.85 // novelty >= this escalates (likely a new thing)
	selfConsistencyFloor     = 0.5  // measured agreement below this is untrustworthy
)

// GateSignals are the non-grounding axes from the design (sec 06), computed by the
// TRUSTED roster infrastructure - never by the model. the zero value means "not
// measured" for every field, so a caller that supplies no signals gets exactly
// the grounding+allow-list behavior. every signal can only BLOCK autonomy (add a
// stop reason); none can promote - the gate stays inverted and downgrade-only.
type GateSignals struct {
	Refuted              bool    // the adversarial verifier refuted this hypothesis
	SelfConsistency      float64 // 0..1 agreement across N samples; 0 = not measured
	Novelty              float64 // 0..1 unlikeness to the graph; 0 = not measured; high => escalate
	RetrievalTier        string  // strongest tier that grounded it ("L0"|"L0.5"|"L1"|"L2"|"")
	CalibratedConfidence string  // confidence adjusted by historical accuracy; overrides self-report
}

// CitationVerifier resolves an agent's cited fact against the trusted L0
// registry. *knowledge.Registry satisfies it; the gate depends on the interface
// so it stays testable and cannot reach into registry internals.
type CitationVerifier interface {
	VerifyCitation(citedID string, kind knowledge.Kind, key string) knowledge.Citation
}

// Disposition is what the gate decided for one hypothesis.
type Disposition int

const (
	// DispDrop: ungrounded and unremarkable - an unsupported model assertion,
	// not surfaced as authority (fail-closed).
	DispDrop Disposition = iota
	// DispEscalate: has merit but cannot be autonomous - grounded yet high-stakes,
	// or ungrounded yet confident enough to be a possible novel true positive. a
	// human triages it (HITL).
	DispEscalate
	// DispAccept: grounded in a verified curated fact AND on the autonomy
	// allow-list - trusted enrichment, capped influence.
	DispAccept
)

func (d Disposition) String() string {
	switch d {
	case DispAccept:
		return "accept"
	case DispEscalate:
		return "escalate"
	default:
		return "drop"
	}
}

// EnrichmentVerdict is the MOST an accepted AI hypothesis may contribute to the
// verdict lattice: SUSPICIOUS, never MALICIOUS. anything not accepted contributes
// nothing (UNKNOWN is the lattice identity). the AI raises, capped; it never
// disposes and never lowers.
func EnrichmentVerdict(d Disposition) pipeline.Verdict {
	if d == DispAccept {
		return pipeline.Suspicious
	}
	return pipeline.Unknown
}

// GatedHypothesis is a hypothesis with the gate's decision and an audit trail.
type GatedHypothesis struct {
	Hypothesis
	Disposition         Disposition
	VerifiedCitations   int      // count of citations that verified AND are curated (OKForVerdict)
	VerifiedCitationIDs []string // the fact IDs that verified, for the audit ledger's provenance
	Reasons             []string // why this disposition, for the audit ledger
}

// GateResult is the gate's decision over a whole proposal. it deliberately has
// NO verdict field: the AI plane cannot dispose. AcceptedIOCs and every
// hypothesis are enrichment/leads for the trusted pipeline to fold in under the
// lattice, or escalations for a human - never a ruling.
type GateResult struct {
	SubmissionID string            // from the trusted evidence, NOT the model
	Hypotheses   []GatedHypothesis // one per proposed hypothesis, in order
	Leads        []ProposedIOC     // proposed IOCs: unverified leads, never authority
	Summary      string            // the model's defanged summary, carried for display
	NeedsHuman   bool              // any escalation, or the model asked for review
	Reasons      []string          // submission-level reasons (e.g. why NeedsHuman)
}

// Gate applies the deterministic policy. it is safe for concurrent use: it holds
// only immutable config and calls the verifier, which is itself concurrency-safe.
type Gate struct {
	verifier   CitationVerifier
	autonomous map[string]bool // hypothesis kinds that MAY be accepted autonomously
}

// defaultAutonomousKinds is the static allow-list of LOW-stakes, high-reliability
// enrichment kinds the gate may accept without a human - and ONLY these. the
// high-stakes classes (family/attribution/campaign/actor/verdict/severity) are
// deliberately absent, so they always escalate no matter how the model labels or
// how confident it claims to be. combined with the mandatory curated citation,
// this bounds autonomy tightly: a model that mislabels a claim "capability" to
// win autonomy still gains nothing unless it also points at a spine-verified
// curated fact, and even then its influence is capped at SUSPICIOUS enrichment.
var defaultAutonomousKinds = map[string]bool{
	"capability":  true, // a capability already surfaced deterministically (capa/MBC)
	"behavior":    true, // an observed behavior, cited to a curated fact
	"technique":   true, // an ATT&CK technique mapping, cited + curated
	"ioc-context": true, // added context for an IOC already surfaced by the pipeline
}

// NewGate builds a gate over a citation verifier with the default autonomy
// allow-list. a nil verifier is permitted and fails closed: with nothing able to
// verify, no citation is ever curated-verified, so nothing is ever accepted.
func NewGate(v CitationVerifier) *Gate {
	return &Gate{verifier: v, autonomous: defaultAutonomousKinds}
}

// NewGateWithPolicy builds a gate with a custom autonomy allow-list (e.g. to
// tighten it further per deployment, or widen it as a kind graduates from
// supervised to autonomous). the map is used read-only.
func NewGateWithPolicy(v CitationVerifier, autonomousKinds map[string]bool) *Gate {
	if autonomousKinds == nil {
		autonomousKinds = defaultAutonomousKinds
	}
	return &Gate{verifier: v, autonomous: autonomousKinds}
}

// Evaluate applies the inverted, downgrade-only policy to a VALIDATED proposal
// against trusted evidence. it must be given a Proposal that already passed
// Validate; it re-derives nothing from raw bytes. the submission id is taken
// from the trusted evidence, never from the model, closing the confused-deputy
// gap by construction.
func (g *Gate) Evaluate(ev Evidence, p Proposal) GateResult {
	return g.EvaluateWithSignals(ev, p, nil)
}

// EvaluateWithSignals is Evaluate with the non-grounding axes (sec 06) supplied
// per hypothesis by the trusted roster: verifier refutation, self-consistency,
// novelty, and calibrated confidence. signals[i] pairs with p.Hypotheses[i];
// a short or nil slice means "no signals" for the rest. every signal is inverted
// and downgrade-only - it can push an otherwise-autonomous hypothesis to a human,
// but can never turn a non-autonomous one into an accept.
func (g *Gate) EvaluateWithSignals(ev Evidence, p Proposal, signals []GateSignals) GateResult {
	res := GateResult{
		SubmissionID: ev.SubmissionID, // trusted source of truth
		Summary:      p.Summary,       // already defanged by Validate
		Leads:        append([]ProposedIOC(nil), p.IOCs...),
	}

	for i, h := range p.Hypotheses {
		gh := GatedHypothesis{Hypothesis: h}
		gh.VerifiedCitationIDs = g.verifiedCurated(h)
		gh.VerifiedCitations = len(gh.VerifiedCitationIDs)
		grounded := gh.VerifiedCitations > 0
		allowed := g.autonomous[h.Kind]

		var sig GateSignals
		if i < len(signals) {
			sig = signals[i]
		}
		// effective confidence: a calibrated value (from historical accuracy)
		// OVERRIDES the model's self-report, and can only ever lower the outcome.
		conf := h.Confidence
		if sig.CalibratedConfidence != "" {
			conf = sig.CalibratedConfidence
		}
		confident := conf == "HIGH" || conf == "MEDIUM"

		// inverted: collect reasons to STOP autonomy. any one blocks acceptance;
		// none can ever create it.
		var stops []string
		if sig.Refuted {
			stops = append(stops, "verifier refuted")
		}
		if sig.Novelty >= noveltyEscalateThreshold {
			stops = append(stops, fmt.Sprintf("novelty %.2f", sig.Novelty))
		}
		if sig.SelfConsistency > 0 && sig.SelfConsistency < selfConsistencyFloor {
			stops = append(stops, fmt.Sprintf("self-consistency %.2f", sig.SelfConsistency))
		}
		if sig.CalibratedConfidence == "LOW" {
			stops = append(stops, "calibrated LOW")
		}

		switch {
		case grounded && allowed && len(stops) == 0:
			gh.Disposition = DispAccept
			gh.Reasons = append(gh.Reasons, fmt.Sprintf(
				"grounded in %d verified curated citation(s); kind %q autonomous; no stop signals",
				gh.VerifiedCitations, h.Kind))
		case sig.Refuted && !grounded:
			gh.Disposition = DispDrop
			gh.Reasons = append(gh.Reasons, "refuted and ungrounded: dropped as unsupported")
		case grounded:
			gh.Disposition = DispEscalate
			r := fmt.Sprintf("grounded (%d curated citation(s)) but not autonomous", gh.VerifiedCitations)
			if !allowed {
				r += fmt.Sprintf("; kind %q is high-stakes", h.Kind)
			}
			if len(stops) > 0 {
				r += "; stop signals: " + strings.Join(stops, ", ")
			}
			gh.Reasons = append(gh.Reasons, r+": human review")
		case confident || sig.Novelty >= noveltyEscalateThreshold:
			gh.Disposition = DispEscalate
			gh.Reasons = append(gh.Reasons,
				"ungrounded but model-confident or novel: possible novel finding, human review")
		default:
			gh.Disposition = DispDrop
			gh.Reasons = append(gh.Reasons,
				"ungrounded and low-confidence: dropped as unsupported")
		}
		res.Hypotheses = append(res.Hypotheses, gh)
	}

	// escalate to a human on ANY escalation, or if the model itself asked. this
	// is a one-way raise: the model can request review, but can never wave it off.
	for _, gh := range res.Hypotheses {
		if gh.Disposition == DispEscalate {
			res.NeedsHuman = true
			break
		}
	}
	if p.NeedsReview {
		res.NeedsHuman = true
		reason := "model requested review"
		if p.ReviewReason != "" {
			reason += ": " + p.ReviewReason
		}
		res.Reasons = append(res.Reasons, reason)
	}
	if res.NeedsHuman && len(res.Reasons) == 0 {
		res.Reasons = append(res.Reasons, "one or more hypotheses require human review")
	}
	return res
}

// verifiedCurated returns the fact IDs of the hypothesis's citations that resolve
// EXACTLY in L0 AND are curated (OKForVerdict). ingest-tier or mismatched
// citations contribute nothing: they are context, never grounding. the returned
// IDs are the ledger's retrieval provenance.
func (g *Gate) verifiedCurated(h Hypothesis) []string {
	if g.verifier == nil {
		return nil // fail closed: nothing can verify, so nothing is grounded
	}
	var ids []string
	for _, c := range h.Citations {
		if g.verifier.VerifyCitation(c.FactID, knowledge.Kind(c.Kind), c.Key).OKForVerdict() {
			ids = append(ids, c.FactID)
		}
	}
	return ids
}
