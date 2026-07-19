package aiplane

// autonomy graduation (design sec 14): a category EARNS autonomy over time, it is
// never trusted by default. each category moves through three modes based on its
// measured track record:
//
//   shadow      - proposals are logged only, never acted on (pure observation).
//   supervised  - proposals are surfaced to a human, never auto-accepted.
//   autonomous  - proposals may be gated-accepted (still subject to grounding,
//                 the allow-list, and every stop signal).
//
// promotion is deterministic and monotone in the evidence: a category needs a
// minimum number of observations to leave shadow, and more observations AT a
// required accuracy to reach autonomous. accuracy is measured from the outcomes
// the learning loop records (was the proposal right?), so a category that starts
// getting things wrong DEMOTES automatically - the same guard that stops the
// cross-time poisoning loop from laundering a wrong lesson into standing trust.

import (
	"fmt"
	"sync"
)

// Mode is a category's current autonomy level.
type Mode int

const (
	ModeShadow Mode = iota
	ModeSupervised
	ModeAutonomous
)

func (m Mode) String() string {
	switch m {
	case ModeAutonomous:
		return "autonomous"
	case ModeSupervised:
		return "supervised"
	default:
		return "shadow"
	}
}

const (
	defaultMinToSupervised = 5    // observations before shadow -> supervised
	defaultMinToAutonomous = 20   // observations before supervised -> autonomous
	defaultAccuracyFloor   = 0.90 // required accuracy to reach/stay autonomous
)

// Graduation tracks per-category autonomy. safe for concurrent use: the learning
// loop Records outcomes while the gate reads Mode.
type Graduation struct {
	mu              sync.Mutex
	correct         map[string]int
	total           map[string]int
	minToSupervised int
	minToAutonomous int
	accuracyFloor   float64
}

// NewGraduation returns a graduation policy with sensible defaults. every category
// starts in shadow (unknown categories included) and must earn its way up.
func NewGraduation() *Graduation {
	return &Graduation{
		correct:         map[string]int{},
		total:           map[string]int{},
		minToSupervised: defaultMinToSupervised,
		minToAutonomous: defaultMinToAutonomous,
		accuracyFloor:   defaultAccuracyFloor,
	}
}

// NewGraduationWithPolicy allows a deployment to tune the thresholds (e.g. tighter
// for higher-stakes installs). non-positive minimums fall back to the defaults.
func NewGraduationWithPolicy(minToSupervised, minToAutonomous int, accuracyFloor float64) *Graduation {
	g := NewGraduation()
	if minToSupervised > 0 {
		g.minToSupervised = minToSupervised
	}
	if minToAutonomous > 0 {
		g.minToAutonomous = minToAutonomous
	}
	if accuracyFloor > 0 {
		g.accuracyFloor = accuracyFloor
	}
	return g
}

// Record logs one resolved outcome for a category (was the proposal correct, per a
// human or a deterministic check). it re-derives the mode from the updated track
// record, so promotion and demotion are both just a function of the counts.
func (g *Graduation) Record(category string, correct bool) {
	if category == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.total[category]++
	if correct {
		g.correct[category]++
	}
}

// Mode returns the category's current autonomy mode, derived from its track
// record. a category with too few observations stays in shadow; enough
// observations promote it to supervised; enough observations AT the accuracy
// floor promote it to autonomous; a later accuracy drop demotes it.
func (g *Graduation) Mode(category string) Mode {
	g.mu.Lock()
	defer g.mu.Unlock()
	total := g.total[category]
	if total < g.minToSupervised {
		return ModeShadow
	}
	acc := float64(g.correct[category]) / float64(total)
	if total >= g.minToAutonomous && acc >= g.accuracyFloor {
		return ModeAutonomous
	}
	return ModeSupervised
}

// Snapshot returns the current mode of every observed category, for the audit
// trail and the console.
func (g *Graduation) Snapshot() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]string, len(g.total))
	for cat, total := range g.total {
		var m Mode
		switch {
		case total < g.minToSupervised:
			m = ModeShadow
		case total >= g.minToAutonomous && float64(g.correct[cat])/float64(total) >= g.accuracyFloor:
			m = ModeAutonomous
		default:
			m = ModeSupervised
		}
		out[cat] = fmt.Sprintf("%s (%d/%d)", m, g.correct[cat], total)
	}
	return out
}
