package aiplane

// autonomy graduation (design sec 14): a category EARNS autonomy over time, it is
// never trusted by default. it moves through three modes on its measured track
// record:
//
//   supervised  - the DEFAULT for a category still earning its record: proposals
//                 are surfaced to a human (escalated), never auto-accepted. this is
//                 also the bootstrap - the human decisions are the feedback that
//                 graduates the category.
//   autonomous  - earned once the category clears the accuracy bar over enough
//                 observations: proposals may be gated-accepted (still subject to
//                 grounding, the allow-list, and every stop signal).
//   shadow      - a DEMOTION for a category proven to be noise (accuracy below the
//                 shadow floor): proposals are dropped and logged only, so a
//                 chronically-wrong category stops bothering the analyst.
//
// (the design names shadow as the START state, presuming an offline eval loop to
// measure it; without that loop shadow would strand a category with no feedback,
// so we bootstrap from supervised - where the live HITL loop provides the feedback
// - and reserve shadow as the earned-downward state. this keeps graduation live
// and deadlock-free while preserving the earned-autonomy invariant.)
//
// promotion is deterministic in the evidence, and a category that starts getting
// things wrong DEMOTES automatically - the guard that stops the cross-time
// poisoning loop from laundering a wrong lesson into standing trust.

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
	defaultMinToAutonomous = 20   // observations before a category may reach autonomous
	defaultAccuracyFloor   = 0.90 // required accuracy to reach/stay autonomous
	defaultShadowFloor     = 0.30 // below this measured accuracy a category is demoted to shadow
)

// Graduation tracks per-category autonomy. safe for concurrent use: the learning
// loop Records outcomes while the gate reads Mode.
type Graduation struct {
	mu              sync.Mutex
	correct         map[string]int
	total           map[string]int
	minToAutonomous int
	accuracyFloor   float64
	shadowFloor     float64
}

// NewGraduation returns a graduation policy with sensible defaults. a fresh
// category starts supervised (escalates + earns) and must clear the bar to reach
// autonomous.
func NewGraduation() *Graduation {
	return &Graduation{
		correct:         map[string]int{},
		total:           map[string]int{},
		minToAutonomous: defaultMinToAutonomous,
		accuracyFloor:   defaultAccuracyFloor,
		shadowFloor:     defaultShadowFloor,
	}
}

// NewGraduationWithPolicy tunes the thresholds; non-positive values fall back to
// the defaults.
func NewGraduationWithPolicy(minToAutonomous int, accuracyFloor, shadowFloor float64) *Graduation {
	g := NewGraduation()
	if minToAutonomous > 0 {
		g.minToAutonomous = minToAutonomous
	}
	if accuracyFloor > 0 {
		g.accuracyFloor = accuracyFloor
	}
	if shadowFloor > 0 {
		g.shadowFloor = shadowFloor
	}
	return g
}

// Record logs one resolved outcome for a category (was the proposal correct, per a
// human or a deterministic check). mode is re-derived from the counts, so both
// promotion and demotion are just a function of the track record.
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

// Mode returns the category's current autonomy mode.
func (g *Graduation) Mode(category string) Mode {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.modeLocked(category)
}

func (g *Graduation) modeLocked(category string) Mode {
	total := g.total[category]
	if total < g.minToAutonomous {
		return ModeSupervised // still earning: escalate to a human (the bootstrap feedback)
	}
	acc := float64(g.correct[category]) / float64(total)
	switch {
	case acc >= g.accuracyFloor:
		return ModeAutonomous // earned
	case acc < g.shadowFloor:
		return ModeShadow // proven noise: drop + log only
	default:
		return ModeSupervised // mediocre: keep escalating
	}
}

// Snapshot returns each observed category's mode + record, for the audit trail.
func (g *Graduation) Snapshot() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]string, len(g.total))
	for cat := range g.total {
		out[cat] = fmt.Sprintf("%s (%d/%d)", g.modeLocked(cat), g.correct[cat], g.total[cat])
	}
	return out
}
