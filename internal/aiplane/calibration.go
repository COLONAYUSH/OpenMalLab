package aiplane

// Calibration is the gate's fourth axis (design sec 06) and the calibration
// tracking of sec 11: it measures whether the model's SELF-reported confidence
// has held up per category, and downgrades a claim that history does not support.
//
// it is DOWNGRADE-ONLY, mirroring the gate's north star. if a category's HIGH
// claims have been wrong too often, a new HIGH claim there is recalibrated down to
// MEDIUM (or LOW); a claim is never raised. the outcomes are fed by the HITL loop
// (a human's confirm/reject is the ground truth), so a confidently-wrong category
// steadily loses the benefit of the doubt - the same anti-overconfidence pressure
// the whole plane is built around.

import "sync"

const (
	calMinObservations = 8    // require this many before calibration acts at all
	calHighFloor       = 0.85 // a HIGH claim's required historical accuracy to stand
	calMedFloor        = 0.60 // a MEDIUM claim's required historical accuracy to stand
)

// Calibration tracks per-(category, claimed-confidence) accuracy. safe for
// concurrent use: the HITL loop Records while the roster/gate reads Calibrated.
type Calibration struct {
	mu      sync.Mutex
	correct map[string]int
	total   map[string]int
}

// NewCalibration returns an empty tracker.
func NewCalibration() *Calibration {
	return &Calibration{correct: map[string]int{}, total: map[string]int{}}
}

func calKey(category, conf string) string { return category + "|" + conf }

// Record logs one resolved outcome: whether a claim of `conf` for `category` was
// correct (per the human/deterministic ground truth).
func (c *Calibration) Record(category, conf string, correct bool) {
	conf = normConfidence(conf)
	c.mu.Lock()
	defer c.mu.Unlock()
	k := calKey(category, conf)
	c.total[k]++
	if correct {
		c.correct[k]++
	}
}

// Calibrated returns the confidence to USE for a claim, downgraded when the
// category's track record at that level is below its floor. it never upgrades;
// with too few observations it returns the claim unchanged (the gate still
// requires grounding, so an un-calibrated claim is not thereby trusted).
func (c *Calibration) Calibrated(category, claimed string) string {
	claimed = normConfidence(claimed)
	if claimed == "LOW" {
		return "LOW"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := calKey(category, claimed)
	total := c.total[k]
	if total < calMinObservations {
		return claimed
	}
	acc := float64(c.correct[k]) / float64(total)
	switch claimed {
	case "HIGH":
		if acc < calHighFloor {
			if acc < calMedFloor {
				return "LOW"
			}
			return "MEDIUM"
		}
	case "MEDIUM":
		if acc < calMedFloor {
			return "LOW"
		}
	}
	return claimed
}
