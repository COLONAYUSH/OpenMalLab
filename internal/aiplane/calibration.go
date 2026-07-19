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

// Calibrated returns a DOWNGRADED confidence ONLY when the category's track record
// at the claimed level is below its floor; otherwise it returns "" - meaning "no
// calibration override". this distinction is load-bearing: the gate treats a
// non-empty calibrated confidence of LOW as a stop signal, so echoing an already-
// LOW (or reliable) claim as its own value would wrongly block it. an honest LOW,
// or a claim the record supports, yields "" and does not stop the gate. it never
// upgrades; with too few observations it returns "" (no data, no override).
func (c *Calibration) Calibrated(category, claimed string) string {
	claimed = normConfidence(claimed)
	if claimed == "LOW" {
		return "" // nothing is below LOW; an honest LOW is never a calibration downgrade
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := calKey(category, claimed)
	total := c.total[k]
	if total < calMinObservations {
		return "" // no track record yet -> no override
	}
	acc := float64(c.correct[k]) / float64(total)
	switch claimed {
	case "HIGH":
		if acc < calMedFloor {
			return "LOW" // very unreliable HIGH -> two-step downgrade
		}
		if acc < calHighFloor {
			return "MEDIUM" // marginal HIGH -> one-step downgrade
		}
	case "MEDIUM":
		if acc < calMedFloor {
			return "LOW"
		}
	}
	return "" // reliable at the claimed level -> no override
}
