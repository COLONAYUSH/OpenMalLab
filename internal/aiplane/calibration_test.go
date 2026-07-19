package aiplane

import "testing"

func TestCalibrationDowngradesUnreliableHigh(t *testing.T) {
	c := NewCalibration()
	// a category that claims HIGH but is right only ~50% of the time.
	for i := 0; i < 20; i++ {
		c.Record("family", "HIGH", i%2 == 0)
	}
	if got := c.Calibrated("family", "HIGH"); got != "LOW" {
		t.Fatalf("a HIGH category right ~50%% should downgrade to LOW, got %s", got)
	}
}

func TestCalibrationDowngradesMarginalHighToMedium(t *testing.T) {
	c := NewCalibration()
	// right ~70%: below the HIGH floor (0.85) but above the MEDIUM floor (0.60).
	for i := 0; i < 20; i++ {
		c.Record("technique", "HIGH", i%10 >= 3) // 7/10 correct
	}
	if got := c.Calibrated("technique", "HIGH"); got != "MEDIUM" {
		t.Fatalf("a marginally-reliable HIGH should downgrade to MEDIUM, got %s", got)
	}
}

func TestCalibrationKeepsReliableHigh(t *testing.T) {
	c := NewCalibration()
	for i := 0; i < 20; i++ {
		c.Record("technique", "HIGH", i%20 != 0) // 19/20 = 0.95, above the floor
	}
	// reliable -> no downgrade -> "" (no override), NOT a blocking value.
	if got := c.Calibrated("technique", "HIGH"); got != "" {
		t.Fatalf("a reliable HIGH needs no override, got %q", got)
	}
}

func TestCalibrationNeverUpgrades(t *testing.T) {
	c := NewCalibration()
	// even a perfect MEDIUM track record must never become HIGH; it yields no
	// override ("") - calibration only ever downgrades.
	for i := 0; i < 20; i++ {
		c.Record("technique", "MEDIUM", true)
	}
	if got := c.Calibrated("technique", "MEDIUM"); got != "" {
		t.Fatalf("a reliable MEDIUM needs no override (never an upgrade), got %q", got)
	}
	// an honest LOW is never a calibration downgrade (and must not become a stop).
	if got := c.Calibrated("technique", "LOW"); got != "" {
		t.Fatalf("an honest LOW must yield no override, got %q", got)
	}
}

func TestCalibrationInsufficientDataLeavesClaimAlone(t *testing.T) {
	c := NewCalibration()
	c.Record("family", "HIGH", false) // one bad observation is not enough to act
	if got := c.Calibrated("family", "HIGH"); got != "" {
		t.Fatalf("too few observations must yield no override, got %q", got)
	}
}
