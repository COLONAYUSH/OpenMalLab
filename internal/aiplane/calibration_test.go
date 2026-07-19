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
	if got := c.Calibrated("technique", "HIGH"); got != "HIGH" {
		t.Fatalf("a reliable HIGH must stand, got %s", got)
	}
}

func TestCalibrationNeverUpgrades(t *testing.T) {
	c := NewCalibration()
	// even a perfect MEDIUM track record must never become HIGH.
	for i := 0; i < 20; i++ {
		c.Record("technique", "MEDIUM", true)
	}
	if got := c.Calibrated("technique", "MEDIUM"); got != "MEDIUM" {
		t.Fatalf("calibration must never upgrade, got %s", got)
	}
	if got := c.Calibrated("technique", "LOW"); got != "LOW" {
		t.Fatalf("LOW stays LOW, got %s", got)
	}
}

func TestCalibrationInsufficientDataLeavesClaimAlone(t *testing.T) {
	c := NewCalibration()
	c.Record("family", "HIGH", false) // one bad observation is not enough to act
	if got := c.Calibrated("family", "HIGH"); got != "HIGH" {
		t.Fatalf("too few observations must leave the claim unchanged, got %s", got)
	}
}
