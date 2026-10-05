package l0

import "math"

// CUSUM is the W1/W5 change-point detector core (architecture §6.2):
//
//	S = max(0, S + (x - mu0) - delta); alarm when S >= h.
//
// mu0 is the calibrated baseline mean; delta the minimal detectable shift;
// h the decision bound. All three come from TrustOps calibration, never by
// hand (N3).
type CUSUM struct {
	mu0, delta, h, S float64
	sigma            float64 // per-sample noise scale (std dev); <=0 means unit
}

func NewCUSUM(mu0, delta, h float64) *CUSUM { return &CUSUM{mu0: mu0, delta: delta, h: h} }

// SetSigma sets the per-sample noise scale σ used by PValue. Calibration
// should provide it; unset keeps the unit-variance assumption.
func (c *CUSUM) SetSigma(s float64) {
	if s > 0 {
		c.sigma = s
	}
}

// Observe feeds one sample; returns true when the alarm bound is crossed.
func (c *CUSUM) Observe(x float64) bool {
	c.S = math.Max(0, c.S+(x-c.mu0)-c.delta)
	return c.S >= c.h
}

// Alarmed reports whether the accumulated drift has crossed the bound.
func (c *CUSUM) Alarmed() bool { return c.S >= c.h }

// PValue is the probability, under the no-change null (drift 0), that the
// CUSUM statistic reaches its current value S. Wald's Brownian-motion
// boundary-crossing approximation: P ≈ exp(-2·delta·S / σ²). It is 1.0
// when there is no drift (S<=0), and monotonically falls toward 0 as the
// evidence against the baseline grows. This replaces the old hardcoded
// 0.01 placeholder: the number now moves with S and the noise scale.
func (c *CUSUM) PValue() float64 {
	if c.S <= 0 || c.delta <= 0 {
		return 1.0
	}
	sigma := c.sigma
	if sigma <= 0 {
		sigma = 1.0
	}
	p := math.Exp(-2 * c.delta * c.S / (sigma * sigma))
	if p < 0 {
		return 0
	}
	if p > 1 {
		return 1
	}
	return p
}
