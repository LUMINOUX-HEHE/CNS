package l0

// detect_test.go — the CUSUM p-value must be a real function of the
// evidence (S, delta, sigma), not a constant. D1.

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"testing"
)

func TestCUSUMPValueIsCalibrated(t *testing.T) {
	c := NewCUSUM(0, 1, 5)
	if p := c.PValue(); p != 1.0 {
		t.Fatalf("no drift: want p=1, got %v", p)
	}
	c.Observe(3)
	p3 := c.PValue()
	if !(p3 > 0 && p3 < 1) {
		t.Fatalf("drift: want 0<p<1, got %v", p3)
	}
	c.Observe(3)
	p6 := c.PValue()
	if !(p6 < p3) {
		t.Fatalf("p must fall as S grows: p3=%v p6=%v", p3, p6)
	}
	// Larger sigma (more noise) means weaker evidence for the same S.
	c.SetSigma(4)
	if noisy := c.PValue(); !(noisy > p6) {
		t.Fatalf("sigma must raise p: sigma=4 %v vs sigma=1 %v", noisy, p6)
	}
	// Wald approximation: p = exp(-2*delta*S/sigma^2). After two observes
	// of 3 with mu0=0, delta=1: S = (3-1)+(3-1) = 4.
	want := math.Exp(-2 * 1 * 4.0 / (4 * 4))
	if math.Abs(c.PValue()-want) > 1e-12 {
		t.Fatalf("formula mismatch: got %v want %v", c.PValue(), want)
	}
}

func TestWatchdogScoreCarriesRealPValue(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	w := NewWatchdog("w1", WDIssuanceRate, 1, 1, 3, tl, nil)
	w.SetSigma(1)
	// Baseline cycle: no alarm, p stays 1.
	w.ObserveBatch(nil, 0)
	if s := w.Score(); s.Score != 100 || s.PValue != 1.0 {
		t.Fatalf("baseline: want score=100 p=1, got %+v", s)
	}
	// Push a burst of issues past the bound; p must be a small, non-0.01
	// number that moved with S.
	events := make([]TrustEvent, 0, 20)
	for i := 0; i < 20; i++ {
		pl := []byte(`{"identity":"acme","via":"root"}`)
		events = append(events, TrustEvent{Type: EvIssue, Payload: pl})
	}
	w.ObserveBatch(events, 0)
	s := w.Score()
	if s.Score != 0 {
		t.Fatalf("alarm: want score=0, got %+v", s)
	}
	if s.PValue <= 0 || s.PValue >= 0.01 {
		t.Fatalf("want a real small p in (0,0.01), got %v", s.PValue)
	}
}