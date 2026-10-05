package l4

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestUpdateRuleBounded(t *testing.T) {
	u := DefaultUpdateRule()
	v := u.Update(0.5, 1.0)
	if v <= 0.5 || v > 1 {
		t.Fatalf("update moved out of range: %v", v)
	}
	if u.Update(1.0, 1.0) != 1.0 {
		t.Fatal("update exceeded upper bound")
	}
	if u.Update(0, 0) != 0 {
		t.Fatal("update went below lower bound")
	}
}

func TestLedgerRejectsUnverified(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	l := NewLedger(DefaultUpdateRule())
	e := Entry{Actor: "a", Kind: "rotation", Delta: 0.5, Ref: "ref-1", Epoch: 1}
	e.Sign(priv)
	if err := l.Append(e, otherPub); err == nil {
		t.Fatal("ledger accepted an entry under the wrong key")
	}
	if err := l.Append(e, pub); err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
}

func TestLedgerNoDoubleSpend(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := NewLedger(DefaultUpdateRule())
	e := Entry{Actor: "a", Kind: "rotation", Delta: 0.5, Ref: "ref-1", Epoch: 1}
	e.Sign(priv)
	if err := l.Append(e, pub); err != nil {
		t.Fatal(err)
	}
	// Same observation ref must not move reputation twice.
	e2 := Entry{Actor: "a", Kind: "rotation", Delta: 0.5, Ref: "ref-1", Epoch: 1}
	e2.Sign(priv)
	if err := l.Append(e2, pub); err == nil {
		t.Fatal("double-spend of the same observation accepted")
	}
}

func TestProperScoringTruthful(t *testing.T) {
	for _, p := range []float64{0.1, 0.3, 0.5, 0.7, 0.9} {
		if !TruthfulIsOptimal(p) {
			t.Fatalf("truthful report not optimal at p=%v", p)
		}
	}
}

func TestWeightCapEnforced(t *testing.T) {
	rep := map[string]float64{"a": 9, "b": 0.5, "c": 0.5}
	w := WeightFromReputation(rep, 0.0)
	for org, v := range w {
		if v > 1.0/3.0 {
			t.Fatalf("%s exceeded cap: %v", org, v)
		}
	}
}

func TestRecoveryMechanism(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	c := &RecoveryCommitment{Org: "a", Kappa: 3, Epoch: 1, G: 1.0}
	if err := c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if !c.Verify(pub) {
		t.Fatal("valid commitment rejected")
	}
	if RecoveryPayoff(1.0, 2, 0) != 2.0 {
		t.Fatal("payoff for 2 completions wrong")
	}
	if RecoveryPayoff(1.0, 0, 1) != -2.0 {
		t.Fatal("penalty for a miss wrong")
	}
	if !DefectingIsUnprofitable(1.0, 0.5) {
		t.Fatal("g above cost should make defecting unprofitable")
	}
}

func TestSimulationHonestyDominates(t *testing.T) {
	agents := []Agent{
		{Name: "h1", Type: TypeHonest},
		{Name: "h2", Type: TypeHonest},
		{Name: "l1", Type: TypeLazy},
		{Name: "m1", Type: TypeMalicious},
		{Name: "s1", Type: TypeSybil},
	}
	final := Simulate(DefaultUpdateRule(), agents, 50)
	if !HonestyDominates(final, agents) {
		t.Fatalf("honesty did not dominate: %+v", final)
	}
}

func TestEnrollmentBarrier(t *testing.T) {
	if !EnrollmentRejectsSybil(2, 10) {
		t.Fatal("shallow history should be rejected")
	}
	if EnrollmentRejectsSybil(10, 10) {
		t.Fatal("sufficient history should clear the barrier")
	}
	if SybilCost(0.3, 100) != 30 {
		t.Fatal("sybil cost bound wrong")
	}
}