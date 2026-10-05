package l3

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"math"
	"testing"

	"trustorchestrator/research/l0"
)

func TestSecureAggregationCancelsMasks(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	peers := []string{"a", "b", "c", "d"}
	inputs := map[string]Signals{
		"a": {ImportCount: 3, RejectCount: 1, KeyRotations: 2},
		"b": {ImportCount: 5, RejectCount: 0, KeyRotations: 1},
		"c": {ImportCount: 0, RejectCount: 4, KeyRotations: 0},
		"d": {ImportCount: 2, RejectCount: 2, KeyRotations: 3},
	}
	var shares []MaskedShare
	for _, p := range peers {
		shares = append(shares, ProduceShare(p, inputs[p], peers, seed))
	}
	names, sum, err := Aggregate(shares)
	if err != nil {
		t.Fatal(err)
	}
	// The recovered sum must equal the true sum for every coordinate.
	want := map[string]float64{}
	for _, s := range inputs {
		want["import_count"] += s.ImportCount
		want["reject_count"] += s.RejectCount
		want["key_rotations"] += s.KeyRotations
	}
	for i, n := range names {
		if w, ok := want[n]; ok {
			if math.Abs(sum[i]-w) > 1e-9 {
				t.Fatalf("coord %s: got %v want %v", n, sum[i], w)
			}
		}
	}
}

func TestMaskedShareHidesIndividual(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	peers := []string{"a", "b"}
	sh := ProduceShare("a", Signals{ImportCount: 7}, peers, seed)
	// The masked vector must not equal the raw value on the coordinate.
	for i, n := range sh.Names {
		if n == "import_count" && math.Abs(sh.Vec[i]-7) < 1e-12 {
			t.Fatal("masked share leaked the raw value")
		}
	}
}

func TestBudgetLedger(t *testing.T) {
	b := NewLedger(1.0)
	if !b.Charge("a", 0.4, 0) || !b.Charge("a", 0.5, 0) {
		t.Fatal("under-budget charges rejected")
	}
	if b.Charge("a", 0.2, 0) {
		t.Fatal("over-budget charge accepted")
	}
	eps, _ := b.Spent("a")
	if math.Abs(eps-0.9) > 1e-9 {
		t.Fatalf("spent %v want 0.9", eps)
	}
}

func TestDPReleaseSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	names := []string{"import_count", "reject_count"}
	sum := []float64{10, 4}
	rel := Release(1, names, sum, 4, 1.0, 0.5, 1e-5, 42)
	if err := rel.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if !rel.Verify(pub) {
		t.Fatal("valid release signature rejected")
	}
	// Noise must actually perturb the mean (probabilistically; scale is
	// large enough at eps=0.5 that equality with the exact mean is
	// effectively impossible).
	if rel.Values[0] == sum[0]/4 {
		t.Fatal("release appears un-noised")
	}
}

func TestSweepEpsilonDetectsLargeShiftLowNoise(t *testing.T) {
	// With plenty of privacy budget the step should be detected; this
	// asserts the pipeline runs and the high-ε end detects.
	res := SweepEpsilon([]float64{5.0}, 0, 10, 40, 7)
	if len(res) != 1 || !res[0].Alarmed {
		t.Fatalf("expected detection at eps=5, got %+v", res)
	}
}

func TestCorrelation(t *testing.T) {
	reg := l0.NewRegistry()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fp := "deadbeef"
	payload, _ := json.Marshal(l0.Fingerprint{FP: fp, Orgs: []string{"a", "b", "c"}, FirstSeen: 100, LastSeen: 200, AlarmCount: 3})
	o := l0.NewObservation("FINGERPRINT", "a", 200, 1, "fp/"+fp, payload)
	o.Sign(priv)
	if err := reg.Register(o, pub); err != nil {
		t.Fatal(err)
	}
	got := Correlation(reg, 3, 250, 100)
	if len(got) != 1 || got[0].FP != fp {
		t.Fatalf("correlation missed the outbreak: %+v", got)
	}
	if len(Correlation(reg, 4, 250, 100)) != 0 {
		t.Fatal("correlation over-counted orgs")
	}
	if len(Correlation(reg, 3, 1000, 100)) != 0 {
		t.Fatal("correlation ignored the time window")
	}
}

func TestRiskFeedGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &RiskFeed{Org: "a", RiskVector: []float64{0.9}, Actions: []string{"rotate"}, Confidence: 0.87}
	if err := f.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if !f.Verify(pub) {
		t.Fatal("valid feed rejected")
	}
	o, err := f.ToObservation(1, 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	// L0 gate with policy allowing rotation accepts.
	allow := ProactiveGate{AllowRotation: true}
	act, err := allow.Apply(o, pub)
	if err != nil || !act {
		t.Fatalf("gate did not apply allowed feed: act=%v err=%v", act, err)
	}
	// L0 gate with policy forbidding rotation declines.
	deny := ProactiveGate{AllowRotation: false}
	act, err = deny.Apply(o, pub)
	if err != nil || act {
		t.Fatalf("gate applied feed against local policy: act=%v err=%v", act, err)
	}
}