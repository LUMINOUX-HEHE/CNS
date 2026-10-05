package l1

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// --- weighted quorum math (Lemmas 1-2) ---

func TestQuorumIntersection(t *testing.T) {
	w := &WeightVector{Epoch: 1, Weights: map[string]float64{"a": 0.4, "b": 0.3, "c": 0.2, "d": 0.1}}
	s1 := []Vote{{Org: "a", Digest: "x"}, {Org: "b", Digest: "x"}} // 0.7 > 2/3
	s2 := []Vote{{Org: "a", Digest: "x"}, {Org: "c", Digest: "x"}} // 0.6, not a quorum
	if got := QuorumWeight(s1, "x", w); got <= 2.0/3.0 {
		t.Fatalf("expected quorum, got %v", got)
	}
	if got := QuorumWeight(s2, "x", w); got > 2.0/3.0 {
		t.Fatalf("expected non-quorum, got %v", got)
	}
}

func TestWeightCap(t *testing.T) {
	w := &WeightVector{Epoch: 1, Weights: map[string]float64{"a": 0.4, "b": 0.3, "c": 0.3}}
	if err := w.VerifyCap(0.0); err == nil {
		t.Fatal("0.4 should violate the 1/3 cap")
	}
	ok := &WeightVector{Epoch: 1, Weights: map[string]float64{"a": 0.25, "b": 0.25, "c": 0.25, "d": 0.25}}
	if err := ok.VerifyCap(0.0); err != nil {
		t.Fatalf("legal vector rejected: %v", err)
	}
}

// --- end-to-end agreement (T1) ---

func TestClusterAgreementUniform(t *testing.T) {
	w := UniformWeights([]string{"a", "b", "c", "d"})
	c, err := NewCluster(w)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.RunRounds(5, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, org := range []string{"a", "b", "c", "d"} {
		if len(got[org]) != 5 {
			t.Fatalf("%s applied %d decisions, want 5", org, len(got[org]))
		}
	}
}

func TestClusterAgreementWithSkewedWeights(t *testing.T) {
	w := &WeightVector{Epoch: 1, Weights: map[string]float64{"a": 0.3, "b": 0.3, "c": 0.2, "d": 0.2}}
	c, err := NewCluster(w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunRounds(3, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// A Byzantine minority by weight cannot break agreement among honest
// nodes (Lemma 2): with one org silent, the remaining > 2/3 still commit.
func TestClusterSurvivesMinoritySilence(t *testing.T) {
	w := UniformWeights([]string{"a", "b", "c", "d"}) // each 0.25
	c, err := NewCluster(w)
	if err != nil {
		t.Fatal(err)
	}
	byz := map[string]bool{"d": true} // 0.25 byzantine
	if _, err := c.RunRounds(3, byz); err != nil {
		t.Fatalf("minority silence broke liveness: %v", err)
	}
}

// If Byzantine weight exceeds 1/3, liveness may stall (03 Lemma 3): the
// honest set alone no longer reaches 2/3. We assert the round fails
// rather than silently violating safety.
func TestClusterHaltsWhenQuorumLost(t *testing.T) {
	w := UniformWeights([]string{"a", "b", "c", "d"})
	c, err := NewCluster(w)
	if err != nil {
		t.Fatal(err)
	}
	byz := map[string]bool{"c": true, "d": true} // 0.5 byzantine
	if _, err := c.RunRound(1, 0, "x", byz); err == nil {
		t.Fatal("expected a halt when > 1/3 weight is withheld")
	}
}

// --- certificate verification (T5) ---

func TestCertificateVerifies(t *testing.T) {
	w := UniformWeights([]string{"a", "b", "c", "d"})
	c, err := NewCluster(w)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := c.RunRound(1, 0, "r", nil)
	if err != nil {
		t.Fatal(err)
	}
	var a Applied
	for _, v := range applied {
		a = v
		break
	}
	if !VerifyCert(a.Cert, w, c.Keys) {
		t.Fatal("valid certificate rejected")
	}
	tampered := a.Cert
	tampered.Commits = tampered.Commits[:1] // drop below quorum
	if VerifyCert(tampered, w, c.Keys) {
		t.Fatal("under-quorum certificate accepted")
	}
}

func TestCertificateRejectsWrongWeightEpoch(t *testing.T) {
	w := UniformWeights([]string{"a", "b", "c", "d"})
	c, _ := NewCluster(w)
	applied, err := c.RunRound(1, 0, "r", nil)
	if err != nil {
		t.Fatal(err)
	}
	var a Applied
	for _, v := range applied {
		a = v
		break
	}
	other := &WeightVector{Epoch: 2, Weights: map[string]float64{"a": 0.5, "b": 0.5}}
	if VerifyCert(a.Cert, other, c.Keys) {
		t.Fatal("certificate accepted under a different weight vector")
	}
}

// --- federated recovery (03 §6) ---

func TestFederatedRecoveryAnchor(t *testing.T) {
	orgs := []string{"a", "b", "c", "d", "e"}
	seed := make([]byte, 32)
	rand.Read(seed)
	cer, err := NewRecoveryCeremony(seed, orgs, 3) // 3-of-5
	if err != nil {
		t.Fatal(err)
	}
	root := []byte("pre-compromise-root")
	anchor, err := cer.Anchor("a", 1750000000, root, []string{"b", "c", "d"})
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if !anchor.Verify(cer.RecKey) {
		t.Fatal("valid anchor rejected")
	}
	if !anchor.Accept(cer.RecKey, root) {
		t.Fatal("correct root not accepted")
	}
	if anchor.Accept(cer.RecKey, []byte("a-different-root")) {
		t.Fatal("false root accepted")
	}
}

func TestFederatedRecoveryRejectsBelowThreshold(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	cer, err := NewRecoveryCeremony(seed, []string{"a", "b", "c", "d", "e"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cer.Anchor("a", 1, []byte("r"), []string{"b"}); err == nil {
		t.Fatal("anchor with 1 of 3 shares should fail")
	}
}

func TestFederatedRecoveryRejectsForeignKey(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	cer, _ := NewRecoveryCeremony(seed, []string{"a", "b", "c"}, 2)
	anchor, err := cer.Anchor("a", 1, []byte("r"), []string{"b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if anchor.Verify(otherPub) {
		t.Fatal("anchor verified under an unrelated key")
	}
}