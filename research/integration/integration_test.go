// Package integration exercises the full TrustFabric loop end to end on
// real L0 artifacts: L0 timeline/CT log -> L2 private claim -> L3 pooled
// risk feed -> L4 reputation -> L1 quorum decision -> L1 federated
// recovery, with every message verified by the receiving layer. It is
// the executable form of the roadmap's definition-of-done item 2
// (../doc/08-research-roadmap.md §8).
package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"trustorchestrator/research/l1"
	"trustorchestrator/research/l2"
	"trustorchestrator/research/l3"
	"trustorchestrator/research/l4"
	"trustorchestrator/research/l0"
)

// TestFullLoop drives one incident through every layer.
func TestFullLoop(t *testing.T) {
	// --- L0: an org's timeline and CT log ---
	_, orgKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tl := l0.NewTimeline(orgKey)
	ctlog := l0.NewMerkleLog()
	events := [][]byte{[]byte("boot"), []byte("rotation"), []byte("alert:fork")}
	for _, ev := range events {
		if _, err := tl.Append("INFO", ev, 1750000000); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(ev)
		ctlog.Append(h[:])
	}
	if !tl.Verify() {
		t.Fatal("L0 timeline failed verification")
	}
	_, logPriv, _ := ed25519.GenerateKey(rand.Reader)
	logPub := logPriv.Public().(ed25519.PublicKey)
	sth := l0.SignSTH(logPriv, ctlog.Root(), ctlog.Size(), 1750000000)
	if !sth.Verify(logPub) {
		t.Fatal("L0 STH failed verification")
	}

	// --- L2: prove a fact about the log without revealing it ---
	claim, err := l2.ProveInclude("acme", ctlog, 2, ctlog.Size(), sth)
	if err != nil {
		t.Fatal(err)
	}
	if !l2.VerifyInclude(claim, logPub, sth) {
		t.Fatal("L2 private claim failed verification")
	}

	// --- Seam: register a fingerprint observed by three orgs ---
	reg := l0.NewRegistry()
	_, obsKey, _ := ed25519.GenerateKey(rand.Reader)
	obsPub := obsKey.Public().(ed25519.PublicKey)
	fp := l0.FingerprintOf([]byte("cert-hash"), "acme", 1750000000)
	payload, _ := json.Marshal(l0.Fingerprint{FP: fp, Orgs: []string{"acme", "globex", "initech"}, FirstSeen: 1750000000, LastSeen: 1750003600, AlarmCount: 3})
	obs := l0.NewObservation("FINGERPRINT", "acme", 1750003600, 1, "fp/"+fp, payload)
	obs.Sign(obsKey)
	if err := reg.Register(obs, obsPub); err != nil {
		t.Fatal(err)
	}

	// --- L3: correlate and emit a signed RISK_FEED ---
	found := l3.Correlation(reg, 3, 1750003700, 7200)
	if len(found) != 1 {
		t.Fatalf("L3 correlation found %d outbreaks, want 1", len(found))
	}
	_, l3Key, _ := ed25519.GenerateKey(rand.Reader)
	l3Pub := l3Key.Public().(ed25519.PublicKey)
	feed := &l3.RiskFeed{Org: "acme", RiskVector: []float64{0.9}, Actions: []string{"rotate"}, Confidence: 0.87, CertRefs: []string{obs.Hash()}}
	if err := feed.Sign(l3Key); err != nil {
		t.Fatal(err)
	}
	feedObs, err := feed.ToObservation(1750003700, 2, l3Key)
	if err != nil {
		t.Fatal(err)
	}
	// --- L0 gate: org-local policy decides whether to act ---
	if act, err := (l3.ProactiveGate{AllowRotation: true}).Apply(feedObs, l3Pub); err != nil || !act {
		t.Fatalf("L0 proactive gate failed to apply allowed feed: act=%v err=%v", act, err)
	}

	// --- L4: reputation moves on verified events and yields L1 weights ---
	ledger := l4.NewLedger(l4.DefaultUpdateRule())
	_, repKey, _ := ed25519.GenerateKey(rand.Reader)
	repPub := repKey.Public().(ed25519.PublicKey)
	entry := l4.Entry{Actor: "acme", Kind: "rotation_on_alarm", Delta: 1.0, Ref: obs.Hash(), Epoch: 1}
	entry.Sign(repKey)
	if err := ledger.Append(entry, repPub); err != nil {
		t.Fatal(err)
	}
	reps := map[string]float64{"acme": ledger.Reputation("acme"), "globex": 0.5, "initech": 0.5}
	weights := l4.WeightFromReputation(reps, 0.01)

	// --- L1: a weighted quorum decision under those weights ---
	wv := &l1.WeightVector{Epoch: 1, Weights: weights}
	cluster, err := l1.NewCluster(wv)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := cluster.RunRound(1, 0, "ROTATE_ON_ALARM", nil)
	if err != nil {
		t.Fatalf("L1 round failed: %v", err)
	}
	// Every org applied the same decision (agreement).
	var digest string
	for _, a := range applied {
		if digest == "" {
			digest = a.Digest
		} else if a.Digest != digest {
			t.Fatal("L1 agreement violated")
		}
	}

	// --- L1 federated recovery for a compromised org ---
	seed := make([]byte, 32)
	rand.Read(seed)
	cer, err := l1.NewRecoveryCeremony(seed, []string{"acme", "globex", "initech", "umbrella", "wayne"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	preRoot := ctlog.Root()
	anchor, err := cer.Anchor("acme", 1750003700, preRoot, []string{"globex", "initech", "umbrella"})
	if err != nil {
		t.Fatal(err)
	}
	if !anchor.Accept(cer.RecKey, preRoot) {
		t.Fatal("federated recovery anchor rejected by the restored org")
	}

	// --- Convert the L1 decision to a seam observation for L0 ---
	decisionObs, err := applied[cluster.Nodes[0].Org].Observation("globex", 1750003701, 3, l3Key)
	if err != nil {
		t.Fatal(err)
	}
	if !decisionObs.Verify(l3Pub) {
		t.Fatal("L1 decision observation failed seam verification")
	}
}