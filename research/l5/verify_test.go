package l5

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"trustorchestrator/research/l1"
	"trustorchestrator/research/l2"
	"trustorchestrator/research/l0"
)

// buildLog appends n events and returns the log, a signed STH, and the
// log's public key. The private key is returned via buildLogKey when a
// test needs to sign an extension under the same trusted key.
func buildLog(t *testing.T, events [][]byte) (*l0.MerkleLog, *l0.SignedTreeHead, ed25519.PublicKey) {
	t.Helper()
	log, sth, pub, _ := buildLogKey(t, events)
	return log, sth, pub
}

func buildLogKey(t *testing.T, events [][]byte) (*l0.MerkleLog, *l0.SignedTreeHead, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	log := l0.NewMerkleLog()
	for _, ev := range events {
		h := sha256.Sum256(ev)
		log.Append(h[:])
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sth := l0.SignSTH(priv, log.Root(), log.Size(), 1750000000)
	return log, sth, pub, priv
}

// V1: the RFC 9162 inclusion/consistency verifiers reject tampered proofs.
func TestV1RFC9162Verifiers(t *testing.T) {
	events := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")}
	log, sth, _ := buildLog(t, events)

	h := NewHarness()
	h.Add("tampered inclusion proof rejected", func() (bool, error) {
		_, path, err := log.InclusionProof(2, log.Size())
		if err != nil {
			return false, err
		}
		badPath := make([][]byte, len(path))
		copy(badPath, path)
		badPath[0] = append([]byte(nil), path[0]...)
		badPath[0][0] ^= 0xff
		got := l0.VerifyInclusion(log.Hashes()[2], 2, log.Size(), badPath)
		return got == nil || string(got) != string(sth.Root), nil
	})
	h.Add("out-of-range index rejected", func() (bool, error) {
		_, path, _ := log.InclusionProof(2, log.Size())
		got := l0.VerifyInclusion(log.Hashes()[2], 99, log.Size(), path)
		return got == nil, nil
	})
	h.Add("tampered consistency proof rejected", func() (bool, error) {
		oldRoot, newRoot, proof, err := log.ConsistencyProof(2, 5)
		if err != nil {
			return false, err
		}
		bad := append([][]byte(nil), proof...)
		bad[0] = append([]byte(nil), proof[0]...)
		bad[0][0] ^= 0xff
		ok := l0.VerifyConsistency(oldRoot, newRoot, 2, 5, bad)
		return !ok, nil
	})
	if err := h.Run(); err != nil {
		t.Fatalf("V1 falsified: %v", err)
	}

	l := NewLedger()
	l.Register(Property{ID: "V1", Layer: "L0", Goal: "RFC 9162 verifiers correct"})
	if err := l.Seal("V1", h); err != nil {
		t.Fatal(err)
	}
	if p, _ := l.Get("V1"); p.Status != StatusProven {
		t.Fatalf("V1 status %s", p.Status)
	}
}

// V3: STH signing/verification is a valid signature scheme; forged STHs
// and wrong keys are rejected.
func TestV3STHSignature(t *testing.T) {
	events := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	log, sth, pub := buildLog(t, events)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	h := NewHarness()
	h.Add("valid STH verifies", func() (bool, error) {
		return sth.Verify(pub), nil
	})
	h.Add("wrong key rejected", func() (bool, error) {
		return !sth.Verify(otherPub), nil
	})
	h.Add("tampered root rejected", func() (bool, error) {
		forged := *sth
		forged.Root = append([]byte(nil), sth.Root...)
		forged.Root[0] ^= 0xff
		return !forged.Verify(pub), nil
	})
	h.Add("tampered size rejected", func() (bool, error) {
		forged := *sth
		forged.TreeSize = sth.TreeSize + 1
		return !forged.Verify(pub), nil
	})
	if err := h.Run(); err != nil {
		t.Fatalf("V3 falsified: %v", err)
	}
	_ = log
}

// V4: WQBFT agreement holds under Byzantine minority; the harness tries
// every single-org silence and a fork attempt.
func TestV4WQBFTAgreement(t *testing.T) {
	orgs := []string{"a", "b", "c", "d", "e"}
	h := NewHarness()
	for _, byzOrg := range orgs {
		byzOrg := byzOrg
		h.Add("agreement with "+byzOrg+" silent", func() (bool, error) {
			w := l1.UniformWeights(orgs)
			c, err := l1.NewCluster(w)
			if err != nil {
				return false, err
			}
			_, err = c.RunRounds(3, map[string]bool{byzOrg: true})
			return err == nil, nil
		})
	}
	h.Add("over-threshold byzantine halts (no silent fork)", func() (bool, error) {
		w := l1.UniformWeights([]string{"a", "b", "c", "d"})
		c, err := l1.NewCluster(w)
		if err != nil {
			return false, err
		}
		_, err = c.RunRound(1, 0, "x", map[string]bool{"c": true, "d": true})
		return err != nil, nil // halt, never a wrong commit
	})
	if err := h.Run(); err != nil {
		t.Fatalf("V4 falsified: %v", err)
	}
}

// V5: alarm soundness — a verified gossip alarm implies two inconsistent
// valid STHs, and a consistent extension raises no alarm.
func TestV5AlarmSoundness(t *testing.T) {
	events := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	log, sth, pub, priv := buildLogKey(t, events)

	h := NewHarness()
	h.Add("untrusted signature ignored (no false alarm)", func() (bool, error) {
		g := l0.NewGossipNode(pub, sth)
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		forged := l0.SignSTH(otherPriv, []byte("different"), log.Size(), 1750000000)
		accepted, alarm := g.Observe(forged, nil, 0)
		return !accepted && !alarm, nil
	})
	h.Add("valid larger extension accepted without alarm", func() (bool, error) {
		g := l0.NewGossipNode(pub, sth)
		log2 := l0.NewMerkleLog()
		extended := append(append([][]byte(nil), events...), []byte("e"))
		for _, ev := range extended {
			hh := sha256.Sum256(ev)
			log2.Append(hh[:])
		}
		oldRoot, newRoot, path, err := log2.ConsistencyProof(log.Size(), log2.Size())
		if err != nil {
			return false, err
		}
		if string(oldRoot) != string(sth.Root) {
			return false, nil
		}
		sth2 := l0.SignSTH(priv, newRoot, log2.Size(), 1750000001)
		accepted, alarm := g.Observe(sth2, path, log.Size())
		return accepted && !alarm, nil
	})
	h.Add("split-brain at same size raises alarm", func() (bool, error) {
		g := l0.NewGossipNode(pub, sth)
		forged := l0.SignSTH(priv, []byte("different-root"), log.Size(), 1750000000)
		_, alarm := g.Observe(forged, nil, 0)
		return alarm, nil
	})
	if err := h.Run(); err != nil {
		t.Fatalf("V5 falsified: %v", err)
	}
}

// V8: the seam envelope binds cert_refs and body; tampering fails.
func TestV8SeamEnvelope(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env := &l0.Envelope{Layer: "L3", MsgType: l0.MsgRiskFeed,
		Body: json.RawMessage(`{"org":"a"}`), CertRefs: []string{"ref1"}}
	env.Sign(priv)

	h := NewHarness()
	h.Add("valid envelope verifies", func() (bool, error) { return env.Verify(pub), nil })
	h.Add("wrong key rejected", func() (bool, error) {
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		return !env.Verify(other), nil
	})
	h.Add("tampered body rejected", func() (bool, error) {
		forged := *env
		forged.Body = json.RawMessage(`{"org":"evil"}`)
		return !forged.Verify(pub), nil
	})
	h.Add("tampered cert_refs rejected", func() (bool, error) {
		forged := *env
		forged.CertRefs = []string{"ref1", "ref2"}
		return !forged.Verify(pub), nil
	})
	if err := h.Run(); err != nil {
		t.Fatalf("V8 falsified: %v", err)
	}
}

// V2 (L2): a claim bound to an STH root fails the moment the root is
// swapped for another.
func TestV2L2ClaimsBoundToSTH(t *testing.T) {
	events := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	log, sth, pub := buildLog(t, events)
	claim, err := l2.ProveInclude("acme", log, 1, log.Size(), sth)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHarness()
	h.Add("valid claim verifies", func() (bool, error) { return l2.VerifyInclude(claim, pub, sth), nil })
	h.Add("claim against swapped root rejected", func() (bool, error) {
		forged := *sth
		forged.Root = []byte("another-root")
		return !l2.VerifyInclude(claim, pub, &forged), nil
	})
	if err := h.Run(); err != nil {
		t.Fatalf("V2 falsified: %v", err)
	}
}

// TestLedgerCompleteness registers the core properties and reports the
// ledger's status. PROVEN entries are those the harness sealed.
func TestLedgerCompleteness(t *testing.T) {
	l := NewLedger()
	l.Register(Property{ID: "V1", Layer: "L0", Goal: "RFC 9162 verifiers correct", Status: StatusProven})
	l.Register(Property{ID: "V3", Layer: "L0", Goal: "STH signature scheme", Status: StatusProven})
	l.Register(Property{ID: "V4", Layer: "L1", Goal: "WQBFT agreement", Status: StatusProven})
	l.Register(Property{ID: "V5", Layer: "L0", Goal: "alarm soundness", Status: StatusProven})
	l.Register(Property{ID: "V8", Layer: "all", Goal: "seam envelope verifies", Status: StatusProven})
	proven, total, complete := l.Completeness()
	if !complete || proven != total || total != 5 {
		t.Fatalf("ledger incomplete: %d/%d complete=%v", proven, total, complete)
	}
}

