package l2

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"trustorchestrator/research/l0"
)

// buildLog appends n event blobs (entry = SHA-256(event)) and returns
// the log, the events, and a signed STH at the full size.
func buildLog(t *testing.T, events [][]byte) (*l0.MerkleLog, *l0.SignedTreeHead, ed25519.PublicKey) {
	t.Helper()
	log := l0.NewMerkleLog()
	for _, ev := range events {
		h := sha256.Sum256(ev)
		log.Append(h[:])
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sth := l0.SignSTH(priv, log.Root(), log.Size(), 1750000000)
	return log, sth, pub
}

func TestProveVerifyInclude(t *testing.T) {
	events := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("secret")}
	log, sth, pub := buildLog(t, events)
	c, err := ProveInclude("acme", log, 3, log.Size(), sth)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclude(c, pub, sth) {
		t.Fatal("valid INCLUDE proof rejected")
	}
	// Tampered root must fail.
	bad := *sth
	bad.Root = []byte("nope")
	if VerifyInclude(c, pub, &bad) {
		t.Fatal("INCLUDE accepted against a tampered root")
	}
}

func TestIncludeRejectsForgedIndex(t *testing.T) {
	events := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	log, sth, pub := buildLog(t, events)
	c, _ := ProveInclude("acme", log, 1, log.Size(), sth)
	// Swap the index: proof should no longer recompute the root.
	c.Params = []byte(`{"index":2,"leaf_hash":"` + strings.Repeat("00", 32) + `"}`)
	if VerifyInclude(c, pub, sth) {
		t.Fatal("forged INCLUDE accepted")
	}
}

func TestProveVerifyNoneOf(t *testing.T) {
	events := [][]byte{[]byte("ok1"), []byte("ok2"), []byte("ok3")}
	log, sth, pub := buildLog(t, events)
	pred := func(ev []byte) bool { return strings.Contains(string(ev), "secret") }
	c, err := ProveNoneOf("acme", log, log.Size(), events, pred, sth)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyNoneOf(c, pub, sth) {
		t.Fatal("valid NONE_OF rejected")
	}
	// A matching event makes the claim unprovable.
	events2 := append(events, []byte("a secret"))
	log2, sth2, _ := buildLog(t, events2)
	if _, err := ProveNoneOf("acme", log2, log2.Size(), events2, pred, sth2); err == nil {
		t.Fatal("NONE_OF proved despite a matching leaf")
	}
}

func TestProveVerifyCountOf(t *testing.T) {
	events := [][]byte{[]byte("err"), []byte("ok"), []byte("err")}
	log, sth, pub := buildLog(t, events)
	pred := func(ev []byte) bool { return string(ev) == "err" }
	c, err := ProveCountOf("acme", log, log.Size(), events, pred, 2, 2, sth)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCountOf(c, pub, sth) {
		t.Fatal("valid COUNT_OF rejected")
	}
	if _, err := ProveCountOf("acme", log, log.Size(), events, pred, 3, 4, sth); err == nil {
		t.Fatal("COUNT_OF proved a false range")
	}
}

func TestConditionalDisclosure(t *testing.T) {
	events := [][]byte{[]byte("a"), []byte("court-order"), []byte("c")}
	log, sth, pub := buildLog(t, events)
	d, err := Open("acme", log, events, 1, log.Size(), sth)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDisclosure(d, sth, pub) {
		t.Fatal("valid disclosure rejected")
	}
	// A swapped event no longer matches the committed leaf.
	forged := *d
	forged.Event = []byte("a")
	if VerifyDisclosure(&forged, sth, pub) {
		t.Fatal("disclosure accepted a non-committed event")
	}
}