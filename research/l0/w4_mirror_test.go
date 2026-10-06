package l0

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// TestW4MirrorUsesSignedEvent is a regression test for the raw-mirror bug:
// the auditor mirror must store the SIGNED appended event, so its head
// equals the timeline head and W4 (external_probe) reads a clean mirror on
// clean traffic. Mirroring the raw batch event (nil Signature) made W4
// alarm on every cycle, permanently consuming one of the 5 quorum votes.
func TestW4MirrorUsesSignedEvent(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	log := &AuditorLog{}

	// Mirror the raw (unsigned) batch events, as the old bench code did.
	for i := 0; i < 5; i++ {
		raw := TrustEvent{Type: EvIssue, Payload: issue("c", "user", "", int64(i)), Timestamp: int64(i)}
		tl.Append(raw.Type, raw.Payload, raw.Timestamp)
		log.Mirror(raw)
	}
	if bytes.Equal(log.Head(), tl.Head()) {
		t.Fatal("precondition: raw mirror must diverge from the signed timeline head")
	}

	// Mirror the signed appended events, as the code now does.
	tl2 := NewTimeline(key)
	log2 := &AuditorLog{}
	for i := 0; i < 5; i++ {
		raw := TrustEvent{Type: EvIssue, Payload: issue("c", "user", "", int64(i)), Timestamp: int64(i)}
		tl2.Append(raw.Type, raw.Payload, raw.Timestamp)
		log2.Mirror(tl2.events[len(tl2.events)-1])
	}
	if !bytes.Equal(log2.Head(), tl2.Head()) {
		t.Fatal("signed mirror head must equal the timeline head")
	}

	// End-to-end: a signed mirror keeps W4 quiet on clean traffic.
	tl3 := NewTimeline(key)
	log3 := &AuditorLog{}
	w := NewWatchdog("W4", WDExternalProbe, 0, 0, 0, tl3, log3)
	for i := 0; i < 20; i++ {
		raw := TrustEvent{Type: EvIssue, Payload: issue(fmt.Sprintf("c%d", i), "user", "", int64(i))}
		tl3.Append(raw.Type, raw.Payload, raw.Timestamp)
		log3.Mirror(tl3.events[len(tl3.events)-1])
		w.ObserveBatch([]TrustEvent{raw}, i)
		if s := w.Score(); s.Score < threshold {
			t.Fatalf("W4 alarmed on clean traffic at cycle %d (score %.0f)", i, s.Score)
		}
	}
}

// TestBaselineNoFalsePositiveW4 confirms the whole baseline scenario emits
// no false positive now that W4 is fed a correct mirror (companion to
// TestBaselineNoFalsePositive).
func TestBaselineNoFalsePositiveW4(t *testing.T) {
	b := NewBench(30 * time.Second)
	if m := b.ScenarioBaseline(); m.FalsePositive {
		t.Fatal("baseline: false positive on clean traffic after W4 mirror fix")
	}
}