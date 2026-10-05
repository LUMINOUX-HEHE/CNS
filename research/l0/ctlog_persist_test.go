package l0

// ctlog_persist_test.go — S2: the CT log frontier survives a restart
// (Marshal/Unmarshal round-trip is byte-identical) and catches up only
// the events appended since the snapshot.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestMerkleLogMarshalRoundTrip(t *testing.T) {
	m := NewMerkleLog()
	for i := 0; i < 1000; i++ {
		m.Append([]byte{byte(i), byte(i >> 8)})
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	restored := NewMerkleLog()
	if err := restored.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Size() != m.Size() {
		t.Fatalf("size: got %d want %d", restored.Size(), m.Size())
	}
	if !bytes.Equal(restored.Root(), m.Root()) {
		t.Fatalf("root mismatch after restore")
	}
	// Appending after restore must match appending to the original.
	m.Append([]byte("x"))
	restored.Append([]byte("x"))
	if !bytes.Equal(restored.Root(), m.Root()) {
		t.Fatalf("root mismatch after post-restore append")
	}
}

func TestLoadCTLogCatchesUp(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	for i := 0; i < 5; i++ {
		if _, err := tl.Append(EvIssue, []byte(`{"identity":"a"}`), int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	s := &Store{dir: t.TempDir(), Tenants: map[string]*Tenant{}}
	ten := &Tenant{ID: "org1", tl: tl}
	// Build + persist a snapshot at 5 events.
	s.loadCTLog(ten)
	if ten.ctLog.Size() != 5 {
		t.Fatalf("want 5, got %d", ten.ctLog.Size())
	}
	root5 := append([]byte(nil), ten.ctLog.Root()...)
	// Append 3 more events, then reload from disk: the snapshot loads and
	// catches up only the new events, preserving the size-5 prefix root.
	for i := 5; i < 8; i++ {
		if _, err := tl.Append(EvIssue, []byte(`{"identity":"b"}`), int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	ten.ctLog, ten.ctLogSrc = nil, nil
	s.loadCTLog(ten)
	if ten.ctLog.Size() != 8 {
		t.Fatalf("catch-up: want 8, got %d", ten.ctLog.Size())
	}
	// The prefix root at size 5 must still recompute identically.
	if !bytes.Equal(mth(ten.ctLog.Hashes(), 0, 5), root5) {
		t.Fatalf("prefix root changed after catch-up")
	}
}

func TestOrgMerkleIncrementalAndForkInvalidation(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tl := NewTimeline(key)
	s := &Store{dir: t.TempDir(), Tenants: map[string]*Tenant{}}
	ten := &Tenant{ID: "o", tl: tl}
	m0 := s.orgMerkle(ten)
	for i := 0; i < 4; i++ {
		tl.Append(EvIssue, []byte(`{"identity":"a"}`), int64(i))
		s.orgMerkle(ten) // append path
	}
	if m0.Size() != 4 {
		t.Fatalf("incremental: want 4, got %d", m0.Size())
	}
	// Same pointer returned when nothing changed (cache hit).
	if got := s.orgMerkle(ten); got != m0 {
		t.Fatalf("expected cached log pointer")
	}
	// A new timeline (fork) forces a rebuild.
	_, key2, _ := ed25519.GenerateKey(rand.Reader)
	tl2 := NewTimeline(key2)
	tl2.Append(EvIssue, []byte(`{"identity":"c"}`), 99)
	ten.tl = tl2
	if got := s.orgMerkle(ten); got.Size() != 1 {
		t.Fatalf("fork rebuild: want 1, got %d", got.Size())
	}
}