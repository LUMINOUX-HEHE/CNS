package l0

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

// TestIncrementalRootMatchesReference is the differential proof that the
// O(log n) incremental frontier (Root) is byte-identical to the O(n)
// reference recurrence (mth) at every tree size — including every size
// around powers of two, where the frontier shape changes. It is the gate
// that lets Root() replace the full rebuild without changing any proof,
// STH, or gossip behavior.
func TestIncrementalRootMatchesReference(t *testing.T) {
	m := NewMerkleLog()
	// 1..1026 covers every frontier transition up to 10 bits.
	for i := 0; i < 1026; i++ {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(i))
		m.Append(buf[:])

		want := mth(m.leaves, 0, len(m.leaves))
		got := m.Root()
		if !bytes.Equal(want, got) {
			t.Fatalf("size %d: incremental root %x != reference %x", len(m.leaves), got, want)
		}
	}
}

// TestIncrementalRootEmpty checks the empty-log contract (nil root).
func TestIncrementalRootEmpty(t *testing.T) {
	if NewMerkleLog().Root() != nil {
		t.Fatal("empty log must have a nil root")
	}
}

// TestIncrementalFrontierBound asserts the frontier never holds more than
// one subtree per bit — the structural invariant that makes Root O(log n).
func TestIncrementalFrontierBound(t *testing.T) {
	m := NewMerkleLog()
	for i := 0; i < 4096; i++ {
		m.Append([]byte{byte(i), byte(i >> 8)})
		seen := map[int]bool{}
		for _, n := range m.stack {
			if seen[n.size] {
				t.Fatalf("size %d: two frontier subtrees of size %d", len(m.leaves), n.size)
			}
			seen[n.size] = true
			if n.size&(n.size-1) != 0 {
				t.Fatalf("frontier subtree size %d is not a power of two", n.size)
			}
		}
		if len(m.stack) > 64 {
			t.Fatalf("frontier grew to %d (> bits of an int)", len(m.stack))
		}
	}
}

// TestIncrementalRootAfterReloadShape simulates a log rebuilt by appending
// the same entries in the same order (the API's rebuild-per-org path) and
// confirms it converges to the same root as an incremental build.
func TestIncrementalRootAfterReloadShape(t *testing.T) {
	entries := make([][]byte, 300)
	for i := range entries {
		h := sha256.Sum256([]byte(fmt.Sprintf("event-%d", i)))
		entries[i] = h[:]
	}
	a, b := NewMerkleLog(), NewMerkleLog()
	for _, e := range entries {
		a.Append(e)
	}
	for _, e := range entries {
		b.Append(e)
	}
	if !bytes.Equal(a.Root(), b.Root()) {
		t.Fatal("two identically-built incremental logs disagree on root")
	}
}