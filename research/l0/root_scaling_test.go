package l0

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestRootScalingIsLogarithmic asserts Root() cost does not grow linearly
// with log size: a 100x larger tree must stay within a small constant
// factor. The old implementation was O(n) and would blow up here.
func TestRootScalingIsLogarithmic(t *testing.T) {
	measure := func(n int) time.Duration {
		m := NewMerkleLog()
		for i := 0; i < n; i++ {
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], uint64(i))
			m.Append(buf[:])
		}
		// warm
		_ = m.Root()
		start := time.Now()
		const iters = 1000
		for i := 0; i < iters; i++ {
			_ = m.Root()
		}
		return time.Since(start) / iters
	}
	small := measure(1000)
	large := measure(100000)
	t.Logf("Root(): n=1k %v, n=100k %v (ratio %.2f)", small, large, float64(large)/float64(small))
	if small == 0 {
		return
	}
	// O(log n): 1k->100k is ~7 more levels, so ratio should be tiny. If
	// it were O(n) the ratio would be ~100. Require < 5.
	if float64(large)/float64(small) > 5 {
		t.Fatalf("Root() cost grew by %.1fx from 1k to 100k leaves; not logarithmic", float64(large)/float64(small))
	}
}
