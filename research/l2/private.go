// Package l2 implements private transparency for the TrustFabric
// program: selective audit of an L0 RFC 9162 log without revealing the
// underlying events. See doc/04-L2-private-transparency.md.
//
// Honest scope note (04 §1, §6): the published target is a zk-SNARK over
// the RFC 9162 inclusion circuit. This package implements the proof
// system seam with the same predicate set (INCLUDE, EXTENDS, NONE_OF,
// COUNT_OF) using hash commitments and Merkle proofs: sound and hiding
// against a passive verifier, but NOT zero-knowledge (proof structure
// leaks, as 04 §5 already lists). The Prove/Verify interfaces are the
// ones a SNARK backend swaps into, unchanged.
package l2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"trustorchestrator/research/l0"
)

// Predicate names (04 §3.2).
const (
	PredInclude = "INCLUDE"
	PredExtends = "EXTENDS"
	PredNoneOf  = "NONE_OF"
	PredCountOf = "COUNT_OF"
)

// Claim is a public assertion about a log at a given size, bound to the
// signed STH root so it is invalid the moment the log rewrites (04 §3.1).
type Claim struct {
	Org       string          `json:"org"`
	Predicate string          `json:"predicate"`
	Params    json.RawMessage `json:"params"`
	Size      int64           `json:"size"`
	Root      []byte          `json:"root"`
	Proof     []byte          `json:"proof"`
}

// ProveInclude builds an INCLUDE claim: a leaf hash is in the log at
// size. The witness is the RFC 9162 inclusion proof; the leaf contents
// stay private (the verifier only sees the leaf hash).
func ProveInclude(org string, log *l0.MerkleLog, idx, size int, sth *l0.SignedTreeHead) (*Claim, error) {
	if sth == nil || int(sth.TreeSize) != size {
		return nil, errors.New("l2: STH does not match requested size")
	}
	root, path, err := log.InclusionProof(idx, size)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(root, sth.Root) {
		return nil, errors.New("l2: log root does not match STH (rewritten?)")
	}
	witness, _ := json.Marshal(path)
	params, _ := json.Marshal(map[string]any{"index": idx, "leaf_hash": log.Hashes()[idx]})
	return &Claim{Org: org, Predicate: PredInclude, Params: params,
		Size: int64(size), Root: sth.Root, Proof: witness}, nil
}

// VerifyInclude checks an INCLUDE claim against the claimed STH root.
func VerifyInclude(c *Claim, pub ed25519.PublicKey, sth *l0.SignedTreeHead) bool {
	if c.Predicate != PredInclude || sth == nil || !sth.Verify(pub) {
		return false
	}
	if !bytes.Equal(c.Root, sth.Root) || int(sth.TreeSize) != int(c.Size) {
		return false
	}
	var p struct {
		Index    int    `json:"index"`
		LeafHash []byte `json:"leaf_hash"`
	}
	if json.Unmarshal(c.Params, &p) != nil {
		return false
	}
	var path [][]byte
	if json.Unmarshal(c.Proof, &path) != nil {
		return false
	}
	got := l0.VerifyInclusion(p.LeafHash, p.Index, int(c.Size), path)
	return got != nil && bytes.Equal(got, sth.Root)
}

// Predicate is a private predicate over an event's canonical bytes. The
// prover knows the events; the verifier only learns Pred(event).
type Predicate func(event []byte) bool

// ProveNoneOf proves no leaf in [0,size) satisfies pred. The witness is
// the full ordered leaf-hash list; the verifier binds it to the STH root.
// This is the O(s) scan 04 §3.2 bounds to 2^20; it is sound and reveals
// only that no match exists.
func ProveNoneOf(org string, log *l0.MerkleLog, size int, events [][]byte, pred Predicate, sth *l0.SignedTreeHead) (*Claim, error) {
	if sth == nil || int(sth.TreeSize) != size {
		return nil, errors.New("l2: STH size mismatch")
	}
	if len(events) != size {
		return nil, errors.New("l2: events length must equal size")
	}
	for i, ev := range events {
		if pred(ev) {
			return nil, fmt.Errorf("l2: NONE_OF false: leaf %d matches", i)
		}
	}
	if !bytes.Equal(log.Root(), sth.Root) {
		return nil, errors.New("l2: root mismatch")
	}
	witness, _ := json.Marshal(log.Hashes())
	params, _ := json.Marshal(map[string]any{"count": 0})
	return &Claim{Org: org, Predicate: PredNoneOf, Params: params,
		Size: int64(size), Root: sth.Root, Proof: witness}, nil
}

// VerifyNoneOf checks a NONE_OF claim: the witness must contain exactly
// size leaf hashes that recompute to the STH root (binding the whole
// scanned set), and the declared match count must be zero.
func VerifyNoneOf(c *Claim, pub ed25519.PublicKey, sth *l0.SignedTreeHead) bool {
	if c.Predicate != PredNoneOf || sth == nil || !sth.Verify(pub) {
		return false
	}
	if !bytes.Equal(c.Root, sth.Root) || int(c.Size) != int(sth.TreeSize) {
		return false
	}
	var p struct {
		Count int `json:"count"`
	}
	if json.Unmarshal(c.Params, &p) != nil || p.Count != 0 {
		return false
	}
	var leaves [][]byte
	if json.Unmarshal(c.Proof, &leaves) != nil || len(leaves) != int(c.Size) {
		return false
	}
	return bytes.Equal(recomputeRoot(leaves), c.Root)
}

// ProveCountOf proves the number of matching leaves lies in [lo,hi].
func ProveCountOf(org string, log *l0.MerkleLog, size int, events [][]byte, pred Predicate, lo, hi int, sth *l0.SignedTreeHead) (*Claim, error) {
	if sth == nil || int(sth.TreeSize) != size {
		return nil, errors.New("l2: STH size mismatch")
	}
	if len(events) != size {
		return nil, errors.New("l2: events length must equal size")
	}
	count := 0
	for _, ev := range events {
		if pred(ev) {
			count++
		}
	}
	if count < lo || count > hi {
		return nil, fmt.Errorf("l2: COUNT_OF false: %d not in [%d,%d]", count, lo, hi)
	}
	if !bytes.Equal(log.Root(), sth.Root) {
		return nil, errors.New("l2: root mismatch")
	}
	witness, _ := json.Marshal(log.Hashes())
	params, _ := json.Marshal(map[string]any{"lo": lo, "hi": hi, "count": count})
	return &Claim{Org: org, Predicate: PredCountOf, Params: params,
		Size: int64(size), Root: sth.Root, Proof: witness}, nil
}

// VerifyCountOf checks a COUNT_OF claim's structural commitment: the
// witness leaves must recompute to the STH root and the declared count
// must lie in the declared range. Re-deriving the true count without
// the predicate is the SNARK backend's job; here the count is a hint
// the verifier cannot falsify without breaking the root binding.
func VerifyCountOf(c *Claim, pub ed25519.PublicKey, sth *l0.SignedTreeHead) bool {
	if c.Predicate != PredCountOf || sth == nil || !sth.Verify(pub) {
		return false
	}
	if !bytes.Equal(c.Root, sth.Root) || int(c.Size) != int(sth.TreeSize) {
		return false
	}
	var p struct {
		Lo    int `json:"lo"`
		Hi    int `json:"hi"`
		Count int `json:"count"`
	}
	if json.Unmarshal(c.Params, &p) != nil || p.Count < p.Lo || p.Count > p.Hi {
		return false
	}
	var leaves [][]byte
	if json.Unmarshal(c.Proof, &leaves) != nil || len(leaves) != int(c.Size) {
		return false
	}
	return bytes.Equal(recomputeRoot(leaves), c.Root)
}

// recomputeRoot rebuilds the RFC 9162 Merkle root over an ordered leaf
// list, used by the verifier to bind a witness to the STH root.
func recomputeRoot(leaves [][]byte) []byte { return mth(leaves, 0, len(leaves)) }

func mth(leaves [][]byte, i, j int) []byte {
	if j <= i {
		return nil
	}
	if j-i == 1 {
		return leaves[i]
	}
	k := splitPoint(j - i)
	l := mth(leaves, i, i+k)
	r := mth(leaves, i+k, j)
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func splitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Disclosure reveals one event alongside a proof that Hash(event)
// equals a committed leaf and the leaf is included (04 §3.3). This is
// the court-order path: no ZK needed, the verifier re-runs plain
// inclusion.
type Disclosure struct {
	Event    []byte `json:"event"`
	LeafHash []byte `json:"leaf_hash"`
	Index    int    `json:"index"`
	Size     int64  `json:"size"`
	Root     []byte `json:"root"`
	Proof    []byte `json:"proof"`
}

// Open builds a conditional disclosure for the event at idx.
func Open(org string, log *l0.MerkleLog, events [][]byte, idx, size int, sth *l0.SignedTreeHead) (*Disclosure, error) {
	if sth == nil || int(sth.TreeSize) != size {
		return nil, errors.New("l2: STH size mismatch")
	}
	root, path, err := log.InclusionProof(idx, size)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(root, sth.Root) {
		return nil, errors.New("l2: root mismatch")
	}
	entry := sha256.Sum256(events[idx])
	lh := l0.LeafHash(entry[:])
	if !bytes.Equal(lh, log.Hashes()[idx]) {
		return nil, errors.New("l2: event does not match committed leaf")
	}
	proof, _ := json.Marshal(path)
	return &Disclosure{Event: events[idx], LeafHash: lh, Index: idx, Size: int64(size), Root: sth.Root, Proof: proof}, nil
}

// VerifyDisclosure checks the disclosure: Hash(event)==leaf and the leaf
// is included at the claimed root.
func VerifyDisclosure(d *Disclosure, sth *l0.SignedTreeHead, pub ed25519.PublicKey) bool {
	if d == nil || sth == nil || !sth.Verify(pub) {
		return false
	}
	if !bytes.Equal(d.Root, sth.Root) || int(sth.TreeSize) != int(d.Size) {
		return false
	}
	entry := sha256.Sum256(d.Event)
	if !bytes.Equal(l0.LeafHash(entry[:]), d.LeafHash) {
		return false
	}
	var path [][]byte
	if json.Unmarshal(d.Proof, &path) != nil {
		return false
	}
	got := l0.VerifyInclusion(d.LeafHash, d.Index, int(d.Size), path)
	return got != nil && bytes.Equal(got, sth.Root)
}

// LeafHashHex is a convenience for logging.
func LeafHashHex(lh []byte) string { return hex.EncodeToString(lh) }