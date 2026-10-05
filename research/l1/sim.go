// sim.go — deterministic in-process WQBFT simulator (03 §9). It wires
// validators in one process with a synchronous message bus, so runs are
// reproducible and the safety harness can inject Byzantine behavior.
package l1

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Node is one simulated validator with its L1 key.
type Node struct {
	Org string
	Key ed25519.PrivateKey
	V   *Validator
}

// Cluster is a set of simulated validators sharing one frozen weight
// vector. Delivery is synchronous and ordered, which is the strongest
// (and simplest) correct schedule; the safety argument does not depend
// on it (03 §3).
type Cluster struct {
	Nodes []*Node
	byOrg map[string]*Node
	Keys  map[string]ed25519.PublicKey
	W     *WeightVector
}

// NewCluster builds n validators with the given weight vector. Keys are
// generated for each org.
func NewCluster(w *WeightVector) (*Cluster, error) {
	c := &Cluster{byOrg: map[string]*Node{}, Keys: map[string]ed25519.PublicKey{}, W: w}
	orgs := make([]string, 0, len(w.Weights))
	for org := range w.Weights {
		orgs = append(orgs, org)
	}
	sort.Strings(orgs)
	for _, org := range orgs {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		n := &Node{Org: org, Key: priv, V: NewValidator(org, priv, w)}
		c.Nodes = append(c.Nodes, n)
		c.byOrg[org] = n
		c.Keys[org] = pub
	}
	return c, nil
}

// Leader picks the highest-weight org (ties broken lexicographically),
// the leader-selection rule in 03 §4.
func (c *Cluster) Leader() string {
	best := ""
	var bw float64
	for _, n := range c.Nodes {
		w := c.W.Weight(n.Org)
		if w > bw || (w == bw && (best == "" || n.Org < best)) {
			best, bw = n.Org, w
		}
	}
	return best
}

// RunRound drives one full decision round: leader proposes, all honest
// nodes prepare, commit, and apply. It returns the applied decision per
// org. byzantine is the set of orgs that withhold their votes (crash
// faults); they are skipped, which exercises the liveness path.
func (c *Cluster) RunRound(epoch int64, slot uint64, rule string, byzantine map[string]bool) (map[string]Applied, error) {
	leader := c.Leader()
	ln := c.byOrg[leader]
	prop := Proposal{Rule: rule, Scope: allOrgs(c.Nodes), Body: json.RawMessage(`{"ok":true}`)}
	d, err := ln.V.Propose(leader, epoch, slot, prop)
	if err != nil {
		return nil, err
	}
	// PREPARE phase.
	var prepares []Vote
	for _, n := range c.Nodes {
		if byzantine[n.Org] {
			continue
		}
		vt, err := n.V.OnPrePrepare(d)
		if err != nil {
			continue // node already committed this round: skip
		}
		prepares = append(prepares, *vt)
	}
	// Deliver prepares; collect emitted commits.
	var commits []Vote
	for _, vt := range prepares {
		for _, n := range c.Nodes {
			if byzantine[n.Org] {
				continue
			}
			next, _, err := n.V.AddVote(vt, c.Keys[vt.Org])
			if err != nil {
				return nil, fmt.Errorf("prepare delivery to %s: %w", n.Org, err)
			}
			if next != nil {
				commits = append(commits, *next)
			}
		}
	}
	// Deliver commits.
	applied := map[string]Applied{}
	for _, vt := range commits {
		for _, n := range c.Nodes {
			if byzantine[n.Org] {
				continue
			}
			_, a, err := n.V.AddVote(vt, c.Keys[vt.Org])
			if err != nil {
				return nil, fmt.Errorf("commit delivery to %s: %w", n.Org, err)
			}
			if a != nil {
				applied[n.Org] = *a
			}
		}
	}
	if len(applied) == 0 {
		return nil, errors.New("l1: round did not commit")
	}
	return applied, nil
}

// RunRounds drives k sequential slots, returning applied decisions keyed
// by (org, slot). It asserts no two orgs apply different digests at the
// same slot (the T1 agreement check).
func (c *Cluster) RunRounds(k int, byzantine map[string]bool) (map[string]map[uint64]Applied, error) {
	out := map[string]map[uint64]Applied{}
	for i := 0; i < k; i++ {
		slot := uint64(i)
		applied, err := c.RunRound(1, slot, fmt.Sprintf("rule-%d", i), byzantine)
		if err != nil {
			return nil, fmt.Errorf("slot %d: %w", slot, err)
		}
		var digest string
		for org, a := range applied {
			if digest == "" {
				digest = a.Digest
			} else if a.Digest != digest {
				return nil, fmt.Errorf("SAFETY VIOLATION at slot %d: %s disagrees", slot, org)
			}
			if out[org] == nil {
				out[org] = map[uint64]Applied{}
			}
			out[org][slot] = a
		}
		for _, n := range c.Nodes {
			n.V.Advance()
		}
	}
	return out, nil
}

func allOrgs(nodes []*Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Org)
	}
	sort.Strings(out)
	return out
}

// UniformWeights builds a uniform weight vector over the given orgs.
func UniformWeights(orgs []string) *WeightVector {
	w := &WeightVector{Epoch: 1, Weights: map[string]float64{}}
	for _, o := range orgs {
		w.Weights[o] = 1.0 / float64(len(orgs))
	}
	return w
}