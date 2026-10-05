// recovery.go — L1 federated recovery (03 §6). Org `a` is fully
// compromised; a quorum of neighbor orgs jointly issue a recovery anchor
// that binds `a`'s pre-compromise log root. The anchor is a threshold
// signature (FROST over Ed25519) produced across orgs, so no single org
// can forge or block it.
package l1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"trustorchestrator/research/l0"
)

// RecoveryAnchor is the quorum action that re-anchors a compromised org
// (03 §6 step 3). It is verifiable by anyone holding the cluster
// recovery key K_rec.
type RecoveryAnchor struct {
	Org               string   `json:"org"`
	FreezeTs          int64    `json:"freeze_ts"`
	PreCompromiseRoot string   `json:"pre_compromise_root"` // hex STH root
	Signers           []string `json:"signers"`             // org ids in the quorum
	Sig               []byte   `json:"sig"`                 // FROST aggregate over descriptor
}

// anchorDescriptor is the exact bytes the cluster threshold-signs.
func (a *RecoveryAnchor) anchorDescriptor() []byte {
	shape := struct {
		Org               string   `json:"org"`
		FreezeTs          int64    `json:"freeze_ts"`
		PreCompromiseRoot string   `json:"pre_compromise_root"`
		Signers           []string `json:"signers"`
	}{a.Org, a.FreezeTs, a.PreCompromiseRoot, uniqueSorted(a.Signers)}
	b, _ := json.Marshal(shape)
	return b
}

// Verify checks the anchor against the cluster recovery key.
func (a *RecoveryAnchor) Verify(recKey ed25519.PublicKey) bool {
	if a == nil || len(a.Sig) != ed25519.SignatureSize || len(recKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(recKey, a.anchorDescriptor(), a.Sig)
}

// RecoveryCeremony holds the cluster's FROST shares of K_rec (one per
// participating org). The shares are produced once at cluster genesis by
// FrostSplit; no single org ever holds K_rec.
type RecoveryCeremony struct {
	RecKey  ed25519.PublicKey
	signers []*l0.FrostSigner
	byID    map[string]*l0.FrostSigner
	// Xs maps org id -> participant index for the aggregator.
	Xs map[string]int
}

// NewRecoveryCeremony splits a cluster recovery key into n shares with
// threshold t (t = 2/3 · n by the L1 quorum rule). Seed must be 32
// bytes of cluster entropy, generated once at genesis.
func NewRecoveryCeremony(seed []byte, orgs []string, t int) (*RecoveryCeremony, error) {
	if len(orgs) < 3 {
		return nil, errors.New("l1: recovery needs >= 3 orgs")
	}
	if t < 2 || t > len(orgs) {
		return nil, fmt.Errorf("l1: bad threshold %d for %d orgs", t, len(orgs))
	}
	signers, recKey, err := l0.FrostSplit(seed, len(orgs), t)
	if err != nil {
		return nil, err
	}
	c := &RecoveryCeremony{RecKey: recKey, byID: map[string]*l0.FrostSigner{}, Xs: map[string]int{}}
	// assign signer i to org i (deterministic by sorted org order).
	ordered := append([]string(nil), orgs...)
	sort.Strings(ordered)
	for i, s := range signers {
		org := ordered[i]
		c.signers = append(c.signers, s)
		c.byID[org] = s
		c.Xs[org] = s.X
	}
	return c, nil
}

// Anchor produces a recovery anchor signed by the given quorum of orgs.
// It requires at least the ceremony threshold of distinct orgs.
func (c *RecoveryCeremony) Anchor(org string, freezeTs int64, preRoot []byte, quorum []string) (*RecoveryAnchor, error) {
	a := &RecoveryAnchor{Org: org, FreezeTs: freezeTs,
		PreCompromiseRoot: hex.EncodeToString(preRoot), Signers: uniqueSorted(quorum)}
	var signers []*l0.FrostSigner
	for _, q := range a.Signers {
		s, ok := c.byID[q]
		if !ok {
			return nil, fmt.Errorf("l1: %s holds no recovery share", q)
		}
		signers = append(signers, s)
	}
	sig, err := l0.FrostRound(c.RecKey, signers, a.anchorDescriptor())
	if err != nil {
		return nil, err
	}
	a.Sig = sig
	return a, nil
}

// Accept validates an anchor against a restored org's own log root. The
// restored L0 accepts only if the anchor verifies under K_rec and the
// anchored pre-compromise root is a prefix of (or equal to) its own
// history — so a compromised org cannot choose a false root (03 §6).
func (a *RecoveryAnchor) Accept(recKey ed25519.PublicKey, ownRoot []byte) bool {
	if !a.Verify(recKey) {
		return false
	}
	want := hex.EncodeToString(ownRoot)
	return want == a.PreCompromiseRoot
}

// FreezeDecision builds the RECOVERY-FREEZE as an L1 Proposal, so the
// freeze itself is an ordinary quorum decision (03 §6 step 2).
func FreezeDecision(org string, forkHash []byte, ts int64) Proposal {
	body, _ := json.Marshal(map[string]any{"org": org, "fork_hash": hex.EncodeToString(forkHash), "ts": ts})
	return Proposal{Rule: "RECOVERY-FREEZE", Scope: []string{org}, Body: body}
}

// rootHash is a convenience for tests: the SHA-256 of an STH root.
func rootHash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}