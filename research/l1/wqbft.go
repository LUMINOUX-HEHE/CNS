// Package l1 implements cross-org consensus for the TrustFabric
// program: weighted-quorum BFT (WQBFT) over heterogeneous reputation
// weights owned by L4, plus the federated recovery protocol that lets a
// quorum of neighbor orgs re-anchor a compromised org. See
// doc/03-L1-cross-org-consensus.md.
//
// The core is deterministic and transport-free: a validator is a pure
// state machine over signed messages, so the same code runs in tests,
// the simulator, and a live node. Safety does not depend on the
// transport; liveness is argued under the partial-synchrony model.
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

// Message types on the L1 wire (03 §4).
const (
	MsgPrePrepare = "PRE-PREPARE"
	MsgPrepare    = "PREPARE"
	MsgCommit     = "COMMIT"
	MsgViewChange = "VIEW-CHANGE"
	MsgDecision   = "DECISION"
)

// WeightVector is the L4-owned reputation weight per org (03 §2). The
// vector is signed by L4 and frozen for the duration of a decision
// round; mid-round weight changes never affect safety.
type WeightVector struct {
	Epoch   int64              `json:"epoch"`
	Weights map[string]float64 `json:"weights"`
	Sig     []byte             `json:"sig"`
}

type weightShape struct {
	Epoch   int64              `json:"epoch"`
	Weights map[string]float64 `json:"weights"`
}

// SigningBytes is the canonical weight-vector bytes covered by Sig.
func (w *WeightVector) SigningBytes() []byte {
	keys := make([]string, 0, len(w.Weights))
	for k := range w.Weights {
		keys = append(keys, k)
	}
	sort.Strings(keys) // map iteration order is random; canonicalize
	ordered := make(map[string]float64, len(keys))
	for _, k := range keys {
		ordered[k] = w.Weights[k]
	}
	b, _ := json.Marshal(weightShape{w.Epoch, ordered})
	return b
}

// Sign sets Sig over the canonical bytes.
func (w *WeightVector) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("l1: bad private key length")
	}
	w.Sig = ed25519.Sign(priv, w.SigningBytes())
	return nil
}

// Verify checks the L4 signature.
func (w *WeightVector) Verify(pub ed25519.PublicKey) bool {
	if w == nil || len(pub) != ed25519.PublicKeySize || len(w.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, w.SigningBytes(), w.Sig)
}

// Total is the sum of weights (design target: 1.0).
func (w *WeightVector) Total() float64 {
	var t float64
	for _, v := range w.Weights {
		t += v
	}
	return t
}

// Weight returns an org's weight (0 if absent).
func (w *WeightVector) Weight(org string) float64 { return w.Weights[org] }

// VerifyCap enforces the L1 weight cap (03 §3): no single org may reach
// the Byzantine threshold alone, w(o) <= 1/3 - eps.
func (w *WeightVector) VerifyCap(eps float64) error {
	limit := 1.0/3.0 - eps
	for org, v := range w.Weights {
		if v < 0 {
			return fmt.Errorf("l1: negative weight for %s", org)
		}
		if v > limit {
			return fmt.Errorf("l1: weight cap violated: %s has %.4f > %.4f", org, v, limit)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Decision messages and certificates (03 §3-§4)
// ---------------------------------------------------------------------

// Proposal is the payload a leader proposes for one slot.
type Proposal struct {
	Epoch int64           `json:"epoch"`
	Slot  uint64          `json:"slot"`
	Rule  string          `json:"rule"`
	Scope []string        `json:"scope"` // orgs the decision applies to
	Body  json.RawMessage `json:"body"`
}

// Decision is a leader's proposal bound to the slot.
type Decision struct {
	Epoch      int64           `json:"epoch"`
	Slot       uint64          `json:"slot"`
	Digest     string          `json:"digest"`
	Proposal   json.RawMessage `json:"proposal"`
	Leader     string          `json:"leader"`
	WeightHash string          `json:"weight_hash"`
}

// decisionDigest = SHA-256(canonical(DECISION message)) (03 §3).
func decisionDigest(d Decision) string {
	h := sha256.Sum256(canonicalDecision(d))
	return hex.EncodeToString(h[:])
}

func canonicalDecision(d Decision) []byte {
	shape := struct {
		Epoch      int64           `json:"epoch"`
		Slot       uint64          `json:"slot"`
		Proposal   json.RawMessage `json:"proposal"`
		Leader     string          `json:"leader"`
		WeightHash string          `json:"weight_hash"`
	}{d.Epoch, d.Slot, d.Proposal, d.Leader, d.WeightHash}
	b, _ := json.Marshal(shape)
	return b
}

// weightHash binds the frozen weight vector into the decision so a
// reweight cannot retroactively validate a different quorum.
func weightHash(w *WeightVector) string {
	h := sha256.Sum256(w.SigningBytes())
	return hex.EncodeToString(h[:])
}

// Vote is a signed PREPARE or COMMIT.
type Vote struct {
	MsgType string `json:"msg_type"` // PREPARE | COMMIT
	Epoch   int64  `json:"epoch"`
	Slot    uint64 `json:"slot"`
	Digest  string `json:"digest"`
	Org     string `json:"org"`
	Sig     []byte `json:"sig"`
}

type voteShape struct {
	MsgType string `json:"msg_type"`
	Epoch   int64  `json:"epoch"`
	Slot    uint64 `json:"slot"`
	Digest  string `json:"digest"`
	Org     string `json:"org"`
}

// SigningBytes is the canonical vote bytes covered by Sig.
func (v *Vote) SigningBytes() []byte {
	b, _ := json.Marshal(voteShape{v.MsgType, v.Epoch, v.Slot, v.Digest, v.Org})
	return b
}

// Sign sets Sig over the canonical vote bytes.
func (v *Vote) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("l1: bad private key length")
	}
	v.Sig = ed25519.Sign(priv, v.SigningBytes())
	return nil
}

// Verify checks the vote signature.
func (v *Vote) Verify(pub ed25519.PublicKey) bool {
	if v == nil || len(pub) != ed25519.PublicKeySize || len(v.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, v.SigningBytes(), v.Sig)
}

// Cert is a commit certificate: a set of COMMIT votes for one
// (epoch, slot, digest) whose total weight exceeds 2/3. Anyone can
// verify it from the voters' public keys and the frozen weights (T5).
type Cert struct {
	Epoch   int64  `json:"epoch"`
	Slot    uint64 `json:"slot"`
	Digest  string `json:"digest"`
	Commits []Vote `json:"commits"`
	Weight  string `json:"weight_hash"`
}

// VerifyCert checks every commit signature and that the committed
// weight exceeds 2/3 of the frozen vector. keys maps org -> L1 key.
func VerifyCert(c Cert, w *WeightVector, keys map[string]ed25519.PublicKey) bool {
	if weightHash(w) != c.Weight {
		return false
	}
	seen := map[string]bool{}
	var total float64
	for _, v := range c.Commits {
		if v.MsgType != MsgCommit || v.Epoch != c.Epoch || v.Slot != c.Slot || v.Digest != c.Digest {
			return false
		}
		pub, ok := keys[v.Org]
		if !ok || !v.Verify(pub) {
			return false
		}
		if seen[v.Org] {
			continue // dedupe: one org, one vote
		}
		seen[v.Org] = true
		total += w.Weight(v.Org)
	}
	return total > 2.0/3.0
}

// QuorumWeight returns the total weight of the given voters for a
// digest, deduping by org.
func QuorumWeight(votes []Vote, digest string, w *WeightVector) float64 {
	seen := map[string]bool{}
	var total float64
	for _, v := range votes {
		if v.Digest != digest || seen[v.Org] {
			continue
		}
		seen[v.Org] = true
		total += w.Weight(v.Org)
	}
	return total
}

// ---------------------------------------------------------------------
// Validator state machine (03 §4, §7.1)
// ---------------------------------------------------------------------

// State is the validator's protocol phase.
type State string

const (
	StateIdle        State = "IDLE"
	StatePrePrepared State = "PRE-PREPARED"
	StatePrepared    State = "PREPARED"
	StateCommitted   State = "COMMITTED"
)

// Validator is one org's L1 participant. It never double-signs a digest
// at the same (epoch, slot): that obligation is the safety core (T1).
type Validator struct {
	Org     string
	Key     ed25519.PrivateKey
	Pub     ed25519.PublicKey
	Weights *WeightVector // frozen at round entry

	state    State
	epoch    int64
	slot     uint64
	proposal *Decision

	prepares map[string]map[string]Vote // digest -> org -> vote
	commits  map[string]map[string]Vote // digest -> org -> vote

	// certified is the append-only decision log this validator applied.
	certified []Applied
}

// Applied is one committed decision plus its certificate.
type Applied struct {
	Epoch  int64  `json:"epoch"`
	Slot   uint64 `json:"slot"`
	Digest string `json:"digest"`
	Cert   Cert   `json:"cert"`
}

// NewValidator constructs an idle validator for org.
func NewValidator(org string, key ed25519.PrivateKey, w *WeightVector) *Validator {
	return &Validator{
		Org: org, Key: key, Pub: key.Public().(ed25519.PublicKey), Weights: w,
		state: StateIdle, prepares: map[string]map[string]Vote{}, commits: map[string]map[string]Vote{},
	}
}

// Epoch / Slot / Phase expose current round context.
func (v *Validator) Epoch() int64 { return v.epoch }
func (v *Validator) Slot() uint64 { return v.slot }
func (v *Validator) Phase() State { return v.state }

// Log returns the applied decision log.
func (v *Validator) Log() []Applied { return append([]Applied(nil), v.certified...) }

// Propose starts a round as leader and returns the PRE-PREPARE decision.
// L is the leader; a validator refuses to propose for another org.
func (v *Validator) Propose(leader string, epoch int64, slot uint64, p Proposal) (*Decision, error) {
	if leader != v.Org {
		return nil, fmt.Errorf("l1: %s is not leader %s", v.Org, leader)
	}
	p.Epoch, p.Slot = epoch, slot
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	d := &Decision{Epoch: epoch, Slot: slot, Proposal: body, Leader: leader, WeightHash: weightHash(v.Weights)}
	d.Digest = decisionDigest(*d)
	v.epoch, v.slot, v.proposal, v.state = epoch, slot, d, StatePrePrepared
	return d, nil
}

// OnPrePrepare handles a leader's proposal: verify the digest and the
// frozen weight epoch, then emit a PREPARE (03 §4).
func (v *Validator) OnPrePrepare(d *Decision) (*Vote, error) {
	if d.WeightHash != weightHash(v.Weights) {
		return nil, errors.New("l1: weight epoch mismatch")
	}
	if want := decisionDigest(*d); want != d.Digest {
		return nil, errors.New("l1: bad decision digest")
	}
	if v.state != StateIdle && (v.epoch != d.Epoch || v.slot != d.Slot) {
		return nil, errors.New("l1: pre-prepare for a different round")
	}
	if v.state == StateIdle {
		v.epoch, v.slot, v.proposal, v.state = d.Epoch, d.Slot, d, StatePrePrepared
	}
	// Obligation 3: never two PREPAREs with different digests at (e,s).
	if m := v.prepares[d.Digest]; m != nil {
		if existing, ok := m[v.Org]; ok {
			return &existing, nil // idempotent: re-delivery returns the same vote
		}
	}
	vt := Vote{MsgType: MsgPrepare, Epoch: d.Epoch, Slot: d.Slot, Digest: d.Digest, Org: v.Org}
	if err := vt.Sign(v.Key); err != nil {
		return nil, err
	}
	v.record(vt)
	return &vt, nil
}

// record stores a vote, rejecting a conflicting one from this org.
func (v *Validator) record(vt Vote) error {
	var bucket map[string]map[string]Vote
	if vt.MsgType == MsgPrepare {
		bucket = v.prepares
	} else {
		bucket = v.commits
	}
	if bucket[vt.Digest] == nil {
		bucket[vt.Digest] = map[string]Vote{}
	}
	bucket[vt.Digest][vt.Org] = vt
	return nil
}

// AddVote ingests a peer's PREPARE/COMMIT, verifies it, and advances the
// phase. It returns a COMMIT vote when the PREPARE quorum is reached,
// and an applied decision when the COMMIT quorum is reached.
func (v *Validator) AddVote(vt Vote, pub ed25519.PublicKey) (next *Vote, applied *Applied, err error) {
	if !vt.Verify(pub) {
		return nil, nil, errors.New("l1: invalid vote signature")
	}
	if vt.Epoch != v.epoch || vt.Slot != v.slot {
		return nil, nil, errors.New("l1: vote for a different round")
	}
	switch vt.MsgType {
	case MsgPrepare:
		if v.proposal == nil || vt.Digest != v.proposal.Digest {
			return nil, nil, nil // prepare for a digest we did not adopt
		}
		if v.prepares[vt.Digest] == nil {
			v.prepares[vt.Digest] = map[string]Vote{}
		}
		v.prepares[vt.Digest][vt.Org] = vt
		if v.state == StatePrePrepared &&
			QuorumWeight(mapValues(v.prepares[vt.Digest]), vt.Digest, v.Weights) > 2.0/3.0 {
			v.state = StatePrepared
			c := Vote{MsgType: MsgCommit, Epoch: v.epoch, Slot: v.slot, Digest: vt.Digest, Org: v.Org}
			if err := c.Sign(v.Key); err != nil {
				return nil, nil, err
			}
			v.record(c)
			return &c, nil, nil
		}
	case MsgCommit:
		if v.proposal == nil || vt.Digest != v.proposal.Digest {
			return nil, nil, nil
		}
		if v.commits[vt.Digest] == nil {
			v.commits[vt.Digest] = map[string]Vote{}
		}
		v.commits[vt.Digest][vt.Org] = vt
		if v.state != StateCommitted &&
			QuorumWeight(mapValues(v.commits[vt.Digest]), vt.Digest, v.Weights) > 2.0/3.0 {
			v.state = StateCommitted
			cert := Cert{Epoch: v.epoch, Slot: v.slot, Digest: vt.Digest,
				Commits: mapValues(v.commits[vt.Digest]), Weight: weightHash(v.Weights)}
			a := Applied{Epoch: v.epoch, Slot: v.slot, Digest: vt.Digest, Cert: cert}
			v.certified = append(v.certified, a)
			return nil, &a, nil
		}
	}
	return nil, nil, nil
}

// CommitCertificate returns the certificate for a committed digest.
func (v *Validator) CommitCertificate(digest string) (Cert, bool) {
	for _, a := range v.certified {
		if a.Digest == digest {
			return a.Cert, true
		}
	}
	return Cert{}, false
}

// Advance returns the validator to IDLE for the next slot, carrying the
// frozen weights forward (reweight happens only at epoch boundaries).
func (v *Validator) Advance() {
	v.state = StateIdle
	v.proposal = nil
	v.prepares = map[string]map[string]Vote{}
	v.commits = map[string]map[string]Vote{}
	v.slot++
}

func mapValues(m map[string]Vote) []Vote {
	out := make([]Vote, 0, len(m))
	for _, vt := range m {
		out = append(out, vt)
	}
	return out
}

// Observation converts an applied decision into a seam observation so
// L0's proactive gate can consume it (01 §7.4).
func (a Applied) Observation(org string, ts int64, seq uint64, priv ed25519.PrivateKey) (*l0.Observation, error) {
	payload, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	o := l0.NewObservation(l0.ObsDecision, org, ts, seq, "l1://decision/"+a.Digest, payload)
	if err := o.Sign(priv); err != nil {
		return nil, err
	}
	return o, nil
}