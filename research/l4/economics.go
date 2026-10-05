// Package l4 implements the incentive layer for the TrustFabric
// program: a token-free reputation mechanism whose update rule depends
// only on verified events, plus proper-scoring for witness alarms and a
// sybil analysis. See doc/06-L4-trust-economics.md.
//
// The reputation ledger is itself an append-only signed log, so the
// economics are auditable at the same bar as the security (06 §2).
package l4

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
)

// UpdateRule is the public, versioned reputation update (06 §2):
//
//	r_i(t+1) = alpha*r_i(t) + (1-alpha)*s_i(t)
//
// where s_i(t) is a quality score derived only from verified events.
type UpdateRule struct {
	Alpha float64 `json:"alpha"` // forgetting factor, 0<alpha<1
}

// DefaultUpdateRule is the v1 rule (06 §2).
func DefaultUpdateRule() UpdateRule { return UpdateRule{Alpha: 0.8} }

// Update applies U to one actor's reputation given its epoch score,
// clamped to [0,1] (P2, bounded).
func (u UpdateRule) Update(prev float64, s float64) float64 {
	v := u.Alpha*prev + (1-u.Alpha)*s
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	return v
}

// ---------------------------------------------------------------------
// The score ledger: append-only, signed, dedup by observation hash (P3)
// ---------------------------------------------------------------------

// Entry is one signed reputation-moving observation.
type Entry struct {
	Actor string  `json:"actor"`
	Kind  string  `json:"kind"`  // the verified event kind (06 §2 table)
	Delta float64 `json:"delta"` // contribution to s_i(t)
	Ref   string  `json:"ref"`   // hash of the justifying observation
	Epoch int64   `json:"epoch"`
	Sig   []byte  `json:"sig"`
}

type entryShape struct {
	Actor string  `json:"actor"`
	Kind  string  `json:"kind"`
	Delta float64 `json:"delta"`
	Ref   string  `json:"ref"`
	Epoch int64   `json:"epoch"`
}

// SigningBytes is the canonical entry bytes covered by Sig.
func (e *Entry) SigningBytes() []byte {
	b, _ := json.Marshal(entryShape{e.Actor, e.Kind, e.Delta, e.Ref, e.Epoch})
	return b
}

// Sign sets Sig over the canonical bytes.
func (e *Entry) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("l4: bad private key length")
	}
	e.Sig = ed25519.Sign(priv, e.SigningBytes())
	return nil
}

// Verify checks the entry signature.
func (e *Entry) Verify(pub ed25519.PublicKey) bool {
	if e == nil || len(pub) != ed25519.PublicKeySize || len(e.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, e.SigningBytes(), e.Sig)
}

// Hash is the entry's dedup key.
func (e *Entry) Hash() string {
	h := sha256.Sum256(append(e.SigningBytes(), e.Sig...))
	return hex.EncodeToString(h[:])
}

// Ledger is the append-only, signed score ledger (06 §2). Every entry
// must verify and be unique (P3: no double-spend).
type Ledger struct {
	rule    UpdateRule
	entries []Entry
	seen    map[string]bool
	rep     map[string]float64
}

// NewLedger starts an empty ledger under a rule.
func NewLedger(rule UpdateRule) *Ledger {
	return &Ledger{rule: rule, seen: map[string]bool{}, rep: map[string]float64{}}
}

// Append verifies and records a reputation-moving observation, updating
// the actor's reputation. Duplicate refs are rejected (P3).
func (l *Ledger) Append(e Entry, pub ed25519.PublicKey) error {
	if !e.Verify(pub) {
		return errors.New("l4: ledger rejects unverified entry")
	}
	h := e.Hash()
	if l.seen[h] || (e.Ref != "" && l.seen[e.Ref]) {
		return errors.New("l4: duplicate observation (no double-spend)")
	}
	l.seen[h] = true
	if e.Ref != "" {
		l.seen[e.Ref] = true
	}
	l.entries = append(l.entries, e)
	prev := l.rep[e.Actor]
	l.rep[e.Actor] = l.rule.Update(prev, clamp01(prev+e.Delta))
	return nil
}

// Reputation returns an actor's current reputation.
func (l *Ledger) Reputation(actor string) float64 { return l.rep[actor] }

// Entries returns the ledger contents.
func (l *Ledger) Entries() []Entry { return append([]Entry(nil), l.entries...) }

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// ---------------------------------------------------------------------
// Proper scoring for witness alarms (06 §3)
// ---------------------------------------------------------------------

// LogScore is the logarithmic proper scoring rule: for outcome y (1 =
// fork, 0 = no fork), reporting r is expected-maximized at r = p.
func LogScore(y int, r float64) float64 {
	if r <= 0 {
		r = 1e-9
	}
	if r >= 1 {
		r = 1 - 1e-9
	}
	if y == 1 {
		return math.Log(r)
	}
	return math.Log(1 - r)
}

// TruthfulIsOptimal checks the defining property numerically: over a
// grid of reports, the truthful report maximizes expected score.
func TruthfulIsOptimal(p float64) bool {
	best, bestR := math.Inf(-1), 0.0
	for i := 1; i < 100; i++ {
		r := float64(i) / 100
		exp := p*LogScore(1, r) + (1-p)*LogScore(0, r)
		if exp > best {
			best, bestR = exp, r
		}
	}
	return math.Abs(bestR-p) < 0.02
}

// ---------------------------------------------------------------------
// Sybil analysis (06 §4)
// ---------------------------------------------------------------------

// SybilCost is the verified honest effort an adversary must expend for
// fake identities to hold a fraction phi of weight over time T. Under
// P1-P3 the barrier grows with network age (06 §4).
func SybilCost(phi, T float64) float64 { return phi * T }

// EnrollmentRejectsSybil reports whether an enrollment attempt with the
// given verified-history depth fails the time-and-score barrier.
func EnrollmentRejectsSybil(depthEpochs, minDepth int) bool { return depthEpochs < minDepth }

// ---------------------------------------------------------------------
// Recovery commitment mechanism (06 §5)
// ---------------------------------------------------------------------

// RecoveryCommitment is a signed promise to contribute to up to Kappa
// recoveries this epoch. Completing earns +g; missing a committed
// recovery loses -2g (06 §5).
type RecoveryCommitment struct {
	Org   string  `json:"org"`
	Kappa int     `json:"kappa"`
	Epoch int64   `json:"epoch"`
	G     float64 `json:"g"`
	Sig   []byte  `json:"sig"`
}

type commitmentShape struct {
	Org   string  `json:"org"`
	Kappa int     `json:"kappa"`
	Epoch int64   `json:"epoch"`
	G     float64 `json:"g"`
}

// SigningBytes is the canonical bytes covered by Sig.
func (c *RecoveryCommitment) SigningBytes() []byte {
	b, _ := json.Marshal(commitmentShape{c.Org, c.Kappa, c.Epoch, c.G})
	return b
}

// Sign sets Sig over the canonical bytes.
func (c *RecoveryCommitment) Sign(priv ed25519.PrivateKey) error {
	if len(c.Sig) != 0 {
		return errors.New("l4: commitment already signed")
	}
	c.Sig = ed25519.Sign(priv, c.SigningBytes())
	return nil
}

// Verify checks the commitment signature.
func (c *RecoveryCommitment) Verify(pub ed25519.PublicKey) bool {
	if c == nil || len(pub) != ed25519.PublicKeySize || len(c.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, c.SigningBytes(), c.Sig)
}

// RecoveryPayoff is the net reputation change for a committed org that
// completed c recoveries and missed m committed ones.
func RecoveryPayoff(g float64, completed, missed int) float64 {
	return g*float64(completed) - 2*g*float64(missed)
}

// DefectingIsUnprofitable checks the mechanism property (06 §5): when
// g >= the worst-case opportunity cost, completing dominates defecting.
func DefectingIsUnprofitable(g, worstCaseCost float64) bool { return g >= worstCaseCost }

// ---------------------------------------------------------------------
// Pricing (06 §6)
// ---------------------------------------------------------------------

// WeightFromReputation derives L1 quorum weights from reputation, capped
// at 1/3 - eps so no single org reaches the Byzantine threshold alone.
func WeightFromReputation(rep map[string]float64, eps float64) map[string]float64 {
	total := 0.0
	for _, v := range rep {
		total += v
	}
	out := map[string]float64{}
	if total == 0 {
		return out
	}
	limit := 1.0/3.0 - eps
	orgs := make([]string, 0, len(rep))
	for o := range rep {
		orgs = append(orgs, o)
	}
	sort.Strings(orgs)
	for _, o := range orgs {
		w := rep[o] / total
		if w > limit {
			w = limit
		}
		out[o] = w
	}
	return out
}

// ---------------------------------------------------------------------
// Agent-based simulation (06 §7)
// ---------------------------------------------------------------------

// AgentType is a player archetype (06 §1).
type AgentType string

const (
	TypeHonest    AgentType = "honest"
	TypeLazy      AgentType = "lazy"
	TypeMalicious AgentType = "malicious"
	TypeSybil     AgentType = "sybil"
)

// Agent is one simulated org.
type Agent struct {
	Name string
	Type AgentType
}

// scoreFor maps an archetype to its per-epoch verified quality score.
func scoreFor(t AgentType) float64 {
	switch t {
	case TypeHonest:
		return 1.0
	case TypeLazy:
		return 0.4
	case TypeMalicious:
		return 0.0
	case TypeSybil:
		return 0.2
	default:
		return 0.0
	}
}

// Simulate runs the reputation dynamics for epochs rounds over the given
// population, returning final reputations. Honest agents keep their
// score; lazy/malicious/sybil agents are penalized on the verifiable
// signals they miss (06 §2 s_i table).
func Simulate(rule UpdateRule, agents []Agent, epochs int) map[string]float64 {
	rep := map[string]float64{}
	for _, a := range agents {
		rep[a.Name] = 0.5 // genesis: uniform prior
	}
	for t := 0; t < epochs; t++ {
		for _, a := range agents {
			rep[a.Name] = rule.Update(rep[a.Name], scoreFor(a.Type))
		}
	}
	return rep
}

// HonestyDominates reports whether honest agents end strictly above
// every non-honest type (the equilibrium property 06 §7 targets).
func HonestyDominates(final map[string]float64, agents []Agent) bool {
	honestMin := math.Inf(1)
	cheatMax := math.Inf(-1)
	for _, a := range agents {
		if a.Type == TypeHonest {
			if final[a.Name] < honestMin {
				honestMin = final[a.Name]
			}
		} else if final[a.Name] > cheatMax {
			cheatMax = final[a.Name]
		}
	}
	return honestMin > cheatMax
}