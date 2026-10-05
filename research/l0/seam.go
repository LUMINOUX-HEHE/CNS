// Package l0 (seam) implements the normative L0 seam contract from
// ../doc/01-system-architecture.md §2: signed observations, the
// cross-org key fingerprint registry, trust-edge metadata, and the
// inter-layer message envelope. L0 emits these; layers L1-L5 consume
// them. The package is stdlib-only and has no dependency on the root
// engine, so it is the stable boundary every layer compiles against.
package l0

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Observation types (01 §2.1 table).
const (
	ObsSTH      = "STH"      // tree_size, root, timestamp, log_key
	ObsAlert    = "ALERT"    // alarm text + evidence refs
	ObsRotation = "ROTATION" // key fingerprints, old/new ids, cause
	ObsRecovery = "RECOVERY" // fork hash + council signature over handoff
	ObsScore    = "SCORE"    // aggregated org-level health (no raw data)

	// Upper-layer observations (emitted by L1-L5 and consumed below).
	ObsDecision   = "DECISION"           // L1 policy decision
	ObsClaim      = "CLAIM"              // L2 private/public claim + proof
	ObsRiskFeed   = "RISK_FEED"          // L3 per-org risk vector
	ObsReputation = "REPUTATION_UPDATE"  // L4 reputation weights
	ObsVerified   = "VERIFIED_PROPERTY"  // L5 machine-checked statement
)

// Observation is one signed, canonical statement about an org. The
// signature covers canonical(obs_type, org, ts, seq, subject, payload);
// verification is ed25519.Verify(pub, canonical, sig) (01 §2.1).
type Observation struct {
	ObsType string `json:"obs_type"`
	Org     string `json:"org"`
	Ts      int64  `json:"ts"`
	Seq     uint64 `json:"seq"`
	Subject string `json:"subject"`
	Payload []byte `json:"payload_b64"`
	Sig     []byte `json:"sig"`
}

// signedShape is the exact field set the signature binds, in fixed order.
type signedShape struct {
	ObsType string `json:"obs_type"`
	Org     string `json:"org"`
	Ts      int64  `json:"ts"`
	Seq     uint64 `json:"seq"`
	Subject string `json:"subject"`
	Payload []byte `json:"payload_b64"`
}

// SigningBytes is canonical(obs_type, org, ts, seq, subject, payload):
// JSON, fixed field order, no whitespace. encoding/json emits struct
// fields in declaration order, so this is deterministic.
func (o *Observation) SigningBytes() []byte {
	b, _ := json.Marshal(signedShape{o.ObsType, o.Org, o.Ts, o.Seq, o.Subject, o.Payload})
	return b
}

// NewObservation builds an unsigned observation.
func NewObservation(obsType, org string, ts int64, seq uint64, subject string, payload []byte) *Observation {
	return &Observation{ObsType: obsType, Org: org, Ts: ts, Seq: seq, Subject: subject, Payload: payload}
}

// Sign sets Sig over the canonical bytes using the emitting org's
// observation key (distinct from the timeline key).
func (o *Observation) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("seam: bad private key length")
	}
	o.Sig = ed25519.Sign(priv, o.SigningBytes())
	return nil
}

// Verify checks the observation's signature against an observation key.
func (o *Observation) Verify(pub ed25519.PublicKey) bool {
	if o == nil || len(pub) != ed25519.PublicKeySize || len(o.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, o.SigningBytes(), o.Sig)
}

// Hash is the canonical observation hash, used as a cert_refs entry: it
// binds the whole statement including its signature.
func (o *Observation) Hash() string {
	h := sha256.Sum256(append(o.SigningBytes(), o.Sig...))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------
// 01 §2.2 — cross-org key fingerprint registry
// ---------------------------------------------------------------------

// FingerprintOf = SHA-256(cert_hash ‖ first-seen-org ‖ ts) (01 §2.2).
func FingerprintOf(certHash []byte, firstOrg string, ts int64) string {
	h := sha256.New()
	h.Write(certHash)
	h.Write([]byte(firstOrg))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	h.Write(b[:])
	return hex.EncodeToString(h.Sum(nil))
}

// Fingerprint is a registry entry: the facts are the signed observations
// that registered it; this struct is only the aggregated index.
type Fingerprint struct {
	FP         string   `json:"fp"`
	Orgs       []string `json:"orgs"`
	FirstSeen  int64    `json:"first_seen"`
	LastSeen   int64    `json:"last_seen"`
	AlarmCount int      `json:"alarm_count"`
}

// Registry is the public fingerprint index. Entries are accepted only as
// verified signed observations, so the registry cannot be poisoned by an
// unsigned write.
type Registry struct {
	mu   sync.Mutex
	byFP map[string]*Fingerprint
}

// NewRegistry starts an empty registry.
func NewRegistry() *Registry { return &Registry{byFP: map[string]*Fingerprint{}} }

// Register verifies the observation and merges its Fingerprint payload
// into the index. The observation must carry a valid signature under pub.
func (r *Registry) Register(o *Observation, pub ed25519.PublicKey) error {
	if !o.Verify(pub) {
		return errors.New("seam: registry rejects unsigned/invalid observation")
	}
	var fp Fingerprint
	if err := json.Unmarshal(o.Payload, &fp); err != nil {
		return fmt.Errorf("seam: registry payload: %w", err)
	}
	if fp.FP == "" {
		return errors.New("seam: registry payload has empty fp")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.byFP[fp.FP]
	if cur == nil {
		cp := fp
		cp.Orgs = uniqueSorted(fp.Orgs)
		r.byFP[fp.FP] = &cp
		return nil
	}
	cur.Orgs = uniqueSorted(append(cur.Orgs, fp.Orgs...))
	if fp.FirstSeen != 0 && (cur.FirstSeen == 0 || fp.FirstSeen < cur.FirstSeen) {
		cur.FirstSeen = fp.FirstSeen
	}
	if fp.LastSeen > cur.LastSeen {
		cur.LastSeen = fp.LastSeen
	}
	cur.AlarmCount += fp.AlarmCount
	return nil
}

// Lookup returns a copy of the entry for fp.
func (r *Registry) Lookup(fp string) (Fingerprint, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byFP[fp]
	if !ok {
		return Fingerprint{}, false
	}
	cp := *e
	cp.Orgs = append([]string(nil), e.Orgs...)
	return cp, true
}

// Present reports membership without revealing the entry (the predicate
// L3 correlates on; L2 authorizes richer predicates).
func (r *Registry) Present(fp string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.byFP[fp]
	return ok
}

// Snapshot returns all entries sorted by fingerprint.
func (r *Registry) Snapshot() []Fingerprint {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Fingerprint, 0, len(r.byFP))
	for _, e := range r.byFP {
		cp := *e
		cp.Orgs = append([]string(nil), e.Orgs...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out
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

// ---------------------------------------------------------------------
// 01 §2.3 — trust-edge metadata
// ---------------------------------------------------------------------

// Trust edge types (01 §2.3).
const (
	EdgeImports   = "IMPORTS"
	EdgeIssuesFor = "ISSUES_FOR"
	EdgeWitnesses = "WITNESSES"
)

// TrustEdge is a signed export of graph.go's scoped reachability: "org A
// imports/trusts keys of org B", versioned and signed.
type TrustEdge struct {
	EdgeType     string `json:"edge_type"`
	FromOrg      string `json:"from_org"`
	ToOrg        string `json:"to_org"`
	SubjectKeyFP string `json:"subject_key_fp"`
	SinceTs      int64  `json:"since_ts"`
	RevokedTs    int64  `json:"revoked_ts"`
	Sig          []byte `json:"sig"`
}

type edgeShape struct {
	EdgeType     string `json:"edge_type"`
	FromOrg      string `json:"from_org"`
	ToOrg        string `json:"to_org"`
	SubjectKeyFP string `json:"subject_key_fp"`
	SinceTs      int64  `json:"since_ts"`
	RevokedTs    int64  `json:"revoked_ts"`
}

// SigningBytes is the canonical edge bytes covered by Sig.
func (e *TrustEdge) SigningBytes() []byte {
	b, _ := json.Marshal(edgeShape{e.EdgeType, e.FromOrg, e.ToOrg, e.SubjectKeyFP, e.SinceTs, e.RevokedTs})
	return b
}

// Sign sets Sig over the canonical edge bytes.
func (e *TrustEdge) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("seam: bad private key length")
	}
	e.Sig = ed25519.Sign(priv, e.SigningBytes())
	return nil
}

// Verify checks the edge signature.
func (e *TrustEdge) Verify(pub ed25519.PublicKey) bool {
	if e == nil || len(pub) != ed25519.PublicKeySize || len(e.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, e.SigningBytes(), e.Sig)
}

// EdgeGraph is an in-memory, signed-edge reachability graph. Only edges
// that verify under their emitting org's key are admitted.
type EdgeGraph struct {
	mu    sync.Mutex
	edges []TrustEdge
	keys  map[string]ed25519.PublicKey // org -> trust-edge key
}

// NewEdgeGraph starts an empty trust-edge graph.
func NewEdgeGraph() *EdgeGraph { return &EdgeGraph{keys: map[string]ed25519.PublicKey{}} }

// SetKey binds an org's trust-edge signing key.
func (g *EdgeGraph) SetKey(org string, pub ed25519.PublicKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.keys[org] = append(ed25519.PublicKey(nil), pub...)
}

// Add verifies an edge against its from-org's bound key and stores it.
func (g *EdgeGraph) Add(e TrustEdge) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	pub, ok := g.keys[e.FromOrg]
	if !ok {
		return fmt.Errorf("seam: no trust-edge key for org %q", e.FromOrg)
	}
	if !e.Verify(pub) {
		return errors.New("seam: trust edge signature invalid")
	}
	g.edges = append(g.edges, e)
	return nil
}

// Reachable returns the set of orgs reachable from start over
// non-revoked edges (BFS), the trust-edge analogue of graph.go.
func (g *EdgeGraph) Reachable(start string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	adj := map[string][]string{}
	for _, e := range g.edges {
		if e.RevokedTs != 0 {
			continue
		}
		adj[e.FromOrg] = append(adj[e.FromOrg], e.ToOrg)
	}
	seen := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, dst := range adj[cur] {
			if !seen[dst] {
				seen[dst] = true
				queue = append(queue, dst)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Edges returns a copy of all admitted edges.
func (g *EdgeGraph) Edges() []TrustEdge {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]TrustEdge(nil), g.edges...)
}

// ---------------------------------------------------------------------
// 01 §3 — inter-layer message envelope
// ---------------------------------------------------------------------

// Message types on the envelope (01 §3 table).
const (
	MsgOBS      = "OBS"
	MsgDecision = "DECISION"
	MsgClaim    = "CLAIM"
	MsgRiskFeed = "RISK_FEED"
	MsgReputation = "REPUTATION_UPDATE"
	MsgVerified = "VERIFIED_PROPERTY"
)

// Envelope wraps every inter-layer message. cert_refs are the hashes of
// the observations that justify the body, so a verifier can re-derive
// the decision from the signed record (01 §3).
type Envelope struct {
	Layer    string          `json:"layer"`
	MsgType  string          `json:"msg_type"`
	Body     json.RawMessage `json:"body"`
	Sig      []byte          `json:"sig"`
	CertRefs []string        `json:"cert_refs"`
}

type envShape struct {
	Layer    string          `json:"layer"`
	MsgType  string          `json:"msg_type"`
	Body     json.RawMessage `json:"body"`
	CertRefs []string        `json:"cert_refs"`
}

// SigningBytes is the canonical envelope bytes covered by Sig.
func (e *Envelope) SigningBytes() []byte {
	b, _ := json.Marshal(envShape{e.Layer, e.MsgType, e.Body, e.CertRefs})
	return b
}

// Sign sets Sig over the canonical envelope bytes.
func (e *Envelope) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("seam: bad private key length")
	}
	e.Sig = ed25519.Sign(priv, e.SigningBytes())
	return nil
}

// Verify checks the envelope signature.
func (e *Envelope) Verify(pub ed25519.PublicKey) bool {
	if e == nil || len(pub) != ed25519.PublicKeySize || len(e.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, e.SigningBytes(), e.Sig)
}