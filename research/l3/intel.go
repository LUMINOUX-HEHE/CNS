// Package l3 implements threat intelligence for the TrustFabric
// program: pooling per-org detection signals into cross-org correlation
// and signed risk advice, without any participant (including the
// aggregator) learning an org's raw data. See
// doc/05-L3-threat-intelligence.md.
//
// Two privacy layers (05 §3):
//   - secure aggregation: pairwise one-time-pad masks cancel, so the
//     aggregator sees only the masked sum, never an org's row;
//   - differential privacy: calibrated Laplace noise on the released
//     aggregate, with an explicit, published (ε,δ) budget ledger.
//
// Detection is streaming CUSUM over the *noised* aggregate (05 §4.2).
// The package is deterministic given a seed, so the ε-sweep is
// reproducible.
package l3

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"

	"trustorchestrator/research/l0"
)

// Signals is one org's per-epoch signal vector (05 §2).
type Signals struct {
	AlarmCounts      map[string]float64 `json:"alarm_counts"`
	ImportCount      float64            `json:"import_count"`
	RejectCount      float64            `json:"reject_count"`
	KeyRotations     float64            `json:"key_rotations"`
	AvgKeyAge        float64            `json:"avg_key_age"`
	StaleSTHSeconds  float64            `json:"stale_sth_seconds"`
	SCPFailures      float64            `json:"scp_failures"`
}

// flatten turns a signal vector into a deterministic ordered slice so
// masking and aggregation are well-defined.
func (s Signals) flatten() ([]string, []float64) {
	keys := []string{"import_count", "reject_count", "key_rotations", "avg_key_age", "stale_sth_seconds", "scp_failures"}
	vals := []float64{s.ImportCount, s.RejectCount, s.KeyRotations, s.AvgKeyAge, s.StaleSTHSeconds, s.SCPFailures}
	names := append([]string(nil), keys...)
	for k := range s.AlarmCounts {
		names = append(names, "alarm:"+k)
	}
	sort.Strings(names)
	ordered := make([]float64, 0, len(names))
	for _, n := range names {
		if v, ok := s.AlarmCounts[n[len("alarm:"):]]; ok && len(n) > 6 && n[:6] == "alarm:" {
			ordered = append(ordered, v)
			continue
		}
		idx := indexOf(keys, n)
		if idx >= 0 {
			ordered = append(ordered, vals[idx])
		}
	}
	return names, ordered
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------
// Secure aggregation (05 §4.1) — pairwise one-time-pad masks
// ---------------------------------------------------------------------

// mask derives the pairwise mask org i and org j share, from a per-epoch
// secret. In v1 the "non-colluding pair of aggregators" holds the seeds;
// here the seed is explicit so the protocol is testable.
func mask(seed []byte, a, b string, n int) []float64 {
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	out := make([]float64, n)
	for k := 0; k < n; k++ {
		mac := hmac.New(sha256.New, seed)
		mac.Write([]byte(lo))
		mac.Write([]byte{0})
		mac.Write([]byte(hi))
		var kb [8]byte
		binary.BigEndian.PutUint64(kb[:], uint64(k))
		mac.Write(kb[:])
		d := mac.Sum(nil)
		// map 8 bytes to a signed float in [-1,1)
		u := binary.BigEndian.Uint64(d[:8])
		out[k] = (float64(u)/float64(math.MaxUint64))*2 - 1
	}
	return out
}

// MaskedShare is one org's contribution: its signal plus its pairwise
// masks, ready for the aggregator.
type MaskedShare struct {
	Org   string    `json:"org"`
	Vec   []float64 `json:"vec"`
	Names []string  `json:"names"`
}

// ProduceShare masks org's signal vector with all peers. Every pair
// (i,j) applies the same mask with opposite sign, so the sum over all
// orgs is the true sum with masks cancelled.
func ProduceShare(org string, s Signals, peers []string, seed []byte) MaskedShare {
	names, vec := s.flatten()
	shared := sharedNames(names, peers)
	out := make([]float64, len(shared))
	copy(out, alignTo(shared, names, vec))
	for _, p := range peers {
		if p == org {
			continue
		}
		m := mask(seed, org, p, len(shared))
		sign := 1.0
		if org > p {
			sign = -1.0
		}
		for k := range out {
			out[k] += sign * m[k]
		}
	}
	return MaskedShare{Org: org, Vec: out, Names: shared}
}

// sharedNames is the union of all orgs' signal names, sorted, so every
// share is a vector over the same basis before masking.
func sharedNames(local []string, peers []string) []string {
	seen := map[string]bool{}
	for _, n := range local {
		seen[n] = true
	}
	// peers may carry extra signals; include a superset by convention:
	// callers pass the known global names through peers' presence. To
	// keep the basis stable we always include the canonical core names.
	core := []string{"alarm:compromise", "alarm:rewrite", "import_count",
		"reject_count", "key_rotations", "avg_key_age", "stale_sth_seconds", "scp_failures"}
	for _, n := range core {
		seen[n] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func alignTo(shared, local []string, vec []float64) []float64 {
	out := make([]float64, len(shared))
	for i, n := range shared {
		if j := indexOf(local, n); j >= 0 {
			out[i] = vec[j]
		}
	}
	return out
}

// Aggregate cancels the masks and returns the raw summed vector. The
// aggregator learns only this sum (05 §4.1).
func Aggregate(shares []MaskedShare) ([]string, []float64, error) {
	if len(shares) == 0 {
		return nil, nil, errors.New("l3: no shares")
	}
	n := len(shares[0].Vec)
	sum := make([]float64, n)
	for _, sh := range shares {
		if len(sh.Vec) != n {
			return nil, nil, errors.New("l3: share length mismatch")
		}
		for k := range sum {
			sum[k] += sh.Vec[k]
		}
	}
	return shares[0].Names, sum, nil
}

// ---------------------------------------------------------------------
// Differential privacy (05 §3) — Laplace mechanism + budget ledger
// ---------------------------------------------------------------------

// Laplacian draws Laplace(0, scale) using the inverse-CDF method.
func laplacian(scale float64, r *randReader) float64 {
	u := r.Float64() - 0.5
	if u == 0 {
		u = 1e-12
	}
	return -scale * math.Copysign(math.Log(1-2*math.Abs(u)), u)
}

// randReader is a tiny deterministic PRNG so the ε-sweep reproduces.
type randReader struct{ s uint64 }

func newRand(seed uint64) *randReader {
	if seed == 0 {
		var b [8]byte
		rand.Read(b[:])
		seed = binary.BigEndian.Uint64(b[:])
	}
	return &randReader{s: seed}
}

func (r *randReader) Uint64() uint64 {
	// splitmix64
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *randReader) Float64() float64 {
	return float64(r.Uint64()>>11) / float64(1<<53)
}

// BudgetLedger tracks per-org ε,δ spend (05 §3 layer 3). Each published
// aggregate carries its cost; an org can verify how much it donated.
type BudgetLedger struct {
	eps   map[string]float64
	delta map[string]float64
	maxEps float64
}

// NewLedger starts a ledger with a per-org epoch budget cap.
func NewLedger(maxEps float64) *BudgetLedger {
	return &BudgetLedger{eps: map[string]float64{}, delta: map[string]float64{}, maxEps: maxEps}
}

// Charge records spend for an org; returns false if the cap is exceeded
// (the org must wait or accept lower precision).
func (b *BudgetLedger) Charge(org string, eps, delta float64) bool {
	if b.eps[org]+eps > b.maxEps {
		return false
	}
	b.eps[org] += eps
	b.delta[org] += delta
	return true
}

// Spent reports an org's accumulated (ε,δ).
func (b *BudgetLedger) Spent(org string) (eps, delta float64) { return b.eps[org], b.delta[org] }

// DPRelease is the public, signed aggregate plus its published budget.
type DPRelease struct {
	Epoch   int64    `json:"epoch"`
	Names   []string `json:"names"`
	Values  []float64 `json:"values"`
	Eps     float64  `json:"eps"`
	Delta   float64  `json:"delta"`
	Sig     []byte   `json:"sig"`
}

type releaseShape struct {
	Epoch  int64     `json:"epoch"`
	Names  []string  `json:"names"`
	Values []float64 `json:"values"`
	Eps    float64   `json:"eps"`
	Delta  float64   `json:"delta"`
}

// SigningBytes is the canonical bytes covered by Sig.
func (r *DPRelease) SigningBytes() []byte {
	b, _ := json.Marshal(releaseShape{r.Epoch, r.Names, r.Values, r.Eps, r.Delta})
	return b
}

// Sign sets Sig over the canonical bytes.
func (r *DPRelease) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("l3: bad private key length")
	}
	r.Sig = ed25519.Sign(priv, r.SigningBytes())
	return nil
}

// Verify checks the aggregate signature.
func (r *DPRelease) Verify(pub ed25519.PublicKey) bool {
	if r == nil || len(pub) != ed25519.PublicKeySize || len(r.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, r.SigningBytes(), r.Sig)
}

// Release applies the Laplace mechanism to a summed vector. Sensitivity
// is the max an org's row can change one coordinate (clipped upstream);
// scale = sensitivity/ε. The published (ε,δ) is attached.
func Release(epoch int64, names []string, sum []float64, nOrgs int, sensitivity, eps, delta float64, seed uint64) *DPRelease {
	r := newRand(seed)
	scale := sensitivity / eps
	vals := make([]float64, len(sum))
	for i, v := range sum {
		mean := v / float64(nOrgs) // aggregate is a mean over orgs
		vals[i] = mean + laplacian(scale/float64(nOrgs), r)
	}
	return &DPRelease{Epoch: epoch, Names: names, Values: vals, Eps: eps, Delta: delta}
}

// ---------------------------------------------------------------------
// Noise-aware CUSUM (05 §4.2)
// ---------------------------------------------------------------------

// CUSUMDetector runs CUSUM over a noised coordinate. The threshold h is
// raised above the noise scale so the false-positive rate stays at
// target despite DP noise (the paper's central plot).
type CUSUMDetector struct {
	mu0, delta, h float64
	S             float64
}

// NewCUSUMDetector derives (k, h) from the noise scale: k is set to half
// the minimal detectable shift plus a noise allowance, h to a multiple
// of the noise standard deviation.
func NewCUSUMDetector(mu0, minShift, noiseScale float64) *CUSUMDetector {
	sigma := math.Sqrt2 * noiseScale // Laplace std = sqrt(2)*scale
	return &CUSUMDetector{mu0: mu0, delta: minShift + sigma, h: 4 * sigma}
}

// Observe feeds one noised sample; returns true when alarmed.
func (c *CUSUMDetector) Observe(x float64) bool {
	c.S = math.Max(0, c.S+(x-c.mu0)-c.delta)
	return c.S >= c.h
}

// ---------------------------------------------------------------------
// Correlation and RISK_FEED (05 §4.3)
// ---------------------------------------------------------------------

// Correlation finds fingerprints seen in at least minOrgs distinct orgs
// within window (seconds), using only the seam registry's public index.
func Correlation(reg *l0.Registry, minOrgs int, now, window int64) []l0.Fingerprint {
	var out []l0.Fingerprint
	for _, e := range reg.Snapshot() {
		if len(e.Orgs) >= minOrgs && now-e.LastSeen <= window {
			out = append(out, e)
		}
	}
	return out
}

// RiskFeed is the signed per-org advisory (05 §4.3). Recommendations
// are suggestions; L0's proactive gate decides (05 §7).
type RiskFeed struct {
	Org          string   `json:"org"`
	RiskVector   []float64 `json:"risk_vector"`
	Actions      []string `json:"recommended_actions"`
	Confidence   float64  `json:"confidence"`
	CertRefs     []string `json:"cert_refs"`
	Sig          []byte   `json:"sig"`
}

type feedShape struct {
	Org        string    `json:"org"`
	RiskVector []float64 `json:"risk_vector"`
	Actions    []string  `json:"recommended_actions"`
	Confidence float64   `json:"confidence"`
	CertRefs   []string  `json:"cert_refs"`
}

// SigningBytes is the canonical feed bytes covered by Sig.
func (f *RiskFeed) SigningBytes() []byte {
	b, _ := json.Marshal(feedShape{f.Org, f.RiskVector, f.Actions, f.Confidence, f.CertRefs})
	return b
}

// Sign sets Sig over the canonical bytes.
func (f *RiskFeed) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("l3: bad private key length")
	}
	f.Sig = ed25519.Sign(priv, f.SigningBytes())
	return nil
}

// Verify checks the feed signature.
func (f *RiskFeed) Verify(pub ed25519.PublicKey) bool {
	if f == nil || len(pub) != ed25519.PublicKeySize || len(f.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, f.SigningBytes(), f.Sig)
}

// ToObservation wraps a feed as a seam RISK_FEED observation.
func (f *RiskFeed) ToObservation(ts int64, seq uint64, priv ed25519.PrivateKey) (*l0.Observation, error) {
	payload, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	o := l0.NewObservation(l0.ObsRiskFeed, f.Org, ts, seq, "l3://risk/"+f.Org, payload)
	if err := o.Sign(priv); err != nil {
		return nil, err
	}
	return o, nil
}

// ProactiveGate is L0's decision point (05 §7, 01 §7.4): it verifies the
// feed and applies org-local policy. L3 never bypasses this.
type ProactiveGate struct {
	AllowRotation bool
}

// Apply verifies a RISK_FEED observation and returns whether the local
// org will act on it. It never forces rotation; policy gates it.
func (g ProactiveGate) Apply(o *l0.Observation, l3Key ed25519.PublicKey) (bool, error) {
	if o.ObsType != l0.ObsRiskFeed || !o.Verify(l3Key) {
		return false, errors.New("l3: gate rejects unverified feed")
	}
	var f RiskFeed
	if err := json.Unmarshal(o.Payload, &f); err != nil {
		return false, err
	}
	if !g.AllowRotation {
		return false, nil
	}
	for _, a := range f.Actions {
		if a == "rotate" {
			return true, nil
		}
	}
	return false, nil
}

// epsilonSweepResult reports detection quality at one ε (05 §6 metric).
type epsilonSweepResult struct {
	Eps     float64
	Alarmed bool
}

// SweepEpsilon runs the pipeline at a set of ε values over a benign
// baseline then a step, returning whether the step was detected. It is
// the reproducible ε-sweep the paper plots (05 §4.2).
func SweepEpsilon(epsilons []float64, baseline, step float64, epochs int, seed uint64) []epsilonSweepResult {
	var out []epsilonSweepResult
	for _, eps := range epsilons {
		r := newRand(seed)
		scale := 1.0 / eps
		det := NewCUSUMDetector(baseline, 0.5*step, scale)
		alarmed := false
		for t := 0; t < epochs; t++ {
			x := baseline
			if t >= epochs/2 {
				x = baseline + step
			}
			x += laplacian(scale, r)
			if det.Observe(x) {
				alarmed = true
			}
		}
		out = append(out, epsilonSweepResult{Eps: eps, Alarmed: alarmed})
	}
	return out
}

func fmtf(v float64) string { return fmt.Sprintf("%.3f", v) }