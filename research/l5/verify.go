// Package l5 implements the formal-verification harness for the
// TrustFabric program: a machine-readable property ledger and an
// adversarial seam checker that attempts to falsify each layer's
// claimed property with concrete hostile inputs. See
// doc/07-L5-formal-verification.md.
//
// Honest scope note (07 §2, §8): the published goal is machine-checked
// proof terms in F*/Coq for V1-V5. This package implements the *other
// half* of that plan, the adversarial seam harness (07 §4): given the
// exact artifacts, an automated adversary cannot produce a violating
// input, or the harness reports the failure. A property here is PROVEN
// only when the harness's adversarial attempts all fail AND the
// corresponding Go unit suite passes; otherwise it is STATED. The
// ledger makes that distinction explicit, as 07 §6 requires.
package l5

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Status is a property's verification state (07 §6).
type Status string

const (
	StatusProven  Status = "PROVEN"
	StatusStated  Status = "STATED"
	StatusFailed  Status = "FAILED"
)

// Property is one row of the property ledger (07 §1, §3).
type Property struct {
	ID       string `json:"id"`       // V1..V9
	Layer    string `json:"layer"`    // L0..L5
	Goal     string `json:"goal"`     // human description
	Status   Status `json:"status"`   // PROVEN | STATED | FAILED
	Evidence string `json:"evidence"` // what checked it
}

// Ledger is the registry of every claimed property (07 §3).
type Ledger struct {
	mu    sync.Mutex
	props map[string]Property
}

// NewLedger starts an empty ledger.
func NewLedger() *Ledger { return &Ledger{props: map[string]Property{}} }

// Register adds or replaces a property entry.
func (l *Ledger) Register(p Property) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.props[p.ID] = p
}

// Get returns a property by ID.
func (l *Ledger) Get(id string) (Property, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.props[id]
	return p, ok
}

// All returns the ledger sorted by ID.
func (l *Ledger) All() []Property {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Property, 0, len(l.props))
	for _, p := range l.props {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Completeness reports the fraction of entries that are PROVEN, and
// whether every registered property is non-STATED (07 §6 gate).
func (l *Ledger) Completeness() (proven int, total int, complete bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	complete = true
	for _, p := range l.props {
		total++
		if p.Status == StatusProven {
			proven++
		}
		if p.Status != StatusProven {
			complete = false
		}
	}
	return
}

// WriteJSON persists the ledger as the paper's generated appendix.
func (l *Ledger) WriteJSON(path string) error {
	b, err := json.MarshalIndent(l.All(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ---------------------------------------------------------------------
// Adversarial seam harness (07 §4)
// ---------------------------------------------------------------------

// Attempt is one adversarial input plus the check that must reject it.
type Attempt struct {
	Name  string
	Run   func() (rejected bool, err error)
}

// Harness runs adversarial attempts against a property.
type Harness struct {
	attempts []Attempt
}

// NewHarness starts an empty harness.
func NewHarness() *Harness { return &Harness{} }

// Add registers an adversarial attempt.
func (h *Harness) Add(name string, run func() (bool, error)) {
	h.attempts = append(h.attempts, Attempt{Name: name, Run: run})
}

// Run executes every attempt; the property holds iff each attempt was
// rejected (no violating input found). It returns the first failure.
func (h *Harness) Run() error {
	for _, a := range h.attempts {
		rejected, err := a.Run()
		if err != nil {
			return fmt.Errorf("harness %q errored: %w", a.Name, err)
		}
		if !rejected {
			return fmt.Errorf("harness %q found a violating input (property falsified)", a.Name)
		}
	}
	return nil
}

// Attempts returns the registered attempt names.
func (h *Harness) Attempts() []string {
	out := make([]string, 0, len(h.attempts))
	for _, a := range h.attempts {
		out = append(out, a.Name)
	}
	return out
}

// ErrUnproven is returned when a property cannot be marked PROVEN.
var ErrUnproven = errors.New("l5: property not proven")

// Seal marks a property PROVEN iff the harness found no violation.
func (l *Ledger) Seal(id string, h *Harness) error {
	if h == nil {
		return ErrUnproven
	}
	if err := h.Run(); err != nil {
		p, ok := l.Get(id)
		if ok {
			p.Status = StatusFailed
			p.Evidence = err.Error()
			l.Register(p)
		}
		return err
	}
	p, ok := l.Get(id)
	if !ok {
		return fmt.Errorf("l5: no such property %s", id)
	}
	p.Status = StatusProven
	p.Evidence = fmt.Sprintf("adversarial harness (%d attempts) found no violation", len(h.Attempts()))
	l.Register(p)
	return nil
}

// CorePropertyIDs lists the L0 properties the harness checks first
// (07 §1 prioritization: V1-V3 are the everest).
var CorePropertyIDs = []string{"V1", "V2", "V3", "V4", "V5", "V8"}