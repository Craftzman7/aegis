// Package policy verifies, persists and distributes the signed server policy.
package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/signing"
)

// Watch is a server-added watch target.
type Watch struct {
	Kind   string `json:"kind"` // path|process|port
	Target string `json:"target"`
}

// Suppression silences a fingerprint until ExpiresAt.
type Suppression struct {
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
	Reason      string `json:"reason"`
}

// Rule is a Sigma rule delivered by policy.
type Rule struct {
	ID     string `json:"id"`
	Status string `json:"status"` // active|shadow|disabled
	YAML   string `json:"yaml"`
}

// IOC is an indicator to match.
type IOC struct {
	Type  string `json:"type"` // ip|sha256|domain
	Value string `json:"value"`
}

// Body is Policy.body from PROTOCOL.md.
type Body struct {
	LogLevel        string             `json:"log_level"`
	Thresholds      map[string]float64 `json:"thresholds"`
	Watches         []Watch            `json:"watches"`
	Suppressions    []Suppression      `json:"suppressions"`
	Rules           []Rule             `json:"rules"`
	IOCs            []IOC              `json:"iocs"`
	ServerEndpoints []string           `json:"server_endpoints"`
}

// Policy is the payload of a policy envelope.
type Policy struct {
	HostID   string `json:"host_id"`
	Version  int64  `json:"version"`
	IssuedAt string `json:"issued_at"`
	Body     Body   `json:"body"`
}

// Threshold returns thresholds[key] or def.
func (b Body) Threshold(key string, def float64) float64 {
	if v, ok := b.Thresholds[key]; ok {
		return v
	}
	return def
}

// Default returns the policy used before the first server policy arrives.
func Default() *Policy {
	return &Policy{Body: Body{LogLevel: "info", Thresholds: map[string]float64{}}}
}

// Manager verifies envelopes with the pinned server key, persists the last
// good policy, and notifies subscribers (hot-swap).
type Manager struct {
	pub    ed25519.PublicKey
	hostID string
	path   string

	mu   sync.RWMutex
	cur  *Policy
	subs []func(*Policy)
}

// NewManager creates a manager persisting to path (the signed envelope is
// stored so it is re-verified on load).
func NewManager(pub ed25519.PublicKey, hostID, path string) *Manager {
	return &Manager{pub: pub, hostID: hostID, path: path, cur: Default()}
}

// Current returns the active policy (never nil).
func (m *Manager) Current() *Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur
}

// Version returns the active policy version (0 if none).
func (m *Manager) Version() int64 { return m.Current().Version }

// Subscribe registers fn, called synchronously on every accepted policy and
// once immediately with the current one.
func (m *Manager) Subscribe(fn func(*Policy)) {
	m.mu.Lock()
	m.subs = append(m.subs, fn)
	cur := m.cur
	m.mu.Unlock()
	fn(cur)
}

// Parse verifies env and decodes the policy without applying it.
func (m *Manager) Parse(env signing.Envelope) (*Policy, error) {
	raw, err := signing.VerifyEnvelope(m.pub, env)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("policy json: %w", err)
	}
	if p.HostID != m.hostID {
		return nil, fmt.Errorf("policy host_id %q does not match %q", p.HostID, m.hostID)
	}
	if p.Body.Thresholds == nil {
		p.Body.Thresholds = map[string]float64{}
	}
	return &p, nil
}

// ErrStale is returned for a policy older than the active one.
var ErrStale = errors.New("policy: stale version")

// Apply verifies, persists and hot-swaps env. A policy with a version lower
// than the active one is rejected (rollback protection); equal versions are
// accepted idempotently.
func (m *Manager) Apply(env signing.Envelope) (*Policy, error) {
	p, err := m.Parse(env)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if p.Version < m.cur.Version {
		m.mu.Unlock()
		return nil, ErrStale
	}
	if err := m.persist(env); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.cur = p
	subs := append([]func(*Policy){}, m.subs...)
	m.mu.Unlock()
	for _, fn := range subs {
		fn(p)
	}
	return p, nil
}

func (m *Manager) persist(env signing.Envelope) error {
	b, _ := json.Marshal(env)
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// Load restores the last good policy from disk. It returns (nil, nil) when
// no policy has been persisted yet.
func (m *Manager) Load() (*Policy, error) {
	b, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var env signing.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	p, err := m.Parse(env)
	if err != nil {
		return nil, fmt.Errorf("persisted policy invalid: %w", err)
	}
	m.mu.Lock()
	m.cur = p
	subs := append([]func(*Policy){}, m.subs...)
	m.mu.Unlock()
	for _, fn := range subs {
		fn(p)
	}
	return p, nil
}

// ActiveSuppression reports whether fingerprint is suppressed at now.
func (b Body) ActiveSuppression(fp string, now time.Time) bool {
	for _, s := range b.Suppressions {
		if s.Fingerprint != fp {
			continue
		}
		if t, err := time.Parse(time.RFC3339, s.ExpiresAt); err == nil && now.Before(t) {
			return true
		}
	}
	return false
}
