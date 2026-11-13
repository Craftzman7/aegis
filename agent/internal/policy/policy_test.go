package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/signing"
)

func keys() (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	return priv, priv.Public().(ed25519.PublicKey)
}

func env(t *testing.T, priv ed25519.PrivateKey, p Policy) signing.Envelope {
	b, _ := json.Marshal(p)
	return signing.SignEnvelope(priv, b)
}

func TestApplyVerifyPersistAndReload(t *testing.T) {
	priv, pub := keys()
	path := filepath.Join(t.TempDir(), "policy.json")
	m := NewManager(pub, "h1", path)
	var got []int64
	m.Subscribe(func(p *Policy) { got = append(got, p.Version) })

	p := Policy{HostID: "h1", Version: 3, Body: Body{Thresholds: map[string]float64{"x": 2}}}
	if _, err := m.Apply(env(t, priv, p)); err != nil {
		t.Fatal(err)
	}
	if m.Version() != 3 || m.Current().Body.Threshold("x", 0) != 2 || len(got) != 2 || got[1] != 3 {
		t.Fatalf("state %v %v", m.Version(), got)
	}
	m2 := NewManager(pub, "h1", path)
	lp, err := m2.Load()
	if err != nil || lp == nil || lp.Version != 3 {
		t.Fatalf("reload: %v %v", lp, err)
	}
}

func TestRejects(t *testing.T) {
	priv, pub := keys()
	m := NewManager(pub, "h1", filepath.Join(t.TempDir(), "p.json"))
	// wrong signer
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9))
	if _, err := m.Apply(env(t, other, Policy{HostID: "h1", Version: 1})); err == nil {
		t.Fatal("foreign signature accepted")
	}
	// wrong host
	if _, err := m.Apply(env(t, priv, Policy{HostID: "h2", Version: 1})); err == nil {
		t.Fatal("wrong host accepted")
	}
	// rollback
	if _, err := m.Apply(env(t, priv, Policy{HostID: "h1", Version: 5})); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(env(t, priv, Policy{HostID: "h1", Version: 4})); err != ErrStale {
		t.Fatalf("want ErrStale, got %v", err)
	}
	if m.Version() != 5 {
		t.Fatal("version changed on rejection")
	}
	// tampered persisted file is not trusted
	m3 := NewManager(pub, "h1", m.path)
	if err := writeBad(m.path); err != nil {
		t.Fatal(err)
	}
	if _, err := m3.Load(); err == nil {
		t.Fatal("tampered persisted policy loaded")
	}
}

func writeBad(path string) error {
	b, _ := json.Marshal(signing.Envelope{Payload: "e30=", Sig: "AAAA"})
	return osWrite(path, b)
}

func TestActiveSuppression(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := Body{Suppressions: []Suppression{
		{Fingerprint: "a", ExpiresAt: "2026-01-02T00:00:00Z"},
		{Fingerprint: "b", ExpiresAt: "2025-12-31T00:00:00Z"},
	}}
	if !b.ActiveSuppression("a", now) || b.ActiveSuppression("b", now) || b.ActiveSuppression("c", now) {
		t.Fatal("suppression window logic")
	}
}

func osWrite(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }
