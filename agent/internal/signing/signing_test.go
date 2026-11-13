package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/sign_vector.json")

const vectorPath = "../../testdata/sign_vector.json"

type vector struct {
	Comment        string `json:"comment"`
	SeedHex        string `json:"seed_hex"`
	PublicKeyB64   string `json:"public_key_b64"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Ts             int64  `json:"ts"`
	Body           string `json:"body"`
	Canonical      string `json:"canonical"`
	SignatureB64   string `json:"signature_b64"`
	EnvelopeJSON   string `json:"envelope_payload_json"`
	EnvelopeB64    string `json:"envelope_payload_b64"`
	EnvelopeSigB64 string `json:"envelope_sig_b64"`
}

func keyFromSeedHex(t *testing.T, h string) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		var b byte
		for _, c := range h[i*2 : i*2+2] {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= byte(c - '0')
			default:
				b |= byte(c-'a') + 10
			}
		}
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestSignVector(t *testing.T) {
	const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	priv := keyFromSeedHex(t, seedHex)
	if *update {
		body := `{"anomalies":[]}`
		payload := `{"id":"11111111-1111-4111-8111-111111111111","host_id":"host-1","action":"collect_evidence","params":{"kind":"user_info","target":"alice"},"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:05:00Z"}`
		env := SignEnvelope(priv, []byte(payload))
		v := vector{
			Comment:        "Ed25519 is deterministic: same seed + inputs must yield identical signatures. canonical = METHOD\\nPATH\\nTS\\nhex(sha256(body)).",
			SeedHex:        seedHex,
			PublicKeyB64:   base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
			Method:         "POST",
			Path:           "/v1/events",
			Ts:             1767225600,
			Body:           body,
			Canonical:      Canonical("POST", "/v1/events", 1767225600, []byte(body)),
			SignatureB64:   SignRequest(priv, "POST", "/v1/events", 1767225600, []byte(body)),
			EnvelopeJSON:   payload,
			EnvelopeB64:    env.Payload,
			EnvelopeSigB64: env.Sig,
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	priv = keyFromSeedHex(t, v.SeedHex)
	if got := Canonical(v.Method, v.Path, v.Ts, []byte(v.Body)); got != v.Canonical {
		t.Fatalf("canonical mismatch:\n%q\n%q", got, v.Canonical)
	}
	if got := SignRequest(priv, v.Method, v.Path, v.Ts, []byte(v.Body)); got != v.SignatureB64 {
		t.Fatalf("signature mismatch: %s != %s", got, v.SignatureB64)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != v.PublicKeyB64 {
		t.Fatal("pubkey mismatch")
	}
	got, err := VerifyEnvelope(pub, Envelope{Payload: v.EnvelopeB64, Sig: v.EnvelopeSigB64})
	if err != nil || string(got) != v.EnvelopeJSON {
		t.Fatalf("envelope verify: %v %s", err, got)
	}
}

func TestCanonicalEmptyBody(t *testing.T) {
	want := "GET\n/v1/commands\n100\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := Canonical("GET", "/v1/commands", 100, nil); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestEnvelopeRejectsTamper(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)
	env := SignEnvelope(priv, []byte(`{"a":1}`))
	if _, err := VerifyEnvelope(pub, env); err != nil {
		t.Fatal(err)
	}
	bad := env
	bad.Payload = base64.StdEncoding.EncodeToString([]byte(`{"a":2}`))
	if _, err := VerifyEnvelope(pub, bad); err == nil {
		t.Fatal("tampered payload accepted")
	}
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1)).Public().(ed25519.PublicKey)
	if _, err := VerifyEnvelope(other, env); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := VerifyEnvelope(pub, Envelope{Payload: "!!", Sig: "x"}); err == nil {
		t.Fatal("garbage accepted")
	}
}
