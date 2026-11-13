// Package signing implements the Ed25519 request-signing and envelope
// verification rules from docs/PROTOCOL.md.
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// Envelope is the PROTOCOL.md SignedEnvelope: payload is base64(JSON bytes),
// sig is base64(ed25519 signature over the raw JSON bytes).
type Envelope struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// Canonical builds METHOD "\n" PATH "\n" TS "\n" hex(sha256(body)).
func Canonical(method, path string, ts int64, body []byte) string {
	sum := sha256.Sum256(body)
	return method + "\n" + path + "\n" + strconv.FormatInt(ts, 10) + "\n" + hex.EncodeToString(sum[:])
}

// SignRequest returns base64(ed25519_sign(priv, canonical)).
func SignRequest(priv ed25519.PrivateKey, method, path string, ts int64, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(Canonical(method, path, ts, body))))
}

// VerifyEnvelope checks env against pub and returns the raw JSON payload.
func VerifyEnvelope(pub ed25519.PublicKey, env Envelope) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("signing: invalid public key")
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("signing: payload base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return nil, fmt.Errorf("signing: sig base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, raw, sig) {
		return nil, errors.New("signing: bad signature")
	}
	return raw, nil
}

// SignEnvelope signs raw JSON bytes (used by tests and tooling).
func SignEnvelope(priv ed25519.PrivateKey, raw []byte) Envelope {
	return Envelope{
		Payload: base64.StdEncoding.EncodeToString(raw),
		Sig:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)),
	}
}
