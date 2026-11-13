// Package transport implements enrollment, the signed HTTP client, the
// offline spool, and the WebSocket/polling command channel.
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/signing"
)

// Identity is the persisted enrollment result.
type Identity struct {
	HostID    string `json:"host_id"`
	ServerURL string `json:"server_url"`
	// ServerPubKey is the pinned raw 32-byte Ed25519 key, base64.
	ServerPubKey string `json:"server_pubkey"`

	Priv ed25519.PrivateKey `json:"-"`
}

// ServerPub decodes the pinned server key.
func (i *Identity) ServerPub() (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(i.ServerPubKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("identity: invalid pinned server_pubkey")
	}
	return ed25519.PublicKey(b), nil
}

func keyPath(dir string) string      { return filepath.Join(dir, "agent.key") }
func identityPath(dir string) string { return filepath.Join(dir, "identity.json") }

// LoadOrCreateKey returns the agent's Ed25519 key, generating and saving it
// (0600) on first use. The file holds base64 of the 32-byte seed.
func LoadOrCreateKey(dataDir string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(keyPath(dataDir))
	if err == nil {
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("agent.key is corrupt")
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath(dataDir), []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadIdentity loads identity.json and the key. ErrNotEnrolled if absent.
var ErrNotEnrolled = errors.New("agent is not enrolled; run `aegis-agent enroll`")

func LoadIdentity(dataDir string) (*Identity, error) {
	b, err := os.ReadFile(identityPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, err
	}
	if id.HostID == "" || id.ServerURL == "" {
		return nil, errors.New("identity.json incomplete")
	}
	if _, err := id.ServerPub(); err != nil {
		return nil, err
	}
	if id.Priv, err = LoadOrCreateKey(dataDir); err != nil {
		return nil, err
	}
	return &id, nil
}

func (i *Identity) save(dataDir string) error {
	b, _ := json.MarshalIndent(i, "", "  ")
	tmp := identityPath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, identityPath(dataDir))
}

// EnrollRequest is the POST /v1/enroll body.
type EnrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Kernel       string `json:"kernel"`
	AgentVersion string `json:"agent_version"`
	Pubkey       string `json:"pubkey"`
}

// EnrollResponse is the POST /v1/enroll response.
type EnrollResponse struct {
	HostID       string           `json:"host_id"`
	ServerPubkey string           `json:"server_pubkey"`
	Policy       signing.Envelope `json:"policy"`
}

// Enroll registers this host, pins the server key and persists identity.
// It returns the identity and the (already verified) initial policy envelope.
func Enroll(ctx context.Context, serverURL, token, dataDir, version string) (*Identity, signing.Envelope, error) {
	var zero signing.Envelope
	u, err := url.Parse(serverURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, zero, fmt.Errorf("invalid server URL %q", serverURL)
	}
	priv, err := LoadOrCreateKey(dataDir)
	if err != nil {
		return nil, zero, err
	}
	host, _ := os.Hostname()
	kernel := runtime.GOOS
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(b))
	}
	body, _ := json.Marshal(EnrollRequest{
		Token: token, Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Kernel: kernel,
		AgentVersion: version, Pubkey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
	})
	endpoint := strings.TrimRight(serverURL, "/") + "/v1/enroll"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, zero, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, zero, fmt.Errorf("enroll failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var er EnrollResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return nil, zero, fmt.Errorf("enroll response: %w", err)
	}
	id := &Identity{HostID: er.HostID, ServerURL: strings.TrimRight(serverURL, "/"), ServerPubKey: er.ServerPubkey, Priv: priv}
	pub, err := id.ServerPub()
	if err != nil || id.HostID == "" {
		return nil, zero, errors.New("enroll response missing host_id or valid server_pubkey")
	}
	if _, err := signing.VerifyEnvelope(pub, er.Policy); err != nil {
		return nil, zero, fmt.Errorf("enroll policy failed verification against server_pubkey: %w", err)
	}
	if err := id.save(dataDir); err != nil {
		return nil, zero, err
	}
	return id, er.Policy, nil
}
