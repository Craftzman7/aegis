package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/executor"
	"github.com/aegis-soc/aegis/agent/internal/signing"
)

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

// Permanent reports whether retrying the same request cannot succeed.
func (e *HTTPError) Permanent() bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != 401 && e.Status != 408 && e.Status != 429
}

// Client is the signed agent HTTP client.
type Client struct {
	base   *url.URL
	hostID string
	priv   ed25519.PrivateKey
	http   *http.Client
	now    func() time.Time
}

// NewClient builds a client for the enrolled identity.
func NewClient(id *Identity) (*Client, error) {
	u, err := url.Parse(id.ServerURL)
	if err != nil {
		return nil, err
	}
	return &Client{base: u, hostID: id.HostID, priv: id.Priv, http: &http.Client{Timeout: 30 * time.Second}, now: time.Now}, nil
}

// signedHeaders returns the PROTOCOL.md section 2 auth headers.
func (c *Client) signedHeaders(method, path string, body []byte) http.Header {
	ts := c.now().Unix()
	h := http.Header{}
	h.Set("X-Aegis-Host", c.hostID)
	h.Set("X-Aegis-Ts", strconv.FormatInt(ts, 10))
	h.Set("X-Aegis-Sig", signing.SignRequest(c.priv, method, path, ts, body))
	return h
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.base.String(), "/") + path
}

// Do performs a signed request. body (if non-nil) is JSON-encoded; out (if
// non-nil) receives the JSON response.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	for k, v := range c.signedHeaders(method, path, raw) {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// PostEvents implements EventPoster.
func (c *Client) PostEvents(ctx context.Context, batch []event.Anomaly) error {
	return c.Do(ctx, http.MethodPost, "/v1/events", map[string]any{"anomalies": batch}, nil)
}

// HeartbeatStats mirrors the heartbeat stats block.
type HeartbeatStats struct {
	EventsPerMin    float64 `json:"events_per_min"`
	AnomaliesPerMin float64 `json:"anomalies_per_min"`
	RulesLoaded     int     `json:"rules_loaded"`
	BufferEvents    int     `json:"buffer_events"`
}

// RuleError is a per-rule load failure.
type RuleError struct {
	RuleID string `json:"rule_id"`
	Error  string `json:"error"`
}

// Heartbeat is the POST /v1/heartbeat body.
type Heartbeat struct {
	AgentVersion  string         `json:"agent_version"`
	PolicyVersion int64          `json:"policy_version"`
	UptimeS       int64          `json:"uptime_s"`
	Stats         HeartbeatStats `json:"stats"`
	RuleErrors    []RuleError    `json:"rule_errors"`
	WSConnected   bool           `json:"ws_connected"`
}

// SendHeartbeat posts hb and returns the server's latest policy version.
func (c *Client) SendHeartbeat(ctx context.Context, hb Heartbeat) (int64, error) {
	var out struct {
		PolicyVersion int64 `json:"policy_version"`
	}
	err := c.Do(ctx, http.MethodPost, "/v1/heartbeat", hb, &out)
	return out.PolicyVersion, err
}

// GetPolicy fetches the current signed policy.
func (c *Client) GetPolicy(ctx context.Context) (signing.Envelope, error) {
	var env signing.Envelope
	err := c.Do(ctx, http.MethodGet, "/v1/policy", nil, &env)
	return env, err
}

// GetCommands fetches pending commands.
func (c *Client) GetCommands(ctx context.Context) ([]signing.Envelope, error) {
	var out struct {
		Commands []signing.Envelope `json:"commands"`
	}
	err := c.Do(ctx, http.MethodGet, "/v1/commands", nil, &out)
	return out.Commands, err
}

// PostResult reports a command result.
func (c *Client) PostResult(ctx context.Context, r executor.CommandResult) error {
	return c.Do(ctx, http.MethodPost, "/v1/results", r, nil)
}
