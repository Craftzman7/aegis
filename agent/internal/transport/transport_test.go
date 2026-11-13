package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/executor"
	"github.com/aegis-soc/aegis/agent/internal/signing"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func serverKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(make([]byte, 32)) }

// verifyAuth is what the server does with the auth headers.
func verifyAuth(t *testing.T, r *http.Request, pub ed25519.PublicKey, body []byte) {
	t.Helper()
	ts, _ := strconv.ParseInt(r.Header.Get("X-Aegis-Ts"), 10, 64)
	if d := time.Since(time.Unix(ts, 0)); d > time.Minute || d < -time.Minute {
		t.Errorf("ts skew %v", d)
	}
	sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Aegis-Sig"))
	canon := r.Method + "\n" + r.URL.Path + "\n" + strconv.FormatInt(ts, 10) + "\n" + hexSHA(body)
	if !ed25519.Verify(pub, []byte(canon), sig) {
		t.Errorf("bad signature for %q", canon)
	}
	if r.Header.Get("X-Aegis-Host") != "host-1" {
		t.Errorf("host header %q", r.Header.Get("X-Aegis-Host"))
	}
}

func hexSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func newClient(t *testing.T, url string) (*Client, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(append(make([]byte, 31), 5))
	c, err := NewClient(&Identity{HostID: "host-1", ServerURL: url, Priv: priv})
	if err != nil {
		t.Fatal(err)
	}
	return c, priv.Public().(ed25519.PublicKey)
}

func TestClientSignsRequests(t *testing.T) {
	var pub ed25519.PublicKey
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		verifyAuth(t, r, pub, b)
		gotPaths = append(gotPaths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v1/commands":
			json.NewEncoder(w).Encode(map[string]any{"commands": []signing.Envelope{{Payload: "a", Sig: "b"}}})
		case "/v1/heartbeat":
			w.Write([]byte(`{"policy_version": 9}`))
		default:
			w.Write([]byte(`{"accepted":1,"ok":true}`))
		}
	}))
	defer srv.Close()
	c, p := newClient(t, srv.URL)
	pub = p
	ctx := context.Background()
	if err := c.PostEvents(ctx, []event.Anomaly{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	cmds, err := c.GetCommands(ctx)
	if err != nil || len(cmds) != 1 {
		t.Fatal(err, cmds)
	}
	v, err := c.SendHeartbeat(ctx, Heartbeat{AgentVersion: "x"})
	if err != nil || v != 9 {
		t.Fatal(err, v)
	}
	if err := c.PostResult(ctx, executor.CommandResult{CommandID: "1", Status: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	if len(gotPaths) != 4 {
		t.Fatalf("%v", gotPaths)
	}
}

func TestHTTPErrorPermanence(t *testing.T) {
	for code, perm := range map[int]bool{400: true, 401: false, 429: false, 500: false, 413: true} {
		if (&HTTPError{Status: code}).Permanent() != perm {
			t.Errorf("%d", code)
		}
	}
}

func TestEnrollPinsKeyAndVerifiesPolicy(t *testing.T) {
	skey := serverKey()
	policyJSON := `{"host_id":"host-1","version":1,"issued_at":"2026-01-01T00:00:00Z","body":{"log_level":"info","thresholds":{},"watches":[],"suppressions":[],"rules":[],"iocs":[],"server_endpoints":[]}}`
	var enrollReq EnrollRequest
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" || r.Header.Get("X-Aegis-Sig") != "" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&enrollReq)
		json.NewEncoder(w).Encode(map[string]any{
			"host_id": "host-1", "server_pubkey": base64.StdEncoding.EncodeToString(skey.Public().(ed25519.PublicKey)),
			"policy": signing.SignEnvelope(skey, []byte(policyJSON)),
		})
	}))
	defer srv.Close()
	dir := t.TempDir()
	id, env, err := Enroll(context.Background(), srv.URL, "tok123", dir, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if enrollReq.Token != "tok123" || enrollReq.AgentVersion != "0.1.0" || enrollReq.Pubkey == "" || enrollReq.Hostname == "" {
		t.Fatalf("%+v", enrollReq)
	}
	if st, _ := os.Stat(dir + "/agent.key"); st.Mode().Perm() != 0o600 {
		t.Fatalf("agent.key perms %v", st.Mode())
	}
	if st, _ := os.Stat(dir + "/identity.json"); st.Mode().Perm() != 0o600 {
		t.Fatalf("identity perms %v", st.Mode())
	}
	pub, _ := id.ServerPub()
	if _, err := signing.VerifyEnvelope(pub, env); err != nil {
		t.Fatal(err)
	}
	// restart: identity + same key reload
	id2, err := LoadIdentity(dir)
	if err != nil || id2.HostID != "host-1" || !id2.Priv.Equal(id.Priv) {
		t.Fatalf("%v", err)
	}
	if base64.StdEncoding.EncodeToString(id.Priv.Public().(ed25519.PublicKey)) != enrollReq.Pubkey {
		t.Fatal("sent pubkey is not the agent key")
	}
	if _, err := LoadIdentity(t.TempDir()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal(err)
	}
}

func TestEnrollRejectsForgedPolicy(t *testing.T) {
	skey := serverKey()
	attacker := ed25519.NewKeyFromSeed(append(make([]byte, 31), 66))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"host_id": "h", "server_pubkey": base64.StdEncoding.EncodeToString(skey.Public().(ed25519.PublicKey)),
			"policy": signing.SignEnvelope(attacker, []byte(`{}`)),
		})
	}))
	defer srv.Close()
	dir := t.TempDir()
	if _, _, err := Enroll(context.Background(), srv.URL, "t", dir, "v"); err == nil {
		t.Fatal("forged policy accepted")
	}
	if _, err := os.Stat(dir + "/identity.json"); err == nil {
		t.Fatal("identity persisted after failed enrollment")
	}
}

type flakyPoster struct {
	mu      sync.Mutex
	fail    bool
	err     error
	batches [][]event.Anomaly
}

func (p *flakyPoster) PostEvents(_ context.Context, b []event.Anomaly) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		if p.err != nil {
			return p.err
		}
		return errors.New("offline")
	}
	p.batches = append(p.batches, b)
	return nil
}

func TestSenderSpoolsOfflineAndDrains(t *testing.T) {
	sp, err := OpenSpool(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	p := &flakyPoster{fail: true}
	s := &Sender{Poster: p, Spool: sp, Log: quiet}
	ctx := context.Background()
	s.flush(ctx, []event.Anomaly{{ID: "1"}, {ID: "2"}})
	s.flush(ctx, []event.Anomaly{{ID: "3"}})
	if sp.Len() != 3 {
		t.Fatalf("spooled %d", sp.Len())
	}
	p.fail = false
	s.flush(ctx, []event.Anomaly{{ID: "4"}}) // posts fresh batch then drains
	if sp.Len() != 0 {
		t.Fatalf("spool not drained: %d", sp.Len())
	}
	var ids []string
	for _, b := range p.batches {
		for _, a := range b {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) != 4 {
		t.Fatalf("%v", ids)
	}
	// permanent rejection drops rather than spooling forever
	p.fail, p.err = true, &HTTPError{Status: 400}
	s.flush(ctx, []event.Anomaly{{ID: "bad"}})
	if sp.Len() != 0 {
		t.Fatal("permanent failure was spooled")
	}
}

func TestSenderBatchesAndFlushesOnTimer(t *testing.T) {
	p := &flakyPoster{}
	s := &Sender{Poster: p, Log: quiet, FlushEvery: 30 * time.Millisecond}
	in := make(chan event.Anomaly, 2000)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, in); close(done) }()
	for i := 0; i < 1200; i++ {
		in <- event.Anomaly{ID: strconv.Itoa(i)}
	}
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	total := 0
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.batches {
		if len(b) > MaxBatch {
			t.Fatalf("batch of %d exceeds %d", len(b), MaxBatch)
		}
		total += len(b)
	}
	if total != 1200 {
		t.Fatalf("delivered %d", total)
	}
}

func TestSpoolCapDropsOldest(t *testing.T) {
	sp, _ := OpenSpool(t.TempDir(), 5)
	defer sp.Close()
	for i := 0; i < 8; i++ {
		sp.Put([]event.Anomaly{{ID: strconv.Itoa(i)}})
	}
	_, as, _ := sp.Peek(100)
	if len(as) != 5 || as[0].ID != "3" || as[4].ID != "7" {
		t.Fatalf("%+v", as)
	}
}

func TestBackoffBounds(t *testing.T) {
	for n := 0; n < 12; n++ {
		d := Backoff(n, time.Second, time.Minute)
		if d < 500*time.Millisecond || d > time.Minute {
			t.Fatalf("attempt %d: %v", n, d)
		}
	}
	if d := Backoff(10, time.Second, time.Minute); d < 30*time.Second {
		t.Fatalf("cap region should be >=30s: %v", d)
	}
}

func TestHubWebSocketCommandRoundTrip(t *testing.T) {
	var pub ed25519.PublicKey
	results := make(chan executor.CommandResult, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		verifyAuth(t, r, pub, nil)
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		env := signing.Envelope{Payload: "cGF5", Sig: "c2ln"}
		b, _ := json.Marshal(ServerMessage{Type: "command", Envelope: &env})
		c.Write(r.Context(), websocket.MessageText, b)
		<-r.Context().Done()
	})
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		verifyAuth(t, r, pub, b)
		var res executor.CommandResult
		json.Unmarshal(b, &res)
		results <- res
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"policy_version":0}`)) })
	mux.HandleFunc("/v1/commands", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"commands":[]}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, p := newClient(t, srv.URL)
	pub = p

	var handled sync.Map
	h := &Hub{
		Client: c, Log: quiet, HeartbeatEvery: time.Hour, PollEvery: time.Hour,
		HandleCommand: func(_ context.Context, env signing.Envelope) (executor.CommandResult, bool) {
			handled.Store(env.Payload, true)
			return executor.CommandResult{CommandID: "c1", Status: "succeeded"}, true
		},
		ApplyPolicy:   func(context.Context, signing.Envelope) error { return nil },
		PolicyVersion: func() int64 { return 0 },
		Snapshot:      func() Heartbeat { return Heartbeat{} },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()
	select {
	case r := <-results:
		if r.CommandID != "c1" || r.Status != "succeeded" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no result posted")
	}
	if !h.WSConnected() {
		t.Fatal("ws should be connected")
	}
	if _, ok := handled.Load("cGF5"); !ok {
		t.Fatal("command not handled")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not stop")
	}
}

func TestHubPollingFallbackAndPolicyFetch(t *testing.T) {
	var polled, policyFetched, resultPosted sync.WaitGroup
	polled.Add(1)
	policyFetched.Add(1)
	resultPosted.Add(1)
	var once1, once2, once3 sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ws", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no ws", 503) })
	mux.HandleFunc("/v1/commands", func(w http.ResponseWriter, r *http.Request) {
		once1.Do(polled.Done)
		json.NewEncoder(w).Encode(map[string]any{"commands": []signing.Envelope{{Payload: "x", Sig: "y"}}})
	})
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, r *http.Request) {
		once2.Do(resultPosted.Done)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"policy_version":7}`)) })
	mux.HandleFunc("/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		once3.Do(policyFetched.Done)
		json.NewEncoder(w).Encode(signing.Envelope{Payload: "p", Sig: "s"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := newClient(t, srv.URL)
	h := &Hub{Client: c, Log: quiet, HeartbeatEvery: time.Hour, PollEvery: 20 * time.Millisecond,
		HandleCommand: func(context.Context, signing.Envelope) (executor.CommandResult, bool) {
			return executor.CommandResult{CommandID: "p1", Status: "succeeded"}, true
		},
		ApplyPolicy:   func(context.Context, signing.Envelope) error { return nil },
		PolicyVersion: func() int64 { return 1 },
		Snapshot:      func() Heartbeat { return Heartbeat{} }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	ch := make(chan struct{})
	go func() { polled.Wait(); resultPosted.Wait(); policyFetched.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("poll/result/policy flow incomplete")
	}
}
