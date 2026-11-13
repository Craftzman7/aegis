package transport

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/aegis-soc/aegis/agent/internal/executor"
	"github.com/aegis-soc/aegis/agent/internal/signing"
)

// ServerMessage is a WS frame from the server (PROTOCOL.md section 4).
type ServerMessage struct {
	Type     string            `json:"type"`
	Envelope *signing.Envelope `json:"envelope,omitempty"`
	Version  int64             `json:"version,omitempty"`
}

// Hub runs the control-plane loops: heartbeat, WebSocket command channel and
// the polling fallback.
type Hub struct {
	Client *Client
	Log    *slog.Logger

	// HandleCommand executes a command envelope. ok=false means do not report.
	HandleCommand func(ctx context.Context, env signing.Envelope) (executor.CommandResult, bool)
	// ApplyPolicy verifies and applies a policy envelope.
	ApplyPolicy   func(ctx context.Context, env signing.Envelope) error
	PolicyVersion func() int64
	// Snapshot supplies the heartbeat body (WSConnected/UptimeS/PolicyVersion are filled in).
	Snapshot func() Heartbeat

	HeartbeatEvery time.Duration // default 30s
	PollEvery      time.Duration // default 15s

	wsUp  atomic.Bool
	start time.Time
	once  sync.Once
}

func (h *Hub) init() {
	h.once.Do(func() {
		h.start = time.Now()
		if h.HeartbeatEvery == 0 {
			h.HeartbeatEvery = 30 * time.Second
		}
		if h.PollEvery == 0 {
			h.PollEvery = 15 * time.Second
		}
	})
}

// WSConnected reports whether the WebSocket is up.
func (h *Hub) WSConnected() bool { return h.wsUp.Load() }

// Run blocks until ctx is done.
func (h *Hub) Run(ctx context.Context) {
	h.init()
	var wg sync.WaitGroup
	for _, f := range []func(context.Context){h.heartbeatLoop, h.wsLoop, h.pollLoop} {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	wg.Wait()
}

func (h *Hub) heartbeatLoop(ctx context.Context) {
	h.beat(ctx)
	t := time.NewTicker(h.HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.beat(ctx)
		}
	}
}

func (h *Hub) beat(ctx context.Context) {
	hb := h.Snapshot()
	hb.PolicyVersion = h.PolicyVersion()
	hb.UptimeS = int64(time.Since(h.start).Seconds())
	hb.WSConnected = h.wsUp.Load()
	if hb.RuleErrors == nil {
		hb.RuleErrors = []RuleError{}
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	latest, err := h.Client.SendHeartbeat(cctx, hb)
	if err != nil {
		h.Log.Warn("heartbeat failed", "err", err)
		return
	}
	if latest > h.PolicyVersion() {
		h.fetchPolicy(ctx)
	}
}

func (h *Hub) fetchPolicy(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	env, err := h.Client.GetPolicy(cctx)
	if err != nil {
		h.Log.Warn("policy fetch failed", "err", err)
		return
	}
	if err := h.ApplyPolicy(ctx, env); err != nil {
		h.Log.Warn("policy rejected", "err", err)
	}
}

func (h *Hub) pollLoop(ctx context.Context) {
	t := time.NewTicker(h.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !h.wsUp.Load() {
				h.pollOnce(ctx)
			}
		}
	}
}

func (h *Hub) pollOnce(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	cmds, err := h.Client.GetCommands(cctx)
	cancel()
	if err != nil {
		h.Log.Debug("command poll failed", "err", err)
		return
	}
	for _, env := range cmds {
		h.dispatch(ctx, env)
	}
}

// dispatch executes env and reports the result, retrying the POST.
func (h *Hub) dispatch(ctx context.Context, env signing.Envelope) {
	res, ok := h.HandleCommand(ctx, env)
	if !ok {
		return
	}
	backoff := time.Second
	for attempt := 0; attempt < 4; attempt++ {
		err := h.Client.PostResult(ctx, res)
		if err == nil || isPermanent(err) {
			if err != nil {
				h.Log.Error("result rejected by server", "command_id", res.CommandID, "err", err)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	h.Log.Error("could not report result; server will redeliver", "command_id", res.CommandID)
}

// Backoff returns a jittered exponential delay for attempt n (0-based):
// base*2^n capped at max, then uniformly in [d/2, d].
func Backoff(n int, base, max time.Duration) time.Duration {
	d := base
	for i := 0; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (h *Hub) wsURL() string {
	u := h.Client.endpoint("/v1/ws")
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		return "ws://" + strings.TrimPrefix(u, "http://")
	}
	return u
}

func (h *Hub) wsLoop(ctx context.Context) {
	attempt := 0
	for ctx.Err() == nil {
		began := time.Now()
		err := h.wsSession(ctx)
		h.wsUp.Store(false)
		if ctx.Err() != nil {
			return
		}
		if time.Since(began) > 30*time.Second {
			attempt = 0
		}
		d := Backoff(attempt, time.Second, time.Minute)
		attempt++
		h.Log.Warn("websocket disconnected", "err", err, "retry_in", d.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

func (h *Hub) wsSession(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, _, err := websocket.Dial(dctx, h.wsURL(), &websocket.DialOptions{
		HTTPHeader: h.Client.signedHeaders(http.MethodGet, "/v1/ws", nil),
	})
	cancel()
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)
	h.wsUp.Store(true)
	h.Log.Info("websocket connected")

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { // liveness: ping every 30s, drop the socket when unanswered
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				pctx, c := context.WithTimeout(sctx, 10*time.Second)
				err := conn.Ping(pctx)
				c()
				if err != nil {
					conn.CloseNow()
					return
				}
			}
		}
	}()

	go h.pollOnce(sctx) // pick up anything queued while the socket was down

	for {
		_, data, err := conn.Read(sctx)
		if err != nil {
			return err
		}
		var msg ServerMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			h.Log.Warn("bad websocket frame", "err", err)
			continue
		}
		switch msg.Type {
		case "command":
			if msg.Envelope == nil {
				continue
			}
			h.dispatch(ctx, *msg.Envelope)
		case "policy_updated":
			if msg.Version > h.PolicyVersion() {
				h.fetchPolicy(ctx)
			}
		case "ping":
		default:
			h.Log.Debug("unknown websocket message", "type", msg.Type)
		}
	}
}
