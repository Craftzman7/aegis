package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/collector"
	"github.com/aegis-soc/aegis/agent/internal/detect"
	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/executor"
	"github.com/aegis-soc/aegis/agent/internal/policy"
	"github.com/aegis-soc/aegis/agent/internal/signing"
	"github.com/aegis-soc/aegis/agent/internal/transport"
)

// NewLogger returns a JSON slog logger writing to stderr and its level var.
func NewLogger(level string) (*slog.Logger, *slog.LevelVar) {
	lv := &slog.LevelVar{}
	setLevel(lv, level)
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv})), lv
}

func setLevel(lv *slog.LevelVar, level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	lv.Set(l)
}

// Run starts the daemon and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, version string) error {
	log, lv := NewLogger(cfg.LogLevel)
	id, err := transport.LoadIdentity(cfg.DataDir)
	if err != nil {
		return err
	}
	pub, err := id.ServerPub()
	if err != nil {
		return err
	}
	client, err := transport.NewClient(id)
	if err != nil {
		return err
	}
	log.Info("aegis-agent starting", "version", version, "host_id", id.HostID, "server", id.ServerURL, "uid", os.Getuid())
	if os.Geteuid() != 0 {
		log.Warn("not running as root: auditd, nftables and some /proc data will be unavailable")
	}

	// Policy + detection.
	pm := policy.NewManager(pub, id.HostID, filepath.Join(cfg.DataDir, "policy.json"))
	engine := detect.NewEngine(log)
	var levelMu sync.Mutex
	var revert *time.Timer
	policyLevel := cfg.LogLevel
	pm.Subscribe(func(p *policy.Policy) {
		engine.SetPolicy(p)
		levelMu.Lock()
		defer levelMu.Unlock()
		if p.Body.LogLevel != "" {
			policyLevel = p.Body.LogLevel
			if revert == nil {
				setLevel(lv, policyLevel)
			}
		}
	})
	if _, err := pm.Load(); err != nil {
		log.Error("persisted policy invalid; using defaults until server sends one", "err", err)
	}

	ex, err := executor.New(executor.Config{
		HostID: id.HostID, ServerPub: pub, DataDir: cfg.DataDir, ServerURL: id.ServerURL,
		Events: engine.Ring(), Logger: log,
		Policy: func() policy.Body { return pm.Current().Body },
		SetLogLevel: func(level string, ttl time.Duration) {
			levelMu.Lock()
			defer levelMu.Unlock()
			setLevel(lv, level)
			if revert != nil {
				revert.Stop()
			}
			revert = time.AfterFunc(ttl, func() {
				levelMu.Lock()
				defer levelMu.Unlock()
				revert = nil
				setLevel(lv, policyLevel)
			})
		},
	})
	if err != nil {
		return err
	}

	spool, err := transport.OpenSpool(cfg.DataDir, 0)
	if err != nil {
		return fmt.Errorf("open spool: %w", err)
	}
	defer spool.Close()

	events := make(chan event.Event, 4096)
	sender := &transport.Sender{Poster: client, Spool: spool, Log: log}
	hub := &transport.Hub{
		Client: client, Log: log,
		HandleCommand: ex.Handle,
		ApplyPolicy: func(_ context.Context, env signing.Envelope) error {
			_, err := pm.Apply(env)
			if err == policy.ErrStale {
				return nil
			}
			return err
		},
		PolicyVersion: pm.Version,
		Snapshot: func() transport.Heartbeat {
			st := engine.Stats()
			var re []transport.RuleError
			for _, e := range engine.RuleErrors() {
				re = append(re, transport.RuleError{RuleID: e.RuleID, Error: e.Error})
			}
			return transport.Heartbeat{
				AgentVersion: version, RuleErrors: re,
				Stats: transport.HeartbeatStats{EventsPerMin: st.EventsPerMin, AnomaliesPerMin: st.AnomaliesPerMin,
					RulesLoaded: st.RulesLoaded, BufferEvents: st.BufferEvents},
			}
		},
	}

	collectors := []collector.Collector{
		&collector.AuthLog{},
		&collector.Proc{UserName: userName},
		&collector.Auditd{},
		&collector.NetConn{},
		&collector.FIM{ExtraPaths: func() []string {
			var out []string
			for _, w := range pm.Current().Body.Watches {
				if w.Kind == "path" {
					out = append(out, w.Target)
				}
			}
			return out
		}},
		&collector.Users{},
	}

	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	run(func() { collector.RunAll(ctx, log, events, collectors...) })
	run(func() { engine.Run(ctx, events) })
	run(func() { sender.Run(ctx, engine.Anomalies()) })
	run(func() { hub.Run(ctx) })
	run(func() { ex.Run(ctx) })

	// Initial policy sync (heartbeat will keep it fresh).
	go func() {
		if env, err := client.GetPolicy(ctx); err == nil {
			if err := hub.ApplyPolicy(ctx, env); err != nil {
				log.Warn("initial policy rejected", "err", err)
			}
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	wg.Wait()
	return nil
}

var (
	userMu    sync.Mutex
	userCache = map[int]string{}
)

func userName(uid int) string {
	userMu.Lock()
	defer userMu.Unlock()
	if n, ok := userCache[uid]; ok {
		return n
	}
	n := strconv.Itoa(uid)
	if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	userCache[uid] = n
	return n
}
