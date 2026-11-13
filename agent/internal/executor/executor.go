// Package executor runs the fixed vocabulary of agent commands from
// PROTOCOL.md section 5. There is no generic execution path: every action is
// a typed Go function, and external programs are invoked only through the
// injectable Runner with argument lists (never via a shell).
package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/policy"
	"github.com/aegis-soc/aegis/agent/internal/signing"
)

// Command is the decoded payload of a command envelope.
type Command struct {
	ID        string          `json:"id"`
	HostID    string          `json:"host_id"`
	Action    string          `json:"action"`
	Params    json.RawMessage `json:"params"`
	IssuedAt  string          `json:"issued_at"`
	ExpiresAt string          `json:"expires_at"`
}

// Result statuses.
const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusRejected  = "rejected"
)

// CommandResult is POSTed to /v1/results.
type CommandResult struct {
	CommandID     string         `json:"command_id"`
	Status        string         `json:"status"`
	Result        map[string]any `json:"result,omitempty"`
	Error         string         `json:"error,omitempty"`
	RollbackToken string         `json:"rollback_token,omitempty"`
}

// Cmd is one external program invocation.
type Cmd struct {
	Name  string
	Args  []string
	Stdin []byte
}

// Runner executes external programs. Implementations must never involve a shell.
type Runner interface {
	Run(ctx context.Context, c Cmd) ([]byte, error)
}

// allowedBinaries bounds what ExecRunner will ever launch.
var allowedBinaries = map[string]bool{"nft": true, "usermod": true, "journalctl": true}

// ExecRunner is the production Runner using os/exec with an argument vector.
type ExecRunner struct{ Timeout time.Duration }

// Run implements Runner.
func (r ExecRunner) Run(ctx context.Context, c Cmd) ([]byte, error) {
	if !allowedBinaries[c.Name] {
		return nil, fmt.Errorf("binary %q is not allowlisted", c.Name)
	}
	to := r.Timeout
	if to == 0 {
		to = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", c.Name, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

// EventSource provides the local event ring buffer to test_rule/user_info.
type EventSource interface {
	Snapshot(since time.Time) []event.Event
}

// Config wires the executor to its environment. Zero values take
// production defaults.
type Config struct {
	HostID    string
	ServerPub ed25519.PublicKey
	DataDir   string // state and quarantine live here (default /var/lib/aegis)
	ServerURL string // always allowed under isolation

	Runner      Runner
	Events      EventSource
	Policy      func() policy.Body
	SetLogLevel func(level string, ttl time.Duration)
	Logger      *slog.Logger

	// Overridable environment (tests).
	ProcRoot   string
	PasswdPath string
	GroupPath  string
	LogDir     string
	Now        func() time.Time
	Resolver   func(ctx context.Context, host string) ([]net.IP, error)
	LocalIPs   func() []net.IP // host interface addresses (default net.InterfaceAddrs)
	Kill       func(pid int) error
	SelfPID    int
	SelfUID    int
	SelfExe    string
}

// Executor validates and runs commands.
type Executor struct {
	cfg Config
	log *slog.Logger
	st  *store
	mu  sync.Mutex // serializes command execution
}

// New builds an Executor, loading persisted state.
func New(cfg Config) (*Executor, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/aegis"
	}
	if cfg.Runner == nil {
		cfg.Runner = ExecRunner{}
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.PasswdPath == "" {
		cfg.PasswdPath = "/etc/passwd"
	}
	if cfg.GroupPath == "" {
		cfg.GroupPath = "/etc/group"
	}
	if cfg.LogDir == "" {
		cfg.LogDir = "/var/log"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Resolver == nil {
		cfg.Resolver = func(ctx context.Context, h string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", h)
		}
	}
	if cfg.Kill == nil {
		cfg.Kill = killPID
	}
	if cfg.SelfPID == 0 {
		cfg.SelfPID = os.Getpid()
	}
	if cfg.SelfUID == 0 {
		cfg.SelfUID = os.Getuid()
	}
	if cfg.SelfExe == "" {
		cfg.SelfExe, _ = os.Executable()
	}
	if cfg.Policy == nil {
		cfg.Policy = func() policy.Body { return policy.Body{} }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	st, err := loadStore(filepath.Join(cfg.DataDir, "executor_state.json"))
	if err != nil {
		return nil, err
	}
	return &Executor{cfg: cfg, log: cfg.Logger, st: st}, nil
}

// rejectError marks a policy/validation refusal (status "rejected").
type rejectError struct{ msg string }

func (e rejectError) Error() string { return e.msg }

func reject(format string, a ...any) error { return rejectError{fmt.Sprintf(format, a...)} }

type handler func(e *Executor, ctx context.Context, cmd Command) (res map[string]any, rollbackToken string, err error)

var handlers map[string]handler

func init() {
	handlers = map[string]handler{
		"collect_evidence": (*Executor).collectEvidence,
		"test_rule":        (*Executor).testRule,
		"yara_scan":        (*Executor).yaraScan,
		"raise_log_level":  (*Executor).raiseLogLevel,
		"kill_process":     (*Executor).killProcess,
		"block_ip":         (*Executor).blockIP,
		"disable_user":     (*Executor).disableUser,
		"quarantine_file":  (*Executor).quarantineFile,
		"isolate_host":     (*Executor).isolateHost,
		"rollback":         (*Executor).rollback,
	}
}

// Actions lists the supported action names.
func Actions() []string {
	out := make([]string, 0, len(handlers))
	for k := range handlers {
		out = append(out, k)
	}
	return out
}

// Handle authenticates, validates and executes one command envelope. The
// returned result is ready to POST to /v1/results; ok=false means the
// envelope was unauthenticated or unparseable and nothing should be reported.
func (e *Executor) Handle(ctx context.Context, env signing.Envelope) (CommandResult, bool) {
	raw, err := signing.VerifyEnvelope(e.cfg.ServerPub, env)
	if err != nil {
		e.log.Warn("command rejected: bad signature", "err", err)
		return CommandResult{Status: StatusRejected, Error: "invalid signature"}, false
	}
	var cmd Command
	if err := json.Unmarshal(raw, &cmd); err != nil || cmd.ID == "" {
		e.log.Warn("command rejected: malformed payload")
		return CommandResult{Status: StatusRejected, Error: "malformed command"}, false
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Dedup by id: replay returns the original result without re-executing.
	if prev, ok := e.st.seen(cmd.ID); ok {
		e.log.Info("duplicate command", "id", cmd.ID, "action", cmd.Action)
		return prev, true
	}
	res := e.run(ctx, cmd)
	exp, _ := time.Parse(time.RFC3339, cmd.ExpiresAt)
	if exp.IsZero() {
		exp = e.cfg.Now().Add(time.Hour)
	}
	if err := e.st.recordSeen(cmd.ID, res, exp, e.cfg.Now()); err != nil {
		e.log.Error("persist executor state", "err", err)
	}
	e.log.Info("command handled", "id", cmd.ID, "action", cmd.Action, "status", res.Status, "error", res.Error)
	return res, true
}

func (e *Executor) run(ctx context.Context, cmd Command) CommandResult {
	res := CommandResult{CommandID: cmd.ID}
	fail := func(status, msg string) CommandResult {
		res.Status, res.Error = status, msg
		return res
	}
	if cmd.HostID != e.cfg.HostID {
		return fail(StatusRejected, "host_id mismatch")
	}
	exp, err := time.Parse(time.RFC3339, cmd.ExpiresAt)
	if err != nil {
		return fail(StatusRejected, "invalid expires_at")
	}
	if !e.cfg.Now().Before(exp) {
		return fail(StatusRejected, "command expired")
	}
	h, ok := handlers[cmd.Action]
	if !ok {
		return fail(StatusRejected, "unknown action")
	}
	out, token, err := h(e, ctx, cmd)
	if err != nil {
		var re rejectError
		if errors.As(err, &re) {
			return fail(StatusRejected, re.msg)
		}
		return fail(StatusFailed, err.Error())
	}
	res.Status, res.Result, res.RollbackToken = StatusSucceeded, out, token
	return res
}

// Run reaps expired isolations until ctx is done.
func (e *Executor) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		e.ReapExpired(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ReapExpired rolls back records whose TTL has elapsed.
func (e *Executor) ReapExpired(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rec := range e.st.expired(e.cfg.Now()) {
		if err := e.undo(ctx, rec); err != nil {
			e.log.Warn("auto-rollback failed", "action", rec.Action, "err", err)
			continue
		}
		_ = e.st.markDone(rec.Token)
		e.log.Info("auto-rollback", "action", rec.Action, "token", rec.Token[:6])
	}
}

func newToken() string {
	var b [18]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
