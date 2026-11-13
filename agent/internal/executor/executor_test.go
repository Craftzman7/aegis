package executor

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/policy"
	"github.com/aegis-soc/aegis/agent/internal/signing"
)

type fakeRunner struct {
	calls []Cmd
	err   error
}

func (f *fakeRunner) Run(_ context.Context, c Cmd) ([]byte, error) {
	f.calls = append(f.calls, c)
	return nil, f.err
}

type fakeEvents []event.Event

func (f fakeEvents) Snapshot(time.Time) []event.Event { return f }

type env struct {
	t      *testing.T
	ex     *Executor
	run    *fakeRunner
	priv   ed25519.PrivateKey
	now    time.Time
	dir    string
	proc   string
	killed []int
	seq    int
	expect []string // path+" "+sha256 passed to ExpectChange
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	e := &env{t: t, run: &fakeRunner{}, priv: priv, now: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC), dir: dir, proc: filepath.Join(dir, "proc")}
	os.MkdirAll(e.proc, 0o755)
	os.WriteFile(filepath.Join(dir, "passwd"), []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nagent:x:999:999::/var/lib/aegis:/bin/false\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "group"), []byte("sudo:x:27:alice\nalice:x:1000:\n"), 0o644)
	os.WriteFile(filepath.Join(e.proc, "stat"), []byte("cpu 1 2 3\nbtime 1000000\n"), 0o644)
	os.MkdirAll(filepath.Join(e.proc, "net"), 0o755)
	// default route via 192.168.97.1 (little-endian hex 0161A8C0)
	os.WriteFile(filepath.Join(e.proc, "net", "route"), []byte("Iface\tDestination\tGateway \tFlags\nnet0\t00000000\t0161A8C0\t0003\nnet0\t0061A8C0\t00000000\t0001\n"), 0o644)
	ex, err := New(Config{
		HostID: "host-1", ServerPub: priv.Public().(ed25519.PublicKey), DataDir: filepath.Join(dir, "data"),
		ServerURL: "https://aegis.example.net", Runner: e.run,
		Policy:   func() policy.Body { return policy.Body{ServerEndpoints: []string{"203.0.113.5"}} },
		LocalIPs: func() []net.IP { return []net.IP{net.ParseIP("192.168.97.2")} },
		ProcRoot: e.proc, PasswdPath: filepath.Join(dir, "passwd"), GroupPath: filepath.Join(dir, "group"), LogDir: filepath.Join(dir, "log"),
		Now:          func() time.Time { return e.now },
		Resolver:     func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.20")}, nil },
		Kill:         func(pid int) error { e.killed = append(e.killed, pid); return nil },
		ExpectChange: func(path, sha string) { e.expect = append(e.expect, path+" "+sha) },
		SelfPID:      4242, SelfUID: 999, SelfExe: filepath.Join(dir, "aegis-agent"),
		Events: fakeEvents{{Time: e.now, Logsource: event.Logsource{Product: "linux", Category: "process_creation"}, Image: "/tmp/evil", CommandLine: "/tmp/evil"},
			{Time: e.now, Logsource: event.Logsource{Product: "linux", Category: "process_creation"}, Image: "/bin/ls"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.ex = ex
	return e
}

func (e *env) cmd(action string, params any) signing.Envelope {
	return e.cmdFull("", "host-1", action, params, e.now.Add(5*time.Minute), e.priv)
}

func (e *env) cmdFull(id, host, action string, params any, exp time.Time, key ed25519.PrivateKey) signing.Envelope {
	e.seq++
	if id == "" {
		id = "cmd-" + strconv.Itoa(e.seq)
	}
	p, _ := json.Marshal(params)
	raw, _ := json.Marshal(map[string]any{"id": id, "host_id": host, "action": action, "params": json.RawMessage(p),
		"issued_at": e.now.Format(time.RFC3339), "expires_at": exp.Format(time.RFC3339)})
	return signing.SignEnvelope(key, raw)
}

func (e *env) do(action string, params any) CommandResult {
	res, ok := e.ex.Handle(context.Background(), e.cmd(action, params))
	if !ok {
		e.t.Fatal("handle returned ok=false")
	}
	return res
}

func (e *env) want(res CommandResult, status string) {
	e.t.Helper()
	if res.Status != status {
		e.t.Fatalf("status %s (%s), want %s", res.Status, res.Error, status)
	}
}

func TestValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// expired
	res, _ := e.ex.Handle(ctx, e.cmdFull("", "host-1", "raise_log_level", map[string]any{"ttl_seconds": 60}, e.now.Add(-time.Second), e.priv))
	e.want(res, StatusRejected)
	if !strings.Contains(res.Error, "expired") {
		t.Fatal(res.Error)
	}
	// wrong host
	res, _ = e.ex.Handle(ctx, e.cmdFull("", "other-host", "raise_log_level", map[string]any{"ttl_seconds": 60}, e.now.Add(time.Minute), e.priv))
	e.want(res, StatusRejected)
	if !strings.Contains(res.Error, "host_id") {
		t.Fatal(res.Error)
	}
	// bad signature -> not reportable
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 7))
	if _, ok := e.ex.Handle(ctx, e.cmdFull("", "host-1", "raise_log_level", map[string]any{"ttl_seconds": 60}, e.now.Add(time.Minute), other)); ok {
		t.Fatal("forged command accepted")
	}
	// unknown action: no arbitrary exec
	e.want(e.do("run_shell", map[string]any{"cmd": "id"}), StatusRejected)
	// unknown param field
	e.want(e.do("raise_log_level", map[string]any{"ttl_seconds": 60, "extra": 1}), StatusRejected)
	if len(e.run.calls) != 0 {
		t.Fatalf("nothing should have executed: %+v", e.run.calls)
	}
}

func TestDedupReturnsCachedResult(t *testing.T) {
	e := newEnv(t)
	logs := 0
	e.ex.cfg.SetLogLevel = func(string, time.Duration) { logs++ }
	env1 := e.cmdFull("dup-1", "host-1", "raise_log_level", map[string]any{"ttl_seconds": 60}, e.now.Add(time.Minute), e.priv)
	r1, _ := e.ex.Handle(context.Background(), env1)
	r2, _ := e.ex.Handle(context.Background(), env1)
	if logs != 1 || r1.Status != StatusSucceeded || r2.Status != StatusSucceeded || r2.CommandID != "dup-1" {
		t.Fatalf("logs=%d %+v %+v", logs, r1, r2)
	}
	// survives restart
	ex2, _ := New(e.ex.cfg)
	r3, _ := ex2.Handle(context.Background(), env1)
	if logs != 1 || r3.Status != StatusSucceeded {
		t.Fatalf("dedup not persisted: logs=%d", logs)
	}
}

func TestDisableUser(t *testing.T) {
	e := newEnv(t)
	for _, u := range []string{"root", "toor", "agent", "nobody-here", "bad name; rm -rf /", ""} {
		res := e.do("disable_user", map[string]any{"username": u})
		e.want(res, StatusRejected)
	}
	if len(e.run.calls) != 0 {
		t.Fatalf("usermod must not run for refused users: %+v", e.run.calls)
	}
	res := e.do("disable_user", map[string]any{"username": "alice"})
	e.want(res, StatusSucceeded)
	if res.RollbackToken == "" || len(e.run.calls) != 1 || e.run.calls[0].Name != "usermod" ||
		strings.Join(e.run.calls[0].Args, " ") != "-L -e 1 alice" {
		t.Fatalf("%+v", e.run.calls)
	}
	rb := e.do("rollback", map[string]any{"rollback_token": res.RollbackToken})
	e.want(rb, StatusSucceeded)
	last := e.run.calls[len(e.run.calls)-1]
	if last.Name != "usermod" || len(last.Args) != 4 || last.Args[0] != "-U" || last.Args[3] != "alice" {
		t.Fatalf("%+v", last)
	}
	// second rollback is idempotent, runs nothing
	n := len(e.run.calls)
	rb = e.do("rollback", map[string]any{"rollback_token": res.RollbackToken})
	e.want(rb, StatusSucceeded)
	if len(e.run.calls) != n {
		t.Fatal("rollback executed twice")
	}
	e.want(e.do("rollback", map[string]any{"rollback_token": "nope"}), StatusRejected)
}

func TestBlockIP(t *testing.T) {
	e := newEnv(t)
	for _, p := range []map[string]any{
		{"ip": "not-an-ip", "ttl_seconds": 60},
		{"ip": "127.0.0.1", "ttl_seconds": 60},
		{"ip": "203.0.113.5", "ttl_seconds": 60},   // policy server endpoint
		{"ip": "198.51.100.20", "ttl_seconds": 60}, // resolved ServerURL
		{"ip": "1.2.3.4", "ttl_seconds": 604801},
		{"ip": "1.2.3.4", "ttl_seconds": 0},
		{"ip": "1.2.3.4; reboot", "ttl_seconds": 60},
		{"ip": "192.168.97.1", "ttl_seconds": 60}, // default gateway
		{"ip": "192.168.97.2", "ttl_seconds": 60}, // own address
	} {
		e.want(e.do("block_ip", p), StatusRejected)
	}
	if len(e.run.calls) != 0 {
		t.Fatal("nft ran for refused input")
	}
	e.want(e.do("block_ip", map[string]any{"ip": "192.168.97.3", "ttl_seconds": 60}), StatusSucceeded) // internal attacker is blockable
	e.run.calls = nil
	res := e.do("block_ip", map[string]any{"ip": "1.2.3.4", "ttl_seconds": 3600})
	e.want(res, StatusSucceeded)
	c := e.run.calls[0]
	if c.Name != "nft" || strings.Join(c.Args, " ") != "-f -" {
		t.Fatalf("%+v", c)
	}
	s := string(c.Stdin)
	for _, w := range []string{"add table inet aegis", "flags timeout", "add element inet aegis blocked { 1.2.3.4 timeout 3600s }", "ip saddr @blocked drop"} {
		if !strings.Contains(s, w) {
			t.Errorf("script missing %q:\n%s", w, s)
		}
	}
	res6 := e.do("block_ip", map[string]any{"ip": "2001:db8::1", "ttl_seconds": 60})
	e.want(res6, StatusSucceeded)
	if !strings.Contains(string(e.run.calls[1].Stdin), "blocked6 { 2001:db8::1 timeout 60s }") {
		t.Fatalf("v6: %s", e.run.calls[1].Stdin)
	}
	e.want(e.do("rollback", map[string]any{"rollback_token": res.RollbackToken}), StatusSucceeded)
	if !strings.Contains(string(e.run.calls[2].Stdin), "delete element inet aegis blocked { 1.2.3.4 }") {
		t.Fatalf("%s", e.run.calls[2].Stdin)
	}
}

func TestIsolateHostAndAutoRollback(t *testing.T) {
	e := newEnv(t)
	e.want(e.do("isolate_host", map[string]any{"ttl_seconds": 86401}), StatusRejected)
	res := e.do("isolate_host", map[string]any{"ttl_seconds": 600})
	e.want(res, StatusSucceeded)
	s := string(e.run.calls[0].Stdin)
	for _, w := range []string{"policy drop", `iifname "lo" accept`, "203.0.113.5", "198.51.100.20", "table inet aegis_isolate"} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in\n%s", w, s)
		}
	}
	if strings.Contains(s, "ct state established") {
		t.Errorf("isolation must not keep pre-existing connections alive:\n%s", s)
	}
	e.ex.ReapExpired(context.Background())
	if len(e.run.calls) != 1 {
		t.Fatal("reaped too early")
	}
	e.now = e.now.Add(11 * time.Minute)
	e.ex.ReapExpired(context.Background())
	if len(e.run.calls) != 2 || !strings.Contains(string(e.run.calls[1].Stdin), "delete table inet aegis_isolate") {
		t.Fatalf("auto rollback: %+v", e.run.calls)
	}
	// no endpoints -> refuse
	e.ex.cfg.ServerURL = ""
	e.ex.cfg.Policy = func() policy.Body { return policy.Body{} }
	e.want(e.do("isolate_host", map[string]any{"ttl_seconds": 60}), StatusRejected)
}

func TestRunnerFailureIsFailedNotRejected(t *testing.T) {
	e := newEnv(t)
	e.run.err = os.ErrPermission
	res := e.do("block_ip", map[string]any{"ip": "1.2.3.4", "ttl_seconds": 60})
	e.want(res, StatusFailed)
	if res.RollbackToken != "" {
		t.Fatal("no rollback token on failure")
	}
}

func TestQuarantineAndRollback(t *testing.T) {
	e := newEnv(t)
	f := filepath.Join(e.dir, "payload.bin")
	os.WriteFile(f, []byte("malware"), 0o755)
	e.want(e.do("quarantine_file", map[string]any{"path": "relative/x"}), StatusRejected)
	e.want(e.do("quarantine_file", map[string]any{"path": "/proc/1/environ"}), StatusRejected)
	e.want(e.do("quarantine_file", map[string]any{"path": e.dir}), StatusRejected) // directory
	e.want(e.do("quarantine_file", map[string]any{"path": filepath.Join(e.dir, "aegis-agent")}), StatusRejected)
	res := e.do("quarantine_file", map[string]any{"path": f})
	e.want(res, StatusSucceeded)
	q := res.Result["quarantine_path"].(string)
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("original still present")
	}
	st, err := os.Lstat(q)
	if err != nil || st.Mode().Perm() != 0 {
		t.Fatalf("quarantine perms: %v %v", st, err)
	}
	if len(res.Result["sha256"].(string)) != 64 {
		t.Fatal("sha256")
	}
	e.want(e.do("rollback", map[string]any{"rollback_token": res.RollbackToken}), StatusSucceeded)
	want := f + " " + res.Result["sha256"].(string)
	if len(e.expect) != 2 || e.expect[0] != want || e.expect[1] != want {
		t.Fatalf("quarantine and restore must announce the change to detection: %v", e.expect)
	}
	b, err := os.ReadFile(f)
	if err != nil || string(b) != "malware" {
		t.Fatalf("restore failed: %v", err)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o755 {
		t.Fatalf("mode not restored: %v", st.Mode())
	}
}

func writeProc(t *testing.T, root string, pid, ppid int, exe, cmdline string, start int) {
	d := filepath.Join(root, strconv.Itoa(pid))
	os.MkdirAll(filepath.Join(d, "fd"), 0o755)
	stat := strconv.Itoa(pid) + " (p) S " + strconv.Itoa(ppid) + " 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 " + strconv.Itoa(start) + " 1 1 0\n"
	os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
	os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.ReplaceAll(cmdline, " ", "\x00")+"\x00"), 0o644)
	os.Symlink(exe, filepath.Join(d, "exe"))
	os.Symlink("/", filepath.Join(d, "cwd"))
	os.Symlink("/dev/null", filepath.Join(d, "fd", "0"))
}

func TestKillProcess(t *testing.T) {
	e := newEnv(t)
	writeProc(t, e.proc, 500, 1, "/tmp/evil", "/tmp/evil -x", 7777)
	writeProc(t, e.proc, 4242, 1, "/usr/bin/aegis-agent", "aegis-agent run", 1)
	e.want(e.do("kill_process", map[string]any{"pid": 1}), StatusRejected)
	e.want(e.do("kill_process", map[string]any{"pid": 4242}), StatusRejected)
	e.want(e.do("kill_process", map[string]any{"pid": 500, "start_time": 1234}), StatusRejected) // pid reuse
	e.want(e.do("kill_process", map[string]any{"pid": 999}), StatusFailed)                       // not found
	if len(e.killed) != 0 {
		t.Fatal("killed despite refusal")
	}
	res := e.do("kill_process", map[string]any{"pid": 500, "start_time": 7777})
	e.want(res, StatusSucceeded)
	if res.Result["killed"] != true || len(e.killed) != 1 || e.killed[0] != 500 {
		t.Fatalf("%+v %v", res, e.killed)
	}
	// RFC3339 start_time derived from btime + ticks
	ts := time.Unix(1000000, 0).Add(7777 * time.Second / 100).UTC().Format(time.RFC3339)
	e.want(e.do("kill_process", map[string]any{"pid": 500, "start_time": ts}), StatusSucceeded)
	e.want(e.do("kill_process", map[string]any{"pid": 500, "start_time": "2001-01-01T00:00:00Z"}), StatusRejected)
}

func TestKillProcessKillsTree(t *testing.T) {
	// bash -c wrapper (52) -> timeout (58) -> bash -i (59) -> sleep (60); agent (4242) child of 59 must survive
	e := newEnv(t)
	writeProc(t, e.proc, 52, 1, "/usr/bin/bash", "bash -c timeout 180 bash -i", 100)
	writeProc(t, e.proc, 58, 52, "/usr/bin/timeout", "timeout 180 bash -i", 101)
	writeProc(t, e.proc, 59, 58, "/usr/bin/bash", "bash -i", 102)
	writeProc(t, e.proc, 60, 59, "/usr/bin/sleep", "sleep 99", 103)
	writeProc(t, e.proc, 4242, 59, "/usr/bin/aegis-agent", "aegis-agent run", 1)
	writeProc(t, e.proc, 70, 1, "/usr/sbin/sshd", "sshd", 5)
	res := e.do("kill_process", map[string]any{"pid": 52})
	e.want(res, StatusSucceeded)
	got := map[int]bool{}
	for _, k := range e.killed {
		got[k] = true
	}
	for _, want := range []int{52, 58, 59, 60} {
		if !got[want] {
			t.Errorf("pid %d not killed: %v", want, e.killed)
		}
	}
	if got[4242] || got[70] || got[1] {
		t.Fatalf("killed protected/unrelated pid: %v", e.killed)
	}
	if e.killed[len(e.killed)-1] != 52 {
		t.Fatalf("target must be killed last (descendants first): %v", e.killed)
	}
}

func TestCollectEvidence(t *testing.T) {
	e := newEnv(t)
	writeProc(t, e.proc, 600, 1, "/usr/bin/bash", "bash", 10)
	writeProc(t, e.proc, 601, 600, "/tmp/evil", "/tmp/evil", 11)
	res := e.do("collect_evidence", map[string]any{"kind": "process_tree", "target": "601"})
	e.want(res, StatusSucceeded)
	data := res.Result["data"].(map[string]any)
	if anc := data["ancestors"].([]map[string]any); len(anc) != 1 || anc[0]["pid"] != 600 {
		t.Fatalf("%+v", data)
	}
	f := filepath.Join(e.dir, "f.txt")
	os.WriteFile(f, []byte("hello"), 0o600)
	res = e.do("collect_evidence", map[string]any{"kind": "file_hash", "target": f})
	e.want(res, StatusSucceeded)
	if res.Result["data"].(map[string]any)["sha256"] != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("%+v", res.Result)
	}
	res = e.do("collect_evidence", map[string]any{"kind": "file_sample", "target": f})
	e.want(res, StatusSucceeded)
	if res.Result["data"].(map[string]any)["text"] != "hello" {
		t.Fatal("sample")
	}
	e.want(e.do("collect_evidence", map[string]any{"kind": "file_sample", "target": "/etc/shadow"}), StatusRejected)
	e.want(e.do("collect_evidence", map[string]any{"kind": "file_hash", "target": "relative"}), StatusRejected)
	e.want(e.do("collect_evidence", map[string]any{"kind": "shell", "target": "id"}), StatusRejected)
	e.want(e.do("collect_evidence", map[string]any{"kind": "log_excerpt", "target": "../../etc/shadow"}), StatusRejected)
	e.want(e.do("collect_evidence", map[string]any{"kind": "log_excerpt", "target": "journal:ssh; id"}), StatusRejected)

	os.MkdirAll(filepath.Join(e.dir, "log"), 0o755)
	os.WriteFile(filepath.Join(e.dir, "log", "auth.log"), []byte("l1\nl2\nl3\n"), 0o644)
	res = e.do("collect_evidence", map[string]any{"kind": "log_excerpt", "target": "auth.log"})
	e.want(res, StatusSucceeded)
	if lines := res.Result["data"].(map[string]any)["lines"].([]string); len(lines) != 3 {
		t.Fatalf("%v", lines)
	}
	res = e.do("collect_evidence", map[string]any{"kind": "user_info", "target": "alice"})
	e.want(res, StatusSucceeded)
	ui := res.Result["data"].(map[string]any)
	if g := ui["groups"].([]string); len(g) != 2 || g[0] != "alice" || g[1] != "sudo" {
		t.Fatalf("%+v", ui)
	}
	e.want(e.do("collect_evidence", map[string]any{"kind": "netconns"}), StatusSucceeded)
}

func TestTestRuleAndYaraAndLogLevel(t *testing.T) {
	e := newEnv(t)
	yaml := `title: tmp exec
id: 8f2d1c3a-1b2c-4d5e-8f90-a1b2c3d4e5f6
logsource: {product: linux, category: process_creation}
detection:
  s: {Image|startswith: /tmp/}
  condition: s
level: medium
`
	res := e.do("test_rule", map[string]any{"yaml": yaml})
	e.want(res, StatusSucceeded)
	if res.Result["matches"] != 1 || len(res.Result["samples"].([]map[string]any)) != 1 {
		t.Fatalf("%+v", res.Result)
	}
	e.want(e.do("test_rule", map[string]any{"yaml": "title: ["}), StatusRejected)

	res = e.do("yara_scan", map[string]any{"path": "/tmp/x"})
	e.want(res, StatusFailed)
	if res.Error != "built without yara" {
		t.Fatal(res.Error)
	}

	var gotTTL time.Duration
	e.ex.cfg.SetLogLevel = func(_ string, d time.Duration) { gotTTL = d }
	e.want(e.do("raise_log_level", map[string]any{"ttl_seconds": 86401}), StatusRejected)
	e.want(e.do("raise_log_level", map[string]any{"ttl_seconds": 120}), StatusSucceeded)
	if gotTTL != 2*time.Minute {
		t.Fatal(gotTTL)
	}
}

func TestExecRunnerAllowlist(t *testing.T) {
	_, err := ExecRunner{}.Run(context.Background(), Cmd{Name: "sh", Args: []string{"-c", "id"}})
	if err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("shell must be refused: %v", err)
	}
}

func TestActionsMatchContract(t *testing.T) {
	want := []string{"collect_evidence", "test_rule", "yara_scan", "raise_log_level", "kill_process", "block_ip", "disable_user", "quarantine_file", "isolate_host", "rollback"}
	got := Actions()
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for _, w := range want {
		if _, ok := handlers[w]; !ok {
			t.Errorf("missing %s", w)
		}
	}
}
