// Package detect is the detection engine: Sigma rules, native rules, IOC
// matching, baselines, suppression and dedup.
package detect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/policy"
	"github.com/aegis-soc/aegis/agent/internal/sigma"
)

const maxEvidenceBytes = 32 * 1024

// Stats is the heartbeat stats block.
type Stats struct {
	EventsPerMin    float64 `json:"events_per_min"`
	AnomaliesPerMin float64 `json:"anomalies_per_min"`
	RulesLoaded     int     `json:"rules_loaded"`
	BufferEvents    int     `json:"buffer_events"`
}

// Engine evaluates events and emits anomalies on Out.
type Engine struct {
	log *slog.Logger
	out chan event.Anomaly
	now func() time.Time

	ring     *Ring
	baseline *Baseline

	mu       sync.RWMutex
	body     policy.Body
	rules    *sigma.RuleSet
	ruleErrs []sigma.LoadError
	iocIP    map[string]bool
	iocSHA   map[string]bool
	iocDom   []string

	smu      sync.Mutex // guards the stateful detectors below
	ssh      *SSHTracker
	rare     *RareDest
	dedup    map[string]time.Time
	counters map[string]float64 // per-minute metric accumulators

	nEvents, nAnomalies atomic.Int64
	lastEv, lastAn      int64
	lastStat            time.Time
	statMu              sync.Mutex
}

// NewEngine builds an engine with default rules loaded.
func NewEngine(log *slog.Logger) *Engine {
	e := &Engine{
		log:      log,
		out:      make(chan event.Anomaly, 1024),
		now:      time.Now,
		ring:     NewRing(DefaultRingCap, DefaultRingAge),
		baseline: NewBaseline(0.1, DefLearnSamples),
		ssh:      NewSSHTracker(),
		dedup:    map[string]time.Time{},
		counters: map[string]float64{},
		lastStat: time.Now(),
	}
	e.rare = NewRareDest(e.now())
	e.SetPolicy(policy.Default())
	return e
}

// Anomalies is the output stream.
func (e *Engine) Anomalies() <-chan event.Anomaly { return e.out }

// Ring exposes the event ring buffer (for test_rule).
func (e *Engine) Ring() *Ring { return e.ring }

// RuleErrors returns per-rule load errors from the last policy swap.
func (e *Engine) RuleErrors() []sigma.LoadError {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]sigma.LoadError(nil), e.ruleErrs...)
}

// SetPolicy hot-swaps rules, thresholds, IOCs, watches and suppressions.
func (e *Engine) SetPolicy(p *policy.Policy) {
	srcs := sigma.DefaultSources()
	for _, r := range p.Body.Rules {
		srcs = append(srcs, sigma.Source{ID: r.ID, Status: r.Status, YAML: r.YAML})
	}
	set, errs := sigma.Load(srcs)
	ip, sha := map[string]bool{}, map[string]bool{}
	var dom []string
	for _, i := range p.Body.IOCs {
		v := strings.ToLower(strings.TrimSpace(i.Value))
		switch i.Type {
		case "ip":
			ip[v] = true
		case "sha256":
			sha[v] = true
		case "domain":
			dom = append(dom, v)
		}
	}
	e.mu.Lock()
	e.body, e.rules, e.ruleErrs = p.Body, set, errs
	e.iocIP, e.iocSHA, e.iocDom = ip, sha, dom
	e.mu.Unlock()
	e.baseline.SetLearning(int(p.Body.Threshold(KeyLearnSamples, DefLearnSamples)))
	for _, le := range errs {
		e.log.Warn("sigma rule failed to load", "rule_id", le.RuleID, "err", le.Error)
	}
	e.log.Info("policy applied to engine", "version", p.Version, "rules", set.Len(), "rule_errors", len(errs))
}

// Stats returns rates since the previous call plus current gauges.
func (e *Engine) Stats() Stats {
	e.statMu.Lock()
	defer e.statMu.Unlock()
	now := time.Now()
	el := now.Sub(e.lastStat).Minutes()
	ev, an := e.nEvents.Load(), e.nAnomalies.Load()
	s := Stats{BufferEvents: e.ring.Len()}
	if el > 0 {
		s.EventsPerMin = float64(ev-e.lastEv) / el
		s.AnomaliesPerMin = float64(an-e.lastAn) / el
	}
	e.lastEv, e.lastAn, e.lastStat = ev, an, now
	e.mu.RLock()
	s.RulesLoaded = e.rules.Len()
	e.mu.RUnlock()
	return s
}

// Run consumes events until ctx is done or in is closed.
func (e *Engine) Run(ctx context.Context, in <-chan event.Event) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			e.Process(ctx, ev)
		case <-t.C:
			e.Tick(ctx)
		}
	}
}

// Process runs detection over one event.
func (e *Engine) Process(ctx context.Context, ev event.Event) {
	if ev.Time.IsZero() {
		ev.Time = e.now().UTC()
	}
	ev.CommandLine = clip(ev.CommandLine, 8192)
	ev.ParentCommandLine = clip(ev.ParentCommandLine, 8192)
	ev.Message = clip(ev.Message, 4096)
	e.nEvents.Add(1)
	e.ring.Add(ev)

	e.mu.RLock()
	rules, body := e.rules, e.body
	e.mu.RUnlock()

	var cands []event.Anomaly
	sigmaHit := false
	for _, m := range rules.Evaluate(ctx, &ev) {
		if !m.Rule.Shadow {
			sigmaHit = true
		}
		cands = append(cands, e.fromSigma(m.Rule, &ev))
	}

	e.smu.Lock()
	cands = append(cands, e.native(&ev, body, sigmaHit)...)
	e.countMetrics(&ev)
	e.smu.Unlock()
	cands = append(cands, e.iocs(&ev)...)

	for _, a := range cands {
		e.emit(ctx, a, body)
	}
}

func (e *Engine) countMetrics(ev *event.Event) {
	switch ev.Kind {
	case event.KindSSHFailed, event.KindSSHInvalidUser:
		e.counters["auth_failures_per_min"]++
	case event.KindExec:
		e.counters["process_execs_per_min"]++
	case event.KindNetOutbound:
		e.counters["outbound_conns_per_min"]++
	}
}

// Tick runs once a minute: baseline scoring and state housekeeping.
func (e *Engine) Tick(ctx context.Context) {
	e.mu.RLock()
	body := e.body
	e.mu.RUnlock()
	now := e.now().UTC()
	e.smu.Lock()
	counters := e.counters
	e.counters = map[string]float64{}
	e.ssh.Sweep(now)
	for fp, t := range e.dedup {
		if now.Sub(t) > 24*time.Hour {
			delete(e.dedup, fp)
		}
	}
	e.smu.Unlock()
	zmax := body.Threshold(KeyZScore, DefZScore)
	for _, m := range []string{"auth_failures_per_min", "process_execs_per_min", "outbound_conns_per_min"} {
		v := counters[m]
		vd := e.baseline.Observe(m, v, zmax)
		if vd.Learning || vd.Z < zmax || v < 3 {
			continue
		}
		a := e.newAnomaly("baseline:"+m, "baseline", "Baseline deviation: "+m, "other", event.SevMedium,
			fmt.Sprintf("%s=%.0f is %.1f sigma above baseline (mean %.1f)", m, v, vd.Z, vd.Mean),
			[]string{m}, nil,
			map[string]any{"metric": m, "value": v, "zscore": vd.Z, "mean": vd.Mean, "std": vd.Std})
		a.AttackTags = []string{}
		e.emit(ctx, a, body)
	}
}

// emit applies suppression and dedup, then queues the anomaly.
func (e *Engine) emit(ctx context.Context, a event.Anomaly, body policy.Body) {
	now := e.now().UTC()
	if body.ActiveSuppression(a.Fingerprint, now) {
		return
	}
	cool := time.Duration(body.Threshold(KeyDedupCooldown, DefCooldown)) * time.Second
	key := a.Fingerprint
	if a.Shadow {
		key = "shadow:" + key
	}
	e.smu.Lock()
	if last, ok := e.dedup[key]; ok && now.Sub(last) < cool {
		e.smu.Unlock()
		return
	}
	e.dedup[key] = now
	e.smu.Unlock()
	e.nAnomalies.Add(1)
	select {
	case e.out <- a:
	case <-ctx.Done():
	default:
		e.log.Warn("anomaly queue full, dropping", "rule_id", a.RuleID)
	}
}

func (e *Engine) fromSigma(r *sigma.Rule, ev *event.Event) event.Anomaly {
	detail := firstNonEmpty(ev.CommandLine, ev.TargetFilename, ev.Image, ev.Message)
	keys := []string{ev.Image, ev.CommandLine, ev.TargetFilename, ev.User, ev.DestinationIp, strconv.Itoa(ev.DestinationPort)}
	a := e.newAnomaly(r.ID, "sigma", r.Title, r.Category(), r.Severity,
		r.Title+": "+clip(detail, 200), keys, ev, nil)
	a.AttackTags = append([]string{}, r.AttackTags...)
	a.Falsepositives = append([]string{}, r.Falsepositives...)
	a.Shadow = r.Shadow
	return a
}

// newAnomaly assembles an Anomaly. evidence may be an *event.Event or a map.
func (e *Engine) newAnomaly(ruleID, source, title, category string, sev event.Severity, summary string, fpKeys []string, evid any, extra map[string]any) event.Anomaly {
	ev := map[string]any{}
	switch v := evid.(type) {
	case *event.Event:
		b, _ := json.Marshal(v)
		_ = json.Unmarshal(b, &ev)
	case map[string]any:
		ev = v
	}
	for k, v := range extra {
		ev[k] = v
	}
	return event.Anomaly{
		ID: newUUID(), Ts: e.now().UTC().Format(time.RFC3339),
		RuleID: ruleID, RuleSource: source, RuleTitle: title, Category: category,
		Severity: sev, Fingerprint: Fingerprint(ruleID, fpKeys...), Summary: clip(summary, 500),
		AttackTags: []string{}, Falsepositives: []string{}, Evidence: boundEvidence(ev),
	}
}

// Fingerprint is sha256(rule_id + key fields), hex.
func Fingerprint(ruleID string, keys ...string) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// boundEvidence keeps the JSON size under maxEvidenceBytes by shrinking long strings.
func boundEvidence(m map[string]any) map[string]any {
	for lim := 4096; lim >= 64; lim /= 4 {
		if b, _ := json.Marshal(m); len(b) <= maxEvidenceBytes {
			return m
		}
		shrink(m, lim)
	}
	return map[string]any{"truncated": true}
}

func shrink(v any, lim int) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, ok := x.(string); ok {
				t[k] = clip(s, lim)
			} else {
				shrink(x, lim)
			}
		}
	case []any:
		for i, x := range t {
			if s, ok := x.(string); ok {
				t[i] = clip(s, lim)
			} else {
				shrink(x, lim)
			}
		}
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// native applies the built-in rules. Caller holds smu.
func (e *Engine) native(ev *event.Event, body policy.Body, sigmaHit bool) []event.Anomaly {
	var out []event.Anomaly
	switch ev.Kind {
	case event.KindSSHFailed, event.KindSSHInvalidUser, event.KindSSHAccepted:
		bw := time.Duration(body.Threshold(KeyBruteWindow, DefBruteWindow)) * time.Second
		sw := time.Duration(body.Threshold(KeySuccessWindow, DefSuccessWindow)) * time.Second
		r, ok := e.ssh.Observe(ev, int(body.Threshold(KeyBruteCount, DefBruteCount)), bw,
			int(body.Threshold(KeySuccessCount, DefSuccessCount)), sw)
		if ok && r.Brute {
			a := e.newAnomaly("native:ssh_bruteforce", "native", "SSH brute force", "auth", event.SevHigh,
				fmt.Sprintf("%d failed SSH logins from %s within %s", r.Failures, r.IP, bw), []string{r.IP}, ev,
				map[string]any{"failures": r.Failures, "window_s": bw.Seconds()})
			a.AttackTags = []string{"attack.credential_access", "attack.t1110"}
			a.Falsepositives = []string{"Misconfigured automation retrying with a bad credential", "Vulnerability scanners"}
			out = append(out, a)
		}
		if ok && r.SuccessAfter {
			a := e.newAnomaly("native:ssh_success_after_failures", "native", "SSH login succeeded after repeated failures", "auth", event.SevCritical,
				fmt.Sprintf("successful SSH login for %s from %s after %d failures", r.User, r.IP, r.Failures), []string{r.IP, r.User}, ev,
				map[string]any{"prior_failures": r.Failures})
			a.AttackTags = []string{"attack.initial_access", "attack.t1078", "attack.credential_access", "attack.t1110"}
			a.Falsepositives = []string{"A legitimate user who mistyped their password repeatedly"}
			out = append(out, a)
		}
	case event.KindNetListen:
		sev := event.SevMedium
		for _, w := range body.Watches {
			if w.Kind == "port" && w.Target == strconv.Itoa(ev.SourcePort) {
				sev = event.SevHigh
			}
		}
		a := e.newAnomaly("native:new_listener", "native", "New listening port", "network", sev,
			fmt.Sprintf("new TCP listener on %s:%d", ev.SourceIp, ev.SourcePort), []string{strconv.Itoa(ev.SourcePort)}, ev, nil)
		a.AttackTags = []string{"attack.command_and_control", "attack.t1571"}
		a.Falsepositives = []string{"Newly installed or restarted services", "Developer test servers"}
		out = append(out, a)
	case event.KindNetOutbound:
		learn := time.Duration(body.Threshold(KeyRareLearning, DefRareLearning)) * time.Second
		if e.rare.Observe(ev.DestinationIp, e.now(), learn) {
			a := e.newAnomaly("native:rare_outbound", "native", "Rare outbound destination", "network", event.SevLow,
				fmt.Sprintf("first outbound connection to %s:%d", ev.DestinationIp, ev.DestinationPort), []string{ev.DestinationIp}, ev, nil)
			a.AttackTags = []string{"attack.command_and_control", "attack.t1071"}
			a.Falsepositives = []string{"New software update or API endpoints", "CDN address rotation"}
			out = append(out, a)
		}
		for _, w := range body.Watches {
			if w.Kind == "port" && w.Target == strconv.Itoa(ev.DestinationPort) {
				a := e.newAnomaly("native:watch_port", "native", "Connection to watched port", "network", event.SevMedium,
					fmt.Sprintf("outbound connection to %s:%d (watched port)", ev.DestinationIp, ev.DestinationPort),
					[]string{ev.DestinationIp, strconv.Itoa(ev.DestinationPort)}, ev, nil)
				out = append(out, a)
			}
		}
	case event.KindProcSuspiciousExe:
		a := e.newAnomaly("native:proc_exec_from_tmp", "native", "Process running from temporary directory", "process", event.SevMedium,
			"process running from "+ev.Image, []string{ev.Image}, ev, nil)
		a.AttackTags = []string{"attack.execution", "attack.t1204.002", "attack.defense_evasion", "attack.t1036"}
		a.Falsepositives = []string{"Installers or test harnesses"}
		out = append(out, a)
	case event.KindProcDeletedExe:
		a := e.newAnomaly("native:proc_deleted_exe", "native", "Process running from deleted binary", "process", event.SevHigh,
			"process "+ev.Image+" executing from a deleted file", []string{ev.Image, strconv.Itoa(ev.ProcessId)}, ev, nil)
		a.AttackTags = []string{"attack.defense_evasion", "attack.t1070.004"}
		a.Falsepositives = []string{"Package upgrades leave long-running daemons on the old inode until restart"}
		out = append(out, a)
	case event.KindProcReverseShell:
		a := e.newAnomaly("native:proc_reverse_shell", "native", "Shell with socket stdin/stdout (reverse shell)", "process", event.SevCritical,
			fmt.Sprintf("shell %s (pid %d) has its stdin/stdout attached to a socket", ev.Image, ev.ProcessId),
			[]string{ev.Image, strconv.Itoa(ev.ProcessId), strconv.FormatUint(ev.ProcessStartTime, 10)}, ev, nil)
		a.AttackTags = []string{"attack.execution", "attack.t1059.004"}
		a.Falsepositives = []string{"inetd/xinetd-style services that spawn a shell per connection"}
		out = append(out, a)
	case event.KindUserNew:
		a := e.newAnomaly("native:user_new", "native", "New local user account", "user", event.SevMedium,
			"new account "+ev.TargetUser, []string{ev.TargetUser}, ev, nil)
		a.AttackTags = []string{"attack.persistence", "attack.t1136.001"}
		a.Falsepositives = []string{"Administrators provisioning accounts", "Package installs creating service users"}
		out = append(out, a)
	case event.KindUserNewUID0:
		a := e.newAnomaly("native:user_new_uid0", "native", "New account with UID 0", "user", event.SevCritical,
			"account "+ev.TargetUser+" has uid 0", []string{ev.TargetUser}, ev, nil)
		a.AttackTags = []string{"attack.persistence", "attack.t1136.001", "attack.privilege_escalation", "attack.t1078.003"}
		out = append(out, a)
	case event.KindFileCreated, event.KindFileModified, event.KindFileDeleted:
		if sigmaHit {
			break // a Sigma rule already covers this change
		}
		sev := event.SevMedium
		if isCriticalPath(ev.TargetFilename) {
			sev = event.SevHigh
		}
		verb := strings.TrimPrefix(ev.Kind, "file_")
		a := e.newAnomaly("native:fim_change", "native", "Monitored file changed", "file", sev,
			fmt.Sprintf("%s %s", ev.TargetFilename, verb), []string{ev.TargetFilename, ev.Sha256, ev.Kind}, ev, nil)
		a.AttackTags = []string{"attack.persistence", "attack.defense_evasion"}
		a.Falsepositives = []string{"Legitimate administration and package upgrades"}
		out = append(out, a)
	}
	if ev.Logsource.Category == event.CategoryProcessCreation {
		for _, w := range body.Watches {
			if w.Kind != "process" || w.Target == "" {
				continue
			}
			if path.Base(ev.Image) == w.Target || strings.Contains(ev.CommandLine, w.Target) {
				out = append(out, e.newAnomaly("native:watch_process", "native", "Watched process executed", "process", event.SevMedium,
					"watched process "+w.Target+": "+clip(ev.CommandLine, 200), []string{w.Target, ev.Image, ev.CommandLine}, ev, nil))
			}
		}
	}
	return out
}

var criticalPaths = []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ld.so.preload", "/etc/ssh/sshd_config"}

func isCriticalPath(p string) bool {
	for _, c := range criticalPaths {
		if p == c {
			return true
		}
	}
	return strings.HasPrefix(p, "/etc/sudoers.d/") || strings.HasSuffix(p, "/authorized_keys")
}

// iocs matches the event against policy indicators.
func (e *Engine) iocs(ev *event.Event) []event.Anomaly {
	e.mu.RLock()
	ips, shas, doms := e.iocIP, e.iocSHA, e.iocDom
	e.mu.RUnlock()
	var out []event.Anomaly
	for _, ip := range []string{ev.DestinationIp, ev.SourceIp} {
		if ip != "" && ips[strings.ToLower(ip)] {
			a := e.newAnomaly("ioc:ip", "ioc", "Known-bad IP address", "network", event.SevHigh,
				"traffic involving IOC address "+ip, []string{ip}, ev, map[string]any{"ioc": ip})
			a.AttackTags = []string{"attack.command_and_control"}
			out = append(out, a)
		}
	}
	if ev.Sha256 != "" && shas[strings.ToLower(ev.Sha256)] {
		a := e.newAnomaly("ioc:sha256", "ioc", "Known-bad file hash", "file", event.SevHigh,
			fmt.Sprintf("file %s matches IOC hash", ev.TargetFilename), []string{ev.Sha256}, ev, map[string]any{"ioc": ev.Sha256})
		out = append(out, a)
	}
	if len(doms) > 0 {
		hay := strings.ToLower(ev.DestinationHostname + " " + ev.CommandLine + " " + ev.Message)
		for _, d := range doms {
			if d != "" && strings.Contains(hay, d) {
				a := e.newAnomaly("ioc:domain", "ioc", "Known-bad domain", "network", event.SevHigh,
					"reference to IOC domain "+d, []string{d}, ev, map[string]any{"ioc": d})
				out = append(out, a)
			}
		}
	}
	return out
}
