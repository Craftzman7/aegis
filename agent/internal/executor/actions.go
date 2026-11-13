package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/collector"
	"github.com/aegis-soc/aegis/agent/internal/sigma"
)

const (
	nftTable        = "aegis"
	nftIsolateTable = "aegis_isolate"
)

var usernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)

// decode strictly unmarshals params into v; unknown fields are a rejection.
func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return reject("invalid params: %v", err)
	}
	return nil
}

// ttl validates a ttl_seconds value against (0, max].
func ttl(v float64, max int64) (time.Duration, error) {
	if v != float64(int64(v)) || v <= 0 || int64(v) > max {
		return 0, reject("ttl_seconds must be an integer in 1..%d", max)
	}
	return time.Duration(int64(v)) * time.Second, nil
}

func killPID(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }

// ---- raise_log_level ----

func (e *Executor) raiseLogLevel(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		TTLSeconds float64 `json:"ttl_seconds"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	d, err := ttl(p.TTLSeconds, 86400)
	if err != nil {
		return nil, "", err
	}
	if e.cfg.SetLogLevel != nil {
		e.cfg.SetLogLevel("debug", d)
	}
	return map[string]any{}, "", nil
}

// ---- test_rule ----

func (e *Executor) testRule(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		YAML string `json:"yaml"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	if len(p.YAML) == 0 || len(p.YAML) > 64*1024 {
		return nil, "", reject("yaml must be 1..65536 bytes")
	}
	rule, err := sigma.Compile(p.YAML, true)
	if err != nil {
		return nil, "", reject("rule does not compile: %v", err)
	}
	if e.cfg.Events == nil {
		return nil, "", errors.New("no event buffer available")
	}
	events := e.cfg.Events.Snapshot(e.cfg.Now().Add(-24 * time.Hour))
	matches := 0
	var samples []map[string]any
	rs, _ := sigma.Load([]sigma.Source{{ID: "test", Status: sigma.StatusShadow, YAML: p.YAML}})
	for i := range events {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		if len(rs.Evaluate(ctx, &events[i])) == 0 {
			continue
		}
		matches++
		if len(samples) < 10 {
			b, _ := json.Marshal(events[i])
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			samples = append(samples, m)
		}
	}
	return map[string]any{"matches": matches, "samples": samples, "scanned": len(events), "rule_id": rule.ID}, "", nil
}

// ---- kill_process ----

func (e *Executor) killProcess(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		PID       float64 `json:"pid"`
		StartTime any     `json:"start_time"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	pid := int(p.PID)
	if float64(pid) != p.PID || pid <= 1 {
		return nil, "", reject("pid must be an integer > 1")
	}
	if pid == e.cfg.SelfPID {
		return nil, "", reject("refusing to kill the agent")
	}
	pi, ok := collector.ReadProc(e.cfg.ProcRoot, pid)
	if !ok {
		return nil, "", fmt.Errorf("process %d not found", pid)
	}
	if pi.Exe == "" && pi.Cmdline == "" {
		return nil, "", reject("refusing to kill kernel thread")
	}
	if p.StartTime != nil {
		match, err := e.startTimeMatches(pi, p.StartTime)
		if err != nil {
			return nil, "", reject("%v", err)
		}
		if !match {
			return nil, "", reject("start_time mismatch: pid %d was reused", pid)
		}
	}
	// Kill the whole tree: an attacker's payload is often a wrapper
	// (bash -c / timeout / nohup) whose children keep running if only the
	// named pid dies. Descendants are killed first so they cannot be
	// re-parented and escape, then the target itself.
	desc := e.descendants(pid)
	var killedDesc []int
	for i := len(desc) - 1; i >= 0; i-- {
		if d := desc[i]; d != e.cfg.SelfPID && e.cfg.Kill(d) == nil {
			killedDesc = append(killedDesc, d)
		}
	}
	if err := e.cfg.Kill(pid); err != nil {
		return nil, "", err
	}
	return map[string]any{"killed": true, "pid": pid, "image": pi.ImagePath(), "descendants_killed": killedDesc}, "", nil
}

// descendants returns all transitive children of pid in BFS order (parents
// before children). It never includes pid 1 or the agent itself.
func (e *Executor) descendants(pid int) []int {
	children := map[int][]int{}
	for _, c := range collector.ListPIDs(e.cfg.ProcRoot) {
		if pi, ok := collector.ReadProc(e.cfg.ProcRoot, c); ok {
			children[pi.PPID] = append(children[pi.PPID], c)
		}
	}
	var out []int
	seen := map[int]bool{pid: true}
	queue := []int{pid}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if seen[c] || c <= 1 || c == e.cfg.SelfPID {
				continue
			}
			seen[c] = true
			out = append(out, c)
			queue = append(queue, c)
		}
	}
	return out
}

const clkTck = 100

// startTimeMatches compares a command start_time (clock ticks since boot as a
// number or digit string, or an RFC3339 timestamp) with the live process.
func (e *Executor) startTimeMatches(pi collector.ProcInfo, v any) (bool, error) {
	switch t := v.(type) {
	case float64:
		return uint64(t) == pi.StartTime, nil
	case string:
		if n, err := strconv.ParseUint(t, 10, 64); err == nil {
			return n == pi.StartTime, nil
		}
		ts, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false, fmt.Errorf("start_time must be ticks or RFC3339")
		}
		boot, err := bootTime(e.cfg.ProcRoot)
		if err != nil {
			return false, err
		}
		actual := boot.Add(time.Duration(pi.StartTime) * time.Second / clkTck)
		d := actual.Sub(ts)
		if d < 0 {
			d = -d
		}
		return d <= 2*time.Second, nil
	}
	return false, fmt.Errorf("start_time must be ticks or RFC3339")
}

func bootTime(procRoot string) (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return time.Time{}, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, "btime "); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			return time.Unix(n, 0), err
		}
	}
	return time.Time{}, errors.New("btime not found")
}

// ---- block_ip ----

func (e *Executor) serverIPs(ctx context.Context) (map[string]bool, error) {
	hosts := append([]string{}, e.cfg.Policy().ServerEndpoints...)
	if e.cfg.ServerURL != "" {
		hosts = append(hosts, e.cfg.ServerURL)
	}
	ips := map[string]bool{}
	for _, h := range hosts {
		host := h
		if strings.Contains(h, "://") {
			u, err := url.Parse(h)
			if err != nil {
				continue
			}
			host = u.Hostname()
		} else if hh, _, err := net.SplitHostPort(h); err == nil {
			host = hh
		}
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips[ip.String()] = true
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		rs, err := e.cfg.Resolver(rctx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range rs {
			ips[ip.String()] = true
		}
	}
	return ips, nil
}

func nftSetFor(ip net.IP) (set, family string) {
	if ip.To4() != nil {
		return "blocked", "ip"
	}
	return "blocked6", "ip6"
}

func (e *Executor) blockIP(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		IP         string  `json:"ip"`
		TTLSeconds float64 `json:"ttl_seconds"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	ip := net.ParseIP(strings.TrimSpace(p.IP))
	if ip == nil {
		return nil, "", reject("invalid ip")
	}
	d, err := ttl(p.TTLSeconds, 604800)
	if err != nil {
		return nil, "", err
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return nil, "", reject("refusing to block %s", ip)
	}
	// Private ranges are allowed (internal attackers), but never the host's own
	// addresses or its default gateway: that would cut the host off the network.
	for _, own := range e.protectedIPs() {
		if own.Equal(ip) {
			return nil, "", reject("refusing to block %s: it is this host's own address or default gateway", ip)
		}
	}
	srv, _ := e.serverIPs(ctx)
	if srv[ip.String()] {
		return nil, "", reject("refusing to block a server endpoint")
	}
	set, fam := nftSetFor(ip)
	script := fmt.Sprintf(`add table inet %[1]s
add set inet %[1]s blocked { type ipv4_addr; flags timeout; }
add set inet %[1]s blocked6 { type ipv6_addr; flags timeout; }
add chain inet %[1]s input { type filter hook input priority -10; policy accept; }
add chain inet %[1]s output { type filter hook output priority -10; policy accept; }
flush chain inet %[1]s input
flush chain inet %[1]s output
add rule inet %[1]s input ip saddr @blocked drop
add rule inet %[1]s input ip6 saddr @blocked6 drop
add rule inet %[1]s output ip daddr @blocked drop
add rule inet %[1]s output ip6 daddr @blocked6 drop
add element inet %[1]s %[2]s { %[3]s timeout %[4]ds }
`, nftTable, set, ip.String(), int64(d.Seconds()))
	_ = fam
	if _, err := e.cfg.Runner.Run(ctx, Cmd{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(script)}); err != nil {
		return nil, "", err
	}
	tok := newToken()
	now := e.cfg.Now()
	if err := e.st.addRollback(RollbackRecord{Token: tok, Action: "block_ip", CommandID: cmd.ID, CreatedAt: now,
		ExpiresAt: now.Add(d + 5*time.Second), Params: map[string]string{"ip": ip.String()}}); err != nil {
		return nil, "", err
	}
	return map[string]any{"ip": ip.String(), "expires_in_s": int64(d.Seconds())}, tok, nil
}

// ---- isolate_host ----

func (e *Executor) isolateHost(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		TTLSeconds float64 `json:"ttl_seconds"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	d, err := ttl(p.TTLSeconds, 86400)
	if err != nil {
		return nil, "", err
	}
	srv, _ := e.serverIPs(ctx)
	var v4, v6 []string
	for s := range srv {
		if ip := net.ParseIP(s); ip != nil {
			if ip.To4() != nil {
				v4 = append(v4, s)
			} else {
				v6 = append(v6, s)
			}
		}
	}
	if len(v4)+len(v6) == 0 {
		return nil, "", reject("no resolvable server endpoints; isolation would cut the agent off")
	}
	var b strings.Builder
	t := nftIsolateTable
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", t, t)
	fmt.Fprintf(&b, "table inet %s {\n", t)
	for _, c := range []struct{ name, hook, ipdir string }{{"input", "input", "saddr"}, {"output", "output", "daddr"}} {
		iface := "iifname"
		if c.name == "output" {
			iface = "oifname"
		}
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority -100; policy drop;\n", c.name, c.hook)
		// No blanket "ct state established" accept: isolation must also sever
		// connections that already exist (e.g. an attacker's reverse shell).
		// Only loopback and the pinned Aegis server endpoints survive.
		fmt.Fprintf(&b, "    %s \"lo\" accept\n", iface)
		if len(v4) > 0 {
			fmt.Fprintf(&b, "    ip %s { %s } accept\n", c.ipdir, strings.Join(v4, ", "))
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "    ip6 %s { %s } accept\n", c.ipdir, strings.Join(v6, ", "))
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	if _, err := e.cfg.Runner.Run(ctx, Cmd{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(b.String())}); err != nil {
		return nil, "", err
	}
	e.st.markActionDone("isolate_host") // supersede earlier isolations
	tok := newToken()
	now := e.cfg.Now()
	if err := e.st.addRollback(RollbackRecord{Token: tok, Action: "isolate_host", CommandID: cmd.ID, CreatedAt: now,
		ExpiresAt: now.Add(d), Params: map[string]string{}}); err != nil {
		return nil, "", err
	}
	return map[string]any{"ttl_seconds": int64(d.Seconds()), "allowed_ips": len(v4) + len(v6)}, tok, nil
}

// ---- disable_user ----

func (e *Executor) lookupUser(name string) (collector.PasswdEntry, bool) {
	f, err := os.Open(e.cfg.PasswdPath)
	if err != nil {
		return collector.PasswdEntry{}, false
	}
	defer f.Close()
	for _, u := range collector.ParsePasswd(f) {
		if u.Name == name {
			return u, true
		}
	}
	return collector.PasswdEntry{}, false
}

func (e *Executor) disableUser(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		Username string `json:"username"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	if !usernameRE.MatchString(p.Username) {
		return nil, "", reject("invalid username")
	}
	if p.Username == "root" {
		return nil, "", reject("refusing to disable root")
	}
	u, ok := e.lookupUser(p.Username)
	if !ok {
		return nil, "", reject("user %q not found", p.Username)
	}
	if u.UID == 0 {
		return nil, "", reject("refusing to disable a uid 0 account")
	}
	if u.UID == e.cfg.SelfUID {
		return nil, "", reject("refusing to disable the agent's own account")
	}
	if _, err := e.cfg.Runner.Run(ctx, Cmd{Name: "usermod", Args: []string{"-L", "-e", "1", p.Username}}); err != nil {
		return nil, "", err
	}
	tok := newToken()
	if err := e.st.addRollback(RollbackRecord{Token: tok, Action: "disable_user", CommandID: cmd.ID, CreatedAt: e.cfg.Now(),
		Params: map[string]string{"username": p.Username}}); err != nil {
		return nil, "", err
	}
	return map[string]any{"username": p.Username, "uid": u.UID}, tok, nil
}

// ---- quarantine_file ----

var quarantineDenyPrefixes = []string{"/proc/", "/sys/", "/dev/", "/boot/"}

func (e *Executor) expectChange(path, sha256 string) {
	if e.cfg.ExpectChange != nil {
		e.cfg.ExpectChange(path, sha256)
	}
}

func (e *Executor) quarantineDir() string { return filepath.Join(e.cfg.DataDir, "quarantine") }

func (e *Executor) quarantineFile(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path {
		return nil, "", reject("path must be absolute and clean")
	}
	for _, d := range quarantineDenyPrefixes {
		if strings.HasPrefix(p.Path, d) {
			return nil, "", reject("path %s is not quarantinable", p.Path)
		}
	}
	if strings.HasPrefix(p.Path, e.cfg.DataDir+"/") || p.Path == e.cfg.SelfExe {
		return nil, "", reject("refusing to quarantine agent files")
	}
	st, err := os.Lstat(p.Path)
	if err != nil {
		return nil, "", err
	}
	if !st.Mode().IsRegular() {
		return nil, "", reject("not a regular file")
	}
	sum, err := collector.HashFile(p.Path)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(e.quarantineDir(), 0o700); err != nil {
		return nil, "", err
	}
	dest := filepath.Join(e.quarantineDir(), fmt.Sprintf("%s-%s.%d", sum[:16], filepath.Base(p.Path), e.cfg.Now().Unix()))
	e.expectChange(p.Path, sum)
	if err := moveFile(p.Path, dest); err != nil {
		return nil, "", err
	}
	if err := os.Chmod(dest, 0o000); err != nil {
		return nil, "", err
	}
	tok := newToken()
	if err := e.st.addRollback(RollbackRecord{Token: tok, Action: "quarantine_file", CommandID: cmd.ID, CreatedAt: e.cfg.Now(),
		Params: map[string]string{"original": p.Path, "quarantine": dest, "mode": strconv.FormatUint(uint64(st.Mode().Perm()), 8), "sha256": sum}}); err != nil {
		return nil, "", err
	}
	return map[string]any{"quarantine_path": dest, "sha256": sum, "size": st.Size()}, tok, nil
}

// moveFile renames, falling back to copy+remove across filesystems.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}

// ---- rollback ----

func (e *Executor) rollback(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		Token string `json:"rollback_token"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	rec, ok := e.st.rollback(p.Token)
	if !ok {
		return nil, "", reject("unknown rollback_token")
	}
	if rec.Done {
		return map[string]any{"already_rolled_back": true, "action": rec.Action}, "", nil
	}
	if err := e.undo(ctx, rec); err != nil {
		return nil, "", err
	}
	if err := e.st.markDone(rec.Token); err != nil {
		return nil, "", err
	}
	return map[string]any{"action": rec.Action}, "", nil
}

// undo performs the inverse of rec.Action.
func (e *Executor) undo(ctx context.Context, rec RollbackRecord) error {
	nft := func(script string) error {
		_, err := e.cfg.Runner.Run(ctx, Cmd{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(script)})
		return err
	}
	ignoreMissing := func(err error) error {
		if err != nil && (strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "does not exist")) {
			return nil
		}
		return err
	}
	switch rec.Action {
	case "block_ip":
		ip := net.ParseIP(rec.Params["ip"])
		if ip == nil {
			return errors.New("corrupt rollback record")
		}
		set, _ := nftSetFor(ip)
		return ignoreMissing(nft(fmt.Sprintf("delete element inet %s %s { %s }\n", nftTable, set, ip)))
	case "isolate_host":
		return ignoreMissing(nft(fmt.Sprintf("delete table inet %s\n", nftIsolateTable)))
	case "disable_user":
		name := rec.Params["username"]
		if !usernameRE.MatchString(name) {
			return errors.New("corrupt rollback record")
		}
		_, err := e.cfg.Runner.Run(ctx, Cmd{Name: "usermod", Args: []string{"-U", "-e", "", name}})
		return err
	case "quarantine_file":
		orig, q := rec.Params["original"], rec.Params["quarantine"]
		if filepath.Dir(q) != e.quarantineDir() || !filepath.IsAbs(orig) {
			return errors.New("corrupt rollback record")
		}
		if _, err := os.Lstat(orig); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite", orig)
		}
		if err := os.Chmod(q, 0o600); err != nil {
			return err
		}
		e.expectChange(orig, rec.Params["sha256"])
		if err := moveFile(q, orig); err != nil {
			return err
		}
		mode, _ := strconv.ParseUint(rec.Params["mode"], 8, 32)
		return os.Chmod(orig, os.FileMode(mode))
	}
	return fmt.Errorf("no rollback for action %q", rec.Action)
}

// protectedIPs returns this host's interface addresses plus its IPv4 default
// gateways (from /proc/net/route).
func (e *Executor) protectedIPs() []net.IP {
	var out []net.IP
	if e.cfg.LocalIPs != nil {
		out = append(out, e.cfg.LocalIPs()...)
	} else if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, n.IP)
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(e.cfg.ProcRoot, "net", "route")); err == nil {
		out = append(out, parseDefaultGateways(string(b))...)
	}
	return out
}

// parseDefaultGateways extracts gateways of default routes (Destination 00000000)
// from /proc/net/route. Addresses are little-endian hex.
func parseDefaultGateways(route string) []net.IP {
	var out []net.IP
	for i, line := range strings.Split(route, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		out = append(out, net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)))
	}
	return out
}
