package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aegis-soc/aegis/agent/internal/collector"
)

const (
	maxSampleBytes = 4096
	maxLogLines    = 200
	maxListEntries = 500
)

var (
	unitRE       = regexp.MustCompile(`^[a-zA-Z0-9_.@:-]{1,64}$`)
	logFileNames = map[string]bool{"auth.log": true, "syslog": true, "secure": true, "messages": true, "kern.log": true, "audit/audit.log": true}
)

// sensitivePath reports paths whose content must never leave the host via
// file_sample (credentials and key material).
func sensitivePath(p string) bool {
	base := filepath.Base(p)
	switch {
	case p == "/etc/shadow", p == "/etc/gshadow", p == "/etc/shadow-", p == "/etc/gshadow-",
		strings.HasPrefix(p, "/proc/kcore"), strings.HasPrefix(p, "/dev/"),
		strings.HasPrefix(p, "/var/lib/aegis/") && !strings.HasPrefix(p, "/var/lib/aegis/quarantine/"),
		strings.HasPrefix(p, "/etc/ssh/ssh_host_") && !strings.HasSuffix(p, ".pub"),
		strings.HasSuffix(p, "/.ssh/id_rsa"), strings.HasSuffix(p, "/.ssh/id_ed25519"),
		strings.HasSuffix(p, "/.ssh/id_ecdsa"), strings.HasSuffix(p, "/.ssh/id_dsa"),
		base == "agent.key", strings.HasSuffix(base, ".pem") && strings.Contains(p, "private"):
		return true
	}
	return false
}

func (e *Executor) collectEvidence(ctx context.Context, cmd Command) (map[string]any, string, error) {
	var p struct {
		Kind   string `json:"kind"`
		Target string `json:"target"`
	}
	if err := decode(cmd.Params, &p); err != nil {
		return nil, "", err
	}
	var data map[string]any
	var err error
	switch p.Kind {
	case "process_tree":
		data, err = e.evProcessTree(p.Target)
	case "open_files":
		data, err = e.evOpenFiles(p.Target)
	case "netconns":
		data, err = e.evNetconns(p.Target)
	case "file_hash":
		data, err = e.evFileHash(p.Target)
	case "log_excerpt":
		data, err = e.evLogExcerpt(ctx, p.Target)
	case "user_info":
		data, err = e.evUserInfo(p.Target)
	case "file_sample":
		data, err = e.evFileSample(p.Target)
	default:
		return nil, "", reject("unknown evidence kind %q", p.Kind)
	}
	if err != nil {
		return nil, "", err
	}
	return map[string]any{"kind": p.Kind, "target": p.Target, "data": data}, "", nil
}

func procMap(p collector.ProcInfo) map[string]any {
	return map[string]any{"pid": p.PID, "ppid": p.PPID, "exe": p.Exe, "cmdline": p.Cmdline, "cwd": p.Cwd,
		"uid": p.UID, "comm": p.Comm, "start_time": p.StartTime,
		"stdin_socket": p.StdinSocket, "stdout_socket": p.StdoutSocket}
}

func (e *Executor) targetPID(t string) (int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(t))
	if err != nil || pid <= 0 {
		return 0, reject("target must be a pid")
	}
	return pid, nil
}

func (e *Executor) evProcessTree(target string) (map[string]any, error) {
	pid, err := e.targetPID(target)
	if err != nil {
		return nil, err
	}
	self, ok := collector.ReadProc(e.cfg.ProcRoot, pid)
	if !ok {
		return nil, fmt.Errorf("process %d not found", pid)
	}
	var ancestors []map[string]any
	cur := self
	for i := 0; i < 32 && cur.PPID > 0; i++ {
		par, ok := collector.ReadProc(e.cfg.ProcRoot, cur.PPID)
		if !ok {
			break
		}
		ancestors = append(ancestors, procMap(par))
		cur = par
	}
	var children []map[string]any
	for _, c := range collector.ListPIDs(e.cfg.ProcRoot) {
		if len(children) >= 100 {
			break
		}
		if ci, ok := collector.ReadProc(e.cfg.ProcRoot, c); ok && ci.PPID == pid {
			children = append(children, procMap(ci))
		}
	}
	return map[string]any{"process": procMap(self), "ancestors": ancestors, "children": children}, nil
}

func (e *Executor) evOpenFiles(target string) (map[string]any, error) {
	pid, err := e.targetPID(target)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(e.cfg.ProcRoot, strconv.Itoa(pid), "fd")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("process %d not readable: %w", pid, err)
	}
	files := []map[string]any{}
	for _, en := range ents {
		if len(files) >= maxListEntries {
			break
		}
		l, err := os.Readlink(filepath.Join(dir, en.Name()))
		if err != nil {
			continue
		}
		files = append(files, map[string]any{"fd": en.Name(), "target": l})
	}
	return map[string]any{"pid": pid, "files": files}, nil
}

var tcpStates = map[int]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
	6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}

func (e *Executor) evNetconns(target string) (map[string]any, error) {
	conns := []map[string]any{}
	for _, c := range collector.ReadProcNet(e.cfg.ProcRoot) {
		if target != "" {
			if !strings.Contains(c.RemoteIP.String(), target) && !strings.Contains(c.LocalIP.String(), target) &&
				strconv.Itoa(c.RemotePort) != target && strconv.Itoa(c.LocalPort) != target {
				continue
			}
		}
		if len(conns) >= maxListEntries {
			break
		}
		conns = append(conns, map[string]any{"local": fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort),
			"remote": fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort), "state": tcpStates[c.State], "uid": c.UID, "inode": c.Inode})
	}
	return map[string]any{"connections": conns}, nil
}

func cleanAbs(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", reject("target must be an absolute path")
	}
	return filepath.Clean(p), nil
}

func (e *Executor) evFileHash(target string) (map[string]any, error) {
	p, err := cleanAbs(target)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, reject("not a regular file")
	}
	sum, err := collector.HashFile(p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"path": p, "sha256": sum, "size": st.Size(), "mode": strconv.FormatUint(uint64(st.Mode().Perm()), 8),
		"mtime": st.ModTime().UTC().Format(time.RFC3339)}, nil
}

func (e *Executor) evFileSample(target string) (map[string]any, error) {
	p, err := cleanAbs(target)
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		if sensitivePath(resolved) {
			return nil, reject("refusing to sample sensitive file")
		}
	}
	if sensitivePath(p) {
		return nil, reject("refusing to sample sensitive file")
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, reject("not a regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxSampleBytes)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	out := map[string]any{"path": p, "size": st.Size(), "sample_bytes": n, "base64": base64.StdEncoding.EncodeToString(buf)}
	if utf8.Valid(buf) {
		out["text"] = string(buf)
	}
	return out, nil
}

func (e *Executor) evLogExcerpt(ctx context.Context, target string) (map[string]any, error) {
	if target == "" {
		target = "auth.log"
		if _, err := os.Stat(filepath.Join(e.cfg.LogDir, target)); err != nil {
			target = "secure"
		}
	}
	if rest, ok := strings.CutPrefix(target, "journal"); ok {
		args := []string{"-n", strconv.Itoa(maxLogLines), "--no-pager", "-o", "short-iso"}
		if unit := strings.TrimPrefix(rest, ":"); unit != "" {
			if !unitRE.MatchString(unit) {
				return nil, reject("invalid journal unit")
			}
			args = append(args, "-u", unit)
		}
		out, err := e.cfg.Runner.Run(ctx, Cmd{Name: "journalctl", Args: args})
		if err != nil {
			return nil, err
		}
		return map[string]any{"source": target, "lines": lastLines(out, maxLogLines)}, nil
	}
	if !logFileNames[target] {
		return nil, reject("log target must be one of the allowlisted log names or journal[:unit]")
	}
	f, err := os.Open(filepath.Join(e.cfg.LogDir, target))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, _ := f.Stat()
	const tail = 64 * 1024
	if st != nil && st.Size() > tail {
		f.Seek(st.Size()-tail, io.SeekStart)
	}
	b, _ := io.ReadAll(f)
	return map[string]any{"source": target, "lines": lastLines(b, maxLogLines)}, nil
}

func lastLines(b []byte, n int) []string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if lines == nil {
		lines = []string{}
	}
	return lines
}

func (e *Executor) evUserInfo(target string) (map[string]any, error) {
	if !usernameRE.MatchString(target) {
		return nil, reject("invalid username")
	}
	u, ok := e.lookupUser(target)
	if !ok {
		return nil, fmt.Errorf("user %q not found", target)
	}
	out := map[string]any{"name": u.Name, "uid": u.UID, "gid": u.GID, "home": u.Home, "shell": u.Shell}
	var groups []string
	if b, err := os.ReadFile(e.cfg.GroupPath); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) < 4 {
				continue
			}
			if f[2] == strconv.Itoa(u.GID) {
				groups = append(groups, f[0])
				continue
			}
			for _, m := range strings.Split(f[3], ",") {
				if m == u.Name {
					groups = append(groups, f[0])
				}
			}
		}
	}
	sort.Strings(groups)
	out["groups"] = groups
	if filepath.IsAbs(u.Home) {
		if b, err := os.ReadFile(filepath.Join(u.Home, ".ssh", "authorized_keys")); err == nil {
			n := 0
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					n++
				}
			}
			out["authorized_keys_count"] = n
		}
	}
	recent := []map[string]any{}
	if e.cfg.Events != nil {
		evs := e.cfg.Events.Snapshot(e.cfg.Now().Add(-24 * time.Hour))
		for i := len(evs) - 1; i >= 0 && len(recent) < 20; i-- {
			ev := evs[i]
			if ev.Logsource.Service != "sshd" && ev.Logsource.Service != "auth" {
				continue
			}
			if ev.User == u.Name || ev.TargetUser == u.Name {
				recent = append(recent, map[string]any{"ts": ev.Time.UTC().Format(time.RFC3339), "kind": ev.Kind, "source_ip": ev.SourceIp})
			}
		}
	}
	out["recent_auth_events"] = recent
	return out, nil
}
