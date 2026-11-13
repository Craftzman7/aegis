package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

var (
	reSSHFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)`)
	reSSHAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	reSSHInvalid  = regexp.MustCompile(`^(?:Invalid user|Disconnected from invalid user|Connection closed by invalid user) (\S*) (?:from )?(\S+)(?: port (\d+))?`)
	reSSHAuthFail = regexp.MustCompile(`^(?:Connection closed|Disconnected from) authenticating user (\S+) (\S+) port (\d+)`)
	reSudoCmd     = regexp.MustCompile(`^\s*(\S+) : (?:(\d+) incorrect password attempts? ; )?(?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; COMMAND=(.*)$`)
	reSudoFail    = regexp.MustCompile(`^\s*(\S+) : (\d+) incorrect password attempts?`)
	reSuOK        = regexp.MustCompile(`^(?:\(to (\S+)\) (\S+) on (\S+)|Successful su for (\S+) by (\S+))`)
	reSuFail      = regexp.MustCompile(`^(?:FAILED SU \(to (\S+)\) (\S+) on (\S+)|FAILED su for (\S+) by (\S+))`)
	reUserAdd     = regexp.MustCompile(`^new user: name=(\S+?), UID=(\d+), GID=(\d+)(?:, home=(\S+?))?(?:, shell=(\S+?))?(?:, from=\S+)?$`)
	reGroupAdd    = regexp.MustCompile(`^new group: name=(\S+?), GID=(\d+)`)
	reUserMod     = regexp.MustCompile(`^(?:change user '(\S+)' (\w+)|add '(\S+)' to (?:shadow )?group '(\S+)'|add '(\S+)' to (?:shadow )?group)`)
	reSyslog      = regexp.MustCompile(`^(?:(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)|(\d{4}-\d\d-\d\dT\S+))\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s*(.*)$`)
)

// ParseMessage normalizes one auth-related log message produced by program
// ident (e.g. "sshd", "sudo", "su", "useradd"). ok is false for irrelevant lines.
func ParseMessage(ident, msg string, ts time.Time) (event.Event, bool) {
	base := event.Event{Time: ts, Source: "authlog", Message: msg}
	base.Logsource = event.Logsource{Product: event.ProductLinux, Service: event.ServiceAuth}
	ident = strings.TrimSuffix(ident, ":")
	switch ident {
	case "sshd", "sshd-session":
		base.Logsource.Service = event.ServiceSSHD
		if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSSHFailed
			base.User, base.SourceIp = m[3], m[4]
			base.SourcePort, _ = strconv.Atoi(m[5])
			base.Extra = map[string]string{"auth_method": m[1]}
			if m[2] != "" {
				base.Extra["invalid_user"] = "true"
			}
			return base, true
		}
		if m := reSSHAccepted.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSSHAccepted
			base.User, base.SourceIp = m[2], m[3]
			base.SourcePort, _ = strconv.Atoi(m[4])
			base.Extra = map[string]string{"auth_method": m[1]}
			return base, true
		}
		if m := reSSHInvalid.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSSHInvalidUser
			base.User, base.SourceIp = m[1], m[2]
			base.SourcePort, _ = strconv.Atoi(m[3])
			return base, true
		}
		if m := reSSHAuthFail.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSSHFailed
			base.User, base.SourceIp = m[1], m[2]
			base.SourcePort, _ = strconv.Atoi(m[3])
			base.Extra = map[string]string{"auth_method": "preauth_close"}
			return base, true
		}
	case "sudo":
		if m := reSudoCmd.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSudo
			base.User, base.CurrentDirectory, base.TargetUser, base.CommandLine = m[1], m[4], m[5], strings.TrimSpace(m[6])
			if m[2] != "" {
				base.Kind = event.KindSudoFailed
			}
			return base, true
		}
		if m := reSudoFail.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSudoFailed
			base.User = m[1]
			return base, true
		}
		if strings.Contains(msg, "authentication failure") {
			base.Kind = event.KindSudoFailed
			base.User = kv(msg, "ruser=")
			base.TargetUser = kv(msg, " user=")
			return base, true
		}
	case "su", "su-l":
		if m := reSuFail.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSuFailed
			base.TargetUser, base.User = pick(m[1], m[4]), pick(m[2], m[5])
			return base, true
		}
		if m := reSuOK.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindSu
			base.TargetUser, base.User = pick(m[1], m[4]), pick(m[2], m[5])
			return base, true
		}
		if strings.Contains(msg, "authentication failure") {
			base.Kind = event.KindSuFailed
			base.User = kv(msg, "ruser=")
			base.TargetUser = kv(msg, " user=")
			return base, true
		}
	case "useradd", "usermod", "groupadd", "adduser", "gpasswd":
		base.Logsource.Service = event.ServiceAuth
		if m := reUserAdd.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindUserAdd
			base.TargetUser = m[1]
			base.Extra = map[string]string{"uid": m[2], "gid": m[3], "home": m[4], "shell": m[5]}
			return base, true
		}
		if m := reGroupAdd.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindGroupAdd
			base.TargetUser = m[1]
			base.Extra = map[string]string{"gid": m[2]}
			return base, true
		}
		if m := reUserMod.FindStringSubmatch(msg); m != nil {
			base.Kind = event.KindUserMod
			base.TargetUser = pick(m[1], pick(m[3], m[5]))
			base.Extra = map[string]string{"change": pick(m[2], "group:"+m[4])}
			return base, true
		}
	}
	return event.Event{}, false
}

func pick(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// kv extracts the value following key up to the next space.
func kv(s, key string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	v := s[i+len(key):]
	if j := strings.IndexByte(v, ' '); j >= 0 {
		v = v[:j]
	}
	return v
}

// ParseSyslogLine parses a traditional auth.log/secure line. year is used for
// RFC3164 timestamps that omit it.
func ParseSyslogLine(line string, year int, loc *time.Location) (event.Event, bool) {
	m := reSyslog.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}
	var ts time.Time
	if m[2] != "" {
		ts, _ = time.Parse(time.RFC3339Nano, m[2])
	} else {
		t, err := time.ParseInLocation("Jan _2 15:04:05 2006", m[1]+" "+strconv.Itoa(year), loc)
		if err == nil {
			ts = t.UTC()
		}
	}
	e, ok := ParseMessage(m[4], m[6], ts)
	if ok && m[5] != "" {
		if e.Extra == nil {
			e.Extra = map[string]string{}
		}
		e.Extra["pid"] = m[5]
	}
	return e, ok
}

// journalEntry is the subset of `journalctl -o json` we use.
type journalEntry struct {
	Message    any    `json:"MESSAGE"`
	Ident      string `json:"SYSLOG_IDENTIFIER"`
	Comm       string `json:"_COMM"`
	PID        string `json:"_PID"`
	RealtimeUs string `json:"__REALTIME_TIMESTAMP"`
}

// ParseJournalJSON parses one line of `journalctl -o json` output.
func ParseJournalJSON(line []byte) (event.Event, bool) {
	var je journalEntry
	if err := json.Unmarshal(line, &je); err != nil {
		return event.Event{}, false
	}
	msg, _ := je.Message.(string)
	if msg == "" {
		return event.Event{}, false
	}
	ident := je.Ident
	if ident == "" {
		ident = je.Comm
	}
	ts := time.Now().UTC()
	if us, err := strconv.ParseInt(je.RealtimeUs, 10, 64); err == nil {
		ts = time.UnixMicro(us).UTC()
	}
	e, ok := ParseMessage(ident, msg, ts)
	if ok && je.PID != "" {
		if e.Extra == nil {
			e.Extra = map[string]string{}
		}
		e.Extra["pid"] = je.PID
	}
	return e, ok
}

// AuthLog tails journald (preferred) or an auth log file.
type AuthLog struct {
	// Files are tried in order when journalctl is unavailable.
	Files []string
	// JournalctlPath overrides the binary lookup (tests).
	JournalctlPath string
}

func (a *AuthLog) Name() string { return "authlog" }

func (a *AuthLog) Run(ctx context.Context, out chan<- event.Event) error {
	if p := a.journalctl(); p != "" {
		if err := a.runJournal(ctx, p, out); err == nil || ctx.Err() != nil {
			return ctx.Err()
		}
	}
	files := a.Files
	if len(files) == 0 {
		files = []string{"/var/log/auth.log", "/var/log/secure"}
	}
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			return TailFile(ctx, f, func(line string) {
				if e, ok := ParseSyslogLine(line, time.Now().Year(), time.Local); ok {
					emit(ctx, out, e)
				}
			})
		}
	}
	return errors.New("no journald and no auth log file found")
}

func (a *AuthLog) journalctl() string {
	if a.JournalctlPath != "" {
		return a.JournalctlPath
	}
	p, _ := exec.LookPath("journalctl")
	return p
}

func (a *AuthLog) runJournal(ctx context.Context, path string, out chan<- event.Event) error {
	cmd := exec.CommandContext(ctx, path, "-f", "-n", "0", "-o", "json", "--no-pager",
		"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sudo", "SYSLOG_IDENTIFIER=su",
		"SYSLOG_IDENTIFIER=useradd", "SYSLOG_IDENTIFIER=usermod", "SYSLOG_IDENTIFIER=groupadd",
		"SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=gpasswd")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if e, ok := ParseJournalJSON(sc.Bytes()); ok {
			if !emit(ctx, out, e) {
				break
			}
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("journalctl exited")
}

// TailFile follows path (like tail -F: handles truncation and rotation by
// inode change), calling fn for each new line, starting at end of file.
func TailFile(ctx context.Context, path string, fn func(line string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()
	st, _ := f.Stat()
	pos, _ := f.Seek(0, io.SeekEnd)
	rd := bufio.NewReader(f)
	var partial string
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				partial += line
				break
			}
			pos += int64(len(line))
			fn(strings.TrimRight(partial+line, "\r\n"))
			partial = ""
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		cur, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !os.SameFile(st, cur) || cur.Size() < pos {
			nf, err := os.Open(path)
			if err != nil {
				continue
			}
			f.Close()
			f, st, pos, rd, partial = nf, cur, 0, bufio.NewReader(nf), ""
		}
	}
}
