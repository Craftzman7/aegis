package collector

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/aucoalesce"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

func TestParseSyslogLines(t *testing.T) {
	cases := []struct {
		line       string
		kind, user string
		ip         string
		port       int
		target     string
	}{
		{"Nov 12 10:00:01 web1 sshd[812]: Failed password for root from 203.0.113.7 port 52211 ssh2", event.KindSSHFailed, "root", "203.0.113.7", 52211, ""},
		{"Nov 12 10:00:02 web1 sshd[812]: Failed password for invalid user admin from 198.51.100.4 port 40022 ssh2", event.KindSSHFailed, "admin", "198.51.100.4", 40022, ""},
		{"Nov 12 10:00:03 web1 sshd[812]: Accepted publickey for alice from 192.0.2.10 port 5000 ssh2: RSA SHA256:abc", event.KindSSHAccepted, "alice", "192.0.2.10", 5000, ""},
		{"Nov 12 10:00:04 web1 sshd[812]: Invalid user oracle from 203.0.113.7 port 6000", event.KindSSHInvalidUser, "oracle", "203.0.113.7", 6000, ""},
		{"Nov 12 10:00:05 web1 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", event.KindSudo, "alice", "", 0, "root"},
		{"Nov 12 10:00:06 web1 sudo:    bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash", event.KindSudoFailed, "bob", "", 0, "root"},
		{"Nov 12 10:00:07 web1 su[900]: (to root) alice on pts/0", event.KindSu, "alice", "", 0, "root"},
		{"Nov 12 10:00:08 web1 su[901]: FAILED SU (to root) mallory on pts/2", event.KindSuFailed, "mallory", "", 0, "root"},
		{"Nov 12 10:00:09 web1 useradd[950]: new user: name=toor, UID=0, GID=0, home=/home/toor, shell=/bin/bash, from=/dev/pts/0", event.KindUserAdd, "", "", 0, "toor"},
		{"Nov 12 10:00:10 web1 usermod[960]: add 'toor' to group 'sudo'", event.KindUserMod, "", "", 0, "toor"},
		{"2026-11-12T10:00:11.123456+00:00 web1 sshd[5]: Failed password for bob from 1.2.3.4 port 22 ssh2", event.KindSSHFailed, "bob", "1.2.3.4", 22, ""},
	}
	for _, c := range cases {
		e, ok := ParseSyslogLine(c.line, 2026, time.UTC)
		if !ok {
			t.Errorf("not parsed: %s", c.line)
			continue
		}
		if e.Kind != c.kind || e.User != c.user || e.SourceIp != c.ip || e.SourcePort != c.port || e.TargetUser != c.target {
			t.Errorf("%s\n got %+v", c.line, e)
		}
		if e.Time.IsZero() {
			t.Errorf("zero time for %s", c.line)
		}
	}
	for _, l := range []string{
		"Nov 12 10:00:00 web1 sshd[1]: Server listening on 0.0.0.0 port 22.",
		"Nov 12 10:00:00 web1 CRON[2]: pam_unix(cron:session): session opened",
		"garbage",
	} {
		if _, ok := ParseSyslogLine(l, 2026, time.UTC); ok {
			t.Errorf("should ignore %q", l)
		}
	}
	e, _ := ParseSyslogLine(cases[4].line, 2026, time.UTC)
	if e.CommandLine != "/usr/bin/cat /etc/shadow" || e.CurrentDirectory != "/home/alice" {
		t.Errorf("sudo fields: %+v", e)
	}
	e, _ = ParseSyslogLine(cases[8].line, 2026, time.UTC)
	if e.Extra["uid"] != "0" {
		t.Errorf("useradd uid: %+v", e)
	}
}

func TestParseJournalJSON(t *testing.T) {
	line := `{"MESSAGE":"Failed password for root from 203.0.113.7 port 52211 ssh2","SYSLOG_IDENTIFIER":"sshd","_PID":"812","__REALTIME_TIMESTAMP":"1762941601000000"}`
	e, ok := ParseJournalJSON([]byte(line))
	if !ok || e.Kind != event.KindSSHFailed || e.Extra["pid"] != "812" || e.Time.Year() != 2025 {
		t.Fatalf("%+v ok=%v", e, ok)
	}
	if e.Logsource.Service != event.ServiceSSHD {
		t.Fatalf("service %s", e.Logsource.Service)
	}
	// journald encodes non-UTF8 messages as byte arrays; must not panic.
	if _, ok := ParseJournalJSON([]byte(`{"MESSAGE":[104,105],"SYSLOG_IDENTIFIER":"sshd"}`)); ok {
		t.Fatal("byte-array message should be ignored")
	}
	if _, ok := ParseJournalJSON([]byte(`not json`)); ok {
		t.Fatal("bad json parsed")
	}
}

const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0F00000A:A5E4 0100A8C0:0050 01 00000000:00000000 02:000A7CDB 00000000  1000        0 33333 2 0000000000000000 20 4 30 10 -1
   3: 0F00000A:0016 0A000001:D2F0 01 00000000:00000000 02:000A7CDB 00000000     0        0 44444 2 0000000000000000 20 4 30 10 -1
`

const procNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCP(t *testing.T) {
	cs, err := ParseProcNetTCP(strings.NewReader(procNetTCP), false)
	if err != nil || len(cs) != 4 {
		t.Fatalf("%v %d", err, len(cs))
	}
	if cs[0].LocalPort != 22 || cs[0].State != TCPListen || cs[0].LocalIP.String() != "0.0.0.0" {
		t.Errorf("row0 %+v", cs[0])
	}
	if cs[1].LocalIP.String() != "127.0.0.1" || cs[1].LocalPort != 8080 || cs[1].UID != 1000 {
		t.Errorf("row1 %+v", cs[1])
	}
	if cs[2].RemoteIP.String() != "192.168.0.1" || cs[2].RemotePort != 80 || cs[2].LocalIP.String() != "10.0.0.15" {
		t.Errorf("row2 %+v", cs[2])
	}
	c6, _ := ParseProcNetTCP(strings.NewReader(procNetTCP6), true)
	if len(c6) != 1 || c6[0].LocalIP.String() != "::1" || c6[0].LocalPort != 80 {
		t.Errorf("v6 %+v", c6)
	}
}

func TestNetStateDiff(t *testing.T) {
	cs, _ := ParseProcNetTCP(strings.NewReader(procNetTCP), false)
	st := NewNetState()
	if evs := st.Diff(cs[:1]); len(evs) != 0 {
		t.Fatalf("first scan must only prime: %v", evs)
	}
	evs := st.Diff(cs)
	var listen, out int
	for _, e := range evs {
		switch e.Kind {
		case event.KindNetListen:
			listen++
			if e.SourcePort != 8080 {
				t.Errorf("listener %+v", e)
			}
		case event.KindNetOutbound:
			out++
			if e.DestinationIp != "192.168.0.1" || e.DestinationPort != 80 {
				t.Errorf("outbound %+v", e)
			}
		}
	}
	// row 3 is an inbound ssh session (local port 22 is listening) and must not count as outbound.
	if listen != 1 || out != 1 {
		t.Fatalf("listen=%d out=%d", listen, out)
	}
	if len(st.Diff(cs)) != 0 {
		t.Fatal("repeat scan must be quiet")
	}
}

func writeProc(t *testing.T, root string, pid int, ppid int, comm, exe, cmdline string, sockets bool) {
	t.Helper()
	d := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(filepath.Join(d, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	stat := itoa(pid) + " (" + comm + ") S " + itoa(ppid) + " 1 1 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 4242 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
	os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
	os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.ReplaceAll(cmdline, " ", "\x00")+"\x00"), 0o644)
	os.Symlink(exe, filepath.Join(d, "exe"))
	os.Symlink("/", filepath.Join(d, "cwd"))
	if sockets {
		os.Symlink("socket:[999]", filepath.Join(d, "fd", "0"))
		os.Symlink("socket:[999]", filepath.Join(d, "fd", "1"))
	} else {
		os.Symlink("/dev/null", filepath.Join(d, "fd", "0"))
		os.Symlink("/dev/null", filepath.Join(d, "fd", "1"))
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestReadProcAndClassify(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 100, 1, "bash", "/usr/bin/bash", "bash -i", true)
	writeProc(t, root, 101, 100, "evil", "/tmp/.x/evil", "/tmp/.x/evil --run", false)
	writeProc(t, root, 102, 1, "ghost", "/usr/bin/ghost (deleted)", "ghost", false)
	writeProc(t, root, 103, 1, "sshd: me (x)", "/usr/sbin/sshd", "sshd: me", false)

	p, ok := ReadProc(root, 100)
	if !ok || p.PPID != 1 || p.StartTime != 4242 || !p.StdinSocket || !p.IsShell() {
		t.Fatalf("%+v", p)
	}
	if k := Classify(p); len(k) != 1 || k[0] != event.KindProcReverseShell {
		t.Errorf("revshell: %v", k)
	}
	p, _ = ReadProc(root, 101)
	if k := Classify(p); len(k) != 1 || k[0] != event.KindProcSuspiciousExe {
		t.Errorf("tmp exe: %v", k)
	}
	if p.Cmdline != "/tmp/.x/evil --run" {
		t.Errorf("cmdline %q", p.Cmdline)
	}
	p, _ = ReadProc(root, 102)
	if k := Classify(p); len(k) != 1 || k[0] != event.KindProcDeletedExe {
		t.Errorf("deleted: %v", k)
	}
	p, _ = ReadProc(root, 103)
	if p.Comm != "sshd: me (x)" || len(Classify(p)) != 0 {
		t.Errorf("comm parse: %+v", p)
	}
	if len(ListPIDs(root)) != 4 {
		t.Error("ListPIDs")
	}
	parent, _ := ReadProc(root, 100)
	child, _ := ReadProc(root, 101)
	e := ToEvent(child, parent, event.KindExec, "root")
	if e.Image != "/tmp/.x/evil" || e.ParentImage != "/usr/bin/bash" || e.ParentProcessId != 100 || e.Logsource.Category != event.CategoryProcessCreation {
		t.Errorf("%+v", e)
	}
}

func TestDiffSnapshots(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "etc", "passwd")
	os.MkdirAll(filepath.Dir(a), 0o755)
	os.WriteFile(a, []byte("root:x:0:0\n"), 0o644)
	pats := []string{filepath.Join(dir, "etc")}
	s1 := Snapshot(pats)
	if len(s1) != 1 {
		t.Fatalf("snapshot %v", s1)
	}
	os.WriteFile(a, []byte("root:x:0:0\nevil:x:0:0\n"), 0o644)
	b := filepath.Join(dir, "etc", "new")
	os.WriteFile(b, []byte("x"), 0o600)
	s2 := Snapshot(pats)
	evs := DiffSnapshots(s1, s2)
	if len(evs) != 2 {
		t.Fatalf("%+v", evs)
	}
	kinds := map[string]string{}
	for _, e := range evs {
		kinds[e.TargetFilename] = e.Kind
		if e.Logsource.Category != event.CategoryFileEvent || e.Sha256 == "" {
			t.Errorf("%+v", e)
		}
	}
	if kinds[a] != event.KindFileModified || kinds[b] != event.KindFileCreated {
		t.Errorf("%v", kinds)
	}
	os.Remove(b)
	evs = DiffSnapshots(s2, Snapshot(pats))
	if len(evs) != 1 || evs[0].Kind != event.KindFileDeleted {
		t.Errorf("%+v", evs)
	}
	if len(DiffSnapshots(s2, s2)) != 0 {
		t.Error("no-op diff produced events")
	}
}

func TestExpandPathsGlob(t *testing.T) {
	dir := t.TempDir()
	for _, u := range []string{"alice", "bob"} {
		os.MkdirAll(filepath.Join(dir, "home", u, ".ssh"), 0o700)
		os.WriteFile(filepath.Join(dir, "home", u, ".ssh", "authorized_keys"), []byte("k"), 0o600)
	}
	got := ExpandPaths([]string{filepath.Join(dir, "home/*/.ssh/authorized_keys"), filepath.Join(dir, "missing")})
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func TestDiffUsers(t *testing.T) {
	old := ParsePasswd(strings.NewReader("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n# c\nbad line\n"))
	if len(old) != 2 {
		t.Fatalf("%+v", old)
	}
	cur := ParsePasswd(strings.NewReader("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\ntoor:x:0:0::/root:/bin/bash\n"))
	evs := DiffUsers(old, cur)
	if len(evs) != 2 || evs[0].Kind != event.KindUserNew || evs[1].Kind != event.KindUserNewUID0 || evs[1].TargetUser != "toor" {
		t.Fatalf("%+v", evs)
	}
	// existing user promoted to uid 0
	promoted := ParsePasswd(strings.NewReader("root:x:0:0:r:/root:/bin/bash\nalice:x:0:0::/home/alice:/bin/bash\n"))
	evs = DiffUsers(old, promoted)
	if len(evs) != 1 || evs[0].Kind != event.KindUserNewUID0 {
		t.Fatalf("%+v", evs)
	}
}

func TestFromAuditEvent(t *testing.T) {
	ae := &aucoalesce.Event{
		Timestamp: time.Unix(1762941601, 0),
		Data:      map[string]string{"syscall": "execve"},
		User:      aucoalesce.User{Names: map[string]string{"uid": "www-data"}},
		Process:   aucoalesce.Process{PID: "77", PPID: "70", Exe: "/usr/bin/curl", CWD: "/var/www", Args: []string{"curl", "-s", "http://x"}},
	}
	e, ok := FromAuditEvent(ae)
	if !ok || e.Image != "/usr/bin/curl" || e.CommandLine != "curl -s http://x" || e.ProcessId != 77 || e.ParentProcessId != 70 || e.User != "www-data" {
		t.Fatalf("%+v", e)
	}
	ce := &aucoalesce.Event{Data: map[string]string{"syscall": "connect"}, Process: aucoalesce.Process{PID: "5", Exe: "/bin/bash"},
		Dest: &aucoalesce.Address{IP: "203.0.113.9", Port: "4444"}}
	e, ok = FromAuditEvent(ce)
	if !ok || e.DestinationIp != "203.0.113.9" || e.DestinationPort != 4444 || e.Logsource.Category != event.CategoryNetworkConnection {
		t.Fatalf("%+v", e)
	}
	if _, ok := FromAuditEvent(&aucoalesce.Event{Data: map[string]string{"syscall": "open"}}); ok {
		t.Fatal("open must be ignored")
	}
}

func TestProcNeverFlagsItself(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 6, 1, "aegis-agent", "/usr/local/bin/aegis-agent (deleted)", "aegis-agent run", false)
	writeProc(t, root, 7, 1, "ghost", "/usr/bin/ghost (deleted)", "ghost", false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	out := make(chan event.Event, 16)
	(&Proc{ProcRoot: root, Interval: 10 * time.Millisecond, SelfPID: 6}).Run(ctx, out)
	close(out)
	var flagged []int
	for ev := range out {
		if ev.Kind == event.KindProcDeletedExe {
			flagged = append(flagged, ev.ProcessId)
		}
	}
	if len(flagged) != 1 || flagged[0] != 7 {
		t.Fatalf("want only pid 7 flagged, got %v", flagged)
	}
}
