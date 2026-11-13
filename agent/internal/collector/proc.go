package collector

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// ProcInfo is a snapshot of one process read from /proc.
type ProcInfo struct {
	PID, PPID    int
	StartTime    uint64
	Exe          string // readlink /proc/pid/exe (may end in " (deleted)")
	Cmdline      string
	Cwd          string
	UID          int
	Comm         string
	StdinSocket  bool
	StdoutSocket bool
}

var shellNames = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true, "csh": true, "tcsh": true, "fish": true}

var suspiciousDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/"}

// Deleted reports whether the exe link points to a deleted file.
func (p ProcInfo) Deleted() bool { return strings.HasSuffix(p.Exe, " (deleted)") }

// ImagePath returns Exe without the " (deleted)" suffix.
func (p ProcInfo) ImagePath() string { return strings.TrimSuffix(p.Exe, " (deleted)") }

// IsShell reports whether the process is a known shell.
func (p ProcInfo) IsShell() bool { return shellNames[filepath.Base(p.ImagePath())] }

// Classify returns the suspicious-process kinds that apply to p.
func Classify(p ProcInfo) []string {
	var kinds []string
	img := p.ImagePath()
	for _, d := range suspiciousDirs {
		if strings.HasPrefix(img, d) {
			kinds = append(kinds, event.KindProcSuspiciousExe)
			break
		}
	}
	if p.Deleted() && img != "" {
		kinds = append(kinds, event.KindProcDeletedExe)
	}
	if p.IsShell() && p.StdinSocket && p.StdoutSocket {
		kinds = append(kinds, event.KindProcReverseShell)
	}
	return kinds
}

// parseStat extracts ppid and starttime from /proc/pid/stat content. The comm
// field may contain spaces and parentheses, so split after the last ')'.
func parseStat(s string) (comm string, ppid int, start uint64, ok bool) {
	l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		return
	}
	comm = s[l+1 : r]
	f := strings.Fields(s[r+1:])
	// After ')': state(0) ppid(1) ... starttime is field 22 overall => index 19 here.
	if len(f) < 20 {
		return
	}
	pp, err1 := strconv.Atoi(f[1])
	st, err2 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil {
		return
	}
	return comm, pp, st, true
}

func isSocketLink(path string) bool {
	l, err := os.Readlink(path)
	return err == nil && strings.HasPrefix(l, "socket:[")
}

// ReadProc reads one process from procRoot; ok=false if it vanished.
func ReadProc(procRoot string, pid int) (ProcInfo, bool) {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ProcInfo{}, false
	}
	comm, ppid, start, ok := parseStat(string(stat))
	if !ok {
		return ProcInfo{}, false
	}
	p := ProcInfo{PID: pid, PPID: ppid, StartTime: start, Comm: comm}
	p.Exe, _ = os.Readlink(filepath.Join(dir, "exe"))
	p.Cwd, _ = os.Readlink(filepath.Join(dir, "cwd"))
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " "))
	}
	if st, err := os.Stat(dir); err == nil {
		p.UID = fileUID(st)
	}
	p.StdinSocket = isSocketLink(filepath.Join(dir, "fd", "0"))
	p.StdoutSocket = isSocketLink(filepath.Join(dir, "fd", "1"))
	return p, true
}

// ListPIDs returns numeric directory names under procRoot.
func ListPIDs(procRoot string) []int {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, n)
		}
	}
	return pids
}

// Proc scans /proc and reports new processes (process_creation) and
// suspicious ones (once per pid+start).
type Proc struct {
	ProcRoot string
	Interval time.Duration
	// UserName resolves a uid to a name; optional.
	UserName func(uid int) string
}

func (p *Proc) Name() string { return "proc" }

type procKey struct {
	pid   int
	start uint64
}

// ToEvent converts a ProcInfo plus its parent into a process_creation event.
func ToEvent(p, parent ProcInfo, kind string, user string) event.Event {
	return event.Event{
		Source: "proc", Kind: kind,
		Logsource:         event.Logsource{Product: event.ProductLinux, Category: event.CategoryProcessCreation},
		Image:             p.ImagePath(),
		CommandLine:       p.Cmdline,
		ParentImage:       parent.ImagePath(),
		ParentCommandLine: parent.Cmdline,
		User:              user,
		ProcessId:         p.PID,
		ParentProcessId:   p.PPID,
		CurrentDirectory:  p.Cwd,
		ProcessStartTime:  p.StartTime,
	}
}

func (p *Proc) Run(ctx context.Context, out chan<- event.Event) error {
	root := p.ProcRoot
	if root == "" {
		root = "/proc"
	}
	iv := p.Interval
	if iv == 0 {
		iv = 5 * time.Second
	}
	seen := map[procKey]bool{}
	flagged := map[procKey]bool{}
	first := true
	tick(ctx, iv, func() {
		cur := map[int]ProcInfo{}
		for _, pid := range ListPIDs(root) {
			if pi, ok := ReadProc(root, pid); ok {
				cur[pid] = pi
			}
		}
		live := map[procKey]bool{}
		for pid, pi := range cur {
			k := procKey{pid, pi.StartTime}
			live[k] = true
			user := strconv.Itoa(pi.UID)
			if p.UserName != nil {
				user = p.UserName(pi.UID)
			}
			parent := cur[pi.PPID]
			if pi.Exe == "" && pi.Cmdline == "" {
				continue // kernel thread
			}
			if !seen[k] {
				seen[k] = true
				if !first {
					if !emit(ctx, out, ToEvent(pi, parent, event.KindExec, user)) {
						return
					}
				}
			}
			if !flagged[k] {
				for _, kind := range Classify(pi) {
					flagged[k] = true
					if !emit(ctx, out, ToEvent(pi, parent, kind, user)) {
						return
					}
				}
			}
		}
		for k := range seen {
			if !live[k] {
				delete(seen, k)
				delete(flagged, k)
			}
		}
		first = false
	})
	return ctx.Err()
}
