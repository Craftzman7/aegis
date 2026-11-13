package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// DefaultFIMPaths are watched out of the box. Entries may be globs; a
// directory entry is walked one level deep recursively (files only).
var DefaultFIMPaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d",
	"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d",
	"/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys",
	"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
	"/var/spool/cron", "/var/spool/cron/crontabs",
	"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
	"/etc/ld.so.preload",
}

// FileState is the baseline record for a file.
type FileState struct {
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
}

// HashFile returns the hex sha256 of a regular file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ExpandPaths resolves globs and directories into a sorted file list.
func ExpandPaths(patterns []string) []string {
	set := map[string]struct{}{}
	var add func(p string, depth int)
	add = func(p string, depth int) {
		st, err := os.Lstat(p)
		if err != nil {
			return
		}
		if st.IsDir() {
			if depth > 3 {
				return
			}
			ents, _ := os.ReadDir(p)
			for _, e := range ents {
				add(filepath.Join(p, e.Name()), depth+1)
			}
			return
		}
		if st.Mode().IsRegular() {
			set[p] = struct{}{}
		}
	}
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			add(m, 0)
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Snapshot hashes every file matched by patterns.
func Snapshot(patterns []string) map[string]FileState {
	snap := map[string]FileState{}
	for _, p := range ExpandPaths(patterns) {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		sum, err := HashFile(p)
		if err != nil {
			continue
		}
		snap[p] = FileState{SHA256: sum, Mode: uint32(st.Mode().Perm()), Size: st.Size()}
	}
	return snap
}

// DiffSnapshots returns file_event events describing changes between two
// snapshots. Pure function for testing.
func DiffSnapshots(prev, cur map[string]FileState) []event.Event {
	var evs []event.Event
	mk := func(kind, path string, st FileState, old *FileState) event.Event {
		e := event.Event{
			Source: "fim", Kind: kind, TargetFilename: path, Sha256: st.SHA256,
			Logsource: event.Logsource{Product: event.ProductLinux, Category: event.CategoryFileEvent},
			Extra:     map[string]string{"mode": strconv.FormatUint(uint64(st.Mode), 8), "size": strconv.FormatInt(st.Size, 10)},
		}
		if old != nil {
			e.Extra["prev_sha256"] = old.SHA256
			e.Extra["prev_mode"] = strconv.FormatUint(uint64(old.Mode), 8)
		}
		return e
	}
	paths := make([]string, 0, len(cur))
	for p := range cur {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		c := cur[p]
		o, ok := prev[p]
		switch {
		case !ok:
			evs = append(evs, mk(event.KindFileCreated, p, c, nil))
		case o.SHA256 != c.SHA256 || o.Mode != c.Mode:
			evs = append(evs, mk(event.KindFileModified, p, c, &o))
		}
	}
	var gone []string
	for p := range prev {
		if _, ok := cur[p]; !ok {
			gone = append(gone, p)
		}
	}
	sort.Strings(gone)
	for _, p := range gone {
		evs = append(evs, mk(event.KindFileDeleted, p, prev[p], nil))
	}
	return evs
}

// FIM is a periodic hash-baseline file integrity monitor.
type FIM struct {
	Paths    []string
	Interval time.Duration
	// ExtraPaths returns policy watches (kind=path); may be nil.
	ExtraPaths func() []string
}

func (f *FIM) Name() string { return "fim" }

func (f *FIM) patterns() []string {
	p := f.Paths
	if p == nil {
		p = DefaultFIMPaths
	}
	if f.ExtraPaths != nil {
		p = append(append([]string{}, p...), f.ExtraPaths()...)
	}
	return p
}

func (f *FIM) Run(ctx context.Context, out chan<- event.Event) error {
	iv := f.Interval
	if iv == 0 {
		iv = 15 * time.Second
	}
	var base map[string]FileState
	tick(ctx, iv, func() {
		cur := Snapshot(f.patterns())
		if base != nil {
			for _, e := range DiffSnapshots(base, cur) {
				emit(ctx, out, e)
			}
		}
		base = cur
	})
	return ctx.Err()
}
