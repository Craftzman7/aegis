package collector

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// PasswdEntry is one /etc/passwd record.
type PasswdEntry struct {
	Name, Home, Shell string
	UID, GID          int
}

// ParsePasswd parses /etc/passwd content, skipping malformed lines.
func ParsePasswd(r io.Reader) []PasswdEntry {
	var out []PasswdEntry
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, e1 := strconv.Atoi(f[2])
		gid, e2 := strconv.Atoi(f[3])
		if e1 != nil || e2 != nil {
			continue
		}
		out = append(out, PasswdEntry{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out
}

// DiffUsers reports accounts added in cur relative to prev. Additional
// uid-0 accounts (name != root) yield KindUserNewUID0; an existing account
// whose UID changed to 0 also does.
func DiffUsers(prev, cur []PasswdEntry) []event.Event {
	old := map[string]PasswdEntry{}
	for _, p := range prev {
		old[p.Name] = p
	}
	var evs []event.Event
	mk := func(kind string, u PasswdEntry) event.Event {
		return event.Event{
			Source: "users", Kind: kind, TargetUser: u.Name, User: u.Name,
			Logsource: event.Logsource{Product: event.ProductLinux, Service: event.ServiceUsers},
			Message:   "account " + u.Name + " uid=" + strconv.Itoa(u.UID) + " shell=" + u.Shell,
			Extra:     map[string]string{"uid": strconv.Itoa(u.UID), "gid": strconv.Itoa(u.GID), "home": u.Home, "shell": u.Shell},
		}
	}
	for _, u := range cur {
		p, existed := old[u.Name]
		switch {
		case !existed && u.UID == 0 && u.Name != "root":
			evs = append(evs, mk(event.KindUserNewUID0, u))
		case !existed:
			evs = append(evs, mk(event.KindUserNew, u))
		case p.UID != 0 && u.UID == 0:
			evs = append(evs, mk(event.KindUserNewUID0, u))
		}
	}
	return evs
}

// Users watches a passwd file for new accounts.
type Users struct {
	Path     string
	Interval time.Duration
}

func (u *Users) Name() string { return "users" }

func (u *Users) Run(ctx context.Context, out chan<- event.Event) error {
	path := u.Path
	if path == "" {
		path = "/etc/passwd"
	}
	iv := u.Interval
	if iv == 0 {
		iv = 10 * time.Second
	}
	var prev []PasswdEntry
	have := false
	tick(ctx, iv, func() {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		cur := ParsePasswd(f)
		f.Close()
		if have {
			for _, e := range DiffUsers(prev, cur) {
				emit(ctx, out, e)
			}
		}
		prev, have = cur, true
	})
	return ctx.Err()
}
