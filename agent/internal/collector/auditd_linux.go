//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// Auditd receives execve and connect syscall audit events over netlink.
// It degrades gracefully: without root or with another auditd owning the
// socket it falls back to the multicast group, and if that fails Run returns
// an error (the agent keeps running on the /proc collectors).
type Auditd struct{}

func (a *Auditd) Name() string { return "auditd" }

type stream struct {
	ctx context.Context
	out chan<- event.Event
}

func (s *stream) EventsLost(int) {}
func (s *stream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	ae, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		return
	}
	if e, ok := FromAuditEvent(ae); ok {
		emit(s.ctx, s.out, e)
	}
}

func (a *Auditd) Run(ctx context.Context, out chan<- event.Event) error {
	if os.Geteuid() != 0 {
		return errors.New("auditd collector requires root")
	}
	client, err := libaudit.NewAuditClient(nil)
	if err != nil {
		return fmt.Errorf("netlink audit socket: %w", err)
	}
	owner := true
	if err := client.SetPID(libaudit.WaitForReply); err != nil {
		// Another daemon (auditd) owns the unicast socket; join multicast instead.
		client.Close()
		owner = false
		if client, err = libaudit.NewMulticastAuditClient(nil); err != nil {
			return fmt.Errorf("multicast audit socket: %w", err)
		}
	}
	defer client.Close()

	if owner {
		_ = client.SetEnabled(true, libaudit.NoWait)
		_ = client.SetBacklogLimit(8192, libaudit.NoWait)
		_ = client.SetRateLimit(2000, libaudit.NoWait)
	}
	// Install rules from a separate unicast client when we are multicast-only.
	if rc, err := libaudit.NewAuditClient(nil); err == nil {
		for _, sc := range []struct{ name, key string }{{"execve", "aegis_exec"}, {"connect", "aegis_connect"}} {
			wf, err := rule.Build(&rule.SyscallRule{
				Type: rule.AppendSyscallRuleType, List: "exit", Action: "always",
				Syscalls: []string{sc.name}, Keys: []string{sc.key},
			})
			if err == nil {
				_ = rc.AddRule(wf) // EEXIST when already installed is fine
			}
		}
		rc.Close()
	}

	re, err := libaudit.NewReassembler(512, 2*time.Second, &stream{ctx: ctx, out: out})
	if err != nil {
		return err
	}
	defer re.Close()

	go func() { <-ctx.Done(); client.Close() }() // unblocks Receive
	for {
		raw, err := client.Receive(false)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("audit receive: %w", err)
		}
		if raw.Type < auparse.AUDIT_USER_AUTH || raw.Type > auparse.AUDIT_LAST_USER_MSG2 {
			// Kernel records (syscall, execve, sockaddr, path, eoe) are 1300-1399.
			if raw.Type < 1300 || raw.Type >= 1400 {
				continue
			}
		}
		_ = re.Push(raw.Type, raw.Data)
	}
}
