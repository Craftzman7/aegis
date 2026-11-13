package collector

import (
	"strconv"

	"github.com/elastic/go-libaudit/v2/aucoalesce"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// FromAuditEvent converts a coalesced audit event into a normalized event.
// Only execve (process_creation) and connect (network_connection) syscalls are
// handled; ok is false otherwise. Pure function, unit-tested on all platforms.
func FromAuditEvent(ae *aucoalesce.Event) (event.Event, bool) {
	if ae == nil {
		return event.Event{}, false
	}
	sc := ae.Data["syscall"]
	user := ae.User.Names["uid"]
	if user == "" {
		user = ae.User.IDs["uid"]
	}
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	switch sc {
	case "execve":
		e := event.Event{
			Time: ae.Timestamp, Source: "auditd", Kind: event.KindExec,
			Logsource:        event.Logsource{Product: event.ProductLinux, Category: event.CategoryProcessCreation},
			Image:            ae.Process.Exe,
			User:             user,
			ProcessId:        atoi(ae.Process.PID),
			ParentProcessId:  atoi(ae.Process.PPID),
			CurrentDirectory: ae.Process.CWD,
		}
		for i, a := range ae.Process.Args {
			if i > 0 {
				e.CommandLine += " "
			}
			e.CommandLine += a
		}
		if e.Image == "" && len(ae.Process.Args) > 0 {
			e.Image = ae.Process.Args[0]
		}
		if e.Image == "" {
			return event.Event{}, false
		}
		return e, true
	case "connect":
		if ae.Dest == nil || ae.Dest.IP == "" {
			return event.Event{}, false
		}
		return event.Event{
			Time: ae.Timestamp, Source: "auditd", Kind: event.KindNetOutbound,
			Logsource:     event.Logsource{Product: event.ProductLinux, Category: event.CategoryNetworkConnection},
			Image:         ae.Process.Exe,
			User:          user,
			ProcessId:     atoi(ae.Process.PID),
			DestinationIp: ae.Dest.IP, DestinationPort: atoi(ae.Dest.Port), Initiated: true,
			Extra: map[string]string{"direction": "outbound", "via": "auditd"},
		}, true
	}
	return event.Event{}, false
}
