package sigma

import (
	"strconv"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// fieldTable maps Sigma-standard field names to accessors on the normalized
// event. Empty/zero values are omitted so that "field: null" selections work
// as Sigma authors expect.
var fieldTable = []struct {
	name string
	get  func(e *event.Event) any
}{
	{"Image", func(e *event.Event) any { return nz(e.Image) }},
	{"CommandLine", func(e *event.Event) any { return nz(e.CommandLine) }},
	{"ParentImage", func(e *event.Event) any { return nz(e.ParentImage) }},
	{"ParentCommandLine", func(e *event.Event) any { return nz(e.ParentCommandLine) }},
	{"User", func(e *event.Event) any { return nz(e.User) }},
	{"TargetUser", func(e *event.Event) any { return nz(e.TargetUser) }},
	{"ProcessId", func(e *event.Event) any { return ni(e.ProcessId) }},
	{"ParentProcessId", func(e *event.Event) any { return ni(e.ParentProcessId) }},
	{"CurrentDirectory", func(e *event.Event) any { return nz(e.CurrentDirectory) }},
	{"DestinationIp", func(e *event.Event) any { return nz(e.DestinationIp) }},
	{"DestinationPort", func(e *event.Event) any { return ni(e.DestinationPort) }},
	{"DestinationHostname", func(e *event.Event) any { return nz(e.DestinationHostname) }},
	{"SourceIp", func(e *event.Event) any { return nz(e.SourceIp) }},
	{"SourcePort", func(e *event.Event) any { return ni(e.SourcePort) }},
	{"Initiated", func(e *event.Event) any {
		if e.Logsource.Category == event.CategoryNetworkConnection {
			return strconv.FormatBool(e.Initiated)
		}
		return nil
	}},
	{"TargetFilename", func(e *event.Event) any { return nz(e.TargetFilename) }},
	{"Hashes", func(e *event.Event) any {
		if e.Sha256 == "" {
			return nil
		}
		return "SHA256=" + e.Sha256
	}},
	{"Message", func(e *event.Event) any { return nz(e.Message) }},
	{"EventType", func(e *event.Event) any { return nz(e.Kind) }},
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func ni(i int) any {
	if i == 0 {
		return nil
	}
	return i
}

// ToSigmaEvent converts a normalized event into the field map evaluated by
// sigma-go. Unknown keys from Event.Extra are passed through verbatim.
func ToSigmaEvent(e *event.Event) map[string]any {
	m := make(map[string]any, len(fieldTable)+len(e.Extra))
	for k, v := range e.Extra {
		m[k] = v
	}
	for _, f := range fieldTable {
		if v := f.get(e); v != nil {
			m[f.name] = v
		}
	}
	return m
}
