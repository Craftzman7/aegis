package sigma

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

type fixtureCase struct {
	Rule   string      `json:"rule"`
	Expect bool        `json:"expect"`
	Event  event.Event `json:"event"`
}

func TestDefaultPackLoads(t *testing.T) {
	srcs := DefaultSources()
	if len(srcs) < 10 {
		t.Fatalf("want >=10 default rules, got %d", len(srcs))
	}
	set, errs := Load(srcs)
	if len(errs) > 0 {
		t.Fatalf("load errors: %+v", errs)
	}
	if set.Len() != len(srcs) {
		t.Fatalf("loaded %d of %d", set.Len(), len(srcs))
	}
	for _, r := range set.Rules() {
		if len(r.AttackTags) == 0 || r.Severity == event.SevInfo || len(r.Falsepositives) == 0 {
			t.Errorf("rule %s missing metadata: %+v", r.Title, r)
		}
	}
}

func TestDefaultRulesPositiveAndBenign(t *testing.T) {
	f, err := os.Open("../../testdata/sigma/cases.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	byStem := map[string]*Rule{}
	for _, s := range DefaultSources() {
		r, err := Compile(s.YAML, false)
		if err != nil {
			t.Fatal(err)
		}
		byStem[s.ID] = r
	}
	set, _ := Load(DefaultSources())
	covered := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c fixtureCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		want := byStem[c.Rule]
		if want == nil {
			t.Fatalf("unknown rule %s", c.Rule)
		}
		fired := false
		for _, m := range set.Evaluate(context.Background(), &c.Event) {
			if m.Rule.ID == want.ID {
				fired = true
			}
		}
		if fired != c.Expect {
			t.Errorf("rule %s event %+v: fired=%v want %v", c.Rule, c.Event.CommandLine+c.Event.TargetFilename, fired, c.Expect)
		}
		if c.Expect {
			covered[c.Rule] = true
		}
	}
	for stem := range byStem {
		if !covered[stem] {
			t.Errorf("rule %s has no positive fixture", stem)
		}
	}
}

func TestLoadErrorsPerRule(t *testing.T) {
	good := DefaultSources()[0]
	set, errs := Load([]Source{
		good,
		{ID: "broken", Status: StatusActive, YAML: "title: x\ndetection: [unclosed"},
		{ID: "noid", Status: StatusActive, YAML: "title: x\nlogsource: {product: linux}\ndetection:\n  s: {a: b}\n  condition: s\n"},
	})
	if set.Len() != 1 || len(errs) != 2 {
		t.Fatalf("len=%d errs=%+v", set.Len(), errs)
	}
}

func TestShadowAndDisabled(t *testing.T) {
	y := strings.Replace(string(mustSrc(t, "lnx_ld_so_preload")), "level: high", "level: critical", 1)
	set, errs := Load(append(DefaultSources(), Source{ID: "x", Status: StatusShadow, YAML: y}))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var shadow *Rule
	for _, r := range set.Rules() {
		if r.Title == "Dynamic Linker Preload File Modified" {
			shadow = r
		}
	}
	if shadow == nil || !shadow.Shadow || shadow.Severity != event.SevCritical {
		t.Fatalf("override failed: %+v", shadow)
	}
	set2, _ := Load(append(DefaultSources(), Source{ID: "x", Status: StatusDisabled, YAML: y}))
	if set2.Len() != set.Len()-1 {
		t.Fatalf("disable should remove rule: %d vs %d", set2.Len(), set.Len())
	}
}

func mustSrc(t *testing.T, id string) string {
	for _, s := range DefaultSources() {
		if s.ID == id {
			return s.YAML
		}
	}
	t.Fatal("no src " + id)
	return ""
}

func TestServiceLogsource(t *testing.T) {
	y := `title: Root SSH login
id: 5b0c6f0e-6b57-4a0e-9d0b-2f4a8f9a1c11
logsource: {product: linux, service: sshd}
detection:
  sel:
    EventType: ssh_accepted
    User: root
  condition: sel
level: medium
`
	set, errs := Load([]Source{{ID: "r", Status: StatusActive, YAML: y}})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	e := &event.Event{Kind: event.KindSSHAccepted, User: "root", Logsource: event.Logsource{Product: "linux", Service: "sshd"}}
	if len(set.Evaluate(context.Background(), e)) != 1 {
		t.Fatal("expected match")
	}
	e.Logsource = event.Logsource{Product: "linux", Category: "process_creation"}
	if len(set.Evaluate(context.Background(), e)) != 0 {
		t.Fatal("wrong logsource matched")
	}
}
