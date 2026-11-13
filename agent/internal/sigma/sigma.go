// Package sigma loads Sigma rules (via sigma-go) and evaluates normalized
// events against them.
package sigma

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	sg "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

//go:embed rules/default/*.yml
var defaultPack embed.FS

// Rule status values from the policy.
const (
	StatusActive   = "active"
	StatusShadow   = "shadow"
	StatusDisabled = "disabled"
)

// Source is a rule as delivered in a policy.
type Source struct {
	ID     string
	Status string
	YAML   string
}

// LoadError reports a rule that failed to load.
type LoadError struct {
	RuleID string `json:"rule_id"`
	Error  string `json:"error"`
}

// Rule is a compiled Sigma rule.
type Rule struct {
	ID             string
	Title          string
	Level          string
	Severity       event.Severity
	Tags           []string
	AttackTags     []string
	Falsepositives []string
	Shadow         bool
	Logsource      sg.Logsource
	Raw            sg.Rule
	eval           *evaluator.RuleEvaluator
}

// Match is a successful rule evaluation.
type Match struct {
	Rule *Rule
}

// RuleSet is an immutable collection of compiled rules.
type RuleSet struct {
	rules      []*Rule
	byCategory map[string][]*Rule // "" key: rules without category
}

// Rules returns the compiled rules.
func (s *RuleSet) Rules() []*Rule { return s.rules }

// Len returns the number of loaded rules.
func (s *RuleSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// Compile parses and prepares a single Sigma YAML document.
func Compile(yamlText string, shadow bool) (*Rule, error) {
	r, err := sg.ParseRule([]byte(yamlText))
	if err != nil {
		return nil, err
	}
	if len(r.Detection.Conditions) == 0 {
		return nil, fmt.Errorf("rule has no detection condition")
	}
	rule := &Rule{
		ID:        r.ID,
		Title:     r.Title,
		Level:     r.Level,
		Severity:  LevelToSeverity(r.Level),
		Tags:      r.Tags,
		Logsource: r.Logsource,
		Shadow:    shadow,
		Raw:       r,
		eval:      evaluator.ForRule(r),
	}
	if rule.ID == "" {
		return nil, fmt.Errorf("rule %q has no id", r.Title)
	}
	for _, t := range r.Tags {
		if strings.HasPrefix(strings.ToLower(t), "attack.") {
			rule.AttackTags = append(rule.AttackTags, strings.ToLower(t))
		}
	}
	if fp, ok := r.AdditionalFields["falsepositives"]; ok {
		switch v := fp.(type) {
		case []any:
			for _, x := range v {
				rule.Falsepositives = append(rule.Falsepositives, fmt.Sprint(x))
			}
		case string:
			rule.Falsepositives = []string{v}
		}
	}
	// Probe evaluation so unsupported modifiers/aggregations surface at load.
	if _, err := rule.eval.Matches(context.Background(), map[string]any{}); err != nil {
		return nil, fmt.Errorf("rule not evaluable: %w", err)
	}
	return rule, nil
}

// LevelToSeverity maps a Sigma level to an Aegis severity.
func LevelToSeverity(level string) event.Severity {
	switch strings.ToLower(level) {
	case "critical":
		return event.SevCritical
	case "high":
		return event.SevHigh
	case "medium":
		return event.SevMedium
	case "low":
		return event.SevLow
	default:
		return event.SevInfo
	}
}

// DefaultSources returns the embedded default rule pack as Sources.
func DefaultSources() []Source {
	var out []Source
	_ = fs.WalkDir(defaultPack, "rules/default", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yml") {
			return nil
		}
		b, rerr := defaultPack.ReadFile(p)
		if rerr != nil {
			return nil
		}
		out = append(out, Source{ID: strings.TrimSuffix(d.Name(), ".yml"), Status: StatusActive, YAML: string(b)})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Load compiles sources. Sources whose Status is "disabled" are skipped.
// Rules sharing an ID: later sources override earlier ones, so callers pass
// defaults first and policy rules after. The returned errors are per-rule.
func Load(sources []Source) (*RuleSet, []LoadError) {
	var errs []LoadError
	byID := map[string]*Rule{}
	order := []string{}
	for _, src := range sources {
		label := src.ID
		r, err := Compile(src.YAML, src.Status == StatusShadow)
		if err != nil {
			errs = append(errs, LoadError{RuleID: label, Error: err.Error()})
			continue
		}
		// The policy rule id is authoritative when the YAML id differs.
		key := r.ID
		if src.Status == StatusDisabled {
			delete(byID, key)
			continue
		}
		if _, seen := byID[key]; !seen {
			order = append(order, key)
		}
		byID[key] = r
	}
	set := &RuleSet{byCategory: map[string][]*Rule{}}
	for _, id := range order {
		if r, ok := byID[id]; ok {
			set.rules = append(set.rules, r)
			set.byCategory[r.Logsource.Category] = append(set.byCategory[r.Logsource.Category], r)
		}
	}
	return set, errs
}

// logsourceMatches reports whether rule r applies to event e.
func logsourceMatches(r *Rule, e *event.Event) bool {
	ls := r.Logsource
	if ls.Product != "" && !strings.EqualFold(ls.Product, event.ProductLinux) {
		return false
	}
	// Events without a declared category/service (e.g. test-rule input)
	// are treated as wildcards for that dimension.
	if ls.Category != "" && e.Logsource.Category != "" && !strings.EqualFold(ls.Category, e.Logsource.Category) {
		return false
	}
	if ls.Service != "" && e.Logsource.Service != "" {
		want, got := strings.ToLower(ls.Service), strings.ToLower(e.Logsource.Service)
		if want != got && !(want == "auth" && got == "sshd") {
			return false
		}
	}
	// A rule with a category must not match events that only declare a service, and vice versa.
	if ls.Category != "" && e.Logsource.Category == "" && e.Logsource.Service != "" {
		return false
	}
	if ls.Service != "" && ls.Category == "" && e.Logsource.Service == "" && e.Logsource.Category != "" {
		return false
	}
	return true
}

// Evaluate returns every rule matching e.
func (s *RuleSet) Evaluate(ctx context.Context, e *event.Event) []Match {
	if s == nil || len(s.rules) == 0 {
		return nil
	}
	fields := ToSigmaEvent(e)
	var out []Match
	for _, r := range s.rules {
		if ctx.Err() != nil {
			return out
		}
		if !logsourceMatches(r, e) {
			continue
		}
		res, err := r.eval.Matches(ctx, fields)
		if err != nil || !res.Match {
			continue
		}
		out = append(out, Match{Rule: r})
	}
	return out
}

// Category derives the anomaly category for a Sigma rule.
func (r *Rule) Category() string {
	for _, t := range r.AttackTags {
		if t == "attack.persistence" {
			return "persistence"
		}
	}
	switch r.Logsource.Category {
	case event.CategoryProcessCreation:
		return "process"
	case event.CategoryNetworkConnection:
		return "network"
	case event.CategoryFileEvent:
		return "file"
	}
	switch r.Logsource.Service {
	case event.ServiceAuth, event.ServiceSSHD:
		return "auth"
	}
	return "other"
}
