// Package report turns a sandbox's event log into a verdict with evidence.
//
// Rules always run: they flag the things that need no judgment (a honeytoken read or sent out,
// writes to persistence paths, miners, exfiltration and policy-bypass attempts). With an API
// key, Claude also reads a compacted log and proposes findings. Every finding must cite event
// ids that exist in the log and fit its category; the validator drops any that do not. The
// verdict can't be lower than what the rules prove, nor higher than the evidence that survives.
package report

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// Verdicts, from least to most severe.
const (
	Clean      = "clean"
	Suspicious = "suspicious"
	Malicious  = "malicious"
)

// Severities.
const (
	Low      = "low"
	Medium   = "medium"
	High     = "high"
	Critical = "critical"
)

var (
	verdicts   = []string{Clean, Suspicious, Malicious}
	severities = []string{Low, Medium, High, Critical}
)

// Categories and the event kinds that can be evidence for each.
var categoryKinds = map[string][]events.Kind{
	"honeytoken":   {events.KindHoneytoken, events.KindFile},
	"exfiltration": {events.KindNet, events.KindDNS, events.KindHoneytoken, events.KindPolicyDenied},
	"persistence":  {events.KindFile, events.KindExec},
	"miner":        {events.KindExec, events.KindNet, events.KindDNS},
	"network":      {events.KindNet, events.KindDNS, events.KindPolicyDenied},
	"execution":    {events.KindExec},
	"file":         {events.KindFile},
	"evasion":      {events.KindFile, events.KindExec},
}

// Categories lists the finding categories (sorted).
func Categories() []string {
	out := make([]string, 0, len(categoryKinds))
	for c := range categoryKinds {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// Finding is one claim about the sandbox, with the events that show it.
type Finding struct {
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Evidence    []string `json:"evidence"`
	Explanation string   `json:"explanation"`
	Source      string   `json:"source"` // "rules" or "claude"
}

// Dropped is a proposed finding the validator rejected.
type Dropped struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// Report is the result for one sandbox.
type Report struct {
	Sandbox  string    `json:"sandbox"`
	Verdict  string    `json:"verdict"`
	Summary  string    `json:"summary"`
	Engine   string    `json:"engine"` // "rules", or the Claude model plus rules
	Note     string    `json:"note,omitempty"`
	Events   int       `json:"events"`
	Findings []Finding `json:"findings"`
	Dropped  []Dropped `json:"dropped,omitempty"`
}

const (
	maxTitle       = 200
	maxExplanation = 2000
	maxSummary     = 4000
	maxEvidence    = 64
)

// Validate keeps the findings whose evidence is real: every id exists in the log, and its kind
// fits the finding's category. Text fields are cleaned (control characters removed) and bounded.
func Validate(fs []Finding, byID map[string]events.Event) (kept []Finding, dropped []Dropped) {
	for _, f := range fs {
		f.Title, f.Explanation = clean(f.Title, maxTitle), clean(f.Explanation, maxExplanation)
		reason := ""
		kinds, okCat := categoryKinds[f.Category]
		switch {
		case f.Title == "":
			reason = "no title"
		case !slices.Contains(severities, f.Severity):
			reason = fmt.Sprintf("unknown severity %.20q", f.Severity)
		case !okCat:
			reason = fmt.Sprintf("unknown category %.20q", f.Category)
		case len(f.Evidence) == 0:
			reason = "no evidence"
		case len(f.Evidence) > maxEvidence:
			reason = "too much evidence to check"
		}
		if reason == "" {
			for _, id := range f.Evidence {
				ev, ok := byID[id]
				if !ok {
					reason = fmt.Sprintf("cites %.48q, which is not in the event log", id)
					break
				}
				if !slices.Contains(kinds, ev.Kind) {
					reason = fmt.Sprintf("cites %s, a %s event, as %s evidence", id, ev.Kind, f.Category)
					break
				}
			}
		}
		if reason != "" {
			dropped = append(dropped, Dropped{Title: orDefault(f.Title, "(untitled)"), Reason: reason})
			continue
		}
		f.Evidence = dedupe(f.Evidence)
		kept = append(kept, f)
	}
	return kept, dropped
}

// impliedVerdict is the strongest verdict a set of findings supports.
func impliedVerdict(fs []Finding) string {
	v := Clean
	for _, f := range fs {
		switch f.Severity {
		case Critical:
			return Malicious
		case High, Medium:
			v = Suspicious
		}
	}
	return v
}

func rank(v string) int { return slices.Index(verdicts, v) }

func maxVerdict(a, b string) string {
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func minVerdict(a, b string) string {
	if rank(a) <= rank(b) {
		return a
	}
	return b
}

// clean removes control and formatting characters (terminal escapes from text derived from
// sandbox data) and bounds the length.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > n {
		for n > 0 && s[n]&0xc0 == 0x80 {
			n--
		}
		s = s[:n] + "…"
	}
	return s
}

func dedupe(ids []string) []string {
	seen := map[string]bool{}
	out := ids[:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func severityRank(s string) int { return slices.Index(severities, s) }

// sortFindings orders by severity (worst first), then title.
func sortFindings(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if d := severityRank(b.Severity) - severityRank(a.Severity); d != 0 {
			return d
		}
		return strings.Compare(a.Title, b.Title)
	})
}
