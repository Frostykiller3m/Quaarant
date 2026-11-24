package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// Build makes the report for one sandbox's events. With a nil analyzer (or when it fails) the
// report is rules-only, and Note says why.
func Build(ctx context.Context, sandbox string, evs []events.Event, an Analyzer) *Report {
	byID := make(map[string]events.Event, len(evs))
	for _, ev := range evs {
		byID[ev.ID] = ev
	}
	rules, _ := Validate(Rules(evs), byID) // rules cite real events; this also cleans their text
	r := &Report{Sandbox: sandbox, Events: len(evs), Engine: "rules", Findings: rules}
	floor := impliedVerdict(rules)
	r.Verdict = floor
	if an != nil {
		p, err := an.Analyze(ctx, sandbox, Compact(evs), rules)
		switch {
		case errors.Is(err, ErrRefused):
			r.Note = "Claude declined to analyse this log; rules only."
		case err != nil:
			r.Note = "Claude analysis failed (" + clean(err.Error(), 300) + "); rules only."
		default:
			r.Engine = an.Name() + " + rules"
			proposed := make([]Finding, 0, len(p.Findings))
			for _, f := range p.Findings {
				proposed = append(proposed, Finding{Title: f.Title, Severity: f.Severity, Category: f.Category, Evidence: f.Evidence, Explanation: f.Explanation, Source: "claude"})
			}
			kept, dropped := Validate(proposed, byID)
			r.Dropped = dropped
			r.Findings = mergeFindings(rules, kept)
			r.Summary = clean(p.Summary, maxSummary)
			// Claude's verdict counts only as far as its surviving evidence goes, and the
			// rules' verdict is a floor.
			v := p.Verdict
			if !slices.Contains(verdicts, v) {
				v = Clean
			}
			r.Verdict = maxVerdict(floor, minVerdict(v, impliedVerdict(kept)))
		}
	}
	sortFindings(r.Findings)
	if r.Summary == "" {
		r.Summary = rulesSummary(r)
	}
	return r
}

// mergeFindings adds Claude's findings to the rules', skipping ones that cite exactly the same
// evidence as a rule finding (a confirmation adds nothing).
func mergeFindings(rules, claude []Finding) []Finding {
	out := append([]Finding(nil), rules...)
	for _, c := range claude {
		dup := false
		for _, r := range rules {
			dup = dup || (r.Category == c.Category && sameIDs(r.Evidence, c.Evidence))
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}

func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func rulesSummary(r *Report) string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("Nothing suspicious in %d events.", r.Events)
	}
	titles := make([]string, 0, 3)
	for _, f := range r.Findings[:min(3, len(r.Findings))] {
		titles = append(titles, strings.ToLower(f.Title[:1])+f.Title[1:])
	}
	return fmt.Sprintf("%d finding(s) in %d events: %s.", len(r.Findings), r.Events, strings.Join(titles, "; "))
}

// WriteText renders the report for a terminal.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "Sandbox %s: %s\n", r.Sandbox, strings.ToUpper(r.Verdict))
	fmt.Fprintf(w, "Engine:  %s (%d events)\n", r.Engine, r.Events)
	if r.Note != "" {
		fmt.Fprintf(w, "Note:    %s\n", r.Note)
	}
	fmt.Fprintf(w, "\n%s\n", r.Summary)
	if len(r.Findings) > 0 {
		fmt.Fprintf(w, "\nFindings (%d):\n", len(r.Findings))
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n  [%s] %s  (%s, %s)\n", f.Severity, f.Title, f.Category, f.Source)
		fmt.Fprintf(w, "      %s\n", f.Explanation)
		fmt.Fprintf(w, "      evidence: %s\n", strings.Join(f.Evidence, ", "))
	}
	if len(r.Dropped) > 0 {
		fmt.Fprintf(w, "\nDropped %d proposed finding(s) without valid evidence:\n", len(r.Dropped))
		for _, d := range r.Dropped {
			fmt.Fprintf(w, "  - %s: %s\n", d.Title, d.Reason)
		}
	}
}
