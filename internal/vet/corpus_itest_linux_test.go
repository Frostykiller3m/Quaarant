//go:build linux

package vet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/report"
)

// corpusExpect is testdata/corpus.json.
type corpusExpect struct {
	Evil map[string]struct {
		Verdicts   []string `json:"verdicts"`
		Categories []string `json:"categories"`
	} `json:"evil"`
	Normal []string `json:"normal"`
}

// TestITestCorpus vets every repository in testdata/evil (harmless stand-ins for malicious
// packages) and testdata/normal through the real flow: offline plan, a gvisor sandbox with
// honeytokens and --net=log (so attempts reach the host proxy and are recorded), the rules-only
// report. Each evil repo must come out suspicious or malicious with a finding of the expected
// category; each normal repo must come out clean.
func TestITestCorpus(t *testing.T) {
	c := qtd(t)
	root := filepath.Join("..", "..", "testdata")
	raw, err := os.ReadFile(filepath.Join(root, "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want corpusExpect
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want.Evil) < 15 || len(want.Normal) < 10 {
		t.Fatalf("corpus too small: %d evil, %d normal", len(want.Evil), len(want.Normal))
	}
	sem := make(chan struct{}, 4)
	vetOne := func(t *testing.T, kind, name string) *Result {
		t.Helper()
		sem <- struct{}{}
		defer func() { <-sem }()
		var out, errb bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		res, err := Run(ctx, Options{
			Client: c, Repo: Repo{URL: "testdata/" + kind + "/" + name, Host: "local", Name: name},
			LocalDir: filepath.Join(root, kind, name), Net: &Net{Mode: "log"},
			Approve: func(*Plan) bool { return true }, Timeout: 3 * time.Minute, Out: &out, Err: &errb,
		})
		if res != nil && res.Sandbox != "" {
			t.Cleanup(func() { _, _ = c.Destroy(context.Background(), &qtdv1.DestroyRequest{SandboxId: res.Sandbox}) })
		}
		if err != nil {
			t.Fatalf("vet %s: %v\n%s", name, err, tail(errb.String(), 3000))
		}
		if t.Failed() || testing.Verbose() {
			t.Logf("plan: %s %v %v", res.Plan.Image, res.Plan.Setup, res.Plan.Run)
		}
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("stderr:\n%s\nreport:\n%s", tail(errb.String(), 3000), tail(out.String(), 4000))
			}
		})
		return res
	}
	t.Run("evil", func(t *testing.T) {
		for name, exp := range want.Evil {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				res := vetOne(t, "evil", name)
				r := res.Report
				if !slices.Contains(exp.Verdicts, r.Verdict) {
					t.Errorf("verdict %s, want one of %v", r.Verdict, exp.Verdicts)
				}
				for _, cat := range exp.Categories {
					if !hasCategory(r, cat) {
						t.Errorf("no %s finding (have %s)", cat, categories(r))
					}
				}
				t.Logf("%s: %s, %s", name, r.Verdict, categories(r))
			})
		}
	})
	t.Run("normal", func(t *testing.T) {
		for _, name := range want.Normal {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				r := vetOne(t, "normal", name).Report
				if r.Verdict != report.Clean {
					t.Errorf("verdict %s, want clean (findings %s)", r.Verdict, categories(r))
				}
				t.Logf("%s: %s (%d events)", name, r.Verdict, r.Events)
			})
		}
	})
}

func hasCategory(r *report.Report, cat string) bool {
	for _, f := range r.Findings {
		if f.Category == cat && len(f.Evidence) > 0 {
			return true
		}
	}
	return false
}

func categories(r *report.Report) string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, fmt.Sprintf("%s/%s:%q", f.Category, f.Severity, f.Title))
	}
	return "[" + strings.Join(out, ", ") + "]"
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
