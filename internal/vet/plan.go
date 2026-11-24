package vet

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

// Step is one command of a plan.
type Step struct {
	Command string `json:"command"`
	Why     string `json:"why"`
}

// Net is a plan's network policy.
type Net struct {
	Mode  string   `json:"mode"` // none, allow or log
	Allow []string `json:"allow"`
}

// Risk is a flagged command or plan choice.
type Risk struct {
	What   string `json:"what"`
	Reason string `json:"reason"`
	Level  string `json:"level"` // high, medium or note
	By     string `json:"by"`    // "rules" or the planner
}

// Plan is how to run a repository.
type Plan struct {
	Image   string `json:"image"`
	Setup   []Step `json:"setup"`
	Run     []Step `json:"run"`
	Net     Net    `json:"net"`
	Risky   []Risk `json:"risky"`
	Summary string `json:"summary"`
	Source  string `json:"source"` // the planner: "repository files" or a Claude model
}

const (
	maxSetup   = 10
	maxRun     = 5
	maxCommand = 1000
	maxDomains = 16
)

// imageRe is a Docker reference: [registry/][namespace/]name[:tag][@sha256:...].
var imageRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*){0,3}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

// Validate checks and normalizes a plan (from Claude or rules) before it is shown.
func (p *Plan) Validate() error {
	p.Image = strings.TrimSpace(p.Image)
	if !imageRe.MatchString(p.Image) || len(p.Image) > 255 {
		return fmt.Errorf("plan: image %.100q is not a valid image reference", p.Image)
	}
	if len(p.Setup) > maxSetup || len(p.Run) > maxRun || len(p.Setup)+len(p.Run) == 0 {
		return fmt.Errorf("plan: want 1-%d setup and 0-%d run commands, got %d and %d", maxSetup, maxRun, len(p.Setup), len(p.Run))
	}
	for _, steps := range [][]Step{p.Setup, p.Run} {
		for i := range steps {
			steps[i].Command = strings.TrimSpace(steps[i].Command)
			steps[i].Why = clean(steps[i].Why, 200)
			c := steps[i].Command
			if c == "" || len(c) > maxCommand || strings.ContainsRune(c, 0) {
				return fmt.Errorf("plan: command %d is empty, too long or has a NUL", i+1)
			}
		}
	}
	switch p.Net.Mode {
	case "none":
		p.Net.Allow = nil
	case "log":
		p.Net.Allow = nil
	case "allow":
		if len(p.Net.Allow) == 0 || len(p.Net.Allow) > maxDomains {
			return fmt.Errorf("plan: an allow-list needs 1-%d domains", maxDomains)
		}
		r, err := netpol.Rules{Mode: netpol.ModeAllow, Allow: p.Net.Allow}.Normalize()
		if err != nil {
			return fmt.Errorf("plan: %w", err)
		}
		p.Net.Allow = r.Allow
	default:
		return fmt.Errorf("plan: network mode %.20q", p.Net.Mode)
	}
	p.Summary = clean(p.Summary, 1500)
	for i := range p.Risky {
		p.Risky[i].What, p.Risky[i].Reason = clean(p.Risky[i].What, 300), clean(p.Risky[i].Reason, 300)
		if !slices.Contains([]string{"high", "medium", "note"}, p.Risky[i].Level) {
			p.Risky[i].Level = "medium"
		}
	}
	return nil
}

// Known registries for package managers: allowing them is the expected case.
var registries = map[string]bool{
	"pypi.org": true, "files.pythonhosted.org": true, "registry.npmjs.org": true, "registry.yarnpkg.com": true,
	"proxy.golang.org": true, "sum.golang.org": true, "crates.io": true, "static.crates.io": true, "index.crates.io": true,
	"rubygems.org": true, "index.rubygems.org": true, "repo.packagist.org": true, "github.com": true,
	"objects.githubusercontent.com": true, "codeload.github.com": true, "repo.maven.apache.org": true,
}

var commandRules = []struct {
	re     *regexp.Regexp
	level  string
	reason string
}{
	{regexp.MustCompile(`(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`), "high", "downloads a script and runs it unseen"},
	{regexp.MustCompile(`base64\s+(-d|--decode)[^|;&]*\|\s*(ba|z|da)?sh\b|\beval\s+["'$(]`), "high", "decodes or builds code and runs it"},
	{regexp.MustCompile(`(^|[;&|]\s*)(sudo|su|doas)\s`), "medium", "asks for root (the sandbox gives none)"},
	{regexp.MustCompile(`>>?\s*(~|\$HOME|/root|/home/[^/\s]+)?/?\.(bashrc|profile|zshrc|bash_profile)\b|>>?\s*/etc/|crontab\s|systemctl\s+enable`), "high", "makes something run again later (persistence)"},
	{regexp.MustCompile(`chmod\s+([ugoa]*\+s|[0-7]?[4-7][0-7]{3})\b`), "high", "sets a setuid/setgid bit"},
	{regexp.MustCompile(`rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME)(\s|$)`), "high", "deletes the root or home directory"},
	{regexp.MustCompile(`\b(nc|ncat|netcat|socat)\b|/dev/(tcp|udp)/`), "high", "opens a raw network connection"},
	{regexp.MustCompile(`(~|\$HOME)/\.(ssh|aws|config/gcloud|kube|docker)\b|\.env\b`), "medium", "reads credential locations"},
	{regexp.MustCompile(`pip3?\s+install\s+[^;&|]*(git\+|https?://)|npm\s+(i|install)\s+[^;&|]*(https?://|github:|git\+)`), "medium", "installs from an unpinned URL"},
	{regexp.MustCompile(`\b(curl|wget)\s`), "medium", "downloads from the internet"},
	{regexp.MustCompile(`\b(npm|pnpm|yarn)\s+(i|install|ci)\b|\bpip3?\s+install\b|\bgem\s+install\b|\bcargo\s+build\b`), "note", "runs the dependencies' install/build scripts (this is what the sandbox watches)"},
}

// Flag adds the rules' risks to a plan's own (independent of who wrote the plan, so a
// prompt-injected planner can't hide them).
func Flag(p *Plan) {
	add := func(what, reason, level string) {
		for _, r := range p.Risky {
			if r.What == what && r.Reason == reason {
				return
			}
		}
		p.Risky = append(p.Risky, Risk{What: clean(what, 300), Reason: reason, Level: level, By: "rules"})
	}
	if strings.ContainsAny(strings.SplitN(p.Image, ":", 2)[0], "/") {
		add("image "+p.Image, "not an official Docker image (anyone can publish under a namespace)", "high")
	}
	if p.Net.Mode == "log" {
		add("network: log", "full internet access (every connection is recorded)", "medium")
	}
	for _, d := range p.Net.Allow {
		known := false
		for r := range registries {
			known = known || d == r || strings.HasSuffix(d, "."+r)
		}
		if !known {
			add("network: allow "+d, "not a known package registry", "medium")
		}
	}
	for _, steps := range [][]Step{p.Setup, p.Run} {
		for _, s := range steps {
			for _, r := range commandRules {
				if r.re.MatchString(s.Command) {
					add(s.Command, r.reason, r.level)
					break
				}
			}
		}
	}
	slices.SortStableFunc(p.Risky, func(a, b Risk) int { return levelRank(a.Level) - levelRank(b.Level) })
}

func levelRank(l string) int { return slices.Index([]string{"high", "medium", "note"}, l) }

// OfflinePlan derives a plan from the repository's manifests (no API key).
func OfflinePlan(s *Summary) Plan {
	p := Plan{Source: "repository files", Net: Net{Mode: "none"}}
	switch {
	case pick(s, "package.json"):
		p.Image = "node:22-alpine"
		p.Net = Net{Mode: "allow", Allow: []string{"registry.npmjs.org"}}
		p.Setup = []Step{{"npm install", "install dependencies (runs their install scripts)"}}
		if scriptsHave(s.Key["package.json"], "test") {
			p.Run = []Step{{"npm test", "run the project's tests"}}
		}
	case pick(s, "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"):
		p.Image = "python:3.13-slim"
		p.Net = Net{Mode: "allow", Allow: []string{"pypi.org", "files.pythonhosted.org"}}
		if pick(s, "requirements.txt") {
			p.Setup = append(p.Setup, Step{"pip install --user -r requirements.txt", "install dependencies"})
		}
		if pick(s, "pyproject.toml", "setup.py", "setup.cfg") {
			p.Setup = append(p.Setup, Step{"pip install --user .", "install the package (runs its build)"})
		}
		if hasPythonTests(s) {
			p.Setup = append(p.Setup, Step{"pip install --user -q pytest", "the test runner"})
			p.Run = []Step{{"python -m pytest -q", "run the tests"}}
		}
	case pick(s, "go.mod"):
		p.Image = "golang:1.26-alpine"
		p.Net = Net{Mode: "allow", Allow: []string{"proxy.golang.org", "sum.golang.org"}}
		p.Setup = []Step{{"go build ./...", "build"}}
		p.Run = []Step{{"go test ./...", "run the tests"}}
	case pick(s, "Cargo.toml"):
		p.Image = "rust:1-slim"
		p.Net = Net{Mode: "allow", Allow: []string{"crates.io", "index.crates.io", "static.crates.io"}}
		p.Setup = []Step{{"cargo build", "build (runs build.rs scripts)"}}
		p.Run = []Step{{"cargo test", "run the tests"}}
	case pick(s, "Gemfile"):
		p.Image = "ruby:3.4-slim"
		p.Net = Net{Mode: "allow", Allow: []string{"rubygems.org", "index.rubygems.org"}}
		p.Setup = []Step{{"bundle install", "install dependencies"}}
	case pick(s, "Makefile"):
		p.Image = "alpine:3.22"
		p.Setup = []Step{{"make", "build with the Makefile"}}
	default:
		p.Image = "alpine:3.22"
		var scripts []string
		for _, f := range s.Files {
			if !strings.Contains(f, "/") && strings.HasSuffix(f, ".sh") {
				scripts = append(scripts, f)
			}
		}
		if len(scripts) > 0 {
			p.Setup = []Step{{"sh ./" + scripts[0], "run the repository's top-level script"}}
		} else {
			p.Setup = []Step{{"ls -la", "nothing to build: list the repository"}}
		}
	}
	p.Summary = fmt.Sprintf("Planned from the repository's files (%d files).", s.Total)
	return p
}

func pick(s *Summary, names ...string) bool {
	_, ok := s.has(names...)
	return ok
}

func scriptsHave(pkg, script string) bool {
	var m struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal([]byte(pkg), &m) != nil {
		return false
	}
	v, ok := m.Scripts[script]
	return ok && !strings.Contains(v, "no test specified")
}

// clean removes control and format characters and bounds the length (text shown in the
// terminal comes from repository content or a model that read it).
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

func hasPythonTests(s *Summary) bool {
	for _, f := range s.Files {
		base := f[strings.LastIndex(f, "/")+1:]
		if strings.HasSuffix(f, ".py") && (strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") || strings.HasPrefix(f, "tests/") || strings.Contains(f, "/tests/")) {
			return true
		}
	}
	return false
}
