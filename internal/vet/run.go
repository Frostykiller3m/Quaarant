package vet

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/report"
)

// CloneImage clones repositories (pinned: a moving tag would change what runs the clone).
const CloneImage = "alpine/git:v2.49.1"

// RepoDir is where the repository lands in the run sandbox.
const RepoDir = "/tmp/repo"

// ErrNotApproved means the user declined the plan.
var ErrNotApproved = errors.New("plan not approved: nothing was run")

// Options configure a vetting run.
type Options struct {
	Client    qtdv1.SandboxServiceClient
	Repo      Repo
	Planner   Planner         // nil: plan from the repository's files
	Analyzer  report.Analyzer // nil: rules-only report
	Approve   func(*Plan) bool
	Isolation qtdv1.Isolation
	Net       *Net     // overrides the plan's network policy (--net)
	Command   []string // overrides the plan's run steps (qt run URL -- cmd)
	Timeout   time.Duration
	Limits    *qtdv1.Limits
	Out, Err  io.Writer
	MaxRepo   int64 // bytes; 0 = 512 MiB
	// LocalDir, if set, is used instead of cloning Repo (a trusted local checkout, e.g. the
	// red-team corpus). Everything after the clone is the same.
	LocalDir string
}

// Result is a finished vetting run.
type Result struct {
	Sandbox string
	Plan    *Plan
	Report  *report.Report
}

// Run clones, plans, asks, runs and reports.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Minute
	}
	if o.MaxRepo == 0 {
		o.MaxRepo = 512 << 20
	}
	say := func(format string, a ...any) { fmt.Fprintf(o.Err, "qt: "+format+"\n", a...) }

	tmp, err := os.CreateTemp("", "qt-vet-*.tar")
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()); _ = tmp.Close() }()
	var sum *Summary
	var n int64
	if o.LocalDir != "" {
		pr, pw := io.Pipe()
		go func() { _ = pw.CloseWithError(tarDir(o.LocalDir, "repo", pw)) }()
		cw := &countWriter{w: tmp}
		if sum, err = Summarize(io.TeeReader(pr, cw), "repo"); err != nil {
			return nil, err
		}
		_, _ = io.Copy(cw, pr)
		n = cw.n
	} else if sum, n, err = clone(ctx, o, tmp, say); err != nil {
		return nil, err
	}
	say("repository: %d files (%s archive)", sum.Total, human(n))
	return o.planAndRun(ctx, sum, tmp, say)
}

// clone clones o.Repo in a sandbox that may reach only the git host and spools it to w.
func clone(ctx context.Context, o Options, w io.Writer, say func(string, ...any)) (*Summary, int64, error) {
	say("cloning %s in a sandbox (network: %s only)", o.Repo.URL, o.Repo.Host)
	cloneID, err := create(ctx, o.Client, CloneImage, &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_ALLOW, AllowDomains: []string{o.Repo.Host}}, false, o.Isolation, map[string]string{"qt.vet": "clone"}, o.Limits)
	if err != nil {
		return nil, 0, fmt.Errorf("clone sandbox: %w", err)
	}
	defer func() { _, _ = o.Client.Destroy(context.WithoutCancel(ctx), &qtdv1.DestroyRequest{SandboxId: cloneID}) }()
	code, err := runIn(ctx, o.Client, cloneID, "/tmp", []string{
		"git", "-c", "protocol.file.allow=never", "-c", "core.hooksPath=/dev/null",
		"clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules", "--", o.Repo.URL, RepoDir,
	},
		[]string{"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false"}, 5*time.Minute, io.Discard, prefixed(o.Err, "  git: "))
	if err != nil {
		return nil, 0, fmt.Errorf("clone: %w", err)
	}
	if code != 0 {
		return nil, 0, fmt.Errorf("git clone exited %d", code)
	}
	// The repository, as a tar stream: summarized for the planner and spooled for the copy.
	return fetchRepo(ctx, o.Client, cloneID, w, o.MaxRepo)
}

// planAndRun plans, flags, asks, runs and reports.
func (o Options) planAndRun(ctx context.Context, sum *Summary, tmp *os.File, say func(string, ...any)) (*Result, error) {
	var err error
	var plan *Plan
	if o.Planner != nil {
		say("asking %s for a plan (the repository is sent to the Claude API as untrusted data)", o.Planner.Name())
		if plan, err = o.Planner.Plan(ctx, o.Repo, sum); err == nil {
			err = plan.Validate()
		}
		if err != nil {
			say("no usable plan from %s (%s); planning from the repository's files", o.Planner.Name(), clean(err.Error(), 200))
			plan = nil
		}
	}
	if plan == nil {
		p := OfflinePlan(sum)
		plan = &p
		if err := plan.Validate(); err != nil {
			return nil, err
		}
	}
	if o.Net != nil {
		plan.Net = *o.Net
		if err := plan.Validate(); err != nil {
			return nil, err
		}
	}
	if len(o.Command) > 0 {
		plan.Run = []Step{{Command: shellJoin(o.Command), Why: "your command"}}
	}
	Flag(plan)
	WritePlan(o.Err, o.Repo, plan)
	if o.Approve == nil || !o.Approve(plan) {
		return &Result{Plan: plan}, ErrNotApproved
	}

	// 4. Run, in a fresh sandbox with honeytokens.
	id, err := create(ctx, o.Client, plan.Image, plan.Net.proto(), true, o.Isolation, map[string]string{"qt.vet": o.Repo.Host + "/" + o.Repo.Name}, o.Limits)
	if err != nil {
		return nil, fmt.Errorf("run sandbox: %w", err)
	}
	res := &Result{Sandbox: id, Plan: plan}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return res, err
	}
	if err := copyIn(ctx, o.Client, id, "/tmp", tmp); err != nil {
		return res, fmt.Errorf("copy the repository in: %w", err)
	}
	say("sandbox %s (%s, network %s)", id, plan.Image, plan.Net.String())
	steps := append(append([]Step(nil), plan.Setup...), plan.Run...)
	for i, s := range steps {
		fmt.Fprintf(o.Err, "\n==> [%d/%d] %s\n", i+1, len(steps), clean(s.Command, 300))
		code, err := runIn(ctx, o.Client, id, RepoDir, []string{"/bin/sh", "-c", s.Command}, nil, o.Timeout, o.Out, o.Err)
		switch {
		case err != nil:
			fmt.Fprintf(o.Err, "==> failed: %s\n", clean(err.Error(), 200))
		case code != 0:
			fmt.Fprintf(o.Err, "==> exit %d\n", code)
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}

	// 5. Report.
	time.Sleep(2500 * time.Millisecond) // gvisor flushes pending file events after 2 s
	evs, err := FetchEvents(ctx, o.Client, id)
	if err != nil {
		return res, err
	}
	res.Report = report.Build(ctx, id, evs, o.Analyzer)
	fmt.Fprintln(o.Out)
	res.Report.WriteText(o.Out)
	return res, nil
}

func (n Net) proto() *qtdv1.NetPolicy {
	switch n.Mode {
	case "allow":
		return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_ALLOW, AllowDomains: n.Allow}
	case "log":
		return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_LOG}
	}
	return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_NONE}
}

func (n Net) String() string {
	if n.Mode == "allow" {
		return "allow " + strings.Join(n.Allow, ", ")
	}
	return n.Mode
}

// WritePlan prints a plan for approval.
func WritePlan(w io.Writer, repo Repo, p *Plan) {
	fmt.Fprintf(w, "\nPlan for %s (from %s):\n", repo.URL, p.Source)
	if p.Summary != "" {
		fmt.Fprintf(w, "  %s\n", p.Summary)
	}
	fmt.Fprintf(w, "  image:    %s\n  network:  %s\n", p.Image, p.Net.String())
	for _, part := range []struct {
		name  string
		steps []Step
	}{{"setup", p.Setup}, {"run", p.Run}} {
		for i, s := range part.steps {
			label := ""
			if i == 0 {
				label = part.name + ":"
			}
			fmt.Fprintf(w, "  %-9s %d. %s", label, i+1, clean(s.Command, 500))
			if s.Why != "" {
				fmt.Fprintf(w, "   # %s", s.Why)
			}
			fmt.Fprintln(w)
		}
	}
	if len(p.Risky) > 0 {
		fmt.Fprintf(w, "\nFlagged:\n")
		for _, r := range p.Risky {
			mark := map[string]string{"high": "!!", "medium": " !", "note": "  "}[r.Level]
			fmt.Fprintf(w, "  %s %s\n     %s (%s)\n", mark, clean(r.What, 300), r.Reason, r.By)
		}
	}
	fmt.Fprintf(w, "\nThe plan runs in a fresh sandbox with fake credentials planted; everything it does is recorded.\n")
}

// FetchEvents reads a sandbox's whole event log, validating each line.
func FetchEvents(ctx context.Context, c qtdv1.SandboxServiceClient, id string) ([]events.Event, error) {
	stream, err := c.Events(ctx, &qtdv1.EventsRequest{SandboxId: id})
	if err != nil {
		return nil, err
	}
	var evs []events.Event
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return evs, nil
		}
		if err != nil {
			return nil, err
		}
		ev, err := events.Validate(m.GetEventJson())
		if err != nil {
			return nil, fmt.Errorf("invalid event from qtd: %w", err)
		}
		evs = append(evs, ev)
	}
}

func create(ctx context.Context, c qtdv1.SandboxServiceClient, img string, net *qtdv1.NetPolicy, honey bool, iso qtdv1.Isolation, labels map[string]string, lim *qtdv1.Limits) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	resp, err := c.Create(cctx, &qtdv1.CreateRequest{Image: img, Net: net, Honeytokens: honey, Isolation: iso, Labels: labels, Limits: lim})
	if err != nil {
		return "", err
	}
	return resp.GetSandbox().GetId(), nil
}

// runIn runs argv to completion, streaming output; it returns the exit code.
func runIn(ctx context.Context, c qtdv1.SandboxServiceClient, id, dir string, argv, env []string, timeout time.Duration, stdout, stderr io.Writer) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	st, err := c.Exec(ctx)
	if err != nil {
		return 0, err
	}
	if err := st.Send(&qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_Start_{Start: &qtdv1.ExecRequest_Start{SandboxId: id, Argv: argv, Env: env, Workdir: dir}}}); err != nil {
		return 0, err
	}
	_ = st.CloseSend()
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return 0, errors.New("exec ended without an exit status")
		}
		if err != nil {
			if ctx.Err() != nil {
				return 0, fmt.Errorf("timed out after %v", timeout)
			}
			return 0, err
		}
		switch x := m.GetMsg().(type) {
		case *qtdv1.ExecResponse_Stdout:
			_, _ = stdout.Write(x.Stdout)
		case *qtdv1.ExecResponse_Stderr:
			_, _ = stderr.Write(x.Stderr)
		case *qtdv1.ExecResponse_Exit_:
			if s := x.Exit.GetSignal(); s != 0 {
				return 128 + int(s), nil
			}
			return int(x.Exit.GetCode()), nil
		}
	}
}

// fetchRepo copies the clone out as a tar, spooling it to w and summarizing it on the way.
func fetchRepo(ctx context.Context, c qtdv1.SandboxServiceClient, id string, w io.Writer, max int64) (*Summary, int64, error) {
	stream, err := c.CopyOut(ctx, &qtdv1.CopyOutRequest{SandboxId: id, Path: RepoDir})
	if err != nil {
		return nil, 0, fmt.Errorf("copy the clone out: %w", err)
	}
	pr, pw := io.Pipe()
	var n int64
	go func() {
		for {
			m, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				_ = pw.Close()
				return
			}
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			chunk := m.GetTarChunk()
			if n += int64(len(chunk)); n > max {
				_ = pw.CloseWithError(fmt.Errorf("the repository is larger than %s", human(max)))
				return
			}
			if _, err := w.Write(chunk); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
	}()
	sum, err := Summarize(pr, "repo")
	_, _ = io.Copy(io.Discard, pr) // drain: the spool gets everything
	if err != nil {
		return nil, 0, err
	}
	return sum, n, nil
}

func copyIn(ctx context.Context, c qtdv1.SandboxServiceClient, id, dir string, r io.Reader) error {
	st, err := c.CopyIn(ctx)
	if err != nil {
		return err
	}
	if err := st.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_Header_{Header: &qtdv1.CopyInRequest_Header{SandboxId: id, Dir: dir}}}); err != nil {
		return err
	}
	buf := make([]byte, 256<<10)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if err := st.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_TarChunk{TarChunk: append([]byte(nil), buf[:n]...)}}); err != nil {
				break
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	_, err = st.CloseAndRecv()
	return err
}

type prefixWriter struct {
	w      io.Writer
	prefix string
	bol    bool
}

func prefixed(w io.Writer, p string) io.Writer { return &prefixWriter{w: w, prefix: p, bol: true} }

func (p *prefixWriter) Write(b []byte) (int, error) {
	for _, line := range strings.SplitAfter(string(b), "\n") {
		if line == "" {
			continue
		}
		if p.bol {
			_, _ = io.WriteString(p.w, p.prefix)
		}
		_, _ = io.WriteString(p.w, strings.Map(func(r rune) rune {
			if r == '\x1b' {
				return -1
			}
			return r
		}, line))
		p.bol = strings.HasSuffix(line, "\n")
	}
	return len(b), nil
}

func shellJoin(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// tarDir writes dir as a tar whose entries start with top/ (regular files, directories and
// symlinks; nothing else).
func tarDir(dir, top string, w io.Writer) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		link := ""
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		case !fi.Mode().IsRegular() && !fi.IsDir():
			return nil
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		h.Name = path.Join(top, filepath.ToSlash(rel))
		if fi.IsDir() {
			h.Name += "/"
		}
		h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(p) //nolint:gosec // G304: the caller's own directory
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			_ = f.Close()
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}
