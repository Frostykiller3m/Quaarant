package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/report"
	"github.com/Frostykiller3m/Quaarant/internal/vet"
)

// vetFlags are qt run's options for a git URL.
type vetFlags struct {
	yes, offline bool
	timeout      time.Duration
}

// Exit codes of a vetting run.
const (
	exitSuspicious = 2
	exitMalicious  = 3
)

// runVet is `qt run <git-url> [-- COMMAND]`: clone in a sandbox, plan, approve, run, report.
func runVet(cmd *cobra.Command, g *globals, url string, argv []string, v vetFlags, isolation, net, memory string, cpus float64, pids int, rm bool) error {
	repo, err := vet.ParseRepo(url)
	if err != nil {
		return err
	}
	req, err := createRequest("x", isolation, net, "", memory, cpus, pids, nil)
	if err != nil {
		return err
	}
	o := vet.Options{
		Repo: repo, Isolation: req.GetIsolation(), Limits: req.GetLimits(), Command: argv, Timeout: v.timeout,
		Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr(),
	}
	if cmd.Flags().Changed("net") { // --net overrides the plan's policy
		np := req.GetNet()
		o.Net = &vet.Net{Mode: strings.ToLower(strings.TrimPrefix(np.GetMode().String(), "MODE_")), Allow: np.GetAllowDomains()}
	}
	haveKey := os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != ""
	if haveKey && !v.offline {
		o.Planner = vet.NewClaudePlanner("")
		o.Analyzer = report.NewClaude("")
	}
	o.Approve = func(*vet.Plan) bool {
		if v.yes {
			fmt.Fprintln(o.Err, "Approved with --yes.")
			return true
		}
		f, ok := cmd.InOrStdin().(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			fmt.Fprintln(o.Err, "Not a terminal: pass --yes to approve the plan.")
			return false
		}
		fmt.Fprint(o.Err, "Run this plan? [y/N] ")
		line, _ := bufio.NewReader(f).ReadString('\n')
		a := strings.ToLower(strings.TrimSpace(line))
		return a == "y" || a == "yes"
	}
	c, closer, err := g.client()
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	o.Client = c
	res, err := vet.Run(cmd.Context(), o)
	if res != nil && res.Sandbox != "" {
		if rm {
			if _, derr := c.Destroy(cmd.Context(), &qtdv1.DestroyRequest{SandboxId: res.Sandbox}); derr == nil {
				fmt.Fprintf(o.Err, "qt: removed sandbox %s\n", res.Sandbox)
			}
		} else {
			fmt.Fprintf(o.Err, "qt: sandbox %s kept: qt events %s, qt diff %s, qt rm %s\n", res.Sandbox, res.Sandbox, res.Sandbox, res.Sandbox)
		}
	}
	if errors.Is(err, vet.ErrNotApproved) {
		fmt.Fprintln(o.Err, "qt: plan not approved; nothing ran.")
		return exitCodeError{code: 1}
	}
	if err != nil {
		return friendly(err, g.socket)
	}
	switch res.Report.Verdict {
	case report.Malicious:
		return exitCodeError{code: exitMalicious}
	case report.Suspicious:
		return exitCodeError{code: exitSuspicious}
	}
	return nil
}
