package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
)

func newRunCommand(g *globals) *cobra.Command {
	var (
		isolation, net, workdir, hostname, memory string
		env, labels                               []string
		cpus                                      float64
		pids                                      int
		rm, interactive, tty, quiet, honeytokens  bool
	)
	cmd := &cobra.Command{
		Use:   "run [flags] IMAGE [--] [COMMAND [ARG...]]",
		Short: "Create a sandbox from an image and run a command in it",
		Long: "run pulls IMAGE, starts a fresh sandbox (gVisor by default, non-root, no network) and runs\n" +
			"COMMAND in it, exiting with the command's status. The sandbox is kept for inspection\n" +
			"(qt ls, qt exec, qt rm) unless --rm is given. With -t and no COMMAND it runs /bin/sh.",
		Example: "  qt run alpine -- sh -c 'echo hi'\n  qt run -it --rm python:3.13-slim",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			img, argv := splitCommand(args)
			if len(argv) == 0 {
				if !tty {
					return errors.New("missing COMMAND (qt run IMAGE -- COMMAND...), or use -t for a shell")
				}
				argv = []string{"/bin/sh"}
			}
			req, err := createRequest(img, isolation, net, hostname, memory, cpus, pids, labels)
			if err != nil {
				return err
			}
			req.Honeytokens = honeytokens
			envs, err := parseEnvFlags(env)
			if err != nil {
				return err
			}
			if tty {
				envs = append([]string{"TERM=" + termName()}, envs...)
			}
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			ctx := cmd.Context()

			resp, err := c.Create(ctx, req)
			if err != nil {
				return friendly(err, g.socket)
			}
			id := resp.GetSandbox().GetId()
			if rm {
				defer func() {
					dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
					defer cancel()
					if _, err := c.Destroy(dctx, &qtdv1.DestroyRequest{SandboxId: id}); err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "qt: remove sandbox %s: %v\n", id, friendly(err, g.socket))
					}
				}()
			} else if !quiet {
				fmt.Fprintf(cmd.ErrOrStderr(), "qt: sandbox %s (%s)\n", id, resp.GetSandbox().GetImage())
			}
			code, err := streamExec(ctx, c, &qtdv1.ExecRequest_Start{
				SandboxId: id, Argv: argv, Env: envs, Workdir: workdir, Tty: tty,
			}, execIO{stdin: cmd.InOrStdin(), stdout: cmd.OutOrStdout(), stderr: cmd.ErrOrStderr(), interactive: interactive, tty: tty})
			if err != nil {
				return friendly(err, g.socket)
			}
			if code != 0 {
				return exitCodeError{code}
			}
			return nil
		},
	}
	addExecFlags(cmd, &interactive, &tty, &env, &workdir)
	f := cmd.Flags()
	f.StringVar(&isolation, "isolation", "gvisor", "isolation level: gvisor or vm")
	f.StringVar(&net, "net", "none", "network: none, log (everything public, all recorded) or allow:DOMAIN[,DOMAIN...] (those names and their subdomains only)")
	f.StringVar(&hostname, "hostname", "", "sandbox hostname (default qt-<id>)")
	f.Float64Var(&cpus, "cpus", 0, "CPU limit in cores, e.g. 1.5 (default 2)")
	f.StringVar(&memory, "memory", "", "memory limit, e.g. 512m or 2g (default 2g)")
	f.IntVar(&pids, "pids", 0, "process limit (default 512)")
	f.StringArrayVar(&labels, "label", nil, "label KEY=VALUE (repeatable)")
	f.BoolVar(&rm, "rm", false, "remove the sandbox when the command exits")
	f.BoolVarP(&quiet, "quiet", "q", false, "do not print the sandbox id")
	f.BoolVar(&honeytokens, "honeytokens", true, "plant fake credentials (SSH key, AWS, .env, browser cookies) in $HOME; reading or sending them is an event")
	return cmd
}

func createRequest(img, isolation, net, hostname, memory string, cpus float64, pids int, labels []string) (*qtdv1.CreateRequest, error) {
	req := &qtdv1.CreateRequest{Image: img, Hostname: hostname, Limits: &qtdv1.Limits{}, Labels: map[string]string{}}
	switch isolation {
	case "gvisor":
		req.Isolation = qtdv1.Isolation_ISOLATION_GVISOR
	case "vm":
		req.Isolation = qtdv1.Isolation_ISOLATION_VM
	default:
		return nil, fmt.Errorf("--isolation must be gvisor or vm, not %q", isolation)
	}
	np, err := parseNet(net)
	if err != nil {
		return nil, err
	}
	req.Net = np
	if cpus < 0 || cpus > 1024 || math.IsNaN(cpus) {
		return nil, fmt.Errorf("--cpus %v out of range", cpus)
	}
	req.Limits.CpuMillis = uint32(math.Round(cpus * 1000))
	if memory != "" {
		b, err := parseBytes(memory)
		if err != nil {
			return nil, fmt.Errorf("--memory: %w", err)
		}
		req.Limits.MemoryBytes = b
	}
	if pids < 0 || pids > 1<<20 {
		return nil, fmt.Errorf("--pids %d out of range", pids)
	}
	req.Limits.Pids = uint32(pids)
	for _, l := range labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--label %q must be KEY=VALUE", l)
		}
		req.Labels[k] = v
	}
	return req, nil
}

// parseBytes parses sizes like 512m, 2g, 1048576 (binary units).
func parseBytes(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := uint64(1)
	for _, u := range []struct {
		suffix string
		m      uint64
	}{{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"t", 1 << 40}} {
		if t, ok := strings.CutSuffix(strings.TrimSuffix(s, "b"), u.suffix); ok && s != "" {
			s, mult = t, u.m
			break
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n <= 0 || n*float64(mult) > 1<<50 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return uint64(n * float64(mult)), nil
}

func newExecCommand(g *globals) *cobra.Command {
	var (
		interactive, tty bool
		env              []string
		workdir          string
	)
	cmd := &cobra.Command{
		Use:     "exec [flags] SANDBOX [--] COMMAND [ARG...]",
		Short:   "Run a command in an existing sandbox",
		Example: "  qt exec 3f2a9c1b7e04 -- ls -la /tmp\n  echo data | qt exec -i 3f2a9c1b7e04 -- cat",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, argv := splitCommand(args)
			if len(argv) == 0 {
				return errors.New("missing COMMAND")
			}
			return execIn(cmd, g, id, argv, env, workdir, interactive, tty)
		},
	}
	addExecFlags(cmd, &interactive, &tty, &env, &workdir)
	return cmd
}

func newShellCommand(g *globals) *cobra.Command {
	var (
		env     []string
		workdir string
	)
	cmd := &cobra.Command{
		Use:   "shell SANDBOX [--] [COMMAND [ARG...]]",
		Short: "Open an interactive terminal (PTY) in a sandbox",
		Long:  "shell runs COMMAND (default /bin/sh) in SANDBOX with a terminal and stdin attached.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, argv := splitCommand(args)
			if len(argv) == 0 {
				argv = []string{"/bin/sh"}
			}
			return execIn(cmd, g, id, argv, env, workdir, true, true)
		},
	}
	cmd.Flags().StringArrayVarP(&env, "env", "e", nil, "set environment variables")
	cmd.Flags().StringVarP(&workdir, "workdir", "w", "", "working directory inside the sandbox")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func execIn(cmd *cobra.Command, g *globals, id string, argv, env []string, workdir string, interactive, tty bool) error {
	envs, err := parseEnvFlags(env)
	if err != nil {
		return err
	}
	if tty {
		envs = append([]string{"TERM=" + termName()}, envs...)
	}
	c, closer, err := g.client()
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	code, err := streamExec(cmd.Context(), c, &qtdv1.ExecRequest_Start{
		SandboxId: id, Argv: argv, Env: envs, Workdir: workdir, Tty: tty,
	}, execIO{stdin: cmd.InOrStdin(), stdout: cmd.OutOrStdout(), stderr: cmd.ErrOrStderr(), interactive: interactive, tty: tty})
	if err != nil {
		return friendly(err, g.socket)
	}
	if code != 0 {
		return exitCodeError{code}
	}
	return nil
}

func newLsCommand(g *globals) *cobra.Command {
	var asJSON, quiet bool
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list", "ps"},
		Short:   "List sandboxes",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			resp, err := c.List(cmd.Context(), &qtdv1.ListRequest{})
			if err != nil {
				return friendly(err, g.socket)
			}
			out := cmd.OutOrStdout()
			switch {
			case asJSON:
				b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(resp)
				if err != nil {
					return fmt.Errorf("encode: %w", err)
				}
				fmt.Fprintln(out, string(b))
			case quiet:
				for _, s := range resp.GetSandboxes() {
					fmt.Fprintln(out, s.GetId())
				}
			default:
				tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tIMAGE\tISOLATION\tSTATE\tCREATED")
				for _, s := range resp.GetSandboxes() {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.GetId(), shortImage(s.GetImage()), isoName(s.GetIsolation()),
						stateName(s.GetState()), ago(s.GetCreatedAt().AsTime()))
				}
				return tw.Flush()
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "print only ids")
	return cmd
}

func newRmCommand(g *globals) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:     "rm SANDBOX...",
		Aliases: []string{"remove", "destroy"},
		Short:   "Stop sandboxes and delete everything they left in the data dir",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !all {
				return errors.New("give sandbox ids or --all")
			}
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			ids := args
			if all {
				resp, err := c.List(cmd.Context(), &qtdv1.ListRequest{})
				if err != nil {
					return friendly(err, g.socket)
				}
				for _, s := range resp.GetSandboxes() {
					ids = append(ids, s.GetId())
				}
			}
			var errs []error
			for _, id := range ids {
				if _, err := c.Destroy(cmd.Context(), &qtdv1.DestroyRequest{SandboxId: id}); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", id, friendly(err, g.socket)))
					continue
				}
				fmt.Fprintln(cmd.OutOrStdout(), id)
			}
			return errors.Join(errs...)
		},
	}
	cmd.Flags().BoolVarP(&all, "all", "a", false, "remove every sandbox")
	return cmd
}

func shortImage(ref string) string {
	if name, digest, ok := strings.Cut(ref, "@sha256:"); ok && len(digest) >= 12 {
		return strings.TrimPrefix(name, "index.docker.io/library/") + "@" + digest[:12]
	}
	return ref
}

func isoName(i qtdv1.Isolation) string {
	switch i {
	case qtdv1.Isolation_ISOLATION_GVISOR:
		return "gvisor"
	case qtdv1.Isolation_ISOLATION_VM:
		return "vm"
	}
	return "?"
}

func stateName(s qtdv1.SandboxState) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "SANDBOX_STATE_"))
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return t.Local().Format("2006-01-02")
}

// parseNet reads --net: none, log, or allow:a.com,b.org (qtd validates the names again).
func parseNet(s string) (*qtdv1.NetPolicy, error) {
	switch {
	case s == "none":
		return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_NONE}, nil
	case s == "log":
		return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_LOG}, nil
	case strings.HasPrefix(s, "allow:"):
		var ds []string
		for _, d := range strings.Split(strings.TrimPrefix(s, "allow:"), ",") {
			if d = strings.TrimSpace(d); d != "" {
				ds = append(ds, d)
			}
		}
		if len(ds) == 0 {
			return nil, errors.New("--net=allow: needs at least one domain, e.g. --net=allow:pypi.org,files.pythonhosted.org")
		}
		return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_ALLOW, AllowDomains: ds}, nil
	}
	return nil, fmt.Errorf("--net=%s: want none, log or allow:DOMAIN[,DOMAIN...]", s)
}
