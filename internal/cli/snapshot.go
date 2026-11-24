package cli

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
)

func newSnapshotCommand(g *globals) *cobra.Command {
	var (
		name     string
		noMemory bool
	)
	cmd := &cobra.Command{
		Use:   "snapshot SANDBOX",
		Short: "Save a sandbox's state (memory and disk) to restore or fork later (vm)",
		Long: "snapshot pauses the sandbox for a moment and saves its memory and disk; it then keeps\n" +
			"running. qt restore SNAPSHOT starts a new sandbox from it, with processes still running and\n" +
			"a fresh identity. --no-memory saves only the disk (a restore boots it).",
		Example: "  qt snapshot --name before-install 3f2a9c1b7e04\n  qt snapshot ls\n  qt restore sn-0123456789ab",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			resp, err := c.Snapshot(cmd.Context(), &qtdv1.SnapshotRequest{SandboxId: args[0], Name: name, IncludeMemory: !noMemory})
			if err != nil {
				return friendly(err, g.socket)
			}
			fmt.Fprintln(cmd.OutOrStdout(), resp.GetSnapshotId())
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "a name to recognize it by")
	cmd.Flags().BoolVar(&noMemory, "no-memory", false, "disk only (restores boot instead of resuming)")
	cmd.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List snapshots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			resp, err := c.ListSnapshots(cmd.Context(), &qtdv1.ListSnapshotsRequest{})
			if err != nil {
				return friendly(err, g.socket)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tFROM\tIMAGE\tMEMORY\tSIZE\tCREATED")
			for _, s := range resp.GetSnapshots() {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%s\t%s ago\n", s.GetId(), displayName(orDash(s.GetName()), nil), s.GetSandboxId(),
					shortImage(s.GetImage()), s.GetIncludesMemory(), humanBytes(s.GetBytes()), time.Since(s.GetCreatedAt().AsTime()).Round(time.Second))
			}
			return tw.Flush()
		},
	}, &cobra.Command{
		Use:   "rm SNAPSHOT...",
		Short: "Delete snapshots (sandboxes restored from them keep running)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			for _, id := range args {
				if _, err := c.DeleteSnapshot(cmd.Context(), &qtdv1.DeleteSnapshotRequest{SnapshotId: id}); err != nil {
					return friendly(err, g.socket)
				}
				fmt.Fprintln(cmd.OutOrStdout(), id)
			}
			return nil
		},
	})
	return cmd
}

func newRestoreCommand(g *globals) *cobra.Command {
	var labels []string
	cmd := &cobra.Command{
		Use:   "restore SNAPSHOT",
		Short: "Start a new sandbox from a snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lm, err := parseLabels(labels)
			if err != nil {
				return err
			}
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			resp, err := c.Restore(cmd.Context(), &qtdv1.RestoreRequest{SnapshotId: args[0], Labels: lm})
			if err != nil {
				return friendly(err, g.socket)
			}
			fmt.Fprintln(cmd.OutOrStdout(), resp.GetSandbox().GetId())
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&labels, "label", nil, "label KEY=VALUE (repeatable)")
	return cmd
}

func newForkCommand(g *globals) *cobra.Command {
	var labels []string
	cmd := &cobra.Command{
		Use:   "fork SANDBOX N",
		Short: "Clone a running sandbox into N copies (vm), each with a fresh identity",
		Long: "fork snapshots a running sandbox and starts N copies of it: same files and running\n" +
			"processes, but each with its own hostname, MAC and IP address, machine-id and random\n" +
			"state. The original keeps running. Prints one id per line.",
		Example: "  for id in $(qt fork 3f2a9c1b7e04 3); do qt exec $id -- ./try-fix.sh & done; wait",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 || n > 64 {
				return fmt.Errorf("the count must be 1-64, not %q", args[1])
			}
			lm, err := parseLabels(labels)
			if err != nil {
				return err
			}
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			resp, err := c.Fork(cmd.Context(), &qtdv1.ForkRequest{SandboxId: args[0], Count: uint32(n), Labels: lm})
			if err != nil {
				return friendly(err, g.socket)
			}
			for _, s := range resp.GetSandboxes() {
				fmt.Fprintln(cmd.OutOrStdout(), s.GetId())
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&labels, "label", nil, "label KEY=VALUE for every copy (repeatable)")
	return cmd
}

func parseLabels(labels []string) (map[string]string, error) {
	m := map[string]string{}
	for _, l := range labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--label %q must be KEY=VALUE", l)
		}
		m[k] = v
	}
	return m, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// writeEventsDiff prints what each sandbox did that the other did not.
func writeEventsDiff(cmd *cobra.Command, a, b string, ed *qtdv1.EventsDiff) {
	out := cmd.OutOrStdout()
	for _, part := range []struct {
		who   string
		facts []string
	}{{a, ed.GetOnlyInSandbox()}, {b, ed.GetOnlyInAgainst()}} {
		fmt.Fprintf(out, "\nOnly %s did (%d):\n", part.who, len(part.facts))
		for _, f := range part.facts {
			fmt.Fprintf(out, "  %s\n", displayName(f, nil))
		}
	}
	if ed.GetTruncated() {
		fmt.Fprintln(cmd.ErrOrStderr(), "qt: behaviour diff truncated")
	}
}
