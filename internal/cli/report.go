package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/report"
)

func newReportCommand(g *globals) *cobra.Command {
	var (
		asJSON, offline bool
		model           string
	)
	cmd := &cobra.Command{
		Use:   "report SANDBOX",
		Short: "Judge what a sandbox did: a verdict (clean, suspicious, malicious) with evidence",
		Long: "report reads the sandbox's event log and prints a verdict and findings. Each finding cites\n" +
			"the event ids that show it (see them with qt events --json). Rule-based checks always run.\n" +
			"With ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN) set, Claude also reads a compacted log\n" +
			"and adds findings; any that cite events that don't exist, or don't fit, are dropped.\n" +
			"The log is sent to the Claude API; use --offline to keep it local (rules only).",
		Example: "  qt report 3f2a9c1b7e04\n  qt report --offline 3f2a9c1b7e04\n  qt report --json 3f2a9c1b7e04 | jq .verdict",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			stream, err := c.Events(ctx, &qtdv1.EventsRequest{SandboxId: args[0]})
			if err != nil {
				return friendly(err, g.socket)
			}
			var evs []events.Event
			for {
				m, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return friendly(err, g.socket)
				}
				ev, err := events.Validate(m.GetEventJson()) // qtd validated it; so do we
				if err != nil {
					return fmt.Errorf("invalid event from qtd: %w", err)
				}
				evs = append(evs, ev)
			}
			var an report.Analyzer
			if !offline && (os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != "") {
				an = report.NewClaude(model)
			}
			r := report.Build(ctx, args[0], evs, an)
			if an == nil && !offline {
				r.Note = "No ANTHROPIC_API_KEY: rules only."
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(r)
			}
			r.WriteText(out)
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&asJSON, "json", false, "print the report as JSON")
	f.BoolVar(&offline, "offline", false, "rules only: do not send the log to the Claude API")
	f.StringVar(&model, "model", report.DefaultModel, "Claude model")
	return cmd
}
