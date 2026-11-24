package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/events"
)

func newEventsCommand(g *globals) *cobra.Command {
	var (
		follow, asJSON bool
		kinds          []string
		after          string
	)
	cmd := &cobra.Command{
		Use:   "events SANDBOX",
		Short: "Show what a sandbox did: exec, file, net, dns, policy and honeytoken events",
		Long: "events prints the sandbox's event log (events.jsonl), one event per line. With --follow it\n" +
			"keeps printing new events until the sandbox is removed or you press Ctrl-C. --json prints\n" +
			"the raw schema v1 events. Paths, arguments and addresses come from sandboxed code and\n" +
			"are quoted when they hold control characters.",
		Example: "  qt events 3f2a9c1b7e04\n  qt events -f --kind exec,net 3f2a9c1b7e04\n  qt events --json 3f2a9c1b7e04 | jq .",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			stream, err := c.Events(ctx, &qtdv1.EventsRequest{SandboxId: args[0], Follow: follow, Kinds: kinds, AfterEventId: after})
			if err != nil {
				return friendly(err, g.socket)
			}
			out := cmd.OutOrStdout()
			for {
				m, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					return nil
				}
				if err != nil {
					if status.Code(err) == codes.Canceled || ctx.Err() != nil {
						return nil // Ctrl-C while following
					}
					return friendly(err, g.socket)
				}
				if asJSON {
					fmt.Fprintln(out, string(m.GetEventJson()))
					continue
				}
				fmt.Fprintln(out, formatEvent(m.GetEventJson()))
			}
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&follow, "follow", "f", false, "keep printing new events")
	f.StringSliceVar(&kinds, "kind", nil, "only these kinds (exec,file,net,dns,policy_denied,honeytoken)")
	f.BoolVar(&asJSON, "json", false, "print raw JSON events")
	f.StringVar(&after, "after", "", "start after this event id")
	return cmd
}

// formatEvent renders one event for a terminal. Untrusted strings go through quote().
func formatEvent(raw []byte) string {
	var ev events.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return quote(string(raw))
	}
	p, err := ev.Payload()
	if err != nil {
		return quote(string(raw))
	}
	ts := ev.TS.Local().Format("15:04:05.000")
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %-5s ", ts, ev.Kind)
	switch v := p.(type) {
	case *events.Exec:
		fmt.Fprintf(&b, "pid=%d ppid=%d", v.PID, v.PPID)
		if v.UID != nil {
			fmt.Fprintf(&b, " uid=%d", *v.UID)
		}
		fmt.Fprintf(&b, "  %s ", quote(v.Path))
		args := make([]string, len(v.Argv))
		for i, a := range v.Argv {
			args[i] = shellQuote(a)
		}
		b.WriteString(strings.Join(args, " "))
		if v.ArgvTruncated {
			b.WriteString(" [truncated]")
		}
	case *events.File:
		fmt.Fprintf(&b, "%-7s %s", v.Op, quote(v.Path))
		if v.NewPath != "" {
			b.WriteString(" -> " + quote(v.NewPath))
		}
		if v.PID != 0 {
			fmt.Fprintf(&b, "  pid=%d", v.PID)
		}
		if len(v.Flags) > 0 {
			b.WriteString("  " + strings.Join(v.Flags, "|"))
		}
		if v.Mode != "" {
			b.WriteString("  mode=" + v.Mode)
		}
		if v.Bytes != nil {
			b.WriteString("  " + humanBytes(uint64(max(*v.Bytes, 0))))
		}
		if v.Errno != "" {
			b.WriteString("  " + v.Errno)
		}
	case *events.Net:
		fmt.Fprintf(&b, "%-7s %s %s", v.Op, v.Proto, joinHostPort(v.DstIP, v.DstPort))
		if v.SNI != "" {
			b.WriteString("  sni=" + quote(v.SNI))
		}
		if v.Allowed != nil && !*v.Allowed {
			b.WriteString("  blocked")
		}
		if v.Errno != "" {
			b.WriteString("  " + v.Errno)
		}
	default:
		data, _ := json.Marshal(p)
		b.WriteString(quote(string(data)))
	}
	if ev.Source == events.SourceGuest {
		b.WriteString("  (guest claim)")
	}
	return b.String()
}

func joinHostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + quote(ip) + "]:" + strconv.Itoa(port)
	}
	return quote(ip) + ":" + strconv.Itoa(port)
}

// quote leaves printable text alone and Go-quotes anything with control characters or
// invalid UTF-8, so terminal escape sequences from sandboxed code are never interpreted.
func quote(s string) string { return displayName(s, nil) }

// shellQuote additionally quotes arguments with spaces or quotes, so argv reads unambiguously.
func shellQuote(s string) string {
	if s == "" {
		return `""`
	}
	if !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsPrint(r) || unicode.IsSpace(r) || strings.ContainsRune(`"'\$`+"`", r)
	}) >= 0 {
		return strconv.Quote(s)
	}
	return s
}
