package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
)

// DefaultSocket is where qtd listens; QT_SOCKET or --socket override it.
const DefaultSocket = "/run/quarantine/qtd.sock"

// globals are flags shared by every command that talks to qtd.
type globals struct {
	socket string
	// dial is replaced in tests.
	dial func(socket string) (qtdv1.SandboxServiceClient, io.Closer, error)
}

func defaultSocket() string {
	if s := os.Getenv("QT_SOCKET"); s != "" {
		return s
	}
	return DefaultSocket
}

func dialSocket(socket string) (qtdv1.SandboxServiceClient, io.Closer, error) {
	conn, err := grpc.NewClient("unix://"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()), // local unix socket; qtd checks SO_PEERCRED
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to qtd: %w", err)
	}
	return qtdv1.NewSandboxServiceClient(conn), conn, nil
}

func (g *globals) client() (qtdv1.SandboxServiceClient, io.Closer, error) {
	return g.dial(g.socket)
}

// exitCodeError makes qt exit with a sandboxed process's exit code without printing anything.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return "exit status " + strconv.Itoa(e.code) }

// friendly rewrites gRPC errors into something a user can act on.
func friendly(err error, socket string) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.Unavailable:
		return fmt.Errorf("cannot reach qtd at %s: %s\n(is it running? `sudo systemctl start qtd`; are you root or in the quarantine group?)", socket, st.Message())
	case codes.NotFound, codes.InvalidArgument, codes.FailedPrecondition, codes.Unimplemented, codes.Internal:
		return errors.New(st.Message())
	}
	return err
}

// execIO is the local side of an exec.
type execIO struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	interactive    bool // forward stdin
	tty            bool
}

// streamExec runs start over the Exec stream and returns the process exit code (128+signal
// when it was killed by a signal, like a shell).
func streamExec(ctx context.Context, c qtdv1.SandboxServiceClient, start *qtdv1.ExecRequest_Start, xio execIO) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var restore func()
	if xio.tty {
		if f, ok := xio.stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			if w, h, err := term.GetSize(int(f.Fd())); err == nil {
				start.Size = &qtdv1.WindowSize{Rows: uint32(h), Cols: uint32(w)} //nolint:gosec // G115: terminal sizes are small
			}
			if st, err := term.MakeRaw(int(f.Fd())); err == nil {
				restore = func() { _ = term.Restore(int(f.Fd()), st) }
				defer restore()
			}
		}
	}
	stream, err := c.Exec(ctx)
	if err != nil {
		return 0, err
	}
	var sendMu sync.Mutex
	send := func(m *qtdv1.ExecRequest) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}
	if err := send(&qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_Start_{Start: start}}); err != nil {
		return 0, err
	}

	if xio.interactive && xio.stdin != nil {
		go func() {
			buf := make([]byte, 32<<10)
			for {
				n, err := xio.stdin.Read(buf)
				if n > 0 {
					if send(&qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_Stdin{Stdin: append([]byte(nil), buf[:n]...)}}) != nil {
						return
					}
				}
				if err != nil {
					_ = send(&qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_CloseStdin{CloseStdin: true}})
					return
				}
			}
		}()
	} else {
		if err := send(&qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_CloseStdin{CloseStdin: true}}); err != nil {
			return 0, err
		}
	}
	stopSignals := forwardSignals(ctx, xio, send)
	defer stopSignals()

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, errors.New("exec stream ended without an exit status")
			}
			return 0, err
		}
		switch m := msg.GetMsg().(type) {
		case *qtdv1.ExecResponse_Stdout:
			if _, err := xio.stdout.Write(m.Stdout); err != nil {
				return 0, fmt.Errorf("write stdout: %w", err)
			}
		case *qtdv1.ExecResponse_Stderr:
			if _, err := xio.stderr.Write(m.Stderr); err != nil {
				return 0, fmt.Errorf("write stderr: %w", err)
			}
		case *qtdv1.ExecResponse_Exit_:
			if m.Exit.GetSignal() != 0 {
				return 128 + int(m.Exit.GetSignal()), nil
			}
			return int(m.Exit.GetCode()), nil
		}
	}
}

// splitCommand separates "IMAGE|ID [--] CMD..." positional args.
func splitCommand(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	rest := args[1:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	return args[0], rest
}

func parseEnvFlags(env []string) ([]string, error) {
	out := make([]string, 0, len(env))
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			v, set := os.LookupEnv(e) // -e NAME passes the local value, like docker
			if !set {
				continue
			}
			e = k + "=" + v
		}
		out = append(out, e)
	}
	return out, nil
}

func addExecFlags(cmd *cobra.Command, interactive, tty *bool, env *[]string, workdir *string) {
	cmd.Flags().BoolVarP(interactive, "interactive", "i", false, "forward stdin")
	cmd.Flags().BoolVarP(tty, "tty", "t", false, "allocate a terminal")
	cmd.Flags().StringArrayVarP(env, "env", "e", nil, "set environment variables (KEY=VALUE, or KEY to pass the local value)")
	cmd.Flags().StringVarP(workdir, "workdir", "w", "", "working directory inside the sandbox")
	cmd.Flags().SetInterspersed(false) // everything after IMAGE/ID belongs to the command
}
