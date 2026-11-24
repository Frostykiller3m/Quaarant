//go:build !windows

package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
)

// forwardSignals relays terminal resizes (tty) or SIGINT/SIGTERM/SIGHUP (no tty: in raw mode
// Ctrl-C is just a byte for the remote terminal) to the sandboxed process.
func forwardSignals(ctx context.Context, xio execIO, send func(*qtdv1.ExecRequest) error) (stop func()) {
	sigs := make(chan os.Signal, 4)
	if xio.tty {
		signal.Notify(sigs, syscall.SIGWINCH)
	} else {
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case s := <-sigs:
				if s == syscall.SIGWINCH {
					f, ok := xio.stdin.(*os.File)
					if !ok {
						continue
					}
					if w, h, err := term.GetSize(int(f.Fd())); err == nil {
						_ = send(&qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_Resize{Resize: &qtdv1.WindowSize{Rows: uint32(h), Cols: uint32(w)}}}) //nolint:gosec // G115: small
					}
					continue
				}
				if n, ok := s.(syscall.Signal); ok {
					_ = send(&qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_Signal{Signal: int32(n)}}) //nolint:gosec // G115: signal numbers are < 65
				}
			}
		}
	}()
	return func() { signal.Stop(sigs); close(done) }
}
