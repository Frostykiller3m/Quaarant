package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// Exec implements backend.Backend: one vsock connection per process. Closing it (ctx
// cancelled) makes the agent kill the process group.
func (b *Backend) Exec(ctx context.Context, id string, e backend.ExecSpec) (backend.Process, error) {
	if len(e.Argv) == 0 {
		return nil, errors.New("firecracker: exec: empty argv")
	}
	bx, err := b.lookup(id)
	if err != nil {
		return nil, err
	}
	req := &agentproto.Exec{
		Argv: e.Argv, Env: mergeEnv(bx.meta.Env, e.Env), Cwd: e.Workdir,
		UID: bx.meta.UID, GID: bx.meta.GID, NProc: uint64(max(bx.meta.PIDs, 8)), TTY: e.TTY,
	}
	if req.Cwd == "" {
		req.Cwd = bx.meta.Workdir
	}
	if e.User != "" {
		if req.UID, req.GID, err = parseUser(e.User); err != nil {
			return nil, fmt.Errorf("firecracker: exec: %w", err)
		}
	}
	if e.TTY && e.Size != nil {
		req.Rows, req.Cols = e.Size.Rows, e.Size.Cols
	}
	conn, err := b.dial(ctx, bx)
	if err != nil {
		return nil, err
	}
	p := &process{conn: conn, w: agentproto.NewWriter(conn), done: make(chan struct{})}
	if err := p.w.JSON(agentproto.FrameRequest, agentproto.Request{Op: agentproto.OpExec, Exec: req}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("firecracker: exec: %w", err)
	}
	go p.read(e.Stdout, e.Stderr)
	go p.feed(e.Stdin)
	go func() {
		select {
		case <-p.done:
		case <-ctx.Done():
			_ = conn.Close() // the agent kills the process group
		}
	}()
	return p, nil
}

func mergeEnv(base, over []string) []string {
	idx := map[string]int{}
	var out []string
	for _, kv := range append(append([]string{}, base...), over...) {
		k := kv
		for i := range kv {
			if kv[i] == '=' {
				k = kv[:i]
				break
			}
		}
		if i, ok := idx[k]; ok {
			out[i] = kv
			continue
		}
		idx[k] = len(out)
		out = append(out, kv)
	}
	return out
}

type process struct {
	conn   net.Conn
	w      *agentproto.Writer
	done   chan struct{}
	once   sync.Once
	pid    int
	status backend.ExitStatus
	err    error
}

// read handles the agent's frames. Its output is the sandboxed program's output, and its
// control frames are guest claims: sizes are bounded and values clamped.
func (p *process) read(stdout, stderr io.Writer) {
	defer p.finish()
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	for {
		t, b, err := agentproto.ReadFrame(p.conn, agentproto.MaxFrame)
		if err != nil {
			p.err = fmt.Errorf("firecracker: exec stream ended without an exit status: %w", err)
			return
		}
		switch t {
		case agentproto.FrameStarted:
			var s agentproto.Started
			if agentproto.Decode(b, &s) == nil && s.PID > 0 && s.PID < 1<<22 {
				p.pid = s.PID
			}
		case agentproto.FrameStdout:
			_, _ = stdout.Write(b)
		case agentproto.FrameStderr:
			_, _ = stderr.Write(b)
		case agentproto.FrameExit:
			var x agentproto.Exit
			if err := agentproto.Decode(b, &x); err != nil {
				p.err = fmt.Errorf("firecracker: exec: %w", err)
				return
			}
			p.status = clampExit(x)
			return
		case agentproto.FrameError:
			var e agentproto.Error
			_ = agentproto.Decode(b, &e)
			p.err = fmt.Errorf("firecracker: exec: agent: %.512s", e.Message)
			return
		default:
			p.err = fmt.Errorf("firecracker: exec: unexpected frame %d from the agent", t)
			return
		}
	}
}

func clampExit(x agentproto.Exit) backend.ExitStatus {
	if x.Signal > 0 && x.Signal <= 64 {
		return backend.ExitStatus{Code: -1, Signal: x.Signal}
	}
	if x.Code < -1 || x.Code > 255 {
		return backend.ExitStatus{Code: -1}
	}
	return backend.ExitStatus{Code: x.Code}
}

func (p *process) feed(stdin io.Reader) {
	if stdin != nil {
		buf := make([]byte, 32<<10)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				if p.w.Frame(agentproto.FrameStdin, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				break
			}
		}
	}
	_ = p.w.Frame(agentproto.FrameCloseStdin, nil)
}

func (p *process) finish() {
	p.once.Do(func() {
		_ = p.conn.Close()
		close(p.done)
	})
}

// Wait implements backend.Process.
func (p *process) Wait(ctx context.Context) (backend.ExitStatus, error) {
	select {
	case <-p.done:
		return p.status, p.err
	case <-ctx.Done():
		return backend.ExitStatus{}, ctx.Err()
	}
}

// Signal implements backend.Process.
func (p *process) Signal(sig int) error {
	if sig < 1 || sig > 64 {
		return fmt.Errorf("invalid signal %d", sig)
	}
	return p.w.JSON(agentproto.FrameSignal, agentproto.Signal{Signal: sig})
}

// Resize implements backend.Process.
func (p *process) Resize(ws backend.WindowSize) error {
	return p.w.JSON(agentproto.FrameResize, agentproto.WindowSize{Rows: ws.Rows, Cols: ws.Cols})
}

// CopyIn implements backend.Backend: the agent extracts the tar (with the same safe
// unpacker qtd uses), owned by the sandbox user.
func (b *Backend) CopyIn(ctx context.Context, id, dir string, r io.Reader) error {
	bx, err := b.lookup(id)
	if err != nil {
		return err
	}
	conn, err := b.dial(ctx, bx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	w := agentproto.NewWriter(conn)
	if err := w.JSON(agentproto.FrameRequest, agentproto.Request{Op: agentproto.OpCopyIn, Path: dir, UID: bx.meta.UID, GID: bx.meta.GID}); err != nil {
		return fmt.Errorf("firecracker: copy in: %w", err)
	}
	if _, err := io.Copy(w.DataWriter(agentproto.FrameData), r); err != nil {
		return fmt.Errorf("firecracker: copy in: %w", err)
	}
	if err := w.Frame(agentproto.FrameEOF, nil); err != nil {
		return fmt.Errorf("firecracker: copy in: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	if _, err := readResult(conn); err != nil {
		return fmt.Errorf("firecracker: copy in: %w", err)
	}
	return nil
}

// CopyOut implements backend.Backend: the agent's tar, forwarded as is. It comes from the
// guest, so whoever unpacks it must do so safely (qt cp uses safetar).
func (b *Backend) CopyOut(ctx context.Context, id, path string, w io.Writer) error {
	bx, err := b.lookup(id)
	if err != nil {
		return err
	}
	conn, err := b.dial(ctx, bx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := agentproto.WriteJSON(conn, agentproto.FrameRequest, agentproto.Request{Op: agentproto.OpCopyOut, Path: path}); err != nil {
		return fmt.Errorf("firecracker: copy out: %w", err)
	}
	if _, err := io.Copy(w, agentproto.DataReader(conn)); err != nil {
		return fmt.Errorf("firecracker: copy out: %w", err)
	}
	return nil
}
