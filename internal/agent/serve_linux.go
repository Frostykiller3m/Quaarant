//go:build linux

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
	"github.com/Frostykiller3m/Quaarant/internal/safetar"
	"github.com/Frostykiller3m/Quaarant/internal/version"
)

// copyLimits bound one copy_in (the guest disk bounds it anyway).
var copyLimits = safetar.UnpackLimits{MaxBytes: 8 << 30, MaxEntries: 1_000_000}

// Serve listens on vsock and handles qtd's requests, one connection per operation.
func Serve() int {
	l, err := listenVsock(agentproto.Port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "qt-agent serve:", err)
		return 1
	}
	for {
		conn, err := l.accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "qt-agent serve:", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handle(conn)
	}
}

func handle(conn *os.File) {
	defer func() { _ = conn.Close() }()
	w := agentproto.NewWriter(conn)
	t, payload, err := agentproto.ReadFrame(conn, agentproto.MaxFrame)
	if err != nil || t != agentproto.FrameRequest {
		return
	}
	var req agentproto.Request
	if err := agentproto.Decode(payload, &req); err != nil {
		_ = w.JSON(agentproto.FrameError, agentproto.Error{Message: err.Error()})
		return
	}
	switch req.Op {
	case agentproto.OpPing:
		_ = w.JSON(agentproto.FrameResult, agentproto.Result{Version: version.Get().Version, Kernel: kernelRelease()})
	case agentproto.OpExec:
		if req.Exec == nil {
			_ = w.JSON(agentproto.FrameError, agentproto.Error{Message: "exec: no spec"})
			return
		}
		if err := runExec(conn, w, req.Exec); err != nil {
			_ = w.JSON(agentproto.FrameError, agentproto.Error{Message: err.Error()})
		}
	case agentproto.OpCopyIn:
		res, err := copyIn(conn, req)
		if err != nil {
			_ = w.JSON(agentproto.FrameError, agentproto.Error{Message: err.Error()})
			return
		}
		_ = w.JSON(agentproto.FrameResult, res)
	case agentproto.OpConfigure:
		if err := configure(req.Configure); err != nil {
			_ = w.JSON(agentproto.FrameError, agentproto.Error{Message: err.Error()})
			return
		}
		_ = w.JSON(agentproto.FrameResult, agentproto.Result{Version: version.Get().Version, Kernel: kernelRelease()})
	case agentproto.OpCopyOut:
		if err := copyOut(w, req.Path); err != nil {
			_ = w.JSON(agentproto.FrameError, agentproto.Error{Message: err.Error()})
			return
		}
		_ = w.Frame(agentproto.FrameEOF, nil)
	default:
		_ = w.JSON(agentproto.FrameError, agentproto.Error{Message: "unknown op " + req.Op})
	}
}

// runExec starts the process through "qt-agent spawn" (which drops privileges) and streams
// its stdio until it exits. If qtd goes away, the process group is killed.
func runExec(conn *os.File, w *agentproto.Writer, e *agentproto.Exec) error {
	if len(e.Argv) == 0 {
		return errors.New("exec: empty argv")
	}
	specR, specW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	cmd := exec.Command(AgentPath, "spawn")
	cmd.ExtraFiles = []*os.File{specR} // fd 3
	cmd.Env = []string{}

	var tty *os.File
	var stdin io.WriteCloser
	if e.TTY {
		master, slave, err := openPTY()
		if err != nil {
			_ = specR.Close()
			_ = specW.Close()
			return fmt.Errorf("exec: %w", err)
		}
		tty = master
		_ = setWinsize(master, e.Rows, e.Cols)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		defer func() { _ = slave.Close() }()
		stdin = master
	} else {
		cmd.Stdout = w.DataWriter(agentproto.FrameStdout)
		cmd.Stderr = w.DataWriter(agentproto.FrameStderr)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.WaitDelay = 2 * time.Second // background children holding stdout can't hang us
		if stdin, err = cmd.StdinPipe(); err != nil {
			return fmt.Errorf("exec: %w", err)
		}
	}
	if err := cmd.Start(); err != nil {
		_ = specR.Close()
		_ = specW.Close()
		if tty != nil {
			_ = tty.Close()
		}
		return fmt.Errorf("exec: %w", err)
	}
	_ = specR.Close()
	go func() {
		_ = json.NewEncoder(specW).Encode(e)
		_ = specW.Close()
	}()
	pid := cmd.Process.Pid
	_ = w.JSON(agentproto.FrameStarted, agentproto.Started{PID: pid})

	ioDone := make(chan struct{})
	if tty != nil {
		go func() {
			defer close(ioDone)
			_, _ = io.Copy(w.DataWriter(agentproto.FrameStdout), tty)
		}()
	} else {
		close(ioDone)
	}
	exited := make(chan struct{})
	go func() { // qtd -> process
		for {
			t, b, err := agentproto.ReadFrame(conn, agentproto.MaxFrame)
			if err != nil {
				select {
				case <-exited:
				default: // qtd went away: kill the process group, as runsc exec would
					_ = syscall.Kill(-pid, syscall.SIGKILL)
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
				return
			}
			switch t {
			case agentproto.FrameStdin:
				_, _ = stdin.Write(b)
			case agentproto.FrameCloseStdin:
				if tty == nil {
					_ = stdin.Close()
				}
			case agentproto.FrameResize:
				var ws agentproto.WindowSize
				if tty != nil && agentproto.Decode(b, &ws) == nil {
					_ = setWinsize(tty, ws.Rows, ws.Cols)
				}
			case agentproto.FrameSignal:
				var s agentproto.Signal
				if agentproto.Decode(b, &s) == nil && s.Signal >= 1 && s.Signal <= 64 {
					_ = syscall.Kill(pid, syscall.Signal(s.Signal))
				}
			}
		}
	}()
	err = cmd.Wait()
	close(exited)
	if tty != nil {
		select {
		case <-ioDone:
		case <-time.After(2 * time.Second):
		}
		_ = tty.Close()
	}
	return w.JSON(agentproto.FrameExit, exitOf(cmd, err))
}

func exitOf(cmd *exec.Cmd, err error) agentproto.Exit {
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && cmd.ProcessState != nil {
		if ws.Signaled() {
			return agentproto.Exit{Code: -1, Signal: int(ws.Signal())}
		}
		return agentproto.Exit{Code: ws.ExitStatus()}
	}
	if err != nil {
		return agentproto.Exit{Code: -1}
	}
	return agentproto.Exit{}
}

// copyIn extracts a tar from qtd into req.Path, owned by req.UID:GID.
func copyIn(conn io.Reader, req agentproto.Request) (agentproto.Result, error) {
	dir := path.Clean(req.Path)
	if !path.IsAbs(dir) {
		return agentproto.Result{}, errors.New("copy_in: path must be absolute")
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: a normal directory in the guest, owned by the sandbox user
			return agentproto.Result{}, fmt.Errorf("copy_in: %w", err)
		}
		_ = os.Lchown(dir, int(req.UID), int(req.GID))
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return agentproto.Result{}, fmt.Errorf("copy_in: %w", err)
	}
	defer func() { _ = root.Close() }()
	st, err := safetar.UnpackInto(agentproto.DataReader(conn), root, copyLimits, safetar.OwnedBy(int(req.UID), int(req.GID)))
	if err != nil {
		return agentproto.Result{}, fmt.Errorf("copy_in: %w", err)
	}
	return agentproto.Result{Bytes: st.Bytes, Files: st.Files + st.Dirs + st.Symlinks + st.Hardlinks}, nil
}

// copyOut archives p (relative to the guest's root) as Data frames.
func copyOut(w *agentproto.Writer, p string) error {
	p = path.Clean(p)
	if !path.IsAbs(p) {
		return errors.New("copy_out: path must be absolute")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return fmt.Errorf("copy_out: %w", err)
	}
	defer func() { _ = root.Close() }()
	rel := strings.TrimPrefix(p, "/")
	if rel == "" {
		rel = "."
	}
	if _, err := safetar.WriteTar(root, rel, w.DataWriter(agentproto.FrameData), safetar.DefaultTarLimits); err != nil {
		return fmt.Errorf("copy_out: %w", err)
	}
	return nil
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// configure makes a VM restored from a shared snapshot this sandbox's own.
func configure(c *agentproto.Configure) error {
	if c == nil || !hostnameRe.MatchString(c.Hostname) {
		return errors.New("configure: bad request")
	}
	if err := syscall.Sethostname([]byte(c.Hostname)); err != nil {
		return fmt.Errorf("configure: hostname: %w", err)
	}
	if c.UnixNano > 0 {
		tv := syscall.NsecToTimeval(c.UnixNano)
		if err := syscall.Settimeofday(&tv); err != nil {
			return fmt.Errorf("configure: clock: %w", err)
		}
	}
	if len(c.Entropy) > 0 {
		f, err := os.OpenFile("/dev/urandom", os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("configure: entropy: %w", err)
		}
		_, werr := f.Write(c.Entropy[:min(len(c.Entropy), 4096)])
		_ = f.Close()
		if werr != nil {
			return fmt.Errorf("configure: entropy: %w", werr)
		}
	}
	return nil
}
