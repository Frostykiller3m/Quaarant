// Package gvisor is the gVisor (runsc) isolation backend.
//
// Each sandbox is a runsc container whose init is the static qt-agent in "pause" mode,
// bind-mounted read-only at /.qt/qt-agent; user commands run with `runsc exec`. The root
// filesystem is a host overlayfs: the cached image rootfs is the read-only lower layer and
// <workspace>/upper receives every write, so the host can inspect changes (M1-T2).
//
// runsc is invoked with --network=none (M3 adds netns attachment), --overlay2=none (writes go to
// the host overlay rather than gVisor's in-memory overlay), and --oci-seccomp so the OCI seccomp
// profile is enforced inside the sandbox. Limits are cgroup v2 under <CgroupParent>/qt-<id>.
package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// Config configures the backend.
type Config struct {
	Runsc        string   // runsc binary; default "runsc" from PATH
	StateDir     string   // runsc --root; default /run/quarantine/runsc
	AgentPath    string   // host path of the static qt-agent binary (sandbox init)
	CgroupParent string   // cgroup v2 parent path; default /quarantine
	Platform     string   // runsc --platform; empty = runsc default (systrap)
	ExtraFlags   []string // extra global runsc flags (debugging)
}

// Backend implements backend.Backend with runsc.
type Backend struct {
	cfg   Config
	mu    sync.Mutex
	boxes map[string]*box
	seq   atomic.Uint64
}

type box struct {
	id        string
	workspace string
	meta      boxMeta
}

// boxMeta is saved in the bundle so a restarted qtd can keep using a running sandbox.
type boxMeta struct {
	Env     []string   `json:"env"`
	Workdir string     `json:"workdir"`
	User    specs.User `json:"user"`
	PIDs    int        `json:"pids"`
	RootFS  string     `json:"rootfs"` // image rootfs: the overlay's lower layer
	Created time.Time  `json:"created"`
}

var _ backend.Backend = (*Backend)(nil)

// New returns a gVisor backend.
func New(cfg Config) (*Backend, error) {
	if cfg.Runsc == "" {
		cfg.Runsc = "runsc"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "/run/quarantine/runsc"
	}
	if cfg.CgroupParent == "" {
		cfg.CgroupParent = "/quarantine"
	}
	if cfg.AgentPath == "" {
		return nil, errors.New("gvisor: AgentPath (static qt-agent binary) is required")
	}
	if !filepath.IsAbs(cfg.AgentPath) || !filepath.IsAbs(cfg.StateDir) || !strings.HasPrefix(cfg.CgroupParent, "/") {
		return nil, errors.New("gvisor: AgentPath, StateDir and CgroupParent must be absolute")
	}
	return &Backend{cfg: cfg, boxes: map[string]*box{}}, nil
}

// Name implements backend.Backend.
func (*Backend) Name() backend.Isolation { return backend.IsolationGVisor }

// Capabilities implements backend.Backend. Disk snapshots, diff and syscall events arrive in
// later tasks and are declared when they work.
func (*Backend) Capabilities() backend.Capabilities { return backend.CapPTY }

func (b *Backend) globalArgs() []string {
	args := []string{"--root", b.cfg.StateDir, "--network=none", "--overlay2=none", "--file-access=shared", "--oci-seccomp"}
	if b.cfg.Platform != "" {
		args = append(args, "--platform="+b.cfg.Platform)
	}
	return append(args, b.cfg.ExtraFlags...)
}

func (b *Backend) cmd(args ...string) *exec.Cmd {
	//nolint:gosec // G204: the binary is from config; args are flags we build and validated ids.
	return exec.Command(b.cfg.Runsc, append(b.globalArgs(), args...)...)
}

// run runs a short runsc command and returns its stdout; stderr goes into the error.
func (b *Backend) run(ctx context.Context, args ...string) ([]byte, error) {
	c := b.cmd(args...)
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	c.WaitDelay = 5 * time.Second
	if err := runWithContext(ctx, c); err != nil {
		return stdout.Bytes(), fmt.Errorf("runsc %s: %w: %s", args[0], err, tail(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

func tail(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 2048 {
		b = b[len(b)-2048:]
	}
	return string(b)
}

func bundleDir(ws string) string { return filepath.Join(ws, "bundle") }
func rootfsDir(ws string) string { return filepath.Join(ws, "rootfs") }

// Create implements backend.Backend: overlay rootfs + bundle + `runsc create`.
func (b *Backend) Create(ctx context.Context, s backend.Spec) (err error) {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("gvisor: %w", err)
	}
	if !s.Network.None {
		return fmt.Errorf("gvisor: network attachment: %w (arrives in M3; use --net=none)", errors.ErrUnsupported)
	}
	for _, p := range []string{s.RootFS, s.Workspace} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, ",:\n") {
			return fmt.Errorf("gvisor: path %q must be absolute without ',' or ':'", p)
		}
	}
	defer func() {
		if err != nil {
			_ = b.Destroy(context.WithoutCancel(ctx), s.ID)
		}
	}()

	b.mu.Lock()
	if _, ok := b.boxes[s.ID]; ok {
		b.mu.Unlock()
		return fmt.Errorf("gvisor: sandbox %s already exists", s.ID)
	}
	bx := &box{id: s.ID, workspace: s.Workspace}
	b.boxes[s.ID] = bx
	b.mu.Unlock()

	for _, d := range []string{"upper", "work", "rootfs", "bundle", "exec"} {
		if err := os.MkdirAll(filepath.Join(s.Workspace, d), 0o700); err != nil {
			return fmt.Errorf("gvisor: workspace: %w", err)
		}
	}
	// The overlay's "/" takes its mode from upper/, so give upper/ the image root's mode;
	// otherwise the non-root sandbox user could not even traverse "/".
	lowerRoot, err := os.Stat(s.RootFS)
	if err != nil {
		return fmt.Errorf("gvisor: image rootfs: %w", err)
	}
	for _, d := range []string{rootfsDir(s.Workspace), filepath.Join(s.Workspace, "upper")} {
		if err := os.Chmod(d, lowerRoot.Mode().Perm()); err != nil {
			return fmt.Errorf("gvisor: workspace: %w", err)
		}
	}
	// Mountpoint for the init binary, created up front so it is 0755 root-owned (if runsc made
	// it, the non-root user could not traverse /.qt).
	if err := prepareQtDir(filepath.Join(s.Workspace, "upper")); err != nil {
		return fmt.Errorf("gvisor: workspace: %w", err)
	}
	if err := ensureCgroupParent(b.cfg.CgroupParent); err != nil {
		return fmt.Errorf("gvisor: cgroup parent: %w", err)
	}
	if err := mountOverlay(s.RootFS, filepath.Join(s.Workspace, "upper"), filepath.Join(s.Workspace, "work"), rootfsDir(s.Workspace)); err != nil {
		return fmt.Errorf("gvisor: %w", err)
	}

	if err := ensureTmp(rootfsDir(s.Workspace)); err != nil {
		return fmt.Errorf("gvisor: %w", err)
	}
	spec, err := buildSpec(s, rootfsDir(s.Workspace), b.cfg.AgentPath, b.cfg.CgroupParent)
	if err != nil {
		return fmt.Errorf("gvisor: %w", err)
	}
	user, err := parseUser(s.User)
	if err != nil {
		return fmt.Errorf("gvisor: %w", err)
	}
	bx.meta = boxMeta{Env: s.Env, Workdir: s.Workdir, User: user, PIDs: s.Limits.PIDs, RootFS: s.RootFS, Created: time.Now().UTC()}
	if err := writeJSON(filepath.Join(bundleDir(s.Workspace), "config.json"), spec); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(bundleDir(s.Workspace), "qt.json"), bx.meta); err != nil {
		return err
	}

	// The init's stdio is inherited by the sandbox for its whole life, so it must be a file,
	// not a pipe (a pipe would keep `runsc create` "running" forever from os/exec's view).
	logf, err := os.OpenFile(filepath.Join(s.Workspace, "init.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("gvisor: init log: %w", err)
	}
	defer func() { _ = logf.Close() }()
	c := b.cmd("create", "--bundle", bundleDir(s.Workspace), containerID(s.ID))
	c.Stdout, c.Stderr = logf, logf
	if err := runWithContext(ctx, c); err != nil {
		log, _ := os.ReadFile(filepath.Join(s.Workspace, "init.log"))
		return fmt.Errorf("gvisor: runsc create: %w: %s", err, tail(log))
	}
	return nil
}

func prepareQtDir(upper string) error {
	dir := filepath.Join(upper, filepath.FromSlash(qtDir))
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) { //nolint:gosec // G301: the sandbox user must traverse /.qt
		return fmt.Errorf("create %s: %w", qtDir, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the sandbox user must traverse /.qt
		return fmt.Errorf("chmod %s: %w", qtDir, err)
	}
	f, err := os.OpenFile(filepath.Join(upper, filepath.FromSlash(agentPath)), os.O_CREATE|os.O_WRONLY, 0o755) //nolint:gosec // G302,G304: empty mountpoint under our workspace
	if err != nil {
		return fmt.Errorf("create %s: %w", agentPath, err)
	}
	return f.Close()
}

// ensureTmp makes sure the image has a /tmp directory (bind-mounted as /tmp), creating a
// world-writable sticky one if the image lacks it. An image whose /tmp is not a plain directory
// (e.g. a symlink) is refused rather than followed.
func ensureTmp(rootfs string) error {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return fmt.Errorf("open rootfs: %w", err)
	}
	defer func() { _ = root.Close() }()
	fi, err := root.Lstat("tmp")
	switch {
	case err == nil && fi.IsDir():
		return nil
	case err == nil:
		return fmt.Errorf("image /tmp is not a directory (%v)", fi.Mode().Type())
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("stat /tmp: %w", err)
	}
	if err := root.Mkdir("tmp", 0o777); err != nil {
		return fmt.Errorf("create /tmp: %w", err)
	}
	if err := root.Chmod("tmp", 0o777|os.ModeSticky); err != nil {
		return fmt.Errorf("chmod /tmp: %w", err)
	}
	return nil
}

func runWithContext(ctx context.Context, c *exec.Cmd) error {
	if err := c.Start(); err != nil {
		return fmt.Errorf("start runsc: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = c.Process.Kill()
		return errors.Join(ctx.Err(), <-done)
	}
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// Start implements backend.Backend.
func (b *Backend) Start(ctx context.Context, id string) error {
	if _, err := b.lookup(ctx, id); err != nil {
		return err
	}
	if _, err := b.run(ctx, "start", containerID(id)); err != nil {
		return fmt.Errorf("gvisor: %w", err)
	}
	return nil
}

type runscState struct {
	ID      string    `json:"id"`
	Status  string    `json:"status"`
	Bundle  string    `json:"bundle"`
	Created time.Time `json:"created"`
}

func (b *Backend) state(ctx context.Context, id string) (runscState, error) {
	out, err := b.run(ctx, "state", containerID(id))
	if err != nil {
		return runscState{}, err
	}
	var st runscState
	if err := json.Unmarshal(out, &st); err != nil {
		return runscState{}, fmt.Errorf("parse runsc state: %w", err)
	}
	return st, nil
}

// errNotFound is returned for ids this backend does not know.
var errNotFound = errors.New("no such sandbox")

// lookup finds a sandbox, recovering it from runsc state after a qtd restart.
func (b *Backend) lookup(ctx context.Context, id string) (*box, error) {
	b.mu.Lock()
	bx, ok := b.boxes[id]
	b.mu.Unlock()
	if ok {
		return bx, nil
	}
	st, err := b.state(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("gvisor: sandbox %s: %w", id, errNotFound)
	}
	ws := filepath.Dir(st.Bundle)
	raw, err := os.ReadFile(filepath.Join(st.Bundle, "qt.json"))
	if err != nil {
		return nil, fmt.Errorf("gvisor: recover sandbox %s: %w", id, err)
	}
	bx = &box{id: id, workspace: ws}
	if err := json.Unmarshal(raw, &bx.meta); err != nil {
		return nil, fmt.Errorf("gvisor: recover sandbox %s: %w", id, err)
	}
	b.mu.Lock()
	b.boxes[id] = bx
	b.mu.Unlock()
	return bx, nil
}

// Exec implements backend.Backend via `runsc exec --process <json>`.
func (b *Backend) Exec(ctx context.Context, id string, e backend.ExecSpec) (backend.Process, error) {
	if e.TTY && !b.Capabilities().Has(backend.CapPTY) {
		return nil, backend.Require(b, backend.CapPTY)
	}
	bx, err := b.lookup(ctx, id)
	if err != nil {
		return nil, err
	}
	base := &specs.Process{User: bx.meta.User, Rlimits: rlimits(bx.meta.PIDs)}
	proc, err := execProcess(base, bx.meta.Env, bx.meta.Workdir, e)
	if err != nil {
		return nil, fmt.Errorf("gvisor: %w", err)
	}
	n := b.seq.Add(1)
	stem := filepath.Join(bx.workspace, "exec", strconv.FormatUint(n, 10))
	if err := writeJSON(stem+".json", proc); err != nil {
		return nil, err
	}
	c := b.cmd("exec", "--process", stem+".json", "--internal-pid-file", stem+".pid", containerID(id))
	p := &process{b: b, id: id, files: []string{stem + ".json", stem + ".pid"}, pidFile: stem + ".pid", cmd: c, done: make(chan struct{})}
	if e.TTY {
		err = p.startTTY(e)
	} else {
		err = p.startPipes(e)
	}
	if err != nil {
		p.cleanup()
		return nil, fmt.Errorf("gvisor: exec: %w", err)
	}
	go p.watch(ctx)
	return p, nil
}

type process struct {
	b       *Backend
	id      string
	cmd     *exec.Cmd
	pidFile string
	files   []string
	tty     *os.File // pty master, nil without a TTY
	ioDone  chan struct{}
	done    chan struct{}
	status  backend.ExitStatus
	waitErr error
	once    sync.Once
}

func (p *process) startPipes(e backend.ExecSpec) error {
	p.cmd.Stdout = orDiscard(e.Stdout)
	p.cmd.Stderr = orDiscard(e.Stderr)
	p.cmd.WaitDelay = 2 * time.Second // background children holding stdout can't hang Wait
	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("start runsc exec: %w", err)
	}
	go func() {
		if e.Stdin != nil {
			_, _ = io.Copy(stdin, e.Stdin)
		}
		_ = stdin.Close()
	}()
	go p.reap()
	return nil
}

func (p *process) startTTY(e backend.ExecSpec) error {
	master, slave, err := openPTY()
	if err != nil {
		return err
	}
	if e.Size != nil {
		_ = setWinsize(master, *e.Size)
	}
	p.tty = master
	p.cmd.Stdin, p.cmd.Stdout, p.cmd.Stderr = slave, slave, slave
	p.cmd.SysProcAttr = ttyProcAttr()
	err = p.cmd.Start()
	_ = slave.Close() // only the child keeps the slave open
	if err != nil {
		_ = master.Close()
		return fmt.Errorf("start runsc exec: %w", err)
	}
	p.ioDone = make(chan struct{})
	go func() {
		defer close(p.ioDone)
		_, _ = io.Copy(orDiscard(e.Stdout), master) // ends with EIO once every slave fd is closed
	}()
	if e.Stdin != nil {
		go func() { _, _ = io.Copy(master, e.Stdin) }()
	}
	go p.reap()
	return nil
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

func (p *process) reap() {
	err := p.cmd.Wait()
	if p.tty != nil {
		select {
		case <-p.ioDone:
		case <-time.After(2 * time.Second):
		}
		_ = p.tty.Close()
	}
	p.status, p.waitErr = exitStatus(err)
	p.cleanup()
	close(p.done)
}

// exitStatus maps runsc exec's own exit to the sandboxed process's status. runsc exits with
// the process's code, or 128+signal when it was killed by a signal.
func exitStatus(err error) (backend.ExitStatus, error) {
	if err == nil {
		return backend.ExitStatus{}, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			// runsc exec itself was killed: we no longer know how the process ended.
			return backend.ExitStatus{Code: -1, Signal: int(ws.Signal())}, nil
		}
		code := ee.ExitCode()
		if code > 128 && code < 128+65 {
			return backend.ExitStatus{Code: -1, Signal: code - 128}, nil
		}
		return backend.ExitStatus{Code: code}, nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return backend.ExitStatus{Code: 0}, nil
	}
	return backend.ExitStatus{Code: -1}, fmt.Errorf("wait for runsc exec: %w", err)
}

func (p *process) cleanup() {
	p.once.Do(func() {
		for _, f := range p.files {
			_ = os.Remove(f)
		}
	})
}

// watch kills the sandboxed process if ctx ends first.
func (p *process) watch(ctx context.Context) {
	select {
	case <-p.done:
	case <-ctx.Done():
		_ = p.Signal(int(syscall.SIGKILL))
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			_ = p.cmd.Process.Kill()
		}
	}
}

// Wait implements backend.Process.
func (p *process) Wait(ctx context.Context) (backend.ExitStatus, error) {
	select {
	case <-p.done:
		return p.status, p.waitErr
	case <-ctx.Done():
		return backend.ExitStatus{}, ctx.Err()
	}
}

// Signal implements backend.Process, signalling the process inside the sandbox by its pid.
func (p *process) Signal(sig int) error {
	if sig < 1 || sig > 64 {
		return fmt.Errorf("invalid signal %d", sig)
	}
	var pid []byte
	for range 50 { // the pid file appears just after runsc exec starts the process
		pid, _ = os.ReadFile(p.pidFile)
		if len(bytes.TrimSpace(pid)) > 0 {
			break
		}
		select {
		case <-p.done:
			return nil
		case <-time.After(20 * time.Millisecond):
		}
	}
	n, err := strconv.Atoi(string(bytes.TrimSpace(pid)))
	if err != nil {
		return fmt.Errorf("signal: process pid unknown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = p.b.run(ctx, "kill", "--pid", strconv.Itoa(n), containerID(p.id), strconv.Itoa(sig))
	return err
}

// Resize implements backend.Process.
func (p *process) Resize(ws backend.WindowSize) error {
	if p.tty == nil {
		return nil
	}
	return setWinsize(p.tty, ws)
}

// Info implements backend.Backend.
func (b *Backend) Info(ctx context.Context, id string) (backend.Info, error) {
	st, err := b.state(ctx, id)
	if err != nil {
		return backend.Info{}, fmt.Errorf("gvisor: sandbox %s: %w", id, errNotFound)
	}
	state := backend.StateStopped
	switch st.Status {
	case "created":
		state = backend.StateCreated
	case "running":
		state = backend.StateRunning
	case "paused":
		state = backend.StatePaused
	}
	return backend.Info{ID: id, Isolation: backend.IsolationGVisor, State: state, CreatedAt: st.Created}, nil
}

// Destroy implements backend.Backend. It is idempotent: it kills and deletes the runsc
// container, unmounts the overlay, and removes the cgroup if runsc left it.
func (b *Backend) Destroy(ctx context.Context, id string) error {
	var errs []error
	ws := ""
	b.mu.Lock()
	if bx, ok := b.boxes[id]; ok {
		ws = bx.workspace
	}
	b.mu.Unlock()
	if st, err := b.state(ctx, id); err == nil {
		if ws == "" {
			ws = filepath.Dir(st.Bundle)
		}
		if _, err := b.run(ctx, "delete", "--force", containerID(id)); err != nil {
			errs = append(errs, err)
		}
	}
	if ws != "" {
		if err := unmount(rootfsDir(ws)); err != nil {
			errs = append(errs, err)
		}
	}
	if err := removeCgroup(cgroupsPath(b.cfg.CgroupParent, id)); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		b.mu.Lock()
		delete(b.boxes, id)
		b.mu.Unlock()
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("gvisor: destroy %s: %w", id, err)
	}
	return nil
}

// Snapshot implements backend.Backend.
func (b *Backend) Snapshot(context.Context, string, backend.SnapshotOptions) (backend.SnapshotRef, error) {
	return backend.SnapshotRef{}, backend.Require(b, backend.CapDiskSnapshot)
}

// Restore implements backend.Backend.
func (b *Backend) Restore(context.Context, backend.SnapshotRef, backend.Spec) error {
	return backend.Require(b, backend.CapDiskSnapshot)
}

// Fork implements backend.Backend.
func (b *Backend) Fork(context.Context, string, []backend.Spec) error {
	return backend.Require(b, backend.CapFork)
}
