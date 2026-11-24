// Package daemon is qtd: it owns the sandbox registry and the data dir, serves the qtd gRPC
// API on a unix socket (peer-credential checked), and drives isolation backends.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/image"
)

// ImagePuller resolves and unpacks images (image.Store in production).
type ImagePuller interface {
	Pull(ctx context.Context, ref string) (image.Image, error)
}

// ext4Builder is implemented by image stores that can make an ext4 disk image (vm isolation).
type ext4Builder interface {
	Ext4(ctx context.Context, img image.Image) (string, error)
}

// Options configures the service.
type Options struct {
	DataDir  string // e.g. /var/lib/quarantine
	Backends []backend.Backend
	Images   ImagePuller
	// DefaultUser runs sandboxes whose image has no non-root user ("uid:gid", never 0).
	DefaultUser string
	Logger      *slog.Logger
}

// DefaultSandboxUser is nobody:nogroup, present in nearly every image's /etc/passwd.
const DefaultSandboxUser = "65534:65534"

// Service implements qtdv1.SandboxServiceServer.
type Service struct {
	qtdv1.UnimplementedSandboxServiceServer

	opts     Options
	reg      *registry
	backends map[backend.Isolation]backend.Backend
	log      *slog.Logger
	locks    sync.Map // sandbox id -> *sync.Mutex (create/destroy are serialized per id)
	logs     sync.Map // sandbox id -> *eventLog
}

// New loads the registry from the data dir and returns the service.
func New(opts Options) (*Service, error) {
	if opts.DataDir == "" || !filepath.IsAbs(opts.DataDir) {
		return nil, errors.New("daemon: DataDir must be an absolute path")
	}
	if opts.Images == nil {
		return nil, errors.New("daemon: Images is required")
	}
	if opts.DefaultUser == "" {
		opts.DefaultUser = DefaultSandboxUser
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: create data dir: %w", err)
	}
	reg, err := newRegistry(filepath.Join(opts.DataDir, "sandboxes"))
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	s := &Service{opts: opts, reg: reg, backends: map[backend.Isolation]backend.Backend{}, log: opts.Logger}
	for _, b := range opts.Backends {
		s.backends[b.Name()] = b
	}
	return s, nil
}

// Register adds the service to a gRPC server.
func (s *Service) Register(g *grpc.Server) { qtdv1.RegisterSandboxServiceServer(g, s) }

func (s *Service) lock(id string) func() {
	m, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func isolationFromProto(i qtdv1.Isolation) (backend.Isolation, error) {
	switch i {
	case qtdv1.Isolation_ISOLATION_UNSPECIFIED, qtdv1.Isolation_ISOLATION_GVISOR:
		return backend.IsolationGVisor, nil
	case qtdv1.Isolation_ISOLATION_VM:
		return backend.IsolationVM, nil
	default:
		return "", fmt.Errorf("unknown isolation %d", i)
	}
}

func isolationToProto(i backend.Isolation) qtdv1.Isolation {
	switch i {
	case backend.IsolationGVisor:
		return qtdv1.Isolation_ISOLATION_GVISOR
	case backend.IsolationVM:
		return qtdv1.Isolation_ISOLATION_VM
	}
	return qtdv1.Isolation_ISOLATION_UNSPECIFIED
}

func limitsFromProto(l *qtdv1.Limits) backend.Limits {
	out := backend.DefaultLimits
	if l == nil {
		return out
	}
	if l.GetCpuMillis() != 0 {
		out.CPUMillis = int(l.GetCpuMillis())
	}
	if l.GetMemoryBytes() != 0 {
		out.MemoryBytes = int64(min(l.GetMemoryBytes(), 1<<50))
	}
	if l.GetPids() != 0 {
		out.PIDs = int(min(l.GetPids(), 1<<20))
	}
	out.DiskBytes = int64(min(l.GetDiskBytes(), 1<<50))
	return out
}

// Create implements the Create RPC: pull, prepare, start.
func (s *Service) Create(ctx context.Context, req *qtdv1.CreateRequest) (*qtdv1.CreateResponse, error) {
	iso, err := isolationFromProto(req.GetIsolation())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	be, ok := s.backends[iso]
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "isolation %q is not available on this host (see `qt doctor`)", iso)
	}
	switch req.GetNet().GetMode() {
	case qtdv1.NetPolicy_MODE_UNSPECIFIED, qtdv1.NetPolicy_MODE_NONE:
	default:
		return nil, status.Error(codes.Unimplemented, "network policies other than none arrive in M3 (use --net=none)")
	}
	if req.GetHoneytokens() {
		return nil, status.Error(codes.Unimplemented, "honeytokens arrive in M4")
	}
	limits := limitsFromProto(req.GetLimits())
	if limits.DiskBytes != 0 {
		return nil, status.Error(codes.Unimplemented, "disk limits are not supported yet")
	}
	if err := errors.Join(limits.Validate(), validateEnv(req.GetEnv()), validateWorkdir(req.GetWorkdir()),
		validateHostname(req.GetHostname()), validateLabels(req.GetLabels())); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	img, err := s.opts.Images.Pull(ctx, req.GetImage())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "image: %v", err)
	}
	user, home := s.sandboxUser(img)
	env := mergeEnv(img.Config.Env, req.GetEnv()...)
	if !hasEnv(env, "PATH") {
		env = append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, env...)
	}
	if !hasEnv(env, "HOME") {
		env = append(env, "HOME="+home)
	}
	workdir := req.GetWorkdir()
	if workdir == "" {
		workdir = img.Config.WorkingDir
	}
	if validateWorkdir(workdir) != nil || workdir == "" {
		workdir = "/"
	}

	id := newID()
	unlock := s.lock(id)
	defer unlock()
	hostname := req.GetHostname()
	if hostname == "" {
		hostname = "qt-" + id
	}
	rec := &record{
		ID: id, Image: img.Ref, Requested: req.GetImage(), Isolation: iso, CreatedAt: time.Now().UTC(),
		Limits: limits, User: user, Workdir: workdir, Env: env, Hostname: hostname, Labels: req.GetLabels(),
	}
	ws := s.reg.workspace(id)
	if err := os.Mkdir(ws, 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "create workspace: %v", err)
	}
	if err := s.reg.save(rec); err != nil {
		_ = os.RemoveAll(ws)
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	rootfs := img.RootFS
	if iso == backend.IsolationVM { // the microVM boots from an ext4 disk image
		eb, ok := s.opts.Images.(ext4Builder)
		if !ok {
			s.cleanup(id, be)
			return nil, status.Error(codes.FailedPrecondition, "this image store cannot build disk images for vm isolation")
		}
		if rootfs, err = eb.Ext4(ctx, img); err != nil {
			s.cleanup(id, be)
			return nil, status.Errorf(codes.Internal, "vm disk image: %v", err)
		}
	}
	spec := backend.Spec{
		ID: id, Image: img.Ref, RootFS: rootfs, Workspace: ws, Hostname: hostname,
		User: user, Env: env, Workdir: workdir, Limits: limits,
		Network: backend.Network{None: true},
		Events:  s.eventLogFor(id),
		Labels:  req.GetLabels(),
	}
	if err := be.Create(ctx, spec); err != nil {
		s.cleanup(id, be)
		return nil, status.Errorf(codes.Internal, "create sandbox: %v", err)
	}
	if err := be.Start(ctx, id); err != nil {
		s.cleanup(id, be)
		return nil, status.Errorf(codes.Internal, "start sandbox: %v", err)
	}
	s.log.Info("sandbox created", "id", id, "image", img.Ref, "isolation", iso, "user", user)
	return &qtdv1.CreateResponse{Sandbox: s.toProto(ctx, rec)}, nil
}

// sandboxUser picks the image's user if it is a resolvable non-root user, else the default.
func (s *Service) sandboxUser(img image.Image) (user, home string) {
	if u, err := image.LookupUser(img.RootFS, img.Config.User); err == nil && u.UID != 0 {
		home = u.Home
		if home == "" || home == "/nonexistent" {
			home = "/tmp"
		}
		return strconv.FormatUint(uint64(u.UID), 10) + ":" + strconv.FormatUint(uint64(u.GID), 10), home
	}
	return s.opts.DefaultUser, "/tmp"
}

func (s *Service) cleanup(id string, be backend.Backend) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := be.Destroy(ctx, id); err != nil {
		s.log.Error("cleanup after failed create", "id", id, "err", err)
		return // keep the workspace so `qt rm` can retry
	}
	if l, ok := s.logs.LoadAndDelete(id); ok {
		l.(*eventLog).close()
	}
	_ = os.RemoveAll(s.reg.workspace(id))
	s.reg.remove(id)
}

func (s *Service) backendFor(id string) (*record, backend.Backend, error) {
	if !sandboxIDRe.MatchString(id) {
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid sandbox id %.64q", id)
	}
	rec, ok := s.reg.get(id)
	if !ok {
		return nil, nil, status.Errorf(codes.NotFound, "no sandbox %s", id)
	}
	be, ok := s.backends[rec.Isolation]
	if !ok {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "sandbox %s uses isolation %q, which is not available", id, rec.Isolation)
	}
	return rec, be, nil
}

func (s *Service) toProto(ctx context.Context, rec *record) *qtdv1.Sandbox {
	st := qtdv1.SandboxState_SANDBOX_STATE_STOPPED
	var caps []qtdv1.Capability
	if be, ok := s.backends[rec.Isolation]; ok {
		if info, err := be.Info(ctx, rec.ID); err == nil {
			switch info.State {
			case backend.StateCreated:
				st = qtdv1.SandboxState_SANDBOX_STATE_CREATED
			case backend.StateRunning:
				st = qtdv1.SandboxState_SANDBOX_STATE_RUNNING
			case backend.StatePaused:
				st = qtdv1.SandboxState_SANDBOX_STATE_PAUSED
			}
		}
		caps = capsToProto(be.Capabilities())
	}
	return &qtdv1.Sandbox{
		Id: rec.ID, Image: rec.Image, Isolation: isolationToProto(rec.Isolation), State: st,
		CreatedAt: timestamppb.New(rec.CreatedAt),
		Limits: &qtdv1.Limits{
			CpuMillis: uint32(rec.Limits.CPUMillis), MemoryBytes: uint64(rec.Limits.MemoryBytes), //nolint:gosec // G115: validated positive
			Pids: uint32(rec.Limits.PIDs), //nolint:gosec // G115: validated positive
		},
		Net:          &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_NONE},
		Capabilities: caps,
		Labels:       rec.Labels,
	}
}

func capsToProto(c backend.Capabilities) []qtdv1.Capability {
	m := []struct {
		c backend.Capabilities
		p qtdv1.Capability
	}{
		{backend.CapMemorySnapshot, qtdv1.Capability_CAPABILITY_MEMORY_SNAPSHOT},
		{backend.CapDiskSnapshot, qtdv1.Capability_CAPABILITY_DISK_SNAPSHOT},
		{backend.CapFork, qtdv1.Capability_CAPABILITY_FORK},
		{backend.CapPTY, qtdv1.Capability_CAPABILITY_PTY},
		{backend.CapGuestKernel, qtdv1.Capability_CAPABILITY_GUEST_KERNEL},
		{backend.CapSyscallEvents, qtdv1.Capability_CAPABILITY_SYSCALL_EVENTS},
	}
	var out []qtdv1.Capability
	for _, x := range m {
		if c.Has(x.c) {
			out = append(out, x.p)
		}
	}
	return out
}

// List implements the List RPC.
func (s *Service) List(ctx context.Context, req *qtdv1.ListRequest) (*qtdv1.ListResponse, error) {
	out := &qtdv1.ListResponse{}
	for _, rec := range s.reg.list() {
		match := true
		for k, v := range req.GetLabelSelector() {
			if rec.Labels[k] != v {
				match = false
				break
			}
		}
		if match {
			out.Sandboxes = append(out.Sandboxes, s.toProto(ctx, rec))
		}
	}
	return out, nil
}

// Destroy implements the Destroy RPC. It is idempotent and removes the whole workspace.
func (s *Service) Destroy(ctx context.Context, req *qtdv1.DestroyRequest) (*qtdv1.DestroyResponse, error) {
	id := req.GetSandboxId()
	if !sandboxIDRe.MatchString(id) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid sandbox id %.64q", id)
	}
	unlock := s.lock(id)
	defer unlock()
	rec, known := s.reg.get(id)
	var errs []error
	if known {
		if be, ok := s.backends[rec.Isolation]; ok {
			errs = append(errs, be.Destroy(ctx, id))
		}
	} else {
		// Unknown to the registry (e.g. a half-created sandbox): ask every backend.
		for _, be := range s.backends {
			errs = append(errs, be.Destroy(ctx, id))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, status.Errorf(codes.Internal, "destroy %s: %v", id, err)
	}
	if l, ok := s.logs.LoadAndDelete(id); ok {
		l.(*eventLog).close() // ends followers after they read the last events
	}
	if err := os.RemoveAll(s.reg.workspace(id)); err != nil {
		return nil, status.Errorf(codes.Internal, "remove workspace: %v", err)
	}
	s.reg.remove(id)
	s.locks.Delete(id)
	if known {
		s.log.Info("sandbox destroyed", "id", id)
	}
	return &qtdv1.DestroyResponse{}, nil
}

// Exec implements the Exec RPC (bidirectional stream).
func (s *Service) Exec(stream grpc.BidiStreamingServer[qtdv1.ExecRequest, qtdv1.ExecResponse]) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "exec: %v", err)
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "exec: the first message must be start")
	}
	if err := errors.Join(validateArgv(start.GetArgv()), validateEnv(start.GetEnv()), validateWorkdir(start.GetWorkdir())); err != nil {
		return status.Errorf(codes.InvalidArgument, "exec: %v", err)
	}
	_, be, err := s.backendFor(start.GetSandboxId())
	if err != nil {
		return err
	}

	out := &streamWriter{stream: stream}
	stdinR, stdinW := io.Pipe()
	defer func() { _ = stdinR.Close() }() // unblocks stdin writes once the process is gone
	spec := backend.ExecSpec{
		Argv: start.GetArgv(), Env: start.GetEnv(), Workdir: start.GetWorkdir(), TTY: start.GetTty(),
		Stdin: stdinR, Stdout: out.writer(false), Stderr: out.writer(true),
	}
	if sz := start.GetSize(); start.GetTty() && sz != nil {
		spec.Size = &backend.WindowSize{Rows: clampU16(sz.GetRows()), Cols: clampU16(sz.GetCols())}
	}
	if spec.TTY {
		if err := backend.Require(be, backend.CapPTY); err != nil {
			return status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	proc, err := be.Exec(execCtx, start.GetSandboxId(), spec)
	if err != nil {
		_ = stdinW.Close()
		return status.Errorf(codes.FailedPrecondition, "exec: %v", err)
	}

	// Client messages: stdin, close, resize, signals. Ends when the client half-closes.
	go func() {
		defer func() { _ = stdinW.Close() }()
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			switch m := msg.GetMsg().(type) {
			case *qtdv1.ExecRequest_Stdin:
				if _, err := stdinW.Write(m.Stdin); err != nil {
					return
				}
			case *qtdv1.ExecRequest_CloseStdin:
				_ = stdinW.Close()
			case *qtdv1.ExecRequest_Resize:
				_ = proc.Resize(backend.WindowSize{Rows: clampU16(m.Resize.GetRows()), Cols: clampU16(m.Resize.GetCols())})
			case *qtdv1.ExecRequest_Signal:
				if m.Signal >= 1 && m.Signal <= 64 {
					_ = proc.Signal(int(m.Signal))
				}
			}
		}
	}()

	st, err := proc.Wait(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "exec wait: %v", err)
	}
	return out.send(&qtdv1.ExecResponse{Msg: &qtdv1.ExecResponse_Exit_{Exit: &qtdv1.ExecResponse_Exit{
		Code: int32(st.Code), Signal: int32(st.Signal), //nolint:gosec // G115: exit codes and signals are small
	}}})
}

func clampU16(v uint32) uint16 { return uint16(min(v, 0xffff)) }

// streamWriter serializes sends on one gRPC stream from stdout and stderr writers.
type streamWriter struct {
	mu     sync.Mutex
	stream grpc.BidiStreamingServer[qtdv1.ExecRequest, qtdv1.ExecResponse]
}

func (w *streamWriter) send(m *qtdv1.ExecResponse) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stream.Send(m)
}

type outWriter struct {
	w      *streamWriter
	stderr bool
}

func (w *streamWriter) writer(stderr bool) io.Writer { return outWriter{w, stderr} }

func (o outWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		c := p[:min(len(p), execChunk)]
		var m *qtdv1.ExecResponse
		if o.stderr {
			m = &qtdv1.ExecResponse{Msg: &qtdv1.ExecResponse_Stderr{Stderr: append([]byte(nil), c...)}}
		} else {
			m = &qtdv1.ExecResponse{Msg: &qtdv1.ExecResponse_Stdout{Stdout: append([]byte(nil), c...)}}
		}
		if err := o.w.send(m); err != nil {
			return n, err
		}
		n += len(c)
		p = p[len(c):]
	}
	return n, nil
}
