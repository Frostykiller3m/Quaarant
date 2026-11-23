// Package fake is an in-memory backend.Backend for tests of code that drives backends (qtd).
// It runs nothing: Exec writes its argv to Stdout and exits with the code set in ExitCodes.
package fake

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/qt-dev/quarantine/internal/backend"
	"github.com/qt-dev/quarantine/internal/events"
)

// Backend is a fake backend. The zero value is not usable; call New.
type Backend struct {
	isolation backend.Isolation
	caps      backend.Capabilities

	mu        sync.Mutex
	sandboxes map[string]*sandbox
	// ExitCodes maps argv[0] to the exit code Exec reports (default 0).
	ExitCodes map[string]int
}

type sandbox struct {
	spec    backend.Spec
	state   backend.State
	created time.Time
	files   map[string][]byte
}

var _ backend.Backend = (*Backend)(nil)

// New returns a fake backend with the given identity and capabilities.
func New(isolation backend.Isolation, caps backend.Capabilities) *Backend {
	return &Backend{isolation: isolation, caps: caps, sandboxes: map[string]*sandbox{}, ExitCodes: map[string]int{}}
}

// Name implements backend.Backend.
func (b *Backend) Name() backend.Isolation { return b.isolation }

// Capabilities implements backend.Backend.
func (b *Backend) Capabilities() backend.Capabilities { return b.caps }

// Len returns the number of live sandboxes (to check Destroy leaves nothing).
func (b *Backend) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.sandboxes)
}

func (b *Backend) get(id string) (*sandbox, error) {
	sb, ok := b.sandboxes[id]
	if !ok {
		return nil, fmt.Errorf("sandbox %q: %w", id, ErrNotFound)
	}
	return sb, nil
}

// ErrNotFound is returned for unknown sandbox ids.
var ErrNotFound = errors.New("not found")

// Create implements backend.Backend.
func (b *Backend) Create(_ context.Context, spec backend.Spec) error {
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.sandboxes[spec.ID]; ok {
		return fmt.Errorf("create: sandbox %q already exists", spec.ID)
	}
	b.sandboxes[spec.ID] = &sandbox{spec: spec, state: backend.StateCreated, created: time.Now(), files: map[string][]byte{}}
	return nil
}

// Start implements backend.Backend.
func (b *Backend) Start(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	sb, err := b.get(id)
	if err != nil {
		return err
	}
	sb.state = backend.StateRunning
	return nil
}

// Exec implements backend.Backend.
func (b *Backend) Exec(ctx context.Context, id string, spec backend.ExecSpec) (backend.Process, error) {
	if len(spec.Argv) == 0 {
		return nil, errors.New("exec: empty argv")
	}
	if spec.TTY {
		if err := backend.Require(b, backend.CapPTY); err != nil {
			return nil, err
		}
	}
	b.mu.Lock()
	sb, err := b.get(id)
	if err == nil && sb.state != backend.StateRunning {
		err = fmt.Errorf("exec: sandbox %q is %s", id, sb.state)
	}
	code := b.ExitCodes[spec.Argv[0]]
	var sink backend.EventSink
	if sb != nil {
		sink = sb.spec.Events
	}
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := sink.Emit(ctx, events.SourceHost, events.Exec{PID: 2, PPID: 1, Path: spec.Argv[0], Argv: spec.Argv}); err != nil {
		return nil, fmt.Errorf("emit exec event: %w", err)
	}
	if spec.Stdout != nil {
		if _, err := io.WriteString(spec.Stdout, strings.Join(spec.Argv, " ")+"\n"); err != nil {
			return nil, fmt.Errorf("write stdout: %w", err)
		}
	}
	return &process{status: backend.ExitStatus{Code: code}}, nil
}

type process struct{ status backend.ExitStatus }

func (p *process) Wait(context.Context) (backend.ExitStatus, error) { return p.status, nil }
func (p *process) Signal(int) error                                 { return nil }
func (p *process) Resize(backend.WindowSize) error                  { return nil }

// CopyIn implements backend.Backend; it records the raw stream under dir.
func (b *Backend) CopyIn(_ context.Context, id, dir string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("copy in: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	sb, err := b.get(id)
	if err != nil {
		return err
	}
	sb.files[dir] = data
	return nil
}

// CopyOut implements backend.Backend.
func (b *Backend) CopyOut(_ context.Context, id, path string, w io.Writer) error {
	b.mu.Lock()
	sb, err := b.get(id)
	var data []byte
	if err == nil {
		var ok bool
		if data, ok = sb.files[path]; !ok {
			err = fmt.Errorf("copy out %q: %w", path, ErrNotFound)
		}
	}
	b.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Diff implements backend.Backend; every CopyIn target shows up as added.
func (b *Backend) Diff(_ context.Context, id string) ([]backend.Change, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sb, err := b.get(id)
	if err != nil {
		return nil, err
	}
	var out []backend.Change
	for p, d := range sb.files {
		out = append(out, backend.Change{Path: p, Kind: backend.Added, Size: int64(len(d))})
	}
	return out, nil
}

// Snapshot implements backend.Backend.
func (b *Backend) Snapshot(_ context.Context, id string, opts backend.SnapshotOptions) (backend.SnapshotRef, error) {
	need := backend.CapDiskSnapshot
	if opts.Memory {
		need = backend.CapMemorySnapshot
	}
	if err := backend.Require(b, need); err != nil {
		return backend.SnapshotRef{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.get(id); err != nil {
		return backend.SnapshotRef{}, err
	}
	return backend.SnapshotRef{ID: "snap-" + id, Backend: b.isolation, Memory: opts.Memory}, nil
}

// Restore implements backend.Backend.
func (b *Backend) Restore(ctx context.Context, ref backend.SnapshotRef, spec backend.Spec) error {
	if ref.Backend != b.isolation {
		return fmt.Errorf("restore: snapshot is from %q", ref.Backend)
	}
	if err := b.Create(ctx, spec); err != nil {
		return err
	}
	return b.Start(ctx, spec.ID)
}

// Fork implements backend.Backend.
func (b *Backend) Fork(ctx context.Context, id string, children []backend.Spec) error {
	if err := backend.Require(b, backend.CapFork); err != nil {
		return err
	}
	b.mu.Lock()
	_, err := b.get(id)
	b.mu.Unlock()
	if err != nil {
		return err
	}
	for _, c := range children {
		if err := b.Restore(ctx, backend.SnapshotRef{Backend: b.isolation}, c); err != nil {
			return fmt.Errorf("fork %s: %w", c.ID, err)
		}
	}
	return nil
}

// Info implements backend.Backend.
func (b *Backend) Info(_ context.Context, id string) (backend.Info, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sb, err := b.get(id)
	if err != nil {
		return backend.Info{}, err
	}
	return backend.Info{ID: id, Isolation: b.isolation, State: sb.state, CreatedAt: sb.created}, nil
}

// Destroy implements backend.Backend. Unknown ids are not an error.
func (b *Backend) Destroy(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sandboxes, id)
	return nil
}
