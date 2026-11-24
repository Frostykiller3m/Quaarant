// Package backend defines the contract between qtd and an isolation backend (gVisor, Firecracker).
//
// qtd owns everything around a sandbox: ids, images, the data dir, network policy, the event
// log. A Backend only turns a prepared Spec into a running sandbox and operates on it. Optional
// features are declared with Capabilities; callers must check them (Require) instead of assuming,
// and backends return an error wrapping errors.ErrUnsupported for anything they do not declare.
package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// Isolation names a backend, as used by --isolation.
type Isolation string

// Known isolation levels.
const (
	IsolationGVisor Isolation = "gvisor"
	IsolationVM     Isolation = "vm"
)

// ParseIsolation validates an --isolation value.
func ParseIsolation(s string) (Isolation, error) {
	switch i := Isolation(s); i {
	case IsolationGVisor, IsolationVM:
		return i, nil
	default:
		return "", fmt.Errorf("unknown isolation %q (want %q or %q)", s, IsolationGVisor, IsolationVM)
	}
}

// Backend is implemented by every isolation backend. All methods must be safe for concurrent
// use on different sandbox ids. Destroy must be idempotent and leave nothing behind.
type Backend interface {
	// Name is the isolation level this backend provides.
	Name() Isolation
	// Capabilities lists the optional features this backend supports on this host.
	Capabilities() Capabilities

	// Create prepares a sandbox from spec without starting user code.
	Create(ctx context.Context, spec Spec) error
	// Start boots the sandbox (VM boot or runsc start) and leaves it ready for Exec.
	Start(ctx context.Context, id string) error
	// Exec runs a process inside a started sandbox. The returned Process streams stdio until
	// it exits; cancelling ctx kills it.
	Exec(ctx context.Context, id string, spec ExecSpec) (Process, error)

	// CopyIn extracts a tar stream into dir inside the sandbox.
	CopyIn(ctx context.Context, id, dir string, tarStream io.Reader) error
	// CopyOut writes path (file or directory) from inside the sandbox to w as a tar stream.
	CopyOut(ctx context.Context, id, path string, w io.Writer) error
	// Diff lists filesystem changes relative to the sandbox's base image.
	Diff(ctx context.Context, id string) ([]Change, error)

	// Snapshot captures the sandbox state. Memory snapshots need CapMemorySnapshot,
	// disk-only snapshots need CapDiskSnapshot.
	Snapshot(ctx context.Context, id string, opts SnapshotOptions) (SnapshotRef, error)
	// Restore creates and starts a new sandbox (spec.ID) from a snapshot.
	Restore(ctx context.Context, ref SnapshotRef, spec Spec) error
	// Fork clones a running sandbox once per child spec (CapFork). Each child gets the
	// fresh identity (hostname, MAC, IP, machine-id, RNG seed) carried in its spec.
	Fork(ctx context.Context, id string, children []Spec) error

	// Info reports the current state of a sandbox.
	Info(ctx context.Context, id string) (Info, error)
	// Destroy stops the sandbox and removes every resource the backend created for it.
	// Destroying an unknown or already destroyed id returns nil.
	Destroy(ctx context.Context, id string) error
}

// Capabilities is a set of optional backend features.
type Capabilities uint32

// Capability flags.
const (
	// CapMemorySnapshot: snapshots include RAM; restore resumes running processes.
	CapMemorySnapshot Capabilities = 1 << iota
	// CapDiskSnapshot: snapshots of the writable filesystem.
	CapDiskSnapshot
	// CapFork: clone a running sandbox into N independent copies.
	CapFork
	// CapPTY: Exec with TTY=true.
	CapPTY
	// CapGuestKernel: user code runs on its own kernel behind a hardware boundary.
	CapGuestKernel
	// CapSyscallEvents: exec/file events come from the runtime itself (not a guest agent).
	CapSyscallEvents
)

var capNames = []struct {
	c    Capabilities
	name string
}{
	{CapMemorySnapshot, "memory-snapshot"},
	{CapDiskSnapshot, "disk-snapshot"},
	{CapFork, "fork"},
	{CapPTY, "pty"},
	{CapGuestKernel, "guest-kernel"},
	{CapSyscallEvents, "syscall-events"},
}

// Has reports whether every capability in want is present.
func (c Capabilities) Has(want Capabilities) bool { return c&want == want }

// Names lists the capability names in c, in a stable order.
func (c Capabilities) Names() []string {
	var out []string
	for _, n := range capNames {
		if c.Has(n.c) {
			out = append(out, n.name)
		}
	}
	if rest := c &^ allCaps(); rest != 0 {
		out = append(out, fmt.Sprintf("0x%x", uint32(rest)))
	}
	return out
}

func (c Capabilities) String() string {
	if c == 0 {
		return "none"
	}
	return strings.Join(c.Names(), ",")
}

func allCaps() Capabilities {
	var all Capabilities
	for _, n := range capNames {
		all |= n.c
	}
	return all
}

// UnsupportedError is returned when a backend lacks a required capability.
type UnsupportedError struct {
	Backend Isolation
	Missing Capabilities
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("isolation %q does not support %s", e.Backend, e.Missing)
}

// Unwrap makes errors.Is(err, errors.ErrUnsupported) true.
func (e *UnsupportedError) Unwrap() error { return errors.ErrUnsupported }

// Require returns an *UnsupportedError if b lacks any capability in need.
func Require(b Backend, need Capabilities) error {
	if missing := need &^ b.Capabilities(); missing != 0 {
		return &UnsupportedError{Backend: b.Name(), Missing: missing}
	}
	return nil
}

// Spec is a fully prepared sandbox. qtd fills it in (ids, paths, network attachment); the
// backend must not reinterpret policy.
type Spec struct {
	ID        string
	Image     string // resolved reference, e.g. "docker.io/library/alpine@sha256:..."
	RootFS    string // host path: unpacked rootfs (gvisor) or ext4 image (vm), read-only
	Workspace string // host path: sandbox directory under the data dir (writable layer lives here)
	Hostname  string
	User      string // "uid:gid"; uid 0 is rejected
	Env       []string
	Workdir   string
	Limits    Limits
	Network   Network
	Events    EventSink
	Labels    map[string]string
}

// Network is how the sandbox is attached; qtd creates and polices it (M3).
type Network struct {
	None      bool   // loopback only
	NetnsPath string // e.g. /run/netns/qt-<id> (gvisor)
	TapDevice string // e.g. qt-<id> (vm)
	MAC       string
}

// Limits are enforced with cgroups v2 (and VM sizing for vm).
type Limits struct {
	CPUMillis   int   // 1000 = one CPU
	MemoryBytes int64 // hard limit
	PIDs        int
	DiskBytes   int64 // writable layer size; 0 = backend default
}

// DefaultLimits are used when the caller sets none.
var DefaultLimits = Limits{CPUMillis: 2000, MemoryBytes: 2 << 30, PIDs: 512}

// EventSink receives events observed by a backend. qtd assigns id, timestamp and sandbox.
type EventSink interface {
	Emit(ctx context.Context, src events.Source, p events.Payload) error
}

var sandboxIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate checks a Spec before it is handed to a backend.
func (s Spec) Validate() error {
	var errs []error
	if !sandboxIDRe.MatchString(s.ID) {
		errs = append(errs, fmt.Errorf("invalid sandbox id %q", s.ID))
	}
	if s.RootFS == "" {
		errs = append(errs, errors.New("rootfs is required"))
	}
	if s.Workspace == "" {
		errs = append(errs, errors.New("workspace is required"))
	}
	if err := validateUser(s.User); err != nil {
		errs = append(errs, err)
	}
	if err := s.Limits.Validate(); err != nil {
		errs = append(errs, err)
	}
	if s.Events == nil {
		errs = append(errs, errors.New("event sink is required"))
	}
	if s.Network.None && (s.Network.NetnsPath != "" || s.Network.TapDevice != "") {
		errs = append(errs, errors.New("network: None conflicts with an attachment"))
	}
	return errors.Join(errs...)
}

func validateUser(u string) error {
	uidStr, gidStr, ok := strings.Cut(u, ":")
	if !ok {
		return fmt.Errorf("user %q must be uid:gid", u)
	}
	uid, err1 := strconv.ParseUint(uidStr, 10, 32)
	_, err2 := strconv.ParseUint(gidStr, 10, 32)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("user %q must be numeric uid:gid", u)
	}
	if uid == 0 {
		return errors.New("sandboxes never run as root (uid 0)")
	}
	return nil
}

// Validate checks that limits are set and sane.
func (l Limits) Validate() error {
	switch {
	case l.CPUMillis < 100:
		return fmt.Errorf("cpu limit %dm below 100m", l.CPUMillis)
	case l.MemoryBytes < 64<<20:
		return fmt.Errorf("memory limit %d below 64MiB", l.MemoryBytes)
	case l.PIDs < 8:
		return fmt.Errorf("pids limit %d below 8", l.PIDs)
	case l.DiskBytes < 0:
		return fmt.Errorf("disk limit %d is negative", l.DiskBytes)
	}
	return nil
}

// ExecSpec describes a process to run inside a sandbox.
type ExecSpec struct {
	Argv    []string
	Env     []string
	Workdir string
	User    string // empty = the sandbox user
	TTY     bool   // needs CapPTY; Stderr is merged into Stdout
	Size    *WindowSize
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// WindowSize is a terminal size.
type WindowSize struct{ Rows, Cols uint16 }

// Process is a running Exec.
type Process interface {
	// Wait blocks until the process exits and stdio is drained.
	Wait(ctx context.Context) (ExitStatus, error)
	// Signal delivers a signal (Linux numbering) to the process.
	Signal(sig int) error
	// Resize changes the TTY size; no-op without a TTY.
	Resize(ws WindowSize) error
}

// ExitStatus is how a process ended.
type ExitStatus struct {
	Code   int // -1 if killed by a signal
	Signal int // 0 unless killed by a signal
}

// ChangeKind classifies a Diff entry.
type ChangeKind string

// Change kinds.
const (
	Added    ChangeKind = "added"
	Modified ChangeKind = "modified"
	Deleted  ChangeKind = "deleted"
)

// Change is one filesystem difference from the base image. Path and LinkTarget come from the
// sandbox: untrusted, and they may contain any byte except NUL and '/' (in names).
type Change struct {
	Path       string
	Kind       ChangeKind
	Mode       fs.FileMode
	Size       int64
	SHA256     string // hex; empty for deleted entries, directories and non-regular files
	LinkTarget string // symlinks only
}

// ErrDiffTruncated is wrapped by Diff when there are more changes than it reports; the
// changes returned with it are still valid.
var ErrDiffTruncated = errors.New("diff truncated")

// SnapshotOptions controls Snapshot.
type SnapshotOptions struct {
	Memory bool // include RAM (CapMemorySnapshot)
}

// SnapshotRef identifies a stored snapshot.
type SnapshotRef struct {
	ID      string
	Backend Isolation
	Memory  bool
	Path    string // host path under the data dir
}

// State of a sandbox.
type State string

// Sandbox states.
const (
	StateCreated State = "created"
	StateRunning State = "running"
	StatePaused  State = "paused"
	StateStopped State = "stopped"
)

// Info describes a sandbox as the backend sees it.
type Info struct {
	ID        string
	Isolation Isolation
	State     State
	CreatedAt time.Time
}
