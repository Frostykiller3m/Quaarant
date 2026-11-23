package backend_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/qt-dev/quarantine/internal/backend"
	"github.com/qt-dev/quarantine/internal/backend/fake"
	"github.com/qt-dev/quarantine/internal/events"
)

type recordingSink struct {
	mu  sync.Mutex
	got []events.Payload
}

func (s *recordingSink) Emit(_ context.Context, _ events.Source, p events.Payload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, p)
	return nil
}

func validSpec(id string, sink backend.EventSink) backend.Spec {
	return backend.Spec{
		ID: id, RootFS: "/var/lib/quarantine/images/x/rootfs", Workspace: "/var/lib/quarantine/sandboxes/" + id,
		User: "1000:1000", Limits: backend.DefaultLimits, Network: backend.Network{None: true}, Events: sink,
	}
}

func TestCapabilities(t *testing.T) {
	c := backend.CapFork | backend.CapPTY
	if !c.Has(backend.CapFork) || !c.Has(backend.CapFork|backend.CapPTY) || c.Has(backend.CapMemorySnapshot) {
		t.Fatalf("Has wrong for %s", c)
	}
	if got := c.String(); got != "fork,pty" {
		t.Errorf("String() = %q", got)
	}
	if got := backend.Capabilities(0).String(); got != "none" {
		t.Errorf("zero String() = %q", got)
	}
	if got := (backend.CapFork | 1<<20).String(); got != "fork,0x100000" {
		t.Errorf("unknown bits String() = %q", got)
	}
}

func TestRequire(t *testing.T) {
	b := fake.New(backend.IsolationGVisor, backend.CapPTY|backend.CapDiskSnapshot)
	if err := backend.Require(b, backend.CapPTY); err != nil {
		t.Fatal(err)
	}
	err := backend.Require(b, backend.CapPTY|backend.CapFork|backend.CapMemorySnapshot)
	var ue *backend.UnsupportedError
	if !errors.As(err, &ue) || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("got %v, want UnsupportedError wrapping ErrUnsupported", err)
	}
	if ue.Missing != backend.CapFork|backend.CapMemorySnapshot || ue.Backend != backend.IsolationGVisor {
		t.Fatalf("wrong missing set: %+v", ue)
	}
	if !strings.Contains(err.Error(), `"gvisor" does not support memory-snapshot,fork`) {
		t.Errorf("message: %v", err)
	}
}

func TestParseIsolation(t *testing.T) {
	for in, ok := range map[string]bool{"gvisor": true, "vm": true, "": false, "docker": false, "VM": false} {
		_, err := backend.ParseIsolation(in)
		if (err == nil) != ok {
			t.Errorf("ParseIsolation(%q) err=%v", in, err)
		}
	}
}

func TestSpecValidate(t *testing.T) {
	sink := &recordingSink{}
	tests := []struct {
		name    string
		mut     func(s *backend.Spec)
		wantErr string
	}{
		{"valid", func(*backend.Spec) {}, ""},
		{"bad id", func(s *backend.Spec) { s.ID = "../x" }, "invalid sandbox id"},
		{"no rootfs", func(s *backend.Spec) { s.RootFS = "" }, "rootfs is required"},
		{"no workspace", func(s *backend.Spec) { s.Workspace = "" }, "workspace is required"},
		{"root uid", func(s *backend.Spec) { s.User = "0:0" }, "never run as root"},
		{"named user", func(s *backend.Spec) { s.User = "root" }, "uid:gid"},
		{"non-numeric", func(s *backend.Spec) { s.User = "a:b" }, "numeric"},
		{"tiny memory", func(s *backend.Spec) { s.Limits.MemoryBytes = 1 << 20 }, "memory limit"},
		{"no limits", func(s *backend.Spec) { s.Limits = backend.Limits{} }, "cpu limit"},
		{"few pids", func(s *backend.Spec) { s.Limits.PIDs = 1 }, "pids limit"},
		{"negative disk", func(s *backend.Spec) { s.Limits.DiskBytes = -1 }, "disk limit"},
		{"no sink", func(s *backend.Spec) { s.Events = nil }, "event sink"},
		{"none plus tap", func(s *backend.Spec) { s.Network.TapDevice = "qt-x" }, "conflicts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validSpec("sb-1", sink)
			tt.mut(&s)
			err := s.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestFakeLifecycle drives the fake through the contract the real backends must honour.
func TestFakeLifecycle(t *testing.T) {
	ctx := context.Background()
	sink := &recordingSink{}
	b := fake.New(backend.IsolationVM, backend.CapFork|backend.CapMemorySnapshot)
	b.ExitCodes["false"] = 1

	if err := b.Create(ctx, validSpec("sb-1", sink)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Exec(ctx, "sb-1", backend.ExecSpec{Argv: []string{"true"}}); err == nil {
		t.Fatal("exec before start should fail")
	}
	if err := b.Start(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	p, err := b.Exec(ctx, "sb-1", backend.ExecSpec{Argv: []string{"echo", "hi"}, Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := p.Wait(ctx); st.Code != 0 || out.String() != "echo hi\n" {
		t.Fatalf("exec: status %+v out %q", st, out.String())
	}
	p, _ = b.Exec(ctx, "sb-1", backend.ExecSpec{Argv: []string{"false"}})
	if st, _ := p.Wait(ctx); st.Code != 1 {
		t.Fatalf("exit code %d, want 1", st.Code)
	}
	if len(sink.got) != 2 || sink.got[0].Kind() != events.KindExec {
		t.Fatalf("events: %+v", sink.got)
	}

	if _, err := b.Exec(ctx, "sb-1", backend.ExecSpec{Argv: []string{"sh"}, TTY: true}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("TTY without CapPTY: got %v", err)
	}
	if _, err := b.Snapshot(ctx, "sb-1", backend.SnapshotOptions{}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("disk snapshot without cap: got %v", err)
	}
	if _, err := b.Snapshot(ctx, "sb-1", backend.SnapshotOptions{Memory: true}); err != nil {
		t.Fatal(err)
	}

	if err := b.Fork(ctx, "sb-1", []backend.Spec{validSpec("sb-1-a", sink), validSpec("sb-1-b", sink)}); err != nil {
		t.Fatal(err)
	}
	if info, err := b.Info(ctx, "sb-1-b"); err != nil || info.State != backend.StateRunning {
		t.Fatalf("forked child: %+v %v", info, err)
	}

	for _, id := range []string{"sb-1", "sb-1-a", "sb-1-b", "sb-1", "never-existed"} {
		if err := b.Destroy(ctx, id); err != nil {
			t.Fatalf("Destroy(%s) must be idempotent: %v", id, err)
		}
	}
	if b.Len() != 0 {
		t.Fatalf("%d sandboxes left after destroy", b.Len())
	}
}
