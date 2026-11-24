package gvisor

import (
	"context"
	"errors"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
)

type sink struct{}

func (sink) Emit(context.Context, events.Source, events.Payload) error { return nil }

func testSpec() backend.Spec {
	return backend.Spec{
		ID: "abc", RootFS: "/data/images/x/rootfs", Workspace: "/data/sandboxes/abc",
		Hostname: "qt-abc", User: "1000:1000",
		Limits:  backend.Limits{CPUMillis: 1500, MemoryBytes: 512 << 20, PIDs: 100},
		Network: backend.Network{None: true}, Events: sink{},
	}
}

func TestBuildSpecLeastPrivilege(t *testing.T) {
	sp, err := buildSpec(testSpec(), "/data/sandboxes/abc/rootfs", "/usr/libexec/qt-agent", "/quarantine")
	if err != nil {
		t.Fatal(err)
	}
	p := sp.Process
	if p.User.UID == 0 || p.User.UID == 1000 {
		t.Errorf("init uid %d: must be non-root and differ from the sandbox user", p.User.UID)
	}
	c := p.Capabilities
	for name, set := range map[string][]string{"bounding": c.Bounding, "effective": c.Effective, "permitted": c.Permitted, "inheritable": c.Inheritable, "ambient": c.Ambient} {
		if set == nil || len(set) != 0 {
			t.Errorf("%s capabilities = %v, want empty and non-nil", name, set)
		}
	}
	if !p.NoNewPrivileges {
		t.Error("NoNewPrivileges is false")
	}
	if !slices.Equal(p.Args, []string{agentPath, "pause"}) {
		t.Errorf("init args = %v", p.Args)
	}
	if sp.Linux.CgroupsPath != "/quarantine/qt-abc" {
		t.Errorf("cgroups path = %s", sp.Linux.CgroupsPath)
	}
	r := sp.Linux.Resources
	if *r.CPU.Quota != 150_000 || *r.CPU.Period != 100_000 {
		t.Errorf("cpu = %d/%d, want 150000/100000", *r.CPU.Quota, *r.CPU.Period)
	}
	if *r.Memory.Limit != 512<<20 || *r.Memory.Swap != 512<<20 {
		t.Errorf("memory = %d swap %d", *r.Memory.Limit, *r.Memory.Swap)
	}
	if *r.Pids.Limit != hostPidsLimit(100) || hostPidsLimit(100) <= 100 {
		t.Errorf("host pids = %d", *r.Pids.Limit)
	}
	if nproc := findRlimit(p.Rlimits, "RLIMIT_NPROC"); nproc == nil || nproc.Hard != 100 || nproc.Soft != 100 {
		t.Errorf("RLIMIT_NPROC = %+v, want 100", nproc)
	}
	sc := sp.Linux.Seccomp
	if sc == nil || sc.DefaultAction != specs.ActAllow || len(sc.Syscalls) != 1 || sc.Syscalls[0].Action != specs.ActErrno {
		t.Fatalf("seccomp = %+v", sc)
	}
	for _, must := range []string{"ptrace", "bpf", "keyctl", "mount", "unshare", "setns", "perf_event_open"} {
		if !slices.Contains(sc.Syscalls[0].Names, must) {
			t.Errorf("seccomp does not deny %s", must)
		}
	}
	ns := map[specs.LinuxNamespaceType]bool{}
	for _, n := range sp.Linux.Namespaces {
		ns[n.Type] = true
	}
	for _, want := range []specs.LinuxNamespaceType{specs.PIDNamespace, specs.NetworkNamespace, specs.MountNamespace, specs.IPCNamespace, specs.UTSNamespace} {
		if !ns[want] {
			t.Errorf("missing %s namespace", want)
		}
	}
	mounts := map[string]specs.Mount{}
	for _, m := range sp.Mounts {
		mounts[m.Destination] = m
	}
	if m := mounts[agentPath]; m.Source != "/usr/libexec/qt-agent" || !slices.Contains(m.Options, "ro") {
		t.Errorf("agent mount = %+v, want read-only bind", m)
	}
	if m := mounts["/tmp"]; m.Type != "bind" || m.Source != "/data/sandboxes/abc/rootfs/tmp" {
		t.Errorf("/tmp mount = %+v, want a bind of the overlay's /tmp", m)
	}
	if m := mounts["/sys"]; !slices.Contains(m.Options, "ro") {
		t.Errorf("/sys mount = %+v, want read-only", m)
	}
}

func findRlimit(rs []specs.POSIXRlimit, typ string) *specs.POSIXRlimit {
	for i := range rs {
		if rs[i].Type == typ {
			return &rs[i]
		}
	}
	return nil
}

func TestBuildSpecRejectsRoot(t *testing.T) {
	s := testSpec()
	s.User = "0:0"
	if _, err := buildSpec(s, "/r", "/a", "/q"); err == nil {
		t.Fatal("root user accepted")
	}
}

func TestInitUserNeverMatchesSandboxUser(t *testing.T) {
	for _, uid := range []uint32{1, 1000, 65532, 65533, 65534} {
		if iu := initUser(specs.User{UID: uid}); iu.UID == uid || iu.UID == 0 {
			t.Errorf("initUser(%d) = %d", uid, iu.UID)
		}
	}
}

func TestExecProcess(t *testing.T) {
	base := &specs.Process{User: specs.User{UID: 1000, GID: 1000}, Rlimits: rlimits(10)}
	tests := []struct {
		name    string
		e       backend.ExecSpec
		wantErr bool
		check   func(*testing.T, *specs.Process)
	}{
		{name: "empty argv", e: backend.ExecSpec{}, wantErr: true},
		{name: "root user", e: backend.ExecSpec{Argv: []string{"id"}, User: "0:0"}, wantErr: true},
		{name: "defaults", e: backend.ExecSpec{Argv: []string{"--looks-like-a-flag"}}, check: func(t *testing.T, p *specs.Process) {
			if p.Cwd != "/srv" || p.User.UID != 1000 || p.Terminal || !p.NoNewPrivileges || len(p.Capabilities.Effective) != 0 {
				t.Errorf("process = %+v", p)
			}
			if !slices.Equal(p.Args, []string{"--looks-like-a-flag"}) {
				t.Errorf("args = %v", p.Args)
			}
		}},
		{name: "env override and tty", e: backend.ExecSpec{Argv: []string{"sh"}, Env: []string{"A=2", "C=3"}, TTY: true, Size: &backend.WindowSize{Rows: 24, Cols: 80}, Workdir: "/tmp"}, check: func(t *testing.T, p *specs.Process) {
			if !slices.Equal(p.Env, []string{"A=2", "B=1", "C=3"}) {
				t.Errorf("env = %v", p.Env)
			}
			if !p.Terminal || p.ConsoleSize == nil || p.ConsoleSize.Height != 24 || p.ConsoleSize.Width != 80 || p.Cwd != "/tmp" {
				t.Errorf("process = %+v", p)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := execProcess(base, []string{"A=1", "B=1"}, "/srv", tt.e)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}

func TestUnsupportedFeatures(t *testing.T) {
	b, err := New(Config{AgentPath: "/usr/libexec/qt-agent"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := b.Diff(ctx, "x"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Diff: %v", err)
	}
	if err := b.Fork(ctx, "x", nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Fork: %v", err)
	}
	if _, err := b.Snapshot(ctx, "x", backend.SnapshotOptions{}); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Snapshot: %v", err)
	}
	s := testSpec()
	s.Network = backend.Network{NetnsPath: "/run/netns/x"}
	if err := b.Create(ctx, s); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Create with a network attachment: %v", err)
	}
	if _, err := New(Config{}); err == nil {
		t.Error("New without AgentPath succeeded")
	}
}
