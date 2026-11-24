//go:build linux

package gvisor

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/image"
)

// Integration tests: QT_ITEST=1, root, runsc on PATH, and network access to pull alpine.

type nopSink struct{}

func (nopSink) Emit(context.Context, events.Source, events.Payload) error { return nil }

type itest struct {
	b    *Backend
	img  image.Image
	data string
}

func setupITest(t *testing.T) *itest {
	t.Helper()
	if os.Getenv("QT_ITEST") != "1" {
		t.Skip("integration test: set QT_ITEST=1 (needs root, runsc, network)")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration test needs root")
	}
	runsc, err := exec.LookPath("runsc")
	if err != nil {
		t.Skip("runsc not on PATH")
	}
	data := t.TempDir()
	// runsc --network=none keeps a shared null netns mounted in its state dir.
	t.Cleanup(func() { _ = unmount(filepath.Join(data, "runsc", "null-netns")) })
	agent := filepath.Join(data, "qt-agent")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", agent, "github.com/Frostykiller3m/Quaarant/cmd/qt-agent")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qt-agent: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	img, err := image.NewStore(filepath.Join(data, "images")).Pull(ctx, "alpine:3.22")
	if err != nil {
		t.Fatalf("pull alpine: %v", err)
	}
	var extra []string
	if d := os.Getenv("QT_RUNSC_DEBUG_DIR"); d != "" { // e.g. /tmp/runsc-debug/
		extra = []string{"--debug", "--debug-log=" + d}
	}
	b, err := New(Config{
		Runsc:        runsc,
		StateDir:     filepath.Join(data, "runsc"),
		AgentPath:    agent,
		CgroupParent: "/quarantine-itest",
		ExtraFlags:   extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &itest{b: b, img: img, data: data}
}

func (it *itest) start(t *testing.T, id string, lim backend.Limits) backend.Spec {
	t.Helper()
	s := backend.Spec{
		ID: id, Image: it.img.Ref, RootFS: it.img.RootFS,
		Workspace: filepath.Join(it.data, "sandboxes", id),
		Hostname:  "qt-" + id, User: "65534:65534",
		Env:     []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
		Limits:  lim,
		Network: backend.Network{None: true},
		Events:  nopSink{},
	}
	ctx := context.Background()
	if err := it.b.Create(ctx, s); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = it.b.Destroy(context.Background(), id) })
	if err := it.b.Start(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}
	return s
}

type result struct {
	stdout, stderr string
	status         backend.ExitStatus
}

func (it *itest) exec(t *testing.T, id string, e backend.ExecSpec) result {
	t.Helper()
	var out, errb bytes.Buffer
	e.Stdout, e.Stderr = &out, &errb
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := it.b.Exec(ctx, id, e)
	if err != nil {
		t.Fatalf("exec %v: %v", e.Argv, err)
	}
	st, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("wait %v: %v", e.Argv, err)
	}
	return result{out.String(), errb.String(), st}
}

func sh(script string) backend.ExecSpec {
	return backend.ExecSpec{Argv: []string{"/bin/sh", "-c", script}}
}

func TestITestRunExecDestroy(t *testing.T) {
	it := setupITest(t)
	lim := backend.Limits{CPUMillis: 500, MemoryBytes: 256 << 20, PIDs: 64}
	s := it.start(t, "it1", lim)

	tests := []struct {
		name   string
		exec   backend.ExecSpec
		stdout string // exact, or prefix when it ends with "*"
		code   int
	}{
		{"echo", sh("echo hi"), "hi\n", 0},
		{"exit code", sh("exit 3"), "", 3},
		{"stdin", backend.ExecSpec{Argv: []string{"cat"}, Stdin: strings.NewReader("abc")}, "abc", 0},
		{"non-root user", sh("id -u; id -g"), "65534\n65534\n", 0},
		{"no capabilities", sh("grep -E '^Cap(Eff|Prm|Bnd|Amb)' /proc/self/status | awk '{print $2}' | sort -u"), "0000000000000000\n", 0},
		{"no new privs", sh("grep NoNewPrivs /proc/self/status | awk '{print $2}'"), "1\n", 0},
		{"gvisor kernel", sh("uname -r"), "4.*", 0},
		{"hostname", sh("hostname"), "qt-it1\n", 0},
		{"loopback only", sh("awk -F: 'NR>2{gsub(/ /,\"\",$1); print $1}' /proc/net/dev"), "lo\n", 0},
		{"process limit visible", sh("ulimit -u"), "64\n", 0},
		{"image is read-only to the user", sh("touch /etc/x 2>/dev/null; echo $?"), "1\n", 0},
		{"exec env and cwd", backend.ExecSpec{Argv: []string{"/bin/sh", "-c", "echo $FOO; pwd"}, Env: []string{"FOO=bar"}, Workdir: "/tmp"}, "bar\n/tmp\n", 0},
		{"init survives signals from inside", sh("for s in TERM INT HUP KILL; do kill -$s 1 2>/dev/null && echo sent-$s; done; sleep 0.3; echo alive"), "alive\n", 0},
		{"seccomp filter installed", sh("grep -E '^Seccomp:' /proc/self/status | awk '{print $2}'"), "2\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := it.exec(t, s.ID, tt.exec)
			ok := r.stdout == tt.stdout
			if p, isPrefix := strings.CutSuffix(tt.stdout, "*"); isPrefix {
				ok = strings.HasPrefix(r.stdout, p)
			}
			if !ok || r.status.Code != tt.code {
				t.Errorf("stdout %q code %d (stderr %q); want %q code %d", r.stdout, r.status.Code, r.stderr, tt.stdout, tt.code)
			}
		})
	}

	t.Run("cgroup limits on the host", func(t *testing.T) {
		dir := filepath.Join(cgroupRoot, "quarantine-itest", "qt-it1")
		want := map[string]string{
			"memory.max": strconv.FormatInt(lim.MemoryBytes, 10),
			"pids.max":   strconv.FormatInt(hostPidsLimit(lim.PIDs), 10),
			"cpu.max":    "50000 100000",
		}
		for f, w := range want {
			got, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				t.Errorf("%s: %v", f, err)
				continue
			}
			if strings.TrimSpace(string(got)) != w {
				t.Errorf("%s = %q, want %q", f, strings.TrimSpace(string(got)), w)
			}
			t.Logf("%s = %s", f, strings.TrimSpace(string(got)))
		}
		procs, _ := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
		if len(bytes.TrimSpace(procs)) == 0 {
			t.Error("no host processes in the sandbox cgroup: limits would not apply")
		}
	})

	t.Run("process limit enforced and the sandbox survives", func(t *testing.T) {
		// Try to start 200 background sleeps with a 64-process limit.
		r := it.exec(t, s.ID, sh("i=0; while [ $i -lt 200 ]; do sleep 30 & i=$((i+1)); done; echo spawned-all"))
		t.Logf("fork loop: stdout %q stderr %q code %d", r.stdout, r.stderr, r.status.Code)
		if strings.Contains(r.stdout, "spawned-all") || !strings.Contains(r.stderr, "can't fork") {
			t.Errorf("fork loop was not limited: %+v", r)
		}
		if r := it.exec(t, s.ID, sh("echo alive")); r.stdout != "alive\n" { // builtin: needs no fork
			t.Errorf("sandbox did not survive the fork loop: %+v", r)
		}
		// The 64 slots are full, so a shell can't fork; exec pkill directly. The orphaned
		// sleeps are reparented to init (qt-agent pause), which must reap them.
		if k := it.exec(t, s.ID, backend.ExecSpec{Argv: []string{"pkill", "sleep"}}); k.status.Code != 0 {
			t.Fatalf("pkill: %+v", k)
		}
		left := "?"
		for range 50 {
			r := it.exec(t, s.ID, backend.ExecSpec{Argv: []string{"pgrep", "sleep"}})
			if left = r.stdout; r.status.Code == 1 && left == "" { // 1 = no match
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if left != "" {
			t.Errorf("sleeps left after pkill (zombies not reaped?): %q", left)
		}
		if r := it.exec(t, s.ID, sh("ls / >/dev/null && echo forks-again")); r.stdout != "forks-again\n" {
			t.Errorf("process slots not released: %+v", r)
		}
	})

	t.Run("writes land in the upper dir", func(t *testing.T) {
		r := it.exec(t, s.ID, sh("echo data > /tmp/f && cat /tmp/f"))
		if r.stdout != "data\n" {
			t.Fatalf("stdout %q stderr %q", r.stdout, r.stderr)
		}
		got, err := os.ReadFile(filepath.Join(s.Workspace, "upper", "tmp", "f"))
		if err != nil || string(got) != "data\n" {
			t.Errorf("upper/tmp/f = %q, %v", got, err)
		}
		if _, err := os.Stat(filepath.Join(it.img.RootFS, "tmp", "f")); !os.IsNotExist(err) {
			t.Error("write reached the shared image rootfs")
		}
	})

	t.Run("tty", func(t *testing.T) {
		r := it.exec(t, s.ID, backend.ExecSpec{Argv: []string{"/bin/sh", "-c", "tty; stty size"}, TTY: true, Size: &backend.WindowSize{Rows: 33, Cols: 101}})
		if !strings.HasPrefix(r.stdout, "/dev/pts/") || !strings.Contains(r.stdout, "33 101") {
			t.Errorf("tty output %q", r.stdout)
		}
	})

	t.Run("signal", func(t *testing.T) {
		ctx := context.Background()
		p, err := it.b.Exec(ctx, s.ID, backend.ExecSpec{Argv: []string{"sleep", "60"}})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if err := p.Signal(int(syscall.SIGTERM)); err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		st, err := p.Wait(wctx)
		if err != nil || st.Signal != int(syscall.SIGTERM) {
			t.Errorf("status %+v err %v; want killed by SIGTERM", st, err)
		}
	})

	t.Run("context cancel kills", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		p, err := it.b.Exec(ctx, s.ID, backend.ExecSpec{Argv: []string{"sleep", "60"}})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		cancel()
		wctx, wcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer wcancel()
		if _, err := p.Wait(wctx); err != nil {
			t.Errorf("process survived cancel: %v", err)
		}
	})

	info, err := it.b.Info(context.Background(), s.ID)
	if err != nil || info.State != backend.StateRunning {
		t.Errorf("info %+v %v", info, err)
	}

	// Destroy leaves no mount, no runsc container, no cgroup; the workspace can be removed.
	if err := it.b.Destroy(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	if mounted(t, rootfsDir(s.Workspace)) {
		t.Error("overlay still mounted after destroy")
	}
	if _, err := it.b.Info(context.Background(), s.ID); err == nil {
		t.Error("runsc still knows the container after destroy")
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, "quarantine-itest", "qt-it1")); !os.IsNotExist(err) {
		t.Errorf("cgroup left behind: %v", err)
	}
	if err := os.RemoveAll(s.Workspace); err != nil {
		t.Errorf("remove workspace: %v", err)
	}
	if err := it.b.Destroy(context.Background(), s.ID); err != nil {
		t.Errorf("second destroy: %v", err)
	}
}

func mounted(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) > 4 && fields[4] == path {
			return true
		}
	}
	return false
}

func TestITestRecoverAfterRestart(t *testing.T) {
	it := setupITest(t)
	s := it.start(t, "it2", backend.DefaultLimits)
	// A fresh Backend (as after a qtd restart) finds the sandbox through runsc state.
	b2, err := New(it.b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	it2 := &itest{b: b2, img: it.img, data: it.data}
	if r := it2.exec(t, s.ID, sh("echo still here")); r.stdout != "still here\n" {
		t.Errorf("stdout %q stderr %q", r.stdout, r.stderr)
	}
	if err := b2.Destroy(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	if mounted(t, rootfsDir(s.Workspace)) {
		t.Error("overlay still mounted")
	}
}
