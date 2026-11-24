// Package backendtest is the integration suite every isolation backend must pass, so the
// same command behaves the same under --isolation=gvisor and --isolation=vm. Backends call
// Run from their QT_ITEST=1 tests.
package backendtest

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// Env starts sandboxes for the suite. Start must create and start a sandbox with user
// 65534:65534, hostname "qt-<id>", --net=none and the given limits, and register cleanup.
type Env interface {
	Backend() backend.Backend
	Start(t *testing.T, id string, lim backend.Limits) backend.Spec
}

// Options are the few places backends legitimately differ.
type Options struct {
	KernelPrefix string // `uname -r` prefix: gVisor's kernel version, or qt's guest kernel
}

// Result is a finished exec.
type Result struct {
	Stdout, Stderr string
	Status         backend.ExitStatus
}

// Exec runs e to completion.
func Exec(t *testing.T, b backend.Backend, id string, e backend.ExecSpec) Result {
	t.Helper()
	var out, errb bytes.Buffer
	e.Stdout, e.Stderr = &out, &errb
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := b.Exec(ctx, id, e)
	if err != nil {
		t.Fatalf("exec %v: %v", e.Argv, err)
	}
	st, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("wait %v: %v (stderr %q)", e.Argv, err, errb.String())
	}
	return Result{out.String(), errb.String(), st}
}

// Sh is an ExecSpec for /bin/sh -c script.
func Sh(script string) backend.ExecSpec {
	return backend.ExecSpec{Argv: []string{"/bin/sh", "-c", script}}
}

// Run is the shared suite.
func Run(t *testing.T, env Env, opts Options) {
	b := env.Backend()
	lim := backend.Limits{CPUMillis: 1000, MemoryBytes: 256 << 20, PIDs: 64}
	s := env.Start(t, "shared", lim)

	tests := []struct {
		name   string
		exec   backend.ExecSpec
		stdout string // exact, or a prefix when it ends with "*"
		code   int
	}{
		{"echo", Sh("echo hi"), "hi\n", 0},
		{"exit code", Sh("exit 3"), "", 3},
		{"stdin", backend.ExecSpec{Argv: []string{"cat"}, Stdin: strings.NewReader("abc")}, "abc", 0},
		{"non-root user", Sh("id -u; id -g"), "65534\n65534\n", 0},
		{"no capabilities", Sh("grep -E '^Cap(Eff|Prm|Bnd|Amb)' /proc/self/status | awk '{print $2}' | sort -u"), "0000000000000000\n", 0},
		{"no new privs", Sh("grep NoNewPrivs /proc/self/status | awk '{print $2}'"), "1\n", 0},
		{"seccomp filter installed", Sh("grep -E '^Seccomp:' /proc/self/status | awk '{print $2}'"), "2\n", 0},
		{"kernel", Sh("uname -r"), opts.KernelPrefix + "*", 0},
		{"hostname", Sh("hostname"), "qt-shared\n", 0},
		{"loopback only", Sh(`awk -F: 'NR>2{gsub(/ /,"",$1); print $1}' /proc/net/dev`), "lo\n", 0},
		{"--net=none: no route out", Sh("echo hi | nc -w 2 1.1.1.1 80 2>/dev/null; echo rc=$?"), "rc=1\n", 0},
		{"process limit visible", Sh("ulimit -u"), "64\n", 0},
		{"image is read-only to the user", Sh("touch /etc/x 2>/dev/null; echo $?"), "1\n", 0},
		{"exec env and cwd", backend.ExecSpec{Argv: []string{"/bin/sh", "-c", "echo $FOO; pwd"}, Env: []string{"FOO=bar"}, Workdir: "/tmp"}, "bar\n/tmp\n", 0},
		{"init survives signals from inside", Sh("for s in TERM INT HUP KILL; do kill -$s 1 2>/dev/null && echo sent-$s; done; sleep 0.3; echo alive"), "alive\n", 0},
		{"command not found", backend.ExecSpec{Argv: []string{"no-such-command-qt"}}, "", 127},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Exec(t, b, s.ID, tt.exec)
			ok := r.Stdout == tt.stdout
			if p, isPrefix := strings.CutSuffix(tt.stdout, "*"); isPrefix {
				ok = strings.HasPrefix(r.Stdout, p)
			}
			if !ok || r.Status.Code != tt.code {
				t.Errorf("stdout %q code %d (stderr %q); want %q code %d", r.Stdout, r.Status.Code, r.Stderr, tt.stdout, tt.code)
			}
		})
	}

	t.Run("process limit enforced and the sandbox survives", func(t *testing.T) {
		r := Exec(t, b, s.ID, Sh("i=0; while [ $i -lt 200 ]; do sleep 30 & i=$((i+1)); done; echo spawned-all"))
		if strings.Contains(r.Stdout, "spawned-all") || !strings.Contains(r.Stderr, "fork") {
			t.Errorf("fork loop was not limited: %+v", r)
		}
		if r := Exec(t, b, s.ID, Sh("echo alive")); r.Stdout != "alive\n" {
			t.Errorf("sandbox did not survive the fork loop: %+v", r)
		}
		if r := Exec(t, b, s.ID, backend.ExecSpec{Argv: []string{"pkill", "sleep"}}); r.Status.Code != 0 {
			t.Fatalf("pkill: %+v", r)
		}
		for range 50 {
			if r := Exec(t, b, s.ID, backend.ExecSpec{Argv: []string{"pgrep", "sleep"}}); r.Status.Code == 1 {
				return // orphans reaped by init; slots free again
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Error("sleeps still alive after pkill (zombies not reaped?)")
	})

	t.Run("tty", func(t *testing.T) {
		r := Exec(t, b, s.ID, backend.ExecSpec{Argv: []string{"/bin/sh", "-c", "tty; stty size"}, TTY: true, Size: &backend.WindowSize{Rows: 33, Cols: 101}})
		if !strings.HasPrefix(r.Stdout, "/dev/pts/") || !strings.Contains(r.Stdout, "33 101") {
			t.Errorf("tty output %q", r.Stdout)
		}
	})

	t.Run("signal", func(t *testing.T) {
		p, err := b.Exec(context.Background(), s.ID, backend.ExecSpec{Argv: []string{"sleep", "60"}})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if err := p.Signal(int(syscall.SIGTERM)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if st, err := p.Wait(ctx); err != nil || st.Signal != int(syscall.SIGTERM) {
			t.Errorf("status %+v err %v; want killed by SIGTERM", st, err)
		}
	})

	t.Run("context cancel kills", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		if _, err := b.Exec(ctx, s.ID, backend.ExecSpec{Argv: []string{"sleep", "60"}}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		cancel()
		for range 50 {
			if r := Exec(t, b, s.ID, backend.ExecSpec{Argv: []string{"pgrep", "-x", "sleep"}}); r.Status.Code == 1 {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Error("process survived cancel")
	})

	t.Run("copy in and out", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, h := range []*tar.Header{
			{Name: "repo/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "repo/run.sh", Typeflag: tar.TypeReg, Mode: 0o4755, Size: 18},
			{Name: "repo/null", Typeflag: tar.TypeChar, Mode: 0o666},
		} {
			_ = tw.WriteHeader(h)
			if h.Size > 0 {
				_, _ = tw.Write([]byte("#!/bin/sh\necho hi\n"))
			}
		}
		_ = tw.Close()
		ctx := context.Background()
		if err := b.CopyIn(ctx, s.ID, "/work", &buf); err != nil {
			t.Fatalf("copy in: %v", err)
		}
		r := Exec(t, b, s.ID, Sh("stat -c '%u:%g %a' /work /work/repo/run.sh; /work/repo/run.sh; ls /work/repo; echo more >> /work/repo/run.sh"))
		if r.Stdout != "65534:65534 755\n65534:65534 755\nhi\nrun.sh\n" {
			t.Errorf("after copy in: %q (stderr %q)", r.Stdout, r.Stderr)
		}
		var out bytes.Buffer
		if err := b.CopyOut(ctx, s.ID, "/work/repo", &out); err != nil {
			t.Fatalf("copy out: %v", err)
		}
		tr := tar.NewReader(&out)
		got := map[string]string{}
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			data, _ := io.ReadAll(tr)
			got[h.Name] = string(data)
		}
		if got["repo/run.sh"] != "#!/bin/sh\necho hi\nmore\n" {
			t.Errorf("copy out = %q", got)
		}
	})

	if info, err := b.Info(context.Background(), s.ID); err != nil || info.State != backend.StateRunning {
		t.Errorf("info = %+v, %v", info, err)
	}
	for range 2 {
		if err := b.Destroy(context.Background(), s.ID); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}
	if info, err := b.Info(context.Background(), s.ID); err == nil && info.State == backend.StateRunning {
		t.Errorf("still running after destroy: %+v", info)
	}
}
