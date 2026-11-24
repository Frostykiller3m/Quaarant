//go:build linux

package gvisor

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/backend/backendtest"
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
	if inMountinfo(t, rootfsDir(s.Workspace)) {
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

func inMountinfo(t *testing.T, path string) bool {
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
	if inMountinfo(t, rootfsDir(s.Workspace)) {
		t.Error("overlay still mounted")
	}
}

func tarStream(t *testing.T, entries ...tarEntry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: e.typ, Linkname: e.link, Size: int64(len(e.body)), Uid: 0, Gid: 0}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

type tarEntry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func TestITestCopyAndDiff(t *testing.T) {
	it := setupITest(t)
	s := it.start(t, "it3", backend.DefaultLimits)
	ctx := context.Background()

	// A fresh sandbox has no changes: qt's and the runtime's own files are not reported.
	if ch, err := it.b.Diff(ctx, s.ID); err != nil || len(ch) != 0 {
		t.Fatalf("fresh diff = %+v, %v; want empty", ch, err)
	}
	// The sandbox looks for /work/late before it exists (gVisor would cache the miss in
	// --file-access=exclusive mode and never see the copied file).
	_ = it.exec(t, s.ID, sh("cat /work/late 2>/dev/null; ls /work 2>/dev/null; true"))

	in := tarStream(t,
		tarEntry{name: "repo/", typ: tar.TypeDir, mode: 0o755},
		tarEntry{name: "repo/main.sh", typ: tar.TypeReg, mode: 0o4755, body: "#!/bin/sh\necho hi\n"},
		tarEntry{name: "repo/README", typ: tar.TypeReg, mode: 0o644, body: "read me"},
		tarEntry{name: "repo/link", typ: tar.TypeSymlink, link: "/etc/passwd"},
		tarEntry{name: "late", typ: tar.TypeReg, mode: 0o644, body: "late\n"},
		tarEntry{name: "dev-null", typ: tar.TypeChar, mode: 0o666},
	)
	if err := it.b.CopyIn(ctx, s.ID, "/work", in); err != nil {
		t.Fatalf("copy in: %v", err)
	}
	r := it.exec(t, s.ID, sh("cat /work/late; stat -c '%u:%g %a' /work /work/repo/main.sh; /work/repo/main.sh; readlink /work/repo/link; ls /work"))
	want := "late\n65534:65534 755\n65534:65534 755\nhi\n/etc/passwd\nlate\nrepo\n"
	if r.stdout != want {
		t.Errorf("inside after copy in:\n%q\nwant\n%q (stderr %q)", r.stdout, want, r.stderr)
	}

	// The sandbox changes things; the host sees it at once.
	r = it.exec(t, s.ID, sh("echo out > /tmp/out && echo more >> /work/repo/main.sh && rm /work/repo/README && mkdir /work/new && ln -s /root /tmp/l"))
	if r.status.Code != 0 {
		t.Fatalf("changes: %+v", r)
	}
	changes, err := it.b.Diff(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range changes {
		line := string(c.Kind) + " " + c.Path
		if c.SHA256 != "" {
			line += fmt.Sprintf(" %d %s", c.Size, c.SHA256[:8])
		}
		if c.LinkTarget != "" {
			line += " -> " + c.LinkTarget
		}
		got = append(got, line)
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return fmt.Sprintf("%d %x", len(s), h[:4]) }
	wantDiff := []string{
		"added /tmp/l -> /root",
		"added /tmp/out " + sum("out\n"),
		"added /work",
		"added /work/late " + sum("late\n"),
		"added /work/new",
		"added /work/repo",
		"added /work/repo/link -> /etc/passwd",
		"added /work/repo/main.sh " + sum("#!/bin/sh\necho hi\nmore\n"),
	}
	if strings.Join(got, "\n") != strings.Join(wantDiff, "\n") {
		t.Errorf("diff while running:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantDiff, "\n"))
	}

	// Copy out: a tar of /work/repo with the sandbox's latest content.
	var out bytes.Buffer
	if err := it.b.CopyOut(ctx, s.ID, "/work/repo", &out); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&out)
	files := map[string]string{}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = string(b) + h.Linkname
	}
	if files["repo/main.sh"] != "#!/bin/sh\necho hi\nmore\n" || files["repo/link"] != "/etc/passwd" || len(files) != 3 {
		t.Errorf("copy out = %q", files)
	}

	// Escapes: a ".." entry, and symlinks the sandbox plants on the way, never reach the host.
	if err := it.b.CopyIn(ctx, s.ID, "/work", tarStream(t, tarEntry{name: "../../../../evil", typ: tar.TypeReg, body: "x"})); err == nil {
		t.Error("copy in with a .. entry succeeded")
	}
	_ = it.exec(t, s.ID, sh("ln -s / /tmp/abs; ln -s ../../../../../../.. /tmp/up"))
	for _, dir := range []string{"/tmp/abs", "/tmp/up", "/tmp/up/etc"} {
		err := it.b.CopyIn(ctx, s.ID, dir, tarStream(t, tarEntry{name: "evil", typ: tar.TypeReg, body: "x", mode: 0o644}))
		t.Logf("copy in to %s: %v", dir, err)
	}
	if err := it.b.CopyOut(ctx, s.ID, "/tmp/up/etc/shadow", io.Discard); err == nil {
		t.Error("copy out through a planted symlink succeeded")
	}
	for _, p := range []string{filepath.Join(it.data, "evil"), filepath.Join(s.Workspace, "evil"), "/evil", "/etc/evil"} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("escaped to the host: %s", p)
		}
	}
}

// recorder is an EventSink that keeps schema-checked events.
type recorder struct {
	mu   sync.Mutex
	evs  []events.Event
	errs []error
	sbID string
}

func (r *recorder) Emit(_ context.Context, src events.Source, p events.Payload) error {
	ev, err := events.New(r.sbID, src, time.Now(), p)
	if err == nil {
		var raw []byte
		raw, err = json.Marshal(ev)
		if err == nil {
			_, err = events.Validate(raw)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("%T %+v: %w", p, p, err))
		return err
	}
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recorder) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.evs {
		out = append(out, string(e.Kind)+" "+string(e.Data))
	}
	return out
}

func TestITestEvents(t *testing.T) {
	it := setupITest(t)
	rec := &recorder{sbID: "it4"}
	s := backend.Spec{
		ID: "it4", Image: it.img.Ref, RootFS: it.img.RootFS, Workspace: filepath.Join(it.data, "sandboxes", "it4"),
		Hostname: "qt-it4", User: "65534:65534", Env: []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
		Limits: backend.DefaultLimits, Network: backend.Network{None: true}, Events: rec,
	}
	ctx := context.Background()
	if err := it.b.Create(ctx, s); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = it.b.Destroy(context.Background(), s.ID) })
	if err := it.b.Start(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	r := it.exec(t, s.ID, sh(`cat /etc/os-release >/dev/null; echo data > /tmp/f; mkdir /tmp/d; ln -s /etc/passwd /tmp/l
		mv /tmp/f /tmp/g; rm /tmp/g; cat /etc/shadow 2>/dev/null; nc -w 1 192.0.2.7 80 </dev/null 2>/dev/null; true`))
	if r.status.Code != 0 {
		t.Fatalf("exec: %+v", r)
	}
	time.Sleep(3 * time.Second) // writes are flushed after 2s at the latest
	lines := rec.lines()
	for _, l := range lines {
		t.Log(l)
	}
	for _, e := range rec.errs {
		t.Errorf("invalid event: %v", e)
	}
	// Each expectation is a set of substrings that must all appear in one event line.
	want := [][]string{
		{`exec `, `"ppid":0`, `"path":"/bin/sh"`, `"argv":["/bin/sh","-c",`}, // started by qt (host)
		{`exec `, `"argv":["cat","/etc/os-release"]`, `"sha256":"`},          // from the sentry
		{`file `, `"op":"open"`, `"path":"/etc/os-release"`, `"flags":["O_RDONLY"]`},
		{`file `, `"op":"create"`, `"path":"/tmp/f"`},
		{`file `, `"op":"write"`, `"path":"/tmp/f"`, `"bytes":5`},
		{`file `, `"op":"mkdir"`, `"path":"/tmp/d"`},
		{`file `, `"op":"symlink"`, `"path":"/tmp/l"`, `"new_path":"/etc/passwd"`},
		{`file `, `"op":"rename"`, `"path":"/tmp/f"`, `"new_path":"/tmp/g"`},
		{`file `, `"op":"unlink"`, `"path":"/tmp/g"`},
		{`file `, `"op":"open"`, `"path":"/etc/shadow"`, `"errno":"EACCES"`},
		{`net `, `"op":"connect"`, `"proto":"tcp"`, `"dst_ip":"192.0.2.7"`, `"dst_port":80`, `"allowed":false`, `"errno":"ENETUNREACH"`},
	}
	for _, w := range want {
		if !anyLine(lines, w) {
			t.Errorf("no event with %q", w)
		}
	}
	for _, l := range lines {
		if strings.Contains(l, `"pid":1,`) || strings.Contains(l, `"path":"/dev/null"`) || strings.Contains(l, `/.qt/`) {
			t.Errorf("noise from qt itself or /dev/null: %s", l)
		}
	}
}

func anyLine(lines, subs []string) bool {
	for _, l := range lines {
		ok := true
		for _, s := range subs {
			if !strings.Contains(l, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

type gvisorSuite struct{ it *itest }

func (s gvisorSuite) Backend() backend.Backend { return s.it.b }
func (s gvisorSuite) Start(t *testing.T, id string, lim backend.Limits) backend.Spec {
	return s.it.start(t, id, lim)
}

// TestITestSharedSuite: the suite --isolation=vm also passes.
func TestITestSharedSuite(t *testing.T) {
	backendtest.Run(t, gvisorSuite{setupITest(t)}, backendtest.Options{KernelPrefix: "4."})
}
