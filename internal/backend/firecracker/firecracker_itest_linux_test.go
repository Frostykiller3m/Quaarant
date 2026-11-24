//go:build linux

package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/backend/backendtest"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/image"
	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

// Integration tests: QT_ITEST=1, root, /dev/kvm, firecracker + jailer on PATH, a guest kernel
// (QT_VM_KERNEL, else the newest bin/kernel/vmlinux-*), and network access to pull alpine.

type nopSink struct{}

func (nopSink) Emit(context.Context, events.Source, events.Payload) error { return nil }

type vmEnv struct {
	B    *Backend
	Img  image.Image
	Ext4 string
	Data string
}

func setupVM(t *testing.T) *vmEnv {
	t.Helper()
	if os.Getenv("QT_ITEST") != "1" || os.Geteuid() != 0 {
		t.Skip("integration test: QT_ITEST=1 as root (needs /dev/kvm, firecracker, jailer, a guest kernel)")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("no /dev/kvm")
	}
	fc, err1 := exec.LookPath("firecracker")
	jailer, err2 := exec.LookPath("jailer")
	if err1 != nil || err2 != nil {
		t.Skip("firecracker/jailer not on PATH")
	}
	kernel := os.Getenv("QT_VM_KERNEL")
	if kernel == "" {
		// go test runs in the package directory (runtime.Caller is useless under -trimpath).
		matches, _ := filepath.Glob(filepath.Join("..", "..", "..", "bin", "kernel", "vmlinux-*-qt"))
		if len(matches) == 0 {
			t.Skip("no guest kernel: run scripts/build-kernel.sh or set QT_VM_KERNEL")
		}
		kernel = matches[len(matches)-1]
	}
	kernel, _ = filepath.Abs(kernel)
	data, err := os.MkdirTemp("", "qtvm") // short: unix socket paths live under it
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(data) })
	agent := filepath.Join(data, "qt-agent")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", agent, "github.com/Frostykiller3m/Quaarant/cmd/qt-agent")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qt-agent: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store := image.NewStore(filepath.Join(data, "images"))
	img, err := store.Pull(ctx, "alpine:3.22")
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	ext4, err := store.Ext4(ctx, img)
	if err != nil {
		t.Fatalf("ext4: %v", err)
	}
	b, err := New(Config{
		Firecracker: fc, Jailer: jailer, Kernel: kernel, AgentPath: agent,
		StateDir: filepath.Join(data, "fc"), CgroupParent: "/quarantine-itest-vm",
		DataDir: data, NoGolden: os.Getenv("QT_VM_COLD") == "1",
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // runs before the data dir is removed (cleanups are LIFO)
		if err := b.Close(context.Background()); err != nil {
			t.Errorf("close backend: %v", err)
		}
	})
	return &vmEnv{B: b, Img: img, Ext4: ext4, Data: data}
}

func (v *vmEnv) start(t *testing.T, id string, lim backend.Limits) backend.Spec {
	t.Helper()
	return v.startNet(t, id, lim, backend.Network{None: true})
}

func (v *vmEnv) startNet(t *testing.T, id string, lim backend.Limits, n backend.Network) backend.Spec {
	t.Helper()
	s := backend.Spec{
		ID: id, Image: v.Img.Ref, RootFS: v.Ext4, Workspace: filepath.Join(v.Data, "sb", id),
		Hostname: "qt-" + id, User: "65534:65534",
		Env:    []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"},
		Limits: lim, Network: n, Events: nopSink{},
	}
	if err := os.MkdirAll(s.Workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.B.Create(ctx, s); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = v.B.Destroy(context.Background(), id) })
	t0 := time.Now()
	if err := v.B.Start(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Logf("boot to agent ready: %v", time.Since(t0).Round(time.Millisecond))
	return s
}

func (v *vmEnv) exec(t *testing.T, id string, e backend.ExecSpec) (string, string, backend.ExitStatus) {
	t.Helper()
	var out, errb bytes.Buffer
	e.Stdout, e.Stderr = &out, &errb
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := v.B.Exec(ctx, id, e)
	if err != nil {
		t.Fatalf("exec %v: %v", e.Argv, err)
	}
	st, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("wait %v: %v (stderr %q)", e.Argv, err, errb.String())
	}
	return out.String(), errb.String(), st
}

func TestITestBoot(t *testing.T) {
	v := setupVM(t)
	v.B.cfg.NoGolden = true // the cold path: kernel boot from a full disk copy
	s := v.start(t, "vm1", backend.DefaultLimits)
	out, errs, st := v.exec(t, s.ID, backend.ExecSpec{Argv: []string{"uname", "-a"}})
	t.Logf("uname -a: %q %q %+v", out, errs, st)
	if st.Code != 0 || !strings.Contains(out, "-qt ") {
		t.Errorf("uname -a = %q (stderr %q, %+v); want our -qt kernel", out, errs, st)
	}
}

type vmSuite struct{ v *vmEnv }

func (s vmSuite) Backend() backend.Backend { return s.v.B }
func (s vmSuite) Start(t *testing.T, id string, lim backend.Limits) backend.Spec {
	return s.v.start(t, id, lim)
}

// TestITestSharedSuite: --isolation=vm behaves like --isolation=gvisor.
func TestITestSharedSuite(t *testing.T) {
	backendtest.Run(t, vmSuite{setupVM(t)}, backendtest.Options{KernelPrefix: "6.18.65-qt"})
}

// TestITestExt4Deterministic: two stores unpack the same image separately; the ext4 disk
// images they build hold the same tree (contents, modes, owners, link targets) and the same
// filesystem identity. (Inode atime/ctime follow the unpack: see image.Store.Ext4.)
func TestITestExt4Deterministic(t *testing.T) {
	v := setupVM(t)
	other, err := os.MkdirTemp("", "qtvm2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(other) })
	ctx := context.Background()
	s2 := image.NewStore(filepath.Join(other, "images"))
	img2, err := s2.Pull(ctx, v.Img.Ref)
	if err != nil {
		t.Fatal(err)
	}
	ext2, err := s2.Ext4(ctx, img2)
	if err != nil {
		t.Fatal(err)
	}
	tree := func(img string) string {
		mnt := t.TempDir()
		if out, err := exec.Command("mount", "-o", "loop,ro", img, mnt).CombinedOutput(); err != nil {
			t.Fatalf("mount %s: %v %s", img, err, out)
		}
		defer func() { _ = exec.Command("umount", mnt).Run() }()
		script := `cd "$1" && find . -printf '%p %y %m %U:%G %s %l\n' | sort && find . -type f -exec sha256sum {} + | sort`
		out, err := exec.Command("sh", "-c", script, "sh", mnt).Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	a, b := tree(v.Ext4), tree(ext2)
	if a != b {
		t.Errorf("the two ext4 images hold different trees")
	}
	t.Logf("same tree in both builds: %d lines, tree hash %x", strings.Count(a, "\n"), sha256.Sum256([]byte(a)))
	id := func(img string) string {
		out, _ := exec.Command("dumpe2fs", "-h", img).Output()
		var keep []string
		for _, l := range strings.Split(string(out), "\n") {
			for _, k := range []string{"Filesystem UUID", "Directory Hash Seed", "Block count", "Inode count", "Filesystem created"} {
				if strings.HasPrefix(l, k) {
					keep = append(keep, l)
				}
			}
		}
		return strings.Join(keep, "\n")
	}
	if ia, ib := id(v.Ext4), id(ext2); ia != ib || ia == "" {
		t.Errorf("filesystem identity differs:\n%s\n--\n%s", ia, ib)
	}
}

func percentile(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[min(len(s)-1, int(float64(len(s))*p))]
}

// TestITestRestoreBenchmark: restore-to-exec from a golden snapshot. Fails if the median is
// over QT_BENCH_MAX_MS (default 300).
func TestITestRestoreBenchmark(t *testing.T) {
	v := setupVM(t)
	lim := backend.DefaultLimits
	t0 := time.Now()
	g := v.B.golden(context.Background(), backend.Spec{RootFS: v.Ext4, Limits: lim}, DefaultDiskBytes)
	if g == nil {
		t.Fatal("no golden snapshot")
	}
	t.Logf("golden snapshot: %v (build %d ms), disks: %s", time.Since(t0).Round(time.Millisecond), g.BuildMS, g.Disk.Kind)
	var creates, restores, execs, total []time.Duration
	for i := range 10 {
		id := fmt.Sprintf("bench%d", i)
		s := backend.Spec{
			ID: id, Image: v.Img.Ref, RootFS: v.Ext4, Workspace: filepath.Join(v.Data, "sb", id),
			Hostname: "qt-" + id, User: "65534:65534", Env: []string{"PATH=/usr/bin:/bin"},
			Limits: lim, Network: backend.Network{None: true}, Events: nopSink{},
		}
		if err := os.MkdirAll(s.Workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		a := time.Now()
		if err := v.B.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		bt := time.Now()
		if err := v.B.Start(ctx, id); err != nil {
			t.Fatal(err)
		}
		c := time.Now()
		if out, _, st := v.exec(t, id, backend.ExecSpec{Argv: []string{"true"}}); st.Code != 0 {
			t.Fatalf("exec: %q %+v", out, st)
		}
		d := time.Now()
		creates, restores, execs, total = append(creates, bt.Sub(a)), append(restores, c.Sub(bt)), append(execs, d.Sub(c)), append(total, d.Sub(bt))
		if err := v.B.Destroy(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	row := func(name string, d []time.Duration) string {
		return fmt.Sprintf("| %s | %v | %v | %v |", name, percentile(d, 0.5).Round(time.Millisecond), percentile(d, 0.9).Round(time.Millisecond), percentile(d, 1).Round(time.Millisecond))
	}
	table := strings.Join([]string{
		"| step (10 runs, disks: " + g.Disk.Kind + ") | p50 | p90 | max |", "|---|---|---|---|",
		row("create (disk clone + jail)", creates), row("restore (jailer, load, resume, configure)", restores),
		row("first exec (`true`)", execs), row("**restore-to-exec**", total),
	}, "\n")
	t.Log("\n" + table)
	if f := os.Getenv("GITHUB_STEP_SUMMARY"); f != "" {
		if fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0); err == nil {
			_, _ = fmt.Fprintf(fh, "### vm restore-to-exec\n\n%s\n", table)
			_ = fh.Close()
		}
	}
	maxMS := 300
	if s := os.Getenv("QT_BENCH_MAX_MS"); s != "" {
		maxMS, _ = strconv.Atoi(s)
	}
	if p := percentile(total, 0.5); p > time.Duration(maxMS)*time.Millisecond {
		t.Errorf("restore-to-exec p50 %v is over %d ms", p, maxMS)
	}
}

// TestITestRestoredAreUnique: sandboxes restored from one snapshot don't share random
// state, hostname or a stale clock.
func TestITestRestoredAreUnique(t *testing.T) {
	v := setupVM(t)
	a := v.start(t, "ua", backend.DefaultLimits)
	b := v.start(t, "ub", backend.DefaultLimits)
	probe := "hostname; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; date +%s"
	oa, _, _ := v.exec(t, a.ID, backend.ExecSpec{Argv: []string{"/bin/sh", "-c", probe}})
	ob, _, _ := v.exec(t, b.ID, backend.ExecSpec{Argv: []string{"/bin/sh", "-c", probe}})
	la, lb := strings.Split(strings.TrimSpace(oa), "\n"), strings.Split(strings.TrimSpace(ob), "\n")
	if len(la) != 3 || len(lb) != 3 {
		t.Fatalf("probe output %q / %q", oa, ob)
	}
	if la[0] != "qt-ua" || lb[0] != "qt-ub" {
		t.Errorf("hostnames %q %q", la[0], lb[0])
	}
	if la[1] == lb[1] {
		t.Errorf("two restored sandboxes produced the same random bytes: %s", la[1])
	}
	for _, l := range []string{la[2], lb[2]} {
		if s, _ := strconv.ParseInt(l, 10, 64); time.Since(time.Unix(s, 0)).Abs() > 5*time.Second {
			t.Errorf("guest clock %s is off from the host (%d)", l, time.Now().Unix())
		}
	}
	if raw, err := os.ReadFile(filepath.Join(a.Workspace, "qt.json")); err != nil || !strings.Contains(string(raw), `"golden": "`) {
		t.Errorf("sandbox was not restored from a golden snapshot: %s", raw)
	}
	t.Logf("restored: %q | %q", la, lb)
	// rm frees the sandbox's disk (a thin volume here).
	if err := v.B.Destroy(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	if ds, _ := v.B.diskStore(context.Background()); ds != nil && ds.kind == "thin" {
		out, _ := exec.Command("dmsetup", "ls").Output()
		var meta boxMeta
		raw, _ := os.ReadFile(filepath.Join(b.Workspace, "qt.json"))
		_ = json.Unmarshal(raw, &meta)
		t.Logf("dmsetup ls:\n%s", out)
		if strings.Count(string(out), ds.pool.name+"-") != 1 { // only ub's volume (the golden one is inactive)
			t.Errorf("thin volumes after rm: %s", out)
		}
	}
}

type recSink struct {
	mu   sync.Mutex
	evs  []string
	errs []error
}

func (r *recSink) Emit(_ context.Context, src events.Source, p events.Payload) error {
	ev, err := events.New("vmev", src, time.Now(), p)
	if err == nil {
		var raw []byte
		if raw, err = json.Marshal(ev); err == nil {
			_, err = events.Validate(raw)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.errs = append(r.errs, err)
		return err
	}
	r.evs = append(r.evs, string(ev.Kind)+" "+string(ev.Source)+" "+string(ev.Data))
	return nil
}

func (r *recSink) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.evs...)
}

// TestITestVMEvents: qt-agent reports exec (proc connector) and file activity (fanotify) in
// the event schema, as guest claims; the guest reports no network activity; qt's own copy-in
// and the golden VM's boot are not in the log.
func TestITestVMEvents(t *testing.T) {
	v := setupVM(t)
	rec := &recSink{}
	s := backend.Spec{
		ID: "vmev", Image: v.Img.Ref, RootFS: v.Ext4, Workspace: filepath.Join(v.Data, "sb", "vmev"),
		Hostname: "qt-vmev", User: "65534:65534", Env: []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/tmp"},
		Limits: backend.DefaultLimits, Network: backend.Network{None: true}, Events: rec,
	}
	if err := os.MkdirAll(s.Workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.B.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.B.Destroy(context.Background(), s.ID) })
	if err := v.B.Start(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	_ = tw.WriteHeader(&tar.Header{Name: "copied.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	if err := v.B.CopyIn(ctx, s.ID, "/work", &tb); err != nil {
		t.Fatal(err)
	}
	out, errs, st := v.exec(t, s.ID, backend.ExecSpec{Argv: []string{"/bin/sh", "-c", `cat /etc/os-release >/dev/null; sleep 1; echo data > /tmp/f; mkdir /tmp/d; ln -s /etc/passwd /tmp/l
		mv /tmp/f /tmp/g; rm /tmp/g; chmod 700 /tmp/d; nc -w 1 192.0.2.7 80 </dev/null 2>/dev/null; true`}})
	if st.Code != 0 {
		t.Fatalf("exec: %q %q %+v", out, errs, st)
	}
	time.Sleep(time.Second)
	lines := rec.lines()
	for _, l := range lines {
		t.Log(l)
	}
	for _, e := range rec.errs {
		t.Errorf("invalid event: %v", e)
	}
	want := [][]string{
		{`exec guest`, `"argv":["/bin/sh","-c",`},
		// argv and uid are read from /proc: assert them on a process that lives long enough
		// (one that exits within ~1 ms is reported with argv_truncated; see BUILD_PLAN M2-T3), and
		// one that does not rewrite its own argv (busybox sleep does, briefly, for "0.3").
		{`exec guest`, `"path":"/bin/busybox"`, `"argv":["sleep","1"]`, `"uid":65534`},
		{`file guest`, `"op":"open"`, `os-release"`}, // fanotify reports the file opened: /usr/lib/os-release (alpine's /etc/os-release is a symlink)
		{`file guest`, `"op":"create"`, `"path":"/tmp/f"`},
		{`file guest`, `"op":"write"`, `"path":"/tmp/f"`, `"bytes":5`},
		{`file guest`, `"op":"mkdir"`, `"path":"/tmp/d"`},
		{`file guest`, `"op":"symlink"`, `"path":"/tmp/l"`, `"new_path":"/etc/passwd"`},
		{`file guest`, `"op":"rename"`, `"path":"/tmp/f"`, `"new_path":"/tmp/g"`},
		{`file guest`, `"op":"unlink"`, `"path":"/tmp/g"`},
		{`file guest`, `"op":"chmod"`, `"path":"/tmp/d"`, `"mode":"0700"`},
		{`exec guest`, `"path":"/bin/busybox"`, `"ppid":`}, // every exec has a binary and a parent, even if it exits at once
	}
	for _, w := range want {
		found := false
		for _, l := range lines {
			ok := true
			for _, s := range w {
				ok = ok && strings.Contains(l, s)
			}
			found = found || ok
		}
		if !found {
			t.Errorf("no event with %q", w)
		}
	}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "net "), strings.HasPrefix(l, "dns "):
			t.Errorf("a network event came from the guest: %s", l)
		case strings.Contains(l, "/work/copied.txt"), strings.Contains(l, "/.qt/"), strings.Contains(l, "/newroot"):
			t.Errorf("qt's own activity (copy-in, agent, boot) was reported: %s", l)
		case !strings.Contains(l, " guest "):
			t.Errorf("not marked as a guest claim: %s", l)
		case strings.HasPrefix(l, "exec ") && strings.Contains(l, `"path":"/lib/ld-`):
			t.Errorf("exec reported the ELF interpreter instead of the binary: %s", l)
		}
	}
}

func (vmSuite) Kind() netpol.Kind   { return netpol.Tap }
func (vmSuite) Owner(id string) int { return jailID(id) }
func (s vmSuite) StartNet(t *testing.T, id string, lim backend.Limits, n backend.Network) backend.Spec {
	return s.v.startNet(t, id, lim, n)
}

// TestITestNetIsolation: probes from inside VMs on a tap link (M3-T1), restored from a
// golden snapshot with a NIC.
func TestITestNetIsolation(t *testing.T) {
	backendtest.RunNet(t, vmSuite{setupVM(t)})
}
