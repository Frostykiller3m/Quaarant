//go:build linux

package daemon

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/backend/gvisor"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/image"
)

// TestITestDaemonGVisor drives real qtd + runsc over the socket: create, exec, list, rm, and
// checks that rm leaves nothing behind (data dir, mounts, cgroup, runsc state).
func TestITestDaemonGVisor(t *testing.T) {
	if os.Getenv("QT_ITEST") != "1" || os.Geteuid() != 0 {
		t.Skip("integration test: QT_ITEST=1 as root, with runsc and network")
	}
	runsc, err := exec.LookPath("runsc")
	if err != nil {
		t.Skip("runsc not on PATH")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	state := filepath.Join(dir, "runsc")
	t.Cleanup(func() { _ = exec.Command("umount", "-l", filepath.Join(state, "null-netns")).Run() })
	agent := filepath.Join(dir, "qt-agent")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", agent, "github.com/Frostykiller3m/Quaarant/cmd/qt-agent")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qt-agent: %v\n%s", err, out)
	}
	be, err := gvisor.New(gvisor.Config{Runsc: runsc, StateDir: state, AgentPath: agent, CgroupParent: "/quarantine-itest-daemon"})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Options{DataDir: data, Backends: []backend.Backend{be}, Images: image.NewStore(filepath.Join(data, "images"))})
	if err != nil {
		t.Fatal(err)
	}
	sockDir, _ := os.MkdirTemp("", "qtd-it")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	lis, authz, err := Listen(filepath.Join(sockDir, "qtd.sock"), "quarantine", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, lis, svc, authz) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	conn, err := grpc.NewClient("unix://"+filepath.Join(sockDir, "qtd.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	h := &harness{client: qtdv1.NewSandboxServiceClient(conn)}

	cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer ccancel()
	resp, err := h.client.Create(cctx, &qtdv1.CreateRequest{
		Image: "alpine:3.22", Limits: &qtdv1.Limits{CpuMillis: 500, MemoryBytes: 256 << 20, Pids: 64},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := resp.GetSandbox().GetId()
	t.Logf("sandbox %s image %s", id, resp.GetSandbox().GetImage())

	r := h.exec(t, start(id, "sh", "-c", "echo hi; id -u; echo x > /tmp/f; cat /proc/self/status | grep CapEff"))
	if r.err != nil || r.exit.GetCode() != 0 || r.stdout != "hi\n65534\nCapEff:\t0000000000000000\n" {
		t.Errorf("exec = %+v", r)
	}
	if _, err := os.Stat(filepath.Join(data, "sandboxes", id, "upper", "tmp", "f")); err != nil {
		t.Errorf("write not in the sandbox upper dir: %v", err)
	}
	list, err := h.client.List(context.Background(), &qtdv1.ListRequest{})
	if err != nil || len(list.GetSandboxes()) != 1 || list.GetSandboxes()[0].GetState() != qtdv1.SandboxState_SANDBOX_STATE_RUNNING {
		t.Errorf("list = %v %v", list, err)
	}

	// Runtime monitoring reached events.jsonl, through the Events RPC.
	time.Sleep(2500 * time.Millisecond) // pending writes flush after 2s
	evs, err := readEvents(t, h, &qtdv1.EventsRequest{SandboxId: id})
	if err != nil {
		t.Fatal(err)
	}
	var joined []string
	for _, e := range evs {
		joined = append(joined, string(e.GetEventJson()))
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		`"kind":"exec","source":"host","data":{"pid":`,             // the exec'd sh, recorded by qtd
		`"argv":["id","-u"]`, `"argv":["cat","/proc/self/status"]`, // children, from the sentry
		`"op":"write","path":"/tmp/f"`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("no event with %s in:\n%s", want, all)
		}
	}
	f, err := os.Open(filepath.Join(data, "sandboxes", id, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := events.ValidateStream(f, func(events.Event) error { n++; return nil }); err != nil || n != len(evs) {
		t.Errorf("events.jsonl: %d valid events (err %v), RPC returned %d", n, err, len(evs))
	}
	_ = f.Close()
	t.Logf("%d events, all schema-valid", n)

	// Copy files in over the real RPC, let the sandbox change them, and diff.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: "in.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()
	cin, err := h.client.CopyIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = cin.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_Header_{Header: &qtdv1.CopyInRequest_Header{SandboxId: id, Dir: "/work"}}})
	_ = cin.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_TarChunk{TarChunk: tarBuf.Bytes()}})
	if resp, err := cin.CloseAndRecv(); err != nil || resp.GetFiles() != 1 {
		t.Fatalf("copy in = %v, %v", resp, err)
	}
	if r := h.exec(t, start(id, "sh", "-c", "cat /work/in.txt; echo def >> /work/in.txt")); r.stdout != "abc" {
		t.Errorf("sandbox read %q", r.stdout)
	}
	diff, err := h.client.Diff(context.Background(), &qtdv1.DiffRequest{SandboxId: id})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, c := range diff.GetChanges() {
		paths = append(paths, c.GetPath())
	}
	if strings.Join(paths, " ") != "/tmp/f /work /work/in.txt" {
		t.Errorf("diff paths = %v", paths)
	}

	if _, err := h.client.Destroy(context.Background(), &qtdv1.DestroyRequest{SandboxId: id}); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	// Nothing left: no sandbox dir, no mounts under the data dir, no cgroup, no runsc container.
	assertEmptyDir(t, filepath.Join(data, "sandboxes"))
	// The whole data dir holds only the image cache and the (empty) sandboxes dir.
	_ = filepath.WalkDir(data, func(p string, _ fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(data, p)
		if err != nil || rel == "." || rel == "sandboxes" || rel == "images" || strings.HasPrefix(rel, "images"+string(filepath.Separator)) {
			return nil
		}
		t.Errorf("left in the data dir after rm: %s", rel)
		return nil
	})
	if m := mountsUnder(t, data); len(m) != 0 {
		t.Errorf("mounts left under the data dir: %v", m)
	}
	if _, err := os.Stat("/sys/fs/cgroup/quarantine-itest-daemon/qt-" + id); !os.IsNotExist(err) {
		t.Errorf("cgroup left behind: %v", err)
	}
	out, _ := exec.Command(runsc, "--root", state, "list", "-quiet").Output()
	if strings.TrimSpace(string(out)) != "" {
		t.Errorf("runsc still lists containers: %q", out)
	}
	// The image stays cached for the next sandbox.
	if des, _ := os.ReadDir(filepath.Join(data, "images")); len(des) != 1 {
		t.Errorf("image cache = %d entries, want 1", len(des))
	}
}

func mountsUnder(t *testing.T, dir string) []string {
	t.Helper()
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) > 4 && strings.HasPrefix(fields[4], dir+"/") {
			out = append(out, fields[4])
		}
	}
	return out
}
