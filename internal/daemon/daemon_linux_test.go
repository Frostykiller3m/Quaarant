//go:build linux

package daemon

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/backend/fake"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/image"
)

type fakeImages struct {
	rootfs string
	user   string
	pulls  int
}

func (f *fakeImages) Pull(_ context.Context, ref string) (image.Image, error) {
	if ref == "missing" {
		return image.Image{}, errors.New("manifest unknown")
	}
	f.pulls++
	return image.Image{
		Ref: "example.com/" + ref + "@sha256:" + strings.Repeat("ab", 32), Digest: "sha256:" + strings.Repeat("ab", 32),
		RootFS: f.rootfs, Config: v1.Config{User: f.user, Env: []string{"PATH=/bin", "LANG=C"}, WorkingDir: "/srv"},
	}, nil
}

type harness struct {
	data   string
	svc    *Service
	be     *fake.Backend
	images *fakeImages
	client qtdv1.SandboxServiceClient
	socket string
}

func newHarness(t *testing.T, caps backend.Capabilities, authorize func(Authorizer) Authorizer) *harness {
	t.Helper()
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	passwd := "root:x:0:0::/root:/bin/sh\napp:x:1001:1002::/home/app:/bin/sh\n"
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}
	h := &harness{data: filepath.Join(dir, "data"), be: fake.New(backend.IsolationGVisor, caps), images: &fakeImages{rootfs: rootfs}}
	h.startService(t, authorize)
	return h
}

func (h *harness) startService(t *testing.T, authorize func(Authorizer) Authorizer) {
	t.Helper()
	svc, err := New(Options{DataDir: h.data, Backends: []backend.Backend{h.be}, Images: h.images})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	// Unix socket paths are limited to 108 bytes; t.TempDir can be long.
	sockDir, err := os.MkdirTemp("", "qtd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	h.socket = filepath.Join(sockDir, "qtd.sock")
	lis, authz, err := Listen(h.socket, "qt-group-that-does-not-exist", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if authorize != nil {
		authz = authorize(authz)
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
	conn, err := grpc.NewClient("unix://"+h.socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	h.client = qtdv1.NewSandboxServiceClient(conn)
}

func (h *harness) create(t *testing.T, req *qtdv1.CreateRequest) *qtdv1.Sandbox {
	t.Helper()
	if req.Image == "" {
		req.Image = "alpine"
	}
	resp, err := h.client.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return resp.GetSandbox()
}

type execResult struct {
	stdout, stderr string
	exit           *qtdv1.ExecResponse_Exit
	err            error
}

func (h *harness) exec(t *testing.T, msgs ...*qtdv1.ExecRequest) execResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := h.client.Exec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if err := st.Send(m); err != nil {
			break
		}
	}
	_ = st.CloseSend()
	var r execResult
	for {
		msg, err := st.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.err = err
			}
			return r
		}
		switch m := msg.GetMsg().(type) {
		case *qtdv1.ExecResponse_Stdout:
			r.stdout += string(m.Stdout)
		case *qtdv1.ExecResponse_Stderr:
			r.stderr += string(m.Stderr)
		case *qtdv1.ExecResponse_Exit_:
			r.exit = m.Exit
		}
	}
}

func start(id string, argv ...string) *qtdv1.ExecRequest {
	return &qtdv1.ExecRequest{Msg: &qtdv1.ExecRequest_Start_{Start: &qtdv1.ExecRequest_Start{SandboxId: id, Argv: argv}}}
}

func TestLifecycle(t *testing.T) {
	h := newHarness(t, backend.CapPTY, nil)
	h.be.ExitCodes["false"] = 3
	sb := h.create(t, &qtdv1.CreateRequest{Labels: map[string]string{"task": "m1"}})
	if sb.GetState() != qtdv1.SandboxState_SANDBOX_STATE_RUNNING || sb.GetIsolation() != qtdv1.Isolation_ISOLATION_GVISOR {
		t.Errorf("sandbox = %v", sb)
	}

	if r := h.exec(t, start(sb.GetId(), "echo", "hi")); r.err != nil || r.stdout != "echo hi\n" || r.exit.GetCode() != 0 {
		t.Errorf("exec echo = %+v", r)
	}
	if r := h.exec(t, start(sb.GetId(), "false")); r.err != nil || r.exit.GetCode() != 3 {
		t.Errorf("exec false = %+v", r)
	}

	// The exec event went through the event log and passes the schema.
	f, err := os.Open(filepath.Join(h.data, "sandboxes", sb.GetId(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := events.ValidateStream(f, func(events.Event) error { n++; return nil }); err != nil || n != 2 {
		t.Errorf("events.jsonl: %d events, err %v", n, err)
	}
	_ = f.Close()

	list, err := h.client.List(context.Background(), &qtdv1.ListRequest{LabelSelector: map[string]string{"task": "m1"}})
	if err != nil || len(list.GetSandboxes()) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if l, _ := h.client.List(context.Background(), &qtdv1.ListRequest{LabelSelector: map[string]string{"task": "other"}}); len(l.GetSandboxes()) != 0 {
		t.Error("label selector did not filter")
	}

	// A restarted qtd finds the sandbox from meta.json.
	svc2, err := New(Options{DataDir: h.data, Backends: []backend.Backend{h.be}, Images: h.images})
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := svc2.List(context.Background(), &qtdv1.ListRequest{}); len(l.GetSandboxes()) != 1 {
		t.Error("registry not reloaded from the data dir")
	}

	for range 2 { // idempotent
		if _, err := h.client.Destroy(context.Background(), &qtdv1.DestroyRequest{SandboxId: sb.GetId()}); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}
	if h.be.Len() != 0 {
		t.Error("backend still has the sandbox")
	}
	assertEmptyDir(t, filepath.Join(h.data, "sandboxes"))
	if r := h.exec(t, start(sb.GetId(), "echo")); status.Code(r.err) != codes.NotFound {
		t.Errorf("exec after rm: %v", r.err)
	}
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		t.Errorf("left behind in %s: %s", dir, de.Name())
	}
}

func TestSandboxUser(t *testing.T) {
	tests := []struct{ imageUser, want, home string }{
		{"", DefaultSandboxUser, "HOME=/tmp"},
		{"root", DefaultSandboxUser, "HOME=/tmp"},
		{"0:0", DefaultSandboxUser, "HOME=/tmp"},
		{"app", "1001:1002", "HOME=/home/app"},
		{"ghost", DefaultSandboxUser, "HOME=/tmp"}, // not in /etc/passwd
	}
	for _, tt := range tests {
		t.Run(tt.imageUser, func(t *testing.T) {
			h := newHarness(t, 0, nil)
			h.images.user = tt.imageUser
			sb := h.create(t, &qtdv1.CreateRequest{Env: []string{"LANG=en_US.UTF-8"}})
			raw, err := os.ReadFile(filepath.Join(h.data, "sandboxes", sb.GetId(), "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rec record
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			if rec.User != tt.want {
				t.Errorf("user = %s, want %s", rec.User, tt.want)
			}
			if !hasEnv(rec.Env, "PATH") || !slicesContains(rec.Env, tt.home) || !slicesContains(rec.Env, "LANG=en_US.UTF-8") || rec.Workdir != "/srv" {
				t.Errorf("env %v workdir %s", rec.Env, rec.Workdir)
			}
		})
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestCreateValidation(t *testing.T) {
	h := newHarness(t, 0, nil)
	tests := []struct {
		name string
		req  *qtdv1.CreateRequest
		code codes.Code
	}{
		{"vm unavailable", &qtdv1.CreateRequest{Image: "alpine", Isolation: qtdv1.Isolation_ISOLATION_VM}, codes.FailedPrecondition},
		{"net allow", &qtdv1.CreateRequest{Image: "alpine", Net: &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_ALLOW, AllowDomains: []string{"pypi.org"}}}, codes.Unimplemented},
		{"honeytokens", &qtdv1.CreateRequest{Image: "alpine", Honeytokens: true}, codes.Unimplemented},
		{"tiny memory", &qtdv1.CreateRequest{Image: "alpine", Limits: &qtdv1.Limits{MemoryBytes: 1 << 20}}, codes.InvalidArgument},
		{"disk limit", &qtdv1.CreateRequest{Image: "alpine", Limits: &qtdv1.Limits{DiskBytes: 1 << 30}}, codes.Unimplemented},
		{"bad env", &qtdv1.CreateRequest{Image: "alpine", Env: []string{"NOEQUALS"}}, codes.InvalidArgument},
		{"env key injection", &qtdv1.CreateRequest{Image: "alpine", Env: []string{"A B=1"}}, codes.InvalidArgument},
		{"relative workdir", &qtdv1.CreateRequest{Image: "alpine", Workdir: "tmp"}, codes.InvalidArgument},
		{"dotdot workdir", &qtdv1.CreateRequest{Image: "alpine", Workdir: "/a/../b"}, codes.InvalidArgument},
		{"bad hostname", &qtdv1.CreateRequest{Image: "alpine", Hostname: "Evil_Host"}, codes.InvalidArgument},
		{"bad label", &qtdv1.CreateRequest{Image: "alpine", Labels: map[string]string{"k": "v\nx"}}, codes.InvalidArgument},
		{"missing image", &qtdv1.CreateRequest{Image: "missing"}, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.client.Create(context.Background(), tt.req)
			if status.Code(err) != tt.code {
				t.Errorf("code = %v (%v), want %v", status.Code(err), err, tt.code)
			}
		})
	}
	assertEmptyDir(t, filepath.Join(h.data, "sandboxes"))
}

func TestExecValidation(t *testing.T) {
	h := newHarness(t, 0, nil) // no PTY capability
	sb := h.create(t, &qtdv1.CreateRequest{})
	id := sb.GetId()
	tests := []struct {
		name string
		msgs []*qtdv1.ExecRequest
		code codes.Code
	}{
		{"no start", []*qtdv1.ExecRequest{{Msg: &qtdv1.ExecRequest_Stdin{Stdin: []byte("x")}}}, codes.InvalidArgument},
		{"empty argv", []*qtdv1.ExecRequest{start(id)}, codes.InvalidArgument},
		{"bad id", []*qtdv1.ExecRequest{start("../../etc", "sh")}, codes.InvalidArgument},
		{"unknown id", []*qtdv1.ExecRequest{start("deadbeef0000", "sh")}, codes.NotFound},
		{"nul in argv", []*qtdv1.ExecRequest{start(id, "sh\x00")}, codes.InvalidArgument},
		{"tty without pty support", []*qtdv1.ExecRequest{{Msg: &qtdv1.ExecRequest_Start_{Start: &qtdv1.ExecRequest_Start{SandboxId: id, Argv: []string{"sh"}, Tty: true}}}}, codes.FailedPrecondition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := h.exec(t, tt.msgs...); status.Code(r.err) != tt.code {
				t.Errorf("code = %v (%v), want %v", status.Code(r.err), r.err, tt.code)
			}
		})
	}
	if _, err := h.client.Destroy(context.Background(), &qtdv1.DestroyRequest{SandboxId: "../x"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("destroy bad id: %v", err)
	}
}

func TestSocketRejectsUnauthorizedPeers(t *testing.T) {
	deny := func(Authorizer) Authorizer { return func(Peer) error { return ErrForbidden } }
	h := newHarness(t, 0, deny)
	_, err := h.client.List(context.Background(), &qtdv1.ListRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("list as a denied peer: %v, want Unavailable (handshake rejected)", err)
	}
	fi, err := os.Stat(h.socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v, want 0600 when the group does not exist", fi.Mode().Perm())
	}
}

func TestGroupAuthorizer(t *testing.T) {
	self := uint32(os.Getuid())
	gids, _ := os.Getgroups()
	tests := []struct {
		name string
		a    Authorizer
		p    Peer
		ok   bool
	}{
		{"root", GroupAuthorizer(4242, true, 999999), Peer{UID: 0, GID: 0, PID: int32(os.Getpid())}, true},
		{"self", GroupAuthorizer(4242, true, self), Peer{UID: self, PID: int32(os.Getpid())}, true},
		{"primary group", GroupAuthorizer(4242, true, 999999), Peer{UID: 1234, GID: 4242, PID: int32(os.Getpid())}, true},
		{"stranger", GroupAuthorizer(4242, true, 999999), Peer{UID: 1234, GID: 1234, PID: int32(os.Getpid())}, false},
		{"no group configured", GroupAuthorizer(0, false, 999999), Peer{UID: 1234, GID: 0, PID: int32(os.Getpid())}, false},
	}
	if len(gids) > 0 {
		g := uint32(gids[len(gids)-1])
		tests = append(tests, struct {
			name string
			a    Authorizer
			p    Peer
			ok   bool
		}{"supplementary group from /proc", GroupAuthorizer(g, true, 999999), Peer{UID: 1234, GID: 1234, PID: int32(os.Getpid())}, true})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.a(tt.p); (err == nil) != tt.ok {
				t.Errorf("authorize(%+v) = %v, want ok=%v", tt.p, err, tt.ok)
			}
		})
	}
}

func TestPeerFromSocket(t *testing.T) {
	var got Peer
	capture := func(Authorizer) Authorizer { return func(p Peer) error { got = p; return nil } }
	h := newHarness(t, 0, capture)
	if _, err := h.client.List(context.Background(), &qtdv1.ListRequest{}); err != nil {
		t.Fatal(err)
	}
	if got.UID != uint32(os.Getuid()) || got.PID != int32(os.Getpid()) {
		t.Errorf("peer = %+v, want uid %d pid %d", got, os.Getuid(), os.Getpid())
	}
}

func TestCopyAndDiffRPCs(t *testing.T) {
	h := newHarness(t, 0, nil)
	sb := h.create(t, &qtdv1.CreateRequest{})
	ctx := context.Background()

	// A 3-entry tar, sent in small chunks.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, n := range []string{"d/", "d/a", "d/b"} {
		hdr := &tar.Header{Name: n, Mode: 0o644, Typeflag: tar.TypeReg}
		if strings.HasSuffix(n, "/") {
			hdr.Typeflag = tar.TypeDir
		}
		_ = tw.WriteHeader(hdr)
	}
	_ = tw.Close()
	in, err := h.client.CopyIn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = in.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_Header_{Header: &qtdv1.CopyInRequest_Header{SandboxId: sb.GetId(), Dir: "/work"}}})
	data := tarBuf.Bytes()
	for i := 0; i < len(data); i += 700 {
		_ = in.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_TarChunk{TarChunk: data[i:min(i+700, len(data))]}})
	}
	resp, err := in.CloseAndRecv()
	if err != nil || resp.GetBytes() != uint64(len(data)) || resp.GetFiles() != 3 {
		t.Fatalf("copy in = %v, %v; want %d bytes, 3 entries", resp, err, len(data))
	}

	out, err := h.client.CopyOut(ctx, &qtdv1.CopyOutRequest{SandboxId: sb.GetId(), Path: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for {
		msg, err := out.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
		got = append(got, msg.GetTarChunk()...)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("copy out returned %d bytes, want the %d copied in", len(got), len(data))
	}

	diff, err := h.client.Diff(ctx, &qtdv1.DiffRequest{SandboxId: sb.GetId()})
	if err != nil || len(diff.GetChanges()) != 1 || diff.GetChanges()[0].GetPath() != "/work" || diff.GetChanges()[0].GetKind() != qtdv1.Change_KIND_ADDED {
		t.Errorf("diff = %v, %v", diff, err)
	}

	errs := []struct {
		name string
		err  error
		code codes.Code
	}{
		{"diff against another sandbox", func() error {
			_, err := h.client.Diff(ctx, &qtdv1.DiffRequest{SandboxId: sb.GetId(), AgainstSandboxId: sb.GetId()})
			return err
		}(), codes.Unimplemented},
		{"diff unknown", func() error { _, err := h.client.Diff(ctx, &qtdv1.DiffRequest{SandboxId: "abcdef012345"}); return err }(), codes.NotFound},
		{"copy out relative path", func() error {
			s, _ := h.client.CopyOut(ctx, &qtdv1.CopyOutRequest{SandboxId: sb.GetId(), Path: "etc/passwd"})
			_, err := s.Recv()
			return err
		}(), codes.InvalidArgument},
		{"copy out dotdot", func() error {
			s, _ := h.client.CopyOut(ctx, &qtdv1.CopyOutRequest{SandboxId: sb.GetId(), Path: "/work/../../etc"})
			_, err := s.Recv()
			return err
		}(), codes.InvalidArgument},
		{"copy in without header", func() error {
			s, _ := h.client.CopyIn(ctx)
			_ = s.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_TarChunk{TarChunk: []byte("x")}})
			_, err := s.CloseAndRecv()
			return err
		}(), codes.InvalidArgument},
		{"copy in bad dir", func() error {
			s, _ := h.client.CopyIn(ctx)
			_ = s.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_Header_{Header: &qtdv1.CopyInRequest_Header{SandboxId: sb.GetId(), Dir: "work"}}})
			_, err := s.CloseAndRecv()
			return err
		}(), codes.InvalidArgument},
	}
	for _, e := range errs {
		if status.Code(e.err) != e.code {
			t.Errorf("%s: %v, want %v", e.name, e.err, e.code)
		}
	}
}

func readEvents(t *testing.T, h *harness, req *qtdv1.EventsRequest) ([]*qtdv1.EventsResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := h.client.Events(ctx, req)
	if err != nil {
		return nil, err
	}
	var out []*qtdv1.EventsResponse
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, m)
	}
}

func TestEventsRPC(t *testing.T) {
	h := newHarness(t, 0, nil)
	sb := h.create(t, &qtdv1.CreateRequest{})
	id := sb.GetId()
	for _, cmd := range []string{"id", "uname"} {
		if r := h.exec(t, start(id, cmd)); r.err != nil {
			t.Fatal(r.err)
		}
	}
	all, err := readEvents(t, h, &qtdv1.EventsRequest{SandboxId: id})
	if err != nil || len(all) != 2 || all[0].GetKind() != "exec" {
		t.Fatalf("events = %v, %v", all, err)
	}
	for _, e := range all {
		if _, err := events.Validate(e.GetEventJson()); err != nil || !strings.Contains(string(e.GetEventJson()), e.GetId()) {
			t.Errorf("event %s: %v", e.GetEventJson(), err)
		}
	}
	if got, _ := readEvents(t, h, &qtdv1.EventsRequest{SandboxId: id, AfterEventId: all[0].GetId()}); len(got) != 1 || got[0].GetId() != all[1].GetId() {
		t.Errorf("after first = %v", got)
	}
	if got, _ := readEvents(t, h, &qtdv1.EventsRequest{SandboxId: id, Kinds: []string{"net", "dns"}}); len(got) != 0 {
		t.Errorf("kind filter = %v", got)
	}
	for _, bad := range []struct {
		req  *qtdv1.EventsRequest
		code codes.Code
	}{
		{&qtdv1.EventsRequest{SandboxId: id, Kinds: []string{"syscall"}}, codes.InvalidArgument},
		{&qtdv1.EventsRequest{SandboxId: id, AfterEventId: "ev_nope"}, codes.NotFound},
		{&qtdv1.EventsRequest{SandboxId: "../x"}, codes.InvalidArgument},
		{&qtdv1.EventsRequest{SandboxId: "abcdef012345"}, codes.NotFound},
	} {
		if _, err := readEvents(t, h, bad.req); status.Code(err) != bad.code {
			t.Errorf("%v: %v, want %v", bad.req, err, bad.code)
		}
	}

	// Follow: replay, then live events, then the stream ends when the sandbox is removed.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := h.client.Events(ctx, &qtdv1.EventsRequest{SandboxId: id, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 10)
	ended := make(chan error, 1)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				ended <- err
				return
			}
			got <- string(m.GetEventJson())
		}
	}()
	for range 2 {
		<-got
	}
	if r := h.exec(t, start(id, "whoami")); r.err != nil {
		t.Fatal(r.err)
	}
	select {
	case e := <-got:
		if !strings.Contains(e, `"whoami"`) {
			t.Errorf("live event = %s", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follow did not deliver a new event")
	}
	if _, err := h.client.Destroy(context.Background(), &qtdv1.DestroyRequest{SandboxId: id}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ended:
		if !errors.Is(err, io.EOF) {
			t.Errorf("follow ended with %v, want EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follow did not end when the sandbox was removed")
	}
}
