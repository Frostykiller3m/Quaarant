//go:build linux

package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/backend/fake"
	"github.com/Frostykiller3m/Quaarant/internal/daemon"
	"github.com/Frostykiller3m/Quaarant/internal/image"
)

type images struct{ rootfs string }

func (i images) Pull(_ context.Context, ref string) (image.Image, error) {
	return image.Image{Ref: "example.com/" + ref + "@sha256:" + strings.Repeat("0", 64), RootFS: i.rootfs, Config: v1.Config{}}, nil
}

// qtd starts an in-process qtd (fake backend) and returns its socket and data dir.
func qtd(t *testing.T) (socket, data string, be *fake.Backend) {
	t.Helper()
	dir := t.TempDir()
	data = filepath.Join(dir, "data")
	be = fake.New(backend.IsolationGVisor, backend.CapPTY)
	svc, err := daemon.New(daemon.Options{DataDir: data, Backends: []backend.Backend{be}, Images: images{rootfs: dir}})
	if err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "qtcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	socket = filepath.Join(sockDir, "qtd.sock")
	lis, authz, err := daemon.Listen(socket, "no-such-group-qt", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Serve(ctx, lis, svc, authz) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return socket, data, be
}

type cliResult struct {
	stdout, stderr string
	code           int
}

func runQt(t *testing.T, socket string, stdin string, args ...string) cliResult {
	t.Helper()
	var out, errb bytes.Buffer
	root := NewRootCommand(&out, &errb)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"--socket", socket}, args...))
	code := exitCode(root.Execute(), &errb)
	return cliResult{out.String(), errb.String(), code}
}

func TestCLIRunExecLsRm(t *testing.T) {
	socket, data, be := qtd(t)
	be.ExitCodes["false"] = 3

	r := runQt(t, socket, "", "run", "alpine", "--", "sh", "-c", "echo hi")
	if r.code != 0 || r.stdout != "sh -c echo hi\n" {
		t.Fatalf("run = %+v", r)
	}
	m := regexp.MustCompile(`sandbox ([0-9a-f]{12})`).FindStringSubmatch(r.stderr)
	if m == nil {
		t.Fatalf("no sandbox id on stderr: %q", r.stderr)
	}
	id := m[1]

	if r := runQt(t, socket, "", "exec", id, "--", "ls", "-la"); r.code != 0 || r.stdout != "ls -la\n" {
		t.Errorf("exec = %+v", r)
	}
	if r := runQt(t, socket, "", "exec", id, "false"); r.code != 3 || r.stderr != "" {
		t.Errorf("exec false = %+v, want exit 3 and no qt error", r)
	}
	if r := runQt(t, socket, "", "shell", id); r.code != 0 || r.stdout != "/bin/sh\n" {
		t.Errorf("shell = %+v", r)
	}
	if r := runQt(t, socket, "", "ls"); r.code != 0 || !strings.Contains(r.stdout, id) || !strings.Contains(r.stdout, "running") || !strings.Contains(r.stdout, "gvisor") {
		t.Errorf("ls = %+v", r)
	}
	if r := runQt(t, socket, "", "ls", "-q"); r.stdout != id+"\n" {
		t.Errorf("ls -q = %+v", r)
	}
	if r := runQt(t, socket, "", "ls", "--json"); !regexp.MustCompile(`"id":\s+"` + id + `"`).MatchString(r.stdout) {
		t.Errorf("ls --json = %+v", r)
	}

	// --rm removes the sandbox even when the command fails, and the exit code passes through.
	if r := runQt(t, socket, "", "run", "--rm", "alpine", "false"); r.code != 3 {
		t.Errorf("run --rm false = %+v", r)
	}
	if r := runQt(t, socket, "", "rm", "--all"); r.code != 0 || r.stdout != id+"\n" {
		t.Errorf("rm --all = %+v", r)
	}
	if r := runQt(t, socket, "", "ls", "-q"); r.stdout != "" {
		t.Errorf("ls after rm = %+v", r)
	}
	des, err := os.ReadDir(filepath.Join(data, "sandboxes"))
	if err != nil || len(des) != 0 {
		t.Errorf("data dir after rm: %v %v", des, err)
	}
	if be.Len() != 0 {
		t.Errorf("backend has %d sandboxes left", be.Len())
	}
}

func TestCLIErrors(t *testing.T) {
	socket, _, _ := qtd(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"run without command", []string{"run", "alpine"}, "missing COMMAND"},
		{"net policy", []string{"run", "--net=log", "alpine", "true"}, "only --net=none"},
		{"unknown sandbox", []string{"exec", "abcdef123456", "true"}, "no sandbox abcdef123456"},
		{"rm without ids", []string{"rm"}, "give sandbox ids"},
		{"vm unavailable", []string{"run", "--isolation=vm", "alpine", "true"}, "not available on this host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runQt(t, socket, "", tt.args...)
			if r.code != 1 || !strings.Contains(r.stderr, tt.want) {
				t.Errorf("%v = %+v, want exit 1 with %q", tt.args, r, tt.want)
			}
		})
	}
	r := runQt(t, filepath.Join(t.TempDir(), "nope.sock"), "", "ls")
	if r.code != 1 || !strings.Contains(r.stderr, "cannot reach qtd") {
		t.Errorf("ls with no daemon = %+v", r)
	}
}

func TestCLICopyAndDiff(t *testing.T) {
	socket, _, _ := qtd(t)
	r := runQt(t, socket, "", "run", "-q", "alpine", "true")
	if r.code != 0 {
		t.Fatalf("run: %+v", r)
	}
	id := strings.TrimSpace(runQt(t, socket, "", "ls", "-q").stdout)

	src := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "f.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := runQt(t, socket, "", "cp", src, id+":/work"); r.code != 0 || !strings.Contains(r.stderr, "copied 3 entries") {
		t.Fatalf("cp in = %+v", r)
	}
	// The fake backend reports each copy-in target as added.
	if r := runQt(t, socket, "", "diff", id); r.code != 0 || !regexp.MustCompile(`(?m)^A\s+\S+\s+\S+.*/work$`).MatchString(r.stdout) || !strings.Contains(r.stderr, "1 added, 0 modified, 0 deleted") {
		t.Errorf("diff = %+v", r)
	}
	if r := runQt(t, socket, "", "diff", "--json", id); !strings.Contains(r.stdout, `"KIND_ADDED"`) {
		t.Errorf("diff --json = %+v", r)
	}
	// Out again: the fake returns the same tar, which unpacks as repo/sub/f.txt.
	out := t.TempDir()
	if r := runQt(t, socket, "", "cp", id+":/work", out); r.code != 0 {
		t.Fatalf("cp out = %+v", r)
	}
	if b, err := os.ReadFile(filepath.Join(out, "repo", "sub", "f.txt")); err != nil || string(b) != "payload" {
		t.Errorf("copied out file = %q, %v", b, err)
	}
	if r := runQt(t, socket, "", "cp", id+":/work", "-"); r.code != 0 || !strings.Contains(r.stdout, "payload") {
		t.Errorf("cp to stdout = code %d, %d bytes", r.code, len(r.stdout))
	}
	for _, args := range [][]string{{"cp", "a", "b"}, {"cp", id + ":/a", id + ":/b"}, {"cp", src, id + ":relative"}} {
		if r := runQt(t, socket, "", args...); r.code != 1 {
			t.Errorf("%v = %+v, want an error", args, r)
		}
	}
}
