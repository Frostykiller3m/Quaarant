//go:build linux

package vet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
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
	"github.com/Frostykiller3m/Quaarant/internal/daemon"
	"github.com/Frostykiller3m/Quaarant/internal/image"
	"github.com/Frostykiller3m/Quaarant/internal/netpol"
	"github.com/Frostykiller3m/Quaarant/internal/report"
)

// qtd starts a real qtd (gvisor, sandbox networking) on a private socket.
func qtd(t *testing.T) qtdv1.SandboxServiceClient {
	t.Helper()
	if os.Getenv("QT_ITEST") != "1" || os.Geteuid() != 0 {
		t.Skip("integration test: QT_ITEST=1 as root, with runsc, nftables and network")
	}
	runsc, err := exec.LookPath("runsc")
	if err != nil {
		t.Skip("runsc not on PATH")
	}
	dir := t.TempDir()
	data, state := filepath.Join(dir, "data"), filepath.Join(dir, "runsc")
	t.Cleanup(func() { // runsc may pin it more than once when sandboxes start in parallel
		for range 64 {
			if exec.Command("umount", "-l", filepath.Join(state, "null-netns")).Run() != nil {
				break
			}
		}
	})
	agent := filepath.Join(dir, "qt-agent")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", agent, "github.com/Frostykiller3m/Quaarant/cmd/qt-agent")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qt-agent: %v\n%s", err, out)
	}
	be, err := gvisor.New(gvisor.Config{Runsc: runsc, StateDir: state, AgentPath: agent, CgroupParent: "/quarantine-itest-vet"})
	if err != nil {
		t.Fatal(err)
	}
	n := rand.IntN(200)
	nm, err := netpol.New(context.Background(), netpol.Config{
		Tag: fmt.Sprintf("v%02x", n), Pool: netip.MustParsePrefix(fmt.Sprintf("10.235.%d.0/24", n)),
		ProxyPort: netpol.DefaultProxyPort, DNSPort: netpol.DefaultDNSPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nm.Close(context.Background()) })
	svc, err := daemon.New(daemon.Options{DataDir: data, Backends: []backend.Backend{be}, Images: image.NewStore(filepath.Join(data, "images")), Net: nm})
	if err != nil {
		t.Fatal(err)
	}
	sockDir, _ := os.MkdirTemp("", "qtd-vet")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "qtd.sock")
	lis, authz, err := daemon.Listen(sock, "quarantine", slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return qtdv1.NewSandboxServiceClient(conn)
}

func sandboxes(t *testing.T, c qtdv1.SandboxServiceClient) []*qtdv1.Sandbox {
	t.Helper()
	l, err := c.List(context.Background(), &qtdv1.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return l.GetSandboxes()
}

// TestITestVet: qt run <git-url> end to end on a real repository.
func TestITestVet(t *testing.T) {
	c := qtd(t)
	repo, err := ParseRepo("https://github.com/octocat/Hello-World")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Run("declined", func(t *testing.T) {
		var out, errb bytes.Buffer
		shown := false
		_, err := Run(ctx, Options{Client: c, Repo: repo, Out: &out, Err: &errb, Approve: func(p *Plan) bool { shown = p.Image != ""; return false }})
		if !errors.Is(err, ErrNotApproved) || !shown {
			t.Fatalf("Run = %v (plan shown: %v)\n%s", err, shown, errb.String())
		}
		if left := sandboxes(t, c); len(left) != 0 {
			t.Errorf("a declined plan left sandboxes: %v", left)
		}
		if !strings.Contains(errb.String(), "network: github.com only") || !strings.Contains(errb.String(), "Plan for https://github.com/octocat/Hello-World") {
			t.Errorf("stderr:\n%s", errb.String())
		}
	})

	t.Run("approved", func(t *testing.T) {
		var out, errb bytes.Buffer
		res, err := Run(ctx, Options{
			Client: c, Repo: repo, Out: &out, Err: &errb, Approve: func(*Plan) bool { return true },
			// A "test command" that goes looking for credentials.
			Command: []string{"sh", "-c", "cat README; cat ~/.aws/credentials >/dev/null"},
		})
		if err != nil {
			t.Fatalf("Run: %v\n%s", err, errb.String())
		}
		t.Cleanup(func() { _, _ = c.Destroy(context.Background(), &qtdv1.DestroyRequest{SandboxId: res.Sandbox}) })
		if !strings.Contains(out.String(), "Hello World!") {
			t.Errorf("the repository did not reach the run sandbox:\n%s", out.String())
		}
		r := res.Report
		if r == nil || r.Verdict != report.Suspicious || !strings.Contains(out.String(), "Planted credentials were read") {
			t.Errorf("report: %+v\n%s", r, out.String())
		}
		left := sandboxes(t, c)
		if len(left) != 1 || left[0].GetId() != res.Sandbox || left[0].GetLabels()["qt.vet"] != "github.com/Hello-World" {
			t.Errorf("sandboxes after the run (the clone sandbox must be gone): %v", left)
		}
		t.Logf("plan: %s, %s; report: %s with %d findings", res.Plan.Image, res.Plan.Net.String(), r.Verdict, len(r.Findings))
	})
}
