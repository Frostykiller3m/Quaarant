//go:build linux

package netpol

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// itestManager is a Manager with its own tag and pool, so tests and an installed qtd can run
// side by side.
func itestManager(t *testing.T) (*Manager, *decisions) {
	t.Helper()
	if os.Getenv("QT_ITEST") != "1" || os.Geteuid() != 0 {
		t.Skip("integration test: QT_ITEST=1 as root (needs ip, nft)")
	}
	d := &decisions{}
	n := rand.IntN(200) // 10.232.<n>.0/24 (63 links)
	m, err := New(context.Background(), Config{
		Tag: fmt.Sprintf("t%02x", n), Pool: netip.MustParsePrefix(fmt.Sprintf("10.232.%d.0/24", n)),
		ProxyPort: DefaultProxyPort, OnDecision: d.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
		assertNothingLeft(t, m.cfg.Tag)
	})
	return m, d
}

type decisions struct {
	mu sync.Mutex
	ds []Decision
}

func (d *decisions) add(x Decision) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ds = append(d.ds, x)
}

func (d *decisions) find(dst string) (Decision, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, x := range d.ds {
		if x.Dst.String() == dst {
			return x, true
		}
	}
	return Decision{}, false
}

// assertNothingLeft: no link, namespace or nftables table with the tag survives.
func assertNothingLeft(t *testing.T, tag string) {
	t.Helper()
	links, _ := filepath.Glob("/sys/class/net/" + tag + "n*")
	nss, _ := filepath.Glob("/run/netns/" + tag + "-*")
	out, _ := exec.Command("nft", "list", "tables").Output()
	if len(links) > 0 || len(nss) > 0 || strings.Contains(string(out), tableName(tag)) {
		t.Errorf("left behind: links %v, netns %v, tables %q", links, nss, out)
	}
}

// hostListener accepts on addr and counts connections that reached it.
func hostListener(t *testing.T, addr string) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	n := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_, _ = c.Write([]byte("host-secret\n"))
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), n
}

// connect runs a TCP connect from inside the namespace and returns what it read.
func connect(t *testing.T, ns, dst string) (string, error) {
	t.Helper()
	host, port, _ := net.SplitHostPort(dst)
	script := fmt.Sprintf(`exec 3<>/dev/tcp/%s/%s && printf 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' >&3 && timeout 3 head -c 64 <&3`, host, port, host)
	out, err := exec.Command("ip", "netns", "exec", ns, "timeout", "8", "bash", "-c", script).CombinedOutput()
	return string(out), err
}

// hostAddrs are the host's IPv4 addresses outside loopback and sandbox links.
func hostAddrs(pool netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, a := range localAddrs() {
		if a.Is4() && !a.IsLoopback() && !pool.Contains(a) {
			out = append(out, a)
		}
	}
	return out
}

// TestITestLinkIsolation: from inside a sandbox link, only public IPv4 TCP gets out (through
// the proxy); the host (any of its addresses, any port), LAN, link-local/metadata, other
// sandboxes, UDP and IPv6 do not.
func TestITestLinkIsolation(t *testing.T) {
	m, d := itestManager(t)
	ctx := context.Background()
	a, err := m.Attach(ctx, "probe-a", Netns, 0, Rules{Mode: ModeLog}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Attach(ctx, "probe-b", Netns, 0, Rules{Mode: ModeLog}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Something listening everywhere on the host, and inside sandbox b.
	hostAddr, hostHits := hostListener(t, "0.0.0.0:0")
	_, port, _ := net.SplitHostPort(hostAddr)
	bListen := exec.Command("ip", "netns", "exec", b.Netns, "bash", "-c", "while true; do echo b-secret | timeout 5 nc -l -p 8080 -q 0 2>/dev/null || sleep 0.2; done")
	if err := bListen.Start(); err == nil {
		t.Cleanup(func() { _ = bListen.Process.Kill(); _ = bListen.Wait() })
	}

	// Positive control: the internet works through the proxy.
	out, err := connect(t, a.Netns, "1.1.1.1:80")
	if err != nil || !strings.HasPrefix(out, "HTTP/") {
		t.Fatalf("public TCP through the proxy: %v %q", err, out)
	}
	if x, ok := d.find("1.1.1.1:80"); !ok || x.Err != nil {
		t.Errorf("proxy decision for 1.1.1.1:80: %+v %v", x, ok)
	}

	// How each probe must fail: rejected by nftables before the redirect (the proxy never
	// sees it), or never leaving the guest at all.
	const refused, local = "refused", "local"
	type probe struct{ name, dst, how string }
	probes := []probe{
		{"gateway (host)", a.Gateway.String() + ":" + port, refused},
		{"guest loopback", "127.0.0.1:" + port, local}, // the guest's own lo: nothing listens
		{"metadata", "169.254.169.254:80", refused},
		{"LAN", "192.168.1.1:80", refused},
		{"private 10/8", "10.0.0.1:80", refused},
		{"other sandbox", b.Guest.Addr().String() + ":8080", refused},
		{"other sandbox's gateway", b.Gateway.String() + ":" + port, refused},
		{"proxy port on the gateway", a.Gateway.String() + fmt.Sprintf(":%d", DefaultProxyPort), refused},
	}
	for _, h := range hostAddrs(m.cfg.Pool) {
		probes = append(probes, probe{"host address " + h.String(), h.String() + ":" + port, refused})
	}
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			out, err := connect(t, a.Netns, p.dst)
			if err == nil || strings.Contains(out, "secret") || strings.HasPrefix(out, "HTTP/") {
				t.Errorf("%s reachable: %v %q", p.dst, err, out)
			}
			if x, seen := d.find(p.dst); seen {
				t.Errorf("%s reached the proxy: %+v", p.dst, x)
			}
			if p.how == refused && !strings.Contains(out, "refused") {
				t.Errorf("%s: want an immediate refusal, got %v %q", p.dst, err, out)
			}
		})
	}
	if n := hostHits.Load(); n != 0 {
		t.Errorf("the host listener was reached %d times", n)
	}

	// Not TCP: UDP (DNS to a public resolver) and ICMP don't leave; nor does IPv6.
	for name, cmd := range map[string]string{
		"udp (not DNS)": `exec 3<>/dev/udp/1.1.1.1/443; printf 'quic?' >&3; timeout 3 head -c 1 <&3`,
		"icmp ping":     "ping -c 1 -W 2 1.1.1.1",
		"ipv6":          "ping -6 -c 1 -W 2 2606:4700:4700::1111 || ip -6 addr show dev eth0 scope global | grep -q inet6 && exit 0; exit 1",
	} {
		out, err := exec.Command("ip", "netns", "exec", a.Netns, "timeout", "8", "bash", "-c", cmd).CombinedOutput()
		if err == nil {
			t.Errorf("%s got out: %q", name, out)
		}
	}
	// A spoofed source (a public address, or another sandbox) is dropped before the proxy.
	for _, src := range []string{"8.8.4.4", b.Guest.Addr().String()} {
		if out, err := exec.Command("ip", "-n", a.Netns, "addr", "add", src+"/32", "dev", "eth0").CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		out, err := exec.Command("ip", "netns", "exec", a.Netns, "timeout", "8", "bash", "-c",
			"printf 'GET / HTTP/1.0\r\n\r\n' | nc -s "+src+" -w 3 1.1.1.1 80 | head -c 64").CombinedOutput()
		if strings.HasPrefix(string(out), "HTTP/") {
			t.Errorf("spoofed source %s got out: %v %q", src, err, out)
		}
	}
	if err := m.Detach(ctx, b.Sandbox); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/run/netns/" + b.Netns); err == nil {
		t.Error("detach left the namespace")
	}
	time.Sleep(100 * time.Millisecond)
}
