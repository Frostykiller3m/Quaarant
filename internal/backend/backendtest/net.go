package backendtest

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

// NetEnv is an Env that can also start sandboxes on a link (internal/netpol).
type NetEnv interface {
	Env
	// Kind is the link the backend takes: a netns (gvisor) or a tap (vm).
	Kind() netpol.Kind
	// Owner is the uid that will open sandbox id's tap (the jailed VMM); unused for a netns.
	Owner(id string) int
	// StartNet is Start with the given network instead of --net=none.
	StartNet(t *testing.T, id string, lim backend.Limits, n backend.Network) backend.Spec
}

type decisions struct {
	mu sync.Mutex
	ds []netpol.Decision
}

func (d *decisions) add(x netpol.Decision) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ds = append(d.ds, x)
}

func (d *decisions) find(dst string) (netpol.Decision, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, x := range d.ds {
		if x.Dst.String() == dst {
			return x, true
		}
	}
	return netpol.Decision{}, false
}

// RunNet probes the network from inside two sandboxes on links: public TCP works (through
// qtd's proxy); the host on every address, the LAN, link-local and cloud metadata, the other
// sandbox, UDP, ICMP and IPv6 do not.
func RunNet(t *testing.T, env NetEnv) {
	n := rand.IntN(200) //nolint:gosec // G404: picks a test pool, not a secret
	d := &decisions{}
	rec := &netEvents{}
	pool := netip.MustParsePrefix(fmt.Sprintf("10.233.%d.0/24", n))
	m, err := netpol.New(context.Background(), netpol.Config{
		Tag: fmt.Sprintf("b%02x", n), Pool: pool, ProxyPort: netpol.DefaultProxyPort, OnDecision: d.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.Background()); err != nil {
			t.Errorf("netpol close: %v", err)
		}
	})
	b := env.Backend()
	lim := backend.Limits{CPUMillis: 1000, MemoryBytes: 256 << 20, PIDs: 64}
	start := func(id string) (*netpol.Link, backend.Spec) {
		l, err := m.Attach(context.Background(), id, env.Kind(), env.Owner(id), netpol.Rules{Mode: netpol.ModeLog}, rec.add)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Detach(context.Background(), id) }) // after the sandbox is gone
		return l, env.StartNet(t, id, lim, l.Network())
	}
	la, a := start("neta")
	lb, sb := start("netb")

	// Listeners: on every host address, and inside sandbox b.
	ln, err := net.Listen("tcp4", "0.0.0.0:0") //nolint:gosec // G102: on purpose: every host address must be probed
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var hostHits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hostHits.Add(1)
			_, _ = c.Write([]byte("host-secret\n"))
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if p, err := b.Exec(ctx, sb.ID, Sh("while true; do echo b-secret | nc -l -p 8080; done")); err == nil {
		t.Cleanup(func() { _ = p.Signal(9) })
	}

	t.Run("guest sees its link", func(t *testing.T) {
		r := Exec(t, b, a.ID, Sh("ip -4 addr show eth0; ip route"))
		if !strings.Contains(r.Stdout, la.Guest.String()) || !strings.Contains(r.Stdout, "default via "+la.Gateway.String()) {
			t.Errorf("guest network: %q %q", r.Stdout, r.Stderr)
		}
	})
	t.Run("public TCP goes through the proxy", func(t *testing.T) {
		r := Exec(t, b, a.ID, Sh(`printf 'GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n' | nc -w 5 1.1.1.1 80 | head -c 12`))
		if !strings.HasPrefix(r.Stdout, "HTTP/1.") {
			t.Fatalf("public TCP: %q %q", r.Stdout, r.Stderr)
		}
		if x, ok := d.find("1.1.1.1:80"); !ok || x.Err != nil || x.Sandbox != a.ID {
			t.Errorf("proxy decision: %+v %v", x, ok)
		}
	})

	// Every forbidden destination is refused in the host kernel before the redirect: the
	// connect fails at once and the proxy never sees it.
	type probe struct{ name, dst string }
	probes := []probe{
		{"gateway (host)", la.Gateway.String() + ":" + port},
		{"metadata", "169.254.169.254:80"},
		{"LAN", "192.168.1.1:80"},
		{"private 10/8", "10.0.0.1:80"},
		{"private 172.16/12", "172.16.0.1:80"},
		{"other sandbox", lb.Guest.Addr().String() + ":8080"},
		{"other sandbox's gateway", lb.Gateway.String() + ":" + port},
		{"the proxy itself", la.Gateway.String() + fmt.Sprintf(":%d", netpol.DefaultProxyPort)},
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() && !ip.IsLoopback() && !pool.Contains(ip.Unmap()) {
					probes = append(probes, probe{"host address " + ip.Unmap().String(), ip.Unmap().String() + ":" + port})
				}
			}
		}
	}
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			host, prt, _ := net.SplitHostPort(p.dst)
			t0 := time.Now()
			r := Exec(t, b, a.ID, Sh(fmt.Sprintf("echo hi | nc -w 3 %s %s; echo rc=$?", host, prt)))
			// A reset fails the connect at once; a silent drop would take nc's 3 s timeout.
			if strings.Contains(r.Stdout, "secret") || strings.Contains(r.Stdout, "rc=0") || time.Since(t0) > 2*time.Second {
				t.Errorf("%s: want an immediate refusal, got %q %q after %v", p.dst, r.Stdout, r.Stderr, time.Since(t0))
			}
			if x, seen := d.find(p.dst); seen {
				t.Errorf("%s reached the proxy: %+v", p.dst, x)
			}
		})
	}
	if n := hostHits.Load(); n != 0 {
		t.Errorf("the host listener was reached %d times", n)
	}

	t.Run("DNS to any server is answered by qtd", func(t *testing.T) {
		r := Exec(t, b, a.ID, Sh("timeout 10 nslookup example.com 8.8.8.8"))
		if r.Status.Code != 0 || !rec.has(`"qname":"example.com"`, `"allowed":true`) {
			t.Errorf("nslookup via 8.8.8.8: %q %q; recorded: %v", r.Stdout, r.Stderr, rec.has(`"qname":"example.com"`))
		}
	})
	t.Run("other UDP is refused and recorded", func(t *testing.T) {
		_ = Exec(t, b, a.ID, Sh("echo x | nc -u -w 1 8.8.8.8 123; true"))
		deadline := time.Now().Add(2 * time.Second)
		for !rec.has(`"target":"8.8.8.8:123"`, `"reason":"not_allowlisted"`) {
			if time.Now().After(deadline) {
				t.Fatal("no policy_denied event for UDP to 8.8.8.8:123")
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	for _, p := range []struct{ name, script string }{
		{"ICMP", "ping -c 1 -W 2 1.1.1.1"},
		{"IPv6", "ping -6 -c 1 -W 2 2606:4700:4700::1111"},
	} {
		t.Run(p.name, func(t *testing.T) {
			if r := Exec(t, b, a.ID, Sh(p.script+" >/dev/null 2>&1; echo rc=$?")); r.Stdout == "rc=0\n" {
				t.Errorf("%s got out", p.name)
			}
		})
	}
}

// netEvents records a link's events as JSON lines.
type netEvents struct {
	mu    sync.Mutex
	lines []string
}

func (r *netEvents) add(p events.Payload) {
	b, _ := json.Marshal(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, string(p.Kind())+" "+string(b))
}

func (r *netEvents) has(subs ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.lines {
		ok := true
		for _, s := range subs {
			ok = ok && strings.Contains(l, s)
		}
		if ok {
			return true
		}
	}
	return false
}
