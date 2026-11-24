//go:build linux

package netpol

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// attachWithDNS attaches a netns link and points the namespace's resolv.conf at its gateway
// (`ip netns exec` bind-mounts /etc/netns/<ns>/resolv.conf).
func attachWithDNS(t *testing.T, m *Manager, id string, rules Rules, rec *recorded) *Link {
	t.Helper()
	l, err := m.Attach(context.Background(), id, Netns, 0, rules, rec.emit)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("/etc/netns", l.Netns)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte("nameserver "+l.Gateway.String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return l
}

// curl runs curl inside the namespace: the HTTP status, or an error with curl's message.
func curl(t *testing.T, ns string, args ...string) (string, error) {
	t.Helper()
	a := append([]string{"netns", "exec", ns, "curl", "-sS", "-m", "15", "-o", "/dev/null", "-w", "%{http_code}"}, args...)
	out, err := exec.Command("ip", a...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (r *recorded) find(kind events.Kind, match func(string) bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.evs {
		b, _ := json.Marshal(e)
		if e.Kind() == kind && match(string(b)) {
			return true
		}
	}
	return false
}

func (r *recorded) dump(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.evs {
		b, _ := json.Marshal(e)
		t.Logf("%s %s", e.Kind(), b)
	}
}

func contains(subs ...string) func(string) bool {
	return func(s string) bool {
		for _, x := range subs {
			if !strings.Contains(s, x) {
				return false
			}
		}
		return true
	}
}

// TestITestAllowList: with an allow-list, the allowed site works and nothing else does:
// other names, direct IPs, DNS-over-HTTPS, SNI and Host fronting on an allowed address, and
// metadata. Every query, connection and denial is an event.
func TestITestAllowList(t *testing.T) {
	m, _ := itestManager(t)
	rec := &recorded{}
	l := attachWithDNS(t, m, "allow", Rules{Mode: ModeAllow, Allow: []string{"pypi.org"}}, rec)
	defer func() {
		if t.Failed() {
			rec.dump(t)
		}
	}()

	if code, err := curl(t, l.Netns, "https://pypi.org/simple/six/"); err != nil || code != "200" {
		t.Fatalf("allowed site: %v %s", err, code)
	}
	out, err := exec.Command("ip", "netns", "exec", l.Netns, "getent", "ahostsv4", "pypi.org").Output()
	if err != nil || len(strings.Fields(string(out))) == 0 {
		t.Fatalf("getent pypi.org: %v %q", err, out)
	}
	pypiIP := strings.Fields(string(out))[0]

	for _, c := range []struct {
		name string
		args []string
	}{
		{"other name", []string{"https://example.com/"}},
		{"direct IP", []string{"https://1.1.1.1/"}},
		{"DNS over HTTPS by name", []string{"https://cloudflare-dns.com/dns-query?name=example.com&type=A", "-H", "accept: application/dns-json"}},
		{"DNS over HTTPS by IP", []string{"--resolve", "cloudflare-dns.com:443:1.1.1.1", "https://cloudflare-dns.com/dns-query?name=example.com&type=A"}},
		{"SNI fronting on an allowed address", []string{"--resolve", "example.com:443:" + pypiIP, "https://example.com/"}},
		{"Host fronting on an allowed address", []string{"-H", "Host: example.com", "http://" + pypiIP + "/"}},
		{"metadata", []string{"http://169.254.169.254/latest/meta-data/"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code, err := curl(t, l.Netns, c.args...); err == nil {
				t.Errorf("reachable: HTTP %s", code)
			}
		})
	}
	// DNS to any server is answered by qtd's resolver (NXDOMAIN here); other UDP is refused.
	q := `exec 3<>/dev/udp/8.8.8.8/53; printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x01\x00\x01' >&3; timeout 3 head -c 4 <&3 | od -An -tx1`
	if out, err := exec.Command("ip", "netns", "exec", l.Netns, "bash", "-c", q).CombinedOutput(); err != nil || !strings.Contains(string(out), "12 34 81 83") {
		t.Errorf("DNS to 8.8.8.8: want qtd's NXDOMAIN (12 34 81 83), got %v %q", err, out)
	}
	_ = exec.Command("ip", "netns", "exec", l.Netns, "bash", "-c", "printf x > /dev/udp/8.8.8.8/123").Run()
	time.Sleep(300 * time.Millisecond) // nflog delivery
	for _, w := range []struct {
		kind events.Kind
		has  []string
	}{
		{events.KindDNS, []string{`"qname":"example.org"`, `"allowed":false`}},
		{events.KindPolicyDenied, []string{`"target":"8.8.8.8:123"`, `"reason":"not_allowlisted"`, "(udp)"}},
		{events.KindDNS, []string{`"qname":"pypi.org"`, `"qtype":"A"`, `"allowed":true`, `"answers":[`}},
		{events.KindDNS, []string{`"qname":"example.com"`, `"allowed":false`, `"rcode":"NXDOMAIN"`}},
		{events.KindPolicyDenied, []string{`"policy":"dns"`, `"target":"cloudflare-dns.com"`, `"reason":"not_allowlisted"`}},
		{events.KindNet, []string{`"op":"connect"`, `"sni":"pypi.org"`, `"allowed":true`}},
		{events.KindNet, []string{`"op":"close"`, `"sni":"pypi.org"`, `"bytes_in":`}},
		{events.KindPolicyDenied, []string{`"target":"1.1.1.1:443"`, `"reason":"direct_ip"`}},
		{events.KindPolicyDenied, []string{`"target":"example.com"`, `"reason":"sni_mismatch"`, "TLS SNI"}},
		{events.KindPolicyDenied, []string{`"target":"example.com"`, `"reason":"sni_mismatch"`, "HTTP Host"}},
		{events.KindPolicyDenied, []string{`"target":"169.254.169.254:80"`, `"reason":"metadata"`}},
		{events.KindNet, []string{`"dst_ip":"169.254.169.254"`, `"allowed":false`}},
	} {
		if !rec.find(w.kind, contains(w.has...)) {
			t.Errorf("no %s event with %q", w.kind, w.has)
		}
	}
	// Every event the manager produced is valid against the schema.
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, p := range rec.evs {
		e, err := events.New("allow", events.SourceHost, time.Now(), p)
		if err == nil {
			var raw []byte
			if raw, err = json.Marshal(e); err == nil {
				_, err = events.Validate(raw)
			}
		}
		if err != nil {
			t.Errorf("invalid event %+v: %v", p, err)
		}
	}
}

// TestITestLogMode: everything public works and every connection is recorded with its name.
func TestITestLogMode(t *testing.T) {
	m, _ := itestManager(t)
	rec := &recorded{}
	l := attachWithDNS(t, m, "log", Rules{Mode: ModeLog}, rec)
	defer func() {
		if t.Failed() {
			rec.dump(t)
		}
	}()
	if code, err := curl(t, l.Netns, "https://example.com/"); err != nil || code != "200" {
		t.Fatalf("log mode: %v %s", err, code)
	}
	if code, err := curl(t, l.Netns, "http://1.1.1.1/"); err != nil || !strings.HasPrefix(code, "30") {
		t.Fatalf("log mode, plain HTTP to an IP: %v %s", err, code)
	}
	if _, err := curl(t, l.Netns, "http://169.254.169.254/"); err == nil {
		t.Error("metadata reachable in log mode")
	}
	time.Sleep(300 * time.Millisecond)
	for _, w := range []struct {
		kind events.Kind
		has  []string
	}{
		{events.KindDNS, []string{`"qname":"example.com"`, `"allowed":true`}},
		{events.KindNet, []string{`"op":"connect"`, `"sni":"example.com"`, `"allowed":true`}},
		{events.KindNet, []string{`"op":"close"`, `"sni":"example.com"`, `"bytes_in":`, `"duration_ms":`}},
		{events.KindNet, []string{`"op":"connect"`, `"dst_ip":"1.1.1.1"`, `"http_host":"1.1.1.1"`}},
		{events.KindPolicyDenied, []string{`"reason":"metadata"`}},
	} {
		if !rec.find(w.kind, contains(w.has...)) {
			t.Errorf("no %s event with %q", w.kind, w.has)
		}
	}
}

// TestITestAdoptAndPrune: a restarted manager takes over a live link, and removes links
// nothing owns.
func TestITestAdoptAndPrune(t *testing.T) {
	m, _ := itestManager(t)
	rec := &recorded{}
	l := attachWithDNS(t, m, "keep", Rules{Mode: ModeLog}, rec)
	orphan, err := m.Attach(context.Background(), "orphan", Netns, 0, Rules{Mode: ModeLog}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a qtd restart: stop serving, forget everything, start a new manager.
	m.Release()
	m2, err := New(context.Background(), m.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m2.Close(context.Background()) }) // before m's cleanup (LIFO)
	rec2 := &recorded{}
	if _, err := m2.Adopt("keep", Netns, l.Index, Rules{Mode: ModeLog}, rec2.emit); err != nil {
		t.Fatal(err)
	}
	if err := m2.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/run/netns/" + orphan.Netns); err == nil {
		t.Error("orphan netns survived Prune")
	}
	if _, err := os.Stat("/sys/class/net/" + orphan.Iface); err == nil {
		t.Error("orphan link survived Prune")
	}
	if code, err := curl(t, l.Netns, "https://example.com/"); err != nil || code != "200" {
		t.Fatalf("adopted link: %v %s", err, code)
	}
	if !rec2.find(events.KindNet, contains(`"sni":"example.com"`)) {
		t.Error("the adopted link's events did not reach the new emitter")
	}
}
