package netpol

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/honeytoken"
)

func TestRulesNormalize(t *testing.T) {
	r, err := Rules{Mode: ModeAllow, Allow: []string{"PyPI.org.", "pypi.org", " files.pythonhosted.org"}}.Normalize()
	if err != nil || strings.Join(r.Allow, ",") != "pypi.org,files.pythonhosted.org" {
		t.Fatalf("Normalize = %+v, %v", r, err)
	}
	for _, bad := range []Rules{
		{Mode: ModeAllow},
		{Mode: ModeAllow, Allow: []string{"localhost"}},
		{Mode: ModeAllow, Allow: []string{"*.example.com"}},
		{Mode: ModeAllow, Allow: []string{"exa mple.com"}},
		{Mode: ModeAllow, Allow: []string{"-bad.com"}},
		{Mode: ModeLog, Allow: []string{"x.com"}},
		{Mode: 0},
	} {
		if _, err := bad.Normalize(); err == nil {
			t.Errorf("%+v: want an error", bad)
		}
	}
	for name, want := range map[string]bool{
		"pypi.org": true, "PYPI.ORG.": true, "www.pypi.org": true, "files.pythonhosted.org": true,
		"evilpypi.org": false, "pypi.org.evil.com": false, "pythonhosted.org": false, "org": false,
	} {
		if got := r.allows(name); got != want {
			t.Errorf("allows(%q) = %v", name, got)
		}
	}
}

type recorded struct {
	mu  sync.Mutex
	evs []events.Payload
}

func (r *recorded) emit(p events.Payload) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, p)
}

func (r *recorded) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.evs {
		out = append(out, string(e.Kind()))
	}
	return out
}

var testPool = netip.MustParsePrefix("10.231.0.0/16")

func allowPolicy(t *testing.T, rec *recorded) *sandboxPolicy {
	t.Helper()
	r, err := Rules{Mode: ModeAllow, Allow: []string{"pypi.org"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return newSandboxPolicy("sb", r, rec.emit, testPool)
}

func TestDecide(t *testing.T) {
	p := allowPolicy(t, &recorded{})
	pypi := netip.MustParseAddrPort("151.101.0.223:443")
	p.learn([]netip.Addr{pypi.Addr()}, 30*time.Second)
	other := netip.MustParseAddrPort("1.1.1.1:443")
	tests := []struct {
		name   string
		dst    netip.AddrPort
		h      hello
		reason string // "" = allowed
	}{
		{"allowed SNI", pypi, hello{Proto: "tls", SNI: "pypi.org"}, ""},
		{"allowed subdomain SNI", pypi, hello{Proto: "tls", SNI: "test.pypi.org"}, ""},
		{"allowed HTTP Host", netip.AddrPortFrom(pypi.Addr(), 80), hello{Proto: "http", Host: "pypi.org"}, ""},
		{"direct IP", other, hello{Proto: "tls", SNI: "pypi.org"}, "direct_ip"},
		{"fronting: other SNI on an allowed IP", pypi, hello{Proto: "tls", SNI: "example.com"}, "sni_mismatch"},
		{"TLS without SNI", pypi, hello{Proto: "tls"}, "sni_mismatch"},
		{"ECH", pypi, hello{Proto: "tls", SNI: "pypi.org", ECH: true}, "sni_mismatch"},
		{"other HTTP Host", netip.AddrPortFrom(pypi.Addr(), 80), hello{Proto: "http", Host: "evil.com"}, "sni_mismatch"},
		{"unknown protocol", netip.AddrPortFrom(pypi.Addr(), 22), hello{}, "not_allowlisted"},
	}
	for _, tt := range tests {
		d := p.decide(tt.dst, tt.h)
		if (d == nil) != (tt.reason == "") || (d != nil && d.Reason != tt.reason) {
			t.Errorf("%s: decide = %v, want %q", tt.name, d, tt.reason)
		}
	}
	// Learned addresses expire.
	p.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if d := p.decide(pypi, hello{Proto: "tls", SNI: "pypi.org"}); d == nil || d.Reason != "direct_ip" {
		t.Errorf("after expiry: %v", d)
	}
	// Log mode allows everything that is not Forbidden.
	lp := newSandboxPolicy("sb", Rules{Mode: ModeLog}, nil, testPool)
	if d := lp.decide(other, hello{}); d != nil {
		t.Errorf("log mode: %v", d)
	}
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func parseResp(t *testing.T, b []byte) (dnsmessage.Header, []string) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	var ips []string
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, netip.AddrFrom4(r.A).String())
		}
	}
	return m.Header, ips
}

func TestAnswerDNS(t *testing.T) {
	rec := &recorded{}
	p := allowPolicy(t, rec)
	asked := 0
	up := func(_ context.Context, name dnsmessage.Name) ([]netip.Addr, uint32, dnsmessage.RCode, error) {
		asked++
		if name.String() != "pypi.org." {
			t.Errorf("upstream asked for %s", name)
		}
		// A rebinding answer (metadata) mixed in with a real one.
		return []netip.Addr{netip.MustParseAddr("151.101.0.223"), netip.MustParseAddr("169.254.169.254")}, 600, dnsmessage.RCodeSuccess, nil
	}
	local := func() []netip.Addr { return nil }
	ctx := context.Background()

	h, ips := parseResp(t, p.answerDNS(ctx, query(t, "pypi.org.", dnsmessage.TypeA), up, local))
	if h.ID != 0x4242 || !h.Response || h.RCode != dnsmessage.RCodeSuccess || strings.Join(ips, ",") != "151.101.0.223" {
		t.Errorf("A pypi.org: %+v %v", h, ips)
	}
	if !p.wasResolved(netip.MustParseAddr("151.101.0.223")) || p.wasResolved(netip.MustParseAddr("169.254.169.254")) {
		t.Error("learned the wrong addresses")
	}
	h, ips = parseResp(t, p.answerDNS(ctx, query(t, "pypi.org.", dnsmessage.TypeAAAA), up, local))
	if h.RCode != dnsmessage.RCodeSuccess || len(ips) != 0 {
		t.Errorf("AAAA: %+v %v", h, ips)
	}
	h, _ = parseResp(t, p.answerDNS(ctx, query(t, "example.com.", dnsmessage.TypeA), up, local))
	if h.RCode != dnsmessage.RCodeNameError {
		t.Errorf("example.com: %+v", h)
	}
	if asked != 1 {
		t.Errorf("upstream asked %d times, want 1 (only the allowed A query)", asked)
	}
	if got := strings.Join(rec.kinds(), ","); got != "policy_denied,dns,dns,policy_denied,dns" {
		t.Errorf("events %s", got)
	}
	for _, e := range rec.evs {
		if d, ok := e.(events.DNS); ok && d.QName == "example.com" && (d.Allowed || d.RCode != "NXDOMAIN") {
			t.Errorf("denied query event: %+v", d)
		}
		if d, ok := e.(events.PolicyDenied); ok && d.Target == "pypi.org" && d.Reason != "metadata" {
			t.Errorf("rebinding event: %+v", d)
		}
	}
	for _, junk := range [][]byte{nil, {1, 2, 3}, query(t, "pypi.org.", dnsmessage.TypeA)[:12]} {
		if r := p.answerDNS(ctx, junk, up, local); r != nil {
			t.Errorf("answered junk %x", junk)
		}
	}
}

func TestPeekHello(t *testing.T) {
	t.Run("tls", func(t *testing.T) {
		c, s := net.Pipe()
		defer func() { _ = c.Close() }()
		go func() {
			_ = tls.Client(c, &tls.Config{ServerName: "PyPI.org", MinVersion: tls.VersionTLS12}).Handshake()
		}()
		buf, h := peekHello(s, 5*time.Second)
		if h.Proto != "tls" || h.SNI != "pypi.org" || h.ECH || len(buf) < 100 || buf[0] != 0x16 {
			t.Errorf("hello %+v (%d bytes)", h, len(buf))
		}
	})
	t.Run("http", func(t *testing.T) {
		c, s := net.Pipe()
		defer func() { _ = c.Close() }()
		go func() {
			req, _ := http.NewRequest(http.MethodGet, "http://Example.com:8080/x", nil)
			_ = req.Write(c)
		}()
		buf, h := peekHello(s, 5*time.Second)
		if h.Proto != "http" || h.Host != "example.com" || !strings.HasPrefix(string(buf), "GET /x HTTP/1.1\r\n") {
			t.Errorf("hello %+v %q", h, buf)
		}
	})
	t.Run("server speaks first", func(t *testing.T) {
		c, s := net.Pipe()
		defer func() { _ = c.Close() }()
		buf, h := peekHello(s, 50*time.Millisecond)
		if h.Proto != "" || len(buf) != 0 {
			t.Errorf("hello %+v %q", h, buf)
		}
	})
}

func TestErrorsAreDenials(t *testing.T) {
	var err error = &Denial{Reason: "direct_ip", Target: "1.1.1.1:443"}
	var d *Denial
	if !errors.As(err, &d) || d.Reason != "direct_ip" || !strings.Contains(err.Error(), "1.1.1.1:443") {
		t.Error(err)
	}
}

func TestHoneyInDNS(t *testing.T) {
	set, err := honeytoken.Generate("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorded{}
	r, _ := Rules{Mode: ModeLog, Honey: honeytoken.NewMatcher(set)}.Normalize()
	p := newSandboxPolicy("sb", r, rec.emit, testPool)
	up := func(context.Context, dnsmessage.Name) ([]netip.Addr, uint32, dnsmessage.RCode, error) {
		return nil, 0, dnsmessage.RCodeNameError, nil
	}
	akid := strings.ToLower(set.Tokens[1].Secrets[0])
	p.answerDNS(context.Background(), query(t, akid+".exfil.example.", dnsmessage.TypeA), up, func() []netip.Addr { return nil })
	p.answerDNS(context.Background(), query(t, akid+".exfil.example.", dnsmessage.TypeAAAA), up, func() []netip.Addr { return nil }) // the same sighting
	p.answerDNS(context.Background(), query(t, "pypi.org.", dnsmessage.TypeA), up, func() []netip.Addr { return nil })
	n := 0
	for _, e := range rec.evs {
		if h, ok := e.(events.Honeytoken); ok {
			n++
			if h.Trigger != "egress_dns" || h.TokenKind != honeytoken.KindAWS || !strings.HasPrefix(h.Dst, akid) {
				t.Errorf("%+v", h)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d honeytoken events, want 1: %v", n, rec.kinds())
	}
}
