package netpol

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

const (
	minLearn     = time.Minute // an answer's IPs stay connectable at least this long
	maxLearn     = time.Hour
	maxGuestTTL  = 300 // seconds: the TTL the guest is told, at most
	maxAnswers   = 32
	maxRemembers = 4096 // resolved IPs kept per sandbox
)

// sandboxPolicy is one sandbox's rules and what its resolver has answered.
type sandboxPolicy struct {
	id    string
	rules Rules
	emit  Emitter
	pool  netip.Prefix
	now   func() time.Time

	mu       sync.Mutex
	resolved map[netip.Addr]time.Time // IP -> until when connections to it may be allowed
}

func newSandboxPolicy(id string, rules Rules, emit Emitter, pool netip.Prefix) *sandboxPolicy {
	if emit == nil {
		emit = func(events.Payload) {}
	}
	return &sandboxPolicy{id: id, rules: rules, emit: emit, pool: pool, now: time.Now, resolved: map[netip.Addr]time.Time{}}
}

func (p *sandboxPolicy) learn(ips []netip.Addr, ttl time.Duration) {
	ttl = min(max(ttl, minLearn), maxLearn)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if len(p.resolved) > maxRemembers {
		for ip, until := range p.resolved {
			if now.After(until) {
				delete(p.resolved, ip)
			}
		}
	}
	for _, ip := range ips {
		if len(p.resolved) >= maxRemembers*2 {
			break
		}
		if until := now.Add(ttl); until.After(p.resolved[ip]) {
			p.resolved[ip] = until
		}
	}
}

func (p *sandboxPolicy) wasResolved(ip netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.resolved[ip.Unmap()]
	return ok && p.now().Before(until)
}

// decide is the verdict for a connection that passed Forbidden.
func (p *sandboxPolicy) decide(dst netip.AddrPort, h hello) *Denial {
	if p.rules.Mode != ModeAllow {
		return nil
	}
	if !p.wasResolved(dst.Addr()) {
		return &Denial{Reason: "direct_ip", Target: dst.String(), Rule: "not an address the sandbox's resolver returned for an allowed name"}
	}
	switch h.Proto {
	case "tls":
		switch {
		case h.SNI == "":
			return &Denial{Reason: "sni_mismatch", Target: dst.String(), Rule: "TLS without SNI"}
		case h.ECH:
			return &Denial{Reason: "sni_mismatch", Target: h.SNI, Rule: "encrypted ClientHello hides the real name"}
		case !p.rules.allows(h.SNI):
			return &Denial{Reason: "sni_mismatch", Target: h.SNI, Rule: "TLS SNI not in the allow-list"}
		}
	case "http":
		if h.Host == "" || !p.rules.allows(h.Host) {
			return &Denial{Reason: "sni_mismatch", Target: orDst(h.Host, dst), Rule: "HTTP Host not in the allow-list"}
		}
	default:
		return &Denial{Reason: "not_allowlisted", Target: dst.String(), Rule: "neither TLS with SNI nor HTTP with a Host header"}
	}
	return nil
}

func orDst(s string, dst netip.AddrPort) string {
	if s != "" {
		return s
	}
	return dst.String()
}

// upstreamFunc resolves name to A records (with the smallest TTL in the answer) and the rcode.
type upstreamFunc func(ctx context.Context, name dnsmessage.Name) ([]netip.Addr, uint32, dnsmessage.RCode, error)

// answerDNS answers one query from the sandbox. A queries for permitted names are resolved
// upstream; their public answers are returned (flattened, CNAMEs dropped) and remembered so
// the proxy lets the sandbox connect to them. Other query types for permitted names get an
// empty answer (no IPv6, no HTTPS/SVCB records, so no ECH configs). Names outside the
// allow-list get NXDOMAIN. Every query is an event. nil means: drop the packet.
func (p *sandboxPolicy) answerDNS(ctx context.Context, raw []byte, up upstreamFunc, local func() []netip.Addr) []byte {
	var ps dnsmessage.Parser
	hdr, err := ps.Start(raw)
	if err != nil || hdr.Response || hdr.OpCode != 0 {
		return nil
	}
	qs, err := ps.AllQuestions()
	if err != nil || len(qs) != 1 || qs[0].Class != dnsmessage.ClassINET {
		return nil
	}
	q := qs[0]
	qname := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	if qname == "" {
		qname = "."
	}
	qtype := typeName(q.Type)
	ev := events.DNS{QName: qname, QType: qtype}
	resp := dnsmessage.Header{ID: hdr.ID, Response: true, RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true}
	var answers []netip.Addr
	var ttl uint32
	switch {
	case !validName(qname) || !p.rules.allows(qname):
		resp.RCode = dnsmessage.RCodeNameError
		p.emit(events.PolicyDenied{Policy: "dns", Target: qname, Reason: "not_allowlisted"})
	case q.Type == dnsmessage.TypeA:
		ev.Allowed = true
		ips, t, rc, err := up(ctx, q.Name)
		if err != nil {
			resp.RCode = dnsmessage.RCodeServerFailure
			break
		}
		resp.RCode, ttl = rc, t
		for _, ip := range ips {
			if len(answers) == maxAnswers {
				break
			}
			if err := Forbidden(ip, p.pool, local()); err != nil { // e.g. rebinding to metadata
				p.emit(events.PolicyDenied{Policy: "dns", Target: qname, Reason: rangeReason(ip), Rule: "answer " + ip.String() + " dropped"})
				continue
			}
			answers = append(answers, ip)
		}
		p.learn(answers, time.Duration(ttl)*time.Second)
	default:
		ev.Allowed = true // permitted name, but only A records are answered
	}
	ev.RCode = rcodeName(resp.RCode)
	if len(answers) > 0 {
		t := int(min(ttl, maxGuestTTL))
		ev.TTL = &t
		for _, a := range answers {
			ev.Answers = append(ev.Answers, a.String())
		}
	}
	p.emit(ev)
	return buildAnswer(resp, q, answers, min(ttl, maxGuestTTL))
}

func buildAnswer(h dnsmessage.Header, q dnsmessage.Question, ips []netip.Addr, ttl uint32) []byte {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), h)
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return nil
	}
	for _, ip := range ips {
		rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}
		if b.AResource(rh, dnsmessage.AResource{A: ip.As4()}) != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// validName: printable LDH-ish names only (dnsmessage escapes anything else as \DDD).
func validName(n string) bool {
	if len(n) == 0 || len(n) > 253 || n == "." {
		return false
	}
	for _, c := range n {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '_' {
			return false
		}
	}
	return true
}

func typeName(t dnsmessage.Type) string {
	s := strings.ToUpper(strings.TrimPrefix(t.String(), "Type"))
	if len(s) > 10 {
		s = s[:10]
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return "UNKNOWN"
		}
	}
	return s
}

func rcodeName(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	}
	return "OTHER"
}
