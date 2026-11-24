// Package netpol gives each sandbox its own network link and polices it from the host.
//
// A gVisor sandbox gets a network namespace with one veth pair; a VM gets a tap device.
// Each link is a /30 from the pool: the host side is the guest's gateway. The host never
// routes sandbox traffic (forwarding to and from sandbox links is dropped):
//
//   - DNS (UDP or TCP port 53, to any server) is redirected to a per-sandbox resolver in
//     qtd that answers A queries only for allowed names and records every query.
//   - Every other TCP connection is redirected to a per-sandbox proxy in qtd. It reads the
//     original destination and the TLS SNI or HTTP Host, decides with the sandbox's Rules,
//     records the connection, and splices it.
//   - Everything else (UDP, ICMP, IPv6, spoofed sources, and TCP to the host, the LAN,
//     link-local/metadata or other sandboxes) is refused in the kernel; those refusals reach
//     qtd through an nflog group and are recorded too.
//
// Whatever the guest says about its traffic is never consulted.
package netpol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// Config configures a Manager.
type Config struct {
	// Tag names this manager's host objects: the nftables table quarantine_<tag>, links
	// <tag>n<index> and namespaces <tag>-<sandbox>. 1-4 lowercase letters or digits.
	Tag string
	// Pool is the IPv4 range sandbox links are cut from (/30 each); it must not overlap a
	// route on the host.
	Pool netip.Prefix
	// ProxyPort and DNSPort are where the per-sandbox proxy and resolver listen (on each
	// gateway address).
	ProxyPort, DNSPort uint16
	// LogGroup is the nflog group kernel refusals are sent to; 0 derives one from Tag.
	LogGroup uint16
	// Upstreams are the DNS servers qtd asks for allowed names; empty means the host's
	// /etc/resolv.conf.
	Upstreams []netip.AddrPort
	// OnDecision, if set, is told about every connection the proxy handled (tests).
	OnDecision func(Decision)
	Logger     *slog.Logger
}

// Defaults for qtd.
const (
	DefaultTag       = "qt"
	DefaultProxyPort = 15001
	DefaultDNSPort   = 15053
)

// DefaultPool is the default address pool (16383 sandboxes).
var DefaultPool = netip.MustParsePrefix("10.231.0.0/16")

// Mode is a sandbox's egress policy.
type Mode int

// Modes. A sandbox without network (--net=none) has no link at all.
const (
	ModeLog   Mode = iota + 1 // everything public allowed, everything recorded
	ModeAllow                 // only Rules.Allow names (DNS, then SNI/Host), everything recorded
)

func (m Mode) String() string {
	switch m {
	case ModeLog:
		return "log"
	case ModeAllow:
		return "allow"
	}
	return "unknown"
}

// Rules is one sandbox's policy.
type Rules struct {
	Mode  Mode
	Allow []string // domains; each also allows its subdomains (ModeAllow)
}

// MaxAllow bounds an allow-list.
const MaxAllow = 64

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ParseDomain normalizes an allow-list entry: lowercase, no trailing dot, LDH labels, at
// least two labels.
func ParseDomain(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	labels := strings.Split(d, ".")
	if len(d) > 253 || len(labels) < 2 {
		return "", fmt.Errorf("domain %.64q: need a name like example.com", s)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("domain %.64q: invalid label %.64q", s, l)
		}
	}
	return d, nil
}

// Normalize validates the rules and returns them with normalized, deduplicated domains.
func (r Rules) Normalize() (Rules, error) {
	switch r.Mode {
	case ModeLog:
		if len(r.Allow) > 0 {
			return Rules{}, errors.New("netpol: log mode takes no allow-list")
		}
		return Rules{Mode: ModeLog}, nil
	case ModeAllow:
	default:
		return Rules{}, errors.New("netpol: unknown mode")
	}
	if len(r.Allow) == 0 || len(r.Allow) > MaxAllow {
		return Rules{}, fmt.Errorf("netpol: an allow-list needs 1-%d domains", MaxAllow)
	}
	out := Rules{Mode: ModeAllow}
	seen := map[string]bool{}
	for _, a := range r.Allow {
		d, err := ParseDomain(a)
		if err != nil {
			return Rules{}, fmt.Errorf("netpol: %w", err)
		}
		if !seen[d] {
			seen[d] = true
			out.Allow = append(out.Allow, d)
		}
	}
	return out, nil
}

// allows reports whether name (any case, optional trailing dot) is permitted.
func (r Rules) allows(name string) bool {
	if r.Mode == ModeLog {
		return true
	}
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, a := range r.Allow {
		if n == a || strings.HasSuffix(n, "."+a) {
			return true
		}
	}
	return false
}

// Emitter receives one sandbox's host-observed network events.
type Emitter func(events.Payload)

// Decision is one connection the proxy handled.
type Decision struct {
	Sandbox string
	Dst     netip.AddrPort
	SNI     string
	Host    string
	Err     error // nil: allowed (and dialed, unless DialErr)
}

// ErrForbidden means the destination is never reachable from a sandbox.
var ErrForbidden = errors.New("destination is not reachable from a sandbox")

// Denial is a refusal by the policy, with the event schema's reason.
type Denial struct {
	Reason string // policy_denied reason: not_allowlisted, blocked_range, metadata, direct_ip, sni_mismatch
	Target string
	Rule   string
}

func (d *Denial) Error() string {
	s := fmt.Sprintf("%s: %s", d.Reason, d.Target)
	if d.Rule != "" {
		s += " (" + d.Rule + ")"
	}
	return s
}

// forbidden are the IPv4 ranges a sandbox can never reach, whatever the policy: this host,
// private and shared (LAN, CGNAT), link-local (cloud metadata lives at 169.254.169.254),
// documentation, benchmarking, multicast and reserved space.
var forbidden = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// metadata are well-known cloud instance-metadata endpoints (all inside forbidden ranges).
var metadata = map[netip.Addr]bool{
	netip.MustParseAddr("169.254.169.254"): true, // AWS, GCP, Azure, OpenStack, ...
	netip.MustParseAddr("169.254.170.2"):   true, // AWS ECS task metadata
	netip.MustParseAddr("100.100.100.200"): true, // Alibaba Cloud
}

// Forbidden reports why dst may never be dialed for a sandbox: it is not public IPv4, it is
// in a forbidden range or the pool, or it is one of the host's own addresses (local).
func Forbidden(dst netip.Addr, pool netip.Prefix, local []netip.Addr) error {
	dst = dst.Unmap()
	if !dst.Is4() {
		return fmt.Errorf("%w: %v is not IPv4", ErrForbidden, dst)
	}
	if pool.IsValid() && pool.Contains(dst) {
		return fmt.Errorf("%w: %v is a sandbox link", ErrForbidden, dst)
	}
	for _, p := range forbidden {
		if p.Contains(dst) {
			return fmt.Errorf("%w: %v is in %v", ErrForbidden, dst, p)
		}
	}
	for _, a := range local {
		if a.Unmap() == dst {
			return fmt.Errorf("%w: %v is this host", ErrForbidden, dst)
		}
	}
	return nil
}

// rangeReason is the policy_denied reason for a forbidden destination.
func rangeReason(dst netip.Addr) string {
	if metadata[dst.Unmap()] {
		return "metadata"
	}
	return "blocked_range"
}

var tagRe = regexp.MustCompile(`^[a-z0-9]{1,4}$`)

func (c *Config) validate() error {
	if !tagRe.MatchString(c.Tag) {
		return fmt.Errorf("netpol: tag %q must be 1-4 lowercase letters or digits", c.Tag)
	}
	if !c.Pool.IsValid() || !c.Pool.Addr().Is4() || c.Pool.Bits() < 8 || c.Pool.Bits() > 28 {
		return fmt.Errorf("netpol: pool %v must be an IPv4 prefix between /8 and /28", c.Pool)
	}
	if c.ProxyPort == 0 || c.DNSPort == 0 || c.ProxyPort == c.DNSPort || c.DNSPort == 53 {
		return errors.New("netpol: distinct proxy and DNS ports are required (not 53)")
	}
	return nil
}

func (c *Config) logGroup() uint16 {
	if c.LogGroup != 0 {
		return c.LogGroup
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(c.Tag))
	return uint16(31000 + h.Sum32()%1000)
}

// slots is how many /30 links fit in the pool (index 0, the pool's first /30, is unused).
func slots(pool netip.Prefix) int { return 1 << (30 - pool.Bits()) }

// link is the addressing of the pool's index-th /30: gateway .1, guest .2.
func link(pool netip.Prefix, index int) (gw, guest netip.Addr, prefix netip.Prefix) {
	b := pool.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:])
	v += uint32(index) * 4 //nolint:gosec // G115: index < slots(pool) <= 2^22
	at := func(off uint32) netip.Addr {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], v+off)
		return netip.AddrFrom4(a)
	}
	gw, guest = at(1), at(2)
	return gw, guest, netip.PrefixFrom(guest, 30)
}

func ifaceName(tag string, index int) string { return fmt.Sprintf("%sn%d", tag, index) }

func tableName(tag string) string { return "quarantine_" + tag }

// ruleset is the nftables table for one manager. Links are matched by name prefix, so a
// sandbox needs no rules of its own. Forbidden destinations (the same list the proxy checks,
// plus the pool and every local address) are refused in the kernel before the redirect: the
// guest sees "connection refused" at once, and the proxy's own check is a second line.
// Refusals are logged (rate-limited) to the nflog group so qtd records them.
func ruleset(c *Config) string {
	elems := []string{c.Pool.Masked().String()}
	for _, p := range forbidden {
		elems = append(elems, p.String())
	}
	r := strings.NewReplacer("TABLE", tableName(c.Tag), "LINKS", c.Tag+"n*",
		"PROXYPORT", fmt.Sprint(c.ProxyPort), "DNSPORT", fmt.Sprint(c.DNSPort),
		"GROUP", fmt.Sprint(c.logGroup()), "FORBIDDEN", strings.Join(elems, ", "))
	return r.Replace(`table inet TABLE {
	set forbidden {
		type ipv4_addr; flags interval; auto-merge;
		elements = { FORBIDDEN }
	}
	chain raw_pre {
		type filter hook prerouting priority raw; policy accept;
		iifname "LINKS" meta nfproto ipv6 drop
		iifname "LINKS" fib saddr . iif oif missing drop
		iifname "LINKS" fib saddr type local drop
		iifname "LINKS" meta l4proto { tcp, udp } th dport 53 accept
		iifname "LINKS" meta l4proto tcp tcp flags & (syn | ack) == syn fib daddr type local limit rate 100/second burst 200 packets counter log group GROUP
		iifname "LINKS" meta l4proto tcp tcp flags & (syn | ack) == syn ip daddr @forbidden limit rate 100/second burst 200 packets counter log group GROUP
		iifname "LINKS" meta l4proto != tcp limit rate 100/second burst 200 packets counter log group GROUP
		iifname "LINKS" fib daddr type local meta l4proto tcp reject with tcp reset
		iifname "LINKS" ip daddr @forbidden meta l4proto tcp reject with tcp reset
		iifname "LINKS" fib daddr type local drop
		iifname "LINKS" ip daddr @forbidden drop
		iifname "LINKS" meta l4proto != tcp drop
	}
	chain nat_pre {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "LINKS" meta l4proto { tcp, udp } th dport 53 redirect to :DNSPORT
		iifname "LINKS" meta l4proto tcp redirect to :PROXYPORT
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "LINKS" ct state established,related accept
		iifname "LINKS" meta l4proto tcp ct status dnat tcp dport PROXYPORT accept
		iifname "LINKS" meta l4proto { tcp, udp } ct status dnat th dport DNSPORT accept
		iifname "LINKS" drop
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "LINKS" drop
		oifname "LINKS" drop
	}
	chain output {
		type filter hook output priority filter; policy accept;
		oifname "LINKS" ct state established,related accept
		oifname "LINKS" meta l4proto tcp tcp flags & rst == rst accept
		oifname "LINKS" drop
	}
}
`)
}
