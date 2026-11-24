// Package netpol gives each sandbox its own network link and polices it from the host.
//
// A gVisor sandbox gets a network namespace with one veth pair; a VM gets a tap device.
// Each link is a /30 from the pool: the host side is the guest's gateway. The host never
// routes sandbox traffic (forwarding to and from sandbox links is dropped): every TCP
// connection is redirected (nftables) to a per-sandbox proxy in qtd that reads the original
// destination and dials it only when the Policy allows it. UDP, ICMP and IPv6 from a
// sandbox, connections to the host itself and packets with a spoofed source are dropped.
// Whatever the guest says about its traffic is never consulted.
package netpol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
)

// Config configures a Manager.
type Config struct {
	// Tag names this manager's host objects: the nftables table quarantine_<tag>, links
	// <tag>n<index> and namespaces <tag>-<sandbox>. 1-4 lowercase letters or digits.
	Tag string
	// Pool is the IPv4 range sandbox links are cut from (/30 each); it must not overlap a
	// route on the host.
	Pool netip.Prefix
	// ProxyPort is the port the per-sandbox proxies listen on (on each gateway address).
	ProxyPort uint16
	// Policy decides each connection that Forbidden allows; nil means AllowAll.
	Policy Policy
	// OnDecision, if set, is told about every connection the proxy handled.
	OnDecision func(Decision)
	Logger     *slog.Logger
}

// Defaults for qtd.
const (
	DefaultTag       = "qt"
	DefaultProxyPort = 15001
)

// DefaultPool is the default address pool (16383 sandboxes).
var DefaultPool = netip.MustParsePrefix("10.231.0.0/16")

// Decision is one connection the proxy handled.
type Decision struct {
	Sandbox string
	Dst     netip.AddrPort
	Err     error // nil: allowed and dialed
}

// Policy decides whether a sandbox may connect to dst. It runs in qtd for every TCP
// connection, after the hard rules (Forbidden) have passed.
type Policy interface {
	Allow(ctx context.Context, sandbox string, dst netip.AddrPort) error
}

// AllowAll allows every destination that is not Forbidden.
type AllowAll struct{}

// Allow implements Policy.
func (AllowAll) Allow(context.Context, string, netip.AddrPort) error { return nil }

// ErrForbidden means the destination is never reachable from a sandbox.
var ErrForbidden = errors.New("destination is not reachable from a sandbox")

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

var tagRe = regexp.MustCompile(`^[a-z0-9]{1,4}$`)

func (c *Config) validate() error {
	if !tagRe.MatchString(c.Tag) {
		return fmt.Errorf("netpol: tag %q must be 1-4 lowercase letters or digits", c.Tag)
	}
	if !c.Pool.IsValid() || !c.Pool.Addr().Is4() || c.Pool.Bits() < 8 || c.Pool.Bits() > 28 {
		return fmt.Errorf("netpol: pool %v must be an IPv4 prefix between /8 and /28", c.Pool)
	}
	if c.ProxyPort == 0 {
		return errors.New("netpol: proxy port is required")
	}
	return nil
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
func ruleset(tag string, port uint16, pool netip.Prefix) string {
	elems := []string{pool.Masked().String()}
	for _, p := range forbidden {
		elems = append(elems, p.String())
	}
	r := strings.NewReplacer("TABLE", tableName(tag), "LINKS", tag+"n*", "PORT", fmt.Sprint(port),
		"FORBIDDEN", strings.Join(elems, ", "))
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
		iifname "LINKS" fib daddr type local meta l4proto tcp reject with tcp reset
		iifname "LINKS" ip daddr @forbidden meta l4proto tcp reject with tcp reset
		iifname "LINKS" fib daddr type local drop
		iifname "LINKS" ip daddr @forbidden drop
	}
	chain nat_pre {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "LINKS" meta l4proto tcp redirect to :PORT
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "LINKS" ct state established,related accept
		iifname "LINKS" meta l4proto tcp ct status dnat tcp dport PORT accept
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
