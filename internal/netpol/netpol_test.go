package netpol

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestForbidden(t *testing.T) {
	pool := netip.MustParsePrefix("10.231.0.0/16")
	local := []netip.Addr{netip.MustParseAddr("203.0.114.9"), netip.MustParseAddr("172.31.22.163")}
	tests := []struct {
		dst string
		ok  bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"151.101.0.223", true},
		{"::ffff:1.1.1.1", true}, // IPv4-mapped is IPv4
		{"203.0.114.9", false},   // a public address of this host
		{"172.31.22.163", false}, // this host's LAN address
		{"169.254.169.254", false},
		{"169.254.170.2", false}, // ECS task metadata
		{"10.0.0.1", false},
		{"10.231.0.6", false}, // another sandbox
		{"172.16.5.4", false},
		{"192.168.1.1", false},
		{"100.100.100.200", false}, // CGNAT; also Alibaba metadata
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"224.0.0.251", false},
		{"255.255.255.255", false},
		{"192.0.2.7", false},
		{"198.18.0.1", false},
		{"2606:4700::1111", false}, // no IPv6 from sandboxes
		{"fd00:ec2::254", false},
		{"::1", false},
	}
	for _, tt := range tests {
		err := Forbidden(netip.MustParseAddr(tt.dst), pool, local)
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrForbidden)) {
			t.Errorf("Forbidden(%s) = %v, want ok=%v", tt.dst, err, tt.ok)
		}
	}
}

func TestLink(t *testing.T) {
	pool := netip.MustParsePrefix("10.231.0.0/16")
	if n := slots(pool); n != 16384 {
		t.Fatalf("slots = %d", n)
	}
	tests := []struct {
		i         int
		gw, guest string
	}{
		{1, "10.231.0.5", "10.231.0.6/30"},
		{2, "10.231.0.9", "10.231.0.10/30"},
		{64, "10.231.1.1", "10.231.1.2/30"},
		{16383, "10.231.255.253", "10.231.255.254/30"},
	}
	for _, tt := range tests {
		gw, _, guest := link(pool, tt.i)
		if gw.String() != tt.gw || guest.String() != tt.guest || !guest.Contains(gw) {
			t.Errorf("link(%d) = %v %v", tt.i, gw, guest)
		}
	}
	if ifaceName("qt", 16383) != "qtn16383" || len(ifaceName("abcd", 4194303)) > 15 {
		t.Error("interface names must fit IFNAMSIZ")
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{Tag: "qt", Pool: DefaultPool, ProxyPort: DefaultProxyPort, DNSPort: DefaultDNSPort}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{Tag: "QT", Pool: DefaultPool, ProxyPort: 1},
		{Tag: "toolong", Pool: DefaultPool, ProxyPort: 1},
		{Tag: "qt", Pool: netip.MustParsePrefix("fd00::/64"), ProxyPort: 1},
		{Tag: "qt", Pool: netip.MustParsePrefix("10.0.0.0/30"), ProxyPort: 1},
		{Tag: "qt", Pool: DefaultPool},
	} {
		if c.validate() == nil {
			t.Errorf("%+v: want an error", c)
		}
	}
}

func TestRuleset(t *testing.T) {
	c := Config{Tag: "qt", Pool: DefaultPool, ProxyPort: 15001, DNSPort: 15053}
	r := ruleset(&c)
	for _, want := range []string{
		"table inet quarantine_qt {",
		`iifname "qtn*" meta nfproto ipv6 drop`,
		`iifname "qtn*" fib saddr . iif oif missing drop`,
		`iifname "qtn*" fib daddr type local meta l4proto tcp reject with tcp reset`,
		`iifname "qtn*" ip daddr @forbidden meta l4proto tcp reject with tcp reset`,
		"elements = { 10.231.0.0/16, 0.0.0.0/8, 10.0.0.0/8, ",
		"169.254.0.0/16",
		`iifname "qtn*" meta l4proto tcp redirect to :15001`,
		`iifname "qtn*" meta l4proto tcp ct status dnat tcp dport 15001 accept`,
		`iifname "qtn*" drop`,
		`oifname "qtn*" drop`,
	} {
		if !strings.Contains(r, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
}
