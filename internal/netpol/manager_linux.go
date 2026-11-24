//go:build linux

package netpol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// Kind is the type of link a sandbox gets.
type Kind int

// Link kinds.
const (
	Netns Kind = iota + 1 // a network namespace with a veth pair (gvisor)
	Tap                   // a tap device a VMM opens (vm)
)

// Manager owns this host's sandbox links, its nftables table and the proxies.
type Manager struct {
	cfg   Config
	log   *slog.Logger
	mu    sync.Mutex
	links map[string]*Link // by sandbox id
	used  map[int]bool
	next  int
}

// Link is one sandbox's attachment.
type Link struct {
	Sandbox string
	Kind    Kind
	Index   int
	Iface   string // host side: the veth end or the tap
	Netns   string // namespace name (Netns kind)
	Gateway netip.Addr
	Guest   netip.Prefix
	proxy   *proxy
}

// Network is what the backend needs to attach the sandbox.
func (l *Link) Network() backend.Network {
	n := backend.Network{Addr: l.Guest, Gateway: l.Gateway}
	if l.Kind == Netns {
		n.NetnsPath = filepath.Join("/run/netns", l.Netns)
	} else {
		n.TapDevice = l.Iface
	}
	return n
}

// New checks the pool against the host's routes and installs the nftables table (replacing
// a stale one with the same tag).
func New(ctx context.Context, cfg Config) (*Manager, error) {
	if cfg.Policy == nil {
		cfg.Policy = AllowAll{}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("netpol: %s not found (install iproute2 and nftables): %w", tool, err)
		}
	}
	if err := checkPool(ctx, cfg.Pool, cfg.Tag); err != nil {
		return nil, err
	}
	_ = run(ctx, nil, "nft", "delete", "table", "inet", tableName(cfg.Tag)) // stale, from a crash
	if err := run(ctx, strings.NewReader(ruleset(cfg.Tag, cfg.ProxyPort, cfg.Pool)), "nft", "-f", "-"); err != nil {
		return nil, fmt.Errorf("netpol: install nftables rules: %w", err)
	}
	return &Manager{cfg: cfg, log: log, links: map[string]*Link{}, used: map[int]bool{}, next: 1}, nil
}

// checkPool refuses a pool that overlaps a route that is not one of ours.
func checkPool(ctx context.Context, pool netip.Prefix, tag string) error {
	out, err := output(ctx, "ip", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return fmt.Errorf("netpol: list routes: %w", err)
	}
	var routes []struct {
		Dst string `json:"dst"`
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return fmt.Errorf("netpol: parse routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst == "" || r.Dst == "default" || strings.HasPrefix(r.Dev, tag+"n") {
			continue
		}
		p, err := netip.ParsePrefix(r.Dst)
		if err != nil {
			a, err2 := netip.ParseAddr(r.Dst)
			if err2 != nil {
				continue
			}
			p = netip.PrefixFrom(a, 32)
		}
		if p.Overlaps(pool) {
			return fmt.Errorf("netpol: pool %v overlaps the host route %v dev %s; choose another pool", pool, p, r.Dev)
		}
	}
	return nil
}

// Attach creates sandbox id's link and starts its proxy. owner is the uid allowed to open a
// tap (the jailed VMM); it is ignored for Netns.
func (m *Manager) Attach(ctx context.Context, id string, kind Kind, owner int) (l *Link, err error) {
	if kind != Netns && kind != Tap {
		return nil, errors.New("netpol: unknown link kind")
	}
	m.mu.Lock()
	if _, ok := m.links[id]; ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("netpol: sandbox %s already has a link", id)
	}
	index, err := m.allocLocked()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	gw, _, guest := link(m.cfg.Pool, index)
	l = &Link{Sandbox: id, Kind: kind, Index: index, Iface: ifaceName(m.cfg.Tag, index), Gateway: gw, Guest: guest}
	if kind == Netns {
		l.Netns = m.cfg.Tag + "-" + id
	}
	m.links[id] = l
	m.mu.Unlock()
	defer func() {
		if err != nil {
			_ = m.Detach(context.WithoutCancel(ctx), id)
		}
	}()

	gwCIDR := netip.PrefixFrom(gw, 30).String()
	switch kind {
	case Netns:
		if err := run(ctx, nil, "ip", "netns", "add", l.Netns); err != nil {
			return nil, fmt.Errorf("netpol: netns: %w", err)
		}
		if err := run(ctx, nil, "ip", "link", "add", l.Iface, "type", "veth", "peer", "name", "eth0", "netns", l.Netns); err != nil {
			return nil, fmt.Errorf("netpol: veth: %w", err)
		}
		for _, args := range [][]string{
			{"-n", l.Netns, "addr", "add", guest.String(), "dev", "eth0"},
			{"-n", l.Netns, "link", "set", "lo", "up"},
			{"-n", l.Netns, "link", "set", "eth0", "up"},
			{"-n", l.Netns, "route", "add", "default", "via", gw.String()},
		} {
			if err := run(ctx, nil, "ip", args...); err != nil {
				return nil, fmt.Errorf("netpol: guest side: %w", err)
			}
		}
	case Tap:
		if err := createTap(l.Iface, owner); err != nil {
			return nil, fmt.Errorf("netpol: %w", err)
		}
	}
	// The host side has no IPv6 (no link-local address to reach either).
	_ = os.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", l.Iface, "disable_ipv6"), []byte("1"), 0o644) //nolint:gosec // G306: sysctl
	if err := run(ctx, nil, "ip", "addr", "add", gwCIDR, "dev", l.Iface); err != nil {
		return nil, fmt.Errorf("netpol: gateway address: %w", err)
	}
	if err := run(ctx, nil, "ip", "link", "set", l.Iface, "up"); err != nil {
		return nil, fmt.Errorf("netpol: link up: %w", err)
	}
	p, err := m.startProxy(id, netip.AddrPortFrom(gw, m.cfg.ProxyPort))
	if err != nil {
		return nil, fmt.Errorf("netpol: proxy: %w", err)
	}
	m.mu.Lock()
	l.proxy = p
	m.mu.Unlock()
	return l, nil
}

func (m *Manager) allocLocked() (int, error) {
	n := slots(m.cfg.Pool)
	for range n {
		i := m.next
		m.next++
		if m.next >= n {
			m.next = 1
		}
		if i == 0 || m.used[i] {
			continue
		}
		if _, err := os.Lstat(filepath.Join("/sys/class/net", ifaceName(m.cfg.Tag, i))); err == nil {
			continue // left behind by someone else
		}
		m.used[i] = true
		return i, nil
	}
	return 0, errors.New("netpol: address pool exhausted")
}

// Detach removes sandbox id's link, namespace and proxy. Unknown ids are not an error.
func (m *Manager) Detach(ctx context.Context, id string) error {
	m.mu.Lock()
	l, ok := m.links[id]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	var errs []error
	if l.proxy != nil {
		l.proxy.close()
	}
	if l.Kind == Tap {
		if err := deleteTap(l.Iface); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	} else if err := run(ctx, nil, "ip", "link", "del", l.Iface); err != nil && !gone(err) {
		errs = append(errs, err)
	}
	if l.Netns != "" {
		if err := run(ctx, nil, "ip", "netns", "del", l.Netns); err != nil && !gone(err) {
			errs = append(errs, err)
		}
	}
	m.mu.Lock()
	delete(m.links, id)
	delete(m.used, l.Index)
	m.mu.Unlock()
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("netpol: detach %s: %w", id, err)
	}
	return nil
}

// Close detaches every sandbox and removes the nftables table.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.links))
	for id := range m.links {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var errs []error
	for _, id := range ids {
		errs = append(errs, m.Detach(ctx, id))
	}
	if err := run(ctx, nil, "nft", "delete", "table", "inet", tableName(m.cfg.Tag)); err != nil && !gone(err) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// localAddrs are this host's addresses (never a sandbox destination).
func localAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func gone(err error) bool {
	s := err.Error()
	return strings.Contains(s, "Cannot find device") || strings.Contains(s, "No such file") ||
		strings.Contains(s, "does not exist")
}

func run(ctx context.Context, stdin *strings.Reader, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: fixed tools; args are names and addresses we build
	if stdin != nil {
		c.Stdin = stdin
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func output(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: fixed tools and arguments
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
