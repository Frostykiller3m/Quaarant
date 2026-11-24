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

// Manager owns this host's sandbox links, its nftables table, the proxies and resolvers.
type Manager struct {
	cfg       Config
	log       *slog.Logger
	upstreams []netip.AddrPort
	nflog     *nflog
	mu        sync.Mutex
	links     map[string]*Link // by sandbox id
	byIfindex map[int]*Link
	used      map[int]bool
	next      int
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
	Rules   Rules
	ifindex int
	pol     *sandboxPolicy
	proxy   *proxy
	dns     *resolver
}

// Network is what the backend needs to attach the sandbox (its resolver is the gateway).
func (l *Link) Network() backend.Network {
	n := backend.Network{Addr: l.Guest, Gateway: l.Gateway}
	if l.Kind == Netns {
		n.NetnsPath = filepath.Join("/run/netns", l.Netns)
	} else {
		n.TapDevice = l.Iface
	}
	return n
}

// New checks the pool against the host's routes, installs the nftables table (replacing a
// stale one with the same tag) and starts reading refusals.
func New(ctx context.Context, cfg Config) (*Manager, error) {
	if cfg.DNSPort == 0 {
		cfg.DNSPort = DefaultDNSPort
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
	ups := cfg.Upstreams
	if len(ups) == 0 {
		var err error
		if ups, err = hostResolvers(); err != nil {
			return nil, err
		}
	}
	if err := checkPool(ctx, cfg.Pool, cfg.Tag); err != nil {
		return nil, err
	}
	nl, err := openNflog(cfg.logGroup())
	if err != nil {
		return nil, fmt.Errorf("netpol: %w", err)
	}
	// One transaction (nft -f is atomic): create the table if missing, delete it, write the
	// new one. Live sandboxes (a qtd restart) are never without rules.
	script := "table inet " + tableName(cfg.Tag) + "\ndelete table inet " + tableName(cfg.Tag) + "\n" + ruleset(&cfg)
	if err := run(ctx, strings.NewReader(script), "nft", "-f", "-"); err != nil {
		nl.close()
		return nil, fmt.Errorf("netpol: install nftables rules: %w", err)
	}
	m := &Manager{cfg: cfg, log: log, upstreams: ups, nflog: nl, links: map[string]*Link{}, byIfindex: map[int]*Link{}, used: map[int]bool{}, next: 1}
	go nl.read(m.refused)
	return m, nil
}

func (m *Manager) refused(r refused) {
	m.mu.Lock()
	l := m.byIfindex[r.ifindex]
	m.mu.Unlock()
	if l == nil || l.pol == nil {
		return
	}
	for _, ev := range refusedEvents(r, m.cfg.Pool, localAddrs()) {
		l.pol.emit(ev)
	}
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

// Attach creates sandbox id's link and starts its proxy and resolver. owner is the uid
// allowed to open a tap (the jailed VMM); it is ignored for Netns. emit receives the
// sandbox's network events.
func (m *Manager) Attach(ctx context.Context, id string, kind Kind, owner int, rules Rules, emit Emitter) (l *Link, err error) {
	if kind != Netns && kind != Tap {
		return nil, errors.New("netpol: unknown link kind")
	}
	if rules, err = rules.Normalize(); err != nil {
		return nil, err
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
	l = m.newLinkLocked(id, kind, index, rules)
	m.mu.Unlock()
	defer func() {
		if err != nil {
			_ = m.Detach(context.WithoutCancel(ctx), id)
		}
	}()

	gw, guest := l.Gateway, l.Guest
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
	if err := run(ctx, nil, "ip", "addr", "add", netip.PrefixFrom(gw, 30).String(), "dev", l.Iface); err != nil {
		return nil, fmt.Errorf("netpol: gateway address: %w", err)
	}
	if err := run(ctx, nil, "ip", "link", "set", l.Iface, "up"); err != nil {
		return nil, fmt.Errorf("netpol: link up: %w", err)
	}
	if err := m.serve(l, emit); err != nil {
		return nil, err
	}
	return l, nil
}

// Adopt takes over sandbox id's existing link after a qtd restart (the link, namespace and
// addresses survive; the proxy and resolver do not).
func (m *Manager) Adopt(id string, kind Kind, index int, rules Rules, emit Emitter) (*Link, error) {
	rules, err := rules.Normalize()
	if err != nil {
		return nil, err
	}
	if index <= 0 || index >= slots(m.cfg.Pool) {
		return nil, fmt.Errorf("netpol: link index %d is outside the pool", index)
	}
	m.mu.Lock()
	if _, ok := m.links[id]; ok || m.used[index] {
		m.mu.Unlock()
		return nil, fmt.Errorf("netpol: sandbox %s or link %d is already attached", id, index)
	}
	m.used[index] = true
	l := m.newLinkLocked(id, kind, index, rules)
	m.mu.Unlock()
	if _, err := net.InterfaceByName(l.Iface); err != nil {
		_ = m.Detach(context.Background(), id)
		return nil, fmt.Errorf("netpol: adopt %s: %w", l.Iface, err)
	}
	if err := m.serve(l, emit); err != nil {
		_ = m.Detach(context.Background(), id)
		return nil, err
	}
	return l, nil
}

func (m *Manager) newLinkLocked(id string, kind Kind, index int, rules Rules) *Link {
	gw, _, guest := link(m.cfg.Pool, index)
	l := &Link{Sandbox: id, Kind: kind, Index: index, Iface: ifaceName(m.cfg.Tag, index), Gateway: gw, Guest: guest, Rules: rules}
	if kind == Netns {
		l.Netns = m.cfg.Tag + "-" + id
	}
	m.links[id] = l
	return l
}

// serve starts the link's proxy and resolver and maps its interface for refusals.
func (m *Manager) serve(l *Link, emit Emitter) error {
	ifc, err := net.InterfaceByName(l.Iface)
	if err != nil {
		return fmt.Errorf("netpol: %w", err)
	}
	pol := newSandboxPolicy(l.Sandbox, l.Rules, emit, m.cfg.Pool)
	p, err := m.startProxy(pol, netip.AddrPortFrom(l.Gateway, m.cfg.ProxyPort))
	if err != nil {
		return fmt.Errorf("netpol: proxy: %w", err)
	}
	r, err := m.startResolver(pol, netip.AddrPortFrom(l.Gateway, m.cfg.DNSPort))
	if err != nil {
		p.close()
		return fmt.Errorf("netpol: resolver: %w", err)
	}
	m.mu.Lock()
	l.pol, l.proxy, l.dns, l.ifindex = pol, p, r, ifc.Index
	m.byIfindex[ifc.Index] = l
	m.mu.Unlock()
	return nil
}

// Prune removes this manager's links and namespaces that no sandbox owns (left by a crash).
// Call it after every live sandbox has been adopted.
func (m *Manager) Prune(ctx context.Context) error {
	m.mu.Lock()
	owned := map[string]bool{}
	for _, l := range m.links {
		owned[l.Iface] = true
		if l.Netns != "" {
			owned["ns:"+l.Netns] = true
		}
	}
	m.mu.Unlock()
	var errs []error
	ifaces, _ := filepath.Glob("/sys/class/net/" + m.cfg.Tag + "n*")
	for _, p := range ifaces {
		name := filepath.Base(p)
		if owned[name] || !strings.HasPrefix(name, m.cfg.Tag+"n") {
			continue
		}
		if err := run(ctx, nil, "ip", "link", "del", name); err != nil && !gone(err) { // a tap or a veth
			errs = append(errs, err)
		}
		m.log.Info("removed an orphaned sandbox link", "iface", name)
	}
	nss, _ := filepath.Glob("/run/netns/" + m.cfg.Tag + "-*")
	for _, p := range nss {
		name := filepath.Base(p)
		if owned["ns:"+name] {
			continue
		}
		if err := run(ctx, nil, "ip", "netns", "del", name); err != nil && !gone(err) {
			errs = append(errs, err)
		}
		m.log.Info("removed an orphaned sandbox netns", "netns", name)
	}
	return errors.Join(errs...)
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

// Detach removes sandbox id's link, namespace, proxy and resolver. Unknown ids are not an
// error.
func (m *Manager) Detach(ctx context.Context, id string) error {
	m.mu.Lock()
	l, ok := m.links[id]
	if ok && l.ifindex != 0 {
		delete(m.byIfindex, l.ifindex)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	var errs []error
	if l.proxy != nil {
		l.proxy.close()
	}
	if l.dns != nil {
		l.dns.close()
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

// Close detaches every sandbox, removes the nftables table and stops reading refusals.
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
	m.nflog.close()
	return errors.Join(errs...)
}

// Release stops serving without removing anything (qtd shutting down: sandboxes keep their
// links and a restarted qtd adopts them).
func (m *Manager) Release() {
	m.mu.Lock()
	links := make([]*Link, 0, len(m.links))
	for _, l := range m.links {
		links = append(links, l)
	}
	m.mu.Unlock()
	for _, l := range links {
		if l.proxy != nil {
			l.proxy.close()
		}
		if l.dns != nil {
			l.dns.close()
		}
	}
	m.nflog.close()
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
