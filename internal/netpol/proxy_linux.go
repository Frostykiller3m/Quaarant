//go:build linux

package netpol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/honeytoken"
)

const (
	maxConns    = 512 // concurrent connections per sandbox
	dialTimeout = 10 * time.Second
	soOrigDst   = 80 // SO_ORIGINAL_DST (linux/netfilter_ipv4.h)
	// How long the proxy waits for the client's first bytes. In allow mode it must see them
	// (SNI/Host) to decide; in log mode they only enrich the record, so a protocol where the
	// server speaks first is delayed by at most logWait.
	allowWait = 10 * time.Second
	logWait   = 2 * time.Second
)

// proxy accepts one sandbox's redirected TCP connections on its gateway address.
type proxy struct {
	m      *Manager
	pol    *sandboxPolicy
	ln     *net.TCPListener
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func (m *Manager) startProxy(pol *sandboxPolicy, at netip.AddrPort) (*proxy, error) {
	ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(at))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &proxy{m: m, pol: pol, ln: ln, ctx: ctx, cancel: cancel, sem: make(chan struct{}, maxConns), conns: map[net.Conn]struct{}{}}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

func (p *proxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		select {
		case p.sem <- struct{}{}:
		default:
			_ = c.SetLinger(0)
			_ = c.Close()
			p.pol.emit(events.PolicyDenied{Policy: "net", Target: "tcp", Reason: "rate_limited", Rule: fmt.Sprintf("more than %d open connections", maxConns)})
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-p.sem }()
			p.handle(c)
		}()
	}
}

func (p *proxy) track(c net.Conn, on bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if on {
		if p.ctx.Err() != nil {
			return false
		}
		p.conns[c] = struct{}{}
	} else {
		delete(p.conns, c)
	}
	return true
}

func (p *proxy) handle(c *net.TCPConn) {
	if !p.track(c, true) {
		_ = c.Close()
		return
	}
	defer p.track(c, false)
	defer func() { _ = c.Close() }()
	start := time.Now()
	dst, err := originalDst(c)
	if err != nil {
		_ = c.SetLinger(0)
		return
	}
	ev := events.Net{Op: "connect", Proto: "tcp", DstIP: dst.Addr().String(), DstPort: int(dst.Port())}
	deny := func(d *Denial, h hello) {
		_ = c.SetLinger(0) // a reset: the guest sees "connection refused"/"reset"
		f := false
		ev.Allowed, ev.SNI, ev.HTTPHost = &f, h.SNI, h.Host
		p.pol.emit(ev)
		p.pol.emit(events.PolicyDenied{Policy: "net", Target: truncate(d.Target, 4096), Reason: d.Reason, Rule: truncate(d.Rule, 256)})
		p.decided(dst, h, d)
	}
	// The kernel already refused these; this is the second line.
	if err := Forbidden(dst.Addr(), p.m.cfg.Pool, localAddrs()); err != nil {
		deny(&Denial{Reason: rangeReason(dst.Addr()), Target: dst.String(), Rule: err.Error()}, hello{})
		return
	}
	wait := logWait
	if p.pol.rules.Mode == ModeAllow {
		wait = allowWait
	}
	first, h := peekHello(c, wait)
	// Honeytokens in what the client sent, whatever the verdict: an attempt counts.
	where := orDst(h.Host, dst)
	var scan *honeytoken.Stream
	if h.SNI != "" {
		p.pol.honey(p.pol.rules.Honey.FindName(h.SNI), "egress_sni", h.SNI)
	}
	if h.Proto != "tls" { // TLS bodies are encrypted: out of scope
		scan = p.pol.rules.Honey.NewStream()
		p.pol.honey(scan.Write(first), "egress_plaintext", where)
	}
	if d := p.pol.decide(dst, h); d != nil {
		deny(d, h)
		return
	}
	ev.SNI, ev.HTTPHost = h.SNI, h.Host
	d := net.Dialer{Timeout: dialTimeout}
	uc, err := d.DialContext(p.ctx, "tcp4", dst.String())
	t := true
	ev.Allowed = &t
	if err != nil {
		ev.Errno = errnoOf(err)
		p.pol.emit(ev)
		p.decided(dst, h, nil)
		_ = c.SetLinger(0)
		return
	}
	p.pol.emit(ev)
	p.decided(dst, h, nil)
	up := uc.(*net.TCPConn)
	if !p.track(up, true) {
		_ = up.Close()
		return
	}
	defer p.track(up, false)
	defer func() { _ = up.Close() }()
	var out, in atomic.Int64
	if len(first) > 0 {
		n, err := up.Write(first)
		out.Add(int64(n))
		if err != nil {
			return
		}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var n int64
		if scan == nil {
			n, _ = io.Copy(up, c) // splice(2) between TCP sockets
		} else {
			n = copyScanning(up, c, func(b []byte) { p.pol.honey(scan.Write(b), "egress_plaintext", where) })
		}
		out.Add(n)
		_ = up.CloseWrite()
	}()
	n, _ := io.Copy(c, up)
	in.Add(n)
	_ = c.CloseWrite()
	wg.Wait()
	bo, bi, ms := out.Load(), in.Load(), time.Since(start).Milliseconds()
	cl := events.Net{
		Op: "close", Proto: "tcp", DstIP: ev.DstIP, DstPort: ev.DstPort, SNI: ev.SNI, HTTPHost: ev.HTTPHost,
		Allowed: &t, BytesOut: &bo, BytesIn: &bi, DurationMS: &ms,
	}
	p.pol.emit(cl)
}

func (p *proxy) decided(dst netip.AddrPort, h hello, d *Denial) {
	if d != nil {
		p.m.log.Debug("sandbox connection refused", "sandbox", p.pol.id, "dst", dst, "reason", d.Reason, "target", d.Target)
	}
	if f := p.m.cfg.OnDecision; f != nil {
		x := Decision{Sandbox: p.pol.id, Dst: dst, SNI: h.SNI, Host: h.Host}
		if d != nil {
			x.Err = d
		}
		f(x)
	}
}

func (p *proxy) close() {
	p.cancel()
	_ = p.ln.Close()
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

func errnoOf(err error) string {
	var e syscall.Errno
	if errors.As(err, &e) {
		switch e {
		case syscall.ECONNREFUSED:
			return "ECONNREFUSED"
		case syscall.ETIMEDOUT:
			return "ETIMEDOUT"
		case syscall.EHOSTUNREACH:
			return "EHOSTUNREACH"
		case syscall.ENETUNREACH:
			return "ENETUNREACH"
		case syscall.ECONNRESET:
			return "ECONNRESET"
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "ETIMEDOUT"
	}
	return "EIO"
}

// truncate cuts s to n bytes on a UTF-8 boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n]
}

// originalDst is where the guest was connecting before nftables redirected it here.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var sa [16]byte // struct sockaddr_in
	var serr error
	err = rc.Control(func(fd uintptr) {
		l := uint32(len(sa))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOrigDst,
			uintptr(unsafe.Pointer(&sa[0])), uintptr(unsafe.Pointer(&l)), 0) //nolint:gosec // G103: getsockopt(2) out-parameters
		if e != 0 {
			serr = e
		}
	})
	if err == nil {
		err = serr
	}
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", err)
	}
	port := binary.BigEndian.Uint16(sa[2:4])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(sa[4:8])), port), nil
}

// copyScanning copies src to dst, showing every chunk to scan first.
func copyScanning(dst io.Writer, src io.Reader, scan func([]byte)) int64 {
	buf := make([]byte, 32<<10)
	var n int64
	for {
		m, err := src.Read(buf)
		if m > 0 {
			scan(buf[:m])
			w, werr := dst.Write(buf[:m])
			n += int64(w)
			if werr != nil {
				return n
			}
		}
		if err != nil {
			return n
		}
	}
}
