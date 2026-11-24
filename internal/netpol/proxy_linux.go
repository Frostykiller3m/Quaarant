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
	"syscall"
	"time"
	"unsafe"
)

const (
	maxConns    = 512 // concurrent connections per sandbox
	dialTimeout = 10 * time.Second
	soOrigDst   = 80 // SO_ORIGINAL_DST (linux/netfilter_ipv4.h)
)

// proxy accepts one sandbox's redirected TCP connections on its gateway address.
type proxy struct {
	m      *Manager
	id     string
	ln     *net.TCPListener
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func (m *Manager) startProxy(id string, at netip.AddrPort) (*proxy, error) {
	ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(at))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &proxy{m: m, id: id, ln: ln, ctx: ctx, cancel: cancel, sem: make(chan struct{}, maxConns), conns: map[net.Conn]struct{}{}}
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
	dst, err := originalDst(c)
	if err == nil {
		err = Forbidden(dst.Addr(), p.m.cfg.Pool, localAddrs())
	}
	if err == nil {
		err = p.m.cfg.Policy.Allow(p.ctx, p.id, dst)
	}
	var up *net.TCPConn
	if err == nil {
		d := net.Dialer{Timeout: dialTimeout}
		var uc net.Conn
		if uc, err = d.DialContext(p.ctx, "tcp4", dst.String()); err == nil {
			up = uc.(*net.TCPConn)
		}
	}
	p.decided(dst, err)
	if err != nil {
		_ = c.SetLinger(0) // a reset: the guest sees "connection refused"
		return
	}
	if !p.track(up, true) {
		_ = up.Close()
		return
	}
	defer p.track(up, false)
	defer func() { _ = up.Close() }()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, c) // splice(2) between TCP sockets
		_ = up.CloseWrite()
	}()
	_, _ = io.Copy(c, up)
	_ = c.CloseWrite()
	wg.Wait()
}

func (p *proxy) decided(dst netip.AddrPort, err error) {
	if err != nil {
		p.m.log.Debug("sandbox connection refused", "sandbox", p.id, "dst", dst, "err", err)
	}
	if f := p.m.cfg.OnDecision; f != nil {
		f(Decision{Sandbox: p.id, Dst: dst, Err: err})
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
