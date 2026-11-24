//go:build linux

package netpol

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	upstreamTimeout = 3 * time.Second
	maxDNSInflight  = 64 // concurrent queries per sandbox
)

// resolver serves one sandbox's DNS on its gateway (UDP and TCP).
type resolver struct {
	pol    *sandboxPolicy
	up     upstreamFunc
	udp    *net.UDPConn
	tcp    *net.TCPListener
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
	wg     sync.WaitGroup
}

func (m *Manager) startResolver(pol *sandboxPolicy, at netip.AddrPort) (*resolver, error) {
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(at))
	if err != nil {
		return nil, err
	}
	tcp, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(at))
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &resolver{pol: pol, up: m.upstream, udp: udp, tcp: tcp, ctx: ctx, cancel: cancel, sem: make(chan struct{}, maxDNSInflight)}
	r.wg.Add(2)
	go r.serveUDP()
	go r.serveTCP()
	return r, nil
}

func (r *resolver) serveUDP() {
	defer r.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, from, err := r.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case r.sem <- struct{}{}:
		default:
			continue // flooded: drop, as a busy server would
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { <-r.sem }()
			if resp := r.pol.answerDNS(r.ctx, q, r.up, localAddrs); resp != nil {
				if len(resp) > 512 { // classic UDP size: set TC, the client retries over TCP
					resp = truncated(resp)
				}
				_, _ = r.udp.WriteToUDPAddrPort(resp, from)
			}
		}()
	}
}

func (r *resolver) serveTCP() {
	defer r.wg.Done()
	for {
		c, err := r.tcp.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		select {
		case r.sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { <-r.sem }()
			defer func() { _ = c.Close() }()
			stop := context.AfterFunc(r.ctx, func() { _ = c.Close() })
			defer stop()
			br := bufio.NewReader(c)
			for range 16 { // queries per connection
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var l uint16
				if binary.Read(br, binary.BigEndian, &l) != nil || l == 0 {
					return
				}
				q := make([]byte, l)
				if _, err := io.ReadFull(br, q); err != nil {
					return
				}
				resp := r.pol.answerDNS(r.ctx, q, r.up, localAddrs)
				if resp == nil {
					return
				}
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp))) //nolint:gosec // G115: < 64 KiB
				if _, err := c.Write(append(out, resp...)); err != nil {
					return
				}
			}
		}()
	}
}

func (r *resolver) close() {
	r.cancel()
	_ = r.udp.Close()
	_ = r.tcp.Close()
	r.wg.Wait()
}

// truncated is resp with TC set and no answers.
func truncated(resp []byte) []byte {
	var ps dnsmessage.Parser
	h, err := ps.Start(resp)
	if err != nil {
		return nil
	}
	q, err := ps.Question()
	if err != nil {
		return nil
	}
	h.Truncated = true
	return buildAnswer(h, q, nil, 0)
}

// upstream asks the host's resolvers for name's A records: UDP first, TCP if truncated.
func (m *Manager) upstream(ctx context.Context, name dnsmessage.Name) ([]netip.Addr, uint32, dnsmessage.RCode, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := buildQuery(id, name)
	if err != nil {
		return nil, 0, 0, err
	}
	var last error
	for _, srv := range m.upstreams {
		ips, ttl, rc, tc, err := exchange(ctx, "udp", srv, q, id)
		if err == nil && tc {
			ips, ttl, rc, _, err = exchange(ctx, "tcp", srv, q, id)
		}
		if err == nil {
			return ips, ttl, rc, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("dns: no upstream resolvers")
	}
	return nil, 0, 0, last
}

func exchange(ctx context.Context, network string, srv netip.AddrPort, q []byte, id uint16) ([]netip.Addr, uint32, dnsmessage.RCode, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, network, srv.String())
	if err != nil {
		return nil, 0, 0, false, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if network == "tcp" {
		msg := binary.BigEndian.AppendUint16(nil, uint16(len(q))) //nolint:gosec // G115: a small query
		if _, err := c.Write(append(msg, q...)); err != nil {
			return nil, 0, 0, false, err
		}
		var l uint16
		if err := binary.Read(c, binary.BigEndian, &l); err != nil {
			return nil, 0, 0, false, err
		}
		resp := make([]byte, l)
		if _, err := io.ReadFull(c, resp); err != nil {
			return nil, 0, 0, false, err
		}
		return parseAAnswers(resp, id)
	}
	if _, err := c.Write(q); err != nil {
		return nil, 0, 0, false, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, 0, 0, false, err
		}
		ips, ttl, rc, tc, err := parseAAnswers(buf[:n], id)
		if err == nil {
			return ips, ttl, rc, tc, nil
		} // else a stray or spoofed packet: keep waiting until the deadline
	}
}

// hostResolvers reads the nameservers in /etc/resolv.conf.
func hostResolvers() ([]netip.AddrPort, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("netpol: upstream DNS: %w", err)
	}
	var out []netip.AddrPort
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil && a.Is4() {
				out = append(out, netip.AddrPortFrom(a, 53))
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("netpol: upstream DNS: no IPv4 nameserver in /etc/resolv.conf")
	}
	return out, nil
}

// parseAAnswers extracts the A records and the smallest TTL (A and CNAME) of a response.
func parseAAnswers(raw []byte, id uint16) ([]netip.Addr, uint32, dnsmessage.RCode, bool, error) {
	var ps dnsmessage.Parser
	h, err := ps.Start(raw)
	if err != nil {
		return nil, 0, 0, false, err
	}
	if h.ID != id || !h.Response {
		return nil, 0, 0, false, errors.New("dns: not our answer")
	}
	if err := ps.SkipAllQuestions(); err != nil {
		return nil, 0, 0, false, err
	}
	var ips []netip.Addr
	ttl := uint32(maxLearn / time.Second)
	for {
		rh, err := ps.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, 0, 0, false, err
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			a, err := ps.AResource()
			if err != nil {
				return nil, 0, 0, false, err
			}
			ips = append(ips, netip.AddrFrom4(a.A))
			ttl = min(ttl, rh.TTL)
		case dnsmessage.TypeCNAME:
			ttl = min(ttl, rh.TTL)
			if err := ps.SkipAnswer(); err != nil {
				return nil, 0, 0, false, err
			}
		default:
			if err := ps.SkipAnswer(); err != nil {
				return nil, 0, 0, false, err
			}
		}
	}
	if len(ips) == 0 {
		ttl = 0
	}
	return ips, ttl, h.RCode, h.Truncated, nil
}

func buildQuery(id uint16, name dnsmessage.Name) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}
