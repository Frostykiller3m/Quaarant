//go:build linux

package netpol

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// nfnetlink_log (linux/netfilter/nfnetlink_log.h).
const (
	nfnlSubsysULog    = 4
	nfulnlMsgPacket   = 0
	nfulnlMsgConfig   = 1
	nfulaCfgCmd       = 1
	nfulaCfgMode      = 2
	nfulaCfgTimeout   = 4 // flush after this many 1/100 s
	nfulaCfgQthresh   = 5 // flush after this many packets
	nfulnlCfgCmdBind  = 1
	nfulnlCopyPacket  = 2
	nfulaIfindexIndev = 4
	nfulaPayload      = 9
	copyRange         = 64 // IPv4 header + the start of TCP/UDP: enough for addresses and ports
)

// nflog receives the packets the ruleset refused and logged to the manager's group.
type nflog struct {
	fd      int
	once    sync.Once
	done    chan struct{}
	stopped chan struct{} // closed when read returns
}

func openNflog(group uint16) (*nflog, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nflog: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nflog: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	n := &nflog{fd: fd, done: make(chan struct{}), stopped: make(chan struct{})}
	bind := []byte{nfulnlCfgCmdBind}
	mode := binary.BigEndian.AppendUint32(nil, copyRange)
	mode = append(mode, nfulnlCopyPacket, 0)
	for i, attr := range []struct {
		typ  uint16
		data []byte
	}{
		{nfulaCfgCmd, bind},
		{nfulaCfgMode, mode},
		{nfulaCfgQthresh, binary.BigEndian.AppendUint32(nil, 1)}, // deliver each refusal at once
		{nfulaCfgTimeout, binary.BigEndian.AppendUint32(nil, 1)},
	} {
		if err := n.config(group, uint32(i+1), attr.typ, attr.data); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}
	// A blocked recvfrom keeps the socket (and the group binding) alive after close(2), so
	// the reader wakes up regularly to notice it should stop.
	tv := unix.NsecToTimeval((250 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nflog: %w", err)
	}
	return n, nil
}

// config sends one NFULNL_MSG_CONFIG with a single attribute and waits for its ack.
func (n *nflog) config(group uint16, seq uint32, typ uint16, data []byte) error {
	attr := make([]byte, 4, 4+len(data)+3)
	binary.NativeEndian.PutUint16(attr[0:], uint16(4+len(data))) //nolint:gosec // G115: tiny
	binary.NativeEndian.PutUint16(attr[2:], typ)
	attr = append(attr, data...)
	for len(attr)%4 != 0 {
		attr = append(attr, 0)
	}
	body := []byte{unix.AF_UNSPEC, 0, 0, 0} // struct nfgenmsg: family, version, res_id (group, BE)
	binary.BigEndian.PutUint16(body[2:], group)
	body = append(body, attr...)
	msg := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(unix.NLMSG_HDRLEN+len(body))) //nolint:gosec // G115: tiny
	binary.NativeEndian.PutUint16(msg[4:], nfnlSubsysULog<<8|nfulnlMsgConfig)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], seq)
	msg = append(msg, body...)
	if err := unix.Sendto(n.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("nflog config: %w", err)
	}
	buf := make([]byte, 4096)
	for {
		m, _, err := unix.Recvfrom(n.fd, buf, 0)
		if err != nil {
			return fmt.Errorf("nflog config: %w", err)
		}
		for b := buf[:m]; len(b) >= unix.NLMSG_HDRLEN; {
			l := int(binary.NativeEndian.Uint32(b[0:4]))
			if l < unix.NLMSG_HDRLEN || l > len(b) {
				break
			}
			if binary.NativeEndian.Uint16(b[4:6]) == unix.NLMSG_ERROR && binary.NativeEndian.Uint32(b[8:12]) == seq {
				if code := int32(binary.NativeEndian.Uint32(b[16:20])); code != 0 { //nolint:gosec // G115: errno
					return fmt.Errorf("nflog config (group %d): %w", group, unix.Errno(-code))
				}
				return nil
			}
			b = b[(l+3)&^3:]
		}
	}
}

// close stops read (waiting for it if it runs) and closes the socket, which releases the
// group.
func (n *nflog) close() {
	n.once.Do(func() {
		close(n.done)
		select {
		case <-n.stopped:
		case <-time.After(2 * time.Second):
		}
		_ = unix.Close(n.fd)
	})
}

// refused is one logged packet: where it came from and where it was going.
type refused struct {
	ifindex int
	proto   string
	dst     netip.AddrPort
}

// read returns refused packets until the socket is closed.
func (n *nflog) read(out func(refused)) {
	defer close(n.stopped)
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-n.done:
			return
		default:
		}
		m, _, err := unix.Recvfrom(n.fd, buf, 0)
		if err == unix.EINTR || err == unix.ENOBUFS || err == unix.EAGAIN {
			continue // ENOBUFS: we fell behind, those refusals are lost; EAGAIN: the timeout
		}
		if err != nil {
			return
		}
		for b := buf[:m]; len(b) >= unix.NLMSG_HDRLEN; {
			l := int(binary.NativeEndian.Uint32(b[0:4]))
			if l < unix.NLMSG_HDRLEN || l > len(b) {
				break
			}
			if binary.NativeEndian.Uint16(b[4:6]) == nfnlSubsysULog<<8|nfulnlMsgPacket {
				if r, ok := parseNflogPacket(b[unix.NLMSG_HDRLEN:l]); ok {
					out(r)
				}
			}
			b = b[(l+3)&^3:]
		}
	}
}

// parseNflogPacket reads struct nfgenmsg + attributes: the incoming ifindex and the IPv4
// header and ports of the payload.
func parseNflogPacket(b []byte) (refused, bool) {
	if len(b) < 4 {
		return refused{}, false
	}
	var r refused
	var payload []byte
	for a := b[4:]; len(a) >= 4; {
		l := int(binary.NativeEndian.Uint16(a[0:2]))
		typ := binary.NativeEndian.Uint16(a[2:4]) &^ 0xc000
		if l < 4 || l > len(a) {
			break
		}
		v := a[4:l]
		switch typ {
		case nfulaIfindexIndev:
			if len(v) >= 4 {
				r.ifindex = int(binary.BigEndian.Uint32(v))
			}
		case nfulaPayload:
			payload = v
		}
		a = a[(l+3)&^3:]
	}
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return refused{}, false
	}
	ihl := int(payload[0]&0x0f) * 4
	dst := netip.AddrFrom4([4]byte(payload[16:20]))
	var port uint16
	switch payload[9] {
	case unix.IPPROTO_TCP:
		r.proto = "tcp"
	case unix.IPPROTO_UDP:
		r.proto = "udp"
	case unix.IPPROTO_ICMP:
		r.proto = "icmp"
	default:
		r.proto = strconv.Itoa(int(payload[9]))
	}
	if (r.proto == "tcp" || r.proto == "udp") && len(payload) >= ihl+4 {
		port = binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
	}
	r.dst = netip.AddrPortFrom(dst, port)
	return r, r.ifindex > 0
}

// refusedEvents are the events for a packet the kernel refused.
func refusedEvents(r refused, pool netip.Prefix, local []netip.Addr) []events.Payload {
	target := r.dst.String()
	if r.proto != "tcp" && r.proto != "udp" {
		target = r.dst.Addr().String()
	}
	den := events.PolicyDenied{Policy: "net", Target: target}
	switch err := Forbidden(r.dst.Addr(), pool, local); {
	case err != nil:
		den.Reason = rangeReason(r.dst.Addr())
		den.Rule = err.Error()
	default:
		den.Reason = "not_allowlisted"
		den.Rule = "only TCP and DNS leave a sandbox (" + r.proto + ")"
	}
	out := []events.Payload{den}
	switch r.proto { // the schema's net protocols
	case "tcp", "udp", "icmp":
		f := false
		out = append(out, events.Net{Op: "connect", Proto: r.proto, DstIP: r.dst.Addr().String(), DstPort: int(r.dst.Port()), Allowed: &f})
	}
	return out
}
