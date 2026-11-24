//go:build linux

package netpol

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// nflogPacket builds the body of an NFULNL_MSG_PACKET: nfgenmsg, then INDEV and PAYLOAD.
func nflogPacket(ifindex uint32, proto byte, dst [4]byte, port uint16) []byte {
	b := []byte{2, 0, 0, 7} // AF_INET, v0, group 7
	attr := func(typ uint16, v []byte) {
		a := make([]byte, 4, 4+len(v)+3)
		binary.NativeEndian.PutUint16(a[0:], uint16(4+len(v)))
		binary.NativeEndian.PutUint16(a[2:], typ)
		a = append(a, v...)
		for len(a)%4 != 0 {
			a = append(a, 0)
		}
		b = append(b, a...)
	}
	attr(nfulaIfindexIndev, binary.BigEndian.AppendUint32(nil, ifindex))
	ip := make([]byte, 28)
	ip[0], ip[9] = 0x45, proto
	copy(ip[12:16], []byte{10, 231, 0, 6})
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[22:24], port)
	attr(nfulaPayload, ip)
	return b
}

func TestNflogPacket(t *testing.T) {
	r, ok := parseNflogPacket(nflogPacket(9, 6, [4]byte{169, 254, 169, 254}, 80))
	if !ok || r.ifindex != 9 || r.proto != "tcp" || r.dst.String() != "169.254.169.254:80" {
		t.Fatalf("%+v %v", r, ok)
	}
	evs := refusedEvents(r, DefaultPool, nil)
	if d := evs[0].(events.PolicyDenied); d.Reason != "metadata" || d.Target != "169.254.169.254:80" {
		t.Errorf("%+v", d)
	}
	r, _ = parseNflogPacket(nflogPacket(9, 17, [4]byte{8, 8, 8, 8}, 123))
	if d := refusedEvents(r, DefaultPool, nil)[0].(events.PolicyDenied); d.Reason != "not_allowlisted" || r.proto != "udp" {
		t.Errorf("udp to a public address: %+v", d)
	}
	r, _ = parseNflogPacket(nflogPacket(9, 1, [4]byte{1, 1, 1, 1}, 0))
	evs = refusedEvents(r, DefaultPool, nil)
	if d := evs[0].(events.PolicyDenied); d.Target != "1.1.1.1" || r.proto != "icmp" {
		t.Errorf("icmp: %+v", d)
	}
	r, _ = parseNflogPacket(nflogPacket(9, 6, [4]byte{203, 0, 114, 9}, 22))
	if d := refusedEvents(r, DefaultPool, []netip.Addr{netip.MustParseAddr("203.0.114.9")})[0].(events.PolicyDenied); d.Reason != "blocked_range" {
		t.Errorf("this host: %+v", d)
	}
	for _, junk := range [][]byte{nil, {1, 2}, {2, 0, 0, 7, 8, 0, 4, 0}} {
		if _, ok := parseNflogPacket(junk); ok {
			t.Errorf("parsed junk %x", junk)
		}
	}
}
