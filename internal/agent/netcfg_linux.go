//go:build linux

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
)

// ioctl numbers (linux/sockios.h) and route flags (linux/route.h).
const (
	siocSIFADDR    = 0x8916
	siocSIFNETMASK = 0x891c
	siocADDRT      = 0x890b
	rtfUp          = 0x1
	rtfGateway     = 0x2
)

// configureNet gives eth0 its address and a default route through the gateway.
func configureNet(n *agentproto.Net) error {
	pfx, err := netip.ParsePrefix(n.Addr)
	if err != nil || !pfx.Addr().Is4() {
		return fmt.Errorf("net: bad address %.64q", n.Addr)
	}
	gw, err := netip.ParseAddr(n.Gateway)
	if err != nil || !gw.Is4() || !pfx.Contains(gw) {
		return fmt.Errorf("net: bad gateway %.64q", n.Gateway)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("net: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	mask := netip.AddrFrom4(maskOf(pfx.Bits()))
	for _, step := range []struct {
		req  uintptr
		addr netip.Addr
	}{{siocSIFADDR, pfx.Addr()}, {siocSIFNETMASK, mask}} {
		var ifr [40]byte
		copy(ifr[:], "eth0")
		putSockaddr(ifr[16:32], step.addr)
		if err := ioctl(fd, step.req, unsafe.Pointer(&ifr[0])); err != nil { //nolint:gosec // G103: struct ifreq
			return fmt.Errorf("net: eth0 address: %w", err)
		}
	}
	var ifr [40]byte
	copy(ifr[:], "eth0")
	*(*uint16)(unsafe.Pointer(&ifr[16])) = syscall.IFF_UP | syscall.IFF_RUNNING      //nolint:gosec // G103: struct ifreq
	if err := ioctl(fd, syscall.SIOCSIFFLAGS, unsafe.Pointer(&ifr[0])); err != nil { //nolint:gosec // G103: struct ifreq
		return fmt.Errorf("net: eth0 up: %w", err)
	}
	// struct rtentry (LP64): pad 8, dst 16, gateway 16, genmask 16, flags u16 @56, ... dev @88.
	var rt [120]byte
	putSockaddr(rt[8:24], netip.IPv4Unspecified())
	putSockaddr(rt[24:40], gw)
	putSockaddr(rt[40:56], netip.IPv4Unspecified())
	binary.NativeEndian.PutUint16(rt[56:58], rtfUp|rtfGateway)
	if err := ioctl(fd, siocADDRT, unsafe.Pointer(&rt[0])); err != nil && !errors.Is(err, syscall.EEXIST) { //nolint:gosec // G103: struct rtentry
		return fmt.Errorf("net: default route: %w", err)
	}
	return nil
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// putSockaddr writes a struct sockaddr_in.
func putSockaddr(b []byte, a netip.Addr) {
	binary.NativeEndian.PutUint16(b[0:2], syscall.AF_INET)
	ip := a.As4()
	copy(b[4:8], ip[:])
}

func maskOf(bits int) [4]byte {
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], ^uint32(0)<<(32-bits))
	return m
}
