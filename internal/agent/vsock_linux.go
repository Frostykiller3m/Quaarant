//go:build linux

package agent

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// AF_VSOCK is not in the frozen syscall package; these are the Linux ABI values.
const (
	afVsock      = 40
	vmaddrCIDAny = 0xFFFFFFFF
)

// sockaddrVM is struct sockaddr_vm.
type sockaddrVM struct {
	Family    uint16
	Reserved1 uint16
	Port      uint32
	CID       uint32
	Zero      [4]uint8
}

// vsockListener is a listening AF_VSOCK socket.
type vsockListener struct{ fd int }

func listenVsock(port uint32) (*vsockListener, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	sa := sockaddrVM{Family: afVsock, Port: port, CID: vmaddrCIDAny}
	if _, _, e := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); e != 0 { //nolint:gosec // G103: sockaddr_vm for bind(2)
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock bind port %d: %w", port, e)
	}
	if err := syscall.Listen(fd, 64); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("vsock listen: %w", err)
	}
	return &vsockListener{fd: fd}, nil
}

// accept blocks for the next connection.
func (l *vsockListener) accept() (*os.File, error) {
	for {
		nfd, _, e := syscall.Syscall6(syscall.SYS_ACCEPT4, uintptr(l.fd), 0, 0, syscall.SOCK_CLOEXEC, 0, 0)
		if e == syscall.EINTR {
			continue
		}
		if e != 0 {
			return nil, fmt.Errorf("vsock accept: %w", e)
		}
		return os.NewFile(nfd, "vsock"), nil
	}
}
