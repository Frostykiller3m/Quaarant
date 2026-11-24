//go:build linux

package netpol

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// CreateTap makes a persistent tap device that uid (an unprivileged VMM) may open.
func CreateTap(name string, uid int) error { return createTap(name, uid) }

// DeleteTap removes a persistent tap device.
func DeleteTap(name string) error { return deleteTap(name) }

func tunIoctl(name string, flags uint16, ops ...[2]uintptr) error {
	if len(name) >= unix.IFNAMSIZ {
		return fmt.Errorf("tap name %q is too long", name)
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("tap %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("tap %s: %w", name, err)
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(int(f.Fd()), unix.TUNSETIFF, ifr); err != nil {
		return fmt.Errorf("tap %s: TUNSETIFF: %w", name, err)
	}
	for _, op := range ops {
		if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), op[0], op[1]); e != 0 {
			return fmt.Errorf("tap %s: ioctl %#x: %w", name, op[0], e)
		}
	}
	return nil
}

func createTap(name string, uid int) error {
	if uid < 0 {
		return fmt.Errorf("tap %s: bad owner %d", name, uid)
	}
	if _, err := os.Lstat("/sys/class/net/" + name); err == nil {
		return fmt.Errorf("tap %s: %w", name, os.ErrExist) // TUNSETIFF would attach to it
	}
	return tunIoctl(name, unix.IFF_TAP|unix.IFF_NO_PI|unix.IFF_VNET_HDR,
		[2]uintptr{unix.TUNSETOWNER, uintptr(uid)}, [2]uintptr{unix.TUNSETGROUP, uintptr(uid)},
		[2]uintptr{unix.TUNSETPERSIST, 1})
}

func deleteTap(name string) error {
	if _, err := os.Lstat("/sys/class/net/" + name); err != nil {
		return fmt.Errorf("tap %s: %w", name, os.ErrNotExist)
	}
	return tunIoctl(name, unix.IFF_TAP|unix.IFF_NO_PI|unix.IFF_VNET_HDR, [2]uintptr{unix.TUNSETPERSIST, 0})
}
