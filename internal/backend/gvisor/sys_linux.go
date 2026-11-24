//go:build linux

package gvisor

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/cgroups"
)

const cgroupRoot = cgroups.Root

func mountOverlay(lower, upper, work, target string) error {
	// metacopy/redirect_dir off: every changed file keeps its full content in upper, and renamed
	// directories are copied, so upper alone (plus whiteouts) describes all changes.
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work + ",redirect_dir=off,metacopy=off,index=off"
	if err := unix.Mount("overlay", target, "overlay", unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("mount overlay on %s: %w", target, err)
	}
	return nil
}

// mounted reports whether target is a mount point on a different filesystem than parent.
func mounted(target, parent string) bool {
	var a, b unix.Stat_t
	if unix.Lstat(target, &a) != nil || unix.Lstat(parent, &b) != nil {
		return false
	}
	return a.Dev != b.Dev
}

func unmount(target string) error {
	for i := 0; ; i++ {
		err := unix.Unmount(target, 0)
		switch {
		case err == nil:
			continue // stacked mounts: keep going until EINVAL
		case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOENT):
			return nil // not a mount point (any more)
		case errors.Is(err, unix.EBUSY) && i < 20:
			time.Sleep(50 * time.Millisecond)
		case errors.Is(err, unix.EBUSY):
			if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
				return fmt.Errorf("unmount %s: %w", target, err)
			}
			return nil
		default:
			return fmt.Errorf("unmount %s: %w", target, err)
		}
	}
}

// openPTY returns a new pseudo-terminal pair. The master stays non-blocking (in the runtime
// poller) so closing it interrupts a pending read.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	var n uint32
	err = control(master, func(fd int) error {
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return fmt.Errorf("unlock pty: %w", err)
		}
		var err error
		n, err = unix.IoctlGetUint32(fd, unix.TIOCGPTN)
		if err != nil {
			return fmt.Errorf("pty number: %w", err)
		}
		return nil
	})
	if err != nil {
		_ = master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("open pty slave: %w", err)
	}
	return master, slave, nil
}

func setWinsize(f *os.File, ws backend.WindowSize) error {
	return control(f, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: ws.Rows, Col: ws.Cols})
	})
}

func control(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("pty: %w", err)
	}
	var inner error
	if err := rc.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return fmt.Errorf("pty: %w", err)
	}
	return inner
}

// ttyProcAttr makes the pty slave (fd 0) the controlling terminal of runsc exec, so the
// terminal's signals and size reach the sandboxed process.
func ttyProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}

func ensureCgroupParent(parent string) error { return cgroups.EnsureParent(parent) }
func removeCgroup(path string) error         { return cgroups.Remove(path) }
