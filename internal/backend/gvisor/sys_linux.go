//go:build linux

package gvisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

const cgroupRoot = "/sys/fs/cgroup"

func mountOverlay(lower, upper, work, target string) error {
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", target, "overlay", unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("mount overlay on %s: %w", target, err)
	}
	return nil
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

// ensureCgroupParent creates the parent cgroup and delegates the cpu, memory and pids
// controllers to its children (cgroup v2).
func ensureCgroupParent(parent string) error {
	dir := filepath.Join(cgroupRoot, parent)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: cgroupfs directory, mode is ignored
		return fmt.Errorf("create %s: %w", dir, err)
	}
	for _, d := range []string{cgroupRoot, dir} {
		for _, c := range []string{"cpu", "memory", "pids"} {
			f := filepath.Join(d, "cgroup.subtree_control")
			if err := os.WriteFile(f, []byte("+"+c), 0); err != nil {
				return fmt.Errorf("enable %s in %s: %w", c, f, err)
			}
		}
	}
	return nil
}

func removeCgroup(path string) error {
	dir := filepath.Join(cgroupRoot, path)
	for i := 0; ; i++ {
		err := unix.Rmdir(dir)
		switch {
		case err == nil, errors.Is(err, unix.ENOENT):
			return nil
		case errors.Is(err, unix.EBUSY) && i < 40:
			time.Sleep(50 * time.Millisecond)
		default:
			return fmt.Errorf("remove cgroup %s: %w", dir, err)
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
