//go:build linux

package agent

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// AgentPath is where the agent lives inside the guest: a read-only tmpfs, never the disk.
const AgentPath = "/.qt/qt-agent"

const rootDevice = "/dev/vda"

// InitStage1 runs as PID 1 from qtd's initramfs: it mounts the sandbox's disk, puts a copy
// of the agent on a tmpfs at /.qt (the disk image never contains qt's code), and switches
// root into the disk, re-executing as "init2".
func InitStage1() int {
	if err := stage1(); err != nil {
		fmt.Fprintln(os.Stderr, "qt-agent init:", err)
		time.Sleep(time.Second) // let the console flush; the kernel panics when PID 1 exits
		return 1
	}
	return 0 // not reached: stage1 execs
}

func stage1() error {
	for _, d := range []string{"/dev", "/proc", "/newroot"} {
		_ = os.MkdirAll(d, 0o755) //nolint:gosec // G301: initramfs mount points
	}
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", syscall.MS_NOSUID, "mode=0755"); err != nil && err != syscall.EBUSY {
		return fmt.Errorf("mount /dev: %w", err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	var err error
	for range 100 { // the disk can appear a moment after PID 1 starts
		if err = syscall.Mount(rootDevice, "/newroot", "ext4", syscall.MS_NOSUID|syscall.MS_NODEV, ""); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("mount %s: %w", rootDevice, err)
	}
	// Mount points the image may lack. /.qt is a tmpfs on top: only the empty directory
	// lands on the disk.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{"/newroot/.qt", 0o755}, {"/newroot/dev", 0o755}, {"/newroot/proc", 0o555}, {"/newroot/sys", 0o555}, {"/newroot/tmp", 0o1777}} {
		if fi, err := os.Lstat(d.path); err == nil && !fi.IsDir() {
			return fmt.Errorf("%s in the image is not a directory", strings.TrimPrefix(d.path, "/newroot"))
		}
		if err := os.Mkdir(d.path, d.mode.Perm()); err == nil && d.mode&os.ModeSticky != 0 {
			_ = os.Chmod(d.path, d.mode)
		}
	}
	if err := syscall.Mount("tmpfs", "/newroot/.qt", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755,size=32m"); err != nil {
		return fmt.Errorf("mount /.qt: %w", err)
	}
	if err := copyFile("/init", "/newroot"+AgentPath, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("/dev", "/newroot/dev", "", syscall.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move /dev: %w", err)
	}
	_ = syscall.Unmount("/proc", syscall.MNT_DETACH)
	_ = os.Remove("/init") // free the initramfs copy
	if err := os.Chdir("/newroot"); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}
	if err := syscall.Mount(".", "/", "", syscall.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move root: %w", err)
	}
	if err := syscall.Chroot("."); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	return syscall.Exec(AgentPath, []string{AgentPath, "init2"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) //nolint:gosec // G304: fixed paths (/init -> /.qt)
	if err != nil {
		return fmt.Errorf("copy agent: %w", err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) //nolint:gosec // G304: fixed paths (/init -> /.qt)
	if err != nil {
		return fmt.Errorf("copy agent: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy agent: %w", err)
	}
	return out.Close()
}

// InitStage2 is PID 1 inside the sandbox's root: it mounts the kernel filesystems, sets the
// hostname, brings up loopback, makes /.qt read-only, and keeps "qt-agent serve" (the part
// that talks to qtd) running as its child. Signals from sandboxed code are ignored; PID 1 is
// root-owned, so a non-root sandbox user cannot kill it anyway.
func InitStage2() int {
	mounts := []struct {
		src, target, fstype string
		flags               uintptr
		data                string
		mode                os.FileMode
	}{
		{"proc", "/proc", "proc", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, "", 0o555},
		{"sysfs", "/sys", "sysfs", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_RDONLY, "", 0o555},
		{"devpts", "/dev/pts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620", 0o755},
		{"tmpfs", "/dev/shm", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, "mode=1777,size=64m", 0o1777},
	}
	for _, m := range mounts {
		_ = os.MkdirAll(m.target, m.mode.Perm())
		if err := syscall.Mount(m.src, m.target, m.fstype, m.flags, m.data); err != nil {
			fmt.Fprintf(os.Stderr, "qt-agent init: mount %s: %v\n", m.target, err)
		}
	}
	_ = os.Remove("/dev/ptmx")
	_ = os.Symlink("pts/ptmx", "/dev/ptmx")
	if err := syscall.Mount("tmpfs", "/.qt", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err != nil {
		fmt.Fprintln(os.Stderr, "qt-agent init: remount /.qt read-only:", err)
	}
	if h := cmdlineParam("qt.hostname"); h != "" {
		_ = syscall.Sethostname([]byte(h))
	}
	if err := loopbackUp(); err != nil {
		fmt.Fprintln(os.Stderr, "qt-agent init: loopback:", err)
	}
	ignoreSignals()
	return superviseServe()
}

// superviseServe reaps every child (PID 1's job) and restarts serve if it dies.
func superviseServe() int {
	var servePID int
	start := func() {
		p, err := os.StartProcess(AgentPath, []string{AgentPath, "serve"}, &os.ProcAttr{
			Env:   []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"},
			Files: []*os.File{nil, os.Stdout, os.Stderr},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "qt-agent init: start serve:", err)
			servePID = 0
			return
		}
		servePID = p.Pid
	}
	start()
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil { // ECHILD: nothing to reap
			time.Sleep(200 * time.Millisecond)
			if servePID == 0 {
				start()
			}
			continue
		}
		if pid == servePID {
			fmt.Fprintln(os.Stderr, "qt-agent init: serve exited, restarting:", ws)
			time.Sleep(100 * time.Millisecond)
			start()
		}
	}
}

func cmdlineParam(name string) string {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(string(b)) {
		if v, ok := strings.CutPrefix(f, name+"="); ok {
			return v
		}
	}
	return ""
}

// loopbackUp sets IFF_UP on lo (struct ifreq { char name[16]; short flags; ... }).
func loopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	var ifr [40]byte
	copy(ifr[:], "lo")
	*(*uint16)(unsafe.Pointer(&ifr[16])) = syscall.IFF_UP | syscall.IFF_RUNNING                                                     //nolint:gosec // G103: struct ifreq
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 { //nolint:gosec // G103: ioctl(SIOCSIFFLAGS)
		return e
	}
	return nil
}

// kernelRelease is uname -r.
func kernelRelease() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c)) //nolint:gosec // G115: utsname chars are ASCII
	}
	return string(bytes.TrimSpace(b))
}
