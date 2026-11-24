//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Proc connector (Documentation/driver-api/connector.rst, linux/cn_proc.h).
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventFork     = 0x1
	procEventExec     = 0x2
	procEventExit     = 0x80000000
	nlmsgDone         = 3
	nlmsgHdrLen       = 16
	cnMsgLen          = 20
)

// watchExec reports every execve in the guest, read back from /proc (path, argv, cwd, uid,
// parent). A process that exits before it is read is reported with what remains.
func (c *collector) watchExec() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("proc connector: %w", err)
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())} //nolint:gosec // G115: pid
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("proc connector bind: %w", err)
	}
	msg := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg))) //nolint:gosec // G115: 40
	binary.NativeEndian.PutUint16(msg[4:], nlmsgDone)
	binary.NativeEndian.PutUint32(msg[12:], uint32(os.Getpid())) //nolint:gosec // G115: pid
	binary.NativeEndian.PutUint32(msg[16:], cnIdxProc)
	binary.NativeEndian.PutUint32(msg[20:], cnValProc)
	binary.NativeEndian.PutUint16(msg[32:], 4)
	binary.NativeEndian.PutUint32(msg[36:], procCnMcastListen)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("proc connector listen: %w", err)
	}
	go c.readProcConnector(fd)
	return nil
}

func (c *collector) readProcConnector(fd int) {
	buf := make([]byte, 16<<10)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err == syscall.EINTR || err == syscall.ENOBUFS { // ENOBUFS: we fell behind; keep going
			continue
		}
		if err != nil {
			return
		}
		for b := buf[:n]; len(b) >= nlmsgHdrLen; {
			l := int(binary.NativeEndian.Uint32(b[0:4]))
			if l < nlmsgHdrLen || l > len(b) {
				break
			}
			body := b[nlmsgHdrLen:l]
			// cn_msg(20) then struct proc_event { what u32; cpu u32; timestamp u64; data }
			if len(body) >= cnMsgLen+16+16 {
				d := body[cnMsgLen+16:]                                                         // the event's data, after what/cpu/timestamp
				u := func(i int) int { return int(int32(binary.NativeEndian.Uint32(d[4*i:]))) } //nolint:gosec // G115: pid_t
				switch binary.NativeEndian.Uint32(body[cnMsgLen:]) {
				case procEventFork: // parent_pid, parent_tgid, child_pid, child_tgid
					if u(2) == u(3) {
						c.forked(u(1), u(3))
					}
				case procEventExec: // process_pid, process_tgid
					c.execed(u(1))
				case procEventExit: // process_pid, process_tgid, ...
					if u(0) == u(1) {
						c.exited(u(1))
					}
				}
			}
			b = b[(l+3)&^3:]
			if len(b) < nlmsgHdrLen {
				break
			}
		}
	}
}

func (c *collector) execed(pid int) {
	if c.ignored(pid) {
		return
	}
	proc := "/proc/" + strconv.Itoa(pid)
	exe, err := os.Readlink(proc + "/exe")
	if err != nil { // already gone: fall back to the binary fanotify saw it open for exec
		exe = c.execOpened(pid)
	}
	if exe == "" || strings.HasPrefix(exe, "/.qt/") { // unknown, or qt-agent spawn itself
		c.forgetExecOpen(pid)
		return
	}
	ev := execEvent{PID: pid, PPID: c.parentOf(pid), Path: boundPath(exe), Argv: []string{}}
	c.forgetExecOpen(pid) // a later exec by the same process starts fresh
	if raw, err := readLimited(proc+"/cmdline", 1<<20); err == nil {
		for i, a := range bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0}) {
			if i == maxArgs {
				ev.ArgvTruncated = true
				break
			}
			s := string(a)
			if len(s) > maxArgLen {
				s, ev.ArgvTruncated = truncate(s, maxArgLen), true
			}
			ev.Argv = append(ev.Argv, s)
		}
	}
	if len(ev.Argv) == 0 {
		ev.ArgvTruncated = true // the process exited before its argv could be read
	}
	if cwd, err := os.Readlink(proc + "/cwd"); err == nil && strings.HasPrefix(cwd, "/") {
		ev.Cwd = boundPath(cwd)
	}
	if st, err := readLimited(proc+"/status", 64<<10); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			f := strings.Fields(line)
			switch {
			case len(f) >= 2 && f[0] == "PPid:":
				if n, err := strconv.Atoi(f[1]); err == nil {
					ev.PPID = n
				}
			case len(f) >= 2 && f[0] == "Uid:":
				if u, err := strconv.ParseUint(f[1], 10, 32); err == nil {
					uid := uint32(u)
					ev.UID = &uid
				}
			}
		}
	}
	c.emit("exec", ev)
}

func readLimited(p string, n int64) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // G304: /proc paths we build
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, n)
	m, err := f.Read(b)
	if m > 0 {
		return b[:m], nil
	}
	return nil, err
}

// Process bookkeeping for exec events of processes that exit before /proc can be read.
const maxTracked = 65536

func (c *collector) forked(parent, child int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.parents == nil || len(c.parents) > maxTracked {
		c.parents = map[int]int{}
	}
	c.parents[child] = parent
}

func (c *collector) exited(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.parents, pid)
	delete(c.execPaths, pid)
}

func (c *collector) parentOf(pid int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.parents[pid]
}

func (c *collector) sawExecOpen(pid int, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.execPaths == nil || len(c.execPaths) > maxTracked {
		c.execPaths = map[int]string{}
	}
	if _, ok := c.execPaths[pid]; !ok { // the binary comes first; its ELF interpreter (ld.so) after
		c.execPaths[pid] = path
	}
}

// execOpened is the binary pid opened for exec, waiting briefly: fanotify and the proc
// connector are separate streams, so it may arrive a moment later.
func (c *collector) execOpened(pid int) string {
	for range 5 {
		c.mu.Lock()
		p := c.execPaths[pid]
		c.mu.Unlock()
		if p != "" {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	return ""
}

func (c *collector) forgetExecOpen(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.execPaths, pid)
}
