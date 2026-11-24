//go:build linux

package agent

import (
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"strconv"
	"syscall"
	"unsafe"
)

// fanotify(7) ABI values (not in the frozen syscall package).
const (
	fanClassNotif     = 0x0
	fanCloexec        = 0x1
	fanReportDFIDName = 0x400 | 0x800 // FAN_REPORT_DIR_FID | FAN_REPORT_NAME
	fanMarkAdd        = 0x1
	fanMarkFilesystem = 0x100

	fanAttrib     = 0x4
	fanCloseWrite = 0x8
	fanOpen       = 0x20
	fanOpenExec   = 0x1000
	fanCreate     = 0x100
	fanDelete     = 0x200
	fanQOverflow  = 0x4000
	fanRename     = 0x10000000
	fanOnDir      = 0x40000000

	infoDFIDName    = 2
	infoDFID        = 3
	infoOldDFIDName = 10
	infoNewDFIDName = 12

	metadataLen = 24       // struct fanotify_event_metadata
	oPath       = 0x200000 // O_PATH (amd64 and arm64; not in the frozen syscall package)
	atFDCWD     = -100
)

// watchFiles reports file activity on the root filesystem: open, write (close after
// writing), create, mkdir, unlink, rename and chmod, each with a full path (resolved from the
// parent directory's file handle). Failed opens are invisible to fanotify.
func (c *collector) watchFiles() error {
	fd, _, e := syscall.Syscall(syscall.SYS_FANOTIFY_INIT, fanClassNotif|fanCloexec|fanReportDFIDName, uintptr(syscall.O_RDONLY|syscall.O_LARGEFILE), 0)
	if e != 0 {
		return fmt.Errorf("fanotify_init: %w", e)
	}
	root, err := syscall.BytePtrFromString("/")
	if err != nil {
		return err
	}
	mask := uint64(fanOpen | fanOpenExec | fanCloseWrite | fanCreate | fanDelete | fanRename | fanAttrib | fanOnDir)
	dirfd := atFDCWD                                                                                                                                                       // a variable: converting the negative value to uintptr sign-extends, as the kernel expects
	if _, _, e := syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, fd, fanMarkAdd|fanMarkFilesystem, uintptr(mask), uintptr(dirfd), uintptr(unsafe.Pointer(root)), 0); e != 0 { //nolint:gosec // G103: fanotify_mark(2) path argument
		return fmt.Errorf("fanotify_mark: %w", e)
	}
	mountFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /: %w", err)
	}
	go c.readFanotify(int(fd), mountFD)
	return nil
}

func (c *collector) readFanotify(fd, mountFD int) {
	buf := make([]byte, 64<<10)
	for {
		n, err := syscall.Read(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || n <= 0 {
			return
		}
		b := buf[:n]
		for len(b) >= metadataLen {
			evLen := int(binary.NativeEndian.Uint32(b[0:4]))
			if evLen < metadataLen || evLen > len(b) {
				break
			}
			c.fanEvent(b[:evLen], mountFD)
			b = b[evLen:]
		}
	}
}

type dirName struct {
	dir  string
	name string
}

func (c *collector) fanEvent(ev []byte, mountFD int) {
	mask := binary.NativeEndian.Uint64(ev[8:16])
	pid := int(int32(binary.NativeEndian.Uint32(ev[20:24]))) //nolint:gosec // G115: pid_t
	if mask&fanQOverflow != 0 || c.ignored(pid) {
		return
	}
	hdrLen := int(binary.NativeEndian.Uint16(ev[6:8]))
	var plain, old, nw *dirName
	for off := hdrLen; off+4 <= len(ev); {
		typ := ev[off]
		l := int(binary.NativeEndian.Uint16(ev[off+2 : off+4]))
		if l < 4 || off+l > len(ev) {
			break
		}
		if dn, ok := resolveInfo(ev[off:off+l], typ, mountFD); ok {
			switch typ {
			case infoOldDFIDName:
				old = &dn
			case infoNewDFIDName:
				nw = &dn
			default:
				plain = &dn
			}
		}
		off += l
	}
	full := func(d *dirName) string {
		if d == nil {
			return ""
		}
		return boundPath(path.Join(d.dir, d.name))
	}
	onDir := mask&fanOnDir != 0
	switch {
	case mask&fanRename != 0:
		if p, np := full(old), full(nw); p != "" && np != "" {
			c.emit("file", fileEvent{Op: "rename", Path: p, NewPath: np, PID: pid})
		}
	case plain == nil:
	case mask&fanCreate != 0:
		op := "create"
		if onDir {
			op = "mkdir"
		}
		ev := fileEvent{Op: op, Path: full(plain), PID: pid}
		if fi, err := os.Lstat(ev.Path); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				if t, err := os.Readlink(ev.Path); err == nil && t != "" {
					ev.Op, ev.NewPath = "symlink", boundPath(t)
				}
			} else {
				ev.Mode = modeString(fi.Mode())
			}
		}
		c.emit("file", ev)
	case mask&fanDelete != 0:
		c.emit("file", fileEvent{Op: "unlink", Path: full(plain), PID: pid})
	case mask&fanAttrib != 0:
		p := full(plain)
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			c.emit("file", fileEvent{Op: "chmod", Path: p, PID: pid, Mode: modeString(fi.Mode())})
		}
	case onDir: // opens and writes of directories (ls, find): noise
	case mask&fanCloseWrite != 0:
		p := full(plain)
		ev := fileEvent{Op: "write", Path: p, PID: pid}
		if fi, err := os.Lstat(p); err == nil {
			n := fi.Size()
			ev.Bytes = &n // its size when the event is processed (best effort: absent if already gone)
		}
		c.emit("file", ev)
	case mask&fanOpen != 0 || mask&fanOpenExec != 0:
		p := full(plain)
		if mask&fanOpenExec != 0 {
			c.sawExecOpen(pid, p) // the binary, in case the process is gone before /proc is read
		}
		if mask&fanOpen != 0 {
			c.emit("file", fileEvent{Op: "open", Path: p, PID: pid})
		}
	}
}

// resolveInfo turns a (parent directory handle, name) info record into a path.
func resolveInfo(rec []byte, typ byte, mountFD int) (dirName, bool) {
	switch typ {
	case infoDFIDName, infoDFID, infoOldDFIDName, infoNewDFIDName:
	default:
		return dirName{}, false
	}
	// struct fanotify_event_info_fid: hdr(4) fsid(8) struct file_handle { u32 bytes; i32 type; data }
	if len(rec) < 4+8+8 {
		return dirName{}, false
	}
	fh := rec[12:]
	hb := int(binary.NativeEndian.Uint32(fh[0:4]))
	if hb <= 0 || hb > 128 || 8+hb > len(fh) {
		return dirName{}, false
	}
	handle := make([]byte, 8+hb)
	copy(handle, fh[:8+hb])
	dir, err := handlePath(mountFD, handle)
	if err != nil {
		return dirName{}, false
	}
	name := ""
	if typ != infoDFID {
		rest := fh[8+hb:]
		for i, ch := range rest {
			if ch == 0 {
				rest = rest[:i]
				break
			}
		}
		name = string(rest)
	}
	return dirName{dir: dir, name: name}, true
}

// handlePath opens a directory by its file handle and reads its path back from /proc.
func handlePath(mountFD int, handle []byte) (string, error) {
	fd, _, e := syscall.Syscall(sysOpenByHandleAt, uintptr(mountFD), uintptr(unsafe.Pointer(&handle[0])), uintptr(oPath|syscall.O_CLOEXEC)) //nolint:gosec // G103: struct file_handle
	if e != 0 {
		return "", e
	}
	defer func() { _ = syscall.Close(int(fd)) }()
	return os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
}
