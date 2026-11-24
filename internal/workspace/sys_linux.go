//go:build linux

package workspace

import (
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// isWhiteout: overlayfs marks a deleted lower entry with a 0/0 character device in upper.
func isWhiteout(fi fs.FileInfo) bool {
	if fi.Mode()&fs.ModeCharDevice == 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Rdev == 0
}

// isOpaque: an upper directory with the opaque xattr hides the lower directory's contents.
func isOpaque(r *os.Root, rel string) bool {
	f, err := r.Open(rel)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	opaque := false
	_ = rc.Control(func(fd uintptr) {
		buf := make([]byte, 8)
		for _, attr := range []string{"trusted.overlay.opaque", "user.overlay.opaque"} {
			if n, err := unix.Fgetxattr(int(fd), attr, buf); err == nil && n > 0 && buf[0] == 'y' {
				opaque = true
				return
			}
		}
	})
	return opaque
}

func owner(fi fs.FileInfo) (uid, gid uint32) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, st.Gid
	}
	return 0, 0
}

// openNoFollow opens rel for reading without following a final symlink and without blocking
// on a fifo the sandbox may have swapped in.
func openNoFollow(r *os.Root, rel string) (*os.File, error) {
	return r.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
