//go:build !windows

package safetar

import (
	"io/fs"
	"os"
	"path"
	"syscall"
)

func owner(fi fs.FileInfo) (uid, gid uint32) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, st.Gid
	}
	return 0, 0
}

// openNoFollow opens rel for reading without following a final symlink and without blocking
// on a fifo swapped in by untrusted code.
func openNoFollow(r *os.Root, rel string) (*os.File, error) {
	return r.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func abs(rel string) string { return path.Clean("/" + rel) }
