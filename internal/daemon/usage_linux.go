//go:build linux

package daemon

import (
	"io/fs"
	"syscall"
)

// allocated is the disk space a file takes (sparse files: less than their size).
func allocated(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return fi.Size()
}
