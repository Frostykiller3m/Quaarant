//go:build !linux

package workspace

import (
	"io/fs"
	"os"
)

// Overlay whiteouts, opaque directories and ownership only exist on Linux.

func isWhiteout(fs.FileInfo) bool                           { return false }
func isOpaque(*os.Root, string) bool                        { return false }
func owner(fs.FileInfo) (uid, gid uint32)                   { return 0, 0 }
func openNoFollow(r *os.Root, rel string) (*os.File, error) { return r.Open(rel) }
