//go:build windows

package safetar

import (
	"io/fs"
	"os"
	"path"
)

func owner(fs.FileInfo) (uid, gid uint32)                   { return 0, 0 }
func openNoFollow(r *os.Root, rel string) (*os.File, error) { return r.Open(rel) }
func abs(rel string) string                                 { return path.Clean("/" + rel) }
