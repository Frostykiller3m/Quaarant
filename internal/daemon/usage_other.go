//go:build !linux

package daemon

import "io/fs"

func allocated(fi fs.FileInfo) int64 { return fi.Size() }
