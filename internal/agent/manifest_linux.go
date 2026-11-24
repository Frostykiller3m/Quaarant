//go:build linux

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
)

// skipped are not part of the sandbox's filesystem: kernel views, devices, runtime state and
// qt's own files.
var skipped = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true, "/.qt": true, "/lost+found": true}

const batch = 500

// manifest streams the guest's filesystem in Entries frames.
func manifest(w *agentproto.Writer) error {
	var out []agentproto.Entry
	n := 0
	flush := func() error {
		if len(out) == 0 {
			return nil
		}
		err := w.JSON(agentproto.FrameEntries, out)
		out = out[:0]
		return err
	}
	err := filepath.WalkDir("/", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: skip, keep walking
		}
		if d.IsDir() && skipped[p] {
			return filepath.SkipDir
		}
		if p == "/" {
			return nil
		}
		if n++; n > agentproto.MaxEntries {
			return errors.New("manifest: too many files")
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		e := agentproto.Entry{Path: p, Mode: uint32(fi.Mode().Perm()) | specialBits(fi.Mode())}
		switch {
		case fi.Mode().IsRegular():
			e.Type, e.Size = "f", fi.Size()
			if fi.Size() <= agentproto.MaxHashed {
				e.SHA256 = hashFile(p)
			}
		case fi.IsDir():
			e.Type = "d"
		case fi.Mode()&fs.ModeSymlink != 0:
			e.Type = "l"
			e.Link, _ = os.Readlink(p)
		default:
			e.Type = "o"
		}
		out = append(out, e)
		if len(out) == batch {
			return flush()
		}
		return nil
	})
	if err != nil {
		return err
	}
	return flush()
}

func specialBits(m fs.FileMode) uint32 {
	var v uint32
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	return v
}

func hashFile(p string) string {
	f, err := os.Open(p) //nolint:gosec // G304: walking the guest's own filesystem
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
