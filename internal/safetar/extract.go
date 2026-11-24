// Package safetar reads and writes tar archives whose contents are untrusted (image layers,
// files copied into or out of sandboxes) without letting them touch anything outside the
// directory they belong to. It uses only the standard library, so qt-agent can use it too.
package safetar

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
)

// UnpackLimits bound what an (untrusted) image may unpack to.
type UnpackLimits struct {
	MaxBytes   int64 // total size of regular files
	MaxEntries int   // number of tar entries
}

// DefaultUnpackLimits are generous for real images and still stop a decompression bomb.
var DefaultUnpackLimits = UnpackLimits{MaxBytes: 16 << 30, MaxEntries: 2_000_000}

// ErrLimit is wrapped by Unpack when an image exceeds UnpackLimits.
var ErrLimit = errors.New("image exceeds unpack limits")

// UnpackStats describes what Unpack did.
type UnpackStats struct {
	Files, Dirs, Symlinks, Hardlinks int
	Skipped                          int // device nodes, fifos and unknown entry types
	Bytes                            int64
}

// Unpack extracts a flattened image filesystem (a tar stream with whiteouts already applied)
// into dst, which must exist and be empty.
//
// Image contents are untrusted. Every filesystem operation goes through an os.Root, so no
// entry name, symlink or hard link can create or modify anything outside dst. Device nodes and
// fifos are skipped, setuid/setgid bits are dropped, and sizes are bounded by lim. When chown
// is true (qtd runs as root), file ownership from the image is kept.
func Unpack(r io.Reader, dst string, lim UnpackLimits, chown bool) (UnpackStats, error) {
	root, err := os.OpenRoot(dst)
	if err != nil {
		return UnpackStats{}, fmt.Errorf("open unpack root: %w", err)
	}
	defer func() { _ = root.Close() }()
	var own Ownership = KeepOwner
	if !chown {
		own = nil
	}
	return UnpackInto(r, root, lim, own)
}

// Ownership decides the owner of each unpacked entry; nil leaves files owned by the caller.
type Ownership func(hdr *tar.Header) (uid, gid int)

// KeepOwner keeps the uid/gid recorded in the archive (image layers).
func KeepOwner(hdr *tar.Header) (int, int) { return hdr.Uid, hdr.Gid }

// OwnedBy gives every entry the same owner (files copied into a sandbox belong to its user).
func OwnedBy(uid, gid int) Ownership { return func(*tar.Header) (int, int) { return uid, gid } }

// UnpackInto is Unpack into an already opened root, with ownership chosen by own (nil = don't
// chown). The same guarantees hold: nothing outside root can be touched.
func UnpackInto(r io.Reader, root *os.Root, lim UnpackLimits, own Ownership) (UnpackStats, error) {
	var st UnpackStats
	chown := own != nil

	type dirMode struct {
		name  string
		mode  fs.FileMode
		mtime time.Time
	}
	var dirs []dirMode
	entries := 0
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return st, fmt.Errorf("read image tar: %w", err)
		}
		entries++
		if entries > lim.MaxEntries {
			return st, fmt.Errorf("%w: more than %d entries", ErrLimit, lim.MaxEntries)
		}
		name, ok, err := cleanName(hdr.Name)
		if err != nil {
			return st, err
		}
		if !ok { // the root directory itself
			continue
		}
		mode := safeMode(hdr.FileInfo().Mode())

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAll(root, name); err != nil {
				return st, err
			}
			dirs = append(dirs, dirMode{name, mode, hdr.ModTime})
			st.Dirs++
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // SA1019: old images still use TypeRegA
			if hdr.Size < 0 || st.Bytes+hdr.Size > lim.MaxBytes {
				return st, fmt.Errorf("%w: more than %d bytes", ErrLimit, lim.MaxBytes)
			}
			if err := writeFile(root, name, tr, hdr.Size); err != nil {
				return st, err
			}
			if err := root.Chmod(name, mode); err != nil {
				return st, fmt.Errorf("chmod %s: %w", name, err)
			}
			_ = root.Chtimes(name, hdr.ModTime, hdr.ModTime)
			st.Bytes += hdr.Size
			st.Files++
		case tar.TypeSymlink:
			if err := prepare(root, name); err != nil {
				return st, err
			}
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				return st, fmt.Errorf("symlink %s: %w", name, err)
			}
			st.Symlinks++
		case tar.TypeLink:
			target, ok, err := cleanName(hdr.Linkname)
			if err != nil || !ok {
				return st, fmt.Errorf("hard link %s: bad target %q", name, hdr.Linkname)
			}
			if err := prepare(root, name); err != nil {
				return st, err
			}
			if err := root.Link(target, name); err != nil {
				return st, fmt.Errorf("hard link %s -> %s: %w", name, target, err)
			}
			st.Hardlinks++
		default: // char/block devices, fifos, and anything unknown: never created
			st.Skipped++
			continue
		}
		if chown {
			uid, gid := own(hdr)
			if err := root.Lchown(name, uid, gid); err != nil {
				return st, fmt.Errorf("chown %s: %w", name, err)
			}
			if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeDir {
				// chown clears mode bits on some systems; reapply.
				if err := root.Chmod(name, mode); err != nil {
					return st, fmt.Errorf("chmod %s: %w", name, err)
				}
			}
		}
	}
	// Directory modes last, deepest first, so read-only directories don't block extraction.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if err := root.Chmod(d.name, d.mode); err != nil {
			return st, fmt.Errorf("chmod %s: %w", d.name, err)
		}
		_ = root.Chtimes(d.name, d.mtime, d.mtime)
	}
	return st, nil
}

// cleanName turns a tar entry name into a clean relative path. ok is false for the root itself.
// Names that try to climb out (".." components) are rejected outright rather than clamped.
func cleanName(n string) (string, bool, error) {
	if len(n) > 4096 || strings.ContainsRune(n, 0) {
		return "", false, fmt.Errorf("bad entry name %.64q", n)
	}
	n = strings.TrimLeft(n, "/")
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", false, fmt.Errorf("entry name %.64q escapes the image root", n)
		}
	}
	c := path.Clean(n)
	if c == "." || c == "" {
		return "", false, nil
	}
	return c, true, nil
}

// safeMode keeps permission bits and the sticky bit (needed for /tmp) but drops setuid/setgid.
func safeMode(m fs.FileMode) fs.FileMode {
	return m.Perm() | (m & fs.ModeSticky)
}

func mkdirAll(root *os.Root, name string) error {
	if fi, err := root.Lstat(name); err == nil && !fi.IsDir() {
		if err := root.Remove(name); err != nil {
			return fmt.Errorf("replace %s with a directory: %w", name, err)
		}
	}
	if err := root.MkdirAll(name, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", name, err)
	}
	return nil
}

// prepare makes the parent directory and removes whatever is at name (never following it).
func prepare(root *os.Root, name string) error {
	if dir := path.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	if fi, err := root.Lstat(name); err == nil {
		if fi.IsDir() {
			err = root.RemoveAll(name)
		} else {
			err = root.Remove(name)
		}
		if err != nil {
			return fmt.Errorf("replace %s: %w", name, err)
		}
	}
	return nil
}

func writeFile(root *os.Root, name string, r io.Reader, size int64) error {
	if err := prepare(root, name); err != nil {
		return err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	if _, err := io.CopyN(f, r, size); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	return nil
}
