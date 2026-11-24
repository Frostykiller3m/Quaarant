// Package workspace inspects and moves files in a sandbox's copy-on-write layer from the host.
//
// A gvisor sandbox's root is a host overlayfs: the image rootfs is the lower layer and
// sandboxes/<id>/upper records every change (overlayfs semantics: a char device 0/0 is a
// whiteout for a deleted entry, an "opaque" xattr on a directory hides the lower directory's
// contents, and a file present in both layers was copied up). Everything in upper/ was written
// by untrusted code: walks go through os.Root, nothing is followed, files are opened with
// O_NOFOLLOW|O_NONBLOCK and checked to be the file that was listed, and output is bounded.
package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// DefaultMaxChanges bounds a diff; more changes return backend.ErrDiffTruncated.
const DefaultMaxChanges = 100_000

// DiffOptions tunes Diff.
type DiffOptions struct {
	// Hidden subtrees are never reported (qt's own /.qt).
	Hidden []string
	// QuietDirs are directories whose own creation is not reported (mount points the runtime
	// creates); their contents still are.
	QuietDirs  []string
	MaxChanges int
}

// Diff lists the changes recorded in upper relative to lower, sorted by path. Directories
// are reported when they are added, deleted or change mode/owner; a file copied up without a
// change in content, mode or owner is not reported. If there are more than MaxChanges changes,
// it returns the first ones and an error wrapping backend.ErrDiffTruncated.
func Diff(lower, upper string, opts DiffOptions) ([]backend.Change, error) {
	lr, err := os.OpenRoot(lower)
	if err != nil {
		return nil, fmt.Errorf("open lower layer: %w", err)
	}
	defer func() { _ = lr.Close() }()
	ur, err := os.OpenRoot(upper)
	if err != nil {
		return nil, fmt.Errorf("open upper layer: %w", err)
	}
	defer func() { _ = ur.Close() }()
	d := &differ{lower: lr, upper: ur, max: opts.MaxChanges, hidden: set(opts.Hidden), quiet: set(opts.QuietDirs)}
	if d.max <= 0 {
		d.max = DefaultMaxChanges
	}
	err = d.walk(".", true, false)
	sort.Slice(d.out, func(i, j int) bool { return d.out[i].Path < d.out[j].Path })
	if errors.Is(err, errFull) {
		return d.out, fmt.Errorf("%w: more than %d changes", backend.ErrDiffTruncated, d.max)
	}
	return d.out, err
}

var errFull = errors.New("diff full")

func set(paths []string) map[string]bool {
	m := map[string]bool{}
	for _, p := range paths {
		m[path.Clean("/"+p)] = true
	}
	return m
}

type differ struct {
	lower, upper  *os.Root
	hidden, quiet map[string]bool
	max           int
	out           []backend.Change
}

func abs(rel string) string { return path.Clean("/" + rel) }

func (d *differ) add(c backend.Change) error {
	if len(d.out) >= d.max {
		return errFull
	}
	d.out = append(d.out, c)
	return nil
}

func readNames(r *os.Root, rel string) ([]string, error) {
	f, err := r.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", abs(rel), err)
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", abs(rel), err)
	}
	sort.Strings(names)
	return names, nil
}

// walk compares upper/rel with lower/rel. lowerDir says whether lower/rel is a directory;
// opaque says whether upper/rel hides it.
func (d *differ) walk(rel string, lowerDir, opaque bool) error {
	names, err := readNames(d.upper, rel)
	if err != nil {
		return err
	}
	inUpper := make(map[string]bool, len(names))
	for _, n := range names {
		inUpper[n] = true
		p := path.Join(rel, n)
		if d.hidden[abs(p)] {
			continue
		}
		fi, err := d.upper.Lstat(p)
		if err != nil {
			continue // removed while we looked
		}
		var lfi fs.FileInfo // nil: not in the lower layer
		if lowerDir {
			// Entries of an opaque directory still compare against what they replaced.
			lfi, _ = d.lower.Lstat(p)
		}
		if isWhiteout(fi) {
			if lfi != nil {
				if err := d.deleted(p, lfi); err != nil {
					return err
				}
			}
			continue
		}
		if err := d.entry(p, fi, lfi); err != nil {
			return err
		}
	}
	if opaque && lowerDir { // everything the opaque directory hides is gone
		lnames, err := readNames(d.lower, rel)
		if err != nil {
			return nil
		}
		for _, n := range lnames {
			p := path.Join(rel, n)
			if inUpper[n] || d.hidden[abs(p)] {
				continue
			}
			if lfi, err := d.lower.Lstat(p); err == nil {
				if err := d.deleted(p, lfi); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (d *differ) entry(p string, fi, lfi fs.FileInfo) error {
	kind := backend.Added
	if lfi != nil {
		kind = backend.Modified
	}
	c := backend.Change{Path: abs(p), Kind: kind, Mode: fi.Mode()}
	switch {
	case fi.IsDir():
		if lfi != nil && lfi.IsDir() {
			if sameMeta(fi, lfi) {
				return d.walk(p, true, isOpaque(d.upper, p))
			}
			if err := d.add(c); err != nil {
				return err
			}
			return d.walk(p, true, isOpaque(d.upper, p))
		}
		if kind != backend.Added || !d.quiet[abs(p)] {
			if err := d.add(c); err != nil {
				return err
			}
		}
		return d.walk(p, false, false)
	case fi.Mode().IsRegular():
		sum, err := hashFile(d.upper, p, fi)
		if err != nil {
			sum = "" // replaced while we looked; still report it
		}
		c.Size, c.SHA256 = fi.Size(), sum
		if lfi != nil && lfi.Mode().IsRegular() && sameMeta(fi, lfi) && lfi.Size() == fi.Size() && sum != "" {
			if lsum, err := hashFile(d.lower, p, lfi); err == nil && lsum == sum {
				return nil // copied up, unchanged
			}
		}
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := d.upper.Readlink(p)
		if err != nil {
			return nil
		}
		c.LinkTarget, c.Size = target, int64(len(target))
		if lfi != nil && lfi.Mode()&fs.ModeSymlink != 0 && sameMeta(fi, lfi) {
			if lt, err := d.lower.Readlink(p); err == nil && lt == target {
				return nil
			}
		}
	default: // fifo, socket, device: reported by type only
		if lfi != nil && lfi.Mode() == fi.Mode() && sameMeta(fi, lfi) {
			return nil
		}
	}
	return d.add(c)
}

// deleted reports lower/p as deleted, with everything under it if it is a directory.
func (d *differ) deleted(p string, lfi fs.FileInfo) error {
	if d.hidden[abs(p)] {
		return nil
	}
	c := backend.Change{Path: abs(p), Kind: backend.Deleted, Mode: lfi.Mode()}
	if lfi.Mode().IsRegular() {
		c.Size = lfi.Size()
	}
	if err := d.add(c); err != nil {
		return err
	}
	if !lfi.IsDir() {
		return nil
	}
	names, err := readNames(d.lower, p)
	if err != nil {
		return nil
	}
	for _, n := range names {
		cp := path.Join(p, n)
		if cfi, err := d.lower.Lstat(cp); err == nil {
			if err := d.deleted(cp, cfi); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameMeta(a, b fs.FileInfo) bool {
	if a.Mode() != b.Mode() {
		return false
	}
	au, ag := owner(a)
	bu, bg := owner(b)
	return au == bu && ag == bg
}

// hashFile returns the sha256 of rel, refusing anything but the regular file fi describes.
func hashFile(r *os.Root, rel string, fi fs.FileInfo) (string, error) {
	f, err := openNoFollow(r, rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	ffi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", abs(rel), err)
	}
	if !ffi.Mode().IsRegular() || !os.SameFile(fi, ffi) {
		return "", fmt.Errorf("%s changed while hashing", abs(rel))
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", abs(rel), err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
