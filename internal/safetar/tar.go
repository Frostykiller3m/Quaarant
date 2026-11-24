package safetar

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"time"
)

// TarLimits bound an archive written from (untrusted) sandbox contents.
type TarLimits struct {
	MaxBytes   int64
	MaxEntries int
}

// DefaultTarLimits for CopyOut.
var DefaultTarLimits = TarLimits{MaxBytes: 16 << 30, MaxEntries: 1_000_000}

// ErrTarLimit is wrapped when a copy exceeds TarLimits.
var ErrTarLimit = errors.New("copy exceeds limits")

// TarStats describes a written archive.
type TarStats struct {
	Entries int
	Bytes   int64
	Skipped int // fifos, sockets, devices
}

// WriteTar archives rel (a file or directory inside root) to w. Entry names start with
// base(rel), or are relative to the root when rel is ".". Symlinks are stored as links, never
// followed; fifos, sockets and devices are skipped; hard links become separate files; and
// every regular file is opened with O_NOFOLLOW|O_NONBLOCK and must be the file that was listed.
// A file that changes size while it is read is padded or cut to the size in its header.
func WriteTar(root *os.Root, rel string, w io.Writer, lim TarLimits) (TarStats, error) {
	rel = path.Clean(rel)
	tw := tar.NewWriter(w)
	t := &tarWriter{root: root, tw: tw, lim: lim}
	name := path.Base(rel)
	if rel == "." {
		name = ""
	}
	fi, err := root.Lstat(rel)
	if err != nil {
		return t.st, fmt.Errorf("copy out %s: %w", abs(rel), err)
	}
	if err := t.add(rel, name, fi); err != nil {
		return t.st, err
	}
	if err := tw.Close(); err != nil {
		return t.st, fmt.Errorf("finish archive: %w", err)
	}
	return t.st, nil
}

type tarWriter struct {
	root *os.Root
	tw   *tar.Writer
	lim  TarLimits
	st   TarStats
}

func (t *tarWriter) add(rel, name string, fi fs.FileInfo) error {
	mode := fi.Mode()
	if mode&(fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice|fs.ModeCharDevice|fs.ModeIrregular) != 0 {
		t.st.Skipped++
		return nil
	}
	t.st.Entries++
	if t.st.Entries > t.lim.MaxEntries {
		return fmt.Errorf("%w: more than %d entries", ErrTarLimit, t.lim.MaxEntries)
	}
	link := ""
	if mode&fs.ModeSymlink != 0 {
		l, err := t.root.Readlink(rel)
		if err != nil {
			return fmt.Errorf("readlink %s: %w", abs(rel), err)
		}
		link = l
	}
	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return fmt.Errorf("header for %s: %w", abs(rel), err)
	}
	hdr.Uid, hdr.Gid = 0, 0
	if u, g := owner(fi); u <= 1<<31 && g <= 1<<31 {
		hdr.Uid, hdr.Gid = int(u), int(g)
	}
	hdr.Uname, hdr.Gname = "", ""
	hdr.Format = tar.FormatPAX
	hdr.ModTime = fi.ModTime().Truncate(time.Second)
	hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
	hdr.Mode &^= 0o6000 // never hand out setuid/setgid bits
	switch {
	case fi.IsDir():
		if name != "" {
			hdr.Name = name + "/"
			if err := t.tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("write %s: %w", abs(rel), err)
			}
		} else {
			t.st.Entries--
		}
		f, err := t.root.Open(rel)
		if err != nil {
			return fmt.Errorf("open %s: %w", abs(rel), err)
		}
		names, err := f.Readdirnames(-1)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("list %s: %w", abs(rel), err)
		}
		sort.Strings(names)
		for _, n := range names {
			cr := path.Join(rel, n)
			cfi, err := t.root.Lstat(cr)
			if err != nil {
				continue // gone
			}
			if err := t.add(cr, path.Join(name, n), cfi); err != nil {
				return err
			}
		}
		return nil
	case mode.IsRegular():
		hdr.Name = name
		if t.st.Bytes+fi.Size() > t.lim.MaxBytes {
			return fmt.Errorf("%w: more than %d bytes", ErrTarLimit, t.lim.MaxBytes)
		}
		f, err := openNoFollow(t.root, rel)
		if err != nil {
			return fmt.Errorf("open %s: %w", abs(rel), err)
		}
		defer func() { _ = f.Close() }()
		ffi, err := f.Stat()
		if err != nil || !ffi.Mode().IsRegular() || !os.SameFile(fi, ffi) {
			return fmt.Errorf("%s changed while copying", abs(rel))
		}
		if err := t.tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write %s: %w", abs(rel), err)
		}
		n, err := io.Copy(t.tw, io.LimitReader(f, hdr.Size))
		if err != nil {
			return fmt.Errorf("copy %s: %w", abs(rel), err)
		}
		if n < hdr.Size { // shrank while reading: pad to the promised size
			if _, err := io.CopyN(t.tw, zeros{}, hdr.Size-n); err != nil {
				return fmt.Errorf("copy %s: %w", abs(rel), err)
			}
		}
		t.st.Bytes += hdr.Size
		return nil
	default: // symlink
		hdr.Name = name
		if err := t.tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write %s: %w", abs(rel), err)
		}
		return nil
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
