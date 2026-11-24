//go:build linux

package workspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// FileEvent is a change in a sandbox's upper layer, seen from the host. Op is one of the
// event schema's file ops: create, mkdir, symlink, unlink, rename, chmod.
type FileEvent struct {
	Op      string
	Path    string // absolute, inside the sandbox
	NewPath string // rename target, or symlink target
	Mode    fs.FileMode
}

// WatchOptions bound a Watcher.
type WatchOptions struct {
	Hidden     []string // subtrees never reported (qt's /.qt)
	MaxWatches int      // directories watched at most (inotify watches are a host resource)
}

// DefaultMaxWatches per sandbox.
const DefaultMaxWatches = 16384

const watchMask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
	unix.IN_ATTRIB | unix.IN_ONLYDIR | unix.IN_EXCL_UNLINK

// Watcher reports namespace changes (what runsc's monitoring has no paths for) by watching
// every directory of upper/ with inotify. Directories are opened through an os.Root and
// watched via /proc/self/fd, so a directory the sandbox swaps for a symlink can never make
// the host watch something outside upper/. A whiteout appearing means a lower file was
// deleted; an entry moved in from overlayfs's work dir is a copy-up (not reported) or a
// create; entries leaving to the work dir are part of an overlay operation.
//
// Like any recursive inotify watcher it races with very fast activity in a directory created
// microseconds earlier: changes made before its watch exists are seen as the end state (a
// file renamed into a brand-new directory shows up there as created). Nothing is missed for
// good: the directory is scanned as soon as it is watched.
type Watcher struct {
	f      *os.File
	upper  *os.Root
	lower  *os.Root
	emit   func(FileEvent)
	hidden map[string]bool
	max    int

	mu        sync.Mutex
	wds       map[int32]string // watch descriptor -> directory (relative to upper)
	moves     map[uint32]string
	modes     map[string]fs.FileMode
	reported  map[string]uint64 // path -> inode last reported (a scan and inotify can both see an entry)
	whiteouts map[string]bool   // whiteouts we reported: their later removal is overlayfs housekeeping
	suppress  []*suppression
	full      bool
	Overflows int
	done      chan struct{}
}

type suppression struct {
	prefix string
	until  time.Time // zero while active
}

// Watch starts watching upper (compared with lower) and calls emit from its own goroutine.
func Watch(upper, lower string, opts WatchOptions, emit func(FileEvent)) (*Watcher, error) {
	ur, err := os.OpenRoot(upper)
	if err != nil {
		return nil, fmt.Errorf("watch: open upper: %w", err)
	}
	lr, err := os.OpenRoot(lower)
	if err != nil {
		_ = ur.Close()
		return nil, fmt.Errorf("watch: open lower: %w", err)
	}
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		_ = ur.Close()
		_ = lr.Close()
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	w := &Watcher{
		f: os.NewFile(uintptr(fd), "inotify"), upper: ur, lower: lr, emit: emit,
		hidden: set(opts.Hidden), max: opts.MaxWatches,
		wds: map[int32]string{}, moves: map[uint32]string{}, modes: map[string]fs.FileMode{}, reported: map[string]uint64{}, whiteouts: map[string]bool{}, done: make(chan struct{}),
	}
	if w.max <= 0 {
		w.max = DefaultMaxWatches
	}
	w.mu.Lock()
	w.addTree(".", false)
	w.mu.Unlock()
	go w.loop()
	return w, nil
}

// Close stops the watcher and waits for its goroutine.
func (w *Watcher) Close() error {
	err := w.f.Close()
	<-w.done
	_ = w.upper.Close()
	_ = w.lower.Close()
	return err
}

// Suppress hides changes under dir (absolute in-sandbox path) until the returned func is
// called, plus a second for events still in flight: qt's own copy-ins are not sandbox
// activity.
func (w *Watcher) Suppress(dir string) (release func()) {
	s := &suppression{prefix: path.Clean("/" + dir)}
	w.mu.Lock()
	w.suppress = append(w.suppress, s)
	w.mu.Unlock()
	return func() {
		w.mu.Lock()
		s.until = time.Now().Add(time.Second)
		w.mu.Unlock()
	}
}

func (w *Watcher) suppressed(p string) bool {
	now := time.Now()
	kept := w.suppress[:0]
	hit := false
	for _, s := range w.suppress {
		if !s.until.IsZero() && now.After(s.until) {
			continue
		}
		kept = append(kept, s)
		if p == s.prefix || strings.HasPrefix(p, s.prefix+"/") || s.prefix == "/" {
			hit = true
		}
	}
	w.suppress = kept
	return hit
}

// addTree watches rel and every directory below it; with report, entries found are emitted
// (they appeared before the watch could see them).
func (w *Watcher) addTree(rel string, report bool) {
	if w.hidden[abs(rel)] {
		return
	}
	if !w.addWatch(rel) {
		return
	}
	names, err := readNames(w.upper, rel)
	if err != nil {
		return
	}
	for _, n := range names {
		p := path.Join(rel, n)
		fi, err := w.upper.Lstat(p)
		if err != nil || w.hidden[abs(p)] {
			continue
		}
		// In a freshly watched directory, anything the image lacks (or a whiteout) is new;
		// entries the image has are copy-ups.
		if report && (isWhiteout(fi) || !w.inLower(p)) {
			w.report(p, fi)
		}
		if fi.IsDir() {
			w.addTree(p, report)
		}
	}
}

func (w *Watcher) addWatch(rel string) bool {
	if len(w.wds) >= w.max {
		w.full = true
		return false
	}
	d, err := w.upper.Open(rel)
	if err != nil {
		return false
	}
	defer func() { _ = d.Close() }()
	if fi, err := d.Stat(); err != nil || !fi.IsDir() {
		return false
	}
	wd, err := unix.InotifyAddWatch(int(w.f.Fd()), "/proc/self/fd/"+strconv.Itoa(int(d.Fd())), watchMask)
	if err != nil {
		return false
	}
	w.wds[int32(wd)] = rel //nolint:gosec // G115: watch descriptors are small
	return true
}

func (w *Watcher) loop() {
	defer close(w.done)
	buf := make([]byte, 64<<10)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		w.mu.Lock()
		w.handle(buf[:n])
		w.mu.Unlock()
	}
}

func (w *Watcher) handle(b []byte) {
	for len(b) >= unix.SizeofInotifyEvent {
		// struct inotify_event { int32 wd; uint32 mask, cookie, len; char name[len]; }, host order
		ev := unix.InotifyEvent{
			Wd:     int32(binary.NativeEndian.Uint32(b[0:4])), //nolint:gosec // G115: the kernel's int32
			Mask:   binary.NativeEndian.Uint32(b[4:8]),
			Cookie: binary.NativeEndian.Uint32(b[8:12]),
			Len:    binary.NativeEndian.Uint32(b[12:16]),
		}
		end := unix.SizeofInotifyEvent + int(ev.Len)
		if end > len(b) {
			return
		}
		name := strings.TrimRight(string(b[unix.SizeofInotifyEvent:end]), "\x00")
		b = b[end:]
		if ev.Mask&unix.IN_Q_OVERFLOW != 0 {
			w.Overflows++
			continue
		}
		dir, ok := w.wds[ev.Wd]
		if !ok {
			continue
		}
		if ev.Mask&unix.IN_IGNORED != 0 {
			delete(w.wds, ev.Wd)
			continue
		}
		if name == "" {
			continue
		}
		p := path.Join(dir, name)
		if w.hidden[abs(p)] || w.suppressed(abs(p)) {
			continue
		}
		w.event(ev.Mask, ev.Cookie, p)
	}
}

func (w *Watcher) event(mask, cookie uint32, p string) {
	switch {
	case mask&unix.IN_CREATE != 0:
		fi, err := w.upper.Lstat(p)
		if err != nil { // already gone again: report what inotify knows
			op := "create"
			if mask&unix.IN_ISDIR != 0 {
				op = "mkdir"
			}
			w.emit(FileEvent{Op: op, Path: abs(p)})
			return
		}
		// overlayfs copies files up by linking a tmpfile into upper/: an entry the image has
		// is a copy-up, not a create.
		if !isWhiteout(fi) && w.inLower(p) {
			if fi.IsDir() {
				w.addTree(p, true)
			}
			return
		}
		w.report(p, fi)
		if fi.IsDir() {
			w.addTree(p, true)
		}
	case mask&unix.IN_MOVED_FROM != 0:
		if len(w.moves) > 1024 {
			clear(w.moves)
		}
		w.moves[cookie] = p
	case mask&unix.IN_MOVED_TO != 0:
		fi, err := w.upper.Lstat(p)
		if err != nil {
			return
		}
		if old, ok := w.moves[cookie]; ok { // a rename inside the sandbox
			delete(w.moves, cookie)
			w.emit(FileEvent{Op: "rename", Path: abs(old), NewPath: abs(p), Mode: fi.Mode()})
			w.moveState(old, p)
			if fi.IsDir() {
				w.renameWatches(old, p)
			}
			return
		}
		// Moved in from overlayfs's work dir: a whiteout (delete), a copy-up of something the
		// image has (not a change by itself), or a new entry replacing a whiteout.
		switch {
		case isWhiteout(fi):
			w.report(p, fi)
		case w.inLower(p):
			if fi.IsDir() { // a copied-up directory: whatever is already in it is new
				w.addTree(p, true)
			}
		default:
			w.report(p, fi)
			if fi.IsDir() {
				w.addTree(p, true)
			}
		}
	case mask&unix.IN_DELETE != 0:
		if _, err := w.upper.Lstat(p); err == nil {
			return // replaced in the same operation (e.g. by a whiteout, reported on its own)
		}
		delete(w.modes, p)
		delete(w.reported, p)
		if w.whiteouts[p] {
			delete(w.whiteouts, p)
			return
		}
		w.emit(FileEvent{Op: "unlink", Path: abs(p)})
	case mask&unix.IN_ATTRIB != 0:
		fi, err := w.upper.Lstat(p)
		if err != nil || isWhiteout(fi) {
			return
		}
		prev, ok := w.modes[p]
		if !ok {
			if lfi, err := w.lower.Lstat(p); err == nil {
				prev, ok = lfi.Mode(), true
			}
		}
		if ok && prev != fi.Mode() {
			w.emit(FileEvent{Op: "chmod", Path: abs(p), Mode: fi.Mode()})
		}
		w.remember(p, fi.Mode())
	}
}

func (w *Watcher) report(p string, fi fs.FileInfo) {
	if ino := inode(fi); ino != 0 {
		if prev, ok := w.reported[p]; ok && prev == ino {
			return
		}
		if len(w.reported) > 65536 {
			clear(w.reported)
		}
		w.reported[p] = ino
	}
	switch {
	case isWhiteout(fi):
		if len(w.whiteouts) > 65536 {
			clear(w.whiteouts)
		}
		w.whiteouts[p] = true
		w.emit(FileEvent{Op: "unlink", Path: abs(p)})
		return
	case fi.IsDir():
		w.emit(FileEvent{Op: "mkdir", Path: abs(p), Mode: fi.Mode()})
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := w.upper.Readlink(p)
		if err != nil || target == "" {
			return
		}
		w.emit(FileEvent{Op: "symlink", Path: abs(p), NewPath: target, Mode: fi.Mode()})
	default:
		w.emit(FileEvent{Op: "create", Path: abs(p), Mode: fi.Mode()})
	}
	w.remember(p, fi.Mode())
}

func (w *Watcher) remember(p string, m fs.FileMode) {
	if len(w.modes) > 65536 {
		clear(w.modes)
	}
	w.modes[p] = m
}

func (w *Watcher) inLower(p string) bool {
	_, err := w.lower.Lstat(p)
	return err == nil
}

func (w *Watcher) renameWatches(old, p string) {
	for wd, d := range w.wds {
		if d == old {
			w.wds[wd] = p
		} else if strings.HasPrefix(d, old+"/") {
			w.wds[wd] = p + strings.TrimPrefix(d, old)
		}
	}
}

// Full reports whether some directories went unwatched because MaxWatches was reached.
func (w *Watcher) Full() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.full
}

// moveState follows a rename with what we remember about the old path(s).
func (w *Watcher) moveState(old, p string) {
	for _, m := range []map[string]fs.FileMode{w.modes} {
		for k, v := range m {
			if k == old || strings.HasPrefix(k, old+"/") {
				delete(m, k)
				m[p+strings.TrimPrefix(k, old)] = v
			}
		}
	}
	for k, v := range w.reported {
		if k == old || strings.HasPrefix(k, old+"/") {
			delete(w.reported, k)
			w.reported[p+strings.TrimPrefix(k, old)] = v
		}
	}
}
