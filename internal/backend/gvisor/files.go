package gvisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/safetar"
	"github.com/Frostykiller3m/Quaarant/internal/workspace"
)

// CopyLimits bound one CopyIn (the tar comes from the qt user, but is unpacked as root).
var CopyLimits = safetar.UnpackLimits{MaxBytes: 8 << 30, MaxEntries: 1_000_000}

// diffOptions hide what qt and the runtime create, not the sandboxed code.
var diffOptions = workspace.DiffOptions{
	Hidden:    []string{qtDir},
	QuietDirs: []string{"/proc", "/dev", "/dev/pts", "/dev/shm", "/sys", "/tmp"},
}

// sandboxPath turns an absolute in-sandbox path into a path relative to the rootfs.
func sandboxPath(p string) (string, error) {
	if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("path %.64q must be a clean absolute path", p)
	}
	if p == "/" {
		return ".", nil
	}
	return strings.TrimPrefix(p, "/"), nil
}

// openRootfs opens the merged overlay of a running sandbox. Host-side reads and writes go
// through it, so the sandbox sees them at once (the root mount uses --file-access=shared).
func (b *Backend) openRootfs(ctx context.Context, id string) (*box, *os.Root, error) {
	bx, err := b.lookup(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	rootfs := rootfsDir(bx.workspace)
	if !mounted(rootfs, bx.workspace) {
		return nil, nil, fmt.Errorf("gvisor: sandbox %s is not running (its filesystem is not mounted)", id)
	}
	r, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil, nil, fmt.Errorf("gvisor: open rootfs: %w", err)
	}
	return bx, r, nil
}

// CopyIn implements backend.Backend: extract a tar into dir (created if missing). Entries are
// owned by the sandbox user, setuid bits and device nodes are dropped, and nothing can land
// outside the sandbox's root even if the sandbox planted symlinks along dir.
func (b *Backend) CopyIn(ctx context.Context, id, dir string, r io.Reader) error {
	rel, err := sandboxPath(dir)
	if err != nil {
		return fmt.Errorf("gvisor: copy in: %w", err)
	}
	bx, root, err := b.openRootfs(ctx, id)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	// qt's own copy is not sandbox activity: keep it out of the event log.
	b.mu.Lock()
	obs := bx.obs
	b.mu.Unlock()
	if obs != nil {
		defer obs.suppress(dir)()
	}
	uid, gid := int(bx.meta.User.UID), int(bx.meta.User.GID)
	if rel != "." {
		if _, err := root.Lstat(rel); errors.Is(err, os.ErrNotExist) {
			if err := root.MkdirAll(rel, 0o755); err != nil {
				return fmt.Errorf("gvisor: copy in: create %s: %w", dir, err)
			}
			if err := root.Lchown(rel, uid, gid); err != nil {
				return fmt.Errorf("gvisor: copy in: chown %s: %w", dir, err)
			}
		}
	}
	sub, err := root.OpenRoot(rel)
	if err != nil {
		return fmt.Errorf("gvisor: copy in: %s: %w", dir, err)
	}
	defer func() { _ = sub.Close() }()
	if _, err := safetar.UnpackInto(ctxReader{ctx, r}, sub, CopyLimits, safetar.OwnedBy(uid, gid)); err != nil {
		return fmt.Errorf("gvisor: copy in: %w", err)
	}
	return nil
}

// CopyOut implements backend.Backend: a tar of path (see workspace.WriteTar).
func (b *Backend) CopyOut(ctx context.Context, id, p string, w io.Writer) error {
	rel, err := sandboxPath(p)
	if err != nil {
		return fmt.Errorf("gvisor: copy out: %w", err)
	}
	_, root, err := b.openRootfs(ctx, id)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if _, err := safetar.WriteTar(root, rel, ctxWriter{ctx, w}, safetar.DefaultTarLimits); err != nil {
		return fmt.Errorf("gvisor: %w", err)
	}
	return nil
}

// Diff implements backend.Backend by reading the overlay's upper layer against the image.
func (b *Backend) Diff(ctx context.Context, id string) ([]backend.Change, error) {
	bx, err := b.lookup(ctx, id)
	if err != nil {
		return nil, err
	}
	if bx.meta.RootFS == "" {
		return nil, fmt.Errorf("gvisor: sandbox %s predates diff support; recreate it", id)
	}
	changes, err := workspace.Diff(bx.meta.RootFS, filepath.Join(bx.workspace, "upper"), diffOptions)
	if err != nil && !errors.Is(err, backend.ErrDiffTruncated) {
		return nil, fmt.Errorf("gvisor: diff: %w", err)
	}
	return changes, err
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

// commandExists resolves argv[0] in the sandbox's root (through os.Root, so the sandbox's
// symlinks cannot point the lookup at the host). If the root can't be opened, it says yes
// and lets runsc report the problem.
func (b *Backend) commandExists(ctx context.Context, id, name string, env []string) bool {
	if name == "" {
		return true
	}
	_, root, err := b.openRootfs(ctx, id)
	if err != nil {
		return true
	}
	defer func() { _ = root.Close() }()
	isExec := func(p string) bool {
		fi, err := statInRoot(root, p)
		return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
	}
	if strings.Contains(name, "/") {
		return !path.IsAbs(name) || isExec(name)
	}
	dirs := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			dirs = v
		}
	}
	for _, d := range strings.Split(dirs, ":") {
		if path.IsAbs(d) && isExec(path.Join(d, name)) {
			return true
		}
	}
	return false
}

// notFound is a process that already failed the way the vm agent reports a missing command.
func notFound(e backend.ExecSpec) backend.Process {
	if w := e.Stderr; w != nil {
		_, _ = fmt.Fprintf(w, "qt: %s: executable file not found in $PATH\n", e.Argv[0])
	} else if e.TTY && e.Stdout != nil {
		_, _ = fmt.Fprintf(e.Stdout, "qt: %s: executable file not found in $PATH\r\n", e.Argv[0])
	}
	return doneProcess{backend.ExitStatus{Code: 127}}
}

type doneProcess struct{ st backend.ExitStatus }

func (d doneProcess) Wait(context.Context) (backend.ExitStatus, error) { return d.st, nil }
func (doneProcess) Signal(int) error                                   { return nil }
func (doneProcess) Resize(backend.WindowSize) error                    { return nil }

// statInRoot stats p as the sandbox sees it: symlinks are followed with absolute targets
// taken relative to the sandbox's root (os.Root alone refuses those as escapes). Every
// step goes through root with Lstat, so nothing outside it is ever touched.
func statInRoot(root *os.Root, p string) (os.FileInfo, error) {
	p = path.Clean("/" + p)
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		cur := "/"
		redirected := false
		for i, part := range parts {
			if part == "" {
				continue
			}
			next := path.Join(cur, part)
			fi, err := root.Lstat(strings.TrimPrefix(next, "/"))
			if err != nil {
				return nil, err
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				target, err := root.Readlink(strings.TrimPrefix(next, "/"))
				if err != nil {
					return nil, err
				}
				if !path.IsAbs(target) {
					target = path.Join(cur, target)
				}
				p = path.Clean("/" + path.Join(append([]string{target}, parts[i+1:]...)...))
				redirected = true
				break
			}
			if i == len(parts)-1 {
				return fi, nil
			}
			cur = next
		}
		if !redirected {
			return root.Lstat(".")
		}
	}
	return nil, errors.New("too many levels of symbolic links")
}
