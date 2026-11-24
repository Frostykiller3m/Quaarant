//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// prepareDisk gives a sandbox its own writable copy of the image's ext4: a reflink when the
// filesystem supports it (instant, copy-on-write), else a full copy. It is then grown
// (sparse) to size and the filesystem resized to fill it.
func prepareDisk(ctx context.Context, base, disk string, size int64, owner int) error {
	src, err := os.Open(base) //nolint:gosec // G304: the image store's base disk
	if err != nil {
		return fmt.Errorf("disk: %w", err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(disk, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: inside our jail dir
	if err != nil {
		return fmt.Errorf("disk: %w", err)
	}
	if err := unix.IoctlFileClone(int(dst.Fd()), int(src.Fd())); err != nil {
		if _, err := io.Copy(dst, src); err != nil {
			_ = dst.Close()
			return fmt.Errorf("disk: copy: %w", err)
		}
	}
	fi, err := src.Stat()
	if err != nil {
		_ = dst.Close()
		return fmt.Errorf("disk: %w", err)
	}
	if size > fi.Size() {
		if err := dst.Truncate(size); err != nil {
			_ = dst.Close()
			return fmt.Errorf("disk: grow: %w", err)
		}
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("disk: %w", err)
	}
	if size > fi.Size() {
		resize, err := exec.LookPath("resize2fs")
		if err != nil {
			return errors.New("disk: resize2fs not found (install e2fsprogs)")
		}
		var out bytes.Buffer
		c := exec.CommandContext(ctx, resize, "-f", disk) //nolint:gosec // G204: our own path
		c.Stdout, c.Stderr = &out, &out
		if err := c.Run(); err != nil {
			return fmt.Errorf("disk: resize2fs: %w: %s", err, strings.TrimSpace(out.String()))
		}
	}
	return os.Chown(disk, owner, owner)
}

// linkOrCopy hard-links src to dst (same filesystem) or copies it, read-only.
func linkOrCopy(src, dst string, mode os.FileMode) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src) //nolint:gosec // G304: configured kernel / our initramfs
	if err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) //nolint:gosec // G304: inside our jail dir
	if err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return out.Close()
}

func killPID(pid int) { _ = unix.Kill(pid, unix.SIGKILL) }
