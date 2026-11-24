//go:build linux

package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ext4Epoch is the fixed timestamp mke2fs writes into the filesystem (E2FSPROGS_FAKE_TIME).
const ext4Epoch = "1795046400"

// Ext4 returns the image's root filesystem as an ext4 file system image
// (<digest dir>/rootfs.ext4), building it once from the unpacked rootfs with mkfs.ext4 -d.
// Two builds of the same image have the same files, contents, modes, owners and link targets,
// the same UUID and directory hash seed (derived from the digest), the same size and the same
// filesystem timestamps. They are not byte-identical: mke2fs 1.47.0 copies each inode's
// atime/ctime from the unpacked files, and ctime is the unpack time. One host builds each
// digest once (cached), so this only matters across hosts. The vm backend copies it for each
// sandbox (it is never written to).
func (s *Store) Ext4(ctx context.Context, img Image) (string, error) {
	dir := filepath.Dir(img.RootFS)
	out := filepath.Join(dir, "rootfs.ext4")
	lock := s.lockFor(img.Digest + "/ext4")
	lock.Lock()
	defer lock.Unlock()
	if _, err := os.Stat(out); err == nil {
		return out, nil
	}
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		return "", fmt.Errorf("ext4 image: mkfs.ext4 not found (install e2fsprogs): %w", err)
	}
	bytesUsed, inodes, err := usage(img.RootFS)
	if err != nil {
		return "", fmt.Errorf("ext4 image: %w", err)
	}
	// Content + 25% + 64 MiB (journal, metadata, a little room), at least 128 MiB.
	size := max(bytesUsed*5/4+64<<20, 128<<20)
	size = (size + 1<<20 - 1) &^ (1<<20 - 1)
	tmp, err := os.CreateTemp(dir, ".rootfs.ext4-")
	if err != nil {
		return "", fmt.Errorf("ext4 image: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Truncate(size); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("ext4 image: %w", err)
	}
	_ = tmp.Close()
	uuid := digestUUID(img.Digest)
	cmd := exec.CommandContext(ctx, mkfs, "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256", "-m", "0", //nolint:gosec // G204: mkfs.ext4 from PATH, arguments we build
		"-N", strconv.FormatInt(inodes*5/4+1024, 10), "-L", "qt-root", "-U", uuid,
		"-E", "hash_seed="+uuid+",root_owner=0:0", "-J", "size=16",
		"-d", img.RootFS, tmp.Name())
	cmd.Env = append(os.Environ(), "E2FSPROGS_FAKE_TIME="+ext4Epoch, "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("mkfs.ext4: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := os.Chmod(tmp.Name(), 0o444); err != nil { //nolint:gosec // G302: shared read-only base image
		return "", fmt.Errorf("ext4 image: %w", err)
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return "", fmt.Errorf("ext4 image: %w", err)
	}
	return out, nil
}

// usage is the bytes (rounded to 4 KiB blocks) and inodes a tree needs.
func usage(root string) (int64, int64, error) {
	var b, n int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n++
		if d.Type().IsRegular() || d.IsDir() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			b += (fi.Size() + 4095) &^ 4095
			if d.IsDir() {
				b += 4096
			}
		}
		return nil
	})
	return b, n, err
}

// digestUUID derives a stable filesystem UUID from an image digest.
func digestUUID(digest string) string {
	h := sha256.Sum256([]byte("qt-rootfs:" + digest))
	h[6] = h[6]&0x0f | 0x40 // RFC 4122 version 4 layout, so tools accept it
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
