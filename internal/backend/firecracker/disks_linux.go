//go:build linux

package firecracker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// diskRef identifies a disk created by a diskStore (saved in qt.json / golden meta).
type diskRef struct {
	Kind   string `json:"kind"`              // reflink | thin | copy
	Path   string `json:"path,omitempty"`    // file disks
	ThinID int    `json:"thin_id,omitempty"` // thin volumes
	Bytes  int64  `json:"bytes"`
}

// diskStore makes golden disks and the per-sandbox copy-on-write clones of them.
type diskStore struct {
	kind string // reflink | thin | copy
	pool *thinPool
}

// newDiskStore picks the fastest mechanism this data dir supports: reflinks (btrfs, xfs),
// else a device-mapper thin pool, else plain copies.
func newDiskStore(ctx context.Context, dataDir string) (*diskStore, error) {
	if canReflink(dataDir) {
		return &diskStore{kind: "reflink"}, nil
	}
	pool, err := openThinPool(ctx, filepath.Join(dataDir, "thin"))
	if err == nil {
		return &diskStore{kind: "thin", pool: pool}, nil
	}
	return &diskStore{kind: "copy"}, fmt.Errorf("no reflinks and no thin pool (%w): disks are full copies", err)
}

func canReflink(dir string) bool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	a, err := os.CreateTemp(dir, ".reflink-probe-")
	if err != nil {
		return false
	}
	defer func() { _ = os.Remove(a.Name()); _ = a.Close() }()
	_, _ = a.WriteString("qt")
	b, err := os.CreateTemp(dir, ".reflink-probe-")
	if err != nil {
		return false
	}
	defer func() { _ = os.Remove(b.Name()); _ = b.Close() }()
	return unix.IoctlFileClone(int(b.Fd()), int(a.Fd())) == nil
}

// newGolden makes a writable disk of size bytes holding base (the image's ext4), for the VM
// a golden snapshot is taken from. File disks live at path.
func (d *diskStore) newGolden(ctx context.Context, base, path string, size int64) (diskRef, error) {
	if d.kind != "thin" {
		if err := prepareDisk(ctx, base, path, size, 0); err != nil {
			return diskRef{}, err
		}
		return diskRef{Kind: d.kind, Path: path, Bytes: size}, nil
	}
	id, err := d.pool.create(ctx, size)
	if err != nil {
		return diskRef{}, err
	}
	ref := diskRef{Kind: "thin", ThinID: id, Bytes: size}
	if err := fillDevice(d.pool.devPath(id), base); err != nil {
		_ = d.pool.remove(ctx, id)
		return diskRef{}, err
	}
	if err := resizeFS(ctx, d.pool.devPath(id)); err != nil {
		_ = d.pool.remove(ctx, id)
		return diskRef{}, err
	}
	return ref, nil
}

func fillDevice(dev, base string) error {
	in, err := os.Open(base) //nolint:gosec // G304: the image store's base disk
	if err != nil {
		return fmt.Errorf("golden disk: %w", err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dev, os.O_WRONLY, 0) //nolint:gosec // G304: our thin volume device
	if err != nil {
		return fmt.Errorf("golden disk: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("golden disk: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("golden disk: %w", err)
	}
	return out.Close()
}

// attachGolden puts the (still writable) golden disk at path inside the build jail.
func (d *diskStore) attachGolden(ref diskRef, path string, uid int) error {
	if ref.Kind == "thin" {
		return d.pool.mknodAt(ref.ThinID, path, uid)
	}
	if err := os.Link(ref.Path, path); err != nil {
		return fmt.Errorf("golden disk: %w", err)
	}
	return os.Chown(path, uid, uid)
}

// seal makes a golden disk immutable: it is only ever cloned from now on.
func (d *diskStore) seal(ctx context.Context, ref diskRef) error {
	if ref.Kind == "thin" {
		return d.pool.deactivate(ctx, ref.ThinID) // snapshots need an inactive origin
	}
	if err := os.Chown(ref.Path, 0, 0); err != nil {
		return fmt.Errorf("seal golden disk: %w", err)
	}
	return os.Chmod(ref.Path, 0o400)
}

// clone gives a sandbox its own copy-on-write disk at path (inside its jail), owned by uid.
func (d *diskStore) clone(ctx context.Context, golden diskRef, path string, uid int) (diskRef, error) {
	switch golden.Kind {
	case "thin":
		id, err := d.pool.snapshot(ctx, golden.ThinID, golden.Bytes)
		if err != nil {
			return diskRef{}, err
		}
		if err := d.pool.mknodAt(id, path, uid); err != nil {
			_ = d.pool.remove(ctx, id)
			return diskRef{}, err
		}
		return diskRef{Kind: "thin", ThinID: id, Bytes: golden.Bytes}, nil
	default: // reflink (instant) or copy: prepareDisk tries FICLONE first
		if err := prepareDisk(ctx, golden.Path, path, 0, uid); err != nil {
			return diskRef{}, err
		}
		return diskRef{Kind: golden.Kind, Path: path, Bytes: golden.Bytes}, nil
	}
}

// snapshotLive captures a running VM's disk (the VM is paused): a thin snapshot of its
// volume (the device suspended for the instant it takes), or a reflink/copy of its file.
func (d *diskStore) snapshotLive(ctx context.Context, ref diskRef, current, dst string) (diskRef, error) {
	if ref.Kind == "thin" {
		id, err := d.pool.snapshotLive(ctx, ref.ThinID)
		if err != nil {
			return diskRef{}, err
		}
		return diskRef{Kind: "thin", ThinID: id, Bytes: ref.Bytes}, nil
	}
	if err := prepareDisk(ctx, current, dst, 0, 0); err != nil {
		return diskRef{}, err
	}
	if err := os.Chmod(dst, 0o400); err != nil {
		return diskRef{}, fmt.Errorf("snapshot disk: %w", err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		return diskRef{}, fmt.Errorf("snapshot disk: %w", err)
	}
	kind := ref.Kind
	if kind == "" {
		kind = "copy"
	}
	return diskRef{Kind: kind, Path: dst, Bytes: fi.Size()}, nil
}

// remove frees a sandbox's disk (file disks go away with the workspace).
func (d *diskStore) remove(ctx context.Context, ref diskRef) error {
	if ref.Kind == "thin" && d.pool != nil {
		return d.pool.remove(ctx, ref.ThinID)
	}
	return nil
}

func resizeFS(ctx context.Context, target string) error {
	if _, err := output(ctx, "resize2fs", "-f", target); err != nil {
		return fmt.Errorf("resize2fs: %w", err)
	}
	return nil
}

func (d *diskStore) close(ctx context.Context) error {
	if d.pool != nil {
		return d.pool.close(ctx)
	}
	return nil
}
