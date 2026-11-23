//go:build linux

package doctor

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// kvmGetAPIVersion is _IO(KVMIO=0xAE, 0x00).
	kvmGetAPIVersion = 0xAE00
	// zfsSuperMagic is ZFS's statfs f_type (not in x/sys/unix: ZFS is out of tree).
	zfsSuperMagic = 0x2fc12fc1
)

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

func (systemEnv) KVMAPIVersion() (int, error) {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err // keeps fs.ErrNotExist / fs.ErrPermission for errors.Is
	}
	defer f.Close()
	v, err := unix.IoctlRetInt(int(f.Fd()), kvmGetAPIVersion)
	if err != nil {
		return 0, fmt.Errorf("KVM_GET_API_VERSION: %w", err)
	}
	return v, nil
}

func (systemEnv) Cgroup2() (bool, []string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil {
		return false, nil, fmt.Errorf("statfs /sys/fs/cgroup: %w", err)
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return false, nil, nil
	}
	raw, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return true, nil, fmt.Errorf("read cgroup.controllers: %w", err)
	}
	return true, strings.Fields(string(raw)), nil
}

var fsNames = map[int64]string{
	unix.BTRFS_SUPER_MAGIC:     "btrfs",
	unix.XFS_SUPER_MAGIC:       "xfs",
	unix.EXT4_SUPER_MAGIC:      "ext4",
	unix.TMPFS_MAGIC:           "tmpfs",
	unix.OVERLAYFS_SUPER_MAGIC: "overlayfs",
	zfsSuperMagic:              "zfs",
	unix.V9FS_MAGIC:            "9p",
	unix.FUSE_SUPER_MAGIC:      "fuse",
}

func (systemEnv) Reflink(dir string) (string, string, bool, error) {
	tested, err := nearestExisting(dir)
	if err != nil {
		return tested, "", false, err
	}
	fsType := ""
	var st unix.Statfs_t
	if unix.Statfs(tested, &st) == nil {
		if fsType = fsNames[int64(st.Type)]; fsType == "" { //nolint:unconvert // Statfs_t.Type is int32 on some arches
			fsType = fmt.Sprintf("0x%x", st.Type)
		}
	}

	src, err := os.CreateTemp(tested, ".qt-doctor-reflink-*")
	if err != nil {
		return tested, fsType, false, fmt.Errorf("create test file: %w", err)
	}
	defer os.Remove(src.Name())
	defer src.Close()
	if _, err := src.Write(bytes.Repeat([]byte{'q'}, 64<<10)); err != nil {
		return tested, fsType, false, fmt.Errorf("write test file: %w", err)
	}
	dst, err := os.CreateTemp(tested, ".qt-doctor-reflink-clone-*")
	if err != nil {
		return tested, fsType, false, fmt.Errorf("create clone file: %w", err)
	}
	defer os.Remove(dst.Name())
	defer dst.Close()

	err = unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
	switch {
	case err == nil:
		return tested, fsType, true, nil
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOTTY), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EXDEV):
		return tested, fsType, false, nil
	default:
		return tested, fsType, false, fmt.Errorf("FICLONE: %w", err)
	}
}
