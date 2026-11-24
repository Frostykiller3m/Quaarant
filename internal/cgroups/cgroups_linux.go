//go:build linux

// Package cgroups manages the cgroup v2 parent qt puts sandboxes under (/quarantine).
package cgroups

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Root is the cgroup v2 mount point.
const Root = "/sys/fs/cgroup"

// EnsureParent creates the parent cgroup (e.g. "/quarantine") and delegates the cpu, memory
// and pids controllers to its children.
func EnsureParent(parent string) error {
	dir := filepath.Join(Root, parent)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: cgroupfs directory, mode is ignored
		return fmt.Errorf("create %s: %w", dir, err)
	}
	for _, d := range []string{Root, dir} {
		for _, c := range []string{"cpu", "memory", "pids"} {
			f := filepath.Join(d, "cgroup.subtree_control")
			if err := os.WriteFile(f, []byte("+"+c), 0); err != nil {
				return fmt.Errorf("enable %s in %s: %w", c, f, err)
			}
		}
	}
	return nil
}

// Remove deletes a cgroup (path relative to Root), waiting briefly for its processes to go.
func Remove(path string) error {
	dir := filepath.Join(Root, path)
	for i := 0; ; i++ {
		err := unix.Rmdir(dir)
		switch {
		case err == nil, errors.Is(err, unix.ENOENT):
			return nil
		case errors.Is(err, unix.EBUSY) && i < 40:
			time.Sleep(50 * time.Millisecond)
		default:
			return fmt.Errorf("remove cgroup %s: %w", dir, err)
		}
	}
}
