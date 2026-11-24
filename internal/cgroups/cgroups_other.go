//go:build !linux

// Package cgroups manages the cgroup v2 parent qt puts sandboxes under (/quarantine).
package cgroups

import "errors"

// Root is the cgroup v2 mount point.
const Root = "/sys/fs/cgroup"

// EnsureParent needs Linux.
func EnsureParent(string) error { return errors.New("cgroups need Linux") }

// Remove is a no-op outside Linux.
func Remove(string) error { return nil }
