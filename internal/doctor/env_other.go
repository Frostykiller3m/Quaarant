//go:build !linux

package doctor

import "errors"

// Sandboxes need Linux; on other systems Run reports the OS check as failed and skips the rest,
// so these are never reached in practice.

func kernelRelease() string { return "" }

func (systemEnv) KVMAPIVersion() (int, error) { return 0, errors.ErrUnsupported }

func (systemEnv) Cgroup2() (bool, []string, error) { return false, nil, errors.ErrUnsupported }

func (systemEnv) Reflink(dir string) (string, string, bool, error) {
	return dir, "", false, errors.ErrUnsupported
}
