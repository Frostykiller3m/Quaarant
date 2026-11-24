//go:build !linux

package gvisor

import (
	"errors"
	"os"
	"syscall"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// gVisor needs Linux; these keep the package building elsewhere.

var errLinuxOnly = errors.New("the gvisor backend needs Linux")

func mountOverlay(_, _, _, _ string) error          { return errLinuxOnly }
func unmount(string) error                          { return nil }
func ensureCgroupParent(string) error               { return errLinuxOnly }
func removeCgroup(string) error                     { return nil }
func openPTY() (*os.File, *os.File, error)          { return nil, nil, errLinuxOnly }
func setWinsize(*os.File, backend.WindowSize) error { return errLinuxOnly }
func ttyProcAttr() *syscall.SysProcAttr             { return nil }
