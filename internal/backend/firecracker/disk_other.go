//go:build !linux

package firecracker

import (
	"context"
	"errors"
	"os"
)

var errLinuxOnly = errors.New("the vm backend needs Linux")

func prepareDisk(context.Context, string, string, int64, int) error { return errLinuxOnly }
func linkOrCopy(string, string, os.FileMode) error                  { return errLinuxOnly }
func killPID(int)                                                   {}
