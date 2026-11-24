//go:build !linux

package agent

import (
	"fmt"
	"os"
)

// The microVM roles only exist inside a Linux guest.

func notLinux(role string) int {
	fmt.Fprintf(os.Stderr, "qt-agent %s: Linux only\n", role)
	return 1
}

// InitStage1 is Linux only.
func InitStage1() int { return notLinux("init") }

// InitStage2 is Linux only.
func InitStage2() int { return notLinux("init2") }

// Serve is Linux only.
func Serve() int { return notLinux("serve") }

// Spawn is Linux only.
func Spawn() int { return notLinux("spawn") }
