//go:build linux

package agent

import "syscall"

const sysOpenByHandleAt = syscall.SYS_OPEN_BY_HANDLE_AT
