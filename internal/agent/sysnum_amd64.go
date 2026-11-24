//go:build linux

package agent

// open_by_handle_at is missing from the frozen syscall table on amd64 (x/sys: 304).
const sysOpenByHandleAt = 304
