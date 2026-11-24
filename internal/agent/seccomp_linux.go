//go:build linux

package agent

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// The same deny-list as the gvisor backend's OCI profile (plus the new mount API), so both
// isolation levels refuse the same syscalls with EPERM. Numbers come from
// golang.org/x/sys/unix zsysnum_linux_{amd64,arm64}.go (generated from kernel headers); the
// agent may not import x/sys, so they are copied here.
var deniedSyscalls = map[string][]uint32{
	"amd64": {
		163, 248, 321, 305, 227, 176, 313, 175, 320, 246, 250, 165, 429, 303, 304, 428, 298,
		155, 310, 311, 101, 179, 169, 249, 308, 164, 168, 167, 103, 166, 272, 323, 153,
		430, 431, 432, 433, 442,
	},
	"arm64": {
		89, 217, 280, 266, 112, 106, 273, 105, 294, 104, 219, 40, 429, 264, 265, 428, 241,
		41, 270, 271, 117, 60, 142, 218, 268, 170, 225, 224, 116, 39, 97, 282, 58,
		430, 431, 432, 433, 442,
	},
}

// In the order of the lists above.
var deniedNames = []string{
	"acct", "add_key", "bpf", "clock_adjtime", "clock_settime", "delete_module",
	"finit_module", "init_module", "kexec_file_load", "kexec_load", "keyctl", "mount",
	"move_mount", "name_to_handle_at", "open_by_handle_at", "open_tree", "perf_event_open",
	"pivot_root", "process_vm_readv", "process_vm_writev", "ptrace", "quotactl", "reboot",
	"request_key", "setns", "settimeofday", "swapoff", "swapon", "syslog", "umount2",
	"unshare", "userfaultfd", "vhangup", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
}

const (
	auditArchX86_64  = 0xc000003e
	auditArchAArch64 = 0xc00000b7
	x32SyscallBit    = 0x40000000

	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfJGE = 0x30
	bpfK   = 0x00
	bpfRET = 0x06

	seccompRetKillProcess = 0x80000000
	seccompRetErrno       = 0x00050000
	seccompRetAllow       = 0x7fff0000

	prSetSeccomp      = 22
	seccompModeFilter = 2
)

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

// seccompProgram builds a classic BPF filter: wrong architecture -> kill, x32 ABI -> EPERM,
// a denied syscall -> EPERM, anything else -> allow.
func seccompProgram() ([]sockFilter, error) {
	nrs, ok := deniedSyscalls[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("seccomp: no syscall table for %s", runtime.GOARCH)
	}
	arch := uint32(auditArchX86_64)
	if runtime.GOARCH == "arm64" {
		arch = auditArchAArch64
	}
	eperm := seccompRetErrno | uint32(syscall.EPERM)
	p := []sockFilter{
		{Code: bpfLD | bpfW | bpfABS, K: 4}, // seccomp_data.arch
		{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: arch},
		{Code: bpfRET | bpfK, K: seccompRetKillProcess},
		{Code: bpfLD | bpfW | bpfABS, K: 0}, // seccomp_data.nr
	}
	if runtime.GOARCH == "amd64" {
		p = append(p,
			sockFilter{Code: bpfJMP | bpfJGE | bpfK, Jt: 0, Jf: 1, K: x32SyscallBit},
			sockFilter{Code: bpfRET | bpfK, K: eperm})
	}
	for _, nr := range nrs {
		p = append(p,
			sockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 0, Jf: 1, K: nr},
			sockFilter{Code: bpfRET | bpfK, K: eperm})
	}
	return append(p, sockFilter{Code: bpfRET | bpfK, K: seccompRetAllow}), nil
}

// installSeccomp applies the filter to the calling thread (no_new_privs must be set).
func installSeccomp() error {
	p, err := seccompProgram()
	if err != nil {
		return err
	}
	prog := sockFprog{Len: uint16(len(p)), Filter: &p[0]}                                                                          //nolint:gosec // G115: a few dozen instructions
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); e != 0 { //nolint:gosec // G103: sock_fprog for prctl(2)
		return fmt.Errorf("seccomp: %w", e)
	}
	runtime.KeepAlive(p)
	return nil
}
