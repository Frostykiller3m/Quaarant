//go:build linux

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
)

const (
	prSetNoNewPrivs = 38
	prCapbsetDrop   = 24
	rlimitNproc     = 6
	lastCap         = 63
)

// Spawn is "qt-agent spawn": it reads an Exec spec from fd 3 and becomes the requested
// process with least privilege. Everything happens on one locked OS thread, because
// no_new_privs, the capability bounding set and seccomp filters are per thread and survive
// execve only on the thread that calls it:
//
//  1. RLIMIT_NPROC (the process limit) and RLIMIT_NOFILE
//  2. no_new_privs: setuid binaries and file capabilities can't raise privileges
//  3. drop every capability from the bounding set (needs CAP_SETPCAP, so before setuid)
//  4. setgroups([]), setgid, setuid: non-root, which also clears effective/permitted caps
//  5. qt's seccomp filter (the same deny-list as the gvisor backend)
//  6. chdir and execve
func Spawn() int {
	runtime.LockOSThread()
	if err := spawn(); err != nil {
		fmt.Fprintln(os.Stderr, "qt:", err)
		return 127
	}
	return 0 // not reached
}

func spawn() error {
	f := os.NewFile(3, "spec")
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("read exec spec: %w", err)
	}
	var e agentproto.Exec
	if err := json.Unmarshal(data, &e); err != nil || len(e.Argv) == 0 {
		return fmt.Errorf("bad exec spec: %w", errors.Join(err, errors.New("need argv")))
	}
	if e.UID == 0 {
		return fmt.Errorf("refusing to run as root")
	}
	nproc := e.NProc
	if nproc == 0 {
		nproc = 512
	}
	if err := syscall.Setrlimit(rlimitNproc, &syscall.Rlimit{Cur: nproc, Max: nproc}); err != nil {
		return fmt.Errorf("setrlimit nproc: %w", err)
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: 65536, Max: 65536})

	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	for c := 0; c <= lastCap; c++ {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prCapbsetDrop, uintptr(c), 0); errno != 0 && errno != syscall.EINVAL {
			return fmt.Errorf("drop capability %d: %w", c, errno)
		}
	}
	path, err := lookPath(e.Argv[0], e.Env)
	if err != nil {
		return err
	}
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(int(e.GID)); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(int(e.UID)); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	cwd := e.Cwd
	if cwd == "" {
		cwd = "/"
	}
	if err := os.Chdir(cwd); err != nil {
		return fmt.Errorf("chdir %s: %w", cwd, err)
	}
	if err := installSeccomp(); err != nil {
		return err
	}
	if err := syscall.Exec(path, e.Argv, e.Env); err != nil { //nolint:gosec // G204: running the sandbox's command is the point
		return fmt.Errorf("exec %s: %w", e.Argv[0], err)
	}
	return nil
}

// lookPath resolves argv[0] against the PATH in the process's own environment.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	p := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			p = v
		}
	}
	for _, dir := range filepath.SplitList(p) {
		if dir == "" {
			dir = "."
		}
		c := filepath.Join(dir, name)
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("%s: executable file not found in $PATH", name)
}
