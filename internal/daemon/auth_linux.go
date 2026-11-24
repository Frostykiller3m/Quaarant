//go:build linux

package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func peerOf(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("raw conn: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, fmt.Errorf("raw conn: %w", err)
	}
	if credErr != nil {
		return Peer{}, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

// processGroups reads the supplementary groups of pid from /proc. The socket's own file mode
// (0660 root:<group>) is the primary gate, enforced by the kernel at connect time; this check
// is the second one.
func processGroups(pid int32) ([]uint32, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/status")
	if err != nil {
		return nil, fmt.Errorf("read groups: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "Groups:")
		if !ok {
			continue
		}
		var out []uint32
		for _, g := range strings.Fields(rest) {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				out = append(out, uint32(n))
			}
		}
		return out, nil
	}
	return nil, errors.New("no Groups line")
}
