package image

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// User is a resolved image user.
type User struct {
	UID, GID uint32
	Home     string // empty if unknown
}

// maxDBSize bounds how much of an (untrusted) /etc/passwd or /etc/group is read.
const maxDBSize = 1 << 20

// LookupUser resolves an image config User value ("", "name", "uid", "name:group", "uid:gid")
// against the image's /etc/passwd and /etc/group. Files are read through an os.Root, so
// symlinks in the image cannot point the lookup at host files. An empty spec is root (0:0),
// as in Docker.
func LookupUser(rootfs, spec string) (User, error) {
	if spec == "" {
		return User{UID: 0, GID: 0, Home: "/root"}, nil
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return User{}, fmt.Errorf("open rootfs: %w", err)
	}
	defer func() { _ = root.Close() }()

	var u User
	if n, err := strconv.ParseUint(userPart, 10, 32); err == nil {
		u.UID = uint32(n)
		// gid and home from passwd if the uid is listed there.
		if e, err := findEntry(root, "etc/passwd", func(f []string) bool { return len(f) >= 6 && f[2] == userPart }); err == nil {
			u.GID = parseID(e[3])
			u.Home = e[5]
		}
	} else {
		e, err := findEntry(root, "etc/passwd", func(f []string) bool { return len(f) >= 6 && f[0] == userPart })
		if err != nil {
			return User{}, fmt.Errorf("user %q: %w", userPart, err)
		}
		uid, err1 := strconv.ParseUint(e[2], 10, 32)
		gid, err2 := strconv.ParseUint(e[3], 10, 32)
		if err1 != nil || err2 != nil {
			return User{}, fmt.Errorf("user %q: malformed passwd entry", userPart)
		}
		u = User{UID: uint32(uid), GID: uint32(gid), Home: e[5]}
	}
	if hasGroup {
		if n, err := strconv.ParseUint(groupPart, 10, 32); err == nil {
			u.GID = uint32(n)
		} else {
			e, err := findEntry(root, "etc/group", func(f []string) bool { return len(f) >= 3 && f[0] == groupPart })
			if err != nil {
				return User{}, fmt.Errorf("group %q: %w", groupPart, err)
			}
			g, err := strconv.ParseUint(e[2], 10, 32)
			if err != nil {
				return User{}, fmt.Errorf("group %q: malformed group entry", groupPart)
			}
			u.GID = uint32(g)
		}
	}
	return u, nil
}

func parseID(s string) uint32 {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func findEntry(root *os.Root, file string, match func([]string) bool) ([]string, error) {
	f, err := root.Open(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoUser
		}
		return nil, fmt.Errorf("open %s: %w", file, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxDBSize))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if fields := strings.Split(line, ":"); match(fields) {
			return fields, nil
		}
	}
	return nil, ErrNoUser
}
