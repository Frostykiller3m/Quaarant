//go:build linux

package gvisor

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/Frostykiller3m/Quaarant/internal/events"
	pb "github.com/Frostykiller3m/Quaarant/internal/gvisorpb"
)

// Bounds from the event schema (internal/events/schema/v1.json).
const (
	maxPathLen    = 4096
	maxArgs       = 256
	maxArgLen     = 4096
	maxFlags      = 16
	maxTracked    = 4096 // sockets / pending writes tracked per sandbox
	writeFlushAge = 2 * time.Second
)

// translator turns gVisor runtime-monitoring messages into schema events. The sentry is
// gVisor's kernel, outside the sandboxed code's control, but every field it reports was
// chosen by that code (paths, argv, addresses): all of it is bounded and treated as data.
// It is not safe for concurrent use; one monitor connection owns one translator.
type translator struct {
	netNone bool // the sandbox has --net=none: only loopback can connect
	sockets map[sockKey]string
	writes  map[writeKey]*pendingWrite
	now     func() time.Time
}

type sockKey struct{ tgid, fd int64 }

type writeKey struct {
	tgid int64
	path string
}

type pendingWrite struct {
	bytes int64
	first time.Time
}

func newTranslator(netNone bool) *translator {
	return &translator{netNone: netNone, sockets: map[sockKey]string{}, writes: map[writeKey]*pendingWrite{}, now: time.Now}
}

// message decodes one payload of the given type into zero or more events.
func (t *translator) message(typ pb.MessageType, payload []byte) ([]events.Payload, error) {
	evs, err := t.decode(typ, payload)
	if err != nil {
		return nil, err
	}
	out := evs[:0]
	for _, e := range evs {
		if !fromInit(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// fromInit: pid 1 is qt's own init (qt-agent pause), not sandboxed code.
func fromInit(e events.Payload) bool {
	switch v := e.(type) {
	case events.Exec:
		return v.PID == 1
	case events.File:
		return v.PID == 1
	}
	return false
}

func (t *translator) decode(typ pb.MessageType, payload []byte) ([]events.Payload, error) {
	opts := proto.UnmarshalOptions{DiscardUnknown: true}
	switch typ {
	case pb.MessageType_MESSAGE_SENTRY_EXEC:
		var m pb.ExecveInfo
		if err := opts.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("decode exec: %w", err)
		}
		return t.exec(&m), nil
	case pb.MessageType_MESSAGE_SYSCALL_OPEN:
		var m pb.Open
		if err := opts.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("decode open: %w", err)
		}
		return t.open(&m), nil
	case pb.MessageType_MESSAGE_SYSCALL_WRITE:
		var m pb.Write
		if err := opts.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("decode write: %w", err)
		}
		return t.write(&m), nil
	case pb.MessageType_MESSAGE_SYSCALL_CLOSE:
		var m pb.Close
		if err := opts.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("decode close: %w", err)
		}
		return t.close(&m), nil
	case pb.MessageType_MESSAGE_SYSCALL_SOCKET:
		var m pb.Socket
		if err := opts.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("decode socket: %w", err)
		}
		t.socket(&m)
		return nil, nil
	case pb.MessageType_MESSAGE_SYSCALL_CONNECT:
		var m pb.Connect
		if err := opts.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("decode connect: %w", err)
		}
		return t.connect(&m), nil
	case pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT:
		var m pb.ExitNotifyParentInfo
		if err := opts.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("decode exit: %w", err)
		}
		return t.exited(int64(m.GetContextData().GetThreadGroupId())), nil
	default:
		return nil, nil // points we did not ask for, or newer message types
	}
}

func (t *translator) exec(m *pb.ExecveInfo) []events.Payload {
	ctx := m.GetContextData()
	p := m.GetBinaryPath()
	if p == "" {
		p = m.GetExecfn()
	}
	if p = boundPath(p); p == "" {
		return nil
	}
	ev := events.Exec{
		PID:  boundPID(ctx.GetThreadGroupId()),
		PPID: boundPID(ctx.GetParentThreadGroupId()),
		Path: p,
		Argv: []string{},
	}
	if c := ctx.GetCredentials(); c != nil {
		uid := c.GetRealUid()
		ev.UID = &uid
	}
	for i, a := range m.GetArgv() {
		if i == maxArgs {
			ev.ArgvTruncated = true
			break
		}
		if len(a) > maxArgLen {
			a, ev.ArgvTruncated = truncate(a, maxArgLen), true
		}
		ev.Argv = append(ev.Argv, a)
	}
	if cwd := boundPath(ctx.GetCwd()); strings.HasPrefix(cwd, "/") {
		ev.Cwd = cwd
	}
	if sum := m.GetBinarySha256(); len(sum) == 32 {
		ev.SHA256 = hex.EncodeToString(sum)
	}
	return []events.Payload{ev}
}

func (t *translator) open(m *pb.Open) []events.Payload {
	flags := int(m.GetFlags())
	if flags&(unix.O_DIRECTORY|unix.O_PATH) != 0 {
		return nil // directory walks and path handles: noise, not file access
	}
	ctx := m.GetContextData()
	p := resolve(m.GetPathname(), m.GetFd(), m.GetFdPath(), ctx.GetCwd())
	if p == "" || isTerminalOrNull(p) {
		return nil
	}
	ev := events.File{Op: "open", Path: p, PID: boundPID(ctx.GetThreadGroupId()), Flags: openFlags(flags), Errno: errnoName(m.GetExit())}
	if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
		ev.Mode = fmt.Sprintf("0%03o", m.GetMode()&0o7777)
	}
	return []events.Payload{ev}
}

// write accumulates bytes per (process, file); the event comes on close, exit, or after
// writeFlushAge, so a process writing a file in many small writes is one event.
func (t *translator) write(m *pb.Write) []events.Payload {
	n := m.GetExit().GetResult()
	p := m.GetFdPath()
	if n <= 0 || !trackedWritePath(p) {
		return nil
	}
	k := writeKey{int64(m.GetContextData().GetThreadGroupId()), boundPath(p)}
	var out []events.Payload
	pw, ok := t.writes[k]
	if !ok {
		if len(t.writes) >= maxTracked {
			out = t.flush(func(writeKey) bool { return true })
		}
		pw = &pendingWrite{first: t.now()}
		t.writes[k] = pw
	}
	pw.bytes += n
	return out
}

func (t *translator) close(m *pb.Close) []events.Payload {
	tgid := int64(m.GetContextData().GetThreadGroupId())
	delete(t.sockets, sockKey{tgid, m.GetFd()})
	if p := m.GetFdPath(); p != "" {
		k := writeKey{tgid, boundPath(p)}
		return t.flush(func(w writeKey) bool { return w == k })
	}
	return nil
}

func (t *translator) exited(tgid int64) []events.Payload {
	for k := range t.sockets {
		if k.tgid == tgid {
			delete(t.sockets, k)
		}
	}
	return t.flush(func(w writeKey) bool { return w.tgid == tgid })
}

// tick flushes writes pending for longer than writeFlushAge.
func (t *translator) tick() []events.Payload {
	cutoff := t.now().Add(-writeFlushAge)
	return t.flush(func(w writeKey) bool { return t.writes[w].first.Before(cutoff) })
}

// flushAll is called when monitoring ends.
func (t *translator) flushAll() []events.Payload {
	return t.flush(func(writeKey) bool { return true })
}

func (t *translator) flush(match func(writeKey) bool) []events.Payload {
	var out []events.Payload
	for k, pw := range t.writes {
		if !match(k) {
			continue
		}
		n := pw.bytes
		out = append(out, events.File{Op: "write", Path: k.path, PID: boundPID(int32(min(k.tgid, 1<<31-1))), Bytes: &n}) //nolint:gosec // G115: clamped
		delete(t.writes, k)
	}
	return out
}

func (t *translator) socket(m *pb.Socket) {
	fd := m.GetExit().GetResult()
	if fd < 0 || m.GetExit().GetErrorno() != 0 {
		return
	}
	d := m.GetDomain()
	if d != unix.AF_INET && d != unix.AF_INET6 {
		return
	}
	if len(t.sockets) >= maxTracked {
		clear(t.sockets)
	}
	proto := "tcp"
	switch m.GetType() & 0xf { // SOCK_NONBLOCK/SOCK_CLOEXEC live in the high bits
	case unix.SOCK_DGRAM:
		proto = "udp"
		if m.GetProtocol() == unix.IPPROTO_ICMP || m.GetProtocol() == unix.IPPROTO_ICMPV6 {
			proto = "icmp"
		}
	case unix.SOCK_RAW:
		proto = "icmp"
	}
	t.sockets[sockKey{int64(m.GetContextData().GetThreadGroupId()), fd}] = proto
}

func (t *translator) connect(m *pb.Connect) []events.Payload {
	addr, ok := parseSockaddr(m.GetAddress())
	if !ok {
		return nil // unix sockets, unknown families, malformed addresses
	}
	proto, ok := t.sockets[sockKey{int64(m.GetContextData().GetThreadGroupId()), m.GetFd()}]
	if !ok {
		proto = "tcp" // socket created before monitoring or via dup: the common case
	}
	// Loopback stays inside the sandbox; with --net=none nothing else can connect. With a link
	// the sentry only sees the attempt: qtd's proxy on the host decides (internal/netpol).
	var allowed *bool
	if v := addr.Addr().IsLoopback(); v || t.netNone {
		allowed = &v
	}
	ev := events.Net{Op: "connect", Proto: proto, DstIP: addr.Addr().String(), DstPort: int(addr.Port()), Allowed: allowed}
	if e := m.GetExit().GetErrorno(); e != int64(unix.EINPROGRESS) {
		ev.Errno = errnoName(m.GetExit())
	}
	return []events.Payload{ev}
}

// parseSockaddr reads a raw sockaddr copied from sandbox memory (host byte order family,
// network byte order port).
func parseSockaddr(b []byte) (netip.AddrPort, bool) {
	if len(b) < 2 {
		return netip.AddrPort{}, false
	}
	switch binary.LittleEndian.Uint16(b[:2]) {
	case unix.AF_INET:
		if len(b) < 8 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[2:4])), true
	case unix.AF_INET6:
		if len(b) < 24 {
			return netip.AddrPort{}, false
		}
		a := netip.AddrFrom16([16]byte(b[8:24])).Unmap()
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[2:4])), true
	}
	return netip.AddrPort{}, false
}

// resolve makes an absolute path from an openat-style (dirfd, pathname) pair.
func resolve(p string, dirfd int64, dirPath, cwd string) string {
	switch {
	case p == "":
		return ""
	case strings.HasPrefix(p, "/"):
	case dirfd == unix.AT_FDCWD && strings.HasPrefix(cwd, "/"):
		p = path.Join(cwd, p)
	case strings.HasPrefix(dirPath, "/"):
		p = path.Join(dirPath, p)
	default:
		return boundPath(p) // can't resolve; keep what the process asked for
	}
	return boundPath(path.Clean(p))
}

// trackedWritePath: real files only, not pipes, sockets, terminals or /dev/null.
func trackedWritePath(p string) bool {
	return strings.HasPrefix(p, "/") && !isTerminalOrNull(p) // not pipe:[..], socket:[..], anon_inode:..
}

func isTerminalOrNull(p string) bool {
	for _, skip := range []string{"/dev/null", "/dev/zero", "/dev/pts/", "/dev/tty", "/dev/console", "/proc/self/fd/"} {
		if strings.HasPrefix(p, skip) {
			return true
		}
	}
	return false
}

var openFlagNames = []struct {
	flag int
	name string
}{
	{unix.O_CREAT, "O_CREAT"},
	{unix.O_EXCL, "O_EXCL"},
	{unix.O_NOCTTY, "O_NOCTTY"},
	{unix.O_TRUNC, "O_TRUNC"},
	{unix.O_APPEND, "O_APPEND"},
	{unix.O_NONBLOCK, "O_NONBLOCK"},
	{unix.O_DSYNC, "O_DSYNC"},
	{unix.O_DIRECT, "O_DIRECT"},
	{unix.O_NOFOLLOW, "O_NOFOLLOW"},
	{unix.O_NOATIME, "O_NOATIME"},
	{unix.O_CLOEXEC, "O_CLOEXEC"},
}

func openFlags(f int) []string {
	out := make([]string, 0, 4)
	switch f & unix.O_ACCMODE {
	case unix.O_RDONLY:
		out = append(out, "O_RDONLY")
	case unix.O_WRONLY:
		out = append(out, "O_WRONLY")
	case unix.O_RDWR:
		out = append(out, "O_RDWR")
	}
	for _, n := range openFlagNames {
		if f&n.flag == n.flag && len(out) < maxFlags {
			out = append(out, n.name)
		}
	}
	if f&unix.O_TMPFILE == unix.O_TMPFILE && len(out) < maxFlags {
		out = append(out, "O_TMPFILE")
	}
	return out
}

func errnoName(e *pb.Exit) string {
	n := e.GetErrorno()
	if n <= 0 || n > 4095 {
		return ""
	}
	name := unix.ErrnoName(syscall.Errno(n))
	if name == "" || len(name) > 16 {
		return ""
	}
	return name
}

func boundPID(p int32) int {
	if p < 0 || p > 4194304 {
		return 0
	}
	return int(p)
}

func boundPath(p string) string {
	if strings.ContainsRune(p, 0) {
		p = strings.ReplaceAll(p, "\x00", "")
	}
	return truncate(p, maxPathLen)
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
