//go:build linux

package gvisor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/Frostykiller3m/Quaarant/internal/events"
	pb "github.com/Frostykiller3m/Quaarant/internal/gvisorpb"
)

func ctxData(tgid, ppid int32, cwd string) *pb.ContextData {
	return &pb.ContextData{ThreadGroupId: tgid, ParentThreadGroupId: ppid, Cwd: cwd, Credentials: &pb.Credentials{RealUid: 1000}}
}

func feed(t *testing.T, tr *translator, typ pb.MessageType, m proto.Message) []events.Payload {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := tr.message(typ, b)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// valid checks every event against the schema, as qtd's event log will.
func valid(t *testing.T, evs []events.Payload) {
	t.Helper()
	for _, p := range evs {
		ev, err := events.New("sb", events.SourceHost, time.Now(), p)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(ev)
		if _, err := events.Validate(raw); err != nil {
			t.Errorf("%+v fails the schema: %v", p, err)
		}
	}
}

func TestTranslateExec(t *testing.T) {
	tr := newTranslator(true)
	long := strings.Repeat("é", 3000) // 6000 bytes
	argv := []string{"sh", "-c", long}
	for i := range 300 {
		argv = append(argv, fmt.Sprint(i))
	}
	sum := make([]byte, 32)
	sum[0] = 0xab
	evs := feed(t, tr, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: ctxData(42, 7, "/work"), BinaryPath: "/bin/busybox", Argv: argv, BinarySha256: sum,
	})
	valid(t, evs)
	if len(evs) != 1 {
		t.Fatalf("events = %+v", evs)
	}
	e := evs[0].(events.Exec)
	if e.PID != 42 || e.PPID != 7 || *e.UID != 1000 || e.Path != "/bin/busybox" || e.Cwd != "/work" || !e.ArgvTruncated {
		t.Errorf("exec = %+v", e)
	}
	if len(e.Argv) != maxArgs || len(e.Argv[2]) > maxArgLen || !strings.HasPrefix(e.SHA256, "ab00") || len(e.SHA256) != 64 {
		t.Errorf("argv %d, arg len %d, sha %q", len(e.Argv), len(e.Argv[2]), e.SHA256)
	}
	// Fallbacks and refusals.
	if evs := feed(t, tr, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: ctxData(5, 1, "rel"), Execfn: "/x"}); len(evs) != 1 || evs[0].(events.Exec).Path != "/x" || evs[0].(events.Exec).Cwd != "" {
		t.Errorf("execfn fallback / relative cwd: %+v", evs)
	}
	if evs := feed(t, tr, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: ctxData(5, 1, "/")}); len(evs) != 0 {
		t.Errorf("exec without a path: %+v", evs)
	}
	if evs := feed(t, tr, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: ctxData(1, 0, "/"), BinaryPath: "/.qt/qt-agent"}); len(evs) != 0 {
		t.Errorf("init's own activity reported: %+v", evs)
	}
}

func TestTranslateOpen(t *testing.T) {
	tr := newTranslator(true)
	tests := []struct {
		name string
		m    *pb.Open
		want string // "" = no event; else path|flags|mode|errno
	}{
		{"absolute", &pb.Open{ContextData: ctxData(9, 1, "/w"), Fd: unix.AT_FDCWD, Pathname: "/etc/passwd", Flags: unix.O_RDONLY | unix.O_CLOEXEC}, "/etc/passwd|O_RDONLY,O_CLOEXEC||"},
		{"relative to cwd", &pb.Open{ContextData: ctxData(9, 1, "/home/u"), Fd: unix.AT_FDCWD, Pathname: "../u/.ssh/id_rsa"}, "/home/u/.ssh/id_rsa|O_RDONLY||"},
		{"relative to dirfd", &pb.Open{ContextData: ctxData(9, 1, "/"), Fd: 5, FdPath: "/root", Pathname: ".aws/credentials", Exit: &pb.Exit{Errorno: int64(unix.EACCES)}}, "/root/.aws/credentials|O_RDONLY||EACCES"},
		{"create with mode", &pb.Open{ContextData: ctxData(9, 1, "/"), Fd: unix.AT_FDCWD, Pathname: "/tmp/x", Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, Mode: 0o4755}, "/tmp/x|O_WRONLY,O_CREAT,O_TRUNC|04755|"},
		{"directory walk", &pb.Open{ContextData: ctxData(9, 1, "/"), Fd: unix.AT_FDCWD, Pathname: "/etc", Flags: unix.O_DIRECTORY}, ""},
		{"O_PATH", &pb.Open{ContextData: ctxData(9, 1, "/"), Fd: unix.AT_FDCWD, Pathname: "/etc", Flags: unix.O_PATH}, ""},
		{"dev null", &pb.Open{ContextData: ctxData(9, 1, "/"), Fd: unix.AT_FDCWD, Pathname: "/dev/null", Flags: unix.O_WRONLY}, ""},
		{"from init", &pb.Open{ContextData: ctxData(1, 0, "/"), Fd: unix.AT_FDCWD, Pathname: "/proc/self/cgroup"}, ""},
		{"empty", &pb.Open{ContextData: ctxData(9, 1, "/")}, ""},
		{"nul and huge path", &pb.Open{ContextData: ctxData(9, 1, "/"), Fd: unix.AT_FDCWD, Pathname: "/a\x00b" + strings.Repeat("x", 5000)}, "LONG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evs := feed(t, tr, pb.MessageType_MESSAGE_SYSCALL_OPEN, tt.m)
			valid(t, evs)
			if tt.want == "" {
				if len(evs) != 0 {
					t.Errorf("want no event, got %+v", evs)
				}
				return
			}
			if len(evs) != 1 {
				t.Fatalf("events = %+v", evs)
			}
			f := evs[0].(events.File)
			if tt.want == "LONG" {
				if len(f.Path) > maxPathLen || strings.ContainsRune(f.Path, 0) {
					t.Errorf("path not bounded: %d bytes", len(f.Path))
				}
				return
			}
			if got := f.Path + "|" + strings.Join(f.Flags, ",") + "|" + f.Mode + "|" + f.Errno; got != tt.want || f.Op != "open" || f.PID != 9 {
				t.Errorf("got %s (op %s pid %d), want %s", got, f.Op, f.PID, tt.want)
			}
		})
	}
}

func TestTranslateWritesAggregate(t *testing.T) {
	now := time.Unix(1000, 0)
	tr := newTranslator(true)
	tr.now = func() time.Time { return now }
	w := func(tgid int32, p string, n int64) []events.Payload {
		return feed(t, tr, pb.MessageType_MESSAGE_SYSCALL_WRITE, &pb.Write{ContextData: ctxData(tgid, 1, "/"), FdPath: p, Exit: &pb.Exit{Result: n}})
	}
	for range 100 {
		if evs := w(5, "/tmp/log", 10); len(evs) != 0 {
			t.Fatalf("write emitted before close: %+v", evs)
		}
	}
	for _, p := range []string{"pipe:[12]", "socket:[3]", "/dev/pts/0", "/dev/null"} {
		w(5, p, 10)
	}
	w(5, "/tmp/fail", -13) // failed write: no bytes
	evs := feed(t, tr, pb.MessageType_MESSAGE_SYSCALL_CLOSE, &pb.Close{ContextData: ctxData(5, 1, "/"), Fd: 3, FdPath: "/tmp/log"})
	valid(t, evs)
	if len(evs) != 1 || evs[0].(events.File).Op != "write" || *evs[0].(events.File).Bytes != 1000 || evs[0].(events.File).PID != 5 {
		t.Fatalf("close flush = %+v", evs)
	}
	if len(tr.writes) != 0 {
		t.Errorf("pipes/terminals/failed writes were tracked: %v", tr.writes)
	}
	// Exit flushes a process's files; age flushes long-lived writers.
	w(6, "/a", 1)
	w(7, "/b", 2)
	if evs := feed(t, tr, pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT, &pb.ExitNotifyParentInfo{ContextData: ctxData(6, 1, "/")}); len(evs) != 1 || evs[0].(events.File).Path != "/a" {
		t.Errorf("exit flush = %+v", evs)
	}
	if evs := tr.tick(); len(evs) != 0 {
		t.Errorf("young write flushed: %+v", evs)
	}
	now = now.Add(3 * time.Second)
	if evs := tr.tick(); len(evs) != 1 || evs[0].(events.File).Path != "/b" {
		t.Errorf("aged flush = %+v", evs)
	}
}

func TestTranslateConnect(t *testing.T) {
	inet := func(ip [4]byte, port uint16) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b, unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:], port)
		copy(b[4:], ip[:])
		return b
	}
	inet6 := func(ip [16]byte, port uint16) []byte {
		b := make([]byte, 28)
		binary.LittleEndian.PutUint16(b, unix.AF_INET6)
		binary.BigEndian.PutUint16(b[2:], port)
		copy(b[8:], ip[:])
		return b
	}
	mapped := [16]byte{10: 0xff, 11: 0xff, 12: 1, 13: 2, 14: 3, 15: 4}
	v6 := [16]byte{0: 0x20, 1: 0x01, 2: 0x0d, 3: 0xb8, 15: 1}
	unixAddr := make([]byte, 20)
	binary.LittleEndian.PutUint16(unixAddr, unix.AF_UNIX)

	tr := newTranslator(true)
	feed(t, tr, pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{ContextData: ctxData(8, 1, "/"), Domain: unix.AF_INET, Type: unix.SOCK_DGRAM | unix.SOCK_CLOEXEC, Exit: &pb.Exit{Result: 4}})
	tests := []struct {
		name string
		m    *pb.Connect
		want string
	}{
		{"udp tracked", &pb.Connect{ContextData: ctxData(8, 1, "/"), Fd: 4, Address: inet([4]byte{8, 8, 8, 8}, 53), Exit: &pb.Exit{Errorno: int64(unix.ENETUNREACH)}}, "udp 8.8.8.8:53 false ENETUNREACH"},
		{"untracked defaults to tcp", &pb.Connect{ContextData: ctxData(8, 1, "/"), Fd: 9, Address: inet([4]byte{192, 0, 2, 1}, 443)}, "tcp 192.0.2.1:443 false "},
		{"loopback is allowed", &pb.Connect{ContextData: ctxData(8, 1, "/"), Fd: 9, Address: inet([4]byte{127, 0, 0, 1}, 8080)}, "tcp 127.0.0.1:8080 true "},
		{"v4-mapped v6", &pb.Connect{ContextData: ctxData(8, 1, "/"), Fd: 9, Address: inet6(mapped, 80)}, "tcp 1.2.3.4:80 false "},
		{"v6", &pb.Connect{ContextData: ctxData(8, 1, "/"), Fd: 9, Address: inet6(v6, 22), Exit: &pb.Exit{Errorno: int64(unix.EINPROGRESS)}}, "tcp 2001:db8::1:22 false "},
		{"unix socket", &pb.Connect{ContextData: ctxData(8, 1, "/"), Address: unixAddr}, ""},
		{"truncated address", &pb.Connect{ContextData: ctxData(8, 1, "/"), Address: inet([4]byte{1, 2, 3, 4}, 1)[:6]}, ""},
		{"empty", &pb.Connect{ContextData: ctxData(8, 1, "/")}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evs := feed(t, tr, pb.MessageType_MESSAGE_SYSCALL_CONNECT, tt.m)
			valid(t, evs)
			if tt.want == "" {
				if len(evs) != 0 {
					t.Errorf("want none, got %+v", evs)
				}
				return
			}
			if len(evs) != 1 {
				t.Fatalf("events = %+v", evs)
			}
			n := evs[0].(events.Net)
			if got := fmt.Sprintf("%s %s:%d %v %s", n.Proto, n.DstIP, n.DstPort, *n.Allowed, n.Errno); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
	// Closing the fd forgets the socket type.
	feed(t, tr, pb.MessageType_MESSAGE_SYSCALL_CLOSE, &pb.Close{ContextData: ctxData(8, 1, "/"), Fd: 4})
	if len(tr.sockets) != 0 {
		t.Errorf("socket table not cleaned: %v", tr.sockets)
	}
}

func TestTranslateRejectsGarbage(t *testing.T) {
	tr := newTranslator(true)
	if _, err := tr.message(pb.MessageType_MESSAGE_SYSCALL_OPEN, []byte{0xff, 0xff, 0xff}); err == nil {
		t.Error("garbage payload decoded")
	}
	if evs, err := tr.message(pb.MessageType(999), []byte("x")); err != nil || evs != nil {
		t.Errorf("unknown type: %v %v", evs, err)
	}
	tests := []struct {
		b  []byte
		ok bool
	}{
		{nil, false},
		{[]byte{8, 0, 7, 0, 0, 0, 0}, false},                // short
		{[]byte{4, 0, 7, 0, 0, 0, 0, 0}, false},             // header size below 8
		{[]byte{200, 0, 7, 0, 0, 0, 0, 0, 1}, false},        // header size beyond the packet
		{[]byte{8, 0, 7, 0, 3, 0, 0, 0, 0xaa}, true},        // normal
		{[]byte{10, 0, 7, 0, 3, 0, 0, 0, 9, 9, 0xaa}, true}, // larger header from a newer sentry
	}
	for _, tt := range tests {
		typ, dropped, payload, ok := parseWire(tt.b)
		if ok != tt.ok || (ok && (typ != 7 || dropped != 3 || len(payload) != 1 || payload[0] != 0xaa)) {
			t.Errorf("parseWire(%v) = %v %v %v %v", tt.b, typ, dropped, payload, ok)
		}
	}
}

type memSink struct {
	mu  sync.Mutex
	evs []events.Payload
}

func (s *memSink) Emit(_ context.Context, _ events.Source, p events.Payload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, p)
	return nil
}

func (s *memSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.evs)
}

// TestMonitorProtocol plays the sentry's side of the remote-sink protocol.
func TestMonitorProtocol(t *testing.T) {
	ws, err := os.MkdirTemp("", "qtmon")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(ws) })
	sink := &memSink{}
	m, err := startMonitor(ws, sink, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.stop()
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: filepath.Join(ws, monitorSocket), Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	hs, _ := proto.Marshal(&pb.Handshake{Version: 1})
	if _, err := conn.Write(hs); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var reply pb.Handshake
	if err := proto.Unmarshal(buf[:n], &reply); err != nil || reply.GetVersion() != 1 {
		t.Fatalf("handshake reply = %v, %v", &reply, err)
	}
	if err := m.waitReady(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ws, monitorSocket)); !os.IsNotExist(err) {
		t.Error("socket file still exists after the one connection was accepted")
	}
	send := func(typ pb.MessageType, dropped uint32, msg proto.Message) {
		body, _ := proto.Marshal(msg)
		hdr := make([]byte, 8)
		binary.LittleEndian.PutUint16(hdr[0:], 8)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(typ))
		binary.LittleEndian.PutUint32(hdr[4:], dropped)
		if _, err := conn.Write(append(hdr, body...)); err != nil {
			t.Fatal(err)
		}
	}
	send(pb.MessageType_MESSAGE_SENTRY_EXEC, 0, &pb.ExecveInfo{ContextData: ctxData(3, 2, "/"), BinaryPath: "/bin/id", Argv: []string{"id"}})
	_, _ = conn.Write([]byte{1, 2, 3}) // malformed: ignored, counted
	send(pb.MessageType_MESSAGE_SYSCALL_OPEN, 4, &pb.Open{ContextData: ctxData(3, 2, "/"), Fd: unix.AT_FDCWD, Pathname: "/etc/hosts"})
	send(pb.MessageType_MESSAGE_SYSCALL_WRITE, 4, &pb.Write{ContextData: ctxData(3, 2, "/"), FdPath: "/tmp/out", Exit: &pb.Exit{Result: 7}})
	_ = conn.Close() // sandbox gone: pending writes are flushed
	deadline := time.Now().Add(3 * time.Second)
	for sink.len() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	m.stop()
	if sink.len() != 3 {
		t.Fatalf("events = %+v", sink.evs)
	}
	if m.malformed.Load() != 1 || m.dropped.Load() != 4 {
		t.Errorf("malformed %d dropped %d, want 1 and 4", m.malformed.Load(), m.dropped.Load())
	}
}
