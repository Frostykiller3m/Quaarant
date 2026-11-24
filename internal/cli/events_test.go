package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

func render(t *testing.T, src events.Source, p events.Payload) string {
	t.Helper()
	ev, err := events.New("sb1", src, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ev)
	return formatEvent(raw)
}

func TestFormatEvent(t *testing.T) {
	uid := uint32(65534)
	n := int64(2048)
	no := false
	tests := []struct {
		name string
		src  events.Source
		p    events.Payload
		want []string
	}{
		{"exec", events.SourceHost, events.Exec{PID: 3, PPID: 2, UID: &uid, Path: "/bin/busybox", Argv: []string{"sh", "-c", "echo hi"}}, []string{"exec  pid=3 ppid=2 uid=65534  /bin/busybox sh -c \"echo hi\""}},
		{"file", events.SourceHost, events.File{Op: "open", Path: "/etc/shadow", PID: 11, Flags: []string{"O_RDONLY"}, Errno: "EACCES"}, []string{"file  open    /etc/shadow  pid=11  O_RDONLY  EACCES"}},
		{"write", events.SourceHost, events.File{Op: "write", Path: "/tmp/f", PID: 2, Bytes: &n}, []string{"write   /tmp/f  pid=2  2.0 KiB"}},
		{"rename", events.SourceHost, events.File{Op: "rename", Path: "/a", NewPath: "/b"}, []string{"rename  /a -> /b"}},
		{"net", events.SourceHost, events.Net{Op: "connect", Proto: "tcp", DstIP: "2001:db8::1", DstPort: 443, Allowed: &no, Errno: "ENETUNREACH"}, []string{"connect tcp [2001:db8::1]:443  blocked  ENETUNREACH"}},
		{"guest claim", events.SourceGuest, events.File{Op: "open", Path: "/x"}, []string{"(guest claim)"}},
		{"escapes", events.SourceHost, events.File{Op: "create", Path: "/tmp/\x1b]0;owned\x07"}, []string{`"/tmp/\x1b]0;owned\a"`}},
		{"argv escapes", events.SourceHost, events.Exec{PID: 3, Path: "/bin/x", Argv: []string{"\x1b[2J"}}, []string{`"\x1b[2J"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := render(t, tt.src, tt.p)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("got  %q\nwant %q", got, w)
				}
			}
			if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
				t.Errorf("control character reached the terminal: %q", got)
			}
		})
	}
	if got := formatEvent([]byte("not json \x1b")); strings.ContainsRune(got, 0x1b) {
		t.Errorf("garbage line not quoted: %q", got)
	}
}
