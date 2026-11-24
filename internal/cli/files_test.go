package cli

import (
	"io/fs"
	"strings"
	"testing"
)

func TestParseLocation(t *testing.T) {
	tests := []struct {
		in            string
		sandbox, path string
	}{
		{"3f2a9c1b7e04:/work", "3f2a9c1b7e04", "/work"},
		{"3f2a9c1b7e04:/work/../etc/", "3f2a9c1b7e04", "/etc"},
		{"./repo", "", "./repo"},
		{"-", "", "-"},
		{`C:\Users\me`, "", `C:\Users\me`},
		{"c:/Users/me", "", "c:/Users/me"}, // a drive letter, not a sandbox
		{"box:relative", "", "box:relative"},
	}
	for _, tt := range tests {
		got := parseLocation(tt.in)
		if got.sandbox != tt.sandbox || got.path != tt.path {
			t.Errorf("parseLocation(%q) = %+v", tt.in, got)
		}
	}
}

func TestDisplayNameEscapesTerminalControl(t *testing.T) {
	tests := []struct {
		in, want string
		raw      []byte
	}{
		{"/tmp/plain name", "/tmp/plain name", nil},
		{"/tmp/ünï", "/tmp/ünï", nil},
		{"/tmp/\x1b]0;pwned\x07", `"/tmp/\x1b]0;pwned\a"`, nil},
		{"/tmp/a\nb", `"/tmp/a\nb"`, nil},
		{"/tmp/\uFFFD", `"/tmp/\xff"`, []byte("/tmp/\xff")}, // raw bytes win
	}
	for _, tt := range tests {
		if got := displayName(tt.in, tt.raw); got != tt.want {
			t.Errorf("displayName(%q) = %s, want %s", tt.in, got, tt.want)
		}
		if strings.ContainsRune(displayName(tt.in, tt.raw), 0x1b) {
			t.Errorf("escape byte reached the terminal for %q", tt.in)
		}
	}
}

func TestFileModeAndHumanBytes(t *testing.T) {
	if m := fileMode(0o120777); m&fs.ModeSymlink == 0 || m.Perm() != 0o777 {
		t.Errorf("symlink mode = %v", m)
	}
	if m := fileMode(0o041777); !m.IsDir() || m&fs.ModeSticky == 0 {
		t.Errorf("sticky dir mode = %v", m)
	}
	for in, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 5 << 20: "5.0 MiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %s, want %s", in, got, want)
		}
	}
}
