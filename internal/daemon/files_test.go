package daemon

import (
	"io/fs"
	"testing"
)

func TestUTF8Field(t *testing.T) {
	if s, raw := utf8Field("/tmp/ok-ünïcode"); s != "/tmp/ok-ünïcode" || raw != nil {
		t.Errorf("valid name: %q %v", s, raw)
	}
	bad := "/tmp/\xff\xfe"
	s, raw := utf8Field(bad)
	if string(raw) != bad || s != "/tmp/�" {
		t.Errorf("invalid name: %q %q", s, raw)
	}
}

func TestPosixMode(t *testing.T) {
	tests := []struct {
		in   fs.FileMode
		want uint32
	}{
		{0o644, 0o100644},
		{fs.ModeDir | 0o755, 0o040755},
		{fs.ModeDir | fs.ModeSticky | 0o777, 0o041777},
		{fs.ModeSymlink | 0o777, 0o120777},
		{fs.ModeSetuid | 0o755, 0o104755},
		{fs.ModeNamedPipe | 0o600, 0o010600},
		{fs.ModeDevice | fs.ModeCharDevice | 0o666, 0o020666},
		{fs.ModeDevice | 0o660, 0o060660},
		{fs.ModeSocket | 0o700, 0o140700},
	}
	for _, tt := range tests {
		if got := posixMode(tt.in); got != tt.want {
			t.Errorf("posixMode(%v) = %o, want %o", tt.in, got, tt.want)
		}
	}
}
