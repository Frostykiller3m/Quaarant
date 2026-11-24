package safetar

import (
	"archive/tar"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type entry struct {
	name     string
	typ      byte
	body     string
	link     string
	mode     int64
	uid, gid int
}

func tarOf(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
			if e.typ == tar.TypeDir {
				mode = 0o755
			}
		}
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: mode, Uid: e.uid, Gid: e.gid}
		if e.typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// unpackDir returns parent/rootfs: anything appearing in parent besides rootfs is an escape.
func unpackDir(t *testing.T) (parent, dst string) {
	t.Helper()
	parent = t.TempDir()
	dst = filepath.Join(parent, "rootfs")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	return parent, dst
}

func assertNoEscape(t *testing.T, parent string) {
	t.Helper()
	des, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if de.Name() != "rootfs" {
			t.Errorf("entry escaped the rootfs: %s", filepath.Join(parent, de.Name()))
		}
	}
}

func TestUnpackLayout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks and unix modes need a unix host")
	}
	parent, dst := unpackDir(t)
	in := tarOf(t,
		entry{name: "./", typ: tar.TypeDir},
		entry{name: "bin/", typ: tar.TypeDir},
		entry{name: "bin/busybox", typ: tar.TypeReg, body: "#!bb", mode: 0o755},
		entry{name: "bin/sh", typ: tar.TypeSymlink, link: "/bin/busybox"},
		entry{name: "bin/ash", typ: tar.TypeLink, link: "bin/busybox"},
		entry{name: "tmp/", typ: tar.TypeDir, mode: 0o1777},
		entry{name: "/usr/bin/su", typ: tar.TypeReg, body: "su", mode: 0o4755}, // absolute name, setuid
		entry{name: "dev/null", typ: tar.TypeChar},
		entry{name: "run/fifo", typ: tar.TypeFifo},
		entry{name: "ro/", typ: tar.TypeDir, mode: 0o555},
		entry{name: "ro/file", typ: tar.TypeReg, body: "x"},
	)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dst, "ro"), 0o755) })
	st, err := Unpack(in, dst, DefaultUnpackLimits, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 3 || st.Symlinks != 1 || st.Hardlinks != 1 || st.Skipped != 2 {
		t.Errorf("stats = %+v", st)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "bin/busybox")); err != nil || string(b) != "#!bb" {
		t.Errorf("busybox = %q, %v", b, err)
	}
	if l, err := os.Readlink(filepath.Join(dst, "bin/sh")); err != nil || l != "/bin/busybox" {
		t.Errorf("sh -> %q, %v", l, err)
	}
	a, _ := os.Stat(filepath.Join(dst, "bin/ash"))
	b, _ := os.Stat(filepath.Join(dst, "bin/busybox"))
	if !os.SameFile(a, b) {
		t.Error("bin/ash is not a hard link to bin/busybox")
	}
	if fi, _ := os.Stat(filepath.Join(dst, "tmp")); fi.Mode()&fs.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Errorf("tmp mode = %v, want sticky 0777", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Join(dst, "usr/bin/su")); fi.Mode()&fs.ModeSetuid != 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("su mode = %v, want 0755 without setuid", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Join(dst, "ro")); fi.Mode().Perm() != 0o555 {
		t.Errorf("ro mode = %v, want 0555 applied after its contents", fi.Mode())
	}
	for _, p := range []string{"dev/null", "run/fifo"} {
		if _, err := os.Lstat(filepath.Join(dst, p)); err == nil {
			t.Errorf("%s was created; device nodes and fifos must be skipped", p)
		}
	}
	assertNoEscape(t, parent)
}

func TestUnpackRejectsEscapes(t *testing.T) {
	tests := []struct {
		name     string
		entries  []entry
		symlinks bool
	}{
		{name: "dotdot name", entries: []entry{{name: "../evil", typ: tar.TypeReg, body: "x"}}},
		{name: "dotdot in the middle", entries: []entry{{name: "a/../../evil", typ: tar.TypeReg, body: "x"}}},
		{name: "hard link outside", entries: []entry{{name: "h", typ: tar.TypeLink, link: "../outside"}}},
		{
			name:     "write through absolute symlink dir",
			symlinks: true,
			entries: []entry{
				{name: "esc", typ: tar.TypeSymlink, link: "/"},
				{name: "esc/evil", typ: tar.TypeReg, body: "x"},
			},
		},
		{
			name:     "write through relative symlink dir",
			symlinks: true,
			entries: []entry{
				{name: "esc", typ: tar.TypeSymlink, link: "../"},
				{name: "esc/evil", typ: tar.TypeReg, body: "x"},
			},
		},
		{
			name:     "hard link via symlink dir",
			symlinks: true,
			entries: []entry{
				{name: "esc", typ: tar.TypeSymlink, link: ".."},
				{name: "h", typ: tar.TypeLink, link: "esc/outside"},
			},
		},
		{
			name:     "mkdir through symlink",
			symlinks: true,
			entries: []entry{
				{name: "esc", typ: tar.TypeSymlink, link: ".."},
				{name: "esc/evil/", typ: tar.TypeDir},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.symlinks && runtime.GOOS == "windows" {
				t.Skip("needs symlinks")
			}
			parent, dst := unpackDir(t)
			if err := os.WriteFile(filepath.Join(parent, "outside"), []byte("host"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Unpack(tarOf(t, tt.entries...), dst, DefaultUnpackLimits, false)
			if err == nil {
				t.Error("expected an error")
			}
			t.Logf("rejected: %v", err)
			// Nothing new outside rootfs, and the host file is untouched.
			des, _ := os.ReadDir(parent)
			for _, de := range des {
				if de.Name() != "rootfs" && de.Name() != "outside" {
					t.Errorf("escaped: %s", de.Name())
				}
			}
			if b, _ := os.ReadFile(filepath.Join(parent, "outside")); string(b) != "host" {
				t.Errorf("host file modified: %q", b)
			}
		})
	}
}

func TestUnpackReplacesSymlinkWithFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks")
	}
	parent, dst := unpackDir(t)
	if err := os.WriteFile(filepath.Join(parent, "outside"), []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := tarOf(t,
		entry{name: "f", typ: tar.TypeSymlink, link: "../outside"},
		entry{name: "f", typ: tar.TypeReg, body: "inside"}, // must replace the link, not write through it
	)
	if _, err := Unpack(in, dst, DefaultUnpackLimits, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(parent, "outside")); string(b) != "host" {
		t.Errorf("wrote through a symlink: outside = %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(dst, "f")); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("f = %v, %v; want a regular file", fi, err)
	}
}

func TestUnpackLimits(t *testing.T) {
	tests := []struct {
		name string
		lim  UnpackLimits
	}{
		{"bytes", UnpackLimits{MaxBytes: 5, MaxEntries: 100}},
		{"entries", UnpackLimits{MaxBytes: 1 << 20, MaxEntries: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, dst := unpackDir(t)
			in := tarOf(t,
				entry{name: "a", typ: tar.TypeReg, body: "1234"},
				entry{name: "b", typ: tar.TypeReg, body: "5678"},
				entry{name: "c", typ: tar.TypeReg, body: "9"},
			)
			_, err := Unpack(in, dst, tt.lim, false)
			if !errors.Is(err, ErrLimit) {
				t.Fatalf("err = %v, want ErrLimit", err)
			}
		})
	}
}

func TestCleanName(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
		err  bool
	}{
		{"./", "", false, false},
		{"/", "", false, false},
		{"a/b/", "a/b", true, false},
		{"/etc/passwd", "etc/passwd", true, false},
		{"./a//b/./c", "a/b/c", true, false},
		{"../x", "", false, true},
		{"a/../../x", "", false, true},
		{"a\x00b", "", false, true},
	}
	for _, tt := range tests {
		got, ok, err := cleanName(tt.in)
		if got != tt.want || ok != tt.ok || (err != nil) != tt.err {
			t.Errorf("cleanName(%q) = %q, %v, %v", tt.in, got, ok, err)
		}
	}
}
