//go:build !windows

package safetar

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteTarRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	mustWrite(t, filepath.Join(src, "work", "a.txt"), "alpha", 0o644)
	mustWrite(t, filepath.Join(src, "work", "sub", "b.bin"), strings.Repeat("b", 100_000), 0o755)
	mustWrite(t, filepath.Join(src, "work", "suid"), "s", 0o4755)
	if err := os.Symlink("/etc/shadow", filepath.Join(src, "work", "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(src, "work", "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "outside"), []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside", filepath.Join(src, "work", "up")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var buf bytes.Buffer
	st, err := WriteTar(root, "work", &buf, DefaultTarLimits)
	if err != nil {
		t.Fatal(err)
	}
	if st.Skipped != 1 {
		t.Errorf("skipped %d, want 1 (the fifo)", st.Skipped)
	}
	// Entries: names under work/, symlinks stored not followed, no setuid bit.
	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	names := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[h.Name] = h
		if data, _ := io.ReadAll(tr); bytes.Contains(data, []byte("host secret")) {
			t.Errorf("%s: archive followed a symlink out of the root", h.Name)
		}
	}
	for _, n := range []string{"work/", "work/a.txt", "work/sub/", "work/sub/b.bin", "work/link", "work/up", "work/suid"} {
		if names[n] == nil {
			t.Errorf("missing entry %s (have %v)", n, keys(names))
		}
	}
	if h := names["work/link"]; h != nil && (h.Typeflag != tar.TypeSymlink || h.Linkname != "/etc/shadow") {
		t.Errorf("link entry = %+v", h)
	}
	if h := names["work/suid"]; h != nil && h.Mode&0o6000 != 0 {
		t.Errorf("setuid bit kept: %o", h.Mode)
	}
	// And it unpacks with the same safe unpacker the CLI uses.
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(bytes.NewReader(buf.Bytes()), out, DefaultUnpackLimits, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "work", "sub", "b.bin")); len(b) != 100_000 {
		t.Errorf("b.bin = %d bytes", len(b))
	}
}

func TestWriteTarLimits(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "d", "a"), "12345", 0o644)
	mustWrite(t, filepath.Join(dir, "d", "b"), "12345", 0o644)
	root, _ := os.OpenRoot(dir)
	defer func() { _ = root.Close() }()
	for _, lim := range []TarLimits{{MaxBytes: 6, MaxEntries: 100}, {MaxBytes: 1 << 20, MaxEntries: 2}} {
		if _, err := WriteTar(root, "d", io.Discard, lim); !errors.Is(err, ErrTarLimit) {
			t.Errorf("limits %+v: err = %v", lim, err)
		}
	}
	if _, err := WriteTar(root, "missing", io.Discard, DefaultTarLimits); err == nil {
		t.Error("missing path accepted")
	}
}

func mustWrite(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func keys(m map[string]*tar.Header) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
