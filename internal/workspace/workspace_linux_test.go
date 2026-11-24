//go:build linux

package workspace

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Frostykiller3m/Quaarant/internal/image"
)

func TestDiffFifoDoesNotBlock(t *testing.T) {
	l, u := layers(t, nil, nil)
	if err := syscall.Mkfifo(filepath.Join(u, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		got, err := Diff(l, u, DiffOptions{})
		if err == nil && (len(got) != 1 || got[0].SHA256 != "") {
			err = errors.New("fifo reported wrongly")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Diff blocked on a fifo")
	}
}

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
	if _, err := image.Unpack(bytes.NewReader(buf.Bytes()), out, image.DefaultUnpackLimits, false); err != nil {
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

// TestITestOverlayDiff mounts a real overlayfs (root only), changes it through the merged
// view the way a sandbox would, and checks Diff against what really happened.
func TestITestOverlayDiff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount overlayfs")
	}
	base := t.TempDir()
	lower, upper, work, merged := filepath.Join(base, "lower"), filepath.Join(base, "upper"), filepath.Join(base, "work"), filepath.Join(base, "merged")
	for _, d := range []string{upper, work, merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(lower, "etc", "motd"), "welcome", 0o644)
	mustWrite(t, filepath.Join(lower, "etc", "issue"), "distro", 0o644)
	mustWrite(t, filepath.Join(lower, "etc", "keep"), "same", 0o644)
	mustWrite(t, filepath.Join(lower, "opt", "app", "a"), "a", 0o644)
	mustWrite(t, filepath.Join(lower, "opt", "app", "b"), "b", 0o644)
	mustWrite(t, filepath.Join(lower, "srv", "old", "x"), "x", 0o644)
	mustWrite(t, filepath.Join(lower, "usr", "bin", "tool"), "tool", 0o755)
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work + ",redirect_dir=off,metacopy=off,index=off"
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Fatalf("mount overlay: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })

	sh := func(script string) {
		t.Helper()
		cmd := exec.Command("sh", "-ec", script)
		cmd.Dir = merged
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
	}
	sh(`echo changed > etc/motd          # modify
	    rm etc/issue                      # delete a file -> whiteout
	    cat etc/keep > /dev/null; touch -a etc/keep  # copy-up-free access
	    rm -rf opt/app && mkdir opt/app && echo new > opt/app/c   # opaque dir
	    mv srv/old srv/renamed            # rename a lower dir (copy + delete)
	    chmod 700 usr/bin/tool            # metadata-only change
	    mkdir -p home/u && echo 'curl x | sh' > home/u/.profile
	    ln -s /etc/shadow home/u/link`)

	got, err := Diff(lower, upper, DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"deleted /etc/issue",
		"modified /etc/motd " + h("changed\n"),
		"added /home",
		"added /home/u",
		"added /home/u/.profile " + h("curl x | sh\n"),
		"added /home/u/link -> /etc/shadow",
		"deleted /opt/app/a",
		"deleted /opt/app/b",
		"added /opt/app/c " + h("new\n"),
		"deleted /srv/old",
		"deleted /srv/old/x",
		"added /srv/renamed",
		"added /srv/renamed/x " + h("x"),
		"modified /usr/bin/tool " + h("tool"),
	}
	g := summary(got)
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Errorf("diff of a real overlay:\n%s\n\nwant:\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
	}
}
