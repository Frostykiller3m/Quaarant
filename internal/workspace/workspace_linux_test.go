//go:build linux

package workspace

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
