//go:build linux

package workspace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type collector struct {
	mu  sync.Mutex
	evs []string
}

func (c *collector) add(e FileEvent) {
	s := e.Op + " " + e.Path
	if e.NewPath != "" {
		s += " -> " + e.NewPath
	}
	if e.Op == "chmod" {
		s += fmt.Sprintf(" %o", e.Mode.Perm())
	}
	c.mu.Lock()
	c.evs = append(c.evs, s)
	c.mu.Unlock()
}

// waitFor waits until every wanted line has been seen and returns everything seen.
func (c *collector) waitFor(t *testing.T, want ...string) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c.mu.Lock()
		got := append([]string(nil), c.evs...)
		c.mu.Unlock()
		missing := []string{}
		for _, w := range want {
			found := false
			for _, g := range got {
				if g == w {
					found = true
				}
			}
			if !found {
				missing = append(missing, w)
			}
		}
		if len(missing) == 0 {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing events %q; got %q", missing, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func startWatch(t *testing.T, lowerFiles map[string]string) (upper string, c *collector, w *Watcher) {
	t.Helper()
	l, u := layers(t, lowerFiles, map[string]string{".qt/qt-agent": ""})
	c = &collector{}
	w, err := Watch(u, l, WatchOptions{Hidden: []string{"/.qt"}}, c.add)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return u, c, w
}

func TestWatchNamespaceChanges(t *testing.T) {
	u, c, _ := startWatch(t, map[string]string{"etc/hosts": "x"})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(u, "new.txt"), []byte("hi"), 0o644))
	// Created faster than watches can be added: the scan of the new directory catches up.
	must(os.MkdirAll(filepath.Join(u, "a", "b", "c"), 0o755))
	must(os.WriteFile(filepath.Join(u, "a", "b", "c", "deep"), nil, 0o644))
	c.waitFor(t, "create /new.txt", "mkdir /a", "mkdir /a/b", "mkdir /a/b/c", "create /a/b/c/deep")
	must(os.Symlink("/etc/shadow", filepath.Join(u, "link")))
	c.waitFor(t, "symlink /link -> /etc/shadow")
	must(os.Rename(filepath.Join(u, "new.txt"), filepath.Join(u, "a", "moved.txt")))
	c.waitFor(t, "rename /new.txt -> /a/moved.txt")
	must(os.Chmod(filepath.Join(u, "a", "moved.txt"), 0o4755))
	must(os.Remove(filepath.Join(u, "link")))
	must(os.WriteFile(filepath.Join(u, ".qt", "hidden"), nil, 0o644))
	got := c.waitFor(t, "chmod /a/moved.txt 755", "unlink /link")
	seen := map[string]int{}
	for _, g := range got {
		if seen[g]++; seen[g] > 1 {
			t.Errorf("reported twice: %s", g)
		}
	}
	for _, g := range got {
		if strings.Contains(g, ".qt") {
			t.Errorf("hidden path reported: %s", g)
		}
	}
}

func TestWatchSuppressAndSymlinkSwap(t *testing.T) {
	u, c, w := startWatch(t, nil)
	outside := t.TempDir()
	release := w.Suppress("/work")
	if err := os.MkdirAll(filepath.Join(u, "work", "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u, "work", "repo", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	release()
	// A directory swapped for a symlink to a host directory must not be watched as that dir.
	if err := os.Mkdir(filepath.Join(u, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.waitFor(t, "mkdir /d")
	if err := os.Remove(filepath.Join(u, "d")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(u, "d")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "host-file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u, "marker"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := c.waitFor(t, "create /marker")
	for _, g := range got {
		if strings.Contains(g, "/work") || strings.Contains(g, "host-file") {
			t.Errorf("reported %q (suppressed copy-in, or a host directory)", g)
		}
	}
}

// TestITestWatchOverlay runs the watcher on a real overlayfs (root only) and changes the
// sandbox's view through the merged mount: whiteouts must read as deletes, copy-ups as nothing.
func TestITestWatchOverlay(t *testing.T) {
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
	mustWrite(t, filepath.Join(lower, "etc", "issue"), "distro", 0o644)
	mustWrite(t, filepath.Join(lower, "etc", "motd"), "hi", 0o644)
	mustWrite(t, filepath.Join(lower, "opt", "app", "a"), "a", 0o644)
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work + ",redirect_dir=off,metacopy=off,index=off"
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Fatalf("mount overlay: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
	c := &collector{}
	w, err := Watch(upper, lower, WatchOptions{}, c.add)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	cmd := exec.Command("sh", "-ec", `rm etc/issue; echo more >> etc/motd; mkdir -p etc/new/dir; echo x > etc/new/dir/f
		rm -rf opt/app; chmod 600 etc/motd; mv etc/motd etc/motd2`)
	cmd.Dir = merged
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := c.waitFor(t,
		"unlink /etc/issue",
		"mkdir /etc/new", "mkdir /etc/new/dir", "create /etc/new/dir/f",
		"unlink /opt/app",
		"chmod /etc/motd 600",
		"rename /etc/motd -> /etc/motd2",
	)
	for _, g := range got {
		if g == "mkdir /etc" || g == "create /etc/motd" || g == "mkdir /opt" {
			t.Errorf("a copy-up was reported as a change: %s (all: %q)", g, got)
		}
	}
	t.Logf("events: %q", got)
}
