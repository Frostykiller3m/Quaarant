package firecracker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitrdDeterministicNewc(t *testing.T) {
	agent := []byte("\x7fELF fake agent binary")
	var a, b bytes.Buffer
	if err := writeInitrd(&a, agent); err != nil {
		t.Fatal(err)
	}
	if err := writeInitrd(&b, agent); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("initrd is not deterministic")
	}
	s := a.String()
	if !strings.HasPrefix(s, "070701") || !strings.Contains(s, "init\x00") || !strings.Contains(s, "TRAILER!!!\x00") || !strings.Contains(s, string(agent)) {
		t.Errorf("not a newc archive with /init: %q", s[:min(len(s), 140)])
	}
	if a.Len()%4 != 0 {
		t.Errorf("archive length %d is not 4-byte aligned", a.Len())
	}
	// mode 0100755 for init
	if !strings.Contains(s[:110], "000081ED") {
		t.Errorf("init mode is not 0100755: %q", s[:110])
	}
	dir := t.TempDir()
	ap := filepath.Join(dir, "qt-agent")
	if err := os.WriteFile(ap, agent, 0o755); err != nil {
		t.Fatal(err)
	}
	p1, err := cachedInitrd(filepath.Join(dir, "c"), ap)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := cachedInitrd(filepath.Join(dir, "c"), ap)
	if err != nil || p1 != p2 {
		t.Errorf("cache: %s %s %v", p1, p2, err)
	}
}

func TestVMConfigAndLimits(t *testing.T) {
	m := boxMeta{CPU: 1500, Memory: 512 << 20}
	l := limitsFor(m)
	if l.cpuMax != "150000 100000" || l.memMax != "805306368" {
		t.Errorf("limits = %+v", l)
	}
	if jailID("abc") == jailID("abd") || jailID("abc") < 900_000 {
		t.Errorf("jail ids: %d %d", jailID("abc"), jailID("abd"))
	}
	if _, _, err := parseUser("0:0"); err == nil {
		t.Error("root accepted")
	}
}
