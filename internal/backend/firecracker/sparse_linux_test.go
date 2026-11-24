//go:build linux

package firecracker

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSparsify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mem")
	data := make([]byte, 8<<20) // 8 MiB, data at 1 MiB and at the very end
	copy(data[1<<20:], "guest page")
	copy(data[len(data)-5:], "tail!")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	saved, err := sparsify(p)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, data) {
		t.Fatal("contents changed")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	if used := st.Blocks * 512; used > 1<<20 || saved < 6<<20 {
		t.Errorf("%d bytes still allocated, %d saved", used, saved)
	}
}
