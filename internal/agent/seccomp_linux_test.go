//go:build linux

package agent

import (
	"runtime"
	"testing"
)

func TestSeccompProgram(t *testing.T) {
	for arch, nrs := range deniedSyscalls {
		if len(nrs) != len(deniedNames) {
			t.Errorf("%s: %d numbers for %d names", arch, len(nrs), len(deniedNames))
		}
		seen := map[uint32]bool{}
		for _, n := range nrs {
			if seen[n] {
				t.Errorf("%s: duplicate syscall %d", arch, n)
			}
			seen[n] = true
		}
	}
	p, err := seccompProgram()
	if err != nil {
		t.Fatal(err)
	}
	want := 4 + 2*len(deniedNames) + 1
	if runtime.GOARCH == "amd64" {
		want += 2
	}
	if len(p) != want || p[len(p)-1].K != seccompRetAllow || p[2].K != seccompRetKillProcess {
		t.Errorf("program: %d instructions (want %d), last %+v", len(p), want, p[len(p)-1])
	}
}
