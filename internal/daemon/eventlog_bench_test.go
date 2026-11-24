package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// BenchmarkEmit measures one event: build, schema-validate, append.
func BenchmarkEmit(b *testing.B) {
	l := newEventLog(filepath.Join(b.TempDir(), "events.jsonl"), "sb1", nil)
	l.tokens = 1e12
	ev := events.Exec{PID: 3, PPID: 2, Path: "/bin/busybox", Argv: []string{"cat", "/etc/os-release"}, Cwd: "/"}
	for b.Loop() {
		l.tokens = 1e12
		if err := l.Emit(context.Background(), events.SourceHost, ev); err != nil {
			b.Fatal(err)
		}
	}
}
