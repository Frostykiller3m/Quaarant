package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

func TestEventLogLimitsAndValidation(t *testing.T) {
	l := newEventLog(filepath.Join(t.TempDir(), "events.jsonl"), "sb1", nil)
	clock := l.last
	l.rate, l.burst, l.tokens = 400, 1000, 1000
	l.now = func() time.Time { return clock } // frozen: no refill during the loop
	ctx := context.Background()
	ok, limited := 0, 0
	for range 1000 + 250 {
		err := l.Emit(ctx, events.SourceHost, events.File{Op: "open", Path: "/etc/passwd", PID: 3})
		switch {
		case err == nil:
			ok++
		case errors.Is(err, errRateLimited):
			limited++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1000 || limited != 250 {
		t.Errorf("written %d, rate-limited %d (burst 1000)", ok, limited)
	}
	if err := l.Emit(ctx, events.SourceHost, events.Exec{PID: 1, Argv: []string{}}); err == nil {
		t.Error("an event without a path passed the schema")
	}
	if l.Dropped() != uint64(limited)+1 {
		t.Errorf("dropped = %d, want %d", l.Dropped(), limited+1)
	}
	// Half a second later, half a second of rate is available again.
	clock = clock.Add(500 * time.Millisecond)
	refill := 0
	for l.Emit(ctx, events.SourceHost, events.File{Op: "open", Path: "/x", PID: 3}) == nil {
		refill++
	}
	if refill != 200 {
		t.Errorf("refilled %d, want 200", refill)
	}
	ok += refill
	l.close()
	if err := l.Emit(ctx, events.SourceHost, events.File{Op: "open", Path: "/x"}); !errors.Is(err, errLogClosed) {
		t.Errorf("emit after close: %v", err)
	}
	// Every line on disk is a valid event.
	f, err := os.Open(l.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	n := 0
	if err := events.ValidateStream(f, func(events.Event) error { n++; return nil }); err != nil || n != ok {
		t.Errorf("%d valid lines (err %v), want %d", n, err, ok)
	}
}

func TestEventLogNotifiesFollowers(t *testing.T) {
	l := newEventLog(filepath.Join(t.TempDir(), "events.jsonl"), "sb1", nil)
	ch, closed := l.changed()
	if closed {
		t.Fatal("new log is closed")
	}
	go func() { _ = l.Emit(context.Background(), events.SourceHost, events.File{Op: "unlink", Path: "/tmp/x"}) }()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("append did not wake followers")
	}
	ch, _ = l.changed()
	l.close()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not wake followers")
	}
	if _, closed := l.changed(); !closed {
		t.Error("closed log reports open")
	}
}
