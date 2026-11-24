package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// Event log limits per sandbox. Sandboxed code decides how many events it causes, so the
// log must not let it fill the disk or starve qtd.
const (
	eventRate     = 2000      // sustained events per second
	eventBurst    = 20000     // tokens available at once
	maxEventBytes = 512 << 20 // events.jsonl size cap
)

var (
	errLogClosed    = errors.New("event log closed")
	errRateLimited  = errors.New("event rate limit exceeded")
	errEventLogFull = errors.New("event log is full")
)

// eventLog appends schema-valid events to sandboxes/<id>/events.jsonl and wakes followers.
// Every event is validated against the schema before it is written: the file only ever
// holds valid v1 events.
type eventLog struct {
	path    string
	sandbox string
	log     *slog.Logger

	mu      sync.Mutex
	f       *os.File
	size    int64
	closed  bool
	notify  chan struct{} // closed and replaced on every append (and on close)
	tokens  float64
	last    time.Time
	dropped uint64
	warned  bool
	now     func() time.Time
	rate    float64 // eventRate; tests lower it
	burst   float64
	derive  func(events.Event) []derived // events implied by one just written (honeytoken reads)
}

// derived is an event implied by another.
type derived struct {
	src events.Source
	p   events.Payload
}

func (l *eventLog) setDerive(f func(events.Event) []derived) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.derive = f
}

func newEventLog(path, sandbox string, log *slog.Logger) *eventLog {
	l := &eventLog{path: path, sandbox: sandbox, log: log, notify: make(chan struct{}), tokens: eventBurst, last: time.Now(), now: time.Now, rate: eventRate, burst: eventBurst}
	if fi, err := os.Stat(path); err == nil {
		l.size = fi.Size()
	}
	return l
}

// Emit implements backend.EventSink.
func (l *eventLog) Emit(_ context.Context, src events.Source, p events.Payload) error {
	ev, derive, err := l.write(src, p)
	if err != nil || derive == nil {
		return err
	}
	for _, d := range derive(ev) {
		_, _, _ = l.write(d.src, d.p)
	}
	return nil
}

// write appends one event and returns it with the derive hook in force.
func (l *eventLog) write(src events.Source, p events.Payload) (events.Event, func(events.Event) []derived, error) {
	ev, err := events.New(l.sandbox, src, time.Now().UTC(), p)
	if err != nil {
		return ev, nil, fmt.Errorf("build event: %w", err)
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return ev, nil, fmt.Errorf("encode event: %w", err)
	}
	if _, err := events.Validate(line); err != nil {
		l.drop("invalid", err)
		return ev, nil, fmt.Errorf("event fails the schema: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ev, nil, errLogClosed
	}
	now := l.now()
	l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	if l.tokens < 1 {
		l.dropLocked("rate", errRateLimited)
		return ev, nil, errRateLimited
	}
	if l.size+int64(len(line)) > maxEventBytes {
		l.dropLocked("size", errEventLogFull)
		return ev, nil, errEventLogFull
	}
	if l.f == nil {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return ev, nil, fmt.Errorf("open event log: %w", err)
		}
		l.f = f
	}
	if _, err := l.f.Write(line); err != nil { // one write per line: followers never see half
		return ev, nil, fmt.Errorf("write event log: %w", err)
	}
	l.tokens--
	l.size += int64(len(line))
	close(l.notify)
	l.notify = make(chan struct{})
	return ev, l.derive, nil
}

func (l *eventLog) drop(reason string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dropLocked(reason, err)
}

func (l *eventLog) dropLocked(reason string, err error) {
	l.dropped++
	if !l.warned && l.log != nil {
		l.log.Warn("dropping events", "sandbox", l.sandbox, "reason", reason, "err", err)
		l.warned = true
	}
}

// changed returns a channel closed at the next append, and whether the log is closed.
func (l *eventLog) changed() (<-chan struct{}, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.notify, l.closed
}

// Dropped is the number of events not written (rate, size or schema).
func (l *eventLog) Dropped() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

func (l *eventLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if l.f != nil {
		_ = l.f.Close()
	}
	close(l.notify)
}

// eventLogFor returns the sandbox's live event log, creating one for sandboxes from before a
// qtd restart (it has no writer, but followers still use it to learn about the end).
func (s *Service) eventLogFor(id string) *eventLog {
	if l, ok := s.logs.Load(id); ok {
		return l.(*eventLog)
	}
	l, _ := s.logs.LoadOrStore(id, newEventLog(s.eventsPath(id), id, s.log))
	return l.(*eventLog)
}

func (s *Service) eventsPath(id string) string { return s.reg.workspace(id) + "/events.jsonl" }

// Events implements the Events RPC: the sandbox's event log from the start (or after an
// event id), optionally filtered by kind, optionally following new events until the sandbox
// is removed or the client goes away. Each line is validated again before it is sent.
func (s *Service) Events(req *qtdv1.EventsRequest, stream grpc.ServerStreamingServer[qtdv1.EventsResponse]) error {
	id := req.GetSandboxId()
	if !sandboxIDRe.MatchString(id) {
		return status.Errorf(codes.InvalidArgument, "invalid sandbox id %.64q", id)
	}
	if _, ok := s.reg.get(id); !ok {
		return status.Errorf(codes.NotFound, "no sandbox %s", id)
	}
	kinds := map[events.Kind]bool{}
	for _, k := range req.GetKinds() {
		known := false
		for _, kk := range events.Kinds {
			known = known || string(kk) == k
		}
		if !known {
			return status.Errorf(codes.InvalidArgument, "unknown event kind %.32q", k)
		}
		kinds[events.Kind(k)] = true
	}
	after := req.GetAfterEventId()
	l := s.eventLogFor(id)
	ctx := stream.Context()

	var f *os.File
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	var r *bufio.Reader
	var partial []byte
	found := after == ""
	for {
		changed, closed := l.changed()
		if f == nil {
			var err error
			if f, err = os.Open(s.eventsPath(id)); err == nil {
				r = bufio.NewReaderSize(f, 64<<10)
			} else if !errors.Is(err, os.ErrNotExist) {
				return status.Errorf(codes.Internal, "open events: %v", err)
			}
		}
		if r != nil {
			for {
				chunk, err := r.ReadBytes('\n')
				partial = append(partial, chunk...)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return status.Errorf(codes.Internal, "read events: %v", err)
				}
				line := bytes.TrimSuffix(partial, []byte{'\n'})
				partial = nil
				ev, err := events.Validate(line)
				if err != nil {
					s.log.Error("invalid line in event log", "sandbox", id, "err", err)
					continue
				}
				if !found {
					found = ev.ID == after
					continue
				}
				if len(kinds) > 0 && !kinds[ev.Kind] {
					continue
				}
				if err := stream.Send(&qtdv1.EventsResponse{Id: ev.ID, Kind: string(ev.Kind), EventJson: bytes.Clone(line)}); err != nil {
					return err
				}
			}
			if len(partial) > 1<<20 { // can't happen with our writer; don't grow forever
				partial = nil
			}
		}
		if !found {
			return status.Errorf(codes.NotFound, "no event %.64q in sandbox %s", after, id)
		}
		if !req.GetFollow() || closed {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		case <-time.After(time.Second): // events written by another qtd process, or the file appeared
		}
	}
}
