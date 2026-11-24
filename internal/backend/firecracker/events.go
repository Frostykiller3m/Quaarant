package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// errNotGuestKind: a guest may only claim exec and file activity. Network, DNS, policy and
// honeytoken-egress truth comes from the host side, so such events from an agent are dropped.
var errNotGuestKind = errors.New("event kind not accepted from a guest")

// guestPayload decodes one agent event strictly (unknown fields rejected).
func guestPayload(ev agentproto.Event) (events.Payload, error) {
	var p events.Payload
	switch events.Kind(ev.Kind) {
	case events.KindExec:
		p = &events.Exec{}
	case events.KindFile:
		p = &events.File{}
	default:
		return nil, fmt.Errorf("%w: %.32q", errNotGuestKind, ev.Kind)
	}
	dec := json.NewDecoder(bytes.NewReader(ev.Data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("decode guest %s event: %w", ev.Kind, err)
	}
	switch v := p.(type) {
	case *events.Exec:
		if v.Argv == nil {
			v.Argv = []string{}
		}
		return *v, nil
	case *events.File:
		return *v, nil
	}
	return nil, errNotGuestKind
}

// guestStats counts what a guest's event stream delivered and what qtd refused.
type guestStats struct {
	accepted, rejected atomic.Uint64
}

// subscribeEvents streams the agent's exec/file events into the sandbox's event log as guest
// claims, reconnecting while the VM runs. It stops when stop is closed.
func (b *Backend) subscribeEvents(bx *box) {
	if bx.sink == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.mu.Lock()
	if bx.stopEvents != nil {
		bx.stopEvents()
	}
	bx.stopEvents = cancel
	b.mu.Unlock()
	go func() {
		warned := false
		for ctx.Err() == nil && b.alive(bx) {
			if err := b.streamEvents(ctx, bx); err != nil && ctx.Err() == nil && !warned {
				b.warn("vm event stream", err)
				warned = true
			}
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()
}

func (b *Backend) streamEvents(ctx context.Context, bx *box) error {
	c, err := b.dial(ctx, bx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if err := agentproto.WriteJSON(c, agentproto.FrameRequest, agentproto.Request{Op: agentproto.OpEvents}); err != nil {
		return err
	}
	for {
		t, payload, err := agentproto.ReadFrame(c, agentproto.MaxEvent)
		if err != nil {
			return err
		}
		if t != agentproto.FrameEvent {
			return fmt.Errorf("unexpected frame %d in the event stream", t)
		}
		var ev agentproto.Event
		if err := agentproto.Decode(payload, &ev); err != nil {
			bx.events.rejected.Add(1)
			continue
		}
		p, err := guestPayload(ev)
		if err != nil {
			bx.events.rejected.Add(1)
			if bx.events.rejected.Load() == 1 {
				b.warn("rejected a guest event", err)
			}
			continue
		}
		// The event log validates against the schema (bounds included) and rate-limits.
		if err := bx.sink.Emit(ctx, events.SourceGuest, p); err != nil {
			bx.events.rejected.Add(1)
			continue
		}
		bx.events.accepted.Add(1)
	}
}
