//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
)

// Event payloads, with the field names of the event schema (internal/events/schema/v1.json).
// The agent can't import internal/events (it links a JSON Schema library); qtd decodes
// these strictly into its own types and validates them.
type execEvent struct {
	PID           int      `json:"pid"`
	PPID          int      `json:"ppid"`
	UID           *uint32  `json:"uid,omitempty"`
	Path          string   `json:"path"`
	Argv          []string `json:"argv"`
	ArgvTruncated bool     `json:"argv_truncated,omitempty"`
	Cwd           string   `json:"cwd,omitempty"`
}

type fileEvent struct {
	Op      string `json:"op"`
	Path    string `json:"path"`
	NewPath string `json:"new_path,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Bytes   *int64 `json:"bytes,omitempty"`
}

const (
	ringSize   = 8192 // events kept while qtd is not listening
	maxPathLen = 4096
	maxArgs    = 256
	maxArgLen  = 4096
)

// collector buffers events until qtd subscribes, then streams them. Its own process (serve)
// and init are never reported: their file activity (copy in/out) is qt's, not the sandbox's.
type collector struct {
	mu        sync.Mutex
	ring      []agentproto.Event
	sub       chan agentproto.Event
	dropped   uint64
	self      map[int]bool
	parents   map[int]int    // child -> parent (proc connector fork events)
	execPaths map[int]string // pid -> binary opened for exec (fanotify)
	paused    bool           // qt is walking the filesystem (manifest): drop file events
}

func (c *collector) pause(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paused = on
}

func newCollector() *collector {
	return &collector{self: map[int]bool{1: true, os.Getpid(): true}}
}

func (c *collector) ignored(pid int) bool { return c.self[pid] }

func (c *collector) emit(kind string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	ev := agentproto.Event{Kind: kind, Data: b}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused && kind == "file" {
		return
	}
	if c.sub != nil {
		select {
		case c.sub <- ev:
		default:
			c.dropped++ // qtd is too slow; never block the collectors
		}
		return
	}
	if len(c.ring) >= ringSize {
		c.ring = c.ring[1:]
		c.dropped++
	}
	c.ring = append(c.ring, ev)
}

// subscribe returns the buffered events and a channel of new ones; a new subscriber replaces
// the old one (qtd reconnected).
func (c *collector) subscribe() ([]agentproto.Event, chan agentproto.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sub != nil {
		close(c.sub)
	}
	backlog := c.ring
	c.ring = nil
	c.sub = make(chan agentproto.Event, 4096)
	return backlog, c.sub
}

func (c *collector) unsubscribe(ch chan agentproto.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sub == ch {
		close(c.sub)
		c.sub = nil
	}
}

// reset forgets everything buffered: after a snapshot restore, the golden VM's boot is not
// this sandbox's activity.
func (c *collector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ring = nil
}

// streamEvents serves one "events" subscription until the connection breaks.
func (c *collector) streamEvents(w *agentproto.Writer) {
	backlog, ch := c.subscribe()
	defer c.unsubscribe(ch)
	for _, ev := range backlog {
		if w.JSON(agentproto.FrameEvent, ev) != nil {
			return
		}
	}
	for ev := range ch {
		if w.JSON(agentproto.FrameEvent, ev) != nil {
			return
		}
	}
}

func boundPath(p string) string {
	p = strings.ReplaceAll(p, "\x00", "")
	return truncate(p, maxPathLen)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 { // don't split a UTF-8 sequence
		n--
	}
	return s[:n]
}

func modeString(m os.FileMode) string {
	v := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		v |= 0o1000
	}
	return fmt.Sprintf("0%03o", v)
}
