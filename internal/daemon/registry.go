package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
)

var sandboxIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// record is what qtd knows about a sandbox; it is persisted as sandboxes/<id>/meta.json.
type record struct {
	ID        string            `json:"id"`
	Image     string            `json:"image"`
	Requested string            `json:"requested_image"`
	Isolation backend.Isolation `json:"isolation"`
	CreatedAt time.Time         `json:"created_at"`
	Limits    backend.Limits    `json:"limits"`
	User      string            `json:"user"`
	Workdir   string            `json:"workdir"`
	Env       []string          `json:"env"`
	Hostname  string            `json:"hostname"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type registry struct {
	dir  string // <data>/sandboxes
	mu   sync.Mutex
	recs map[string]*record
}

func newRegistry(dir string) (*registry, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandboxes dir: %w", err)
	}
	r := &registry{dir: dir, recs: map[string]*record{}}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read sandboxes dir: %w", err)
	}
	for _, de := range des {
		if !de.IsDir() || !sandboxIDRe.MatchString(de.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, de.Name(), "meta.json")) //nolint:gosec // G304: name matched sandboxIDRe
		if err != nil {
			continue // half-created sandbox; `qt rm` still cleans it up
		}
		var rec record
		if err := json.Unmarshal(raw, &rec); err != nil || rec.ID != de.Name() {
			continue
		}
		r.recs[rec.ID] = &rec
	}
	return r, nil
}

func (r *registry) workspace(id string) string { return filepath.Join(r.dir, id) }

func (r *registry) save(rec *record) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode meta: %w", err)
	}
	tmp := filepath.Join(r.workspace(rec.ID), ".meta.json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(r.workspace(rec.ID), "meta.json")); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	r.mu.Lock()
	r.recs[rec.ID] = rec
	r.mu.Unlock()
	return nil
}

func (r *registry) get(id string) (*record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.recs[id]
	return rec, ok
}

func (r *registry) remove(id string) {
	r.mu.Lock()
	delete(r.recs, id)
	r.mu.Unlock()
}

func (r *registry) list() []*record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*record, 0, len(r.recs))
	for _, rec := range r.recs {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// eventLog appends schema-valid events to sandboxes/<id>/events.jsonl. M1-T3 adds the runtime
// monitoring feed and followers; for now only backends emit through it.
type eventLog struct {
	mu      sync.Mutex
	path    string
	sandbox string
}

func (l *eventLog) Emit(_ context.Context, src events.Source, p events.Payload) error {
	ev, err := events.New(l.sandbox, src, time.Now().UTC(), p)
	if err != nil {
		return fmt.Errorf("build event: %w", err)
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	if _, err := events.Validate(line); err != nil {
		return fmt.Errorf("event fails the schema: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	_, werr := f.Write(append(line, '\n'))
	cerr := f.Close()
	return errors.Join(werr, cerr)
}
