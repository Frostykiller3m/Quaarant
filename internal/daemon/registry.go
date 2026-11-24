package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
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
	Net       *netRecord        `json:"net,omitempty"`       // nil: --net=none
	ParentID  string            `json:"parent_id,omitempty"` // restored or forked from this sandbox
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
