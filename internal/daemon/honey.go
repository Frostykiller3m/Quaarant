package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/honeytoken"
)

func (s *Service) honeyPath(id string) string {
	return filepath.Join(s.reg.workspace(id), "honeytokens.json")
}

// honeySet is sandbox id's planted honeytokens, or nil.
func (s *Service) honeySet(id string) *honeytoken.Set {
	if v, ok := s.honey.Load(id); ok {
		return v.(*honeytoken.Set)
	}
	return nil
}

// newHoneytokens generates sandbox id's tokens under home and records them (before the link
// is attached: its proxy and resolver watch for them).
func (s *Service) newHoneytokens(id, home string) (*honeytoken.Set, error) {
	set, err := honeytoken.Generate(home)
	if err != nil {
		return nil, err
	}
	if err := set.Save(s.honeyPath(id)); err != nil {
		return nil, err
	}
	s.useHoneytokens(id, set)
	return set, nil
}

func (s *Service) useHoneytokens(id string, set *honeytoken.Set) {
	s.honey.Store(id, set)
	s.eventLogFor(id).setDerive(honeyReads(set))
}

// plantHoneytokens copies the tokens into the running sandbox as its user.
func plantHoneytokens(ctx context.Context, be backend.Backend, id string, set *honeytoken.Set) error {
	r, err := set.Tar()
	if err != nil {
		return err
	}
	if err := be.CopyIn(ctx, id, set.Home, r); err != nil {
		return fmt.Errorf("plant honeytokens in %s: %w", set.Home, err)
	}
	return nil
}

// loadHoneytokens restores the sets of sandboxes that survived a qtd restart.
func (s *Service) loadHoneytokens() {
	for _, rec := range s.reg.list() {
		set, err := honeytoken.Load(s.honeyPath(rec.ID))
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			s.log.Error("honeytokens not restored", "id", rec.ID, "err", err)
		default:
			s.useHoneytokens(rec.ID, set)
		}
	}
}

// honeyReads turns opens of a planted file into honeytoken read events (once per token and
// process), keeping the source of the file event: host for gvisor, a guest claim for vm.
func honeyReads(set *honeytoken.Set) func(events.Event) []derived {
	var mu sync.Mutex
	seen := map[string]bool{}
	return func(ev events.Event) []derived {
		if ev.Kind != events.KindFile {
			return nil
		}
		var f events.File
		if json.Unmarshal(ev.Data, &f) != nil || f.Op != "open" {
			return nil
		}
		tok, ok := set.ByPath(f.Path)
		if !ok {
			return nil
		}
		key := fmt.Sprintf("%s/%d", tok.ID, f.PID)
		mu.Lock()
		defer mu.Unlock()
		if seen[key] || len(seen) > 4096 {
			return nil
		}
		seen[key] = true
		return []derived{{src: ev.Source, p: events.Honeytoken{
			TokenID: tok.ID, TokenKind: tok.Kind, Trigger: "read", Path: f.Path, PID: f.PID, RelatedEvent: ev.ID,
		}}}
	}
}

// hideHoneytokens drops the planted files (while unchanged) and the directories made for them
// from a diff: they are qtd's, not the sandbox's.
func hideHoneytokens(set *honeytoken.Set, changes []backend.Change) []backend.Change {
	if set == nil {
		return changes
	}
	dirs := map[string]bool{}
	for _, d := range set.Dirs {
		dirs[d] = true
	}
	out := changes[:0]
	for _, c := range changes {
		if tok, ok := set.ByPath(c.Path); ok && c.Kind == backend.Added && c.SHA256 == tok.SHA256 {
			continue
		}
		if dirs[c.Path] && c.Kind == backend.Added && c.Mode.IsDir() {
			continue
		}
		out = append(out, c)
	}
	return out
}
