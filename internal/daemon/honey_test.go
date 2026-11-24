package daemon

import (
	"encoding/json"
	"io/fs"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/honeytoken"
)

func TestHoneyReads(t *testing.T) {
	set, err := honeytoken.Generate("/home/app")
	if err != nil {
		t.Fatal(err)
	}
	derive := honeyReads(set)
	fileEv := func(src events.Source, op, path string, pid int) events.Event {
		e, err := events.New("sb", src, time.Now(), events.File{Op: op, Path: path, PID: pid})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	aws := "/home/app/.aws/credentials"
	open := fileEv(events.SourceGuest, "open", aws, 42)
	got := derive(open)
	if len(got) != 1 || got[0].src != events.SourceGuest {
		t.Fatalf("derive(open) = %+v", got)
	}
	h := got[0].p.(events.Honeytoken)
	if h.Trigger != "read" || h.TokenKind != honeytoken.KindAWS || h.Path != aws || h.PID != 42 || h.RelatedEvent != open.ID {
		t.Errorf("%+v", h)
	}
	// The derived event is valid for the schema with the triggering event's source.
	e, err := events.New("sb", got[0].src, time.Now(), h)
	if err == nil {
		raw, _ := json.Marshal(e)
		_, err = events.Validate(raw)
	}
	if err != nil {
		t.Errorf("derived event: %v", err)
	}
	for name, ev := range map[string]events.Event{
		"same process again": fileEv(events.SourceGuest, "open", aws, 42),
		"not a token":        fileEv(events.SourceHost, "open", "/etc/passwd", 7),
		"not an open":        fileEv(events.SourceHost, "unlink", aws, 7),
	} {
		if got := derive(ev); len(got) != 0 {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if got := derive(fileEv(events.SourceHost, "open", aws, 43)); len(got) != 1 {
		t.Error("another process reading the token is another event")
	}
}

func TestHideHoneytokens(t *testing.T) {
	set, _ := honeytoken.Generate("/tmp")
	aws := set.Tokens[1]
	changes := []backend.Change{
		{Path: "/tmp/.aws", Kind: backend.Added, Mode: fs.ModeDir | 0o700},
		{Path: aws.Path, Kind: backend.Added, Mode: 0o600, SHA256: aws.SHA256},
		{Path: "/tmp/.ssh/id_ed25519", Kind: backend.Added, Mode: 0o600, SHA256: "changed"},
		{Path: "/tmp/payload", Kind: backend.Added, Mode: 0o755, SHA256: "x"},
	}
	out := hideHoneytokens(set, changes)
	if len(out) != 2 || out[0].Path != "/tmp/.ssh/id_ed25519" || out[1].Path != "/tmp/payload" {
		t.Errorf("hideHoneytokens = %+v", out)
	}
	if got := hideHoneytokens(nil, []backend.Change{{Path: "/x"}}); len(got) != 1 {
		t.Error("nil set")
	}
}
