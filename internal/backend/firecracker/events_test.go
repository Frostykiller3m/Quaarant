package firecracker

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
	"github.com/Frostykiller3m/Quaarant/internal/events"
)

func TestGuestPayload(t *testing.T) {
	tests := []struct {
		name    string
		ev      agentproto.Event
		ok      bool
		notKind bool
	}{
		{"exec", agentproto.Event{Kind: "exec", Data: []byte(`{"pid":5,"ppid":1,"path":"/bin/cat","argv":["cat","/etc/passwd"],"cwd":"/"}`)}, true, false},
		{"file", agentproto.Event{Kind: "file", Data: []byte(`{"op":"write","path":"/tmp/f","pid":5,"bytes":3}`)}, true, false},
		{"guest net claim", agentproto.Event{Kind: "net", Data: []byte(`{"op":"connect","proto":"tcp","dst_ip":"1.2.3.4","dst_port":443}`)}, false, true},
		{"guest dns claim", agentproto.Event{Kind: "dns", Data: []byte(`{"qname":"evil.example","qtype":"A","allowed":true}`)}, false, true},
		{"guest honeytoken claim", agentproto.Event{Kind: "honeytoken", Data: []byte(`{"token_id":"ht_1","token_kind":"ssh_key","trigger":"egress_dns","dst":"x"}`)}, false, true},
		{"policy claim", agentproto.Event{Kind: "policy_denied", Data: []byte(`{}`)}, false, true},
		{"unknown field", agentproto.Event{Kind: "file", Data: []byte(`{"op":"open","path":"/x","source":"host"}`)}, false, false},
		{"garbage", agentproto.Event{Kind: "exec", Data: []byte(`not json`)}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := guestPayload(tt.ev)
			if (err == nil) != tt.ok || errors.Is(err, errNotGuestKind) != tt.notKind {
				t.Fatalf("guestPayload = %v, %v", p, err)
			}
			if !tt.ok {
				return
			}
			// What qtd writes is a valid schema v1 event with source guest.
			e, err := events.New("sb1", events.SourceGuest, timeNow(), p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := events.Validate(mustJSON(t, e)); err != nil {
				t.Errorf("%s: %v", tt.name, err)
			}
		})
	}
}

func timeNow() time.Time { return time.Now() }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
