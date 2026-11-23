package qtdv1_test

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	qtdv1 "github.com/qt-dev/quarantine/internal/api/qtd/v1"
	"github.com/qt-dev/quarantine/internal/backend"
	"github.com/qt-dev/quarantine/internal/events"
)

// TestServiceShape pins the RPC surface and streaming modes so changes are deliberate.
func TestServiceShape(t *testing.T) {
	svc := qtdv1.File_qtd_v1_qtd_proto.Services().ByName("SandboxService")
	if svc == nil {
		t.Fatal("SandboxService not found")
	}
	want := map[string][2]bool{ // name -> {client streams, server streams}
		"Create":   {false, false},
		"Exec":     {true, true},
		"CopyIn":   {true, false},
		"CopyOut":  {false, true},
		"Diff":     {false, false},
		"Events":   {false, true},
		"Snapshot": {false, false},
		"Fork":     {false, false},
		"Destroy":  {false, false},
		"List":     {false, false},
	}
	methods := svc.Methods()
	if methods.Len() != len(want) {
		t.Errorf("service has %d methods, want %d", methods.Len(), len(want))
	}
	for name, modes := range want {
		m := methods.ByName(protoreflect.Name(name))
		if m == nil {
			t.Errorf("missing rpc %s", name)
			continue
		}
		if m.IsStreamingClient() != modes[0] || m.IsStreamingServer() != modes[1] {
			t.Errorf("%s: client streaming=%v server streaming=%v, want %v",
				name, m.IsStreamingClient(), m.IsStreamingServer(), modes)
		}
	}
}

// TestCapabilitiesMirrorBackend keeps the proto enum in step with backend.Capabilities.
func TestCapabilitiesMirrorBackend(t *testing.T) {
	enum := qtdv1.Capability(0).Descriptor().Values()
	var caps backend.Capabilities
	for i := 0; i < 32; i++ {
		caps |= 1 << i
	}
	names := caps.Names()
	known := 0
	for _, n := range names {
		if n[0] != '0' { // skip the "0x..." unknown-bits entry
			known++
		}
	}
	if got := enum.Len() - 1; got != known { // minus UNSPECIFIED
		t.Fatalf("proto has %d capabilities, backend has %d (%v)", got, known, names)
	}
}

// TestEventsResponseCarriesSchemaJSON checks an example event survives the proto round trip
// byte for byte and still validates.
func TestEventsResponseCarriesSchemaJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "events", "examples", "honeytoken_egress.json"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := events.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	in := &qtdv1.EventsResponse{Id: ev.ID, Kind: string(ev.Kind), EventJson: raw}
	wire, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out qtdv1.EventsResponse
	if err := proto.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := events.Validate(out.GetEventJson()); err != nil {
		t.Fatalf("event no longer valid after round trip: %v", err)
	}
	if _, err := protojson.Marshal(&out); err != nil {
		t.Fatal(err)
	}
}
