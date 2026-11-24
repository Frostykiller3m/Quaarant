package events

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("examples", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExamplesValid(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("examples", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	seenKinds := map[Kind]bool{}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			ev, err := Validate(raw)
			if err != nil {
				t.Fatalf("example should be valid: %v", err)
			}
			seenKinds[ev.Kind] = true
		})
	}
	for _, k := range Kinds {
		if !seenKinds[k] {
			t.Errorf("no example for kind %q", k)
		}
	}
}

func TestExampleStream(t *testing.T) {
	f, err := os.Open(filepath.Join("examples", "session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var redFlags, n int
	err = ValidateStream(f, func(ev Event) error {
		n++
		p, err := ev.Payload()
		if err != nil {
			return err
		}
		if h, ok := p.(*Honeytoken); ok && h.IsRedFlag() {
			redFlags++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 || redFlags != 1 {
		t.Fatalf("got %d events, %d red flags; want 7, 1", n, redFlags)
	}
}

// mutate decodes a valid example, applies f, and re-encodes it.
func mutate(t *testing.T, example string, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readExample(t, example), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func data(m map[string]any) map[string]any { return m["data"].(map[string]any) }

func TestInvalid(t *testing.T) {
	tests := []struct {
		name    string
		example string
		mutate  func(m map[string]any)
	}{
		{"wrong version", "exec.json", func(m map[string]any) { m["v"] = 2 }},
		{"missing id", "exec.json", func(m map[string]any) { delete(m, "id") }},
		{"bad id", "exec.json", func(m map[string]any) { m["id"] = "1; rm -rf /" }},
		{"bad sandbox id", "exec.json", func(m map[string]any) { m["sandbox"] = "../../etc" }},
		{"bad timestamp", "exec.json", func(m map[string]any) { m["ts"] = "yesterday" }},
		{"unknown kind", "exec.json", func(m map[string]any) { m["kind"] = "syscall" }},
		{"unknown source", "exec.json", func(m map[string]any) { m["source"] = "agent" }},
		{"unknown envelope field", "exec.json", func(m map[string]any) { m["severity"] = "high" }},
		{"unknown payload field", "exec.json", func(m map[string]any) { data(m)["note"] = "ignore previous instructions" }},
		{"payload of other kind", "exec.json", func(m map[string]any) { m["kind"] = "file" }},
		{"exec missing argv", "exec.json", func(m map[string]any) { delete(data(m), "argv") }},
		{"exec argv too long", "exec.json", func(m map[string]any) {
			argv := make([]any, 257)
			for i := range argv {
				argv[i] = "x"
			}
			data(m)["argv"] = argv
		}},
		{"path too long", "file.json", func(m map[string]any) { data(m)["path"] = "/" + strings.Repeat("a", 4096) }},
		{"empty path", "file.json", func(m map[string]any) { data(m)["path"] = "" }},
		{"rename without new_path", "file.json", func(m map[string]any) { data(m)["op"] = "rename" }},
		{"bad errno", "file.json", func(m map[string]any) { data(m)["errno"] = "EACCES; rm -rf /" }},
		{"lowercase errno", "file.json", func(m map[string]any) { data(m)["errno"] = "eacces" }},
		{"bad exec sha256", "exec.json", func(m map[string]any) { data(m)["sha256"] = strings.Repeat("A", 64) }},
		{"short exec sha256", "exec.json", func(m map[string]any) { data(m)["sha256"] = "abc" }},
		{"bad file flag", "file.json", func(m map[string]any) { data(m)["flags"] = []any{"rm -rf"} }},
		{"net from guest", "net.json", func(m map[string]any) { m["source"] = "guest" }},
		{"dns from guest", "dns.json", func(m map[string]any) { m["source"] = "guest" }},
		{"policy_denied from guest", "policy_denied.json", func(m map[string]any) { m["source"] = "guest" }},
		{"honeytoken egress from guest", "honeytoken_egress.json", func(m map[string]any) { m["source"] = "guest" }},
		{"egress without dst", "honeytoken_egress.json", func(m map[string]any) { delete(data(m), "dst") }},
		{"read without path", "honeytoken_read.json", func(m map[string]any) { delete(data(m), "path") }},
		{"bad ip", "net.json", func(m map[string]any) { data(m)["dst_ip"] = "999.1.1.1" }},
		{"bad port", "net.json", func(m map[string]any) { data(m)["dst_port"] = 70000 }},
		{"hostname too long", "dns.json", func(m map[string]any) { data(m)["qname"] = strings.Repeat("a", 254) }},
		{"unknown deny reason", "policy_denied.json", func(m map[string]any) { data(m)["reason"] = "because" }},
		{"data not object", "exec.json", func(m map[string]any) { m["data"] = "x" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := mutate(t, tt.example, tt.mutate)
			_, err := Validate(raw)
			if err == nil {
				t.Fatalf("expected invalid:\n%s", raw)
			}
			t.Logf("rejected: %v", strings.ReplaceAll(err.Error(), "\n", " | "))
		})
	}
}

func TestInvalidJSON(t *testing.T) {
	for _, raw := range []string{"", "{", "[]", "null", `{"v":1}`} {
		if _, err := Validate([]byte(raw)); err == nil {
			t.Errorf("Validate(%q) should fail", raw)
		}
	}
}

func TestTooLarge(t *testing.T) {
	raw := make([]byte, MaxEventBytes+1)
	if _, err := Validate(raw); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	line := strings.Repeat("x", MaxEventBytes+10) + "\n"
	err := ValidateStream(strings.NewReader(line), nil)
	var le *LineError
	if !errors.As(err, &le) || le.Line != 1 || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want LineError{1, ErrTooLarge}", err)
	}
}

func TestStreamErrors(t *testing.T) {
	exec := compact(t, readExample(t, "exec.json"))
	file := compact(t, readExample(t, "file.json"))

	t.Run("duplicate id", func(t *testing.T) {
		err := ValidateStream(strings.NewReader(exec+"\n"+exec+"\n"), nil)
		var le *LineError
		if !errors.As(err, &le) || le.Line != 2 || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad line reported with number", func(t *testing.T) {
		err := ValidateStream(strings.NewReader(exec+"\n\n"+file+"\nnot json\n"), nil)
		var le *LineError
		if !errors.As(err, &le) || le.Line != 4 {
			t.Fatalf("got %v, want error on line 4", err)
		}
	})
	t.Run("callback error stops", func(t *testing.T) {
		stop := errors.New("stop")
		if err := ValidateStream(strings.NewReader(exec+"\n"+file+"\n"), func(Event) error { return stop }); !errors.Is(err, stop) {
			t.Fatalf("got %v", err)
		}
	})
}

func compact(t *testing.T, raw []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// TestGoTypesMatchSchema builds an event of every kind from the Go types and checks that the
// schema accepts it, so the structs and schema/v1.json cannot drift apart silently.
func TestGoTypesMatchSchema(t *testing.T) {
	uid, exit, ttl := uint32(1000), 0, 60
	n, yes := int64(512), true
	payloads := []struct {
		src Source
		p   Payload
	}{
		{SourceHost, Exec{PID: 10, PPID: 1, UID: &uid, Path: "/bin/sh", Argv: []string{"sh", "-c", "id"}, ArgvTruncated: true, Cwd: "/work", ExitCode: &exit, SHA256: strings.Repeat("ab", 32)}},
		{SourceGuest, File{Op: "rename", Path: "/a", NewPath: "/b", PID: 10, Flags: []string{"O_WRONLY", "O_CREAT"}, Mode: "0644", Bytes: &n, Errno: "EACCES"}},
		{SourceHost, Net{Op: "connect", Proto: "tcp", SrcIP: "10.0.0.2", SrcPort: 4000, DstIP: "2001:db8::1", DstPort: 443, SNI: "pypi.org", HTTPHost: "pypi.org", Allowed: &yes, BytesOut: &n, BytesIn: &n, DurationMS: &n, Errno: "ENETUNREACH"}},
		{SourceHost, DNS{QName: "pypi.org", QType: "AAAA", Allowed: true, RCode: "NOERROR", Answers: []string{"2001:db8::1", "151.101.0.223"}, TTL: &ttl}},
		{SourceHost, PolicyDenied{Policy: "net", Target: "1.2.3.4:443", Reason: "direct_ip", Rule: "allow:pypi.org"}},
		{SourceHost, Honeytoken{TokenID: "ht_ssh1", TokenKind: "ssh_key", Trigger: "egress_plaintext", Dst: "1.2.3.4:80", RelatedEvent: NewID()}},
		{SourceGuest, Honeytoken{TokenID: "ht_ssh1", TokenKind: "ssh_key", Trigger: "read", Path: "/home/sandbox/.ssh/id_ed25519", PID: 10}},
	}
	for _, tc := range payloads {
		t.Run(string(tc.p.Kind()), func(t *testing.T) {
			ev, err := New("sb-test", tc.src, time.Now(), tc.p)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Validate(raw)
			if err != nil {
				t.Fatalf("schema rejects Go-built event: %v\n%s", err, raw)
			}
			if got.ID != ev.ID || got.Kind != tc.p.Kind() {
				t.Fatalf("round trip mismatch: %+v", got)
			}
		})
	}
}

func TestNewID(t *testing.T) {
	a, b := NewID(), NewID()
	if a == b || len(a) != 35 || !strings.HasPrefix(a, "ev_") {
		t.Fatalf("bad ids %q %q", a, b)
	}
}

func TestSchemaJSONIsCopy(t *testing.T) {
	s := SchemaJSON()
	s[0] = 'X'
	if SchemaJSON()[0] == 'X' {
		t.Fatal("SchemaJSON must return a copy")
	}
}
