// Package events defines the versioned event format written to each sandbox's events.jsonl.
//
// The JSON Schema in schema/v1.json is the source of truth; the Go types below mirror it and a
// test keeps the two in sync. Events may carry data produced by untrusted code (anything with
// Source == SourceGuest, and every string that names a path, argv or hostname): never act on
// event contents, and escape them before showing them to a model.
package events

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion is the event schema major version written in every event's "v" field.
const SchemaVersion = 1

// Kind is the event type.
type Kind string

// Event kinds.
const (
	KindExec         Kind = "exec"
	KindFile         Kind = "file"
	KindNet          Kind = "net"
	KindDNS          Kind = "dns"
	KindPolicyDenied Kind = "policy_denied"
	KindHoneytoken   Kind = "honeytoken"
)

// Kinds lists every event kind in schema order.
var Kinds = []Kind{KindExec, KindFile, KindNet, KindDNS, KindPolicyDenied, KindHoneytoken}

// Source says who observed an event.
type Source string

const (
	// SourceHost events were observed by qtd on the host (trusted).
	SourceHost Source = "host"
	// SourceGuest events are claims made from inside the sandbox (untrusted).
	SourceGuest Source = "guest"
)

// Event is one line of events.jsonl.
type Event struct {
	V       int             `json:"v"`
	ID      string          `json:"id"`
	TS      time.Time       `json:"ts"`
	Sandbox string          `json:"sandbox"`
	Kind    Kind            `json:"kind"`
	Source  Source          `json:"source"`
	Data    json.RawMessage `json:"data"`
}

// Payload is the kind-specific body of an event.
type Payload interface {
	Kind() Kind
}

// Exec is a process execution (execve).
type Exec struct {
	PID           int      `json:"pid"`
	PPID          int      `json:"ppid"`
	UID           *uint32  `json:"uid,omitempty"`
	Path          string   `json:"path"`
	Argv          []string `json:"argv"`
	ArgvTruncated bool     `json:"argv_truncated,omitempty"`
	Cwd           string   `json:"cwd,omitempty"`
	ExitCode      *int     `json:"exit_code,omitempty"`
	SHA256        string   `json:"sha256,omitempty"` // of the executed binary
}

// File is a filesystem operation.
type File struct {
	Op      string   `json:"op"`
	Path    string   `json:"path"`
	NewPath string   `json:"new_path,omitempty"`
	PID     int      `json:"pid,omitempty"`
	Flags   []string `json:"flags,omitempty"`
	Mode    string   `json:"mode,omitempty"`
	Bytes   *int64   `json:"bytes,omitempty"`
	Errno   string   `json:"errno,omitempty"` // set when the operation failed, e.g. EACCES
}

// Net is a network connection, always observed on the host.
type Net struct {
	Op         string `json:"op"`
	Proto      string `json:"proto"`
	SrcIP      string `json:"src_ip,omitempty"`
	SrcPort    int    `json:"src_port,omitempty"`
	DstIP      string `json:"dst_ip"`
	DstPort    int    `json:"dst_port"`
	SNI        string `json:"sni,omitempty"`
	HTTPHost   string `json:"http_host,omitempty"`
	Allowed    *bool  `json:"allowed,omitempty"`
	BytesOut   *int64 `json:"bytes_out,omitempty"`
	BytesIn    *int64 `json:"bytes_in,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
	Errno      string `json:"errno,omitempty"` // set when the connection failed
}

// DNS is a query answered (or refused) by the per-sandbox resolver.
type DNS struct {
	QName   string   `json:"qname"`
	QType   string   `json:"qtype"`
	Allowed bool     `json:"allowed"`
	RCode   string   `json:"rcode,omitempty"`
	Answers []string `json:"answers,omitempty"`
	TTL     *int     `json:"ttl,omitempty"`
}

// PolicyDenied records something the host-side policy blocked.
type PolicyDenied struct {
	Policy string `json:"policy"`
	Target string `json:"target"`
	Reason string `json:"reason"`
	Rule   string `json:"rule,omitempty"`
}

// Honeytoken records a planted credential being read or leaving the sandbox.
type Honeytoken struct {
	TokenID      string `json:"token_id"`
	TokenKind    string `json:"token_kind"`
	Trigger      string `json:"trigger"`
	Path         string `json:"path,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Dst          string `json:"dst,omitempty"`
	RelatedEvent string `json:"related_event,omitempty"`
}

// Kind implements Payload.
func (Exec) Kind() Kind { return KindExec }

// Kind implements Payload.
func (File) Kind() Kind { return KindFile }

// Kind implements Payload.
func (Net) Kind() Kind { return KindNet }

// Kind implements Payload.
func (DNS) Kind() Kind { return KindDNS }

// Kind implements Payload.
func (PolicyDenied) Kind() Kind { return KindPolicyDenied }

// Kind implements Payload.
func (Honeytoken) Kind() Kind { return KindHoneytoken }

// IsRedFlag reports whether a honeytoken event means the token left the sandbox.
func (h Honeytoken) IsRedFlag() bool { return h.Trigger != "read" }

// NewID returns a fresh random event id ("ev_" + 32 hex chars).
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("events: crypto/rand failed: %v", err)) // never happens on supported platforms
	}
	return "ev_" + hex.EncodeToString(b[:])
}

// New builds an event around a payload. It does not validate; call Validate on the encoded
// event (or use a Writer, M1-T3) before trusting it.
func New(sandbox string, src Source, ts time.Time, p Payload) (Event, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return Event{}, fmt.Errorf("marshal %s payload: %w", p.Kind(), err)
	}
	return Event{
		V:       SchemaVersion,
		ID:      NewID(),
		TS:      ts.UTC(),
		Sandbox: sandbox,
		Kind:    p.Kind(),
		Source:  src,
		Data:    data,
	}, nil
}

// Payload decodes the kind-specific body, rejecting unknown fields.
func (e Event) Payload() (Payload, error) {
	var p Payload
	switch e.Kind {
	case KindExec:
		p = &Exec{}
	case KindFile:
		p = &File{}
	case KindNet:
		p = &Net{}
	case KindDNS:
		p = &DNS{}
	case KindPolicyDenied:
		p = &PolicyDenied{}
	case KindHoneytoken:
		p = &Honeytoken{}
	default:
		return nil, fmt.Errorf("unknown event kind %q", e.Kind)
	}
	dec := json.NewDecoder(bytes.NewReader(e.Data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", e.Kind, err)
	}
	return p, nil
}
