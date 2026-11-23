package events

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// MaxEventBytes bounds a single encoded event (one JSONL line).
const MaxEventBytes = 256 << 10

// SchemaID is the $id of the v1 schema.
const SchemaID = "https://quarantine.dev/schema/events/v1.json"

//go:embed schema/v1.json
var schemaV1 []byte

// SchemaJSON returns the embedded v1 JSON Schema document.
func SchemaJSON() []byte { return bytes.Clone(schemaV1) }

var (
	compileOnce sync.Once
	compiled    *jsonschema.Schema
	compileErr  error
)

func schema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaV1))
		if err != nil {
			compileErr = fmt.Errorf("parse embedded schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if err := c.AddResource(SchemaID, doc); err != nil {
			compileErr = fmt.Errorf("add schema resource: %w", err)
			return
		}
		compiled, compileErr = c.Compile(SchemaID)
		if compileErr != nil {
			compileErr = fmt.Errorf("compile schema: %w", compileErr)
		}
	})
	return compiled, compileErr
}

// ErrTooLarge is returned for events larger than MaxEventBytes.
var ErrTooLarge = errors.New("event exceeds size limit")

// Validate checks one encoded event against the v1 schema and returns it decoded.
// The payload is also decoded into its Go type, so a valid event always has a usable Payload.
func Validate(raw []byte) (Event, error) {
	if len(raw) > MaxEventBytes {
		return Event{}, fmt.Errorf("%w (%d > %d bytes)", ErrTooLarge, len(raw), MaxEventBytes)
	}
	sch, err := schema()
	if err != nil {
		return Event{}, err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return Event{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return Event{}, fmt.Errorf("schema: %w", err)
	}

	var ev Event
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return Event{}, fmt.Errorf("decode event: %w", err)
	}
	if _, err := ev.Payload(); err != nil {
		return Event{}, err
	}
	return ev, nil
}

// LineError is a validation failure at a specific line of a JSONL stream.
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }

func (e *LineError) Unwrap() error { return e.Err }

// ValidateStream validates every line of an events.jsonl stream and calls fn for each valid
// event. Event ids must be unique within the stream (reports cite them as evidence). It stops at
// the first invalid line and returns a *LineError, or the error returned by fn. Blank lines are
// skipped.
func ValidateStream(r io.Reader, fn func(Event) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxEventBytes+1)
	seen := make(map[string]int)
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		ev, err := Validate(b)
		if err != nil {
			return &LineError{Line: line, Err: err}
		}
		if first, dup := seen[ev.ID]; dup {
			return &LineError{Line: line, Err: fmt.Errorf("duplicate event id %s (first on line %d)", ev.ID, first)}
		}
		seen[ev.ID] = line
		if fn != nil {
			if err := fn(ev); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return &LineError{Line: line + 1, Err: ErrTooLarge}
		}
		return fmt.Errorf("read events: %w", err)
	}
	return nil
}
