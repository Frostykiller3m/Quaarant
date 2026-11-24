// Package agentproto is the protocol between qtd and qt-agent inside a microVM, over vsock.
//
// qtd opens one vsock connection per operation (agent port Port). Everything is a frame:
// one type byte, a 4-byte big-endian length, then the payload (at most MaxFrame bytes).
// The first frame from qtd is a Request (JSON). Then, depending on the operation:
//
//	exec:     qtd -> Stdin*, CloseStdin, Resize, Signal      agent -> Started, Stdout*, Stderr*, Exit
//	copy_in:  qtd -> Data*, EOF                              agent -> Result | Error
//	copy_out:                                                agent -> Data*, EOF | Error
//	ping:                                                    agent -> Result
//
// The agent runs inside the guest: once guest code has run, nothing it sends can be trusted.
// qtd bounds every frame, rejects unknown types, and never acts on what it is told. Only the
// standard library is used here (qt-agent links it).
package agentproto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Port is the vsock port qt-agent listens on.
const Port = 1024

// MaxFrame bounds one frame's payload.
const MaxFrame = 1 << 20

// FrameType identifies a frame.
type FrameType byte

// Frame types. Values are part of the protocol: never renumber.
const (
	// qtd -> agent
	FrameRequest    FrameType = 1 // JSON Request, always first
	FrameStdin      FrameType = 2 // raw bytes
	FrameCloseStdin FrameType = 3 // empty
	FrameResize     FrameType = 4 // JSON WindowSize
	FrameSignal     FrameType = 5 // JSON Signal
	// both directions
	FrameData FrameType = 6 // raw tar bytes (copy_in from qtd, copy_out from the agent)
	FrameEOF  FrameType = 7 // end of a Data stream
	// agent -> qtd
	FrameStarted FrameType = 16 // JSON Started
	FrameStdout  FrameType = 17 // raw bytes
	FrameStderr  FrameType = 18 // raw bytes
	FrameExit    FrameType = 19 // JSON Exit
	FrameError   FrameType = 20 // JSON Error
	FrameResult  FrameType = 21 // JSON Result
)

// Ops.
const (
	OpPing    = "ping"
	OpExec    = "exec"
	OpCopyIn  = "copy_in"
	OpCopyOut = "copy_out"
	// OpConfigure gives a VM restored from a golden snapshot its own identity.
	OpConfigure = "configure"
)

// Request starts an operation.
type Request struct {
	Op   string `json:"op"`
	Exec *Exec  `json:"exec,omitempty"`
	Path string `json:"path,omitempty"` // copy_in: destination dir; copy_out: what to archive
	UID  uint32 `json:"uid,omitempty"`  // copy_in: owner of the extracted files
	GID  uint32 `json:"gid,omitempty"`

	Configure *Configure `json:"configure,omitempty"`
}

// Configure is sent once after a snapshot restore: the snapshot is shared by every sandbox
// restored from it, so hostname, clock and randomness must be made the sandbox's own.
type Configure struct {
	Hostname string `json:"hostname"`
	UnixNano int64  `json:"unix_nano"` // host wall clock
	Entropy  []byte `json:"entropy"`   // mixed into /dev/urandom (the kernel also reseeds on VMGenID)
}

// Exec describes a process. The agent drops to UID/GID with no capabilities, no_new_privs,
// RLIMIT_NPROC=NProc and qt's seccomp filter before it runs Argv.
type Exec struct {
	Argv  []string `json:"argv"`
	Env   []string `json:"env,omitempty"`
	Cwd   string   `json:"cwd,omitempty"`
	UID   uint32   `json:"uid"`
	GID   uint32   `json:"gid"`
	NProc uint64   `json:"nproc"`
	TTY   bool     `json:"tty,omitempty"`
	Rows  uint16   `json:"rows,omitempty"`
	Cols  uint16   `json:"cols,omitempty"`
}

// WindowSize is a terminal size.
type WindowSize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// Signal asks the agent to signal the exec'd process.
type Signal struct {
	Signal int `json:"signal"`
}

// Started reports the guest pid of an exec'd process.
type Started struct {
	PID int `json:"pid"`
}

// Exit is how an exec'd process ended.
type Exit struct {
	Code   int `json:"code"`   // -1 if killed by a signal
	Signal int `json:"signal"` // 0 unless killed by a signal
}

// Error reports a failed operation.
type Error struct {
	Message string `json:"message"`
}

// Result ends a successful copy_in or ping.
type Result struct {
	Bytes   int64  `json:"bytes,omitempty"`
	Files   int    `json:"files,omitempty"`
	Version string `json:"version,omitempty"` // ping: agent version
	Kernel  string `json:"kernel,omitempty"`  // ping: guest kernel release
}

// ErrFrameTooLarge is returned by ReadFrame for frames over the limit.
var ErrFrameTooLarge = errors.New("agentproto: frame too large")

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, t FrameType, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	var hdr [5]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload))) //nolint:gosec // G115: bounded above
	if _, err := w.Write(append(hdr[:], payload...)); err != nil {
		return fmt.Errorf("agentproto: write: %w", err)
	}
	return nil
}

// WriteJSON writes a frame with a JSON payload.
func WriteJSON(w io.Writer, t FrameType, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("agentproto: encode: %w", err)
	}
	return WriteFrame(w, t, b)
}

// ReadFrame reads one frame whose payload is at most max bytes (max <= MaxFrame).
func ReadFrame(r io.Reader, max int) (FrameType, []byte, error) {
	if max <= 0 || max > MaxFrame {
		max = MaxFrame
	}
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err // unwrapped: callers test for io.EOF
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > uint32(max) {
		return 0, nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, fmt.Errorf("agentproto: short frame: %w", err)
	}
	return FrameType(hdr[0]), buf, nil
}

// Decode unmarshals a JSON payload strictly.
func Decode(payload []byte, v any) error {
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("agentproto: decode: %w", err)
	}
	return nil
}

// Writer serializes frames from several goroutines (stdout and stderr) onto one connection.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Frame writes one frame.
func (s *Writer) Frame(t FrameType, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return WriteFrame(s.w, t, payload)
}

// JSON writes one JSON frame.
func (s *Writer) JSON(t FrameType, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return WriteJSON(s.w, t, v)
}

// DataWriter returns an io.Writer that sends everything as frames of type t, chunked.
func (s *Writer) DataWriter(t FrameType) io.Writer { return dataWriter{s, t} }

type dataWriter struct {
	s *Writer
	t FrameType
}

func (d dataWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		c := p[:min(len(p), 64<<10)]
		if err := d.s.Frame(d.t, c); err != nil {
			return n, err
		}
		n += len(c)
		p = p[len(c):]
	}
	return n, nil
}

// DataReader reads a stream of Data frames up to EOF from r. An Error frame ends it with
// that error; any other frame type is a protocol error.
func DataReader(r io.Reader) io.Reader { return &dataReader{r: r} }

type dataReader struct {
	r    io.Reader
	buf  []byte
	err  error
	done bool
}

func (d *dataReader) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.done {
			return 0, d.err
		}
		t, b, err := ReadFrame(d.r, MaxFrame)
		if err != nil {
			d.done, d.err = true, fmt.Errorf("agentproto: data stream: %w", err)
			continue
		}
		switch t {
		case FrameData:
			d.buf = b
		case FrameEOF:
			d.done, d.err = true, io.EOF
		case FrameError:
			var e Error
			_ = Decode(b, &e)
			d.done, d.err = true, fmt.Errorf("agent: %.512s", e.Message)
		default:
			d.done, d.err = true, fmt.Errorf("agentproto: unexpected frame %d in data stream", t)
		}
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}
