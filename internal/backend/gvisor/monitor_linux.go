//go:build linux

package gvisor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	pb "github.com/Frostykiller3m/Quaarant/internal/gvisorpb"
)

const (
	monitorSocket   = "monitor.sock"
	traceConfigFile = "trace.json"
	// Wire format of gVisor's remote sink (pkg/sentry/seccheck/sinks/remote/wire).
	wireVersion    = 1
	wireHeaderSize = 8
	maxMessage     = 1 << 20 // larger messages (huge argv) are dropped and counted
)

// contextFields we ask the sentry to attach to each point.
var contextFields = []string{"time", "group_id", "parent_thread_group_id", "credentials", "cwd"}

type tracePoint struct {
	Name           string   `json:"name"`
	OptionalFields []string `json:"optional_fields,omitempty"`
	ContextFields  []string `json:"context_fields,omitempty"`
}

// traceConfig is the runsc --pod-init-config session: which points to report and where.
func traceConfig(endpoint string) ([]byte, error) {
	fdPath := []string{"fd_path"}
	points := []tracePoint{
		{Name: "sentry/execve", OptionalFields: []string{"binary_info", "binary_sha256"}, ContextFields: contextFields},
		{Name: "sentry/exit_notify_parent", ContextFields: []string{"group_id"}},
		{Name: "syscall/socket/exit", ContextFields: []string{"group_id"}},
		{Name: "syscall/connect/exit", OptionalFields: fdPath, ContextFields: contextFields},
		{Name: "syscall/close/exit", OptionalFields: fdPath, ContextFields: []string{"group_id"}},
		{Name: "syscall/open/exit", ContextFields: contextFields},
	}
	for _, s := range []string{"openat", "creat"} {
		points = append(points, tracePoint{Name: "syscall/" + s + "/exit", OptionalFields: fdPath, ContextFields: contextFields})
	}
	for _, s := range []string{"write", "writev", "pwrite64", "pwritev", "pwritev2"} {
		points = append(points, tracePoint{Name: "syscall/" + s + "/exit", OptionalFields: fdPath, ContextFields: []string{"group_id"}})
	}
	cfg := map[string]any{"trace_session": map[string]any{
		"name":   "Default",
		"points": points,
		"sinks": []map[string]any{{
			"name": "remote",
			// When qtd falls behind, the sentry retries before dropping: a syscall flood slows
			// the sandbox down instead of silently losing its events.
			"config": map[string]any{"endpoint": endpoint, "retries": 10, "backoff": "1ms", "backoff_max": "20ms"},
		}},
	}}
	return json.MarshalIndent(cfg, "", "  ")
}

// monitor receives one sandbox's runtime-monitoring stream.
type monitor struct {
	lis   *net.UnixListener
	sink  backend.EventSink
	tr    *translator
	log   *slog.Logger
	ready chan error

	mu   sync.Mutex
	conn *net.UnixConn
	done chan struct{}

	dropped, truncated, malformed atomic.Uint64
	stopOnce                      sync.Once
}

// startMonitor listens on <ws>/monitor.sock. runsc connects to it while creating the
// sandbox (before any sandboxed code runs) and qtd accepts exactly that one connection.
func startMonitor(ws string, sink backend.EventSink, netNone bool, log *slog.Logger) (*monitor, error) {
	p := filepath.Join(ws, monitorSocket)
	if len(p) > 107 {
		return nil, fmt.Errorf("monitor socket path %s is too long for a unix socket", p)
	}
	_ = os.Remove(p)
	lis, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: p, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("listen for runtime monitoring: %w", err)
	}
	lis.SetUnlinkOnClose(true)
	if err := os.Chmod(p, 0o600); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("monitor socket: %w", err)
	}
	m := &monitor{lis: lis, sink: sink, tr: newTranslator(netNone), log: log, ready: make(chan error, 1), done: make(chan struct{})}
	go m.acceptAndServe()
	return m, nil
}

func (m *monitor) acceptAndServe() {
	defer close(m.done)
	conn, err := m.lis.AcceptUnix()
	_ = m.lis.Close() // one connection only; also removes the socket file
	if err != nil {
		m.ready <- fmt.Errorf("accept monitoring connection: %w", err)
		return
	}
	m.mu.Lock()
	m.conn = conn
	m.mu.Unlock()
	if err := handshake(conn); err != nil {
		_ = conn.Close()
		m.ready <- err
		return
	}
	m.ready <- nil
	_ = conn.SetReadBuffer(8 << 20)
	m.serve(conn)
}

// handshake: the sink sends its Handshake first; we answer with ours.
func handshake(conn *net.UnixConn) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	buf := make([]byte, 10240)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read monitoring handshake: %w", err)
	}
	var in pb.Handshake
	if err := proto.Unmarshal(buf[:n], &in); err != nil {
		return fmt.Errorf("decode monitoring handshake: %w", err)
	}
	if in.GetVersion() < wireVersion {
		return fmt.Errorf("runsc monitoring protocol version %d is older than %d", in.GetVersion(), wireVersion)
	}
	out, err := proto.Marshal(&pb.Handshake{Version: wireVersion})
	if err != nil {
		return fmt.Errorf("encode monitoring handshake: %w", err)
	}
	if _, err := conn.Write(out); err != nil {
		return fmt.Errorf("send monitoring handshake: %w", err)
	}
	return nil
}

// waitReady returns once runsc has connected and shaken hands.
func (m *monitor) waitReady(timeout time.Duration) error {
	select {
	case err := <-m.ready:
		return err
	case <-time.After(timeout):
		return errors.New("runsc did not connect to the monitoring socket")
	}
}

func (m *monitor) serve(conn *net.UnixConn) {
	buf := make([]byte, maxMessage)
	var lastDropped uint32
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				m.emit(m.tr.tick())
				continue
			}
			break // sandbox gone (EOF) or stop() closed the connection
		}
		if n == 0 {
			break
		}
		if flags&syscall.MSG_TRUNC != 0 {
			m.truncated.Add(1)
			continue
		}
		typ, dropped, payload, ok := parseWire(buf[:n])
		if !ok {
			m.malformed.Add(1)
			continue
		}
		if dropped > lastDropped {
			m.dropped.Add(uint64(dropped - lastDropped))
			if m.log != nil {
				m.log.Warn("runtime monitoring dropped events", "dropped_total", dropped)
			}
			lastDropped = dropped
		}
		evs, err := m.tr.message(typ, payload)
		if err != nil {
			m.malformed.Add(1)
			continue
		}
		m.emit(evs)
	}
	m.emit(m.tr.flushAll())
}

// parseWire splits one packet into its header fields and payload.
func parseWire(b []byte) (pb.MessageType, uint32, []byte, bool) {
	if len(b) < wireHeaderSize {
		return 0, 0, nil, false
	}
	hs := int(binary.LittleEndian.Uint16(b[0:2]))
	if hs < wireHeaderSize || hs > len(b) {
		return 0, 0, nil, false
	}
	return pb.MessageType(binary.LittleEndian.Uint16(b[2:4])), binary.LittleEndian.Uint32(b[4:8]), b[hs:], true
}

func (m *monitor) emit(evs []events.Payload) {
	for _, e := range evs {
		_ = m.sink.Emit(context.Background(), events.SourceHost, e) // the sink validates, bounds and counts
	}
}

// stop ends monitoring (idempotent) and waits for pending events to be written.
func (m *monitor) stop() {
	m.stopOnce.Do(func() {
		_ = m.lis.Close()
		m.mu.Lock()
		if m.conn != nil {
			_ = m.conn.Close()
		}
		m.mu.Unlock()
		select {
		case <-m.done:
		case <-time.After(5 * time.Second):
		}
	})
}
