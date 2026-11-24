package netpol

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxHello bounds what the proxy buffers before it decides: a TLS ClientHello (with
// post-quantum key shares, about 1.7 KiB, up to 16 KiB records) or HTTP request headers.
const maxHello = 32 << 10

// hello is what the client said first.
type hello struct {
	Proto string // "tls", "http" or "" (unknown, or the client did not speak first)
	SNI   string // TLS server_name
	Host  string // HTTP Host (port stripped)
	ECH   bool   // the ClientHello carries encrypted_client_hello: SNI is only the outer name
}

var errStop = errors.New("hello read")

// recorder is a read-only net.Conn over the first bytes of the client's stream.
type recorder struct {
	net.Conn
	r io.Reader
}

func (c recorder) Read(p []byte) (int, error) { return c.r.Read(p) }
func (recorder) Write(p []byte) (int, error)  { return len(p), nil }

// peekHello reads what the client sends first (up to maxHello, waiting up to wait) and
// returns those bytes, to be replayed upstream, and what they say.
func peekHello(c net.Conn, wait time.Duration) ([]byte, hello) {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var buf bytes.Buffer
	lr := io.LimitReader(c, maxHello)
	first := make([]byte, 1)
	n, _ := io.ReadFull(lr, first)
	if n == 0 {
		return nil, hello{} // server speaks first, or nothing at all
	}
	buf.Write(first)
	src := io.MultiReader(bytes.NewReader(first), io.TeeReader(lr, &buf))
	switch {
	case first[0] == 0x16: // TLS handshake record
		h := hello{Proto: "tls"}
		conf := &tls.Config{GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			h.SNI = strings.ToLower(ch.ServerName)
			for _, e := range ch.Extensions {
				h.ECH = h.ECH || e == 0xfe0d // encrypted_client_hello
			}
			return nil, errStop
		}}
		_ = tls.Server(recorder{Conn: c, r: src}, conf).Handshake()
		return buf.Bytes(), h
	case first[0] >= 'A' && first[0] <= 'Z': // an HTTP method
		req, err := http.ReadRequest(bufio.NewReaderSize(src, 4096))
		h := hello{}
		if err == nil {
			h.Proto = "http"
			host := req.Host
			if hh, _, err := net.SplitHostPort(host); err == nil {
				host = hh
			}
			h.Host = strings.ToLower(host)
		}
		// bufio may have read past the headers: everything read is in buf (tee'd).
		return buf.Bytes(), h
	}
	return buf.Bytes(), hello{}
}
