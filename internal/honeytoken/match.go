package honeytoken

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Hit is a token found in some data.
type Hit struct {
	TokenID string
	Kind    string
}

type needle struct {
	b   []byte
	hit Hit
}

// Matcher finds a set's secrets in data, raw or encoded (hex, base64 and base64url at every
// alignment, base32 for DNS labels).
type Matcher struct {
	needles []needle // case-sensitive (plaintext)
	folded  []needle // lowercased (DNS names, SNI)
	maxLen  int
}

// NewMatcher builds a matcher for s; nil for an empty set.
func NewMatcher(s *Set) *Matcher {
	if s == nil || len(s.Tokens) == 0 {
		return nil
	}
	m := &Matcher{}
	seen := map[string]bool{}
	for _, t := range s.Tokens {
		h := Hit{TokenID: t.ID, Kind: t.Kind}
		for _, sec := range t.Secrets {
			for _, v := range variants(sec) {
				if len(v) < minSecretLen || seen[v] {
					continue
				}
				seen[v] = true
				m.needles = append(m.needles, needle{[]byte(v), h})
				m.folded = append(m.folded, needle{[]byte(strings.ToLower(v)), h})
				m.maxLen = max(m.maxLen, len(v))
			}
		}
	}
	return m
}

// variants are the forms a secret takes on the wire. For the block encodings, a value inside
// a larger encoded blob starts at any of 3 (base64) or 5 (base32) byte alignments; each
// variant drops the edge characters that depend on the neighbouring bytes.
func variants(sec string) []string {
	out := []string{sec, hex.EncodeToString([]byte(sec))}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for pad := range 3 {
			e := enc.EncodeToString(append(bytes.Repeat([]byte{0}, pad), sec...))
			skip := (pad*8 + 5) / 6 // characters touched by the padding bytes
			e = strings.TrimRight(e, "=")
			if len(e) > skip+2 {
				out = append(out, e[skip:len(e)-2])
			}
		}
	}
	for pad := range 5 {
		e := base32.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0}, pad), sec...))
		skip := (pad*8 + 4) / 5
		e = strings.TrimRight(e, "=")
		if len(e) > skip+2 {
			out = append(out, e[skip:len(e)-2])
		}
	}
	return out
}

// Find reports the tokens in data (each once).
func (m *Matcher) Find(data []byte) []Hit {
	if m == nil {
		return nil
	}
	return m.find(m.needles, data)
}

// FindName reports the tokens in a DNS name or SNI: case-insensitive, dots ignored (a value
// split over labels).
func (m *Matcher) FindName(name string) []Hit {
	if m == nil {
		return nil
	}
	n := strings.ToLower(name)
	hits := m.find(m.folded, []byte(n))
	return merge(hits, m.find(m.folded, []byte(strings.ReplaceAll(n, ".", ""))))
}

func (m *Matcher) find(ns []needle, data []byte) []Hit {
	if m == nil {
		return nil
	}
	var hits []Hit
	for _, n := range ns {
		if bytes.Contains(data, n.b) {
			hits = merge(hits, []Hit{n.hit})
		}
	}
	return hits
}

func merge(a, b []Hit) []Hit {
	for _, h := range b {
		dup := false
		for _, x := range a {
			dup = dup || x.TokenID == h.TokenID
		}
		if !dup {
			a = append(a, h)
		}
	}
	return a
}

// Stream scans a byte stream in chunks, finding secrets that straddle chunk boundaries.
type Stream struct {
	m    *Matcher
	tail []byte
	seen map[string]bool
}

// NewStream starts scanning a stream; nil-safe.
func (m *Matcher) NewStream() *Stream {
	if m == nil {
		return nil
	}
	return &Stream{m: m, seen: map[string]bool{}}
}

// Write scans p and returns tokens not reported earlier in this stream.
func (s *Stream) Write(p []byte) []Hit {
	if s == nil || len(p) == 0 {
		return nil
	}
	buf := append(s.tail, p...) //nolint:gocritic // tail is ours to reuse
	var out []Hit
	for _, h := range s.m.Find(buf) {
		if !s.seen[h.TokenID] {
			s.seen[h.TokenID] = true
			out = append(out, h)
		}
	}
	keep := min(len(buf), s.m.maxLen-1)
	s.tail = append(s.tail[:0], buf[len(buf)-keep:]...)
	return out
}
