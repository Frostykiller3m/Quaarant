package honeytoken

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// Hit is a token found in some data.
type Hit struct {
	TokenID string
	Kind    string
}

// windows is how much of a secret must show up for a match: 20 bytes of the secret, in the
// encoding's characters. Real exfiltration chunks values (DNS labels are 63 characters), so a
// piece of a secret counts, not only the whole of it; 20 random bytes don't occur by chance.
var windows = map[string]int{"raw": 20, "hex": 40, "base64": 27, "base32": 32}

// index finds windows by their first 8 bytes (every window is at least minSecretLen = 16
// bytes), behind a 1 Mi-bit filter so most positions cost one array read.
type index struct {
	cands  map[uint64][]cand
	filter []uint64
}

type cand struct {
	w string
	h Hit
}

const filterBits = 1 << 20

func newIndex() *index {
	return &index{cands: map[uint64][]cand{}, filter: make([]uint64, filterBits/64)}
}

func key8(b []byte) uint64      { return binary.LittleEndian.Uint64(b) }
func filterPos(k uint64) uint64 { return (k * 0x9E3779B97F4A7C15) >> (64 - 20) }

func (x *index) add(w string, h Hit) {
	k := key8([]byte(w))
	for _, c := range x.cands[k] {
		if c.w == w {
			return
		}
	}
	x.cands[k] = append(x.cands[k], cand{w, h})
	p := filterPos(k)
	x.filter[p>>6] |= 1 << (p & 63)
}

func (x *index) find(data []byte) []Hit {
	var hits []Hit
	for i := 0; i+minSecretLen <= len(data); i++ {
		k := key8(data[i:])
		if p := filterPos(k); x.filter[p>>6]&(1<<(p&63)) == 0 {
			continue
		}
		for _, c := range x.cands[k] {
			if bytes.HasPrefix(data[i:], []byte(c.w)) {
				hits = merge(hits, []Hit{c.h})
			}
		}
	}
	return hits
}

// Matcher finds pieces of a set's secrets in data, raw or encoded (hex, base64 and base64url
// at every alignment, base32 at every alignment).
type Matcher struct {
	exact  *index // plaintext
	folded *index // lowercased, for DNS names and SNI (base64 can't survive lowercasing)
	maxLen int
}

// NewMatcher builds a matcher for s; nil for an empty set.
func NewMatcher(s *Set) *Matcher {
	if s == nil || len(s.Tokens) == 0 {
		return nil
	}
	m := &Matcher{exact: newIndex(), folded: newIndex()}
	for _, t := range s.Tokens {
		h := Hit{TokenID: t.ID, Kind: t.Kind}
		for _, sec := range t.Secrets {
			if len(sec) < minSecretLen {
				continue
			}
			for family, vs := range variants(sec) {
				for _, v := range vs {
					w := min(windows[family], len(v))
					if w < minSecretLen {
						continue
					}
					m.maxLen = max(m.maxLen, w)
					for i := 0; i+w <= len(v); i++ {
						m.exact.add(v[i:i+w], h)
						if family != "base64" {
							m.folded.add(strings.ToLower(v[i:i+w]), h)
						}
					}
				}
			}
		}
	}
	return m
}

// variants are the forms a secret takes on the wire, by family. For the block encodings, a
// value inside a larger encoded blob starts at any of 3 (base64) or 5 (base32) byte
// alignments; each variant drops the edge characters that depend on the neighbouring bytes.
func variants(sec string) map[string][]string {
	out := map[string][]string{"raw": {sec}, "hex": {hex.EncodeToString([]byte(sec))}}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for pad := range 3 {
			e := strings.TrimRight(enc.EncodeToString(append(bytes.Repeat([]byte{0}, pad), sec...)), "=")
			if skip := (pad*8 + 5) / 6; len(e) > skip+2 {
				out["base64"] = append(out["base64"], e[skip:len(e)-2])
			}
		}
	}
	for pad := range 5 {
		e := strings.TrimRight(base32.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0}, pad), sec...)), "=")
		if skip := (pad*8 + 4) / 5; len(e) > skip+2 {
			out["base32"] = append(out["base32"], e[skip:len(e)-2])
		}
	}
	return out
}

// Find reports the tokens a piece of which is in data (each once).
func (m *Matcher) Find(data []byte) []Hit {
	if m == nil {
		return nil
	}
	return m.exact.find(data)
}

// FindName reports the tokens in a DNS name or SNI: case-insensitive, dots ignored (a value
// split over labels).
func (m *Matcher) FindName(name string) []Hit {
	if m == nil {
		return nil
	}
	n := strings.ToLower(name)
	return merge(m.folded.find([]byte(n)), m.folded.find([]byte(strings.ReplaceAll(n, ".", ""))))
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
