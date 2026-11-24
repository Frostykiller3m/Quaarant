package honeytoken

import (
	"encoding/binary"
	"errors"
	"time"
)

// A minimal, valid SQLite 3 database (https://www.sqlite.org/fileformat.html): page 1 holds
// the schema (one table), page 2 the table's rows, both as single leaf b-tree pages. It is
// what a cookie stealer opens with sqlite3 and queries; values are stored in the clear.

const pageSize = 4096

type cookie struct{ host, name, value string }

// chromeTime is microseconds since 1601-01-01 (Chrome's cookie timestamps).
func chromeTime(t time.Time) int64 {
	return t.UnixMicro() + 11644473600*1_000_000
}

func cookieDB(cs []cookie) ([]byte, error) {
	schema := "CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,name TEXT NOT NULL," +
		"value TEXT NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL," +
		"is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL)"
	now := time.Now()
	var rows [][]any
	for i, c := range cs {
		created := chromeTime(now.Add(-time.Duration(30+i) * 24 * time.Hour))
		rows = append(rows, []any{created, c.host, c.name, c.value, "/", chromeTime(now.Add(365 * 24 * time.Hour)), int64(1), int64(1), chromeTime(now.Add(-time.Hour))})
	}
	db := make([]byte, 2*pageSize)
	h := db[:100]
	copy(h, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(h[16:], pageSize)
	h[18], h[19], h[20], h[21], h[22], h[23] = 1, 1, 0, 64, 32, 32
	binary.BigEndian.PutUint32(h[24:], 1)       // file change counter
	binary.BigEndian.PutUint32(h[28:], 2)       // database size in pages
	binary.BigEndian.PutUint32(h[40:], 1)       // schema cookie
	binary.BigEndian.PutUint32(h[44:], 4)       // schema format
	binary.BigEndian.PutUint32(h[56:], 1)       // UTF-8
	binary.BigEndian.PutUint32(h[92:], 1)       // version-valid-for = change counter
	binary.BigEndian.PutUint32(h[96:], 3045001) // SQLITE_VERSION_NUMBER that "wrote" it
	if err := leafPage(db[:pageSize], 100, [][]any{{"table", "cookies", "cookies", int64(2), schema}}); err != nil {
		return nil, err
	}
	if err := leafPage(db[pageSize:], 0, rows); err != nil {
		return nil, err
	}
	return db, nil
}

// leafPage writes a table b-tree leaf page (its header at hdr) holding rows as rowids 1..n.
func leafPage(page []byte, hdr int, rows [][]any) error {
	end := len(page)
	ptrs := hdr + 8
	for i, r := range rows {
		rec := record(r)
		cell := appendVarint(nil, uint64(len(rec)))
		cell = appendVarint(cell, uint64(i+1))
		cell = append(cell, rec...)
		if len(rec) > pageSize-35 || end-len(cell) < ptrs+2*len(rows) {
			return errors.New("honeytoken: cookie db row too large")
		}
		end -= len(cell)
		copy(page[end:], cell)
		binary.BigEndian.PutUint16(page[ptrs+2*i:], uint16(end)) //nolint:gosec // G115: < pageSize
	}
	page[hdr] = 0x0d                                            // leaf table b-tree page
	binary.BigEndian.PutUint16(page[hdr+3:], uint16(len(rows))) //nolint:gosec // G115: tiny
	binary.BigEndian.PutUint16(page[hdr+5:], uint16(end))       //nolint:gosec // G115: < pageSize
	return nil
}

// record encodes a row in SQLite's record format: a header of serial types, then the values.
func record(vals []any) []byte {
	var types, body []byte
	for _, v := range vals {
		switch x := v.(type) {
		case string:
			types = appendVarint(types, uint64(len(x))*2+13)
			body = append(body, x...)
		case int64:
			t, b := intSerial(x)
			types = appendVarint(types, t)
			body = append(body, b...)
		}
	}
	// The header length counts itself (one byte while the header is under 127 bytes).
	hdr := appendVarint(nil, uint64(len(types)+1))
	return append(append(hdr, types...), body...)
}

func intSerial(v int64) (uint64, []byte) {
	switch {
	case v == 0:
		return 8, nil
	case v == 1:
		return 9, nil
	case v >= -128 && v <= 127:
		return 1, []byte{byte(v)} //nolint:gosec // G115: in range
	case v >= -32768 && v <= 32767:
		return 2, binary.BigEndian.AppendUint16(nil, uint16(v)) //nolint:gosec // G115: in range
	case v >= -1<<31 && v < 1<<31:
		return 4, binary.BigEndian.AppendUint32(nil, uint32(v)) //nolint:gosec // G115: in range
	}
	return 6, binary.BigEndian.AppendUint64(nil, uint64(v)) //nolint:gosec // G115: two's complement
}

// appendVarint appends SQLite's big-endian varint (7 bits per byte, high bit = more).
func appendVarint(b []byte, v uint64) []byte {
	if v <= 0x7f {
		return append(b, byte(v))
	}
	var tmp [10]byte
	n := 0
	for v > 0 {
		tmp[n] = byte(v & 0x7f)
		v >>= 7
		n++
	}
	for i := n - 1; i >= 0; i-- {
		c := tmp[i]
		if i > 0 {
			c |= 0x80
		}
		b = append(b, c)
	}
	return b
}
