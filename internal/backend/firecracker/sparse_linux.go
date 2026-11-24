//go:build linux

package firecracker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// sparsify punches holes over the all-zero blocks of a file. A Full snapshot writes every
// page of guest memory, most of them zero; a VMM maps the file copy-on-write, so holes read
// back as zeros and the snapshot takes only the memory the guest used.
func sparsify(path string) (saved int64, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: a snapshot file qtd just wrote
	if err != nil {
		return 0, fmt.Errorf("sparsify: %w", err)
	}
	defer func() { _ = f.Close() }()
	const block = 1 << 16
	buf := make([]byte, block)
	zero := make([]byte, block)
	var off, holeStart int64 = 0, -1
	punch := func(end int64) error {
		if holeStart < 0 || end <= holeStart {
			return nil
		}
		err := unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, holeStart, end-holeStart)
		if err == nil {
			saved += end - holeStart
		}
		holeStart = -1
		return err
	}
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			if n == block && bytes.Equal(buf, zero) {
				if holeStart < 0 {
					holeStart = off
				}
			} else if err := punch(off); err != nil {
				return saved, fmt.Errorf("sparsify: %w", err)
			}
			off += int64(n)
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			return saved, fmt.Errorf("sparsify: %w", rerr)
		}
	}
	if err := punch(off); err != nil {
		return saved, fmt.Errorf("sparsify: %w", err)
	}
	return saved, nil
}
