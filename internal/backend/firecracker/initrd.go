package firecracker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeInitrd writes a newc cpio archive holding only /init (the static qt-agent). The
// kernel unpacks it into its rootfs and runs /init as PID 1. Fixed metadata (mtime 0,
// root-owned) keeps it byte-for-byte reproducible for a given agent binary.
func writeInitrd(w io.Writer, agent []byte) error {
	entry := func(name string, mode uint32, data []byte, ino int) error {
		hdr := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
		var b bytes.Buffer
		b.WriteString(hdr)
		b.WriteString(name)
		b.WriteByte(0)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
		b.Write(data)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
		_, err := w.Write(b.Bytes())
		return err
	}
	if err := entry("init", 0o100755, agent, 1); err != nil {
		return fmt.Errorf("write initrd: %w", err)
	}
	if err := entry("TRAILER!!!", 0, nil, 0); err != nil {
		return fmt.Errorf("write initrd: %w", err)
	}
	return nil
}

// cachedInitrd returns <dir>/initrd-<sha256 of agent>.cpio, building it if needed.
func cachedInitrd(dir, agentPath string) (string, error) {
	agent, err := os.ReadFile(agentPath) //nolint:gosec // G304: qtd's own agent binary
	if err != nil {
		return "", fmt.Errorf("read qt-agent: %w", err)
	}
	sum := sha256.Sum256(agent)
	out := filepath.Join(dir, "initrd-"+hex.EncodeToString(sum[:8])+".cpio")
	if _, err := os.Stat(out); err == nil { //nolint:gosec // G703: path under qtd's state dir
		return out, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: read by the jailed VMM
		return "", fmt.Errorf("initrd dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".initrd-*")
	if err != nil {
		return "", fmt.Errorf("initrd: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := writeInitrd(tmp, agent); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("initrd: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o444); err != nil { //nolint:gosec // G302: read by the jailed VMM
		return "", fmt.Errorf("initrd: %w", err)
	}
	if err := os.Rename(tmp.Name(), out); err != nil { //nolint:gosec // G703: path under qtd's state dir
		return "", fmt.Errorf("initrd: %w", err)
	}
	return out, nil
}
