//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// thinPool is a device-mapper thin pool on two sparse files (data and metadata) attached to
// loop devices. Golden disks are thin volumes; each sandbox's disk is an instant thin snapshot
// of one. The pool keeps dm-thin's default zeroing of newly provisioned blocks, so a block
// freed by one sandbox can never be read by another.
type thinPool struct {
	dir  string
	name string // dm device name, unique per data dir
	mu   sync.Mutex
}

const (
	thinDataBytes  = 256 << 30 // sparse: only what sandboxes write is allocated
	thinMetaBytes  = 1 << 30
	thinBlockSects = 128 // 64 KiB data blocks
	sector         = 512
)

func openThinPool(ctx context.Context, dir string) (*thinPool, error) {
	if _, err := exec.LookPath("dmsetup"); err != nil {
		return nil, errors.New("dmsetup not found")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("thin pool dir: %w", err)
	}
	h := sha256.Sum256([]byte(dir))
	p := &thinPool{dir: dir, name: fmt.Sprintf("qt-pool-%x", h[:4])}
	if run(ctx, "dmsetup", "info", p.name) == nil {
		return p, nil // already up (qtd restarted)
	}
	_ = run(ctx, "modprobe", "dm-thin-pool")
	data, err := p.loop(ctx, "data.img", thinDataBytes)
	if err != nil {
		return nil, err
	}
	meta, err := p.loop(ctx, "meta.img", thinMetaBytes)
	if err != nil {
		return nil, err
	}
	table := fmt.Sprintf("0 %d thin-pool %s %s %d 32768", thinDataBytes/sector, meta, data, thinBlockSects)
	if err := run(ctx, "dmsetup", "create", p.name, "--table", table); err != nil {
		return nil, fmt.Errorf("create thin pool: %w", err)
	}
	return p, nil
}

// loop attaches a (sparse) backing file to a loop device, reusing an existing attachment.
func (p *thinPool) loop(ctx context.Context, file string, size int64) (string, error) {
	path := filepath.Join(p.dir, file)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: our pool dir
		if err != nil {
			return "", fmt.Errorf("thin pool file: %w", err)
		}
		err = f.Truncate(size) // all zeros: a fresh metadata device is formatted by the pool
		_ = f.Close()
		if err != nil {
			return "", fmt.Errorf("thin pool file: %w", err)
		}
	}
	if out, err := output(ctx, "losetup", "-j", path); err == nil && out != "" {
		return strings.TrimSuffix(strings.SplitN(out, ":", 2)[0], ":"), nil
	}
	out, err := output(ctx, "losetup", "--find", "--show", path)
	if err != nil {
		return "", fmt.Errorf("losetup %s: %w", file, err)
	}
	return out, nil
}

func (p *thinPool) volName(id int) string { return p.name + "-" + strconv.Itoa(id) }

func (p *thinPool) devPath(id int) string { return "/dev/mapper/" + p.volName(id) }

// allocID hands out thin device ids (persisted, so restarts don't reuse live ids).
func (p *thinPool) allocID() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := filepath.Join(p.dir, "ids.json")
	var st struct{ Next int }
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: our pool dir
		_ = json.Unmarshal(b, &st)
	}
	if st.Next < 1 {
		st.Next = 1
	}
	id := st.Next
	st.Next++
	b, _ := json.Marshal(st)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return 0, fmt.Errorf("thin ids: %w", err)
	}
	return id, nil
}

func (p *thinPool) message(ctx context.Context, msg string) error {
	return run(ctx, "dmsetup", "message", p.name, "0", msg)
}

// create makes a new, empty thin volume and activates it.
func (p *thinPool) create(ctx context.Context, bytes int64) (int, error) {
	id, err := p.allocID()
	if err != nil {
		return 0, err
	}
	if err := p.message(ctx, fmt.Sprintf("create_thin %d", id)); err != nil {
		return 0, fmt.Errorf("create thin volume: %w", err)
	}
	return id, p.activate(ctx, id, bytes)
}

// snapshot makes an instant copy-on-write snapshot of an inactive volume and activates it.
func (p *thinPool) snapshot(ctx context.Context, origin int, bytes int64) (int, error) {
	id, err := p.allocID()
	if err != nil {
		return 0, err
	}
	if err := p.message(ctx, fmt.Sprintf("create_snap %d %d", id, origin)); err != nil {
		return 0, fmt.Errorf("snapshot thin volume: %w", err)
	}
	return id, p.activate(ctx, id, bytes)
}

func (p *thinPool) activate(ctx context.Context, id int, bytes int64) error {
	table := fmt.Sprintf("0 %d thin /dev/mapper/%s %d", bytes/sector, p.name, id)
	if err := run(ctx, "dmsetup", "create", p.volName(id), "--table", table); err != nil {
		return fmt.Errorf("activate thin volume %d: %w", id, err)
	}
	return nil
}

func (p *thinPool) deactivate(ctx context.Context, id int) error {
	if run(ctx, "dmsetup", "info", p.volName(id)) != nil {
		return nil
	}
	if err := run(ctx, "dmsetup", "remove", "--retry", p.volName(id)); err != nil {
		return fmt.Errorf("deactivate thin volume %d: %w", id, err)
	}
	return nil
}

// remove deactivates and deletes a volume (idempotent).
func (p *thinPool) remove(ctx context.Context, id int) error {
	if err := p.deactivate(ctx, id); err != nil {
		return err
	}
	if err := p.message(ctx, fmt.Sprintf("delete %d", id)); err != nil && !strings.Contains(err.Error(), "No data available") {
		return fmt.Errorf("delete thin volume %d: %w", id, err)
	}
	return nil
}

// mknodAt creates a block device node for volume id at path (inside a jail), owned by uid.
func (p *thinPool) mknodAt(id int, path string, uid int) error {
	var st unix.Stat_t
	if err := unix.Stat(p.devPath(id), &st); err != nil {
		return fmt.Errorf("thin volume %d: %w", id, err)
	}
	if err := unix.Mknod(path, syscall.S_IFBLK|0o600, int(st.Rdev)); err != nil { //nolint:gosec // G115: dev_t fits
		return fmt.Errorf("device node: %w", err)
	}
	return os.Chown(path, uid, uid)
}

func run(ctx context.Context, name string, args ...string) error {
	_, err := output(ctx, name, args...)
	return err
}

func output(ctx context.Context, name string, args ...string) (string, error) {
	var out, errb bytes.Buffer
	c := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: fixed tools, arguments we build
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// close tears the pool down: active volumes, the pool device, its loop devices. The backing
// files (and so every volume) stay; openThinPool brings it all back.
func (p *thinPool) close(ctx context.Context) error {
	if out, err := output(ctx, "dmsetup", "ls"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], p.name+"-") {
				_ = run(ctx, "dmsetup", "remove", "--retry", f[0])
			}
		}
	}
	var errs []error
	if run(ctx, "dmsetup", "info", p.name) == nil {
		if err := run(ctx, "dmsetup", "remove", "--retry", p.name); err != nil {
			errs = append(errs, err)
		}
	}
	for _, f := range []string{"data.img", "meta.img"} {
		if out, err := output(ctx, "losetup", "-j", filepath.Join(p.dir, f)); err == nil && out != "" {
			if err := run(ctx, "losetup", "-d", strings.SplitN(out, ":", 2)[0]); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
