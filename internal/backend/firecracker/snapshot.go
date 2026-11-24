package firecracker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// snapMeta is a user snapshot's meta.json.
type snapMeta struct {
	Box     boxMeta   `json:"box"`    // the source sandbox's settings at the time
	Memory  bool      `json:"memory"` // vmstate + mem are in the directory
	Disk    diskRef   `json:"disk"`   // the snapshot's own disk (never written again)
	Inputs  string    `json:"inputs"` // kernel, agent, firecracker: a memory snapshot only resumes on the same ones
	Created time.Time `json:"created"`
}

// Snapshot implements backend.Backend: the VM is paused, its memory and device state saved
// (Memory) and its disk captured copy-on-write, then it resumes. Without Memory the guest
// syncs its filesystems first and only the disk is kept.
func (b *Backend) Snapshot(ctx context.Context, id string, o backend.SnapshotOptions) (ref backend.SnapshotRef, err error) {
	bx, err := b.lookup(id)
	if err != nil {
		return backend.SnapshotRef{}, err
	}
	if !filepath.IsAbs(o.Dir) {
		return backend.SnapshotRef{}, errors.New("firecracker: snapshot needs an absolute directory")
	}
	if !b.alive(bx) {
		return backend.SnapshotRef{}, fmt.Errorf("firecracker: sandbox %s is not running", id)
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return backend.SnapshotRef{}, fmt.Errorf("firecracker: snapshot: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(o.Dir)
		}
	}()
	if !o.Memory {
		if err := b.call(ctx, bx, agentproto.Request{Op: agentproto.OpSync}); err != nil {
			return backend.SnapshotRef{}, fmt.Errorf("firecracker: sync before snapshot: %w", err)
		}
	}
	root := jailRoot(bx.workspace, bx.id)
	api := newAPI(filepath.Join(root, "api.sock"))
	if err := api.patch(ctx, "/vm", map[string]any{"state": "Paused"}); err != nil {
		return backend.SnapshotRef{}, fmt.Errorf("firecracker: pause: %w", err)
	}
	defer func() {
		if rerr := api.patch(context.WithoutCancel(ctx), "/vm", map[string]any{"state": "Resumed"}); rerr != nil && err == nil {
			err = fmt.Errorf("firecracker: resume after snapshot: %w", rerr)
		}
	}()
	if o.Memory {
		if err := api.put(ctx, "/snapshot/create", map[string]any{"snapshot_type": "Full", "snapshot_path": "/snap.vmstate", "mem_file_path": "/snap.mem"}); err != nil {
			return backend.SnapshotRef{}, fmt.Errorf("firecracker: snapshot: %w", err)
		}
		for src, dst := range map[string]string{"snap.vmstate": "vmstate", "snap.mem": "mem"} {
			to := filepath.Join(o.Dir, dst)
			if err := os.Rename(filepath.Join(root, src), to); err != nil {
				return backend.SnapshotRef{}, fmt.Errorf("firecracker: snapshot: %w", err)
			}
			if dst == "mem" {
				// In the background: only all-zero blocks become holes, so the contents never
				// change, even for VMMs already mapping the file (restores, fork children).
				go func() {
					if _, err := sparsify(to); err != nil {
						b.warn("snapshot memory file stays fully allocated", err)
					}
				}()
			}
			if err := os.Chown(to, 0, 0); err != nil {
				return backend.SnapshotRef{}, fmt.Errorf("firecracker: snapshot: %w", err)
			}
			if err := os.Chmod(to, 0o444); err != nil { //nolint:gosec // G302: read by every restored VMM
				return backend.SnapshotRef{}, fmt.Errorf("firecracker: snapshot: %w", err)
			}
		}
	}
	ds, err := b.diskStore(ctx)
	if err != nil {
		return backend.SnapshotRef{}, err
	}
	disk, err := ds.snapshotLive(ctx, bx.meta.Disk, filepath.Join(root, "disk.ext4"), filepath.Join(o.Dir, "disk.ext4"))
	if err != nil {
		return backend.SnapshotRef{}, fmt.Errorf("firecracker: snapshot disk: %w", err)
	}
	inputs, err := b.inputsHash()
	if err != nil {
		_ = ds.remove(ctx, disk)
		return backend.SnapshotRef{}, err
	}
	meta := snapMeta{Box: bx.meta, Memory: o.Memory, Disk: disk, Inputs: inputs, Created: time.Now().UTC()}
	meta.Box.Net, meta.Box.Golden, meta.Box.Disk = nil, "", diskRef{}
	if err := writeJSON(filepath.Join(o.Dir, "meta.json"), meta); err != nil {
		_ = ds.remove(ctx, disk)
		return backend.SnapshotRef{}, err
	}
	return backend.SnapshotRef{ID: filepath.Base(o.Dir), Backend: backend.IsolationVM, Memory: o.Memory, Path: o.Dir}, nil
}

func readSnapMeta(dir string) (*snapMeta, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "meta.json")) //nolint:gosec // G304: a snapshot directory qtd chose
	if err != nil {
		return nil, fmt.Errorf("firecracker: snapshot: %w", err)
	}
	var m snapMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("firecracker: snapshot meta: %w", err)
	}
	return &m, nil
}

// Restore implements backend.Backend: a new sandbox (s.ID, its own link and identity) from a
// snapshot. A memory snapshot resumes where the source was; a disk-only one boots its disk.
func (b *Backend) Restore(ctx context.Context, ref backend.SnapshotRef, s backend.Spec) (err error) {
	m, err := readSnapMeta(ref.Path)
	if err != nil {
		return err
	}
	if m.Memory {
		inputs, err := b.inputsHash()
		if err != nil {
			return err
		}
		if inputs != m.Inputs {
			return errors.New("firecracker: the guest kernel, agent or firecracker changed since this snapshot; its memory can't be resumed")
		}
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("firecracker: %w", err)
	}
	if !s.Network.None && s.Network.TapDevice == "" {
		return fmt.Errorf("firecracker: a network link must be a tap device: %w", errors.ErrUnsupported)
	}
	if !hostnameRe.MatchString(s.Hostname) {
		return fmt.Errorf("firecracker: invalid hostname %.64q", s.Hostname)
	}
	b.mu.Lock()
	if _, ok := b.boxes[s.ID]; ok {
		b.mu.Unlock()
		return fmt.Errorf("firecracker: sandbox %s already exists", s.ID)
	}
	meta := m.Box // the source's user, env, workdir and shape: memory is the source's
	meta.Hostname, meta.Created, meta.Snapshot = s.Hostname, time.Now().UTC(), ref.ID
	bx := &box{id: s.ID, workspace: s.Workspace, meta: meta, sink: s.Events}
	if !s.Network.None {
		bx.meta.Net = &netMeta{Tap: s.Network.TapDevice, Addr: s.Network.Addr.String(), Gateway: s.Network.Gateway.String(), MAC: newMAC()}
	}
	b.boxes[s.ID] = bx
	b.mu.Unlock()
	defer func() {
		if err != nil {
			_ = b.Destroy(context.WithoutCancel(ctx), s.ID)
		}
	}()
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("firecracker: state dir: %w", err)
	}
	if err := writeJSON(b.statePath(s.ID), stateFile{Workspace: s.Workspace}); err != nil {
		return err
	}
	root := jailRoot(s.Workspace, s.ID)
	if err := os.MkdirAll(root, 0o755); err != nil { //nolint:gosec // G301: inside the 0700 workspace
		return fmt.Errorf("firecracker: jail: %w", err)
	}
	jid := jailID(s.ID)
	if err := os.Chown(root, jid, jid); err != nil {
		return fmt.Errorf("firecracker: jail: %w", err)
	}
	ds, err := b.diskStore(ctx)
	if err != nil {
		return err
	}
	disk, err := ds.clone(ctx, m.Disk, filepath.Join(root, "disk.ext4"), jid)
	if err != nil {
		return fmt.Errorf("firecracker: disk clone: %w", err)
	}
	bx.meta.Disk = disk
	if m.Memory {
		for _, f := range []string{"vmstate", "mem"} {
			if err := linkOrCopy(filepath.Join(ref.Path, f), filepath.Join(root, f), 0o444); err != nil {
				return fmt.Errorf("firecracker: %w", err)
			}
		}
	} else {
		bx.meta.Snapshot = "" // boots cold from the disk
		if err := b.linkBoot(root); err != nil {
			return err
		}
		s.Limits.CPUMillis, s.Limits.MemoryBytes = meta.CPU, meta.Memory
		if bx.meta.Net != nil {
			s.Network.MAC = bx.meta.Net.MAC
		}
		cfg, err := vmConfig(s)
		if err != nil {
			return fmt.Errorf("firecracker: %w", err)
		}
		if err := os.WriteFile(filepath.Join(root, "vm.json"), cfg, 0o444); err != nil { //nolint:gosec // G306: read by the jailed VMM
			return fmt.Errorf("firecracker: vm config: %w", err)
		}
	}
	if err := writeJSON(filepath.Join(s.Workspace, "qt.json"), bx.meta); err != nil {
		return err
	}
	return b.Start(ctx, s.ID)
}

// Fork implements backend.Backend: one memory snapshot of the running source, then one
// restore per child. The snapshot is removed after: children share its memory file (each
// maps it copy-on-write) and have their own disk snapshots.
func (b *Backend) Fork(ctx context.Context, id string, children []backend.Spec) (err error) {
	if len(children) == 0 {
		return nil
	}
	if b.cfg.DataDir == "" {
		return errors.New("firecracker: fork needs a data directory")
	}
	dir := filepath.Join(b.cfg.DataDir, "snapshots", ".fork-"+randHex(6))
	ref, err := b.Snapshot(ctx, id, backend.SnapshotOptions{Memory: true, Dir: dir})
	if err != nil {
		return err
	}
	defer func() { _ = b.DeleteSnapshot(context.WithoutCancel(ctx), ref) }()
	var made []string
	defer func() {
		if err != nil {
			for _, c := range made {
				_ = b.Destroy(context.WithoutCancel(ctx), c)
			}
		}
	}()
	for _, c := range children {
		if err := b.Restore(ctx, ref, c); err != nil {
			return fmt.Errorf("firecracker: fork child %s: %w", c.ID, err)
		}
		made = append(made, c.ID)
	}
	return nil
}

// DeleteSnapshot removes a snapshot's disk and files (sandboxes restored from it keep running:
// their memory files are hard links, their disks their own snapshots).
func (b *Backend) DeleteSnapshot(ctx context.Context, ref backend.SnapshotRef) error {
	if m, err := readSnapMeta(ref.Path); err == nil && m.Disk.Kind == "thin" {
		ds, err := b.diskStore(ctx)
		if err != nil {
			return err
		}
		if err := ds.remove(ctx, m.Disk); err != nil {
			return err
		}
	}
	return os.RemoveAll(ref.Path)
}

// Manifest implements backend.Manifester: the guest lists its filesystem.
func (b *Backend) Manifest(ctx context.Context, id string) ([]backend.Entry, error) {
	bx, err := b.lookup(id)
	if err != nil {
		return nil, err
	}
	c, err := b.dial(ctx, bx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if err := agentproto.WriteJSON(c, agentproto.FrameRequest, agentproto.Request{Op: agentproto.OpManifest}); err != nil {
		return nil, err
	}
	var out []backend.Entry
	for {
		t, payload, err := agentproto.ReadFrame(c, agentproto.MaxFrame)
		if err != nil {
			return nil, fmt.Errorf("firecracker: manifest: %w", err)
		}
		switch t {
		case agentproto.FrameEntries:
			var es []agentproto.Entry
			if err := agentproto.Decode(payload, &es); err != nil {
				return nil, fmt.Errorf("firecracker: manifest: %w", err)
			}
			for _, e := range es {
				if len(out) >= agentproto.MaxEntries {
					return nil, errors.New("firecracker: manifest: too many entries")
				}
				if !strings.HasPrefix(e.Path, "/") || len(e.Path) > 4096 || len(e.SHA256) > 64 || len(e.Link) > 4096 {
					continue // the guest's word: bound it, skip what doesn't fit
				}
				out = append(out, backend.Entry{Path: e.Path, Type: e.Type, Mode: e.Mode, Size: e.Size, SHA256: e.SHA256, Link: e.Link})
			}
		case agentproto.FrameResult:
			return out, nil
		case agentproto.FrameError:
			var e agentproto.Error
			_ = agentproto.Decode(payload, &e)
			return nil, fmt.Errorf("firecracker: manifest: %.200s", e.Message)
		default:
			return nil, fmt.Errorf("firecracker: manifest: unexpected frame %d", t)
		}
	}
}

// newMAC is a random locally administered unicast address.
func newMAC() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	b[0] = (b[0] | 0x02) &^ 0x01
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
