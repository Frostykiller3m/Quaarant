package firecracker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/cgroups"
)

// A golden snapshot is a booted VM of one image, paused right after its agent came up:
// <DataDir>/golden/<key>/{vmstate, mem, meta.json} plus its disk (a file there, or a thin
// volume). New sandboxes of that image restore it instead of booting, each with its own
// copy-on-write clone of the golden disk. The key covers everything the snapshot depends
// on: image disk, kernel, agent, Firecracker binary, vCPUs, memory and disk size.
type goldenInfo struct {
	Key     string    `json:"key"`
	RootFS  string    `json:"rootfs"`
	Inputs  string    `json:"inputs"` // hash of kernel, agent and firecracker
	Disk    diskRef   `json:"disk"`
	VCPUs   int       `json:"vcpus"`
	MemMiB  int       `json:"mem_mib"`
	Created time.Time `json:"created"`
	BuildMS int64     `json:"build_ms"`

	dir string
}

func shape(l backend.Limits) (vcpus, memMiB int) {
	return max(1, min(32, (l.CPUMillis+999)/1000)), max(128, int(l.MemoryBytes>>20))
}

var hashCache sync.Map // path -> hex sha256 (kernel, firecracker, agent: fixed while qtd runs)

func fileHash(path string) (string, error) {
	if h, ok := hashCache.Load(path); ok {
		return h.(string), nil
	}
	f, err := os.Open(path) //nolint:gosec // G304: configured binaries
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	s := hex.EncodeToString(h.Sum(nil))
	hashCache.Store(path, s)
	return s, nil
}

// inputsHash identifies the kernel, agent and firecracker a snapshot depends on.
func (b *Backend) inputsHash() (string, error) {
	h := sha256.New()
	for _, p := range []string{b.cfg.Kernel, b.cfg.AgentPath, b.cfg.Firecracker} {
		fh, err := fileHash(p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "|%s", fh)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

func (b *Backend) goldenKey(s backend.Spec, vcpus, mem int, size int64) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "qt-golden-v1|%s|%d|%d|%d", s.RootFS, vcpus, mem, size)
	if fi, err := os.Stat(s.RootFS); err == nil {
		fmt.Fprintf(h, "|%d|%d", fi.Size(), fi.ModTime().UnixNano())
	}
	for _, p := range []string{b.cfg.Kernel, b.cfg.AgentPath, b.cfg.Firecracker} {
		fh, err := fileHash(p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "|%s", fh)
	}
	return hex.EncodeToString(h.Sum(nil))[:24], nil
}

// golden returns the golden snapshot for s, building it the first time (one build per key
// at a time). It returns nil when snapshots are off or the build failed (the sandbox then
// boots cold).
func (b *Backend) golden(ctx context.Context, s backend.Spec, size int64) *goldenInfo {
	if b.cfg.DataDir == "" || b.cfg.NoGolden {
		return nil
	}
	ds, err := b.diskStore(ctx)
	if err != nil || ds == nil {
		return nil
	}
	vcpus, mem := shape(s.Limits)
	key, err := b.goldenKey(s, vcpus, mem, size)
	if err != nil {
		b.warn("golden snapshot key", err)
		return nil
	}
	m, _ := b.goldenLocks.LoadOrStore(key, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	dir := filepath.Join(b.cfg.DataDir, "golden", key)
	if raw, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil { //nolint:gosec // G304: our golden dir
		var g goldenInfo
		if json.Unmarshal(raw, &g) == nil {
			g.dir = dir
			return &g
		}
	}
	t0 := time.Now()
	g, err := b.buildGolden(context.WithoutCancel(ctx), key, dir, s, vcpus, mem, size, ds)
	if err != nil {
		b.warn("golden snapshot build failed; booting cold", err)
		return nil
	}
	if b.cfg.Logger != nil {
		b.cfg.Logger.Info("golden snapshot built", "key", key, "disk", g.Disk.Kind, "ms", time.Since(t0).Milliseconds())
	}
	b.pruneGoldens(ctx, g, ds)
	return g
}

func (b *Backend) warn(msg string, err error) {
	if b.cfg.Logger != nil {
		b.cfg.Logger.Warn(msg, "err", err)
	}
}

func (b *Backend) buildGolden(ctx context.Context, key, dir string, s backend.Spec, vcpus, mem int, size int64, ds *diskStore) (g *goldenInfo, err error) {
	t0 := time.Now()
	// Short paths: the jail's unix sockets must stay under the 108-byte sun_path limit.
	build := filepath.Join(filepath.Dir(dir), ".b"+key[:8])
	_ = os.RemoveAll(build)
	if err := os.MkdirAll(build, 0o700); err != nil {
		return nil, fmt.Errorf("golden: %w", err)
	}
	var ref diskRef
	defer func() {
		if err != nil {
			_ = ds.remove(context.WithoutCancel(ctx), ref)
			_ = os.RemoveAll(build)
		}
	}()
	gid := "g" + key[:8]
	ws := filepath.Join(build, "w")
	root := jailRoot(ws, gid)
	if err := os.MkdirAll(root, 0o755); err != nil { //nolint:gosec // G301: inside the 0700 golden dir
		return nil, fmt.Errorf("golden: %w", err)
	}
	jid := jailID(gid)
	if err := os.Chown(root, jid, jid); err != nil {
		return nil, fmt.Errorf("golden: %w", err)
	}
	if err := b.linkBoot(root); err != nil {
		return nil, err
	}
	if ref, err = ds.newGolden(ctx, s.RootFS, filepath.Join(build, "disk.ext4"), size); err != nil {
		return nil, fmt.Errorf("golden disk: %w", err)
	}
	if err := ds.attachGolden(ref, filepath.Join(root, "disk.ext4"), jid); err != nil {
		return nil, err
	}
	gs := s
	gs.Hostname = "qt-golden"
	cfg, err := vmConfig(gs)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(root, "vm.json"), cfg, 0o444); err != nil { //nolint:gosec // G306: read by the jailed VMM
		return nil, fmt.Errorf("golden: %w", err)
	}
	bx := &box{id: gid, workspace: ws, meta: boxMeta{CPU: s.Limits.CPUMillis, Memory: s.Limits.MemoryBytes}}
	exited, err := b.launch(bx, "--config-file", "/vm.json", "--api-sock", "/api.sock", "--level", "Warning")
	if err != nil {
		return nil, err
	}
	stop := func() {
		killPID(bx.pid)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
		}
		_ = cgroups.Remove(filepath.Join(b.cfg.CgroupParent, containerID(gid)))
	}
	if err := b.waitAgent(ctx, bx, exited, 30*time.Second); err != nil {
		stop()
		return nil, err
	}
	api := newAPI(filepath.Join(root, "api.sock"))
	if err := api.patch(ctx, "/vm", map[string]any{"state": "Paused"}); err != nil {
		stop()
		return nil, err
	}
	err = api.put(ctx, "/snapshot/create", map[string]any{"snapshot_type": "Full", "snapshot_path": "/vmstate", "mem_file_path": "/mem"})
	stop() // never resumed: the disk stays exactly as the snapshot expects
	if err != nil {
		return nil, err
	}
	for _, f := range []string{"vmstate", "mem"} {
		if err := os.Rename(filepath.Join(root, f), filepath.Join(build, f)); err != nil {
			return nil, fmt.Errorf("golden: %w", err)
		}
		if err := os.Chown(filepath.Join(build, f), 0, 0); err != nil {
			return nil, fmt.Errorf("golden: %w", err)
		}
		if err := os.Chmod(filepath.Join(build, f), 0o444); err != nil { //nolint:gosec // G302: read by every restored VMM
			return nil, fmt.Errorf("golden: %w", err)
		}
	}
	if err := os.RemoveAll(ws); err != nil {
		return nil, fmt.Errorf("golden: %w", err)
	}
	if err := ds.seal(ctx, ref); err != nil {
		return nil, err
	}
	inputs, err := b.inputsHash()
	if err != nil {
		return nil, err
	}
	g = &goldenInfo{Key: key, RootFS: s.RootFS, Inputs: inputs, Disk: ref, VCPUs: vcpus, MemMiB: mem, Created: time.Now().UTC(), BuildMS: time.Since(t0).Milliseconds()}
	if ref.Path != "" {
		g.Disk.Path = filepath.Join(dir, "disk.ext4")
	}
	if err := writeJSON(filepath.Join(build, "meta.json"), g); err != nil {
		return nil, err
	}
	if err := os.Rename(build, dir); err != nil {
		return nil, fmt.Errorf("golden: %w", err)
	}
	g.dir = dir
	return g, nil
}

// linkBoot puts the kernel and initramfs into a jail root.
func (b *Backend) linkBoot(root string) error {
	initrd, err := cachedInitrd(filepath.Join(b.cfg.StateDir, "initrd"), b.cfg.AgentPath)
	if err != nil {
		return fmt.Errorf("firecracker: %w", err)
	}
	for src, dst := range map[string]string{b.cfg.Kernel: "vmlinux", initrd: "initrd.cpio"} {
		if err := linkOrCopy(src, filepath.Join(root, dst), 0o444); err != nil {
			return fmt.Errorf("firecracker: %w", err)
		}
	}
	return nil
}

// prepareRestore puts a golden snapshot and a fresh clone of its disk into a sandbox's jail.
func (b *Backend) prepareRestore(ctx context.Context, bx *box, g *goldenInfo, root string, jid int) error {
	for _, f := range []string{"vmstate", "mem"} {
		if err := linkOrCopy(filepath.Join(g.dir, f), filepath.Join(root, f), 0o444); err != nil {
			return fmt.Errorf("firecracker: %w", err)
		}
	}
	ds, err := b.diskStore(ctx)
	if err != nil {
		return err
	}
	ref, err := ds.clone(ctx, g.Disk, filepath.Join(root, "disk.ext4"), jid)
	if err != nil {
		return fmt.Errorf("firecracker: disk clone: %w", err)
	}
	bx.meta.Golden, bx.meta.Disk = g.Key, ref
	return nil
}

// restore starts a sandbox from its golden snapshot: an empty Firecracker loads the
// snapshot (memory mapped from the shared file, copy-on-write) and resumes it; then the agent
// is given the sandbox's own hostname, clock and entropy.
func (b *Backend) restore(ctx context.Context, bx *box, hostname string) error {
	exited, err := b.launch(bx, "--api-sock", "/api.sock", "--level", "Warning")
	if err != nil {
		return err
	}
	sock := filepath.Join(jailRoot(bx.workspace, bx.id), "api.sock")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case <-exited:
			return fmt.Errorf("firecracker: VMM exited before its API was up: %s", consoleTail(bx.workspace))
		case <-time.After(time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("firecracker: API socket did not appear")
		}
	}
	if err := newAPI(sock).put(ctx, "/snapshot/load", map[string]any{
		"snapshot_path": "/vmstate",
		"mem_backend":   map[string]any{"backend_type": "File", "backend_path": "/mem"},
		"resume_vm":     true,
	}); err != nil {
		return err
	}
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	req := agentproto.Request{Op: agentproto.OpConfigure, Configure: &agentproto.Configure{
		Hostname: hostname, UnixNano: time.Now().UnixNano(), Entropy: seed,
	}}
	var last error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if last = b.call(ctx, bx, req); last == nil {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("firecracker: VM exited after restore: %s", consoleTail(bx.workspace))
		case <-time.After(2 * time.Millisecond):
		}
	}
	return fmt.Errorf("firecracker: agent did not take its configuration: %w", last)
}

// call sends one request and reads its Result.
func (b *Backend) call(ctx context.Context, bx *box, req agentproto.Request) error {
	c, err := b.dial(ctx, bx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := agentproto.WriteJSON(c, agentproto.FrameRequest, req); err != nil {
		return err
	}
	_, err = readResult(c)
	return err
}

// pruneGoldens removes golden snapshots built from another kernel, agent or Firecracker
// (or too old to say): their keys can never be looked up again. Sandboxes restored from them keep working:
// their memory file is hard-linked into their jail, and thin snapshots don't need the origin.
func (b *Backend) pruneGoldens(ctx context.Context, keep *goldenInfo, ds *diskStore) {
	root := filepath.Dir(keep.dir)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == keep.Key || len(e.Name()) == 0 || e.Name()[0] == '.' {
			continue
		}
		dir := filepath.Join(root, e.Name())
		raw, err := os.ReadFile(filepath.Join(dir, "meta.json")) //nolint:gosec // G304: our golden dir
		if err != nil {
			continue
		}
		var old goldenInfo
		if json.Unmarshal(raw, &old) != nil || old.Inputs == keep.Inputs {
			continue
		}
		if err := ds.remove(ctx, old.Disk); err != nil {
			b.warn("prune golden snapshot disk", err)
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			b.warn("prune golden snapshot", err)
			continue
		}
		if b.cfg.Logger != nil {
			b.cfg.Logger.Info("pruned old golden snapshot", "key", old.Key)
		}
	}
}
