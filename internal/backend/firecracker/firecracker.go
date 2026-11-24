// Package firecracker is the microVM isolation backend (--isolation=vm).
//
// Each sandbox is a Firecracker microVM started through Firecracker's jailer: the VMM runs
// chrooted in <workspace>/j/firecracker/qt-<id>/root as its own unprivileged uid, in a
// cgroup v2 under the qt parent (cpu, memory, pids), with Firecracker's own seccomp
// filters. The VM boots qt's guest kernel with an initramfs holding only the static
// qt-agent, whose stage-1 init mounts the sandbox's disk (a copy of the image's ext4) and
// switches into it. qtd talks to the agent over vsock (Firecracker's host-side unix socket
// with the CONNECT handshake), one connection per operation (internal/agentproto).
//
// The VM is configured from a file (--config-file): no API calls are needed to boot it, so
// qt does not use the Firecracker Go SDK.
package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/agentproto"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/cgroups"
)

// Config configures the backend.
type Config struct {
	Firecracker  string // firecracker binary (the jailer copies it into each chroot)
	Jailer       string // jailer binary
	Kernel       string // guest vmlinux (scripts/build-kernel.sh)
	AgentPath    string // static qt-agent binary (becomes the initramfs /init)
	StateDir     string // per-sandbox state and the initramfs cache; default /run/quarantine/fc
	CgroupParent string // default /quarantine
	// DataDir holds golden snapshots (<DataDir>/golden) and the thin pool (<DataDir>/thin).
	// Empty: every sandbox boots cold from a full disk copy.
	DataDir  string
	NoGolden bool // boot cold even with a DataDir
	Logger   *slog.Logger
}

// DefaultDiskBytes is a sandbox's disk size when the caller sets none (sparse on the host).
const DefaultDiskBytes = 4 << 30

// Backend implements backend.Backend with Firecracker microVMs.
type Backend struct {
	cfg   Config
	mu    sync.Mutex
	boxes map[string]*box

	goldenLocks sync.Map // key -> *sync.Mutex
	dsOnce      sync.Once
	ds          *diskStore
	dsErr       error
}

type box struct {
	id         string
	workspace  string
	meta       boxMeta
	pid        int
	exited     chan struct{}     // closed when the VMM exits; nil after a qtd restart
	sink       backend.EventSink // the sandbox's event log; nil after a qtd restart
	stopEvents context.CancelFunc
	events     guestStats
}

// boxMeta is saved as <workspace>/qt.json.
type boxMeta struct {
	Env      []string  `json:"env"`
	Workdir  string    `json:"workdir"`
	UID      uint32    `json:"uid"`
	GID      uint32    `json:"gid"`
	PIDs     int       `json:"pids"`
	CPU      int       `json:"cpu_millis"`
	Memory   int64     `json:"memory_bytes"`
	Hostname string    `json:"hostname"`
	Golden   string    `json:"golden,omitempty"` // restored from this golden snapshot
	Disk     diskRef   `json:"disk"`
	Net      *netMeta  `json:"net,omitempty"` // nil: --net=none (no NIC at all)
	Created  time.Time `json:"created"`
}

// netMeta is the VM's link: qtd's tap and the guest's addressing on it.
type netMeta struct {
	Tap     string `json:"tap"`
	Addr    string `json:"addr"`
	Gateway string `json:"gateway"`
}

func (n *netMeta) agent() *agentproto.Net {
	if n == nil {
		return nil
	}
	return &agentproto.Net{Addr: n.Addr, Gateway: n.Gateway}
}

// guestMAC is every VM's eth0 MAC (locally administered); each VM is alone on its tap.
const guestMAC = "06:00:ac:10:00:02"

// stateFile (<StateDir>/<id>.json) lets a restarted qtd find a running VM.
type stateFile struct {
	Workspace string `json:"workspace"`
	PID       int    `json:"pid"`
}

var _ backend.Backend = (*Backend)(nil)

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// New returns a Firecracker backend.
func New(cfg Config) (*Backend, error) {
	if cfg.StateDir == "" {
		cfg.StateDir = "/run/quarantine/fc"
	}
	if cfg.CgroupParent == "" {
		cfg.CgroupParent = "/quarantine"
	}
	for name, p := range map[string]string{"firecracker": cfg.Firecracker, "jailer": cfg.Jailer, "kernel": cfg.Kernel, "qt-agent": cfg.AgentPath, "state dir": cfg.StateDir} {
		if p == "" || !filepath.IsAbs(p) {
			return nil, fmt.Errorf("firecracker: %s path must be absolute, got %q", name, p)
		}
	}
	if filepath.Base(cfg.Firecracker) != "firecracker" {
		return nil, errors.New("firecracker: the jailer requires the VMM binary to be named firecracker")
	}
	return &Backend{cfg: cfg, boxes: map[string]*box{}}, nil
}

// Name implements backend.Backend.
func (*Backend) Name() backend.Isolation { return backend.IsolationVM }

// Capabilities implements backend.Backend. Snapshots, fork and events arrive in M2-T2/T3.
func (*Backend) Capabilities() backend.Capabilities {
	return backend.CapPTY | backend.CapGuestKernel
}

func containerID(id string) string { return "qt-" + id }

func jailRoot(ws, id string) string {
	return filepath.Join(ws, "j", "firecracker", containerID(id), "root")
}

// jailID is the unprivileged uid/gid the VMM runs as: distinct per sandbox, never a real user.
func jailID(id string) int { return 900_000 + int(crc32.ChecksumIEEE([]byte(id))%90_000) }

// LinkOwner is the uid sandbox id's VMM runs as: the owner of its tap (internal/netpol).
func (b *Backend) LinkOwner(id string) int { return jailID(id) }

func (b *Backend) statePath(id string) string { return filepath.Join(b.cfg.StateDir, id+".json") }

// Create implements backend.Backend: jail directory, kernel, initramfs, disk, VM config.
func (b *Backend) Create(ctx context.Context, s backend.Spec) (err error) {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("firecracker: %w", err)
	}
	if !s.Network.None && s.Network.TapDevice == "" {
		return fmt.Errorf("firecracker: a network link must be a tap device: %w", errors.ErrUnsupported)
	}
	if !hostnameRe.MatchString(s.Hostname) { // it goes on the kernel command line
		return fmt.Errorf("firecracker: invalid hostname %.64q", s.Hostname)
	}
	uid, gid, err := parseUser(s.User)
	if err != nil {
		return fmt.Errorf("firecracker: %w", err)
	}
	b.mu.Lock()
	if _, ok := b.boxes[s.ID]; ok {
		b.mu.Unlock()
		return fmt.Errorf("firecracker: sandbox %s already exists", s.ID)
	}
	bx := &box{id: s.ID, workspace: s.Workspace, meta: boxMeta{Env: s.Env, Workdir: s.Workdir, UID: uid, GID: gid, PIDs: s.Limits.PIDs, CPU: s.Limits.CPUMillis, Memory: s.Limits.MemoryBytes, Hostname: s.Hostname, Created: time.Now().UTC()}, sink: s.Events}
	if !s.Network.None {
		bx.meta.Net = &netMeta{Tap: s.Network.TapDevice, Addr: s.Network.Addr.String(), Gateway: s.Network.Gateway.String()}
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
	if err := writeJSON(filepath.Join(s.Workspace, "qt.json"), bx.meta); err != nil {
		return err
	}
	root := jailRoot(s.Workspace, s.ID)
	if err := os.MkdirAll(root, 0o755); err != nil { //nolint:gosec // G301: inside the 0700 workspace
		return fmt.Errorf("firecracker: jail: %w", err)
	}
	jid := jailID(s.ID)
	if err := os.Chown(root, jid, jid); err != nil { // the VMM creates its sockets here
		return fmt.Errorf("firecracker: jail: %w", err)
	}
	size := s.Limits.DiskBytes
	if size == 0 {
		size = DefaultDiskBytes
	}
	// Fast path: restore this image's golden snapshot onto a copy-on-write disk clone.
	if g := b.golden(ctx, s, size); g != nil {
		if err := b.prepareRestore(ctx, bx, g, root, jid); err != nil {
			return err
		}
		return writeJSON(filepath.Join(s.Workspace, "qt.json"), bx.meta)
	}
	// Cold boot: kernel + initramfs + a full disk copy.
	if err := b.linkBoot(root); err != nil {
		return err
	}
	disk := filepath.Join(root, "disk.ext4")
	if err := prepareDisk(ctx, s.RootFS, disk, size, jid); err != nil {
		return fmt.Errorf("firecracker: %w", err)
	}
	cfg, err := vmConfig(s)
	if err != nil {
		return fmt.Errorf("firecracker: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "vm.json"), cfg, 0o444); err != nil { //nolint:gosec // G306: read by the jailed VMM
		return fmt.Errorf("firecracker: vm config: %w", err)
	}
	return nil
}

func parseUser(u string) (uint32, uint32, error) {
	us, gs, ok := strings.Cut(u, ":")
	uid, err1 := strconv.ParseUint(us, 10, 32)
	gid, err2 := strconv.ParseUint(gs, 10, 32)
	if !ok || err1 != nil || err2 != nil || uid == 0 {
		return 0, 0, fmt.Errorf("user %q must be a non-root numeric uid:gid", u)
	}
	return uint32(uid), uint32(gid), nil
}

// vmConfig is the Firecracker --config-file. Paths are inside the jail's chroot.
func vmConfig(s backend.Spec) ([]byte, error) {
	vcpus := max(1, min(32, (s.Limits.CPUMillis+999)/1000))
	mem := max(128, int(s.Limits.MemoryBytes>>20))
	args := "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=4 i8042.noaux i8042.nomux i8042.dumbkbd " +
		"random.trust_cpu=on qt.hostname=" + s.Hostname
	cfg := map[string]any{
		"boot-source": map[string]any{"kernel_image_path": "/vmlinux", "initrd_path": "/initrd.cpio", "boot_args": args},
		"drives": []map[string]any{{
			"drive_id": "root", "path_on_host": "/disk.ext4", "is_root_device": false, "is_read_only": false,
		}},
		"machine-config": map[string]any{"vcpu_count": vcpus, "mem_size_mib": mem, "smt": false},
		"vsock":          map[string]any{"guest_cid": 3, "uds_path": "/v.sock"},
		"entropy":        map[string]any{},
	}
	if s.Network.TapDevice != "" { // no NIC at all with --net=none
		cfg["network-interfaces"] = []map[string]any{{"iface_id": "eth0", "guest_mac": guestMAC, "host_dev_name": s.Network.TapDevice}}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// Start implements backend.Backend: run the jailer (which becomes firecracker) and wait for
// the agent to answer a ping.
func (b *Backend) Start(ctx context.Context, id string) error {
	bx, err := b.lookup(id)
	if err != nil {
		return err
	}
	if bx.meta.Golden != "" {
		if err := b.restore(ctx, bx, bx.meta.Hostname); err != nil {
			return err
		}
	} else {
		exited, err := b.launch(bx, "--config-file", "/vm.json", "--api-sock", "/api.sock", "--level", "Warning")
		if err != nil {
			return err
		}
		if err := b.waitAgent(ctx, bx, exited, 30*time.Second); err != nil {
			return err
		}
		if bx.meta.Net != nil {
			req := agentproto.Request{Op: agentproto.OpConfigure, Configure: &agentproto.Configure{Hostname: bx.meta.Hostname, Net: bx.meta.Net.agent()}}
			if err := b.call(ctx, bx, req); err != nil {
				return fmt.Errorf("firecracker: guest network: %w", err)
			}
		}
	}
	b.subscribeEvents(bx) // guest exec/file events -> the event log
	return nil
}

// launch runs the jailer, which sets up the chroot, uid and cgroup and becomes firecracker
// with fcArgs.
func (b *Backend) launch(bx *box, fcArgs ...string) (chan struct{}, error) {
	if err := cgroups.EnsureParent(b.cfg.CgroupParent); err != nil {
		return nil, fmt.Errorf("firecracker: cgroup parent: %w", err)
	}
	cons, err := os.OpenFile(filepath.Join(bx.workspace, "console.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("firecracker: console log: %w", err)
	}
	defer func() { _ = cons.Close() }()
	jid := strconv.Itoa(jailID(bx.id))
	l := limitsFor(bx.meta)
	args := []string{
		"--id", containerID(bx.id), "--exec-file", b.cfg.Firecracker,
		"--uid", jid, "--gid", jid,
		"--chroot-base-dir", filepath.Join(bx.workspace, "j"),
		"--cgroup-version", "2", "--parent-cgroup", strings.TrimPrefix(b.cfg.CgroupParent, "/"),
		"--cgroup", "cpu.max=" + l.cpuMax, "--cgroup", "memory.max=" + l.memMax, "--cgroup", "pids.max=256",
		"--",
	}
	cmd := exec.Command(b.cfg.Jailer, append(args, fcArgs...)...) //nolint:gosec // G204: binaries from config, arguments built from validated values
	cmd.Stdout, cmd.Stderr = cons, cons
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("firecracker: start jailer: %w", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	b.mu.Lock()
	bx.pid, bx.exited = cmd.Process.Pid, exited
	b.mu.Unlock()
	if err := writeJSON(b.statePath(bx.id), stateFile{Workspace: bx.workspace, PID: cmd.Process.Pid}); err != nil {
		return nil, err
	}
	return exited, nil
}

// waitAgent waits for the booted agent to answer a ping.
func (b *Backend) waitAgent(ctx context.Context, bx *box, exited chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, perr := b.ping(pctx, bx)
		cancel()
		if perr == nil {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("firecracker: VM exited during boot: %s", consoleTail(bx.workspace))
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("firecracker: agent did not answer within 30s: %w; console: %s", perr, consoleTail(bx.workspace))
		}
	}
}

type vmLimits struct{ cpuMax, memMax string }

// limitsFor sizes the VMM's host cgroup: the guest's CPU share and memory plus the VMM's
// own overhead.
func limitsFor(m boxMeta) vmLimits {
	quota := int64(max(m.CPU, 100)) * 100   // per 100ms period
	mem := max(m.Memory, 128<<20) + 256<<20 // guest RAM + VMM overhead
	return vmLimits{cpuMax: strconv.FormatInt(quota, 10) + " 100000", memMax: strconv.FormatInt(mem, 10)}
}

func consoleTail(ws string) string {
	b, _ := os.ReadFile(filepath.Join(ws, "console.log")) //nolint:gosec // G304: our workspace
	if len(b) > 4096 {
		b = b[len(b)-4096:]
	}
	return strings.TrimSpace(string(b))
}

// lookup finds a sandbox, recovering it from the state file after a qtd restart.
func (b *Backend) lookup(id string) (*box, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bx, ok := b.boxes[id]; ok {
		return bx, nil
	}
	raw, err := os.ReadFile(b.statePath(id))
	if err != nil {
		return nil, fmt.Errorf("firecracker: sandbox %s: no such sandbox", id)
	}
	var st stateFile
	if err := json.Unmarshal(raw, &st); err != nil || !filepath.IsAbs(st.Workspace) {
		return nil, fmt.Errorf("firecracker: sandbox %s: bad state file", id)
	}
	bx := &box{id: id, workspace: st.Workspace, pid: st.PID}
	if raw, err := os.ReadFile(filepath.Join(st.Workspace, "qt.json")); err == nil {
		_ = json.Unmarshal(raw, &bx.meta)
	}
	b.boxes[id] = bx
	return bx, nil
}

// alive reports whether the sandbox's VMM is still running.
func (b *Backend) alive(bx *box) bool {
	if bx.exited != nil {
		select {
		case <-bx.exited:
			return false
		default:
			return true
		}
	}
	if bx.pid <= 0 {
		return false
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(bx.pid) + "/cmdline")
	// The jailer passes --id to firecracker: a recycled pid will not match.
	return err == nil && strings.Contains(string(cmdline), "\x00"+containerID(bx.id)+"\x00") // cmdline is NUL-separated
}

// dial opens a vsock connection to the agent through Firecracker's host-side socket.
func (b *Backend) dial(ctx context.Context, bx *box) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", filepath.Join(jailRoot(bx.workspace, bx.id), "v.sock"))
	if err != nil {
		return nil, fmt.Errorf("firecracker: vsock: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c, "CONNECT %d\n", agentproto.Port); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("firecracker: vsock connect: %w", err)
	}
	// "OK <port>\n", read byte by byte so nothing after it is buffered away.
	line := make([]byte, 0, 32)
	one := make([]byte, 1)
	for len(line) < 32 {
		if _, err := c.Read(one); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("firecracker: vsock handshake: %w", err)
		}
		if one[0] == '\n' {
			break
		}
		line = append(line, one[0])
	}
	if !strings.HasPrefix(string(line), "OK ") {
		_ = c.Close()
		return nil, fmt.Errorf("firecracker: vsock handshake: %.32q", line)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func (b *Backend) ping(ctx context.Context, bx *box) (agentproto.Result, error) {
	c, err := b.dial(ctx, bx)
	if err != nil {
		return agentproto.Result{}, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := agentproto.WriteJSON(c, agentproto.FrameRequest, agentproto.Request{Op: agentproto.OpPing}); err != nil {
		return agentproto.Result{}, err
	}
	return readResult(c)
}

// readResult reads a Result or Error frame (bounded: the agent is untrusted).
func readResult(r io.Reader) (agentproto.Result, error) {
	t, payload, err := agentproto.ReadFrame(r, 64<<10)
	if err != nil {
		return agentproto.Result{}, fmt.Errorf("agent: %w", err)
	}
	switch t {
	case agentproto.FrameResult:
		var res agentproto.Result
		return res, agentproto.Decode(payload, &res)
	case agentproto.FrameError:
		var e agentproto.Error
		_ = agentproto.Decode(payload, &e)
		return agentproto.Result{}, fmt.Errorf("agent: %.512s", e.Message)
	default:
		return agentproto.Result{}, fmt.Errorf("agent: unexpected frame %d", t)
	}
}

// Info implements backend.Backend.
func (b *Backend) Info(_ context.Context, id string) (backend.Info, error) {
	bx, err := b.lookup(id)
	if err != nil {
		return backend.Info{}, err
	}
	st := backend.StateStopped
	if b.alive(bx) {
		st = backend.StateRunning
	} else if bx.pid == 0 {
		st = backend.StateCreated
	}
	return backend.Info{ID: id, Isolation: backend.IsolationVM, State: st, CreatedAt: bx.meta.Created}, nil
}

// Destroy implements backend.Backend: kill the VMM, remove its cgroup and state. qtd
// removes the workspace (which holds the jail).
func (b *Backend) Destroy(ctx context.Context, id string) error {
	bx, err := b.lookup(id)
	if err != nil {
		return nil // unknown or already destroyed
	}
	b.mu.Lock()
	if bx.stopEvents != nil {
		bx.stopEvents()
	}
	b.mu.Unlock()
	if bx.pid > 0 && b.alive(bx) {
		killPID(bx.pid)
		if bx.exited != nil {
			select {
			case <-bx.exited:
			case <-time.After(10 * time.Second):
			}
		} else {
			for range 100 {
				if !b.alive(bx) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
	var errs []error
	if bx.meta.Disk.Kind == "thin" {
		if ds, err := b.diskStore(ctx); err == nil {
			if err := ds.remove(ctx, bx.meta.Disk); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := cgroups.Remove(filepath.Join(b.cfg.CgroupParent, containerID(id))); err != nil {
		errs = append(errs, err)
	}
	if err := os.Remove(b.statePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("firecracker: destroy %s: %w", id, err)
	}
	b.mu.Lock()
	delete(b.boxes, id)
	b.mu.Unlock()
	return nil
}

// Diff implements backend.Backend; the vm disk is a live guest filesystem, not inspected from the host yet.
func (*Backend) Diff(context.Context, string) ([]backend.Change, error) {
	return nil, fmt.Errorf("firecracker: diff: %w (the disk is a live guest filesystem; not inspectable from the host yet)", errors.ErrUnsupported)
}

// Snapshot implements backend.Backend.
func (b *Backend) Snapshot(context.Context, string, backend.SnapshotOptions) (backend.SnapshotRef, error) {
	return backend.SnapshotRef{}, backend.Require(b, backend.CapDiskSnapshot)
}

// Restore implements backend.Backend.
func (b *Backend) Restore(context.Context, backend.SnapshotRef, backend.Spec) error {
	return backend.Require(b, backend.CapDiskSnapshot)
}

// Fork implements backend.Backend.
func (b *Backend) Fork(context.Context, string, []backend.Spec) error {
	return backend.Require(b, backend.CapFork)
}

// diskStore opens the copy-on-write disk store once (it may set up the thin pool).
func (b *Backend) diskStore(ctx context.Context) (*diskStore, error) {
	b.dsOnce.Do(func() {
		if b.cfg.DataDir == "" {
			b.dsErr = errors.New("firecracker: no data dir for disks")
			return
		}
		b.ds, b.dsErr = newDiskStore(context.WithoutCancel(ctx), b.cfg.DataDir)
		if b.dsErr != nil {
			b.warn("copy-on-write disks", b.dsErr)
			b.dsErr = nil // the copy store still works
		}
		if b.cfg.Logger != nil && b.ds != nil {
			b.cfg.Logger.Info("vm disks", "kind", b.ds.kind)
		}
	})
	return b.ds, b.dsErr
}

// Close releases host resources the backend set up for disks (the thin pool's device and
// loop devices). Sandboxes must be destroyed first; qtd itself keeps the pool for its life.
func (b *Backend) Close(ctx context.Context) error {
	if b.ds == nil {
		return nil
	}
	return b.ds.close(ctx)
}
