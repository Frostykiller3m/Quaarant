package gvisor

import (
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// Paths inside the sandbox owned by qt.
const (
	qtDir      = "/.qt"
	agentPath  = qtDir + "/qt-agent" // static qt-agent, bind-mounted read-only; runs as init
	defaultCwd = "/"
)

// deniedSyscalls are refused with EPERM inside the sandbox (on top of gVisor's own syscall
// surface and its host-side seccomp filter). Nothing a build or test suite needs, plenty that
// malware likes: kernel keyrings, BPF, module loading, namespaces, mounts, ptrace, clock changes.
var deniedSyscalls = []string{
	"acct", "add_key", "bpf", "clock_adjtime", "clock_settime", "delete_module",
	"finit_module", "init_module", "kexec_file_load", "kexec_load", "keyctl",
	"mount", "move_mount", "name_to_handle_at", "open_by_handle_at", "open_tree",
	"perf_event_open", "pivot_root", "process_vm_readv", "process_vm_writev", "ptrace",
	"quotactl", "reboot", "request_key", "setns", "settimeofday", "swapoff", "swapon",
	"syslog", "umount2", "unshare", "userfaultfd", "vhangup",
}

func seccompProfile() *specs.LinuxSeccomp {
	arch := specs.ArchX86_64
	if runtime.GOARCH == "arm64" {
		arch = specs.ArchAARCH64
	}
	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Architectures: []specs.Arch{arch},
		Syscalls: []specs.LinuxSyscall{{
			Names:    deniedSyscalls,
			Action:   specs.ActErrno,
			ErrnoRet: ptr(uint(1)), // EPERM
		}},
	}
}

func ptr[T any](v T) *T { return &v }

// noCaps is an empty, non-nil capability set: the process gets no capabilities at all.
func noCaps() *specs.LinuxCapabilities {
	return &specs.LinuxCapabilities{
		Bounding: []string{}, Effective: []string{}, Inheritable: []string{},
		Permitted: []string{}, Ambient: []string{},
	}
}

func parseUser(u string) (specs.User, error) {
	uidS, gidS, ok := strings.Cut(u, ":")
	uid, err1 := strconv.ParseUint(uidS, 10, 32)
	gid, err2 := strconv.ParseUint(gidS, 10, 32)
	if !ok || err1 != nil || err2 != nil {
		return specs.User{}, fmt.Errorf("user %q must be numeric uid:gid", u)
	}
	if uid == 0 {
		return specs.User{}, fmt.Errorf("sandboxes never run as root (uid 0)")
	}
	return specs.User{UID: uint32(uid), GID: uint32(gid)}, nil
}

// initUser is the (non-root) uid:gid of the sandbox init. It differs from the sandbox user, so
// sandboxed code without CAP_KILL cannot signal it (gVisor does not shield PID 1 from SIGKILL
// sent inside its own pid namespace, so `kill -9 1` would otherwise stop the sandbox).
func initUser(u specs.User) specs.User {
	id := uint32(65533)
	if u.UID == id {
		id = 65532
	}
	return specs.User{UID: id, GID: id}
}

func cgroupsPath(parent, id string) string {
	return parent + "/" + containerID(id)
}

// containerID is the runsc container id for a sandbox id.
func containerID(id string) string { return "qt-" + id }

// buildSpec turns a validated backend.Spec into the OCI runtime spec for the sandbox's init.
// rootfs is the writable overlay (image as read-only lower, sandbox upper dir).
func buildSpec(s backend.Spec, rootfs, agent, cgroupParent string) (*specs.Spec, error) {
	user, err := parseUser(s.User)
	if err != nil {
		return nil, err
	}
	l := s.Limits
	period := uint64(100_000)
	quota := int64(l.CPUMillis) * int64(period) / 1000
	mem := l.MemoryBytes
	pids := hostPidsLimit(l.PIDs)

	sp := &specs.Spec{
		Version:  specs.Version,
		Hostname: s.Hostname,
		Root:     &specs.Root{Path: rootfs, Readonly: false}, // lower image is read-only; writes land in upper/
		Process: &specs.Process{
			User:            initUser(user),
			Args:            []string{agentPath, "pause"},
			Env:             []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Cwd:             defaultCwd,
			Capabilities:    noCaps(),
			NoNewPrivileges: true,
			Rlimits:         rlimits(l.PIDs),
		},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
			// runsc puts an in-memory tmpfs on an empty /tmp unless the spec mounts /tmp itself.
			// Bind the overlay's own /tmp so /tmp writes land in upper/ where the host sees them.
			{Destination: "/tmp", Type: "bind", Source: rootfs + "/tmp", Options: []string{"rbind", "rw", "nosuid", "nodev"}},
			{Destination: agentPath, Type: "bind", Source: agent, Options: []string{"rbind", "ro", "nosuid", "nodev"}},
		},
		Linux: &specs.Linux{
			CgroupsPath: cgroupsPath(cgroupParent, s.ID),
			Resources: &specs.LinuxResources{
				CPU:    &specs.LinuxCPU{Quota: &quota, Period: &period},
				Memory: &specs.LinuxMemory{Limit: &mem, Swap: &mem}, // swap == limit: no swap
				Pids:   &specs.LinuxPids{Limit: &pids},
			},
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.MountNamespace},
				netns(s.Network),
			},
			Seccomp:       seccompProfile(),
			MaskedPaths:   []string{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"},
			ReadonlyPaths: []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"},
		},
		Annotations: map[string]string{"dev.quarantine.sandbox": s.ID},
	}
	if !s.Network.None { // qtd's resolver (DNS to any server reaches it anyway); not in upper/
		sp.Mounts = append(sp.Mounts, specs.Mount{
			Destination: "/etc/resolv.conf", Type: "bind",
			Source: resolvConfPath(s.Workspace), Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"},
		})
	}
	return sp, nil
}

func resolvConfPath(ws string) string { return ws + "/resolv.conf" }

// ResolvConf is the resolv.conf of a sandbox on a link: its gateway is qtd's resolver.
func ResolvConf(gw netip.Addr) []byte {
	return []byte("# qt: DNS is answered by qtd on the host (internal/netpol)\nnameserver " + gw.String() + "\noptions ndots:1 timeout:2 attempts:2\n")
}

// The process limit is enforced inside the sandbox with RLIMIT_NPROC (gVisor implements it:
// fork fails with EAGAIN). The host cgroup's pids.max also counts gVisor's own host threads
// (sentry, gofer, systrap stubs: roughly one per guest task plus a fixed set), so it gets
// headroom: hitting it would kill the whole sandbox instead of failing one fork.
func hostPidsLimit(guest int) int64 { return int64(guest)*2 + 256 }

func rlimits(pids int) []specs.POSIXRlimit {
	return []specs.POSIXRlimit{
		{Type: "RLIMIT_NOFILE", Hard: 65536, Soft: 65536},
		{Type: "RLIMIT_NPROC", Hard: uint64(pids), Soft: uint64(pids)}, //nolint:gosec // G115: Limits.Validate ensures pids >= 8
	}
}

// execProcess builds the OCI process for `runsc exec --process`. Passing a JSON process (rather
// than argv on the command line) means untrusted argv can never be parsed as runsc flags.
func execProcess(base *specs.Process, sandboxEnv []string, sandboxCwd string, e backend.ExecSpec) (*specs.Process, error) {
	if len(e.Argv) == 0 {
		return nil, fmt.Errorf("exec: argv is empty")
	}
	user := base.User
	if e.User != "" {
		u, err := parseUser(e.User)
		if err != nil {
			return nil, err
		}
		user = u
	}
	cwd := e.Workdir
	if cwd == "" {
		cwd = sandboxCwd
	}
	if cwd == "" {
		cwd = defaultCwd
	}
	p := &specs.Process{
		Terminal:        e.TTY,
		User:            user,
		Args:            e.Argv,
		Env:             mergeEnv(sandboxEnv, e.Env),
		Cwd:             cwd,
		Capabilities:    noCaps(),
		NoNewPrivileges: true,
		Rlimits:         base.Rlimits,
	}
	if e.TTY && e.Size != nil {
		p.ConsoleSize = &specs.Box{Height: uint(e.Size.Rows), Width: uint(e.Size.Cols)}
	}
	return p, nil
}

// mergeEnv applies over on top of base (KEY=VALUE; later keys win), keeping first-seen order.
func mergeEnv(base, over []string) []string {
	idx := map[string]int{}
	var out []string
	for _, kv := range append(append([]string{}, base...), over...) {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := idx[k]; ok {
			out[i] = kv
			continue
		}
		idx[k] = len(out)
		out = append(out, kv)
	}
	return out
}

// netns is a fresh, empty network namespace (--net=none), or the one qtd prepared.
func netns(n backend.Network) specs.LinuxNamespace {
	if n.None {
		return specs.LinuxNamespace{Type: specs.NetworkNamespace}
	}
	return specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: n.NetnsPath}
}
