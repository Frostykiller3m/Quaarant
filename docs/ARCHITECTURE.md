# Architecture

quarantine (`qt`) runs untrusted code in a throwaway sandbox, watches it from the host, and
reports what it did. This document covers the overall design. `docs/BUILD_PLAN.md` says when each
piece gets built.

## Components

```
 ┌────────────┐   gRPC over unix socket      ┌──────────────────────────────────────────┐
 │  qt (CLI)  │ ───────────────────────────▶ │ qtd (daemon, root, systemd)              │
 │  cobra     │   (mTLS TCP with --host, M7) │  ├─ sandbox registry + data dir          │
 └────────────┘                              │  ├─ image store (OCI pull, ext4 convert) │
 ┌────────────┐                              │  ├─ events: collector → events.jsonl     │
 │ qt mcp /   │ ──── same API ─────────────▶ │  ├─ netpol: resolver, nftables, SNI proxy│
 │ Python SDK │                              │  ├─ honeytokens                          │
 └────────────┘                              │  └─ Backend interface                    │
                                             │       ├─ gvisor      (runsc, OCI bundle) │
                                             │       └─ firecracker (jailer + VMM)      │
                                             └──────────────┬───────────────────────────┘
                                                            │ vsock (vm only)
                                                   ┌────────▼────────┐
                                                   │ qt-agent (guest)│ static, CGO_ENABLED=0
                                                   │ exec/files/sig  │ events: exec, file
                                                   └─────────────────┘
```

- **qt** is a thin CLI. It parses flags, calls qtd, and renders output. It holds no sandbox state.
- **qtd** owns every sandbox. It listens on `/run/quarantine/qtd.sock` and checks the caller's
  peer credentials (SO_PEERCRED: the caller must be root or in the `quarantine` group). The API is
  in `proto/qtd/v1/qtd.proto` (service `qtd.v1.SandboxService`) and has these calls: Create, Exec (streaming), CopyIn/CopyOut, Diff,
  Events (stream), Snapshot, Fork, Destroy, List.
- **qt-agent** runs inside the microVM as PID 1's child and talks to qtd over vsock. It is
  untrusted once guest code has run. qtd validates every message, limits message sizes, and
  never takes network facts from it.

## Isolation levels

| `--isolation` | Mechanism | Strengths | Limits |
|---|---|---|---|
| `gvisor` | runsc (user-space kernel) in an OCI bundle | Works with no KVM, starts fast, monitors syscalls at runtime | Bugs in the gVisor kernel affect the shared host |
| `vm` | Firecracker microVM, guest kernel built by us, jailer | A hardware boundary, memory snapshots, fork | Needs `/dev/kvm` (nested virtualization in WSL2) |

Both backends implement `internal/backend.Backend` and declare capability flags such as
`MemorySnapshot` and `Fork`. The CLI checks those flags and never assumes a feature exists.
The two backends share integration tests, so the same command behaves the same on both.

### gvisor backend (M1-T1)

- **Root filesystem.** The cached image rootfs is the read-only lower layer of a host overlayfs;
  `sandboxes/<id>/upper` receives every write, so the host sees changes without asking the guest.
  runsc runs with `--overlay2=none` (no in-memory overlay). gVisor puts a tmpfs on an empty `/tmp`
  by default, so the spec bind-mounts the overlay's own `/tmp` to keep `/tmp` writes visible too.
  `upper/` gets the image root's mode, or the non-root user could not traverse `/`. The overlay
  is mounted with `metacopy=off,redirect_dir=off`, so `upper/` holds full file contents and plain
  directories, and the diff can rely on it.
- **File access.** The root mount uses `--file-access=shared`. With `exclusive`, gVisor caches
  failed lookups, so a file copied in after the sandbox looked for it stays invisible (measured).
  Sandbox writes reach `upper/` immediately in either mode.
- **Init.** The sandbox's PID 1 is the static `qt-agent pause`, bind-mounted read-only at
  `/.qt/qt-agent`. It reaps orphans and ignores signals. It runs as its own non-root uid (65533),
  because gVisor does not shield PID 1 from `kill -9` inside its pid namespace; with a different
  uid and no `CAP_KILL`, sandboxed code cannot stop the sandbox. User commands use `runsc exec
  --process <json>`, so untrusted argv is never parsed as runsc flags.
- **Least privilege.** The sandbox user is the image's user when it is a resolvable non-root
  user, else `65534:65534`. Every process has empty capability sets, `no_new_privs`, an OCI seccomp
  profile enforced inside the sandbox (`--oci-seccomp`; denies ptrace, bpf, keyrings, mount,
  namespaces, module loading, clock changes), and `--network=none`.
- **Limits.** cgroup v2 at `/quarantine/qt-<id>`: `cpu.max`, `memory.max` (no swap), `pids.max`.
  The host `pids.max` counts gVisor's own threads (sentry, gofer, systrap stubs), so the guest
  process limit is enforced inside with `RLIMIT_NPROC` (fork fails with EAGAIN). The host
  `pids.max` is `2×limit+256` as a backstop; hitting it would kill the whole sandbox.
- **Restart.** runsc state lives in `/run/quarantine/runsc`. A restarted qtd finds running
  sandboxes again via `runsc state` (the bundle holds `qt.json`). After a host reboot they are
  `stopped`, and `qt rm` cleans them up.

### vm backend (M2-T1)

```
 qtd ──jailer──▶ firecracker (chroot <ws>/j/firecracker/qt-<id>/root, own uid, cgroup, seccomp)
  │                  │ boots vmlinux (qt kernel) + initrd.cpio (/init = qt-agent), disk.ext4 = /dev/vda
  │                  ▼
  └──vsock (v.sock, "CONNECT 1024")──▶ guest PID 1: qt-agent init2 ──▶ child: qt-agent serve
                                                                        └─ spawn (drop privileges) ─▶ command
```

- **Guest kernel.** `scripts/build-kernel.sh` (`make kernel`) builds a pinned Linux 6.18 LTS
  (Firecracker v1.18 supports 6.18 guests until 2028; its 6.1 support has ended).
  `kernel/guest-x86_64.config` is merged on `make tinyconfig`: virtio-mmio, block, vsock,
  entropy, ext4, initramfs, pty, serial console, KVM guest, ACPI, seccomp, IPv4/IPv6 without
  the automatic `sit0` tunnel. No modules. The script checks that every option survived
  Kconfig, pins the tarball's sha256, and fixes all build metadata: two builds give the same
  vmlinux (checked).
- **Disk.** `image.Store.Ext4` builds `rootfs.ext4` once per digest with `mkfs.ext4 -d`
  (UUID and directory-hash seed from the digest, fixed times). Each sandbox gets a copy (a
  reflink where the filesystem supports it), grown sparse to 4 GiB.
- **Agent delivery.** qtd writes an initramfs holding only the static qt-agent (cached by its
  hash). Stage 1 (`/init`) mounts `/dev/vda`, mounts a tmpfs at `/.qt`, copies itself there and
  switches root, so qt's binary is never written to the sandbox's disk. Stage 2 (PID 1, root)
  mounts `/proc`, `/sys`, `/dev/pts` and `/dev/shm`, sets the hostname from `qt.hostname=`,
  brings up `lo`, reaps orphans, ignores signals, and supervises `qt-agent serve`.
- **Least privilege in the guest.** Every command goes through `qt-agent spawn` on one locked
  OS thread: `RLIMIT_NPROC`, `no_new_privs`, an empty capability bounding set,
  `setgroups([])`/`setgid`/`setuid` to the sandbox user, then a seccomp filter (the gvisor
  deny-list plus the new mount API, from x/sys's syscall tables), then `execve`. The VMM itself
  runs under the jailer (chroot, uid 900000+, cgroup v2 `cpu.max`/`memory.max`/`pids.max`) with
  Firecracker's own seccomp filters.
- **Protocol.** `internal/agentproto` uses length-prefixed frames (max 1 MiB) with a JSON
  request first, one vsock connection per operation (exec with stdio/TTY/resize/signals, copy
  in/out, ping). Everything the agent sends is untrusted: frames are bounded, exit codes
  clamped, and copy-out tars go through the same safe unpacker as everywhere else.
- **Parity.** `internal/backend/backendtest` is one integration suite that both backends
  pass: user, capabilities, `no_new_privs`, seccomp, hostname, loopback only, process limit,
  read-only image, env/cwd, init that can't be killed from inside, TTY, signals, cancel,
  copy in/out, exit 127 for a missing command.
- qt boots from a `--config-file`, not the Firecracker Go SDK (no API calls are needed, and
  the SDK would add about 30 modules).

## qtd and its socket

qtd runs as root under systemd (`contrib/systemd/qtd.service`, `make install`). It listens on
`/run/quarantine/qtd.sock`, mode `0660 root:quarantine`. The gRPC transport credentials read
`SO_PEERCRED` during the handshake. They admit root, qtd's own uid, and members of the
`quarantine` group (primary gid, or a supplementary group from `/proc/<pid>/status`); every other
peer is dropped before any RPC is read. Every request field is validated and size-bounded
before it reaches a backend.

## Data dir

```
/var/lib/quarantine/                (0700 root)
  images/sha256-<hex>/      cached by manifest digest; appears only by atomic rename after unpack
    rootfs/                 unpacked image (gvisor lower layer); rootfs.ext4 for vm (M2)
    config.json, image.json image config; what was pulled from where
  golden/<digest>/          vm memory and disk snapshot ready to restore (M2-T2)
  sandboxes/<id>/
    meta.json               image, isolation, user, env, limits, labels, created-at
    upper/, work/           writable overlay layer (or reflinked disk for vm)
    rootfs/                 overlay mount point (gvisor)
    bundle/                 OCI config.json + qt.json (gvisor)
    exec/, init.log         per-exec process specs; runsc create output
    events.jsonl            append-only event log
    honeytokens.json        the values planted in this sandbox (M4)
```

Image layers are untrusted. Unpacking goes through an `os.Root`, so no entry name, symlink or hard
link can reach outside the rootfs. Device nodes and fifos are skipped, setuid/setgid bits are
dropped, and total size and entry count are bounded.

## Workspace: diff and copy (M1-T2)

`internal/workspace` reads a sandbox's layers from the host, never from the guest.

- **Diff** walks `upper/` against the image (`lower`). A 0/0 char device is a deleted entry (all
  of its lower contents are reported deleted); an opaque directory hides the lower one, so its
  lower-only entries are deleted; anything else is added or modified. A copy-up with the same
  content, mode and owner is not reported. Regular files carry size and sha256, symlinks their
  target. qt's `/.qt` is hidden, and runtime mount points (`/proc`, `/dev`, `/tmp`, ...) are not
  reported as created, so a fresh sandbox diffs empty. At most 100k changes (`truncated`).
- **Untrusted names.** Everything in `upper/` was written by sandboxed code. The walk uses
  `os.Root` and follows nothing. Files are opened `O_NOFOLLOW|O_NONBLOCK` (a planted fifo can't
  hang qtd) and must be the inode that was listed. Names reach the API as data: non-UTF-8 names
  travel as raw bytes next to a lossy string, and `qt diff` quotes names with control
  characters, so escape sequences never reach the terminal.
- **Copy in** extracts a tar through the merged overlay with the same safe unpacker as images.
  It resolves the destination inside the sandbox's root (planted symlinks can't redirect it to
  the host), makes the sandbox user the owner of every entry, and drops setuid bits and device
  nodes. **Copy out** writes a tar the same careful way (symlinks stored, never followed;
  special files skipped). `qt cp` unpacks it on the host with the safe unpacker, so output can't
  land outside the destination directory.

`qt rm` deletes `sandboxes/<id>` and every host resource tied to it: cgroup, netns, tap,
nftables sets, proxy and resolver. Tests check that nothing is left behind.

## Events

Each event is one JSON line with a versioned schema: `internal/events/schema/v1.json` (JSON Schema
2020-12), with examples in `internal/events/examples/`. Every event
carries `v`, `id`, `ts`, `sandbox`, `kind` and `source` (host or guest), plus fields specific to
its kind. The kinds are `exec`, `file`, `net`, `dns`, `policy_denied` and `honeytoken`.

- In gvisor, events come from runsc runtime monitoring and the host.
- In vm, the agent reports exec events (proc connector) and file events (fanotify). These count
  as guest claims. Network and DNS events always come from the host.
- The schema enforces this: a `net`, `dns`, `policy_denied` or honeytoken-egress event with
  `source: guest` is invalid. Every string and array has a size limit, unknown fields are
  rejected, and a line may be at most 256 KiB.
- Versioning: `v` is the major version. Within v1, only new optional fields may be added. Any
  other change makes v2, with a new `schema/v2.json`, and readers accept both versions while
  the migration runs.
- The gRPC `Events` stream carries the validated JSON bytes unchanged. Only one definition of
  the format exists.
- Schema v1.1 (additive): `exec.sha256` (of the executed binary) and `errno` on `file` and
  `net`. Failed attempts are evidence too: a denied read of `/etc/shadow` is an event.

### gvisor event sources (M1-T3)

```
 sandboxed code ──syscalls──▶ sentry (gVisor kernel) ──seqpacket──▶ qtd monitor ─┐
                                   │ writes via gofer                             ├─▶ eventLog ─▶ events.jsonl
                                   ▼                                              │   (validate, rate/size cap)
                          host overlay upper/ ──inotify──▶ qtd watcher ──────────┘          │
 qt exec / qt run ─▶ qtd ─▶ runsc exec (qtd records the exec itself) ─────────────┘   Events RPC ─▶ qt events -f
```

- **Runtime monitoring.** Before `runsc create`, qtd listens on `sandboxes/<id>/monitor.sock`
  (SOCK_SEQPACKET) and passes `--pod-init-config` with a trace session. runsc connects from
  outside the sandbox before any sandboxed code runs; qtd accepts that one connection and
  removes the socket. Points: `sentry/execve` (with binary sha256), `syscall/open|openat|creat`,
  `syscall/write|writev|pwrite*` (`fd_path`), `syscall/connect`, `syscall/socket` (socket type),
  `syscall/close` and `sentry/exit_notify_parent` (to flush writes). The wire format and protos
  are gVisor's (vendored in `third_party/gvisor`, generated into `internal/gvisorpb`).
- **Source.** These events are `host`. The sentry runs on the host and is not under the
  sandboxed code's control, although every value in them (paths, argv, addresses) was chosen
  by that code. They are bounded to schema limits and treated as data.
- **What the sentry can't name.** runsc has no trace points with paths for unlink, rename,
  mkdir, symlink or chmod (only raw syscall numbers). Those come from an inotify watcher on the
  overlay's `upper/`: a whiteout is an unlink, an entry the image has is a copy-up (not
  reported), anything else is new. They have no pid. Watches go through `os.Root` and
  `/proc/self/fd`, so a planted symlink can't redirect them, and there are at most 16384 per sandbox.
- **Shaping.** Opens of directories, `O_PATH` and `/dev/null`/terminals are dropped, and so is
  qt's own init (pid 1). Writes are summed per process and file and reported on close, on exit,
  or after 2 s, so an event's time is when it was flushed. A command qtd starts with `runsc exec`
  has no `execve`, so qtd records it (pid from runsc, `ppid: 0`). `qt cp` suppresses the watcher
  for its target, so qt's own copies are not sandbox activity.
- **Limits.** The event log validates every event (about 37 µs each), allows 2000 events/s per
  sandbox with a burst of 20000, and caps `events.jsonl` at 512 MiB. The sentry retries for up
  to about 20 ms before it drops an event (so a flood slows the sandbox down), and dropped
  counts are logged.

## Network policy (host side)

Each sandbox gets its own netns and veth, or a tap for vm. The `--net` flag takes one of these
modes:

- `none`: no interface besides loopback.
- `log`: full egress, but every connection is recorded.
- `allow:<domains>`: traffic follows this path: guest DNS → per-sandbox resolver (answers only for
  allowed names and logs every query) → the returned IPs go into nftables sets with TTL expiry →
  TCP is redirected to a transparent proxy → the proxy checks TLS SNI or the HTTP Host header
  against the allow-list → if it matches, the proxy splices the connection.

In every mode, LAN, host, link-local and cloud metadata addresses are unreachable.

## Honeytokens and report

- **Honeytokens (M4-T1).** qtd plants a unique fake SSH key, AWS credentials, `.env` keys and a
  browser cookie DB in each sandbox. A read of one is an event. If a token turns up in DNS, SNI
  or plaintext egress, that is a red-flag event.
- **Report (M4-T2).** The pipeline compacts the events, then asks Claude for findings through a
  forced tool call with a strict schema. Event data goes to Claude as escaped, untrusted data.
  A validator drops any finding whose evidence ids are missing or of the wrong kind. Without an
  API key, a rule-based fallback produces the findings instead. The verdict is one of `clean`,
  `suspicious` or `malicious`.

## Package map

| Package | Purpose | Arrives |
|---|---|---|
| `cmd/qt`, `cmd/qtd`, `cmd/qt-agent` | thin `main` packages | M0-T1 |
| `internal/version` | build metadata (ldflags) | M0-T1 |
| `internal/cli` | cobra commands | M0-T1 |
| `proto/qtd/v1`, `internal/api/qtd/v1` | qtd gRPC API (generated code committed) | M0-T2 |
| `internal/backend`, `internal/backend/fake` | Backend interface, capabilities, in-memory fake | M0-T2 |
| `internal/events` | schema, types, validator (M0-T2); writer and follow reader (M1-T3) | M0-T2 |
| `internal/doctor` | host capability checks | M0-T2 |
| `internal/daemon` | qtd server, registry, socket auth | M1-T1 |
| `internal/image` | OCI pull/unpack, ext4 conversion | M1-T1 / M2-T1 |
| `internal/backend/gvisor` | runsc backend; runtime-monitoring server (M1-T3) | M1 |
| `internal/gvisorpb`, `third_party/gvisor` | gVisor monitoring protos (vendored) and generated Go | M1-T3 |
| `internal/agent` | qt-agent code (gvisor init: `qt-agent pause`) | M1-T1 |
| `internal/workspace` | upper-dir diff, tar out, inotify watcher (M1-T3) | M1-T2 |
| `internal/backend/firecracker`, `internal/agentproto` | vm backend (jailer, initramfs, disks), vsock protocol | M2-T1 |
| `internal/backend/backendtest` | integration suite every backend passes | M2-T1 |
| `internal/safetar` | untrusted tar in/out (stdlib only: used by qt-agent too) | M2-T1 |
| `internal/cgroups` | the cgroup v2 parent for sandboxes | M2-T1 |
| `scripts/build-kernel.sh`, `kernel/` | reproducible guest kernel | M2-T1 |
| `internal/netpol` | netns, nftables, resolver, SNI proxy | M3 |
| `internal/honeytoken` | plant and detect | M4-T1 |
| `internal/report` | compaction, Claude, rules, validator | M4-T2 |
| `internal/vet` | `qt run <git-url>` flow | M5 |
| `internal/mcp`, `sdk/python` | agent front door | M6-T2 |
| `internal/remote` | mTLS listener, cert pinning | M7 |

A package appears only when its task starts. No empty placeholder packages.
