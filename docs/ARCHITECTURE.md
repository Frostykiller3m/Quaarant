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

### vm fast start (M2-T2)

- **Golden snapshot.** The first sandbox of an image and VM shape boots a VM normally, waits
  for its agent, pauses it, and has Firecracker write a full snapshot (`vmstate`, `mem`). The
  VM is never resumed, so its disk stays exactly as the snapshot expects. It is keyed by image
  disk, kernel, agent and Firecracker binary hashes, vCPUs, memory and disk size. Building a new
  golden prunes older ones of the same image and shape.
- **Restore.** Every later sandbox hard-links `vmstate` and `mem` into its own jail and gets a
  copy-on-write clone of the golden disk. An empty Firecracker loads the snapshot (memory
  mapped from the shared file, private copy-on-write) and resumes it. Then the agent's
  `configure` sets the sandbox's hostname, wall clock and extra entropy. Firecracker also bumps
  the VMGenID, so the guest kernel reseeds its RNG (tested: two restores read different random
  bytes). The vsock listener survives the restore.
- **Copy-on-write disks.** A reflink where the data dir's filesystem supports it (btrfs, xfs),
  else a device-mapper thin pool: two sparse files on loop devices, one thin volume per golden
  disk, and an instant thin snapshot per sandbox, given to the jail as a block-device node. The
  pool keeps dm-thin's zeroing of new blocks, so no sandbox can read blocks freed by another.
  Plain copies are the last resort.
- **Numbers** (WSL2 on an i3-12100F, alpine, dm-thin, 10 runs; the CI `vm` job prints the same
  table for GitHub's runners):

  | step | p50 | p90 |
  |---|---|---|
  | create (thin snapshot of the disk, jail) | 28 ms | 41 ms |
  | restore (jailer, snapshot load, resume, configure) | 46 ms | 53 ms |
  | first exec (`true`) | 30 ms | 31 ms |
  | **restore-to-exec** | **76 ms** | **83 ms** |

  Across runs here the p50 stays at 76-86 ms; p90 ranged from 83 ms to 386 ms (one slow
  restore in ten in one run). The CI gate is on the p50.

  GitHub Actions ubuntu-24.04 runner (KVM, dm-thin), CI run 45379413309: create 20 ms, restore
  25 ms, first exec 21 ms, **restore-to-exec p50 47 ms / p90 49 ms**; golden build 13.6 s.

  Through qtd and the CLI, `qt run --rm --isolation=vm alpine -- true` takes 0.25–0.30 s
  (create + start + exec ≈ 120 ms, rm ≈ 170 ms); gvisor takes 0.14 s. A golden build is ~4 s
  per image. The image store remembers tag resolutions for 10 minutes and serves cached
  digests without asking the registry, which saved 0.5–1 s per `qt run`.

### vm events (M2-T3)

- **In the guest**, qt-agent watches exec with the kernel's proc connector (netlink; argv,
  path, cwd and uid read from `/proc`, parent pid tracked from fork events, the binary from
  fanotify's `FAN_OPEN_EXEC` if the process is already gone). It watches files with one
  fanotify group on the root filesystem (`FAN_REPORT_DFID_NAME`, paths resolved with
  `open_by_handle_at`): open, write (close after writing, size at processing time), create,
  mkdir, symlink, unlink, rename (`FAN_RENAME`) and chmod. The agent's own pids are never
  reported, so `qt cp` is not sandbox activity. Events queue in a bounded ring (8192) until
  qtd subscribes over vsock (`events`), and the ring is cleared when a snapshot is restored,
  so the golden VM's boot never shows up.
- **On the host**, qtd decodes them strictly and accepts only `exec` and `file`, written
  as `source: guest` (claims made inside the VM). Network, DNS, policy and honeytoken
  events from a guest are dropped and counted. With `--net=none` the VM has no network device,
  so there is no traffic to see; M3's tap devices are observed on the host.
- **Differences from gvisor** (whose events come from the runtime, `source: host`): a path
  is the file actually opened (symlinks resolved); failed opens are invisible to fanotify; a
  process that exits within a fraction of a millisecond has its exec reported without argv
  (`argv_truncated`), and argv is read from the live process, which can rewrite it (busybox
  `sleep 0.3` briefly does; `setproctitle` does on purpose); `write` carries the file's size,
  not the bytes written.

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
  golden/<key>/             vm snapshot of a booted image: vmstate, mem (+ disk.ext4 without thin)
  thin/                     dm-thin pool backing files (data.img, meta.img: sparse) and ids
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

### Links (M3-T1)

`internal/netpol` gives a sandbox with a network its own link. It also polices that link
without ever routing sandbox traffic.

- **The link.** A gVisor sandbox gets a namespace `<tag>-<id>` with a veth pair: `eth0`
  inside, `<tag>n<index>` on the host. runsc gets `--network=sandbox` at create and at start,
  and copies `eth0` into its netstack. A VM gets a persistent tap `<tag>n<index>`, owned by its
  jailed VMM's uid. Each link is a `/30` from the pool (default `10.231.0.0/16`): the host side
  is `.1` and is the guest's gateway, the guest is `.2`. A pool that overlaps a host route is
  refused. The host side has no IPv6.
- **No routing.** IP forwarding is not needed, and forwarded traffic to or from links is
  dropped. One nftables table (`inet quarantine_<tag>`) matches links by name, so a sandbox
  needs no rules of its own:
  - IPv6 and packets with a spoofed source are dropped (a `fib` reverse-path check, and no
    local source addresses).
  - TCP to a forbidden destination is reset before anything else sees it. Forbidden means
    any local address of the host, the pool (other sandboxes), private, CGNAT and link-local
    ranges (cloud metadata), documentation, benchmarking, multicast and reserved space.
    Other protocols to those destinations are dropped.
  - Every other TCP connection is redirected to the sandbox's proxy on its gateway, and
    nothing else from a link may reach the host.
  - UDP and ICMP are dropped. DNS arrives with M3-T2's resolver.
- **The proxy** (in qtd, one listener per sandbox on `gateway:15001`) reads the original
  destination (`SO_ORIGINAL_DST`), checks it again against the forbidden list and the
  host's current addresses, then asks the `Policy` (M3-T2: allow-list, SNI, logging). It
  dials with a 10 s timeout and splices both directions. A refusal is a TCP reset. It
  allows 512 concurrent connections per sandbox.
- **vm.** A networked VM restores from a golden snapshot that has a NIC: `|net` in the key,
  built against its own tap, which stays down without a host address. `network_overrides`
  points `eth0` at the sandbox's tap. The agent's `configure` sets the address and default
  route with ioctls. A cold boot does the same after the agent is up. `--net=none` VMs have no
  NIC at all.
- **What the guest sees.** `eth0` with its `/30`, a default route, and a `resolv.conf`
  naming the gateway. Public TCP works, subject to the policy below. Everything forbidden is
  "connection refused" at once. UDP (except DNS), ICMP and IPv6 get no answer.

### Policy and records (M3-T2)

`qt run --net=log` or `--net=allow:pypi.org,files.pythonhosted.org`. A domain also allows
its subdomains. qtd attaches the link at create time and records it in the sandbox's record.
`qt rm` and failed creates detach it. A restarted qtd adopts every recorded link, prunes
links nothing owns, and replaces its nftables table in one transaction, so live sandboxes are
never without rules.

- **DNS.** UDP and TCP to port 53, to any server, are redirected to the sandbox's resolver
  on `gateway:15053`. For a permitted name, an A query is asked of the host's resolvers
  (`/etc/resolv.conf`) with a fresh query that carries nothing from the guest but the name.
  Answers are flattened to A records. Forbidden addresses are dropped (DNS rebinding to
  metadata, for example), and the guest is told TTL ≤ 300 s. Every returned address is
  remembered for its TTL (at least 1 minute, at most 1 hour). Other query types for a
  permitted name get an empty answer: no IPv6, and no HTTPS/SVCB records, so no ECH configs.
  A name outside the allow-list gets NXDOMAIN. Every query is a `dns` event, and each
  refusal also a `policy_denied` event.
- **TCP.** The proxy reads the client's first bytes: a TLS ClientHello, parsed by
  `crypto/tls`, or HTTP request headers. In allow mode it waits up to 10 s, in log mode up to
  2 s, so a server-first protocol is delayed by at most that. In allow mode a connection
  needs two things: the destination must be an address the resolver returned for a
  permitted name, and the SNI or Host must be permitted. Otherwise the reason is
  `direct_ip` or `sni_mismatch`. TLS without SNI or with an encrypted ClientHello is
  refused, as is any other protocol (`not_allowlisted`). The IP allow set lives in the
  proxy rather than in an nftables set: all TCP passes through the proxy anyway, and this
  way every refusal is seen and recorded. Log mode allows every public destination.
  Each connection is a `net` connect event, with the SNI or Host, and a close event with
  bytes and duration. A refusal is a `net` event with `allowed: false` plus a
  `policy_denied` event. All of these are `source: host`.
- **Kernel refusals.** Forbidden destinations (rejected TCP SYNs) and non-DNS UDP and ICMP
  are logged to an nflog group, rate-limited to 100/s with a burst of 200 per host. qtd
  maps each one to its sandbox by the incoming interface and records `policy_denied`
  (`metadata`, `blocked_range` or `not_allowlisted`) and `net` with `allowed: false`.
- **Measured.** A warm `qt run --rm --isolation=vm --net=allow:example.com alpine -- true`
  takes 0.39–0.49 s, against 0.34–0.39 s with `--net=none`. The first networked VM builds
  its own golden snapshot (about 5 s, once per image).

## Honeytokens and report

- **Honeytokens (M4-T1).** On by default for `qt run` (`--honeytokens=false` turns them off).
  qtd generates a fresh set per sandbox (`internal/honeytoken`) under the sandbox user's
  `$HOME`:
  - `.ssh/id_ed25519`: an OpenSSH-format key;
  - `.aws/credentials`: an `AKIA…` key ID and a secret;
  - `.env`: OpenAI, Stripe and GitHub-style keys and a database URL;
  - `.config/google-chrome/Default/Cookies`: a valid SQLite database whose `cookies` table
    has session cookies in the clear.

  They are planted right after start through the backend's `CopyIn` (the sandbox user's,
  0600, dated 37 days back) and saved in `honeytokens.json`. `qt diff` hides them while their
  content is unchanged.
  - **Read:** when the event log writes a `file` open of a token path, it adds a `honeytoken`
    event (`trigger: read`) that cites the file event (`related_event`) and keeps its
    source. That is host for gvisor and a guest claim for vm. One event per token and
    process.
  - **Egress** (host, red flags): the resolver checks every query name and the proxy every
    SNI (case-insensitive, dots ignored, so a value split over labels still matches). The
    proxy also checks the plaintext client-to-server stream of every non-TLS connection,
    including the first bytes of connections the policy refuses. Each value is matched raw,
    as hex, as base64 and base64url at every alignment, and as base32. A hit is a
    `honeytoken` event with `egress_dns`, `egress_sni` or `egress_plaintext` and the
    destination. The same sighting within 10 s is recorded once. TLS bodies are not
    inspected.
- **Report (M4-T2).** `qt report <id>` (`internal/report`) runs in the CLI, so the API key
  stays with the user and never reaches qtd. It reads the log over the Events RPC and
  validates every line again.
  - **Rules** always run: planted credentials read or sent out, persistence writes (shell
    start-up files, cron, services, SSH keys, git hooks, `crontab`/`systemctl enable`),
    miners (binaries, stratum arguments, pool names and ports), metadata probes, allow-list
    bypass attempts, many refused destinations, data-like DNS names, `curl | sh`, programs
    run from `/tmp`, and large uploads.
  - **Claude** runs when `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set and
    `--offline` isn't. It reads a compacted log: honeytoken and `policy_denied` events are
    always kept; execs are ordered as a process tree with repeats counted; file, net and dns
    repeats are collapsed; system-library opens and missing-file probes are dropped; long
    runs in one directory become one counted line; the whole is at most 1500 lines and
    300 KiB. The log goes between `<sandbox_events>` tags as JSON lines with `<`, `>` and `&`
    escaped, so sandbox text can't close the tag, and the system prompt says it is untrusted
    data. The model is `claude-opus-5-5` at effort `high`, with server-side refusal fallbacks
    (`fallbacks: "default"`). It answers through structured outputs (`output_config.format`,
    a strict JSON schema of verdict, summary and findings, each with title, severity,
    category, evidence and explanation): the model rejects a forced `tool_choice`, and
    structured outputs give the same schema guarantee.
  - **Validation:** a finding is dropped unless every cited id exists in the log and its kind
    fits the finding's category (a honeytoken event can't prove a miner). Text is stripped of
    control and format characters and bounded. The verdict is at least what the rules prove,
    and at most what the surviving findings support: critical means malicious, high or
    medium suspicious. A refusal, an error or an answer that isn't the schema falls back to
    rules only, with a note.

## Vetting a repository (M5-T1)

`qt run [--yes] [--offline] <git-url> [-- COMMAND]` (`internal/vet`) drives qtd's API from
the CLI:

1. **Clone in a sandbox.** A throwaway `alpine/git:v2.49.1` sandbox with `--net=allow:<git
   host>` and no honeytokens runs `git clone --depth 1 --no-tags --single-branch
   --no-recurse-submodules -- <url> /tmp/repo`. Repository hooks, file protocols and
   prompts are off. Only `https://` URLs with a domain host are accepted;
   `git@host:path` becomes https, since a sandbox has no SSH keys. The repository leaves as
   a tar stream (CopyOut), spooled to a private temporary file. On the host, only tar
   headers and bounded key files are read; nothing from the repository is unpacked or run
   there. The clone sandbox is then removed.
2. **Plan.** With an API key, Claude (`claude-opus-5-5`, structured outputs, refusal
   fallbacks) proposes an official image, setup and run steps, a network policy and
   risks. It sees the file list (400 entries at most) and the key files (README,
   manifests, CI workflows; 24 KiB each, 160 KiB in all), wrapped in `<repository>` as
   escaped JSON lines and declared untrusted. Without a key, the plan comes from the
   manifests: npm, pip/pyproject (with pytest when there are tests), Go, Cargo, Bundler,
   Make, a top-level script, or a listing. The plan is validated: a valid image
   reference, at most 10 setup and 5 run steps, commands without NUL and at most
   1000 bytes, and allow-list domains that are names, not addresses.
3. **Flag.** Rules flag the plan whoever wrote it, so a prompt-injected README can't talk
   its way past them:
   - non-official images and full-internet mode;
   - unknown allow-list domains;
   - `curl | sh`, decode-and-run, and `sudo`;
   - persistence writes, setuid bits, `rm -rf /` and raw sockets;
   - credential paths and unpinned URL installs;
   - dependency install scripts (a note).
4. **Approve.** The plan and its flags are printed. The user answers `y` at the terminal;
   `--yes` approves without asking, and with neither (for example no terminal) nothing
   runs. `--net` overrides the plan's network policy, and `-- COMMAND` replaces its run
   steps.
5. **Run and report.** A fresh sandbox (honeytokens planted, labelled `qt.vet`) receives the
   repository in `/tmp/repo` and runs each step there with `sh -c` (10 minutes each,
   `--step-timeout`), streaming output. The `qt report` result prints at the end. The exit
   status is 0 for clean, 2 for suspicious, 3 for malicious, and 1 if the plan was not
   approved. The sandbox is kept for `qt events` and `qt diff`, or removed with `--rm`.

## Red-team corpus (M5-T2)

`testdata/evil/` (21 repositories) and `testdata/normal/` (10) are vetted by
`TestITestCorpus` through the real flow:
- a local directory instead of a clone, then the offline plan;
- a gvisor sandbox with honeytokens and `--net=log`, so attempts reach the proxy and are
  recorded instead of being blocked before they happen;
- the rules-only report.

`testdata/corpus.json` gives each evil repository the verdicts it may get and the finding
categories it must have; normal repositories must be clean. The evil ones are harmless
stand-ins: what they "steal" is the planted fake data, and every destination is
`example.com`, `example.net` or a TEST-NET address.

| Behaviour | Repositories | Verdict, finding |
|---|---|---|
| Credentials sent out | `exfil-aws-http` (base64 POST), `exfil-dns-npm` (key id in a DNS name), `env-dns-hex` (hex piece of a key in a label), `cookie-stealer` (setup.py, SQLite to a URL), `prompt-injection-readme` | malicious: credential left, credentials read |
| Credentials read only | `ssh-key-over-tls` (TLS body not inspected), `env-reader-npm` | suspicious: credentials read |
| Miners | `miner-xmrig` (renamed binary, stratum arguments), `miner-pool-node` (pool name, port 3333) | malicious: miner ran / suspicious: pool traffic |
| Persistence | `cron-persistence`, `bashrc-persistence`, `authorized-keys`, `git-hook` | suspicious: persistence |
| Remote access | `revshell-nc`, `revshell-fifo` (npm postinstall), `revshell-python` (setup.py, `pty.spawn`) | malicious: reverse shell |
| Downloaders | `postinstall-curl-sh`, `dropper-hidden-tmp` | suspicious: downloaded and ran a script / hidden-path binary |
| Other | `dns-tunnel` (hex labels), `sandbox-detect-idle` (artifacts and `dmesg`, then idles), `metadata-probe` | suspicious: data-like DNS / evasion / metadata |

The normal repositories are clean, with between 8 and 14,477 events each: npm with and
without dependencies and a build step, pip with requirements, pyproject and a CLI (pytest
from PyPI), a Go module, shell build and system-inspection scripts, and docs only.

Rules added or tightened for it:
- reverse shells (`nc -e`, `/dev/tcp`, `socat exec:`, the mkfifo idiom, `pty.spawn`);
- sandbox and VM probing (container and DMI artifacts, opened or missing, and `dmesg`,
  `systemd-detect-virt`, `virt-what`; cgroup and cpuinfo reads are not counted);
- binaries only from hidden paths under `/tmp`, `/var/tmp` and `/dev/shm`, not build outputs
  such as `/tmp/go-build*` and `node_modules/.bin`;
- mining pools by operator name, not any `pool.` host;
- miner ports only for connections the proxy allowed.

The honeytoken matcher now finds any 20-byte piece of a secret, raw or encoded, because
exfiltration chunks values. It indexes windows by their first 8 bytes behind a 1 Mi-bit
filter, and scans at about 825 MB/s.

## Snapshots, restore and fork (M6-T1, vm)

- **`qt snapshot <id>`** pauses the VM (Firecracker `PATCH /vm Paused`), saves a Full
  snapshot (`vmstate` and `mem`), and captures the disk copy-on-write. On thin disks the
  volume is suspended for the instant of `create_snap`; otherwise it is reflinked or
  copied. The VM then resumes. `--no-memory` syncs the guest first (agent op `sync`) and
  keeps only the disk.
  - It lands in `<DataDir>/snapshots/sn-<12 hex>/`: `meta.json` (the backend's),
    `qt-snapshot.json` (the source sandbox's record) and `honeytokens.json`.
  - All-zero blocks of the memory file are punched out in the background, so an idle
    2 GiB VM's snapshot takes about 60 MiB instead of 2 GiB; golden snapshots do the same.
  - A memory snapshot restores only with the same kernel, agent and firecracker
    (`Inputs`).
  - `qt snapshot ls` and `qt snapshot rm` manage them. `qt rm` of the source leaves its
    snapshots alone.
- **`qt restore <snapshot>`** makes a new sandbox through the golden-restore path: the
  memory file is hard-linked and mapped copy-on-write, the disk is a copy-on-write clone,
  and `network_overrides` points the NIC at the new sandbox's tap. A disk-only snapshot
  boots its disk cold instead.
- **`qt fork <id> N`** is one memory snapshot and N restores. The snapshot is removed after;
  the children keep their hard links and their own disk snapshots. The source keeps
  running.
- **A fresh identity for every restored VM**, golden ones included: the agent's `configure`
  sets a new hostname, IP and default route on the sandbox's own link, a new random
  locally administered MAC (interface down, `SIOCSIFHWADDR`, up), and a new
  `/etc/machine-id`, and it writes 64 bytes of host entropy to `/dev/urandom`. VMGenID
  also makes the kernel reseed. Children share the source's honeytokens (their memory
  holds them), so those keep working.
- **`qt diff A B`** compares two running sandboxes. For files, each guest lists its
  filesystem (agent op `manifest`: path, type, mode, size, SHA-256 up to 64 MiB, link;
  `/proc`, `/sys`, `/dev`, `/run` and `/.qt` skipped; its own walk is not reported as file
  events). For behaviour, each event log is reduced to normalized facts (`exec …`,
  `write …`, `connect host:port`, `refused …`, `dns …`, `honeytoken …`, `denied …`) and
  the two sets are compared.
- **Measured** on this WSL machine: with 256 MiB VMs, a snapshot takes 272 ms, a restore
  128 ms and a fork of 3 576 ms. With 512 MiB, a fork of 3 takes 825 ms. With the default
  2 GiB, a snapshot takes 4.2 s, a fork of 3 2.6–4.4 s and a restore 106–187 ms. Snapshot
  time is Firecracker writing guest RAM, so use `--memory` for VMs you intend to fork.

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
| `internal/netpol` | sandbox links (netns/veth, tap), nftables, resolver, SNI/Host proxy, nflog refusals | M3 |
| `internal/report` | `qt report`: rules, compaction, Claude (structured outputs), evidence validation | M4-T2 |
| `internal/honeytoken` | per-sandbox fake credentials, SQLite cookie DB, matcher for raw and encoded values | M4-T1 |
| `internal/report` | compaction, Claude, rules, validator | M4-T2 |
| `internal/vet` | `qt run <git-url>`: clone in a sandbox, plan (Claude or manifests), flag, approve, run, report | M5-T1 |
| `internal/mcp`, `sdk/python` | agent front door | M6-T2 |
| `internal/remote` | mTLS listener, cert pinning | M7 |

A package appears only when its task starts. No empty placeholder packages.
