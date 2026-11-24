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
  `upper/` gets the image root's mode, or the non-root user could not traverse `/`.
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
| `internal/backend/gvisor` | runsc backend | M1 |
| `internal/workspace` | copy-on-write upper dir, diff | M1-T2 |
| `internal/backend/firecracker`, `internal/agentproto` | vm backend, vsock protocol | M2 |
| `internal/netpol` | netns, nftables, resolver, SNI proxy | M3 |
| `internal/honeytoken` | plant and detect | M4-T1 |
| `internal/report` | compaction, Claude, rules, validator | M4-T2 |
| `internal/vet` | `qt run <git-url>` flow | M5 |
| `internal/mcp`, `sdk/python` | agent front door | M6-T2 |
| `internal/remote` | mTLS listener, cert pinning | M7 |

A package appears only when its task starts. No empty placeholder packages.
