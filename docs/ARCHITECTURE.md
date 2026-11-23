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
  in `proto/qtd.proto` and has these calls: Create, Exec (streaming), CopyIn/CopyOut, Diff,
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

## Data dir

```
/var/lib/quarantine/
  images/<digest>/          unpacked OCI rootfs (gvisor) and rootfs.ext4 (vm), cached by digest
  golden/<digest>/          vm memory and disk snapshot ready to restore (M2-T2)
  sandboxes/<id>/
    meta.json               spec, backend, created-at, policy
    upper/                  writable copy-on-write layer (overlay upper or reflinked disk)
    events.jsonl            append-only event log
    honeytokens.json        the values planted in this sandbox (M4)
```

`qt rm` deletes `sandboxes/<id>` and every host resource tied to it: cgroup, netns, tap,
nftables sets, proxy and resolver. Tests check that nothing is left behind.

## Events

Each event is one JSON line with a versioned schema (`internal/events`, M0-T2). Every event
carries `v`, `id`, `ts`, `sandbox`, `kind` and `source` (host or guest), plus fields specific to
its kind. The kinds are `exec`, `file`, `net`, `dns`, `policy_denied` and `honeytoken`.

- In gvisor, events come from runsc runtime monitoring and the host.
- In vm, the agent reports exec events (proc connector) and file events (fanotify). These count
  as guest claims. Network and DNS events always come from the host.

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
| `proto/`, `internal/api` | qtd gRPC API | M0-T2 |
| `internal/backend` | Backend interface and capabilities | M0-T2 |
| `internal/events` | schema, validator, writer and reader | M0-T2 |
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
