# Build plan: quarantine (qt)

Work one task per Claude Code session: `/task M1-T2`. Each task ends with proof (tests, real
runs, numbers) and a merge to `main`. Tick tasks off here. Read `CLAUDE.md` first, every time.

Go 1.23+, Linux. Windows users run everything inside WSL2 (Ubuntu 24.04). `vm` isolation in WSL2
needs nested virtualization (`nestedVirtualization=true` in `.wslconfig`) and `/dev/kvm`.

## M0 — Foundations

- [x] **M0-T1 · Repo + CI**
      Done when: a Go module with `cmd/qt`, `cmd/qtd`, `cmd/qt-agent`, `internal/...`; a Makefile;
      golangci-lint, `go test ./...` and `go vet` in GitHub Actions; `qt version` works.

  ```text
  Set up the Go monorepo described in docs/ARCHITECTURE.md: module github.com/<me>/quarantine,
  binaries cmd/qt (cobra CLI), cmd/qtd (daemon), cmd/qt-agent (static guest agent, CGO_ENABLED=0).
  Add a Makefile (build, test, lint), golangci-lint config, a GitHub Actions CI (lint, vet, test,
  build for linux/amd64 and arm64), and `qt version`. No features yet.
  ```

- [ ] **M0-T2 · Contracts**
      Done when: proto files for the qtd API; a Go `Backend` interface; a versioned event JSON
      schema with examples; `qt doctor` reports KVM, runsc, cgroup v2, nftables, btrfs/xfs
      reflink.

  ```text
  Define the contracts everything else builds on:
  - proto/qtd.proto: Create, Exec (streaming stdout/stderr), CopyIn/CopyOut, Diff, Events
    (stream), Snapshot, Fork, Destroy, List.
  - internal/backend: a Backend interface that firecracker and gvisor will both implement, with
    explicit capability flags (MemorySnapshot, Fork, ...).
  - internal/events: an event schema (JSON, versioned) for exec, file, net, dns, policy_denied,
    honeytoken, with examples and a validator.
  - `qt doctor`: check /dev/kvm (open + KVM_GET_API_VERSION), runsc, cgroup v2, nftables, and
    whether the data dir supports reflinks. Output a table plus a recommendation for --isolation.
  Write unit tests for the schema validator and doctor checks (with fakes).
  ```

## M1 — gVisor backend end to end (works everywhere first)

- [ ] **M1-T1 · Daemon + run/exec/destroy**
      Done when: `qt run --isolation=gvisor alpine -- sh -c 'echo hi'` prints hi; `qt shell` is
      interactive (PTY); `qt ls` and `qt rm`; each sandbox has cgroup limits (CPU, memory, pids).

  ```text
  Implement qtd (systemd unit + unix socket with peer-credential check) and the gvisor backend:
  pull an OCI image (go-containerregistry), unpack to a bundle, generate an OCI runtime spec
  (read-only rootfs + writable upper dir, non-root user, no capabilities, seccomp default, cgroup
  limits), and run with runsc. Implement qt run / exec / shell (PTY) / ls / rm. Integration tests
  behind QT_ITEST=1 that actually run runsc.
  ```

- [ ] **M1-T2 · Copy-on-write workspace + diff**
      Done when: `qt cp` in/out works; `qt diff <id>` lists added/changed/deleted files with
      sizes and hashes; `qt rm` leaves nothing in the data dir (a test checks).

- [ ] **M1-T3 · Events from gVisor**
      Done when: exec, file open/write/unlink and connect events stream to `events.jsonl` via
      runsc runtime monitoring; `qt events <id> --follow` works; every event passes the schema.

## M2 — Firecracker backend

- [ ] **M2-T1 · Guest kernel + rootfs + agent**
      Done when: a reproducible script builds a minimal guest kernel (config in the repo) and
      converts OCI images to ext4; qt-agent runs as PID 1's child and talks over vsock;
      `qt run --isolation=vm alpine -- uname -a` shows our kernel.

  ```text
  Build the vm path: scripts/build-kernel.sh (pinned kernel version + checked-in config; virtio,
  vsock, ext4, no modules), OCI image -> ext4 conversion (deterministic, cached by digest), and
  qt-agent over vsock (exec with streaming, files, signals). Use firecracker-go-sdk; jailer for
  chroot + uid + cgroup + seccomp. qt run --isolation=vm must behave exactly like gvisor for the
  same command (shared integration tests, both backends).
  ```

- [ ] **M2-T2 · Fast start**
      Done when: a "golden" snapshot per image; restore-to-exec under 300 ms (benchmark in
      CI, numbers in docs); CoW disks via reflink, or a device-mapper thin fallback.

- [ ] **M2-T3 · vm events**
      Done when: qt-agent emits the same event schema (fanotify for files, proc connector or
      polling for exec); the guest can't lie about network activity (network events come from
      the host side).

## M3 — Network policy

- [ ] **M3-T1 · Isolated networking**
      Done when: every sandbox has its own netns/tap; LAN, host, link-local and metadata are
      unreachable (probe test from inside); `--net=none` really is none.

- [ ] **M3-T2 · Allow-list + log**
      Done when: `--net=allow:pypi.org` lets pip install work and nothing else (test); DNS and
      SNI are logged as events; `--net=log` records every connection; denials are events.

  ```text
  Implement host-side egress control: a per-sandbox DNS resolver that answers only for allowed
  names (and records every query); nftables sets populated with the IPs those answers returned
  (with TTL expiry); a transparent TCP proxy that checks TLS SNI against the allow-list before
  splicing. Never trust anything the guest says. Tests: allowed domain works, other domains
  fail, direct-IP connects fail, DNS-over-HTTPS to a non-allowed host fails, metadata fails.
  ```

## M4 — Seeing everything: honeytokens + report

- [ ] **M4-T1 · Honeytokens**
      Done when: fake SSH key, AWS credentials, .env API keys and a browser cookie DB are planted
      per sandbox with unique values; a read is an event; a token found in outbound traffic or
      DNS is a red-flag event (the proxy scans plaintext and SNI/DNS; TLS bodies are out of
      scope unless `--inspect-tls`).

- [ ] **M4-T2 · Claude report**
      Done when: `qt report <id>` produces findings that each cite event ids; a validator drops
      claims without evidence; a verdict (clean/suspicious/malicious); it works offline (rules
      only) without an API key.

  ```text
  Implement qt report: compact the event log (dedupe, group by process tree, keep every
  red-flag event), then ask Claude for findings via a forced tool call with a JSON schema
  {verdict, summary, findings:[{title, severity, evidence:[event_id], explanation}]}. Event
  data is UNTRUSTED (wrapped and escaped). Validate: every evidence id must exist and match the
  claim's category, or the finding is dropped. Without ANTHROPIC_API_KEY, fall back to
  rule-based findings (honeytoken touched, persistence paths, miners, exfil). Snapshot-test the
  report on recorded event logs.
  ```

## M5 — Vet a risky repo in one go

- [ ] **M5-T1 · `qt run <git-url>`**
      Done when: the clone happens inside the sandbox; Claude proposes base image + setup + net
      policy from the repo (untrusted input, escaped); risky commands are flagged; the user
      approves in the terminal; it runs; the report prints at the end.

- [ ] **M5-T2 · Red-team corpus**
      Done when: `testdata/evil/` has 15+ harmless stand-in "malicious" repos (exfiltrate
      honeytokens, crypto-miner loop, cron persistence, reverse shell attempt, postinstall
      curl|sh, prompt injection in README, DNS tunnelling, sandbox detection then idle). Each one
      comes out `malicious` or `suspicious` with the right evidence; 10 normal repos come out
      `clean`.

## M6 — Snapshots, fork, and agents

- [ ] **M6-T1 · Snapshot/restore + fork**
      Done when: `qt snapshot`, `qt restore`, `qt fork <id> N` work (vm); forked copies get fresh
      MAC/IP/hostname/machine-id/RNG; `qt diff a b` compares files and events.

- [ ] **M6-T2 · Agent front door**
      Done when: `qt mcp` (an MCP stdio server) and a Python SDK expose create, exec, cp, diff,
      fork and destroy; an example agent tries 3 fixes in 3 forks and keeps the one whose
      tests pass; keeping outputs on the host needs human approval.

## M7 — Remote backend

- [ ] **M7-T1 · Remote qtd**
      Done when: `qtd --listen` with mTLS; `qt remote add home-pc` pins the cert; every command
      works with `--host`; file copy streams; the CLI shows where things run.

- [ ] **M7-T2 · Installers**
      Done when: `install.sh` for Ubuntu 22.04/24.04 and a WSL2 guide (nested virt, systemd);
      signed release binaries + checksums from a tag.

## M8 — Hardening, evals, release

- [ ] **M8-T1 · Escape + leak tests**: a host canary file and a host-network canary that no
      sandbox can reach (both backends); discard leaves nothing in the data dir; fuzz the agent
      protocol.
- [ ] **M8-T2 · Benchmarks**: boot, restore, fork, exec latency; overhead of event recording;
      published table.
- [ ] **M8-T3 · Docs + demo**: README, SECURITY.md (threat model, what each isolation level
      does and doesn't stop), a 90 s video: `qt run` an evil repo → report catches the honeytoken
      leaving → fork an agent 3 ways.
