# Build plan: quarantine (qt)

Work one task per Claude Code session: `/task M1-T2`. Each task ends with proof (tests, real
runs, numbers) and a merge to `main`. Tick tasks off here. Read `CLAUDE.md` first, every time.

Go 1.26+ (was 1.23+; raised in M0-T2 because current x/sys and grpc need it), Linux. Windows users run everything inside WSL2 (Ubuntu 24.04). `vm` isolation in WSL2
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

- [x] **M0-T2 · Contracts**
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

- [x] **M1-T1 · Daemon + run/exec/destroy**
      Done when: `qt run --isolation=gvisor alpine -- sh -c 'echo hi'` prints hi; `qt shell` is
      interactive (PTY); `qt ls` and `qt rm`; each sandbox has cgroup limits (CPU, memory, pids).

  ```text
  Implement qtd (systemd unit + unix socket with peer-credential check) and the gvisor backend:
  pull an OCI image (go-containerregistry), unpack to a bundle, generate an OCI runtime spec
  (read-only rootfs + writable upper dir, non-root user, no capabilities, seccomp default, cgroup
  limits), and run with runsc. Implement qt run / exec / shell (PTY) / ls / rm. Integration tests
  behind QT_ITEST=1 that actually run runsc.
  ```

  Follow-ups noted during M1-T1 (not done there):
  - M1-T2 (resolved there): `--file-access=exclusive` caches failed lookups, so files copied in
    from the host stayed invisible; the root mount now uses `--file-access=shared`. `/.qt/` is
    hidden from diffs. `Limits.DiskBytes` is still rejected until a disk quota exists.
  - M1-T3 (done there): the event log now has runtime monitoring, limits and follow.
  - Sandboxes do not survive a host (or WSL distro) restart: runsc state lives in /run. qtd then
    shows them as `stopped` and `qt rm` cleans them up (checked by hand). WSL shuts an idle distro
    down when no terminal is attached; keep one open, or see WSL's idle-timeout settings.
  - Live terminal resize (SIGWINCH → TIOCSWINSZ) is wired but only the initial size is tested.

- [x] **M1-T2 · Copy-on-write workspace + diff**
      Done when: `qt cp` in/out works; `qt diff <id>` lists added/changed/deleted files with
      sizes and hashes; `qt rm` leaves nothing in the data dir (a test checks).

  Follow-ups noted during M1-T2 (not done there):
  - Diff and copy for a sandbox that is `stopped` after a host restart: the backend finds
    sandboxes through `runsc state`, so both fail with "no such sandbox" until it is recreated.
  - `qt diff` compares with the image: files copied in with `qt cp` show as added. M5 may want a
    "since copy-in" baseline (snapshot the upper dir after setup).
  - Diff hashes every changed regular file in full; a sandbox writing huge files makes diff slow.
    Bounded by MaxChanges (100k entries) but not by bytes.

- [x] **M1-T3 · Events from gVisor**
      Done when: exec, file open/write/unlink and connect events stream to `events.jsonl` via
      runsc runtime monitoring; `qt events <id> --follow` works; every event passes the schema.

  Done with one deviation: runsc has no trace points with paths for unlink/rename/mkdir, so
  those come from a host-side inotify watcher on the overlay upper dir (host-observed, no pid).
  exec, open, write and connect come from runsc runtime monitoring.

  Follow-ups noted during M1-T3 (not done there):
  - The monitoring connection does not survive a qtd restart (the sandboxed sentry cannot
    reconnect): a sandbox that outlives qtd keeps running unobserved. Either keep a small
    per-sandbox collector process alive across qtd restarts, or refuse to keep such sandboxes.
  - Dropped events (rate, size, sentry backpressure) are only logged by qtd; surface a count
    in `qt ls`/`qt events` and in the M4 report.
  - `exec.exit_code` is not filled in (`sentry/exit_notify_parent` carries the status).
  - Connects on sockets created before monitoring or via dup default to `tcp`.
  - Recursive inotify sees very fast activity in brand-new directories as its end state.
  - M3 will add host-side (netns/proxy) net events; decide then whether sentry connect events
    stay (they show attempts on `--net=none`) or are folded into the host ones.

## M2 — Firecracker backend

- [x] **M2-T1 · Guest kernel + rootfs + agent**
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

  Done with these choices: guest kernel 6.18 (Firecracker v1.18 has ended 6.1 guest support);
  Firecracker is driven by `--config-file` under the jailer, not firecracker-go-sdk (no API
  calls needed; avoids ~30 modules). The agent arrives in an initramfs, so image disks never
  hold qt's code. The kernel build is byte-reproducible (checked). Two ext4 builds hold the
  same tree and filesystem identity but are not byte-identical (mke2fs 1.47.0 copies inode
  ctime from the unpacked files); the cache by digest makes that matter only across hosts.

  Follow-ups noted during M2-T1 (not done there):
  - (resolved in M2-T2) `qt run --rm --isolation=vm` took ~2.2 s; now 0.25-0.30 s.
  - (moved to M6) `qt diff` for vm.
  - vm events (exec/file) arrive in M2-T3; the vm backend declares no CapSyscallEvents.
  - CI skips the vm itests (no guest kernel there); build and cache the kernel in CI.
  - arm64: the agent and seccomp tables are ready; the kernel config fragment is x86_64 only.
  - A VM that outlives a qtd restart is found again through /run/quarantine/fc, but a host
    reboot leaves it `stopped` (like gvisor).

- [x] **M2-T2 · Fast start**
      Done when: a "golden" snapshot per image; restore-to-exec under 300 ms (benchmark in
      CI, numbers in docs); CoW disks via reflink, or a device-mapper thin fallback.

  Done: restore-to-exec p50 76-86 ms here, p90 83-386 ms (docs/ARCHITECTURE.md has the table; the
  CI `vm` job runs the same benchmark, fails above 300 ms p50, and prints the table in its
  summary). Disks: reflink where the data dir supports it, else dm-thin (used here, ext4);
  plain copy as the last resort. Restored sandboxes get their own hostname, clock and RNG
  (VMGenID + configure).

  Follow-ups noted during M2-T2 (not done there):
  - A golden snapshot's mem file is the VM's full RAM (2 GiB for the default 2 GiB VM) per
    image and shape. Consider smaller default VMs, or diff/compressed memory files.
  - Golden snapshots only exist per VM shape; non-default `--cpus/--memory` build their own.
  - The thin pool is created at 256 GiB sparse with no monitoring of free space; add a
    `qt doctor` check and low-water handling (dm-thin's event).
  - `qt rm` keeps golden snapshots and the pool (caches, like images); there is no `qt gc` yet.
  - `qt diff` for vm (mount a read-only thin snapshot of a stopped/paused disk) — M6.
  - Snapshots are tied to this host's CPU and kernel; restoring elsewhere is unsupported.

- [x] **M2-T3 · vm events**
      Done when: qt-agent emits the same event schema (fanotify for files, proc connector or
      polling for exec); the guest can't lie about network activity (network events come from
      the host side).

  Done: proc connector (exec) and fanotify (files) in qt-agent, streamed over vsock and
  written as `source: guest`; qtd accepts only exec/file kinds from a guest (unit-tested with
  forged net/dns/honeytoken events); a VM has no network device with `--net=none`.

  Follow-ups noted during M2-T3 (not done there):
  - Exec argv is lost for processes that exit within ~1 ms (busybox applets), failed opens
    (e.g. a denied /etc/shadow read) are invisible, argv is read from the live process (which
    can rewrite it, e.g. setproctitle), and attribute changes to files deleted
    right after are missed. The guest kernel's audit subsystem (CONFIG_AUDIT, execve and
    failing-open rules over NETLINK_AUDIT) records all of these in-kernel; use it.
  - The event stream does not survive a qtd restart (the backend no longer has the sandbox's
    event log); the agent's ring buffers 8192 events meanwhile.
  - `exec.exit_code` is not filled in for vm either (the proc connector's exit events carry it).
  - Every itest pulls `alpine:3.22` into a fresh store (~13 Docker Hub pulls per `make itest`);
    repeated runs hit the anonymous limit (100/h). Share one image cache across itests.
  - Pre-existing (M1-T3) flake seen once in 3 full `make itest` runs (0/40 alone):
    TestITestWatchOverlay timed out on a missing event, most likely `chmod` then an immediate
    `mv`: the watcher drops IN_ATTRIB when the path is already gone. Same race in the vm agent.
    Report the chmod with the inode's mode (fstat by handle) or keep the path rename-aware.

## M3 — Network policy

- [x] **M3-T1 · Isolated networking**
      Done when: every sandbox has its own netns/tap; LAN, host, link-local and metadata are
      unreachable (probe test from inside); `--net=none` really is none.

  Done: `internal/netpol` (a netns and veth for gvisor, a tap for vm, one `/30` each, one
  nftables table, a per-sandbox TCP proxy, nothing routed). The shared `backendtest.RunNet`
  probes from inside both backends: public TCP works through the proxy, while the gateway and
  every host address, metadata, LAN and private ranges, the other sandbox and its gateway,
  and the proxy port are refused at once in the kernel. UDP, ICMP, IPv6 and spoofed sources
  don't get out. `--net=none` shows only `lo` and has no route out (both backends). Nothing
  is left on the host after detach.

  Follow-ups noted during M3-T1 (not done there):
  - qtd does not attach links yet: `--net` still accepts only `none`. M3-T2 wires netpol
    into Create and `qt rm` (with the leave-nothing test) and re-adopts links after a qtd
    restart. Today `netpol.New` only replaces a stale table.
  - Destinations refused in nftables never reach qtd, so they leave no event. M3-T2's
    "denials are events" needs an nflog group (or a counter per link) for those resets.
  - All UDP is dropped, DNS included, until the M3-T2 resolver.
  - A host firewall that drops INPUT (ufw, firewalld) would also drop the redirected
    connections; `qt doctor` should detect that. The proxy dials from the host's namespace,
    so host routes (for example a VPN) apply to sandbox traffic.

- [x] **M3-T2 · Allow-list + log**
      Done when: `--net=allow:pypi.org` lets pip install work and nothing else (test); DNS and
      SNI are logged as events; `--net=log` records every connection; denials are events.

  Done: the per-sandbox resolver, the SNI/Host proxy policy, nflog for kernel refusals, and
  qtd wiring (attach, rm, adoption after a restart, pruning). `TestITestDaemonNetwork` goes
  through qtd's socket. With `--net=allow:pypi.org,files.pythonhosted.org`, `pip install
  six` works. Refused, each with an event: other names, a direct IP, DNS-over-HTTPS, SNI
  fronting on a PyPI address, metadata, and UDP. With `--net=log`, the internet works and
  every connection is recorded (SNI, bytes, duration). `rm` leaves no link. The netpol
  itests also cover HTTP Host fronting, DNS to 8.8.8.8 being captured, and adoption.
  Checked by hand with the installed qtd as well, including a `qtd` restart under a live
  sandbox and a VM with `--net=allow`.

  One "Done when" detail can't hold as written: `--net=allow:pypi.org` alone can't make pip
  work, because pip downloads packages from `files.pythonhosted.org`. pip fails with a
  "can't connect to files.pythonhosted.org" hint, and the refusal is an event. The test
  allows both names. The plan's nftables IP sets became the proxy's in-memory set
  (ARCHITECTURE explains why).

  Follow-ups noted during M3-T2 (not done there):
  - The kernel-refusal log limit (100/s, burst 200) is per host, not per sandbox: a noisy
    sandbox can crowd out another's refusal events. Use an nftables meter keyed by iifname.
  - In allow mode, only TLS (with SNI) and HTTP get through. SSH, git://, SMTP and similar
    need a rule type of their own (host:port allow entries). QUIC falls back to TCP.
  - `qt ls` does not show a sandbox's network policy (the API returns it).
  - Allow-list presets (for example `pypi` = pypi.org + files.pythonhosted.org) would save
    users from the pip surprise above.

  ```text
  Implement host-side egress control: a per-sandbox DNS resolver that answers only for allowed
  names (and records every query); nftables sets populated with the IPs those answers returned
  (with TTL expiry); a transparent TCP proxy that checks TLS SNI against the allow-list before
  splicing. Never trust anything the guest says. Tests: allowed domain works, other domains
  fail, direct-IP connects fail, DNS-over-HTTPS to a non-allowed host fails, metadata fails.
  ```

## M4 — Seeing everything: honeytokens + report

- [x] **M4-T1 · Honeytokens**
      Done when: fake SSH key, AWS credentials, .env API keys and a browser cookie DB are planted
      per sandbox with unique values; a read is an event; a token found in outbound traffic or
      DNS is a red-flag event (the proxy scans plaintext and SNI/DNS; TLS bodies are out of
      scope unless `--inspect-tls`).

  Done: `internal/honeytoken` generates and matches. qtd plants the set through `CopyIn`;
  the event log adds read events; the resolver and proxy find values (raw, hex, base64,
  base32) in DNS names, SNI and plaintext. `TestITestDaemonNetwork` covers a gvisor sandbox
  over qtd's socket:
  - the four files are owned by the sandbox user with mode 0600;
  - `sqlite3` opens the cookie DB;
  - `cat` of the AWS file and the cookie query are `read` events citing their file events;
  - a base64 POST of the file and the key ID in a DNS name are red flags;
  - `qt diff` hides the untouched tokens and shows a modified one.

  The netpol itests also cover SNI, raw and base64 bodies, and a refused destination, in
  both modes. Checked by hand on vm as well (read events as guest claims).

  Follow-ups noted during M4-T1 (not done there):
  - `--inspect-tls` (TLS interception with a per-sandbox CA, to scan TLS bodies) is not
    built. TLS egress is matched on SNI only.
  - Other transformations (gzip, encryption, character-by-character exfiltration across
    connections) are not detected. Reading a copy of a token made by `cp` is not a read
    event, but sending it out still is a red flag.
  - Tokens live in `$HOME` only. M5's repo vetting could add a `.env` next to the repo.

- [x] **M4-T2 · Claude report**
      Done when: `qt report <id>` produces findings that each cite event ids; a validator drops
      claims without evidence; a verdict (clean/suspicious/malicious); it works offline (rules
      only) without an API key.

  Done: `internal/report` (rules, compaction, Claude through the official Go SDK, the
  validator) and `qt report [--json] [--offline] [--model]`. Snapshot tests run on four real
  recorded logs:
  - a clean `pip install` is clean;
  - a stealer on gvisor and on vm is malicious: credentials read and sent out, metadata
    probed;
  - a miner with persistence is malicious: xmrig run, `.profile`, `crontab -`, `curl | sh`.

  The Claude path is tested through the SDK against a local fake API. The test checks the
  request (model, effort, schema, fallbacks, untrusted wrapping, a planted
  `</sandbox_events>` escaped). It checks that an invented evidence id and a category
  mismatch are dropped while a valid finding is kept, and that a refusal, a 500, non-JSON
  and `max_tokens` fall back to rules. `qt report` was also run by hand with the installed
  qtd on a clean and a malicious sandbox.

  Not verified: a live call to the Claude API. This machine has no API key, so the real
  model's findings on these logs have not been seen. Run `ANTHROPIC_API_KEY=... qt report
  <id>` to check. The plan's "forced tool call" became structured outputs (`claude-opus-5-5`
  rejects a forced `tool_choice`); ARCHITECTURE explains.

  Follow-ups noted during M4-T2 (not done there):
  - `qt report` exits 0 whatever the verdict. M5's one-shot vetting will want a non-zero
    exit for suspicious or malicious (or `--fail-on`).
  - A live-API snapshot test (recorded responses, opt-in with a key) and an eval of the
    findings on more varied logs.
  - The report is not stored with the sandbox; each `qt report` asks again.

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
