# CLAUDE.md — quarantine (qt)

qt runs untrusted code (a repo, a package, an agent's command) inside a disposable sandbox — gVisor
(`--isolation=gvisor`) or a Firecracker microVM (`--isolation=vm`) — records everything it does
(exec, files, network, DNS, honeytoken touches) as structured events on the host, enforces a
host-side network policy, and produces an evidence-backed report (clean / suspicious / malicious).

Read `docs/ARCHITECTURE.md` for the design and `docs/BUILD_PLAN.md` for the task list.

## Workflow

- One task per session (`/task M1-T2`). Do only that task; note follow-ups in the plan instead.
- A task is done only with **proof**: tests, real runs, numbers — paste them in the summary.
- Work on a branch `mX-tY-<slug>`, merge `--no-ff` to `main`, tick the box in `docs/BUILD_PLAN.md`.
- If a "Done when" criterion can't be met (e.g. no KVM here), say so explicitly — never fake it.

## Commands

```sh
make build        # bin/qt, bin/qtd, bin/qt-agent (host OS)
make build-linux  # bin/linux-{amd64,arm64}/..., CGO_ENABLED=0
make test         # go test -race ./...
make vet lint     # go vet, golangci-lint (v2)
QT_ITEST=1 go test ./...   # integration tests (need runsc / KVM / root) — skipped otherwise
```

## Invariants (security — do not break)

1. **Linux only at runtime.** Windows/macOS may build and run unit tests; sandboxes need Linux
   (WSL2 on Windows). Platform code goes in `_linux.go` files with stubs elsewhere.
2. **qt-agent is static**: `CGO_ENABLED=0`, stdlib + minimal deps. It runs inside the guest.
3. **Never trust the guest.** Anything from inside a sandbox (agent messages, event payloads, file
   names, repo contents, README text) is untrusted input: validate, bound sizes, and never act on it.
4. **Network truth comes from the host** (netns/tap, nftables, resolver, proxy) — never from the
   guest's own reports.
5. **Untrusted data reaching Claude is wrapped and escaped** as data; prompts never interpolate it raw.
6. **Every report finding cites event ids**; findings without valid evidence are dropped.
7. **`qt rm` leaves nothing behind** in the data dir; tests check it.
8. Least privilege by default: non-root guest user, no capabilities, seccomp, cgroup limits,
   `--net=none` unless asked.

## Code conventions

- Go 1.23+. Everything non-`main` lives under `internal/`. `cmd/*/main.go` stays thin.
- Errors: wrap with `fmt.Errorf("doing x: %w", err)`; no panics outside `main` setup.
- Tests: table-driven, fakes over mocks, no network in unit tests. Integration tests gated by
  `QT_ITEST=1` and `t.Skip` otherwise.
- `golangci-lint run` must be clean; don't add `//nolint` without a reason comment.
- Keep `go.mod` deps few and justified.

## Dev environment notes

- The current dev machine is Windows; M0 builds natively (cross-compiling to linux). From M1 on,
  work inside WSL2 Ubuntu 24.04 (`vm` isolation also needs `nestedVirtualization=true` + `/dev/kvm`).
- The module path `github.com/qt-dev/quarantine` is a placeholder; rename with
  `go mod edit -module <new>` plus a search/replace of imports.
