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
make vet lint     # go vet, golangci-lint (v2); lint with GOOS=linux too for *_linux.go
make proto        # regenerate internal/api from proto/ (make tools installs pinned buf + plugins)
make agent-deps   # fails if qt-agent links anything outside stdlib + internal/
make check        # everything CI runs
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

## Contracts (M0-T2) — change deliberately

- `proto/qtd/v1/qtd.proto`: the qtd API. Generated code in `internal/api/qtd/v1` is committed;
  run `make proto` after editing. Never break v1 wire compatibility (`buf breaking`).
- `internal/backend`: the `Backend` interface + `Capabilities`. Check with `backend.Require`;
  unsupported features return errors wrapping `errors.ErrUnsupported`.
- `internal/events/schema/v1.json`: the event schema (source of truth). Update the Go types,
  `examples/` and tests together; additive optional fields only within v1.

## Code conventions

- Go 1.26+ (oldest supported Go release; current x/sys and grpc require it). Everything non-`main` lives under `internal/`. `cmd/*/main.go` stays thin.
- Errors: wrap with `fmt.Errorf("doing x: %w", err)`; no panics outside `main` setup.
- Tests: table-driven, fakes over mocks, no network in unit tests. Integration tests gated by
  `QT_ITEST=1` and `t.Skip` otherwise.
- `golangci-lint run` must be clean; don't add `//nolint` without a reason comment.
- Keep `go.mod` deps few and justified.

## Dev environment notes

- The current dev machine is Windows; M0 builds natively (cross-compiling to linux). From M1 on,
  work inside WSL2 Ubuntu 24.04 (`vm` isolation also needs `nestedVirtualization=true` + `/dev/kvm`).
- Module path: `github.com/Frostykiller3m/Quaarant` (repo: https://github.com/Frostykiller3m/Quaarant).
  If the repo is renamed, update it with `go mod edit -module <new>`, a search/replace of
  imports, `.golangci.yml`, the Makefile `MODULE`, the proto `go_package`, then `make proto`.
