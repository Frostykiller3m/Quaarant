# gVisor runtime-monitoring protos (vendored)

The `.proto` files under `pkg/sentry/seccheck/points/` define the messages gVisor's
runtime monitoring ("seccheck") **remote** sink sends to qtd. They are copied unmodified from
gVisor at tag `release-20261116.0` (the runsc version qt is developed against) and keep their
import paths, so this directory is its own buf module (`buf.yaml`). Go code is generated
into `internal/gvisorpb` by `make proto` (`buf.gen.gvisor.yaml`).

License: Apache 2.0, see `LICENSE` (gVisor's).

| file | sha256 |
|---|---|
| common.proto | c5da98607aafb974344bdd5110b3899ab50e4a074a9a9617239cc76c2417a1e7 |
| container.proto | 200da99e494f31732f02464529094832de77c3274e272a72194317748e34326f |
| sentry.proto | 3b3e2bd5bc5f03b246e64477ae3a1c671fa9ca0cbc1eda5c838c8f49e592dac8 |
| syscall.proto | f2fa37da9e959df05b0ef6f84dbcaca680ff611679939334898ebb9b58b756f4 |

The wire format around them (`pkg/sentry/seccheck/sinks/remote/wire`): one SOCK_SEQPACKET
message per event, an 8-byte little-endian header `{header_size u16, message_type u16,
dropped_count u32}` followed by the serialized message; a `gvisor.common.Handshake`
exchange (sink first) precedes the stream. qt reimplements the server side in
`internal/backend/gvisor/monitor.go`.

To update: fetch the same four files at the new runsc release tag, update the hashes above,
run `make proto`, and run the integration tests (`sudo make itest`).
