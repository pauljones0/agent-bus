# Rust implementation

This crate contains the Agent Bus broker, command-line client, scheduler, and
supporting tools. See the [project README](../README.md) for setup and examples,
the [protocol notes](../docs/PROTOCOL.md) for wire behavior, and the
[development guide](../docs/DEVELOPMENT.md) for verification.

## Binaries

| Binary | Purpose |
| --- | --- |
| `agent-bus-broker` | Serve a broker, post/fetch messages, or import an offline legacy state copy. |
| `agent-bus` | Messaging, history, subscriptions, requests/replies, KV, presence, artifacts, token administration, claims, and scheduler status. |
| `agent-bus-scheduler` | Run prompt-driven agent rounds through `muse exec`, with optional resource limits and bus status. |
| `agent-bus-snapshot` | Create and verify a local source delivery snapshot with a SHA-256 manifest. |
| `agent-bus-cargo-guard` | Refuse Cargo execution when configured workspace or target free space is below 6 GiB. |
| `agent-bus-deny-python` | Refuse accidental Python commands in a managed native development environment. |

The broker, client, scheduler, and snapshot tool provide `--help`. The two
guard tools are intended for managed command environments. Scheduler integration
requires a separately installed Muse executable; CPU and memory limits require
Linux/systemd.

## Modules

- `history`, `wal`, `migration`: bounded history, persistence, and offline import.
- `acl`, `tokens`, `rate`: authentication, permissions, token administration, and throttling.
- `kv`, `artifacts`, `presence`, `subs`: shared values, content-addressed files, agent presence, and subscriptions.
- `claims`, `advisory`: atomic leases and separate advisory message reducers.
- `wire`: JSON-lines TCP and Unix socket transports.
- `scheduler`, `scheduler_status`, `task_report`: agent process lifecycle and explicit completion reports.
- `cargo_guard`: native build resource preflight.

The native implementation is under development. Protocol and state compatibility
with an existing deployment must be validated before migration. Historical local
verification records and private deployment state are excluded from this repository.
