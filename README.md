# Agent Bus

A local coordination bus for AI agents, implemented in Rust. Agents exchange
messages over newline-delimited JSON, catch up with per-topic cursors, share
key/value state and artifacts, and report their presence and task progress.

The native broker is under development. Validate protocol and persisted-state
compatibility before replacing an existing deployment.

## Features

- Topic-based publish/subscribe and bounded history with explicit gap reporting.
- Correlated request/reply through agent inboxes.
- Durable write-ahead logging and sequence counters that survive retention.
- Token authentication, topic/KV permissions, expiry, rate limits, and artifact quotas.
- Shared key/value state and content-addressed artifact storage.
- Atomic lease claims with fencing counters, plus separate advisory claim views.
- Agent presence, health checks, and optional scheduler lifecycle/completion reports.
- TCP on localhost and opt-in Unix sockets.

## Build

Install a Rust toolchain with Cargo. The crate uses the Rust 2021 edition;
the repository does not currently declare a minimum supported Rust version.

```sh
cargo fetch --manifest-path rust/Cargo.toml --locked
export CARGO_INCREMENTAL=0
cargo build --manifest-path rust/Cargo.toml --offline --locked -j1
```

Binaries are written to `rust/target/debug/` unless `CARGO_TARGET_DIR` is set.
In a managed development environment, use its assigned build target and Cargo
guard. See [development notes](docs/DEVELOPMENT.md).

## Run a local broker

The following example requires `openssl` and `jq`. It creates a random demo
credential and stores runtime state in a private directory outside the checkout.
Use a new, empty state directory for this example.

```sh
umask 077
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/agent-bus-demo"
mkdir -p "$state_dir"
test ! -e "$state_dir/tokens.json" || { echo 'Use a new state directory'; exit 1; }
openssl rand -hex 32 | jq -R '{(.): {
  agent: "demo",
  publish: ["board.*", "inbox.demo"],
  subscribe: ["board.*", "inbox.demo"],
  kv_read: ["ctx.demo.*"],
  kv_write: ["ctx.demo.*"]
}}' > "$state_dir/tokens.json"

rust/target/debug/agent-bus-broker serve \
  --listen 127.0.0.1:18379 \
  --tokens "$state_dir/tokens.json" \
  --wal "$state_dir/wal.log"
```

In a second terminal, from the checkout:

```sh
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/agent-bus-demo"
export AGENT_BUS_AGENT=demo
export AGENT_BUS_TOKEN="$(jq -r 'keys[0]' "$state_dir/tokens.json")"
export AGENT_BUS_HOST=127.0.0.1
export AGENT_BUS_PORT=18379
unset AGENT_BUS_SOCK

rust/target/debug/agent-bus ping --format short
rust/target/debug/agent-bus post board.demo '{"message":"hello"}'
rust/target/debug/agent-bus show board.demo --since-seq 0 --format json
rust/target/debug/agent-bus heartbeat 'ready'
rust/target/debug/agent-bus kv-put ctx.demo.status '{"ready":true}'
rust/target/debug/agent-bus kv-get ctx.demo.status
```

Keep a separate returned history cursor for each topic. `--since-seq N` is
exclusive: the next fetch starts after `N`. A history gap exits with code 2;
an incomplete view cannot establish that a task or resource is available.

The demo credential is intentionally limited. Lease operations, artifact
operations, and administration have their own requirements; inspect the CLI
help and source-backed [protocol notes](docs/PROTOCOL.md) before using them.

## Configuration

| Variable | Purpose / default |
| --- | --- |
| `AGENT_BUS_AGENT` | Client identity; required. |
| `AGENT_BUS_TOKEN` | Client credential; required. |
| `AGENT_BUS_HOST`, `AGENT_BUS_PORT` | TCP address; defaults to `127.0.0.1:8379`. |
| `AGENT_BUS_SOCK` | Explicit Unix socket path; unset for TCP. Client `--tcp` overrides it. |
| `AGENT_BUS_WAL` | Broker WAL path; defaults to `./data/wal.log`. |
| `AGENT_BUS_TOKENS` | Broker credential file; defaults to `./tokens.json`. |

Broker flags `--listen`, `--wal`, `--tokens`, and `--unix` override the
corresponding settings. Use private runtime paths and keep credentials,
messages, artifacts, logs, and task reports out of version control. There is
no TLS transport; keep the listener on localhost or within an appropriately
protected local environment. Do not enable `AGENT_BUS_OPEN` for authenticated use.

## Test and contribute

```sh
export CARGO_INCREMENTAL=0
cargo test --manifest-path rust/Cargo.toml --offline --locked -j1 -- --test-threads=1
```

One historical compatibility test is explicitly ignored because it requires
a separately supplied older CLI. See [development notes](docs/DEVELOPMENT.md)
for running it. Maintained implementation and tests live in Rust; private
runtime data and archived legacy code are not included in the public source.

Read the [crate overview](rust/README.md) for the modules and binaries.
