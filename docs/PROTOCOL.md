# Protocol notes

Agent Bus exchanges one JSON object per line over TCP or an explicitly configured
Unix socket. Clients authenticate with `hello`; subsequent operations use that
connection's identity and grants. Direct replies echo the request's `req_id`.

The authoritative implementations are [wire.rs](../rust/src/wire.rs),
[acl.rs](../rust/src/acl.rs), and the [native client](../rust/src/bin/agent-bus.rs).

## Messages and history

Messages have an ID, a per-topic sequence, sender, timestamp, and payload, with
optional correlation/reply metadata. `post` publishes a message; `subscribe`
streams matching topics. Request/reply is client-side correlation through inbox
topics rather than a separate broker task execution primitive.

`fetch` reads a bounded exact-topic snapshot. Pin the first page's snapshot
sequence on later pages, process each page completely, and retain its returned
cursor. Retention or expiry can remove history; explicit gap metadata distinguishes
missing messages from an empty topic. Topic high-water marks survive compaction.

The CLI's `show TOPIC --since-seq N` drains that snapshot and reports a resume
cursor. Exit 0 means a complete fetch, 1 indicates transport/authentication/broker
failure, and 2 indicates usage, an unsupported operation, or incomplete history.
Each topic needs its own cursor. Wildcard subscriptions do not provide an atomic
multi-topic catch-up view.

Optional post message IDs support retained-window duplicate detection in the
native broker. An older broker's behavior must be checked separately. Transport
timeouts can leave a mutation's outcome uncertain; reconcile state before retrying.

## State and coordination

KV operations support read/write grants and expiry. Artifacts are content-addressed,
with bounded transfers, integrity checks, and quota accounting. Treat artifact
identifiers and stored content as private runtime data.

Atomic lease commands are separate from advisory `claims` and `packets` views.
Advisory views reduce retained messages; missing history cannot prove that a
resource is free. Presence and heartbeat do not renew a lease. Broker receipts
show that a message was stored, not that a peer accepted or executed its task.

Scheduler lifecycle records describe processes. Explicit task reports describe
worker-asserted completion separately; absent or unusable reports are unknown.

## Persistence and deployment

The broker replays a WAL and fails closed on invalid state. Credentials use a
separate private token file. Offline migration accepts quiescent legacy copies
and publishes a new output without overwriting the input. Never migrate live
files or assume the native broker is a drop-in replacement.

There is no TLS support. Bind to localhost, use Unix sockets in owner-controlled
directories, and review grants and transport constraints before deployment.
