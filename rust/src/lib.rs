//! Native Rust agent-bus core.
//!
//! Wire-compatible replacement slice for the transitional Python bus:
//! durable exact-topic post/fetch with explicit retention-gap cursors,
//! broker-enforced atomic lease claims with idempotent retries, a
//! fsync-backed WAL with sequence high-water marks that survive expiry,
//! compaction and restart, and a JSON-lines TCP wire server/client.
//!
//! Presence/heartbeat never affects leases: only absolute `expires_at` does.

pub mod acl;
pub mod advisory;
pub mod artifacts;
pub mod cargo_guard;
pub mod claims;
pub mod history;
pub mod kv;
pub mod migration;
pub mod presence;
pub mod rate;
pub mod scheduler;
pub mod subs;
pub mod task_report;
pub mod tokens;
pub mod wal;
pub mod wire;
