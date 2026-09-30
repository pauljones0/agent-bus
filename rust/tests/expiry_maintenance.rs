//! Bounded expiry maintenance: idle payload release with high-water kept.
//!
//! No Python, no production IO, no multi-minute sleeps, no large workloads:
//! each test pins its own WAL, fixture tokens, ephemeral loopback port, and
//! fixed clock (`set_fixed_now`). Proves the wire maintenance tick reuses the
//! existing expiry predicates (`Topic::expire`/`KvStore::purge_expired` with
//! `now > exp`, `ClaimStore::purge_expired_at` with `now >= expires_at`,
//! `PresenceStore::prune`) to release expired payloads during idle too, not
//! only filter them from fetch. High-water `seq`/cursors/gaps, retained-window
//! idempotency, TTL exact boundaries, ACL/ownership, and WAL durability are
//! preserved. One small real worker test proves idle cleanup and clean
//! shutdown with a 10ms interval (never multi-minute).

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use agent_bus::acl::TokenStore;
use agent_bus::wal::snapshot_path_for;
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-expiry-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn open_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .expect("fixture tokens valid")
}

fn scoped_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["allowed"], "subscribe": ["allowed"]}
        }"#,
    )
    .expect("scoped tokens valid")
}

fn start_handle(name: &str) -> (String, PathBuf, Server) {
    start_with(name, open_tokens())
}

fn start_with(name: &str, tokens: TokenStore) -> (String, PathBuf, Server) {
    let wal = wal_path(name);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    let server = Server::new(wal.clone(), tokens).expect("fresh WAL starts clean");
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    (addr, wal, handle)
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn fetch_all(c: &mut Client, topic: &str) -> Value {
    c.rpc(&json!({"op": "fetch", "topic": topic})).unwrap()
}

// Expired payloads are released, high-water kept, gaps reported, WAL kept.
#[test]
fn tick_releases_expired_posts_keeps_high_water_and_gaps() {
    let (addr, wal, server) = start_handle("posts-hw");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "e1", "ttl_ms": 1000}))
        .unwrap();
    assert_eq!(r1["seq"], json!(1));
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 2}))
        .unwrap();
    assert_eq!(r2["seq"], json!(2));
    let r3 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 3, "msg_id": "e3", "ttl_ms": 1000}))
        .unwrap();
    assert_eq!(r3["seq"], json!(3));
    // Before expiry: all stored, all live.
    assert_eq!(server.topic_stored_for_test("t"), Some((3, 3)));
    let f0 = fetch_all(&mut c, "t");
    assert_eq!(f0["messages"].as_array().unwrap().len(), 3);
    assert_eq!(f0["cursor"]["gap"], json!(false));
    // Advance past expiry: still stored (no auto purge), filtered from fetch.
    server.set_fixed_now(Some(T0 + 2.0));
    assert_eq!(server.topic_stored_for_test("t"), Some((3, 3)));
    let f1 = fetch_all(&mut c, "t");
    assert_eq!(f1["messages"].as_array().unwrap().len(), 1);
    assert_eq!(f1["messages"][0]["seq"], json!(2));
    assert_eq!(f1["cursor"]["gap"], json!(true));
    // WAL bytes before tick (tick must not write/truncate).
    let wal_before = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert!(wal_before > 0);
    // Tick releases the two expired, keeps seq 3 and the live payload.
    let rep = server.maintenance_tick();
    assert_eq!(rep.topics_scanned, 1);
    assert_eq!(rep.msgs_removed, 2);
    assert_eq!(server.topic_stored_for_test("t"), Some((3, 1)));
    let wal_after = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert_eq!(wal_after, wal_before, "tick performs no WAL IO");
    // Fetch still shows the same live message with the same gaps.
    let f2 = fetch_all(&mut c, "t");
    assert_eq!(f2["messages"].as_array().unwrap().len(), 1);
    assert_eq!(f2["messages"][0]["seq"], json!(2));
    assert_eq!(f2["cursor"]["gap"], json!(true));
    assert_eq!(f2["cursor"]["missing_ranges"], json!([[1, 1], [3, 3]]));
    // Topics introspection: high-water 3, live retained 1.
    let t = c.rpc(&json!({"op": "topics"})).unwrap();
    assert_eq!(t["topics"][0]["seq"], json!(3));
    assert_eq!(t["topics"][0]["retained"], json!(1));
    // No sequence reuse: next post is 4.
    let r4 = c.rpc(&json!({"op": "post", "topic": "t", "payload": 4})).unwrap();
    assert_eq!(r4["seq"], json!(4));
    server.set_fixed_now(None);
}

// Fresh retained ids still dedup after ticks (no fresh loss).
#[test]
fn fresh_retained_retry_still_dups_after_tick() {
    let (addr, _wal, server) = start_handle("fresh-dup");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "k1"}))
        .unwrap();
    assert_eq!(r1["seq"], json!(1));
    let rep0 = server.maintenance_tick();
    assert_eq!(rep0.msgs_removed, 0);
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 1)));
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "k1"}))
        .unwrap();
    assert_eq!(r2["dup"], json!(true));
    assert_eq!(r2["seq"], json!(1));
    // Advance (still live, no exp) and tick: still dups.
    server.set_fixed_now(Some(T0 + 100.0));
    let rep1 = server.maintenance_tick();
    assert_eq!(rep1.msgs_removed, 0);
    let r3 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "k1"}))
        .unwrap();
    assert_eq!(r3["dup"], json!(true));
    assert_eq!(r3["seq"], json!(1));
    server.set_fixed_now(None);
}

// Expired ids are outside the window: retry becomes new, never fabricated.
#[test]
fn expired_id_new_post_after_tick() {
    let (addr, _wal, server) = start_handle("expired-new");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "e1", "ttl_ms": 1000}))
        .unwrap();
    assert_eq!(r1["seq"], json!(1));
    server.set_fixed_now(Some(T0 + 2.0));
    let rep = server.maintenance_tick();
    assert_eq!(rep.msgs_removed, 1);
    // Empty topic keeps high-water (seq 1, 0 stored).
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 0)));
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "e1"}))
        .unwrap();
    assert!(ok(&r2), "{r2}");
    assert_eq!(r2["seq"], json!(2));
    assert!(r2.get("dup").is_none(), "{r2}");
    let f = fetch_all(&mut c, "t");
    assert_eq!(f["messages"].as_array().unwrap().len(), 1);
    assert_eq!(f["messages"][0]["seq"], json!(2));
    assert_eq!(f["cursor"]["gap"], json!(true));
    assert_eq!(f["cursor"]["missing_ranges"], json!([[1, 1]]));
    server.set_fixed_now(None);
}

// Exact boundaries: topic/KV `now > exp` (== live), leases `now >= exp`.
#[test]
fn ttl_exact_boundary_now_equals_exp() {
    let (addr, _wal, server) = start_handle("boundary");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Topic: exp T0+1.
    c.rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "b1", "ttl_ms": 1000}))
        .unwrap();
    // KV: exp T0+1.
    c.rpc(&json!({"op": "kv_put", "key": "k.b", "value": 1, "ttl_ms": 1000}))
        .unwrap();
    // Lease: expires_at T0+1.
    let g = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/b.rs", "ttl_ms": 1000}))
        .unwrap();
    assert!(ok(&g), "{g}");
    // At now == exp: topic/KV live, lease expired.
    server.set_fixed_now(Some(T0 + 1.0));
    let rep_eq = server.maintenance_tick();
    assert_eq!(rep_eq.msgs_removed, 0, "now==exp stays live for posts");
    assert_eq!(rep_eq.kv_removed, 0, "now==exp stays live for KV");
    assert_eq!(rep_eq.leases_removed, 1, "now==expires_at expires leases");
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 1)));
    assert_eq!(server.kv_stored_len_for_test(), 1);
    assert_eq!(server.leases_stored_len_for_test(), 0);
    // Retry still dups at the boundary (live).
    let rd = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "b1"}))
        .unwrap();
    assert_eq!(rd["dup"], json!(true));
    // Just past: topic/KV drop.
    server.set_fixed_now(Some(T0 + 1.0001));
    let rep_past = server.maintenance_tick();
    assert_eq!(rep_past.msgs_removed, 1);
    assert_eq!(rep_past.kv_removed, 1);
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 0)));
    assert_eq!(server.kv_stored_len_for_test(), 0);
    server.set_fixed_now(None);
}

// KV tick: expired released, live kept, delete-found follows storage.
#[test]
fn kv_cleanup_tick_releases_expired_keeps_live() {
    let (addr, _wal, server) = start_handle("kv-clean");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "k.live", "value": 1})).unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "k.exp", "value": 2, "ttl_ms": 1000}))
        .unwrap();
    assert_eq!(server.kv_stored_len_for_test(), 2);
    // Live reads before tick: live found, expired not found (filtered).
    let gl = c.rpc(&json!({"op": "kv_get", "key": "k.live"})).unwrap();
    assert_eq!(gl["found"], json!(true));
    server.set_fixed_now(Some(T0 + 2.0));
    let ge = c.rpc(&json!({"op": "kv_get", "key": "k.exp"})).unwrap();
    assert_eq!(ge["found"], json!(false));
    // Still stored before tick.
    assert_eq!(server.kv_stored_len_for_test(), 2);
    // Delete of expired-but-stored reports found=true (presence-only).
    c.rpc(&json!({"op": "kv_put", "key": "k.del", "value": 3, "ttl_ms": -1000}))
        .unwrap();
    let del_before = c.rpc(&json!({"op": "kv_del", "key": "k.del"})).unwrap();
    assert_eq!(del_before["found"], json!(true), "{del_before}");
    // Re-put an expired key for the tick (del removed k.del entirely).
    c.rpc(&json!({"op": "kv_put", "key": "k.exp2", "value": 4, "ttl_ms": -1000}))
        .unwrap();
    assert_eq!(server.kv_stored_len_for_test(), 3);
    let rep = server.maintenance_tick();
    assert_eq!(rep.kv_removed, 2);
    assert_eq!(server.kv_stored_len_for_test(), 1);
    // Live kept, expired gone from list and get.
    let gl2 = c.rpc(&json!({"op": "kv_get", "key": "k.live"})).unwrap();
    assert_eq!(gl2["found"], json!(true));
    let ge2 = c.rpc(&json!({"op": "kv_get", "key": "k.exp"})).unwrap();
    assert_eq!(ge2["found"], json!(false));
    let li = c.rpc(&json!({"op": "kv_list", "prefix": "k."})).unwrap();
    assert_eq!(li["keys"], json!(["k.live"]), "{li}");
    // Delete of purged reports found=false (already gone).
    let del_after = c.rpc(&json!({"op": "kv_del", "key": "k.exp"})).unwrap();
    assert_eq!(del_after["found"], json!(false), "{del_after}");
    server.set_fixed_now(None);
}

// Leases tick: expired released, live kept, receipts never evicted.
#[test]
fn leases_cleanup_tick_releases_expired_keeps_receipts() {
    let (addr, _wal, server) = start_handle("lease-clean");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let g1 = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/a.rs", "ttl_ms": 1000, "idempotency_key": "k1"}))
        .unwrap();
    assert!(ok(&g1), "{g1}");
    let f1 = g1["fencing"].as_u64().unwrap();
    let g2 = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/b.rs", "ttl_ms": 60000}))
        .unwrap();
    assert!(ok(&g2), "{g2}");
    assert_eq!(server.leases_stored_len_for_test(), 2);
    // Advance past g1 expiry without any claim op (ops purge eagerly).
    server.set_fixed_now(Some(T0 + 2.0));
    assert_eq!(server.leases_stored_len_for_test(), 2);
    let rep = server.maintenance_tick();
    assert_eq!(rep.leases_removed, 1);
    assert_eq!(server.leases_stored_len_for_test(), 1);
    // Expired gone from status, live kept.
    let s1 = c.rpc(&json!({"op": "claim_status", "resource": "repo/a.rs"})).unwrap();
    assert_eq!(s1["live"], json!(false), "{s1}");
    let s2 = c.rpc(&json!({"op": "claim_status", "resource": "repo/b.rs"})).unwrap();
    assert_eq!(s2["owner"], json!("alice"), "{s2}");
    // Same idem key stays retired (receipt kept, never mints anew).
    let retry = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/a.rs", "ttl_ms": 1000, "idempotency_key": "k1"}))
        .unwrap();
    assert_eq!(retry["retired"], json!(true), "{retry}");
    // Fresh key on the freed resource wins with higher fencing.
    let g3 = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/a.rs", "ttl_ms": 60000, "idempotency_key": "k2"}))
        .unwrap();
    assert!(ok(&g3), "{g3}");
    assert!(g3["fencing"].as_u64().unwrap() > f1, "{g3}");
    server.set_fixed_now(None);
}

// Presence tick: stale pruned, fresh kept, retired suppressed then released.
#[test]
fn presence_cleanup_tick_prunes_stale_keeps_fresh() {
    let (addr, _wal, server) = start_handle("presence-clean");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    a.rpc(&json!({"op": "heartbeat", "status": "online"})).unwrap();
    // Bob arrives later so ages differ without an intermediate prune of alice.
    server.set_fixed_now(Some(T0 + 80000.0));
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    b.rpc(&json!({"op": "heartbeat", "status": "online"})).unwrap();
    // Both fresh (alice age 80000 < 86400).
    assert_eq!(server.presence_stored_len_for_test(), (2, 0));
    let rep0 = server.maintenance_tick();
    assert_eq!(rep0.presence_removed, 0);
    // Advance so alice is stale (90000 > 86400) and bob is fresh (10000).
    server.set_fixed_now(Some(T0 + 90000.0));
    assert_eq!(server.presence_stored_len_for_test(), (2, 0));
    let rep1 = server.maintenance_tick();
    assert_eq!(rep1.presence_removed, 1);
    assert_eq!(server.presence_stored_len_for_test(), (1, 0));
    // Exact boundary: age == 86400 stays, > 86400 drops (pure core proof via
    // tick_at on a fresh server to avoid liveness refresh from agents ops).
    let (_a2, _w2, s2) = start_handle("presence-bound");
    s2.set_fixed_now(Some(T0));
    {
        let mut c = Client::connect(&_a2, "alice", "tok-alice").unwrap();
        c.rpc(&json!({"op": "heartbeat"})).unwrap();
    }
    let rep_eq = s2.maintenance_tick_at(T0 + 86400.0);
    assert_eq!(rep_eq.presence_removed, 0);
    assert_eq!(s2.presence_stored_len_for_test(), (1, 0));
    let rep_past = s2.maintenance_tick_at(T0 + 86400.1);
    assert_eq!(rep_past.presence_removed, 1);
    assert_eq!(s2.presence_stored_len_for_test(), (0, 0));
    // Retired: suppressed 1h, then released by tick (no re-add while held).
    let (_a3, _w3, s3) = start_handle("presence-retired");
    s3.set_fixed_now(Some(T0));
    {
        let mut c = Client::connect(&_a3, "alice", "tok-alice").unwrap();
        c.rpc(&json!({"op": "heartbeat"})).unwrap();
    }
    s3.retire_presence_for_test("alice");
    assert_eq!(s3.presence_stored_len_for_test(), (0, 1));
    let rep_r0 = s3.maintenance_tick_at(T0 + 3599.0);
    assert_eq!(rep_r0.retired_removed, 0);
    let rep_r1 = s3.maintenance_tick_at(T0 + 3600.1);
    assert_eq!(rep_r1.retired_removed, 1);
    assert_eq!(s3.presence_stored_len_for_test(), (0, 0));
    server.set_fixed_now(None);
}

// Non-finite clocks never mass-drop.
#[test]
fn nonfinite_tick_is_noop_never_mass_drops() {
    let (addr, _wal, server) = start_handle("nonfinite");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "post", "topic": "t", "payload": 1})).unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "k", "value": 1})).unwrap();
    c.rpc(&json!({"op": "heartbeat"})).unwrap();
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 1)));
    let rep_nan = server.maintenance_tick_at(f64::NAN);
    assert!(rep_nan.is_empty());
    let rep_inf = server.maintenance_tick_at(f64::INFINITY);
    assert!(rep_inf.is_empty());
    // Nothing dropped.
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 1)));
    assert_eq!(server.kv_stored_len_for_test(), 1);
    assert_eq!(server.presence_stored_len_for_test().0, 1);
    // Server-clock NaN also no-ops.
    server.set_fixed_now(Some(f64::NAN));
    let rep_clock = server.maintenance_tick();
    assert!(rep_clock.is_empty());
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 1)));
    server.set_fixed_now(None);
}

// WAL unchanged by ticks; replay recovers high-water and filters expired.
#[test]
fn wal_unchanged_and_replay_recovers_high_water() {
    let (addr, wal, server) = start_handle("wal-replay");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "e1", "ttl_ms": 1000}))
        .unwrap();
    c.rpc(&json!({"op": "post", "topic": "t", "payload": 2})).unwrap();
    server.set_fixed_now(Some(T0 + 2.0));
    let before = std::fs::read_to_string(&wal).unwrap();
    assert!(before.contains("\"e1\""), "WAL keeps expired record");
    let rep = server.maintenance_tick();
    assert_eq!(rep.msgs_removed, 1);
    let after = std::fs::read_to_string(&wal).unwrap();
    assert_eq!(after, before, "tick writes no WAL bytes");
    // Deterministic replay at T0+2 recovers seq 2 with only the live payload.
    let mut state = agent_bus::wal::BusState::new();
    agent_bus::wal::replay(&wal, &mut state, T0 + 2.0).expect("replay clean");
    let t = state.topics.get("t").expect("topic replayed");
    assert_eq!(t.seq, 2);
    assert_eq!(t.msgs.len(), 1);
    assert_eq!(t.msgs[0].seq, 2);
    server.set_fixed_now(None);
}

// ACL preserved across ticks: denied stays denied, allowed keeps gaps.
#[test]
fn acl_preserved_across_tick() {
    let (addr, _wal, server) = start_with("acl-preserved", scoped_tokens());
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    a.rpc(&json!({"op": "post", "topic": "secret", "payload": 1, "ttl_ms": 1000}))
        .unwrap();
    a.rpc(&json!({"op": "post", "topic": "allowed", "payload": 1, "ttl_ms": 1000}))
        .unwrap();
    a.rpc(&json!({"op": "post", "topic": "allowed", "payload": 2})).unwrap();
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let denied0 = b.rpc(&json!({"op": "fetch", "topic": "secret"})).unwrap();
    assert!(denied0.get("error").is_some(), "{denied0}");
    server.set_fixed_now(Some(T0 + 2.0));
    let rep = server.maintenance_tick();
    assert_eq!(rep.msgs_removed, 2);
    let denied1 = b.rpc(&json!({"op": "fetch", "topic": "secret"})).unwrap();
    assert!(denied1.get("error").is_some(), "{denied1}");
    let allowed = b.rpc(&json!({"op": "fetch", "topic": "allowed"})).unwrap();
    assert!(ok(&allowed), "{allowed}");
    assert_eq!(allowed["messages"].as_array().unwrap().len(), 1);
    assert_eq!(allowed["cursor"]["gap"], json!(true));
    server.set_fixed_now(None);
}

// Small real lifecycle: worker cleans during idle, then shuts down cleanly.
#[test]
fn idle_worker_cleans_during_idle_and_shuts_down_cleanly() {
    let (addr, _wal, server) = start_handle("worker-idle");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "w1", "ttl_ms": 1000}))
        .unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "k.w", "value": 1, "ttl_ms": 1000}))
        .unwrap();
    c.rpc(&json!({"op": "claim_acquire", "resource": "repo/w.rs", "ttl_ms": 1000}))
        .unwrap();
    // Advance past expiry; no explicit tick from here until the worker acts.
    server.set_fixed_now(Some(T0 + 2.0));
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 1)));
    assert_eq!(server.kv_stored_len_for_test(), 1);
    assert_eq!(server.leases_stored_len_for_test(), 1);
    // Idle worker (10ms) must release without any client op.
    let worker = server.spawn_maintenance_worker(Duration::from_millis(10));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let posts = server.topic_stored_for_test("t").map(|(_, n)| n).unwrap_or(999);
        if posts == 0
            && server.kv_stored_len_for_test() == 0
            && server.leases_stored_len_for_test() == 0
        {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "idle worker did not clean in 2s");
        std::thread::sleep(Duration::from_millis(10));
    }
    // High-water kept after idle purge.
    assert_eq!(server.topic_stored_for_test("t"), Some((1, 0)));
    // Clean shutdown: joining returns (no hang), server stays usable.
    worker.shutdown();
    let r = c.rpc(&json!({"op": "post", "topic": "t", "payload": 2})).unwrap();
    assert_eq!(r["seq"], json!(2));
    // After shutdown the background no longer purges: new expired stays until
    // an explicit tick proves the worker thread ended (not leaked ticking).
    c.rpc(&json!({"op": "post", "topic": "t", "payload": 3, "msg_id": "w2", "ttl_ms": 1000}))
        .unwrap();
    server.set_fixed_now(Some(T0 + 4.0));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(server.topic_stored_for_test("t"), Some((3, 2)));
    let rep = server.maintenance_tick();
    assert_eq!(rep.msgs_removed, 1);
    assert_eq!(server.topic_stored_for_test("t"), Some((3, 1)));
    server.set_fixed_now(None);
}
