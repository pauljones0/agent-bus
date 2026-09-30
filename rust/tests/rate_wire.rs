//! Native post rate limits: ordered first-match, buckets, and boundaries.
//!
//! No Python, no production IO, no wall sleeps: each test pins its own WAL,
//! fixture tokens, ephemeral loopback port, and fixed clock. Proves the
//! `rate.rs` + `wire.rs` post gate is source-backed (first-match file
//! order, fallback global, per-agent/rule buckets, burst/refill/retry,
//! admin bypass for rate only, live `rate_limited`) with explicit
//! malformed-config rejection (never panic, never silent unlimited) and
//! preserved idempotent-post guarantees (denied/conflict/retry/WAL-failure
//! create no seq/WAL/posts/delivery; dup retries spend no budget).

use std::net::TcpListener;
use std::path::PathBuf;

use agent_bus::acl::TokenStore;
use agent_bus::wal::{snapshot_path_for, APPEND_FAIL_NONE, APPEND_FAIL_OPEN};
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-rate-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn start_with_handle(name: &str, tokens: TokenStore) -> (String, PathBuf, Server) {
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

fn post(c: &mut Client, topic: &str, payload: Value) -> Value {
    c.rpc(&json!({"op": "post", "topic": topic, "payload": payload}))
        .unwrap()
}

fn stats(c: &mut Client) -> Value {
    let s = c.rpc(&json!({"op": "stats"})).unwrap();
    assert!(ok(&s), "{s}");
    s["stats"].clone()
}

fn fetch_count(c: &mut Client, topic: &str) -> usize {
    let f = c
        .rpc(&json!({"op": "fetch", "topic": topic, "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    f["messages"].as_array().unwrap().len()
}

// Burst exhausts at fixed clock, retry hints appear, refill allows again.
#[test]
fn burst_exhausts_then_refills_with_retry_hints() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 2}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("burst-refill", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    // Burst 2: first two succeed.
    assert!(ok(&post(&mut c, "board.build", json!(1))));
    assert!(ok(&post(&mut c, "board.build", json!(2))));
    assert_eq!(stats(&mut c)["posts"], json!(2));
    assert_eq!(stats(&mut c)["rate_limited"], json!(0));
    // Exhausted: tokens 0, retry (1-0)/2*1000=500.
    let r = post(&mut c, "board.build", json!(3));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(r["retry_after_ms"], json!(500.0), "{r}");
    assert_eq!(stats(&mut c)["rate_limited"], json!(1));
    assert_eq!(stats(&mut c)["posts"], json!(2));
    assert_eq!(fetch_count(&mut c, "board.build"), 2);
    assert_eq!(server.deliveries(), 0, "no subs: denial must not deliver");
    // +0.25s refills 0.5: still short, retry (1-0.5)/2*1000=250.
    server.set_fixed_now(Some(T0 + 0.25));
    let r = post(&mut c, "board.build", json!(4));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(r["retry_after_ms"], json!(250.0), "{r}");
    // +0.5s total refills 1.0: allowed.
    server.set_fixed_now(Some(T0 + 0.5));
    assert!(ok(&post(&mut c, "board.build", json!(5))));
    assert_eq!(stats(&mut c)["posts"], json!(3));
    assert_eq!(stats(&mut c)["rate_limited"], json!(2));
    server.set_fixed_now(None);
}

// File order wins over sorted order and specificity.
#[test]
fn pattern_precedence_is_file_order_first_match() {
    // File order: board.build (1/s) before board.* (10/s). Sorted order
    // would put board.* first ("*" 42 < "b" 98). Topic matches both.
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"],
            "topic_rates": {"board.build": 1, "board.*": 10}}}"#,
    )
    .unwrap();
    // Prove the policy holds file order, not sorted.
    let policy = tokens.get("tok-a").unwrap();
    let raws: Vec<&str> = policy
        .rate_config()
        .rules
        .iter()
        .map(|r| r.pattern_raw.as_str())
        .collect();
    assert_eq!(raws, vec!["board.build", "board.*"]);
    let (addr, _wal, server) = start_with_handle("precedence", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    assert!(ok(&post(&mut c, "board.build", json!(1))));
    // Second immediate fails (1/s burst 1 exhausted). Sorted order would
    // have used 10/s (burst 10) and succeeded.
    let r = post(&mut c, "board.build", json!(2));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    // Other board topics use board.* (10/s): 9 more succeed at same clock
    // (1 already spent on board.build? No: separate buckets per rule.
    // board.other matches board.* only, fresh bucket burst 10).
    for i in 0..10 {
        assert!(ok(&post(&mut c, "board.other", json!(i))), "i={i}");
    }
    let r = post(&mut c, "board.other", json!("over"));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    server.set_fixed_now(None);
}

// Buckets are per agent+rule: agents isolated, conns shared.
#[test]
fn separate_agents_isolated_shared_conns() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1},
            "tok-b": {"agent": "b", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1}
        }"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("isolated-shared", tokens);
    server.set_fixed_now(Some(T0));
    let mut a1 = Client::connect(&addr, "a", "tok-a").unwrap();
    let mut a2 = Client::connect(&addr, "a", "tok-a").unwrap();
    let mut b = Client::connect(&addr, "b", "tok-b").unwrap();
    // Alice conn1 spends her (a, "*") bucket.
    assert!(ok(&post(&mut a1, "t", json!(1))));
    // Bob unaffected (separate agent bucket).
    assert!(ok(&post(&mut b, "t", json!(1))));
    // Alice conn2 shares her bucket: exhausted.
    let r = post(&mut a2, "t", json!(2));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    // Bob second immediate also exhausted (his own bucket).
    let r = post(&mut b, "t", json!(2));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(stats(&mut a1)["rate_limited"], json!(2));
    // Refill 1s: both agents allow again on either conn.
    server.set_fixed_now(Some(T0 + 1.0));
    assert!(ok(&post(&mut a2, "t", json!(3))));
    assert!(ok(&post(&mut b, "t", json!(3))));
    server.set_fixed_now(None);
}

// Admin bypasses rate only, never ACL.
#[test]
fn admin_bypass_rate_but_not_acl() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-admin": {"agent": "*", "publish": ["board.*"], "subscribe": ["*"], "rate_per_s": 1, "topic_rates": {"board.*": 1}},
            "tok-bare": {"agent": "*", "publish": [], "subscribe": []}
        }"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("admin-bypass", tokens);
    server.set_fixed_now(Some(T0));
    // Admin with grants: 10 rapid posts all succeed despite 1/s config.
    let mut admin = Client::connect(&addr, "anyone", "tok-admin").unwrap();
    for i in 0..10 {
        assert!(ok(&post(&mut admin, "board.build", json!(i))), "i={i}");
    }
    assert_eq!(stats(&mut admin)["rate_limited"], json!(0));
    assert_eq!(stats(&mut admin)["posts"], json!(10));
    // Admin without grants still denied (no ACL broadening).
    let mut bare = Client::connect(&addr, "anyone", "tok-bare").unwrap();
    let r = post(&mut bare, "board.build", json!(1));
    assert!(r["error"].as_str().unwrap().contains("publish denied"), "{r}");
    server.set_fixed_now(None);
}

// Denied ACL spends no budget and mutates nothing durable.
#[test]
fn denied_acl_consumes_no_token() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["board.*"], "subscribe": ["*"], "rate_per_s": 1}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("denied-no-consume", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    let before_posts = server.posts();
    let before_deliveries = server.deliveries();
    let r = post(&mut c, "secret.x", json!(1));
    assert!(r["error"].as_str().unwrap().contains("publish denied"), "{r}");
    assert!(r.get("retry_after_ms").is_none(), "{r}");
    assert_eq!(stats(&mut c)["rate_limited"], json!(0));
    // Allowed post still has full burst (denied spent nothing).
    assert!(ok(&post(&mut c, "board.a", json!(1))));
    assert_eq!(server.posts(), before_posts + 1);
    assert_eq!(server.deliveries(), before_deliveries, "no subs: no delivery");
    assert_eq!(fetch_count(&mut c, "board.a"), 1);
    server.set_fixed_now(None);
}

// Identical retry spends no budget: dup succeeds, refill preserved.
#[test]
fn identical_retry_consumes_no_token() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("retry-no-consume", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "r1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    assert_eq!(stats(&mut c)["posts"], json!(1));
    // Refill 1s, then dup retry: succeeds with dup, spends nothing.
    server.set_fixed_now(Some(T0 + 1.0));
    let dup = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "r1"}))
        .unwrap();
    assert!(ok(&dup), "{dup}");
    assert_eq!(dup["dup"], json!(true));
    assert_eq!(dup["seq"], r1["seq"]);
    assert_eq!(stats(&mut c)["posts"], json!(1), "dup adds no post");
    assert_eq!(stats(&mut c)["rate_limited"], json!(0));
    assert_eq!(server.deliveries(), 0, "no subs: dup must not deliver");
    // Refill still available (dup spent nothing): new post succeeds.
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 2, "msg_id": "r2"}))
        .unwrap();
    assert!(ok(&r2), "{r2} (dup must not consume refill)");
    assert_eq!(stats(&mut c)["posts"], json!(2));
    assert_eq!(fetch_count(&mut c, "t"), 2);
    server.set_fixed_now(None);
}

// Conflicting retry spends no budget and discloses no receipt.
#[test]
fn conflicting_retry_consumes_no_token() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("conflict-no-consume", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "c1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    server.set_fixed_now(Some(T0 + 1.0));
    // Conflict (different payload, same id): refuses, spends nothing.
    let conflict = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 2, "msg_id": "c1"}))
        .unwrap();
    assert!(
        conflict["error"].as_str().unwrap().contains("msg_id conflict"),
        "{conflict}"
    );
    assert!(conflict.get("retry_after_ms").is_none(), "{conflict}");
    assert_eq!(stats(&mut c)["posts"], json!(1));
    assert_eq!(stats(&mut c)["rate_limited"], json!(0));
    // Refill preserved: new post succeeds.
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 2, "msg_id": "c2"}))
        .unwrap();
    assert!(ok(&r2), "{r2}");
    // Different sender, same id: also conflict, no spend.
    let tokens2 = TokenStore::from_json_str(
        r#"{
            "tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 10},
            "tok-b": {"agent": "b", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 10}
        }"#,
    )
    .unwrap();
    let (addr2, _w2, s2) = start_with_handle("conflict-sender", tokens2);
    s2.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr2, "a", "tok-a").unwrap();
    let mut b = Client::connect(&addr2, "b", "tok-b").unwrap();
    assert!(ok(&a
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "s1"}))
        .unwrap()));
    let conflict = b
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "s1"}))
        .unwrap();
    assert!(
        conflict["error"].as_str().unwrap().contains("different sender"),
        "{conflict}"
    );
    s2.set_fixed_now(None);
    server.set_fixed_now(None);
}

// WAL failure consumes (rate before WAL); retry then hits rate first.
#[test]
fn wal_failure_consumes_token() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("wal-consumes", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    server.set_append_failpoint(APPEND_FAIL_OPEN);
    let fail = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "w1"}))
        .unwrap();
    assert!(fail["error"].as_str().unwrap().contains("wal append failed"), "{fail}");
    assert_eq!(stats(&mut c)["posts"], json!(0));
    assert_eq!(stats(&mut c)["rate_limited"], json!(0), "wal failure is not rate denial");
    // Immediate retry (same id, same payload): treated as NEW (nothing
    // committed), hits exhausted bucket first (rate before WAL).
    let limited = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "w1"}))
        .unwrap();
    assert_eq!(limited["error"], json!("rate exceeded"), "{limited}");
    assert_eq!(stats(&mut c)["rate_limited"], json!(1));
    // Clear failpoint, refill 1s: retry posts new.
    server.set_append_failpoint(APPEND_FAIL_NONE);
    server.set_fixed_now(Some(T0 + 1.0));
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "w1"}))
        .unwrap();
    assert!(ok(&r2), "{r2}");
    assert!(r2.get("dup").is_none(), "{r2}");
    assert_eq!(stats(&mut c)["posts"], json!(1));
    server.set_fixed_now(None);
}

// Only post is throttled; all other ops ignore buckets.
#[test]
fn other_ops_not_rate_limited() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"],
            "kv_read": ["ctx.*"], "kv_write": ["ctx.*"], "rate_per_s": 1}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("other-ops", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    assert!(ok(&post(&mut c, "t", json!(1))));
    assert_eq!(post(&mut c, "t", json!(2))["error"], json!("rate exceeded"));
    // Every other op succeeds despite exhausted post bucket.
    assert!(ok(&c.rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": 1})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "kv_get", "key": "ctx.k"})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "kv_list", "prefix": "ctx."})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "kv_del", "key": "ctx.k"})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "heartbeat", "status": "busy"})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "agents"})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "topics"})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "limits"})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "stats"})).unwrap()));
    assert!(ok(&c.rpc(&json!({"op": "ping"})).unwrap()));
    server.set_fixed_now(None);
}

// Concurrent same-agent posts share one bucket safely (one wins).
#[test]
fn concurrent_same_agent_shares_bucket() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("concurrent-share", tokens);
    server.set_fixed_now(Some(T0));
    let mut handles = Vec::new();
    for i in 0..8 {
        let addr = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
            c.rpc(&json!({"op": "post", "topic": "t", "payload": i})).unwrap()
        }));
    }
    let mut allowed = 0;
    let mut limited = 0;
    for h in handles {
        let r = h.join().unwrap();
        if ok(&r) {
            allowed += 1;
        } else if r["error"] == json!("rate exceeded") {
            limited += 1;
        } else {
            panic!("unexpected: {r}");
        }
    }
    assert_eq!(allowed, 1, "burst 1 allows exactly one");
    assert_eq!(limited, 7);
    assert_eq!(server.posts(), 1);
    assert_eq!(server.rate_limited(), 7);
    server.set_fixed_now(None);
}

// Malformed configs reject at load (no panic, no silent unlimited, no echo).
#[test]
fn malformed_configs_reject_at_load() {
    // Zero/negative/non-number globals.
    for bad in [
        r#"{"t": {"agent": "a", "rate_per_s": 0}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": 0.0}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": -1}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": "2"}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": true}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": false}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": []}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": {}}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": [1]}}"#,
    ] {
        let err = TokenStore::from_json_str(bad).expect_err("must reject");
        let msg = err.to_string();
        assert!(!msg.contains("tok-") && !msg.contains("\"t\""), "echoed: {msg}");
    }
    // Truthy non-object containers.
    for bad in [
        r#"{"t": {"agent": "a", "topic_rates": [1]}}"#,
        r#"{"t": {"agent": "a", "topic_rates": "x"}}"#,
        r#"{"t": {"agent": "a", "topic_rates": 5}}"#,
        r#"{"t": {"agent": "a", "topic_rates": true}}"#,
    ] {
        TokenStore::from_json_str(bad).expect_err("must reject");
    }
    // Bad entries inside objects (zero value, string value, bad pattern).
    for bad in [
        r#"{"t": {"agent": "a", "topic_rates": {"b": 0}}}"#,
        r#"{"t": {"agent": "a", "topic_rates": {"b": -1}}}"#,
        r#"{"t": {"agent": "a", "topic_rates": {"b": "1"}}}"#,
        r#"{"t": {"agent": "a", "topic_rates": {"[": 1}}}"#,
        r#"{"t": {"agent": "a", "topic_rates": {"[z-a]": 1}}}"#,
    ] {
        TokenStore::from_json_str(bad).expect_err("must reject");
    }
    // Huge numbers fail at JSON parse (BadRoot, no echo).
    let err = TokenStore::from_json_str(r#"{"t": {"agent": "a", "rate_per_s": 1e1000}}"#)
        .expect_err("huge must reject");
    assert!(!err.to_string().contains("tok-"));
    // Falsy containers are valid (no rules); fractional > 0 valid.
    let store = TokenStore::from_json_str(
        r#"{
            "t0": {"agent": "a", "topic_rates": 0},
            "t1": {"agent": "a", "topic_rates": false},
            "t2": {"agent": "a", "topic_rates": ""},
            "t3": {"agent": "a", "topic_rates": []},
            "t4": {"agent": "a", "topic_rates": {}},
            "t5": {"agent": "a", "topic_rates": null},
            "t6": {"agent": "a", "rate_per_s": 0.5, "topic_rates": {"b": 2.5}}
        }"#,
    )
    .expect("falsy/fractional valid");
    assert!(store.get("t0").unwrap().rate_config().is_unlimited());
    assert_eq!(store.get("t6").unwrap().rate_config().global, Some(0.5));
}

// Non-finite clocks fail closed without spending budget.
#[test]
fn non_finite_clock_fails_closed() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("nonfinite", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    assert!(ok(&post(&mut c, "t", json!(1))));
    server.set_fixed_now(Some(f64::NAN));
    let r = post(&mut c, "t", json!(2));
    assert_eq!(r["error"], json!("non-finite time"), "{r}");
    assert_eq!(server.rate_limited(), 0, "non-finite is not rate denial");
    server.set_fixed_now(Some(T0 + 1.0));
    assert!(ok(&post(&mut c, "t", json!(3))));
    server.set_fixed_now(None);
}

// Fractional 0.5/s: first allows, immediate denies, before/at boundary,
// plus non-finite and backwards clocks without spending.
#[test]
fn fractional_first_accepts_then_refills_with_correct_hints() {
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 0.5}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("frac-first", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    // First succeeds (burst 1, refill 0.5/s).
    assert!(ok(&post(&mut c, "t", json!(1))));
    assert_eq!(stats(&mut c)["posts"], json!(1));
    // Immediate: tokens 0, retry 2000.
    let r = post(&mut c, "t", json!(2));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(r["retry_after_ms"], json!(2000.0), "{r}");
    assert_eq!(fetch_count(&mut c, "t"), 1);
    // +1s: 0.5 tokens, retry 1000.
    server.set_fixed_now(Some(T0 + 1.0));
    let r = post(&mut c, "t", json!(3));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(r["retry_after_ms"], json!(1000.0), "{r}");
    // Just before +2s: still short, finite hint.
    server.set_fixed_now(Some(T0 + 1.999));
    let r = post(&mut c, "t", json!(4));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    let hint = r["retry_after_ms"].as_f64().unwrap();
    assert!(hint.is_finite() && hint > 0.0 && hint < 10.0, "{r}");
    // At +2s: refills to 1.0, allowed.
    server.set_fixed_now(Some(T0 + 2.0));
    assert!(ok(&post(&mut c, "t", json!(5))));
    assert_eq!(stats(&mut c)["posts"], json!(2));
    assert_eq!(stats(&mut c)["rate_limited"], json!(3));
    // Non-finite fails closed without spending (fractional bucket).
    // `stats` also fails on non-finite clocks, so assert via counters.
    server.set_fixed_now(Some(f64::NAN));
    let r = post(&mut c, "t", json!(6));
    assert_eq!(r["error"], json!("non-finite time"), "{r}");
    assert_eq!(server.rate_limited(), 3);
    assert_eq!(server.posts(), 2);
    // +2s after last allow (T0+4.0): allows again.
    server.set_fixed_now(Some(T0 + 4.0));
    assert!(ok(&post(&mut c, "t", json!(7))));
    // Backwards to T0+3.0: no refill, denies, last stays T0+4.0.
    server.set_fixed_now(Some(T0 + 3.0));
    let r = post(&mut c, "t", json!(8));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(r["retry_after_ms"], json!(2000.0), "{r}");
    // Forward 2s from T0+4.0 (T0+6.0): allows.
    server.set_fixed_now(Some(T0 + 6.0));
    assert!(ok(&post(&mut c, "t", json!(9))));
    server.set_fixed_now(None);
}

// Fractional buckets: agents isolated, conns shared (0.5/s cadence).
#[test]
fn fractional_separate_agents_isolated_shared_conns() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 0.5},
            "tok-b": {"agent": "b", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 0.5}
        }"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("frac-isolated-shared", tokens);
    server.set_fixed_now(Some(T0));
    let mut a1 = Client::connect(&addr, "a", "tok-a").unwrap();
    let mut a2 = Client::connect(&addr, "a", "tok-a").unwrap();
    let mut b = Client::connect(&addr, "b", "tok-b").unwrap();
    assert!(ok(&post(&mut a1, "t", json!(1))));
    assert!(ok(&post(&mut b, "t", json!(1))));
    assert_eq!(post(&mut a2, "t", json!(2))["error"], json!("rate exceeded"));
    assert_eq!(post(&mut b, "t", json!(2))["error"], json!("rate exceeded"));
    assert_eq!(stats(&mut a1)["rate_limited"], json!(2));
    server.set_fixed_now(Some(T0 + 2.0));
    assert!(ok(&post(&mut a2, "t", json!(3))));
    assert!(ok(&post(&mut b, "t", json!(3))));
    server.set_fixed_now(None);
}

// Shared-agent policy changes: no fabricated credit, no over-burst.
#[test]
fn shared_agent_policy_change_no_fabrication_no_overburst() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-slow": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 1},
            "tok-fast": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 10}
        }"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("policy-change", tokens);
    server.set_fixed_now(Some(T0));
    let mut slow = Client::connect(&addr, "a", "tok-slow").unwrap();
    let mut fast = Client::connect(&addr, "a", "tok-fast").unwrap();
    // Slow spends the shared (a, "*") bucket at T0.
    assert!(ok(&post(&mut slow, "t", json!(1))));
    // +0.5s at fast policy: min(1,10)=1 refill gives 0.5 tokens, denies.
    // Legacy fast refill (0.5*10=5) would allow.
    server.set_fixed_now(Some(T0 + 0.5));
    let r = post(&mut fast, "t", json!(2));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(r["retry_after_ms"], json!(50.0), "{r}");
    // +0.1s more at fast: 0.5+1.0=1.5, allows (no lockout; 0.1
    // avoids large-T0 float-boundary flake at exactly 0.05).
    server.set_fixed_now(Some(T0 + 0.6));
    assert!(ok(&post(&mut fast, "t", json!(3))));
    // Fast accumulates: ~1s later allows with 9 left.
    server.set_fixed_now(Some(T0 + 1.6));
    assert!(ok(&post(&mut fast, "t", json!(4))));
    // Immediate slow policy caps 9 to new burst 1: allows once.
    let r = post(&mut slow, "t", json!(5));
    assert!(ok(&r), "{r} (reduction caps, no lockout)");
    // Next slow immediate denies (no 9-deep over-burst).
    let r = post(&mut slow, "t", json!(6));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    assert_eq!(stats(&mut slow)["posts"], json!(4));
    assert_eq!(stats(&mut slow)["rate_limited"], json!(2));
    server.set_fixed_now(None);
}

// Tiny rates refuse at load; smallest allowed wire rate stays finite.
#[test]
fn tiny_rates_refuse_at_load_and_small_allows_first() {
    for bad in [
        r#"{"t": {"agent": "a", "rate_per_s": 1e-306}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": 1e-310}}"#,
        r#"{"t": {"agent": "a", "rate_per_s": 5e-324}}"#,
        r#"{"t": {"agent": "a", "topic_rates": {"b": 1e-310}}}"#,
    ] {
        let err = TokenStore::from_json_str(bad).expect_err("must refuse tiny");
        let msg = err.to_string();
        assert!(msg.contains("finite retry"), "{msg}");
        assert!(!msg.contains("tok-") && !msg.contains("\"t\""), "echoed: {msg}");
    }
    // 1e-3/s wire: first allows, immediate denies with finite 1e6ms.
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"], "rate_per_s": 0.001}}"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("tiny-small", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "a", "tok-a").unwrap();
    assert!(ok(&post(&mut c, "t", json!(1))));
    let r = post(&mut c, "t", json!(2));
    assert_eq!(r["error"], json!("rate exceeded"), "{r}");
    let hint = r["retry_after_ms"].as_f64().expect("finite number hint");
    assert!(hint.is_finite(), "{r}");
    assert!((hint - 1_000_000.0).abs() < 1e-6, "{r}");
    server.set_fixed_now(Some(T0 + 1000.0));
    assert!(ok(&post(&mut c, "t", json!(3))));
    server.set_fixed_now(None);
}
