//! Native introspection: `topics`/`limits`/`stats` over the live server.
//!
//! No Python, no production IO, no wall sleeps: each test pins its own WAL,
//! fixture tokens, ephemeral loopback port, and fixed clock (`set_fixed_now`
//! plus `set_started_for_test` for deterministic `uptime_s`). Proves the
//! `wire.rs` introspection ops are source-backed (policy visibility, live
//! `BusState`/presence/KV/WAL/started/posts/subscriptions/quotas):
//! subscription counters live since `native-broker-subscriptions`,
//! `rate_limited` since `native-post-rate-limits`, `quota_denied` +
//! `art_used_bytes` + `art_*` since `native-artifact-quota-migration`
//! (see `docs/NATIVE_ARTIFACTS.md`); only `token_list` stays unknown.
//! Proves the native CLI
//! `stats`/`topics`/`limits`/`subs` (json + short) work against ephemeral
//! servers without leaking credentials.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use agent_bus::acl::TokenStore;
use agent_bus::presence::round1_py;
use agent_bus::wal::snapshot_path_for;
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-introspection-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn open_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["board.build"], "subscribe": ["board.build"]}
        }"#,
    )
    .expect("fixture tokens valid")
}

fn limited_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"],
                "art_quota_bytes": 1048576, "rate_per_s": 10,
                "topic_rates": {"board.*": 5, "inbox.alice": 2}},
            "tok-bob": {"agent": "bob", "publish": ["board.build"], "subscribe": ["board.build"]},
            "tok-falsy0": {"agent": "f0", "publish": [], "subscribe": [], "topic_rates": 0},
            "tok-falsyfalse": {"agent": "f1", "publish": [], "subscribe": [], "topic_rates": false},
            "tok-falsystr": {"agent": "f2", "publish": [], "subscribe": [], "topic_rates": ""},
            "tok-falsyarr": {"agent": "f3", "publish": [], "subscribe": [], "topic_rates": []},
            "tok-falsyobj": {"agent": "f4", "publish": [], "subscribe": [], "topic_rates": {}},
            "tok-falsynull": {"agent": "f5", "publish": [], "subscribe": [], "topic_rates": null}
        }"#,
    )
    .expect("fixture tokens valid")
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

fn start_handle(name: &str) -> (String, PathBuf, Server) {
    start_with_handle(name, open_tokens())
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn post(c: &mut Client, topic: &str, payload: Value) -> Value {
    c.rpc(&json!({"op": "post", "topic": topic, "payload": payload}))
        .unwrap()
}

// Topics are sorted, filtered by `subscribe` cover, with high-water seq.
#[test]
fn topics_sorted_filtered_with_high_water_seq() {
    let (addr, _wal, server) = start_handle("topics-filter");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Post out of order; listing must sort.
    assert!(ok(&post(&mut a, "board.build", json!({"n": 1}))));
    assert!(ok(&post(&mut a, "inbox.alice", json!({"n": 2}))));
    assert!(ok(&post(&mut a, "board.announce", json!({"n": 3}))));
    assert!(ok(&post(&mut a, "board.build", json!({"n": 4}))));

    // Alice sees all three (wildcard), sorted.
    let out = a.rpc(&json!({"op": "topics"})).unwrap();
    assert!(ok(&out), "{out}");
    let topics = out["topics"].as_array().unwrap();
    let names: Vec<&str> = topics
        .iter()
        .map(|t| t["topic"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["board.announce", "board.build", "inbox.alice"],
        "{out}"
    );
    // board.build has seq 2 (two posts), retained 2, last_ts T0.
    let build = topics.iter().find(|t| t["topic"] == "board.build").unwrap();
    assert_eq!(build["seq"], json!(2), "{out}");
    assert_eq!(build["retained"], json!(2), "{out}");
    assert_eq!(build["last_ts"], json!(T0), "{out}");

    // Bob sees only board.build (exact cover), not board.announce.
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b.rpc(&json!({"op": "topics"})).unwrap();
    assert!(ok(&out), "{out}");
    let topics = out["topics"].as_array().unwrap();
    assert_eq!(topics.len(), 1, "{out}");
    assert_eq!(topics[0]["topic"], json!("board.build"), "{out}");
    server.set_fixed_now(None);
}

// Topics filter expired synchronously; seq stays high-water, last_ts nulls.
#[test]
fn topics_live_expiry_filtering_nulls_last_ts() {
    let (addr, _wal, server) = start_handle("topics-expiry");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // One expiring post (1s TTL) and one retained post.
    let r = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1, "ttl_ms": 1000.0}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert!(ok(&post(&mut c, "board.build", json!(2))));

    let out = c.rpc(&json!({"op": "topics"})).unwrap();
    assert_eq!(out["topics"][0]["seq"], json!(2), "{out}");
    assert_eq!(out["topics"][0]["retained"], json!(2), "{out}");

    // Past expiry: retained drops to 1 (live only), seq stays 2.
    server.set_fixed_now(Some(T0 + 2.0));
    let out = c.rpc(&json!({"op": "topics"})).unwrap();
    assert_eq!(out["topics"][0]["seq"], json!(2), "{out}");
    assert_eq!(out["topics"][0]["retained"], json!(1), "{out}");
    assert_eq!(out["topics"][0]["last_ts"], json!(T0), "{out}");

    // Expire-all topic: retained 0, last_ts null, seq preserved.
    let r = c
        .rpc(&json!({"op": "post", "topic": "board.temp", "payload": 1, "ttl_ms": 1000.0}))
        .unwrap();
    assert!(ok(&r), "{r}");
    server.set_fixed_now(Some(T0 + 5.0));
    let out = c.rpc(&json!({"op": "topics"})).unwrap();
    let temp = out["topics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["topic"] == "board.temp")
        .cloned()
        .unwrap();
    assert_eq!(temp["seq"], json!(1), "{out}");
    assert_eq!(temp["retained"], json!(0), "{out}");
    assert_eq!(temp["last_ts"], Value::Null, "{out}");
    server.set_fixed_now(None);
}

// Topics requires auth and fails closed on non-finite clocks.
#[test]
fn topics_requires_auth_and_rejects_nonfinite() {
    let (addr, _wal, server) = start_handle("topics-auth");
    server.set_fixed_now(Some(T0));
    let mut raw = Client::raw(&addr).unwrap();
    let r = raw.rpc(&json!({"op": "topics"})).unwrap();
    assert_eq!(
        r.get("error"),
        Some(&json!("auth required (send hello first)")),
        "{r}"
    );
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        server.set_fixed_now(Some(bad));
        let r = c.rpc(&json!({"op": "topics"})).unwrap();
        assert_eq!(r.get("error"), Some(&json!("non-finite time")), "{r}");
    }
    server.set_fixed_now(None);
}

// Limits echoes preserved policy config; usage is actual 0; rate enforced.
#[test]
fn limits_echoes_policy_config_with_rate_enforcement() {
    let (addr, _wal, server) = start_with_handle("limits-cfg", limited_tokens());
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = a.rpc(&json!({"op": "limits"})).unwrap();
    assert!(ok(&out), "{out}");
    assert_eq!(out["art_used_bytes"], json!(0), "{out}");
    assert_eq!(out["art_quota_bytes"], json!(1048576), "{out}");
    assert_eq!(out["rate_per_s"], json!(10), "{out}");
    assert_eq!(
        out["topic_rates"],
        json!({"board.*": 5, "inbox.alice": 2}),
        "{out}"
    );

    // Scoped token without extras: nulls and {}.
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(out["art_used_bytes"], json!(0), "{out}");
    assert_eq!(out["art_quota_bytes"], Value::Null, "{out}");
    assert_eq!(out["rate_per_s"], Value::Null, "{out}");
    assert_eq!(out["topic_rates"], json!({}), "{out}");

    // Burst 5 allows five rapid posts (rate enforced, see rate_wire.rs).
    for i in 0..5 {
        let r = post(&mut a, "board.build", json!({"i": i}));
        assert!(ok(&r), "{r}");
    }
    // Sixth immediate would exhaust (tested in rate_wire.rs); refill 1s
    // for the idempotency checks below.
    server.set_fixed_now(Some(T0 + 1.0));
    // Post idempotency (see docs/NATIVE_IDEMPOTENCY.md): same id + same
    // payload dedups to the original seq; same id + different payload
    // conflicts without mutation (dup/conflict spend no rate budget).
    let r1 = a
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1, "msg_id": "dup1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    let r2 = a
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1, "msg_id": "dup1"}))
        .unwrap();
    assert!(ok(&r2), "{r2}");
    assert_eq!(r1["seq"], r2["seq"], "retry must return original seq");
    assert_eq!(r2["dup"], json!(true), "{r2}");
    let r3 = a
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 2, "msg_id": "dup1"}))
        .unwrap();
    assert!(r3.get("error").is_some(), "{r3}");
    assert!(
        r3["error"].as_str().unwrap().contains("msg_id conflict"),
        "{r3}"
    );

    // ACL-only stubs stay Unsupported (buckets live in wire for rate,
    // `ArtifactStore` + WAL in wire for quota; see `NATIVE_ARTIFACTS.md`).
    let store = limited_tokens();
    let policy = store.get("tok-alice").unwrap();
    assert!(policy.enforce_rate_limit("board.build").is_err());
    assert!(policy.enforce_artifact_quota(1).is_err());
    server.set_fixed_now(None);
}

// Limits `topic_rates` follows Python `or {}` falsiness exactly.
#[test]
fn limits_topic_rates_falsy_matches_python_or() {
    let (addr, _wal, server) = start_with_handle("limits-falsy", limited_tokens());
    server.set_fixed_now(Some(T0));
    // Falsy values (0/false/""/[]/{}/null/missing) all yield {}.
    for (agent, token) in [
        ("f0", "tok-falsy0"),
        ("f1", "tok-falsyfalse"),
        ("f2", "tok-falsystr"),
        ("f3", "tok-falsyarr"),
        ("f4", "tok-falsyobj"),
        ("f5", "tok-falsynull"),
    ] {
        let mut c = Client::connect(&addr, agent, token).unwrap();
        let out = c.rpc(&json!({"op": "limits"})).unwrap();
        assert_eq!(out["topic_rates"], json!({}), "{agent}: {out}");
    }
    // Missing key (bob) also yields {}.
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(out["topic_rates"], json!({}), "{out}");
    // Truthy non-objects (e.g. [1]) reject at load (fail-closed, see
    // rate_wire.rs); they never reach limits echo.
    for bad in [
        r#"{"t": {"agent": "x", "topic_rates": [1]}}"#,
        r#"{"t": {"agent": "x", "topic_rates": "s"}}"#,
        r#"{"t": {"agent": "x", "topic_rates": 5}}"#,
    ] {
        assert!(TokenStore::from_json_str(bad).is_err(), "{bad}");
    }
    // Limits needs no clock: works even when fixed is non-finite.
    let mut c = Client::connect(&addr, "f0", "tok-falsy0").unwrap();
    server.set_fixed_now(Some(f64::NAN));
    let out = c.rpc(&json!({"op": "limits"})).unwrap();
    assert!(ok(&out), "{out}");
    server.set_fixed_now(None);
}

// Stats fields are source-backed: started/posts/topics/agents/kv/wal/uptime.
#[test]
fn stats_source_backed_fields_reflect_live_broker() {
    let (addr, wal, server) = start_handle("stats-src");
    server.set_started_for_test(T0);
    server.set_fixed_now(Some(T0));
    // Fresh WAL (no file yet): wal_bytes 0, posts 0, topics 0.
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = c.rpc(&json!({"op": "stats"})).unwrap();
    assert!(ok(&out), "{out}");
    assert_eq!(out["stats"]["started"], json!(T0), "{out}");
    assert_eq!(out["stats"]["posts"], json!(0), "{out}");
    assert_eq!(out["stats"]["topics"], json!(0), "{out}");
    assert_eq!(out["stats"]["agents"], json!(1), "{out}");
    assert_eq!(out["stats"]["kv_keys"], json!(0), "{out}");
    assert_eq!(out["stats"]["wal_bytes"], json!(0), "{out}");
    assert_eq!(out["stats"]["uptime_s"], json!(0.0), "{out}");

    // Two posts + one KV put + bob joins.
    assert!(ok(&post(&mut c, "board.build", json!(1))));
    assert!(ok(&post(&mut c, "board.announce", json!(2))));
    let r = c
        .rpc(&json!({"op": "kv_put", "key": "k1", "value": 1}))
        .unwrap();
    assert!(ok(&r), "{r}");
    let _b = Client::connect(&addr, "bob", "tok-bob").unwrap();

    server.set_fixed_now(Some(T0 + 2.25));
    let out = c.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(2), "{out}");
    assert_eq!(out["stats"]["topics"], json!(2), "{out}");
    assert_eq!(out["stats"]["agents"], json!(2), "{out}");
    assert_eq!(out["stats"]["kv_keys"], json!(1), "{out}");
    // wal_bytes matches the live file size.
    let size = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert!(size > 0, "WAL must exist after posts");
    assert_eq!(out["stats"]["wal_bytes"], json!(size), "{out}");
    // uptime uses Python half-even round1 (2.25 -> 2.2).
    assert_eq!(out["stats"]["uptime_s"], json!(round1_py(2.25)), "{out}");
    assert_eq!(out["stats"]["uptime_s"], json!(2.2), "{out}");
    server.set_fixed_now(None);
}

// Stats posts counts durable live posts only (denied/failed/replay excluded).
#[test]
fn stats_posts_counts_durable_only() {
    let (addr, _wal, server) = start_handle("stats-posts");
    server.set_started_for_test(T0);
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    // Bob cannot publish inbox.alice: denied, no increment.
    let r = b
        .rpc(&json!({"op": "post", "topic": "inbox.alice", "payload": 1}))
        .unwrap();
    assert!(r.get("error").is_some(), "{r}");
    let out = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(0), "{out}");

    // One durable post increments.
    assert!(ok(&post(&mut a, "board.build", json!(1))));
    let out = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(1), "{out}");

    // WAL append failure: no increment, no visibility.
    server.set_append_failpoint(agent_bus::wal::APPEND_FAIL_OPEN);
    let r = post(&mut a, "board.build", json!(2));
    assert!(r.get("error").is_some(), "{r}");
    server.set_append_failpoint(agent_bus::wal::APPEND_FAIL_NONE);
    let out = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(1), "{out}");

    // Replay exclusion: a server started on a WAL with posts reports 0.
    let wal2 = wal_path("stats-replay");
    let _ = std::fs::remove_file(&wal2);
    let _ = std::fs::remove_file(snapshot_path_for(&wal2));
    // Seed the WAL via a first server, then drop it (lock released on drop
    // of all clones? No: lock is Arc-held by handle; drop handle first).
    // Simpler: write one post record directly via the WAL append helper.
    agent_bus::wal::append_fsync(
        &wal2,
        &json!({"t": "post", "topic": "board.build",
            "msg": {"seq": 1, "id": "seed1", "sender": "alice", "ts": T0,
                "exp": null, "payload": 1}}),
    )
    .unwrap();
    let tokens = open_tokens();
    let srv = Server::new(wal2.clone(), tokens).unwrap();
    assert_eq!(srv.posts(), 0, "replay must not increment posts");
    server.set_fixed_now(None);
    let _ = std::fs::remove_file(&wal2);
}

// Stats requires auth, fails on non-finite clocks, prunes stale presence.
#[test]
fn stats_requires_auth_rejects_nonfinite_and_prunes() {
    let (addr, _wal, server) = start_handle("stats-auth");
    server.set_started_for_test(T0);
    server.set_fixed_now(Some(T0));
    let mut raw = Client::raw(&addr).unwrap();
    let r = raw.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(
        r.get("error"),
        Some(&json!("auth required (send hello first)")),
        "{r}"
    );
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let _b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        server.set_fixed_now(Some(bad));
        let r = a.rpc(&json!({"op": "stats"})).unwrap();
        assert_eq!(r.get("error"), Some(&json!("non-finite time")), "{r}");
    }
    server.set_fixed_now(Some(T0));
    server.set_started_for_test(f64::NAN);
    let r = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(r.get("error"), Some(&json!("non-finite time")), "{r}");
    server.set_started_for_test(T0);

    // Prune: bob goes stale (>86400), alice's stats call refreshes alice
    // (generic liveness) then prunes bob, leaving 1 agent.
    server.set_fixed_now(Some(T0 + 86400.0 + 20.0));
    let out = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["agents"], json!(1), "{out}");
    server.set_fixed_now(None);
}

// Subscription + rate + quota counters now supported (live
// `deliveries`/`drops`/`replays`/`subs`/`rate_limited`/
// `quota_denied`); artifact ops are live (see `artifacts.rs` and
// `docs/NATIVE_ARTIFACTS.md`); only `token_list` stays unknown
// (`token_claim` is live, see `token_admin.rs`). See
// `docs/NATIVE_SUBSCRIPTIONS.md`, `docs/NATIVE_RATE_LIMITS.md`, and
// `docs/NATIVE_ARTIFACTS.md`.
#[test]
fn subscription_counters_supported_and_remaining_gaps_omitted() {
    let (addr, _wal, server) = start_handle("stats-gaps");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = c.rpc(&json!({"op": "stats"})).unwrap();
    let stats = out["stats"].as_object().unwrap();
    // Live counters are present numbers (0 when idle), including quota
    // and owned-staging cleanup failures (disconnect/commit/abort unlink).
    for live in [
        "deliveries",
        "drops",
        "replays",
        "subs",
        "rate_limited",
        "quota_denied",
        "staging_cleanup_failed",
    ] {
        assert!(stats[live].is_number(), "missing {live}: {out}");
    }
    // Fourteen source-backed keys (seven + four subscription + rate + quota + staging cleanup).
    let mut keys: Vec<&str> = stats.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "agents",
            "deliveries",
            "drops",
            "kv_keys",
            "posts",
            "quota_denied",
            "rate_limited",
            "replays",
            "staging_cleanup_failed",
            "started",
            "subs",
            "topics",
            "uptime_s",
            "wal_bytes"
        ],
        "{out}"
    );
    for op in ["token_list"] {
        let r = c.rpc(&json!({"op": op})).unwrap();
        let err = r.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert!(err.starts_with("unknown op:"), "{op}: {r}");
    }
    // Artifact ops are live, not unknown: empty `art_put` stores empty
    // bytes (legacy allows len 0), empty `art_get` misses as not-found.
    let r = c.rpc(&json!({"op": "art_put", "data_b64": ""})).unwrap();
    assert!(ok(&r) && r["sha"].is_string(), "{r}");
    let r = c.rpc(&json!({"op": "art_get", "sha": ""})).unwrap();
    assert_eq!(r["error"], json!("artifact not found"), "{r}");
    // `token_claim` is live: claimless caller hits the claim negative.
    let r = c.rpc(&json!({"op": "token_claim"})).unwrap();
    assert_eq!(r["error"], json!("claim token required"), "{r}");
    // Subscription ops are now supported (not unknown): `subs` lists,
    // `unsubscribe` is idempotent ok. (`subscribe` needs a streaming
    // reader for replay; see `rust/tests/subscriptions.rs`.)
    let r = c.rpc(&json!({"op": "subs"})).unwrap();
    assert!(ok(&r) && r["subs"].is_array(), "{r}");
    let r = c.rpc(&json!({"op": "unsubscribe", "sub_id": "deadbeefcafe"})).unwrap();
    assert!(ok(&r), "{r}");
    server.set_fixed_now(None);
}

// Introspection ops refresh presence liveness (ping-negative preserved).
#[test]
fn introspection_ops_refresh_liveness() {
    let (addr, _wal, server) = start_handle("intro-live");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Alice touches via each introspection op at successive times.
    server.set_fixed_now(Some(T0 + 10.0));
    assert!(ok(&a.rpc(&json!({"op": "topics"})).unwrap()));
    server.set_fixed_now(Some(T0 + 20.0));
    assert!(ok(&a.rpc(&json!({"op": "limits"})).unwrap()));
    server.set_fixed_now(Some(T0 + 30.0));
    assert!(ok(&a.rpc(&json!({"op": "stats"})).unwrap()));
    // Bob observes: alice age 0 (touched at +30), proving all three touched.
    server.set_fixed_now(Some(T0 + 30.0));
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["age_s"], json!(0.0), "{out}");
    // Ping still never touches: alice pings at +40, bob sees age 10.
    server.set_fixed_now(Some(T0 + 40.0));
    let r = a.rpc(&json!({"op": "ping"})).unwrap();
    assert!(ok(&r), "{r}");
    let out = b.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["age_s"], json!(10.0), "{out}");
    server.set_fixed_now(None);
}

// Stats is global (unfiltered) while topics respects subscribe grants.
#[test]
fn stats_global_counts_vs_topics_filtered_visibility() {
    let (addr, _wal, server) = start_handle("intro-vis");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut a, "board.build", json!(1))));
    assert!(ok(&post(&mut a, "board.secret", json!(2))));
    // Bob's topics shows only board.build, but his stats sees both topics.
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let t = b.rpc(&json!({"op": "topics"})).unwrap();
    assert_eq!(t["topics"].as_array().unwrap().len(), 1, "{t}");
    let s = b.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(s["stats"]["topics"], json!(2), "{s}");
    assert_eq!(s["stats"]["posts"], json!(2), "{s}");
    server.set_fixed_now(None);
}

// Introspection never leaks tokens, grants, or peer addresses.
#[test]
fn introspection_responses_contain_no_credentials() {
    let (addr, _wal, server) = start_with_handle("intro-leak", limited_tokens());
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut c, "board.build", json!(1))));
    for op in ["topics", "limits", "stats"] {
        let out = c.rpc(&json!({"op": op})).unwrap();
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("tok-alice"), "{op} leaked token: {text}");
        assert!(!text.contains("tok-bob"), "{op} leaked token: {text}");
        assert!(!text.contains("127.0.0.1"), "{op} leaked addr: {text}");
    }
    // Limits echoes quota/rate config but never the token itself.
    let out = c.rpc(&json!({"op": "limits"})).unwrap();
    assert!(ok(&out));
    server.set_fixed_now(None);
}

// Native CLI stats/topics/limits (json + short) on an ephemeral server.
#[test]
fn native_cli_stats_topics_limits_on_ephemeral_server() {
    fn cli_bin() -> String {
        env!("CARGO_BIN_EXE_agent-bus").to_string()
    }
    fn run_cli(
        addr: &str,
        agent: &str,
        token: &str,
        args: &[&str],
    ) -> (i32, String, String) {
        let (host, port) = addr.rsplit_once(':').expect("addr has port");
        let out = Command::new(cli_bin())
            .args(args)
            .env("AGENT_BUS_AGENT", agent)
            .env("AGENT_BUS_TOKEN", token)
            .env_remove("AGENT_BUS_SOCK")
            .env("AGENT_BUS_HOST", host)
            .env("AGENT_BUS_PORT", port)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn agent-bus");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    let (addr, _wal, server) = start_with_handle("cli-intro", limited_tokens());
    server.set_started_for_test(T0);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut c, "board.build", json!({"n": 1}))));

    // stats json: twelve source-backed keys, subscription + rate live.
    let (st, stdout, stderr) = run_cli(&addr, "alice", "tok-alice", &["stats", "--format", "json"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    assert!(!stdout.contains("tok-alice") && !stderr.contains("tok-alice"));
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&resp), "{resp}");
    assert_eq!(resp["stats"]["posts"], json!(1), "{resp}");
    assert_eq!(resp["stats"]["topics"], json!(1), "{resp}");
    assert_eq!(resp["stats"]["subs"], json!(0), "{resp}");
    assert_eq!(resp["stats"]["drops"], json!(0), "{resp}");
    assert_eq!(resp["stats"]["deliveries"], json!(0), "{resp}");
    assert_eq!(resp["stats"]["replays"], json!(0), "{resp}");
    assert_eq!(resp["stats"]["rate_limited"], json!(0), "{resp}");

    // stats short: one line with numbers for live counters.
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["stats", "--format", "short"]);
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains("posts 1"), "{stdout}");
    assert!(stdout.contains("topics 1"), "{stdout}");
    assert!(stdout.contains("subs 0"), "{stdout}");
    assert!(stdout.contains("drops 0"), "{stdout}");
    assert!(stdout.contains("rl 0"), "{stdout}");
    assert!(!stdout.contains("tok-alice"), "{stdout}");

    // topics json + short.
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["topics", "--format", "json"]);
    assert_eq!(st, 0, "{stdout}");
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(resp["topics"][0]["topic"], json!("board.build"), "{resp}");
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["topics", "--format", "short"]);
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains("board.build"), "{stdout}");
    assert!(stdout.contains("seq=1"), "{stdout}");
    assert!(stdout.contains("retained=1"), "{stdout}");

    // limits json + short (quota/rate from policy, usage 0).
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["limits", "--format", "json"]);
    assert_eq!(st, 0, "{stdout}");
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(resp["art_used_bytes"], json!(0), "{resp}");
    assert_eq!(resp["art_quota_bytes"], json!(1048576), "{resp}");
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["limits", "--format", "short"]);
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains("art 0B/1.0MB"), "{stdout}");
    assert!(stdout.contains("rate 10/s"), "{stdout}");
    assert!(stdout.contains("+2 topic-rates"), "{stdout}");

    // Scoped limits short: infinities for missing quota/rate.
    let (st, stdout, _) = run_cli(&addr, "bob", "tok-bob", &["limits", "--format", "short"]);
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains("art 0B/\u{221e}"), "{stdout}");
    assert!(stdout.contains("rate \u{221e}"), "{stdout}");

    // Usage errors: bad format, unknown flag, positional all exit 2.
    for args in [
        vec!["stats", "--format", "yaml"],
        vec!["topics", "--bogus"],
        vec!["limits", "extra"],
    ] {
        let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &args);
        assert_eq!(st, 2, "{args:?} stderr={stderr}");
    }
    // subs is now supported at the CLI (empty list, exit 0).
    let (st, stdout, stderr) = run_cli(&addr, "alice", "tok-alice", &["subs"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&resp) && resp["subs"].is_array(), "{resp}");
    server.set_fixed_now(None);
}
