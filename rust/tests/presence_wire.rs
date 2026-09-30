//! Presence wire integration: `heartbeat`/`agents` lifecycle over live server.
//!
//! No Python, no production IO, no wall sleeps: each test pins its own WAL,
//! fixture tokens, ephemeral loopback port, and fixed clock (`set_fixed_now`).
//! Proves the reviewed `presence.rs` core is the live wire decision:
//! auth-only presence, hello reconnect preservation, generic liveness
//! (ping-negative), exact 600s online / 24h prune boundaries, multi-conn
//! sharing, no lease renewal, no credential exposure, non-finite fail-closed,
//! and native CLI `heartbeat` then `agents` against an ephemeral server.
//! `token_claim`/bootstrap retirement is live (see `token_admin.rs`);
//! `token_list` stays the explicit unknown-op gap; `subs`/`subscribe`/
//! `unsubscribe` landed separately (see `rust/tests/subscriptions.rs`);
//! `stats`/`topics`/`limits` landed separately (see
//! `rust/tests/introspection.rs`).

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use agent_bus::acl::TokenStore;
use agent_bus::presence::{coerce_status, round1_py, truncate_status, PresenceStore};
use agent_bus::wal::snapshot_path_for;
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-presence-{name}-{}", std::process::id()));
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

fn agents_of(resp: &Value) -> &serde_json::Map<String, Value> {
    resp.get("agents")
        .and_then(|v| v.as_object())
        .expect("agents object")
}

// Pure core: touch/hello/prune/retire/coerce/round boundaries.
#[test]
fn presence_pure_boundaries() {
    // Truncation: 200 chars, Unicode scalar.
    assert_eq!(truncate_status(&"a".repeat(300)).chars().count(), 200);
    assert_eq!(truncate_status("hi"), "hi");
    let uni = "é".repeat(250);
    assert_eq!(truncate_status(&uni).chars().count(), 200);
    // Coercion: Python `str` shape for scalars, compact JSON for containers.
    assert_eq!(coerce_status(&json!(true)), "True");
    assert_eq!(coerce_status(&json!(false)), "False");
    assert_eq!(coerce_status(&json!(123)), "123");
    assert_eq!(coerce_status(&json!("x")), "x");
    assert_eq!(coerce_status(&json!({"a": 1})), r#"{"a":1}"#);
    // Round half-even on exact halves.
    assert_eq!(round1_py(2.25), 2.2);
    assert_eq!(round1_py(1.75), 1.8);

    let mut s = PresenceStore::new();
    // Empty/retired/non-finite never add.
    assert!(!s.touch("", Some("x"), T0, "p"));
    assert!(!s.touch("a", Some("x"), f64::NAN, "p"));
    assert!(s.is_empty());
    // Hello new -> online, reconnect preserves.
    assert!(s.hello_touch("alice", T0, "p1"));
    assert_eq!(s.get("alice").unwrap().status, "online");
    assert!(s.touch("alice", Some("working"), T0 + 1.0, "p1"));
    assert!(s.hello_touch("alice", T0 + 2.0, "p2"));
    assert_eq!(s.get("alice").unwrap().status, "working");
    assert_eq!(s.get("alice").unwrap().last_seen, T0 + 2.0);
    // Null-preserve is wire-level (touch None); direct None preserves too.
    assert!(s.touch("alice", None, T0 + 3.0, "p2"));
    assert_eq!(s.get("alice").unwrap().status, "working");
    // Online boundary: <=600 online.
    let snap = s.agents_snapshot(T0 + 3.0 + 600.0).unwrap();
    assert_eq!(snap["alice"]["online"], json!(true));
    assert_eq!(snap["alice"]["age_s"], json!(600.0));
    let snap = s.agents_snapshot(T0 + 3.0 + 600.1).unwrap();
    assert_eq!(snap["alice"]["online"], json!(false));
    // Retention boundary: ==86400 kept, >86400 pruned.
    s.prune(T0 + 3.0 + 86400.0);
    assert!(s.contains("alice"));
    s.prune(T0 + 3.0 + 86400.1);
    assert!(!s.contains("alice"));
    // Retire suppresses re-add for 1h, then prunes.
    assert!(s.hello_touch("bob", T0, "p"));
    s.retire("bob", T0 + 10.0);
    assert!(!s.contains("bob"));
    assert!(s.is_retired("bob"));
    assert!(!s.touch("bob", Some("x"), T0 + 20.0, "p"));
    assert!(!s.hello_touch("bob", T0 + 20.0, "p"));
    s.prune(T0 + 10.0 + 3600.0);
    assert!(s.is_retired("bob"));
    s.prune(T0 + 10.0 + 3600.1);
    assert!(!s.is_retired("bob"));
    assert!(s.hello_touch("bob", T0 + 3700.0, "p"));
    assert_eq!(s.get("bob").unwrap().status, "online");
    // Non-finite snapshot/prune fail closed.
    assert!(s.agents_snapshot(f64::NAN).is_none());
    let n = s.len();
    s.prune(f64::INFINITY);
    assert_eq!(s.len(), n);
}

// Unauthenticated ops cannot add presence; bad hello leaves no ghost.
#[test]
fn unauthenticated_presence_ops_cannot_add_presence() {
    let (addr, _wal, server) = start_handle("unauth");
    server.set_fixed_now(Some(T0));
    let mut raw = Client::raw(&addr).unwrap();
    let hb = raw
        .rpc(&json!({"op": "heartbeat", "status": "ghost"}))
        .unwrap();
    assert_eq!(
        hb.get("error"),
        Some(&json!("auth required (send hello first)"))
    );
    let ag = raw.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(
        ag.get("error"),
        Some(&json!("auth required (send hello first)"))
    );
    // Bad token hello fails and adds nothing.
    let bad = raw
        .rpc(&json!({"op": "hello", "agent": "alice", "token": "tok-wrong"}))
        .unwrap();
    assert!(bad.get("error").is_some());
    // Authenticated roster has only the authed agent (hello adds it).
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert!(ok(&out), "{out}");
    let agents = agents_of(&out);
    assert_eq!(agents.len(), 1, "{out}");
    assert!(agents.contains_key("alice"));
    assert!(!agents.contains_key("ghost"));
    server.set_fixed_now(None);
}

// Hello reconnect preserves heartbeat status; new agents get online.
#[test]
fn hello_reconnect_preserves_heartbeat_status() {
    let (addr, _wal, server) = start_handle("reconnect");
    server.set_fixed_now(Some(T0));
    let mut c1 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = c1.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("online"));
    c1.rpc(&json!({"op": "heartbeat", "status": "working"}))
        .unwrap();
    server.set_fixed_now(Some(T0 + 10.0));
    // Reconnect (new TCP conn, same agent) preserves status, refreshes age.
    let mut c2 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = c2.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("working"), "{out}");
    assert_eq!(out["agents"]["alice"]["age_s"], json!(0.0), "{out}");
    // New agent gets online.
    let mut cb = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = cb.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["bob"]["status"], json!("online"), "{out}");
    assert_eq!(out["agents"]["alice"]["status"], json!("working"), "{out}");
    server.set_fixed_now(None);
}

// Every authenticated op refreshes liveness; ping never does; unknown refreshes.
// Alice acts, bob observes (bob's touch never moves alice), so ages prove
// exactly which alice ops touched.
#[test]
fn authenticated_requests_refresh_liveness_ping_does_not() {
    let (addr, _wal, server) = start_handle("liveness");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "heartbeat", "status": "busy"}))
        .unwrap();
    // Post at T0+100 refreshes (status preserved, age reset).
    server.set_fixed_now(Some(T0 + 100.0));
    let r = c
        .rpc(&json!({"op": "post", "topic": "test.presence", "payload": {"n": 1}}))
        .unwrap();
    assert!(ok(&r), "{r}");
    let mut b1 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b1.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("busy"), "{out}");
    assert_eq!(out["agents"]["alice"]["age_s"], json!(0.0), "{out}");
    // Authenticated ping at T0+200 does not touch: alice age keeps growing.
    server.set_fixed_now(Some(T0 + 200.0));
    let p = c.rpc(&json!({"op": "ping"})).unwrap();
    assert!(ok(&p), "{p}");
    let mut b2 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b2.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["age_s"], json!(100.0), "{out}");
    assert_eq!(out["agents"]["alice"]["status"], json!("busy"), "{out}");
    // Unknown op at T0+250 refreshes (error still touches, like legacy).
    server.set_fixed_now(Some(T0 + 250.0));
    let u = c.rpc(&json!({"op": "bogus-op"})).unwrap();
    assert!(u.get("error").is_some(), "{u}");
    let mut b3 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b3.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["age_s"], json!(0.0), "{out}");
    // Advance to T0+260: age 10 proves the T0+250 unknown-op touch.
    server.set_fixed_now(Some(T0 + 260.0));
    let mut b4 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b4.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["age_s"], json!(10.0), "{out}");
    server.set_fixed_now(None);
}

// Exact 600s online boundary with fixed clock.
#[test]
fn age_online_600s_boundary_exact() {
    let (addr, _wal, server) = start_handle("online600");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "heartbeat", "status": "x"})).unwrap();
    // Observe from bob so alice's age is not refreshed by the read.
    server.set_fixed_now(Some(T0 + 599.9));
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["online"], json!(true), "{out}");
    assert_eq!(out["agents"]["alice"]["age_s"], json!(599.9), "{out}");
    server.set_fixed_now(Some(T0 + 600.0));
    let mut b2 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b2.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["online"], json!(true), "{out}");
    assert_eq!(out["agents"]["alice"]["age_s"], json!(600.0), "{out}");
    server.set_fixed_now(Some(T0 + 600.1));
    let mut b3 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b3.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["online"], json!(false), "{out}");
    assert_eq!(out["agents"]["alice"]["age_s"], json!(600.1), "{out}");
    let _ = c;
    server.set_fixed_now(None);
}

// Exact 24h pruning with fixed clock; active survives while idle drops.
#[test]
fn stale_24h_pruning_exact_with_fixed_clock() {
    let (addr, _wal, server) = start_handle("prune24h");
    server.set_fixed_now(Some(T0));
    let a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    // ==86400 kept.
    server.set_fixed_now(Some(T0 + 86400.0));
    let mut o = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = o.rpc(&json!({"op": "agents"})).unwrap();
    // Alice hello at T0+86400 refreshes alice; bob last_seen T0, delta 86400 kept.
    assert!(agents_of(&out).contains_key("alice"), "{out}");
    assert!(agents_of(&out).contains_key("bob"), "{out}");
    // >86400 prunes idle (bob), active (alice just touched) survives.
    server.set_fixed_now(Some(T0 + 86400.1));
    let mut o2 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = o2.rpc(&json!({"op": "agents"})).unwrap();
    assert!(agents_of(&out).contains_key("alice"), "{out}");
    assert!(!agents_of(&out).contains_key("bob"), "bob pruned: {out}");
    // Alice goes idle and prunes too.
    server.set_fixed_now(Some(T0 + 86400.1 + 86400.1));
    let mut o3 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = o3.rpc(&json!({"op": "agents"})).unwrap();
    assert!(agents_of(&out).contains_key("bob"), "{out}");
    assert!(
        !agents_of(&out).contains_key("alice"),
        "alice pruned: {out}"
    );
    let _ = (a, b);
    server.set_fixed_now(None);
}

// Multiple conns share one entry; disconnects never clear presence.
#[test]
fn multiple_connections_and_disconnects_share_presence() {
    let (addr, _wal, server) = start_handle("multiconn");
    server.set_fixed_now(Some(T0));
    let mut c1 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut c2 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c1.rpc(&json!({"op": "heartbeat", "status": "one"}))
        .unwrap();
    let out = c2.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("one"), "{out}");
    c2.rpc(&json!({"op": "heartbeat", "status": "two"}))
        .unwrap();
    let out = c1.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("two"), "{out}");
    // Drop one conn: presence stays.
    drop(c1);
    let out = c2.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("two"), "{out}");
    // Drop all: presence stays until prune.
    drop(c2);
    let mut c3 = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = c3.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("two"), "{out}");
    server.set_fixed_now(None);
}

// Presence never renews leases: absolute expiry wins over heartbeats.
#[test]
fn presence_never_renews_leases() {
    let (addr, _wal, server) = start_handle("norenew");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let ac = c
        .rpc(&json!({"op": "claim_acquire", "resource": "job.1", "ttl_ms": 60000}))
        .unwrap();
    assert!(ok(&ac), "{ac}");
    let f1 = ac["fencing"].as_u64().unwrap();
    // Heartbeats do not extend the 60s lease.
    c.rpc(&json!({"op": "heartbeat", "status": "still-here"}))
        .unwrap();
    server.set_fixed_now(Some(T0 + 61.0));
    c.rpc(&json!({"op": "heartbeat", "status": "still-here"}))
        .unwrap();
    let st = c
        .rpc(&json!({"op": "claim_status", "resource": "job.1"}))
        .unwrap();
    assert!(ok(&st), "{st}");
    assert_eq!(
        st.get("live"),
        Some(&json!(false)),
        "expired despite heartbeat: {st}"
    );
    // Re-acquire succeeds with higher fencing; presence still lists alice.
    let ac2 = c
        .rpc(&json!({"op": "claim_acquire", "resource": "job.1", "ttl_ms": 60000}))
        .unwrap();
    assert!(ok(&ac2), "{ac2}");
    assert!(ac2["fencing"].as_u64().unwrap() > f1, "{ac2}");
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert!(agents_of(&out).contains_key("alice"), "{out}");
    server.set_fixed_now(None);
}

// Agents exposes only status/age_s/online; never addr/token/grants.
#[test]
fn agents_exposes_only_status_age_online() {
    let (addr, _wal, server) = start_handle("noexpose");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "heartbeat", "status": "hi"})).unwrap();
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert!(ok(&out), "{out}");
    let agents = agents_of(&out);
    let info = agents.get("alice").unwrap().as_object().unwrap();
    let keys: Vec<&String> = info.keys().collect();
    assert_eq!(keys.len(), 3, "only 3 keys: {out}");
    assert!(info.contains_key("status"));
    assert!(info.contains_key("age_s"));
    assert!(info.contains_key("online"));
    let text = serde_json::to_string(&out).unwrap();
    assert!(!text.contains("tok-alice"), "token leaked: {text}");
    assert!(!text.contains("127.0.0.1"), "addr leaked: {text}");
    assert!(!text.contains("publish"), "grant leaked: {text}");
    assert!(!text.contains("subscribe"), "grant leaked: {text}");
    server.set_fixed_now(None);
}

// Heartbeat status shapes: missing->online, null preserves, coerce+trunc200.
#[test]
fn heartbeat_status_coercion_truncation_and_null_preserve() {
    let (addr, _wal, server) = start_handle("hbshape");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Missing status defaults to online.
    let r = c.rpc(&json!({"op": "heartbeat"})).unwrap();
    assert!(ok(&r), "{r}");
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("online"), "{out}");
    // Explicit status then null preserves.
    c.rpc(&json!({"op": "heartbeat", "status": "keep"}))
        .unwrap();
    c.rpc(&json!({"op": "heartbeat", "status": null})).unwrap();
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("keep"), "{out}");
    // Bool/number coerce like Python str.
    c.rpc(&json!({"op": "heartbeat", "status": true})).unwrap();
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("True"), "{out}");
    c.rpc(&json!({"op": "heartbeat", "status": 123})).unwrap();
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["status"], json!("123"), "{out}");
    // Containers render compact JSON (documented, not Python repr).
    c.rpc(&json!({"op": "heartbeat", "status": {"s": "v"}}))
        .unwrap();
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(
        out["agents"]["alice"]["status"],
        json!(r#"{"s":"v"}"#),
        "{out}"
    );
    // Long statuses truncate to 200 chars.
    let long = "z".repeat(300);
    c.rpc(&json!({"op": "heartbeat", "status": long})).unwrap();
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    let got = out["agents"]["alice"]["status"].as_str().unwrap();
    assert_eq!(got.chars().count(), 200, "trunc200");
    assert_eq!(got, &"z".repeat(200));
    server.set_fixed_now(None);
}

// Non-finite clocks fail closed; hello maps to auth failed (existing).
#[test]
fn nonfinite_clock_fails_closed() {
    let (addr, _wal, server) = start_handle("nonfinite");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        server.set_fixed_now(Some(bad));
        let hb = c.rpc(&json!({"op": "heartbeat", "status": "x"})).unwrap();
        assert_eq!(hb.get("error"), Some(&json!("non-finite time")), "{hb}");
        let ag = c.rpc(&json!({"op": "agents"})).unwrap();
        assert_eq!(ag.get("error"), Some(&json!("non-finite time")), "{ag}");
        // Hello with non-finite clock refuses (auth failed, no ghost).
        let mut raw = Client::raw(&addr).unwrap();
        let h = raw
            .rpc(&json!({"op": "hello", "agent": "bob", "token": "tok-bob"}))
            .unwrap();
        assert!(h.get("error").is_some(), "{h}");
    }
    server.set_fixed_now(Some(T0 + 5.0));
    let out = c.rpc(&json!({"op": "agents"})).unwrap();
    assert!(ok(&out), "{out}");
    assert!(agents_of(&out).contains_key("alice"));
    assert!(!agents_of(&out).contains_key("bob"));
    server.set_fixed_now(None);
}

// `token_claim` is live (claim auth, see `token_admin.rs`); `token_list`
// stays the explicit unknown-op gap. `stats`/`topics`/`limits` landed in
// `rust/tests/introspection.rs`; `subs`/`subscribe`/`unsubscribe` landed
// in `rust/tests/subscriptions.rs`; none are gaps here.
#[test]
fn token_claim_live_and_token_list_unknown_with_subs_supported() {
    let (addr, _wal, server) = start_handle("gaps");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Claimless caller hits the claim negative, never unknown-op.
    let r = c.rpc(&json!({"op": "token_claim"})).unwrap();
    assert_eq!(r["error"], json!("claim token required"), "{r}");
    let r = c.rpc(&json!({"op": "token_list"})).unwrap();
    let err = r.get("error").and_then(|e| e.as_str()).unwrap_or("");
    assert!(err.starts_with("unknown op:"), "token_list: {r}");
    // `subs` is now supported (empty list, not unknown).
    let r = c.rpc(&json!({"op": "subs"})).unwrap();
    assert!(ok(&r) && r["subs"].is_array(), "{r}");
    // Denied/unknown ops still refreshed liveness (generic touch before dispatch).
    server.set_fixed_now(Some(T0 + 50.0));
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b.rpc(&json!({"op": "agents"})).unwrap();
    // Alice touched at T0 via token_claim attempt and subs (both generic
    // touches); bob hello at T0+50. Alice age 50 proves the touch.
    assert_eq!(out["agents"]["alice"]["age_s"], json!(50.0), "{out}");
    server.set_fixed_now(None);
}

// Native CLI `heartbeat` then `agents` against an ephemeral native server.
#[test]
fn native_cli_heartbeat_then_agents_on_ephemeral_server() {
    fn cli_bin() -> String {
        env!("CARGO_BIN_EXE_agent-bus").to_string()
    }
    fn run_cli(addr: &str, args: &[&str]) -> (i32, String, String) {
        let (host, port) = addr.rsplit_once(':').expect("addr has port");
        let out = Command::new(cli_bin())
            .args(args)
            .env("AGENT_BUS_AGENT", "alice")
            .env("AGENT_BUS_TOKEN", "tok-alice")
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

    let (addr, _wal, server) = start_handle("cli-presence");
    server.set_fixed_now(Some(T0));
    // CLI heartbeat sets status over the real wire.
    let (st, stdout, stderr) = run_cli(&addr, &["heartbeat", "cli-working"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        !stdout.contains("tok-alice") && !stderr.contains("tok-alice"),
        "token leaked"
    );
    // CLI agents json shows the heartbeat with exact wire shape.
    let (st, stdout, stderr) = run_cli(&addr, &["agents", "--format", "json"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&resp), "{resp}");
    assert_eq!(
        resp["agents"]["alice"]["status"],
        json!("cli-working"),
        "{resp}"
    );
    assert_eq!(resp["agents"]["alice"]["online"], json!(true), "{resp}");
    // CLI reconnect preserves status (second agents still shows it).
    let (st, stdout, _) = run_cli(&addr, &["agents", "--format", "json"]);
    assert_eq!(st, 0);
    let resp2: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        resp2["agents"]["alice"]["status"],
        json!("cli-working"),
        "{resp2}"
    );
    // Short format renders `name age status` fresh-first.
    let (st, stdout, _) = run_cli(&addr, &["agents", "--format", "short"]);
    assert_eq!(st, 0);
    assert!(stdout.contains("alice"), "{stdout}");
    assert!(stdout.contains("cli-working"), "{stdout}");
    assert!(!stdout.contains("tok-alice"), "token leaked: {stdout}");
    server.set_fixed_now(None);
}
