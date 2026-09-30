//! KV wire integration: `kv` core over live `wire::Server` with ACL + WAL.
//!
//! No Python, no production IO: each test pins its own WAL file, fixture
//! tokens, and ephemeral loopback port (or child broker process). Proves the
//! reviewed `kv.rs` state plus `acl.rs` effective grants are the live wire
//! decision: put/get/del/list envelopes with `req_id`, missing/null fallback
//! vs explicit deny, prefix cover plus per-key filtering before the 1000 cap,
//! TTL/expiry boundaries, validate-before-durability rollback on failed
//! appends, mixed post/claim/KV replay and compaction, legacy snapshot
//! refusal (never silent discard), SIGKILL durability, and native CLI
//! compatibility against an ephemeral native server. Rate/quota/token-admin
//! stay preserved-but-unenforced (see `acl_wire.rs`); subscriptions and
//! artifacts stay unknown-op.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_bus::acl::TokenStore;
use agent_bus::kv::{expiry_for_ttl_f64, KvStore};
use agent_bus::wal::{
    compact, replay, snapshot_path_for, BusState, APPEND_FAIL_AFTER_LINE,
    APPEND_FAIL_AFTER_NEWLINE, APPEND_FAIL_NONE, APPEND_FAIL_OPEN, APPEND_FAIL_SYNC,
};
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-kvwire-{name}-{}", std::process::id()));
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

fn start_with(name: &str, tokens: TokenStore) -> (String, PathBuf) {
    let wal = wal_path(name);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    let server = Server::new(wal.clone(), tokens).expect("fresh WAL starts clean");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    (addr, wal)
}

fn start(name: &str) -> (String, PathBuf) {
    start_with(name, open_tokens())
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

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[test]
fn kv_put_get_roundtrip_over_wire() {
    let (addr, _wal) = start("roundtrip");
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Missing key reports found=false (no value field), with req_id echoed.
    let miss = c.rpc(&json!({"op": "kv_get", "key": "ctx.missing"})).unwrap();
    assert!(ok(&miss), "{miss}");
    assert_eq!(miss["found"], json!(false));
    assert!(miss.get("req_id").is_some(), "req_id echoed: {miss}");
    // Put then get round-trips the value verbatim.
    let put = c
        .rpc(&json!({"op": "kv_put", "key": "ctx.goal", "value": {"n": 1}}))
        .unwrap();
    assert!(ok(&put), "{put}");
    assert_eq!(put["key"], json!("ctx.goal"));
    assert!(put.get("req_id").is_some(), "req_id echoed: {put}");
    let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.goal"})).unwrap();
    assert!(ok(&got), "{got}");
    assert_eq!(got["found"], json!(true));
    assert_eq!(got["value"], json!({"n": 1}));
    // JSON null is a first-class value, never confused with absence.
    let put_null = c.rpc(&json!({"op": "kv_put", "key": "ctx.null", "value": null})).unwrap();
    assert!(ok(&put_null), "{put_null}");
    let got_null = c.rpc(&json!({"op": "kv_get", "key": "ctx.null"})).unwrap();
    assert_eq!(got_null["found"], json!(true));
    assert_eq!(got_null["value"], json!(null));
    // Missing value defaults to null (lenient .get convention).
    let put_novalue = c.rpc(&json!({"op": "kv_put", "key": "ctx.novalue"})).unwrap();
    assert!(ok(&put_novalue), "{put_novalue}");
    let got_novalue = c.rpc(&json!({"op": "kv_get", "key": "ctx.novalue"})).unwrap();
    assert_eq!(got_novalue["found"], json!(true));
    assert_eq!(got_novalue["value"], json!(null));
}

#[test]
fn kv_put_rejects_empty_key_and_bad_ttl() {
    let (addr, _wal) = start("validate");
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Empty and missing keys fail with the legacy string.
    for req in [
        json!({"op": "kv_put", "key": "", "value": 1}),
        json!({"op": "kv_put", "value": 1}),
        json!({"op": "kv_del", "key": ""}),
        json!({"op": "kv_del"}),
    ] {
        let r = c.rpc(&req).unwrap();
        assert_eq!(r["error"], json!("key required"), "{req} -> {r}");
        assert!(r.get("req_id").is_some(), "req_id echoed: {r}");
    }
    // Non-numeric ttl_ms fails cleanly (legacy would crash the connection).
    for bad in [json!("60000"), json!(true), json!([1]), json!({"n": 1})] {
        let r = c
            .rpc(&json!({"op": "kv_put", "key": "ctx.t", "value": 1, "ttl_ms": bad}))
            .unwrap();
        assert_eq!(r["error"], json!("ttl_ms must be a number"), "ttl={bad} -> {r}");
    }
    // Null/missing/zero ttl means no expiry (live).
    for ttl in [json!(null), json!(0), json!(0.0)] {
        let r = c
            .rpc(&json!({"op": "kv_put", "key": "ctx.live", "value": 1, "ttl_ms": ttl}))
            .unwrap();
        assert!(ok(&r), "{r}");
    }
    let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.live"})).unwrap();
    assert_eq!(got["found"], json!(true));
    // Negative TTL is a valid durable write that reads as expired immediately.
    let put_exp = c
        .rpc(&json!({"op": "kv_put", "key": "ctx.old", "value": 1, "ttl_ms": -1000}))
        .unwrap();
    assert!(ok(&put_exp), "{put_exp}");
    let got_exp = c.rpc(&json!({"op": "kv_get", "key": "ctx.old"})).unwrap();
    assert!(ok(&got_exp), "{got_exp}");
    assert_eq!(got_exp["found"], json!(false));
}

#[test]
fn kv_ttl_core_f64_boundaries() {
    // Deterministic core proof: fractional TTLs preserved exactly via
    // `now + ttl/1000`, matching legacy float division (no rounding).
    // `0.0`/`-0.0`/`None` mean no expiry; non-zero always carries exp.
    const T0: f64 = 1_790_000_000.0;
    assert_eq!(expiry_for_ttl_f64(None, T0), None);
    assert_eq!(expiry_for_ttl_f64(Some(0.0), T0), None);
    assert_eq!(expiry_for_ttl_f64(Some(-0.0), T0), None);
    assert_eq!(expiry_for_ttl_f64(Some(0.1), T0), Some(T0 + 0.0001));
    assert_eq!(expiry_for_ttl_f64(Some(0.5), T0), Some(T0 + 0.0005));
    assert_eq!(expiry_for_ttl_f64(Some(-0.1), T0), Some(T0 - 0.0001));
    assert_eq!(expiry_for_ttl_f64(Some(1500.5), T0), Some(T0 + 1.5005));
    assert_eq!(expiry_for_ttl_f64(Some(-1500.5), T0), Some(T0 - 1.5005));
    // Distinct fractionals stay distinct (rounding would collapse 0.1
    // and 0.4 to the same 1ms). Each equals its exact `T0 + ttl/1000`.
    let e1 = expiry_for_ttl_f64(Some(0.1), T0).unwrap();
    let e2 = expiry_for_ttl_f64(Some(0.4), T0).unwrap();
    assert_eq!(e1, T0 + 0.1 / 1000.0);
    assert_eq!(e2, T0 + 0.4 / 1000.0);
    assert_ne!(e1, e2, "fractionals not collapsed");
    // Core put/get with fixed time: tiny positive live at T0, expired
    // just after; tiny negative expired at T0; zero immortal.
    let mut s = KvStore::new();
    let put = |s: &mut KvStore, k: &str, ttl: Option<f64>| {
        let p = s.prepare_put_f64(k, json!(1), ttl, T0).expect("valid");
        s.commit_put(p, |_: &str| Ok::<(), String>(())).unwrap();
    };
    put(&mut s, "pos", Some(0.1));
    put(&mut s, "neg", Some(-0.1));
    put(&mut s, "zero", Some(0.0));
    put(&mut s, "none", None);
    assert!(s.get("pos", T0).is_some());
    assert!(s.get("pos", T0 + 0.0002).is_none(), "0.1ms expires fast");
    assert!(s.get("neg", T0).is_none());
    assert!(s.get("zero", T0 + 1e9).is_some());
    assert!(s.get("none", T0 + 1e9).is_some());
    // Non-finite TTL rejected, never stored as null-exp immortal.
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(s.prepare_put_f64("k", json!(1), Some(bad), T0).is_err());
    }
}

#[test]
fn kv_ttl_fractional_preserved_over_wire_with_fixed_clock() {
    // Wire proof with a pinned server clock: WAL `exp` equals
    // `T0 + ttl/1000` exactly (no rounding), and expiry flips
    // deterministically when the clock advances (no sleeps).
    const T0: f64 = 1_790_000_000.0;
    let (addr, wal, server) = start_handle("ttl-frac-wire");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Fractional put: WAL exp exact, live at T0.
    let r = c
        .rpc(&json!({"op": "kv_put", "key": "ctx.frac", "value": 1, "ttl_ms": 1500.5}))
        .unwrap();
    assert!(ok(&r), "{r}");
    let raw = std::fs::read_to_string(&wal).unwrap();
    let line = raw.lines().find(|l| l.contains("ctx.frac")).expect("wal has put");
    let rec: Value = serde_json::from_str(line).unwrap();
    let exp = rec.get("exp").and_then(|v| v.as_f64()).expect("exp numeric");
    assert_eq!(exp, T0 + 1.5005, "fractional preserved, not rounded: {line}");
    let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.frac"})).unwrap();
    assert_eq!(got["found"], json!(true));
    // Advance past exp: now expired (deterministic, no sleep).
    server.set_fixed_now(Some(T0 + 1.5006));
    let got2 = c.rpc(&json!({"op": "kv_get", "key": "ctx.frac"})).unwrap();
    assert_eq!(got2["found"], json!(false), "{got2}");
    // Tiny positive: distinct from 1ms rounding (exp differs).
    server.set_fixed_now(Some(T0));
    c.rpc(&json!({"op": "kv_put", "key": "ctx.tiny", "value": 1, "ttl_ms": 0.1}))
        .unwrap();
    let raw = std::fs::read_to_string(&wal).unwrap();
    let line = raw.lines().find(|l| l.contains("ctx.tiny")).unwrap();
    let rec: Value = serde_json::from_str(line).unwrap();
    let exp_tiny = rec.get("exp").and_then(|v| v.as_f64()).unwrap();
    assert_eq!(exp_tiny, T0 + 0.0001, "0.1ms exact: {line}");
    assert_ne!(exp_tiny, T0 + 0.001, "not rounded to 1ms");
    // Tiny negative already expired, zero immortal.
    c.rpc(&json!({"op": "kv_put", "key": "ctx.neg", "value": 1, "ttl_ms": -0.1}))
        .unwrap();
    let got_neg = c.rpc(&json!({"op": "kv_get", "key": "ctx.neg"})).unwrap();
    assert_eq!(got_neg["found"], json!(false));
    c.rpc(&json!({"op": "kv_put", "key": "ctx.zero", "value": 1, "ttl_ms": 0.0}))
        .unwrap();
    server.set_fixed_now(Some(T0 + 1e6));
    let got_zero = c.rpc(&json!({"op": "kv_get", "key": "ctx.zero"})).unwrap();
    assert_eq!(got_zero["found"], json!(true), "0.0 immortal");
    server.set_fixed_now(None);
}

#[test]
fn kv_delete_reports_presence_and_durables_tombstone() {
    let (addr, wal) = start("delete");
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Deleting a JSON-null value reports found=true (presence-based; legacy
    // `pop(...) is not None` wrongly reported false for null).
    c.rpc(&json!({"op": "kv_put", "key": "ctx.n", "value": null})).unwrap();
    let del_null = c.rpc(&json!({"op": "kv_del", "key": "ctx.n"})).unwrap();
    assert!(ok(&del_null), "{del_null}");
    assert_eq!(del_null["found"], json!(true));
    assert_eq!(del_null["key"], json!("ctx.n"));
    let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.n"})).unwrap();
    assert_eq!(got["found"], json!(false));
    // Normal put then delete clears the key.
    c.rpc(&json!({"op": "kv_put", "key": "ctx.a", "value": 1})).unwrap();
    let del = c.rpc(&json!({"op": "kv_del", "key": "ctx.a"})).unwrap();
    assert_eq!(del["found"], json!(true));
    // Deleting an absent key still durables a tombstone (unconditional append
    // like legacy) but reports found=false.
    let del_absent = c.rpc(&json!({"op": "kv_del", "key": "ctx.absent"})).unwrap();
    assert!(ok(&del_absent), "{del_absent}");
    assert_eq!(del_absent["found"], json!(false));
    let raw = std::fs::read_to_string(&wal).unwrap();
    assert!(
        raw.contains(r#""t":"kv_del""#) && raw.contains("ctx.absent"),
        "absent-key delete tombstoned: {raw}"
    );
    // Delete ignores expiry (presence-only): an already-expired stored key
    // still counts as present at delete time.
    c.rpc(&json!({"op": "kv_put", "key": "ctx.exp", "value": 1, "ttl_ms": -1000}))
        .unwrap();
    let del_exp = c.rpc(&json!({"op": "kv_del", "key": "ctx.exp"})).unwrap();
    assert_eq!(del_exp["found"], json!(true), "{del_exp}");
}

#[test]
fn kv_acl_effective_grants_fallback_vs_explicit() {
    // Missing/null share pub/sub; explicit [] denies without fallback;
    // explicit lists replace (never merge with) pub/sub.
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-missing": {"agent": "a", "publish": ["board.*"], "subscribe": ["board.*"]},
            "tok-nulled": {"agent": "b", "publish": ["board.*"], "subscribe": ["board.*"], "kv_read": null, "kv_write": null},
            "tok-empty": {"agent": "c", "publish": ["board.*"], "subscribe": ["board.*"], "kv_read": [], "kv_write": []},
            "tok-explicit": {"agent": "d", "publish": ["board.*"], "subscribe": ["board.*"], "kv_read": ["bus.*"], "kv_write": ["bus.*"]}
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("kv-acl", tokens);
    // Missing and nulled fall back: board.* allowed, other.* denied.
    for (agent, token) in [("a", "tok-missing"), ("b", "tok-nulled")] {
        let mut c = Client::connect(&addr, agent, token).unwrap();
        let put_ok = c
            .rpc(&json!({"op": "kv_put", "key": "board.k", "value": 1}))
            .unwrap();
        assert!(ok(&put_ok), "{agent} board.k should allow: {put_ok}");
        let put_no = c
            .rpc(&json!({"op": "kv_put", "key": "other.k", "value": 1}))
            .unwrap();
        assert_eq!(put_no["error"], json!("kv_put denied: other.k"), "{put_no}");
        let get_no = c.rpc(&json!({"op": "kv_get", "key": "other.k"})).unwrap();
        assert_eq!(get_no["error"], json!("kv_get denied: other.k"), "{get_no}");
        let del_no = c.rpc(&json!({"op": "kv_del", "key": "other.k"})).unwrap();
        assert_eq!(del_no["error"], json!("kv_del denied: other.k"), "{del_no}");
    }
    // Explicit [] denies everything, even board.* (no fallback).
    let mut c = Client::connect(&addr, "c", "tok-empty").unwrap();
    for op in ["kv_put", "kv_get", "kv_del"] {
        let r = c.rpc(&json!({"op": op, "key": "board.k", "value": 1})).unwrap();
        assert!(
            r["error"].as_str().unwrap().contains("denied"),
            "{op} should deny: {r}"
        );
    }
    // Explicit lists replace pub/sub: bus.* allowed, board.* denied.
    let mut d = Client::connect(&addr, "d", "tok-explicit").unwrap();
    let put_bus = d
        .rpc(&json!({"op": "kv_put", "key": "bus.k", "value": 1}))
        .unwrap();
    assert!(ok(&put_bus), "{put_bus}");
    let put_board = d
        .rpc(&json!({"op": "kv_put", "key": "board.k", "value": 1}))
        .unwrap();
    assert_eq!(put_board["error"], json!("kv_put denied: board.k"), "{put_board}");
    let get_board = d.rpc(&json!({"op": "kv_get", "key": "board.k"})).unwrap();
    assert_eq!(get_board["error"], json!("kv_get denied: board.k"), "{get_board}");
}

#[test]
fn kv_list_prefix_cover_and_per_key_filtering() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-admin": {"agent": "admin", "publish": ["*"], "subscribe": ["*"]},
            "tok-scoped": {"agent": "s", "publish": ["board.*"], "subscribe": ["board.*"]},
            "tok-exact": {"agent": "e", "publish": ["*"], "subscribe": ["*"], "kv_read": ["board.top"]}
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("kv-list", tokens);
    let mut admin = Client::connect(&addr, "admin", "tok-admin").unwrap();
    for key in ["board.top", "board.top2", "board.other", "other.x"] {
        let r = admin.rpc(&json!({"op": "kv_put", "key": key, "value": 1})).unwrap();
        assert!(ok(&r), "{r}");
    }
    // Scoped fallback: prefix must be covered (empty denied for scoped grants).
    let mut s = Client::connect(&addr, "s", "tok-scoped").unwrap();
    let denied_empty = s.rpc(&json!({"op": "kv_list", "prefix": ""})).unwrap();
    assert!(
        denied_empty["error"].as_str().unwrap().contains("kv_list denied"),
        "{denied_empty}"
    );
    let denied_other = s.rpc(&json!({"op": "kv_list", "prefix": "other."})).unwrap();
    assert!(
        denied_other["error"].as_str().unwrap().contains("kv_list denied"),
        "{denied_other}"
    );
    let allowed = s.rpc(&json!({"op": "kv_list", "prefix": "board."})).unwrap();
    assert!(ok(&allowed), "{allowed}");
    let keys: Vec<String> = allowed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(keys, vec!["board.other", "board.top", "board.top2"]);
    // Exact grant: prefix "board.top" is covered, but per-key filtering drops
    // "board.top2" (same prefix, no grant match) before any cap.
    let mut e = Client::connect(&addr, "e", "tok-exact").unwrap();
    let filtered = e.rpc(&json!({"op": "kv_list", "prefix": "board.top"})).unwrap();
    assert!(ok(&filtered), "{filtered}");
    assert_eq!(filtered["keys"], json!(["board.top"]), "{filtered}");
}

#[test]
fn kv_list_filters_before_cap_with_1001_denied_preceding() {
    // Wire proof that per-key filtering happens BEFORE the 1000 cap:
    // 1001 denied keys sort before a single allowed key sharing the
    // same list prefix. If the cap applied first, the allowed key
    // would be hidden; filtering first surfaces it.
    //
    // Grants: exact "board.a" covers prefix "board.a" (list allowed),
    // while "board.a*-zzz" matches only the allowed suffix. Denied
    // keys "board.a-0000".."board.a-1000" match neither grant but sort
    // before "board.a-zzz" ('0'-'9' < 'z').
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-admin": {"agent": "admin", "publish": ["*"], "subscribe": ["*"]},
            "tok-scoped": {"agent": "s", "publish": ["other.*"], "subscribe": ["other.*"], "kv_read": ["board.a", "board.a*-zzz"]}
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("kv-list-cap", tokens);
    let mut admin = Client::connect(&addr, "admin", "tok-admin").unwrap();
    for i in 0..1001 {
        let key = format!("board.a-{i:04}");
        let r = admin.rpc(&json!({"op": "kv_put", "key": key, "value": 1})).unwrap();
        assert!(ok(&r), "put {key}: {r}");
    }
    let r = admin
        .rpc(&json!({"op": "kv_put", "key": "board.a-zzz", "value": 1}))
        .unwrap();
    assert!(ok(&r), "{r}");
    let mut s = Client::connect(&addr, "s", "tok-scoped").unwrap();
    let listed = s.rpc(&json!({"op": "kv_list", "prefix": "board.a"})).unwrap();
    assert!(ok(&listed), "{listed}");
    assert_eq!(listed["keys"], json!(["board.a-zzz"]), "{listed}");
    // Sanity: admin (wildcard) sees all 1002, capped at 1000.
    let mut admin_list = Client::connect(&addr, "admin", "tok-admin").unwrap();
    let all = admin_list
        .rpc(&json!({"op": "kv_list", "prefix": "board.a"}))
        .unwrap();
    assert!(ok(&all), "{all}");
    assert_eq!(all["keys"].as_array().unwrap().len(), 1000, "cap enforced");
}

#[test]
fn mixed_post_claim_kv_replay_and_compaction() {
    // One WAL interleaves all three stores; replay restores each, and
    // compaction regenerates a minimal WAL that replays to the same state.
    let (addr, wal) = start("mixed");
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let p1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}}))
        .unwrap();
    assert_eq!(p1["seq"], json!(1));
    c.rpc(&json!({"op": "kv_put", "key": "ctx.keep", "value": {"v": 1}}))
        .unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "ctx.gone", "value": 1, "ttl_ms": -1000}))
        .unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "ctx.del", "value": 1})).unwrap();
    c.rpc(&json!({"op": "kv_del", "key": "ctx.del"})).unwrap();
    let grant = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/a.rs", "ttl_ms": 600_000}))
        .unwrap();
    assert!(ok(&grant), "{grant}");
    let live_token = grant["token"].as_str().unwrap().to_string();
    // Direct WAL replay into fresh state (in-process restart simulation).
    let mut s = BusState::new();
    replay(&wal, &mut s, now()).expect("mixed WAL replays");
    assert_eq!(s.topics["t"].seq, 1);
    assert_eq!(s.topics["t"].msgs.len(), 1);
    assert_eq!(s.kv.get("ctx.keep", now()).unwrap(), &json!({"v": 1}));
    assert!(s.kv.get("ctx.gone", now()).is_none(), "expired stays gone");
    assert!(s.kv.get("ctx.del", now()).is_none(), "deleted stays gone");
    assert!(s.claims.status("repo/a.rs", now()).is_some());
    // Compaction drops the expired put and delete tombstones, keeps live KV.
    compact(&wal, &s, now()).unwrap();
    let raw = std::fs::read_to_string(&wal).unwrap();
    assert!(raw.contains(r#""t":"kv""#), "live kv kept: {raw}");
    assert!(!raw.contains("ctx.gone"), "expired put dropped: {raw}");
    assert!(!raw.contains(r#""t":"kv_del""#), "tombstones dropped: {raw}");
    // The compacted WAL replays to identical live state (no resurrection).
    let mut s2 = BusState::new();
    replay(&wal, &mut s2, now()).expect("compacted WAL replays");
    assert_eq!(s2.topics["t"].seq, 1);
    assert_eq!(s2.kv.get("ctx.keep", now()).unwrap(), &json!({"v": 1}));
    assert!(s2.kv.get("ctx.gone", now()).is_none());
    assert!(s2.kv.get("ctx.del", now()).is_none());
    let live = s2.claims.status("repo/a.rs", now()).unwrap();
    assert_eq!(live.token, live_token);
}

#[test]
fn kv_failed_append_preserves_old_state() {
    // Real append failure: the WAL pathname is temporarily a directory, so
    // the per-append open fails. Failed puts/deletes report errors and leave
    // existing KV untouched (validate-before-durability, mutate-after).
    let (addr, wal) = start("kv-rollback");
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": {"v": 1}}))
        .unwrap();
    let backup = std::fs::read(&wal).unwrap();
    std::fs::remove_file(&wal).unwrap();
    std::fs::create_dir(&wal).unwrap();
    let put_fail = c
        .rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": {"v": 2}}))
        .unwrap();
    assert!(put_fail.get("error").is_some(), "{put_fail}");
    assert!(
        put_fail["error"].as_str().unwrap().contains("wal append failed"),
        "{put_fail}"
    );
    let del_fail = c.rpc(&json!({"op": "kv_del", "key": "ctx.k"})).unwrap();
    assert!(
        del_fail["error"].as_str().unwrap().contains("wal append failed"),
        "{del_fail}"
    );
    let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.k"})).unwrap();
    assert_eq!(got["value"], json!({"v": 1}), "old value preserved: {got}");
    // Restore the WAL file; old state intact and new writes work again.
    std::fs::remove_dir(&wal).unwrap();
    std::fs::write(&wal, backup).unwrap();
    let put_ok = c
        .rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": {"v": 3}}))
        .unwrap();
    assert!(ok(&put_ok), "{put_ok}");
    let got2 = c.rpc(&json!({"op": "kv_get", "key": "ctx.k"})).unwrap();
    assert_eq!(got2["value"], json!({"v": 3}));
}

#[test]
fn kv_injected_partial_failures_rollback_disk_and_state() {
    // Deterministic failure injection: each mode performs real partial
    // bytes before failing (line without newline, line+newline without
    // fsync, flush without fsync, open refusal). The server truncates
    // back to pre-append length, so WAL bytes are identical to before,
    // old state is preserved, no poison is set, replay shows no
    // resurrection, and the next write succeeds on a clean tail.
    for (name, mode) in [
        ("open", APPEND_FAIL_OPEN),
        ("after-line", APPEND_FAIL_AFTER_LINE),
        ("after-newline", APPEND_FAIL_AFTER_NEWLINE),
        ("sync", APPEND_FAIL_SYNC),
    ] {
        let (addr, wal, server) =
            start_with_handle(&format!("kv-inject-{name}"), open_tokens());
        let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
        c.rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": {"v": 1}}))
            .unwrap();
        let before = std::fs::read(&wal).unwrap();
        assert!(before.ends_with(b"\n"), "baseline clean tail");
        server.set_append_failpoint(mode);
        // Failed put and delete both report `wal append failed` (not
        // poisoned) and leave old state untouched.
        let put_fail = c
            .rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": {"v": 2}}))
            .unwrap();
        assert!(
            put_fail["error"].as_str().unwrap().contains("wal append failed"),
            "{name}: {put_fail}"
        );
        let del_fail = c.rpc(&json!({"op": "kv_del", "key": "ctx.k"})).unwrap();
        assert!(
            del_fail["error"].as_str().unwrap().contains("wal append failed"),
            "{name}: {del_fail}"
        );
        assert!(server.wal_poisoned().is_none(), "{name} must not poison");
        let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.k"})).unwrap();
        assert_eq!(got["value"], json!({"v": 1}), "{name} old state: {got}");
        // Disk restored byte-identical: no torn tail, no partial record.
        let after_fail = std::fs::read(&wal).unwrap();
        assert_eq!(after_fail, before, "{name} disk rolled back");
        // Replay of the rolled-back WAL shows old state, no v2 revival.
        let mut s = BusState::new();
        replay(&wal, &mut s, now()).expect("rolled-back WAL replays");
        assert_eq!(s.kv.get("ctx.k", now()).unwrap(), &json!({"v": 1}));
        // Next write succeeds on the clean tail and replays.
        server.set_append_failpoint(APPEND_FAIL_NONE);
        let put_ok = c
            .rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": {"v": 3}}))
            .unwrap();
        assert!(ok(&put_ok), "{name} recovery: {put_ok}");
        let raw = std::fs::read_to_string(&wal).unwrap();
        assert!(raw.ends_with('\n'), "{name} clean tail after recovery");
        let mut s2 = BusState::new();
        replay(&wal, &mut s2, now()).expect("recovered WAL replays");
        assert_eq!(s2.kv.get("ctx.k", now()).unwrap(), &json!({"v": 3}));
    }
}

#[test]
fn kv_poisoned_server_fails_closed_for_writes_reads_live() {
    // Fail-closed poisoning: while poisoned, all mutations refuse with
    // `wal poisoned` (post, kv_put/del, claim acquire/renew/release)
    // while reads (get/list/fetch/status) stay available. Production
    // poison comes only from a failed truncate rollback after an
    // `opened=true` append failure; this test pins the poisoned state
    // directly to prove the fail-closed behavior.
    let (addr, _wal, server) = start_handle("kv-poison");
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    c.rpc(&json!({"op": "kv_put", "key": "ctx.k", "value": 1}))
        .unwrap();
    c.rpc(&json!({"op": "post", "topic": "t", "payload": 1}))
        .unwrap();
    server.poison_for_test("injected for fail-closed proof");
    assert!(server.wal_poisoned().is_some());
    for req in [
        json!({"op": "kv_put", "key": "ctx.k", "value": 2}),
        json!({"op": "kv_del", "key": "ctx.k"}),
        json!({"op": "post", "topic": "t", "payload": 2}),
        json!({"op": "claim_acquire", "resource": "r", "ttl_ms": 60000}),
        json!({"op": "claim_renew", "resource": "r", "token": "x", "ttl_ms": 60000}),
        json!({"op": "claim_release", "resource": "r", "token": "x"}),
    ] {
        let r = c.rpc(&req).unwrap();
        assert!(
            r["error"].as_str().unwrap().contains("wal poisoned"),
            "{req} -> {r}"
        );
    }
    // Reads stay live.
    let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.k"})).unwrap();
    assert_eq!(got["value"], json!(1));
    let listed = c.rpc(&json!({"op": "kv_list", "prefix": "ctx."})).unwrap();
    assert!(ok(&listed), "{listed}");
    let fetched = c.rpc(&json!({"op": "fetch", "topic": "t"})).unwrap();
    assert!(ok(&fetched), "{fetched}");
    let status = c.rpc(&json!({"op": "claim_status", "resource": "r"})).unwrap();
    assert!(ok(&status), "{status}");
}

#[test]
fn kv_malformed_wal_fails_closed_without_echo() {
    // Structurally invalid KV records refuse startup like malformed posts
    // do; the diagnostic names the line, never the record bytes (values may
    // be sensitive). A put with a missing value is lenient (null default).
    for (name, line) in [
        ("no-key", r#"{"t":"kv","value":1,"exp":null}"#),
        ("int-key", r#"{"t":"kv","key":123,"value":1}"#),
        ("bad-exp", r#"{"t":"kv","key":"k","value":1,"exp":"soon"}"#),
        ("del-no-key", r#"{"t":"kv_del"}"#),
        ("del-int-key", r#"{"t":"kv_del","key":null}"#),
    ] {
        let wal = wal_path(&format!("kv-corrupt-{name}"));
        let _ = std::fs::remove_file(&wal);
        std::fs::write(&wal, format!("{line}\n")).unwrap();
        let mut s = BusState::new();
        let err = replay(&wal, &mut s, now()).expect_err("malformed kv must fail");
        let msg = err.to_string();
        assert!(msg.contains("malformed kv record"), "{name}: {msg}");
        assert!(!msg.contains("secret"), "{name} echoed bytes: {msg}");
        assert!(s.kv.is_empty(), "{name} left no partial state");
        let _ = std::fs::remove_file(&wal);
    }
    // Missing value is valid (null default), not malformed.
    let wal = wal_path("kv-novalue-ok");
    let _ = std::fs::remove_file(&wal);
    std::fs::write(&wal, "{\"t\":\"kv\",\"key\":\"k\",\"exp\":null}\n").unwrap();
    let mut s = BusState::new();
    replay(&wal, &mut s, now()).expect("missing value replays as null");
    assert_eq!(s.kv.get("k", now()).unwrap(), &Value::Null);
    let _ = std::fs::remove_file(&wal);
}

#[test]
fn legacy_snapshot_sibling_refuses_startup() {
    // A legacy `kv.json` snapshot sibling refuses startup explicitly instead
    // of starting with a WAL-only view that silently drops snapshot keys.
    let wal = wal_path("snap-refusal");
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    std::fs::write(&wal, "{\"t\":\"kv\",\"key\":\"ctx.wal\",\"value\":1,\"exp\":null}\n").unwrap();
    std::fs::write(
        snapshot_path_for(&wal),
        r#"{"v":1,"kv":{"ctx.snap":1},"exp":{}}"#,
    )
    .unwrap();
    // `expect_err` needs `Server: Debug`; match keeps the error value
    // for the message assertions without touching `Server`.
    let err = match Server::new(wal.clone(), open_tokens()) {
        Ok(_) => panic!("snapshot must refuse"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("unsupported legacy KV snapshot"), "{msg}");
    assert!(msg.contains("kv.json"), "{msg}");
    // Cleanup for lease-file hygiene; the WAL itself is untouched.
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
}

// ---------------------------------------------------------------------------
// Real-process durability: KV ACKs survive SIGKILL via the broker binary.
// ---------------------------------------------------------------------------

fn broker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus-broker"))
}

fn proc_tmpdir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "agent-bus-kvproc-{name}-{}-{}",
        std::process::id(),
        name.len()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn write_proc_tokens(dir: &Path) -> PathBuf {
    let path = dir.join("tokens.json");
    std::fs::write(
        &path,
        r#"{"tok-test": {"agent": "tester", "publish": ["*"], "subscribe": ["*"]}}"#,
    )
    .unwrap();
    path
}

fn spawn_proc_broker(dir: &Path, wal: &Path, port: u16) -> Child {
    let tokens = write_proc_tokens(dir);
    Command::new(broker_bin())
        .env_remove("AGENT_BUS_SOCK")
        .arg("serve")
        .arg("--wal")
        .arg(wal)
        .arg("--tokens")
        .arg(&tokens)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .env_remove("AGENT_BUS_OPEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("broker child spawns")
}

fn wait_proc_ready(addr: &str) -> Client {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match Client::connect(addr, "tester", "tok-test") {
            Ok(c) => return c,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("broker at {addr} never became ready: {e}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn proc_kill(child: &mut Child) {
    child.kill().expect("SIGKILL child");
    let status = child.wait().expect("reap child");
    assert!(!status.success(), "killed broker exits non-zero, got {status}");
}

#[test]
fn kv_durable_ack_survives_process_kill() {
    // ACKed KV puts (durable flag accepted, always fsync-backed) survive
    // SIGKILL; deletes survive too, and the post sequence continues.
    let dir = proc_tmpdir("kv-kill");
    let wal = dir.join("wal.log");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = spawn_proc_broker(&dir, &wal, port);
    let mut c = wait_proc_ready(&addr);
    let put = c
        .rpc(&json!({"op": "kv_put", "key": "ctx.keep", "value": {"v": 1}, "durable": true}))
        .unwrap();
    assert!(ok(&put), "{put}");
    c.rpc(&json!({"op": "kv_put", "key": "ctx.drop", "value": 1}))
        .unwrap();
    let del = c.rpc(&json!({"op": "kv_del", "key": "ctx.drop"})).unwrap();
    assert_eq!(del["found"], json!(true));
    let p1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1}))
        .unwrap();
    assert_eq!(p1["seq"], json!(1));
    drop(c);
    proc_kill(&mut child);
    // Restart on the same WAL: live KV, the delete tombstone, and the next
    // post sequence must all survive the kill.
    let port2 = free_port();
    let addr2 = format!("127.0.0.1:{port2}");
    let mut child2 = spawn_proc_broker(&dir, &wal, port2);
    let mut c2 = wait_proc_ready(&addr2);
    let got = c2.rpc(&json!({"op": "kv_get", "key": "ctx.keep"})).unwrap();
    assert_eq!(got["value"], json!({"v": 1}), "{got}");
    let gone = c2.rpc(&json!({"op": "kv_get", "key": "ctx.drop"})).unwrap();
    assert_eq!(gone["found"], json!(false));
    let p2 = c2
        .rpc(&json!({"op": "post", "topic": "t", "payload": 2}))
        .unwrap();
    assert_eq!(p2["seq"], json!(2), "{p2}");
    drop(c2);
    proc_kill(&mut child2);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Native CLI compatibility against an ephemeral native server.
// ---------------------------------------------------------------------------

fn cli_bin() -> String {
    env!("CARGO_BIN_EXE_agent-bus").to_string()
}

struct CliOut {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli_against(addr: &str, args: &[&str], stdin_text: Option<&str>) -> CliOut {
    let (host, port) = addr.rsplit_once(':').expect("addr has port");
    let mut cmd = Command::new(cli_bin());
    cmd.args(args)
        .env("AGENT_BUS_AGENT", "alice")
        .env("AGENT_BUS_TOKEN", "tok-alice")
        .env_remove("AGENT_BUS_SOCK")
        .env("AGENT_BUS_HOST", host)
        .env("AGENT_BUS_PORT", port)
        .stdin(if stdin_text.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn agent-bus");
    if let Some(text) = stdin_text {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().expect("wait agent-bus");
    CliOut {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

#[test]
fn native_cli_kv_compatible_with_ephemeral_server() {
    // The shipped `agent-bus` CLI speaks KV against a native ephemeral
    // server exactly as it does against the transitional broker: put (with
    // stdin + durable + ttl), get (json + short, missing exits 1), and list
    // (json + short + values fan-out).
    let (addr, _wal) = start("cli-compat");
    // kv-put with stdin value, durable flag, and ttl.
    let r = run_cli_against(&addr, &["kv-put", "ctx.cli", "-", "--durable", "--ttl-ms", "60000"], Some(r#"{"a":1}"#));
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    // kv-get json prints the reply with the value.
    let r = run_cli_against(&addr, &["kv-get", "ctx.cli"], None);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let resp: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(resp["value"], json!({"a": 1}));
    // kv-get short prints the value; missing short exits 1.
    let r = run_cli_against(&addr, &["kv-get", "ctx.cli", "--format", "short"], None);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let r = run_cli_against(&addr, &["kv-get", "ctx.nope", "--format", "short"], None);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("not found"), "stderr={}", r.stderr);
    // kv-list json and short show the key; values fan-out fetches it.
    let r = run_cli_against(&addr, &["kv-list", "ctx.", "--format", "short"], None);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("ctx.cli"), "stdout={}", r.stdout);
    let r = run_cli_against(&addr, &["kv-list", "ctx.", "--values", "--format", "short"], None);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("ctx.cli"), "stdout={}", r.stdout);
    assert!(!r.stdout.contains("tok-alice"), "token leaked: {}", r.stdout);
    assert!(!r.stderr.contains("tok-alice"), "token leaked: {}", r.stderr);
    // Native delete completes the CLI workflow. Repeating a confirmed
    // deletion is a successful found=false receipt, not a missing-key error.
    for found in [true, false] {
        let r = run_cli_against(&addr, &["kv-del", "ctx.cli", "--durable"], None);
        assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
        let receipt: Value = serde_json::from_str(r.stdout.trim()).unwrap();
        assert_eq!(receipt["key"], "ctx.cli");
        assert_eq!(receipt["found"], found);
    }
    let r = run_cli_against(&addr, &["kv-get", "ctx.cli", "--format", "short"], None);
    assert_eq!(r.status, 1, "deleted key must be absent: {}", r.stdout);
    let r = run_cli_against(&addr, &["kv-list", "ctx.", "--format", "short"], None);
    assert_eq!(r.status, 0, "{}", r.stderr);
    assert!(!r.stdout.contains("ctx.cli"), "deleted key was still listed");
}
