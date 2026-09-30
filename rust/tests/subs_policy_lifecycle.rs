//! Subscription policy lifecycle: revocation/expiry/identity boundaries.
//!
//! Defensive hardening for long-lived subscriptions: current policy governs
//! eligibility + delivery for the connection lifetime, stale subs are
//! removed, and queued live never crosses an authentication boundary.
//! Reliable receipts are preserved; ordinary authorized delivery is unchanged.
//! No Python, no production IO: ephemeral WAL/ports/tokens, fixed clocks,
//! bounded fixtures (<=3 posts), deterministic hold gates (no timing races).
//! See `docs/NATIVE_SUBSCRIPTIONS.md` lifecycle + `NATIVE_TOKEN_ADMIN.md`.

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use agent_bus::acl::TokenStore;
use agent_bus::wal::snapshot_path_for;
use agent_bus::wire::{Client, Server, StreamingConn};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-subs-policy-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn tokens_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-subs-policy-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("tokens.json")
}

fn open_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["*"], "subscribe": ["*"]},
            "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .expect("fixture tokens valid")
}

fn start_handle(name: &str) -> (String, PathBuf, Server) {
    let wal = wal_path(name);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    let server = Server::new(wal.clone(), open_tokens()).expect("fresh WAL starts clean");
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    (addr, wal, handle)
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

// Revocation: held live (2 queued, no drain) is purged with accounting on
// `token_revoke` commit (sweep, no next-RPC wait); subs drop to 0, new
// posts never deliver, and the revoked conn's next RPC fails `auth failed`
// with a reliable receipt (no stale live).
#[test]
fn revoke_removes_subs_and_purges_queued_live() {
    let name = "revoke-purge";
    let wal = wal_path(name);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    let tpath = tokens_path(name);
    std::fs::write(
        &tpath,
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["*"], "subscribe": ["*"]},
            "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .unwrap();
    let tokens = TokenStore::from_json_str(&std::fs::read_to_string(&tpath).unwrap()).unwrap();
    let server = Server::new(wal.clone(), tokens)
        .expect("fresh WAL")
        .with_tokens_path(tpath.clone());
    server.set_fixed_now(Some(T0));
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));

    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, rep, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 0);
    assert!(handle.set_sub_hold_for_test(&sub_id, true));
    let mut pubc = Client::connect(&addr, "bob", "tok-bob").unwrap();
    for n in 1..=2 {
        let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": n}})).unwrap();
        assert!(ok(&r), "{r}");
    }
    assert_eq!(handle.subs_queued_for_test(&sub_id), Some(2));
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["deliveries"], json!(2), "{out}");
    assert_eq!(out["stats"]["drops"], json!(0), "{out}");

    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let r = admin.rpc(&json!({"op": "token_revoke", "token": "tok-alice"})).unwrap();
    assert_eq!(r["revoked"], json!(true), "{r}");

    // Sweep removed the sub and purged 2 held live (counted drops).
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["subs"], json!(0), "{out}");
    assert_eq!(out["stats"]["drops"], json!(2), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(2), "{out}");
    let subs = admin.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(subs["subs"].as_array().unwrap().len(), 0, "{subs}");

    // Revoked conn's next RPC fails with a receipt (purge released hold).
    let r = s.unsubscribe(&sub_id).unwrap();
    assert_eq!(r["error"], json!("auth failed"), "{r}");
    // New posts never deliver to the removed sub.
    let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 3}})).unwrap();
    assert!(ok(&r), "{r}");
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["deliveries"], json!(2), "{out}");
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");

    handle.set_fixed_now(None);
    let _ = std::fs::remove_file(&tpath);
}

// Expiry: delivery-time check prunes the expired sub (no delivery), and the
// next RPC fails `token expired`. Publisher uses a valid token so the post
// commits; only the expired subscriber is denied.
#[test]
fn expiry_blocks_delivery_and_next_rpc_fails() {
    let wal = wal_path("expiry-deny");
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    let tokens = TokenStore::from_json_str(&format!(
        r#"{{"tok-alice-exp": {{"agent": "alice", "publish": ["*"], "subscribe": ["*"], "exp": {}}}, "tok-bob": {{"agent": "bob", "publish": ["*"], "subscribe": ["*"]}}}}"#,
        T0 + 10.0
    ))
    .unwrap();
    let server = Server::new(wal.clone(), tokens).expect("fresh WAL");
    server.set_fixed_now(Some(T0));
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));

    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice-exp").unwrap();
    let (sub_id, rep, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 0);
    let mut pubc = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}})).unwrap();
    assert!(ok(&r), "{r}");
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["msg"]["seq"], json!(1));

    handle.set_fixed_now(Some(T0 + 20.0));
    let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 2}})).unwrap();
    assert!(ok(&r), "{r}");
    // Delivery pruned the expired sub; no live for seq2.
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["subs"], json!(0), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(1), "{out}");
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    // Next RPC on the expired conn fails with the hello string.
    let r = pubc.rpc(&json!({"op": "subs"})).unwrap();
    assert!(ok(&r), "{r}");
    assert!(Client::connect(&addr, "alice", "tok-alice-exp").is_err());
    // Streaming conn revalidation via unsubscribe fails expired.
    let r = s.unsubscribe(&sub_id).unwrap();
    assert_eq!(r["error"], json!("token expired"), "{r}");

    handle.set_fixed_now(None);
}

// Identity transition: re-hello on the same connection clears prior subs +
// purges held live (no cross-identity delivery); the connection stays usable
// for new subs + ordinary delivery under the new identity.
#[test]
fn rehello_clears_old_subs_and_blocks_cross_identity_live() {
    let (addr, _wal, server) = start_handle("rehello-clear");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r = a.rpc(&json!({"op": "subscribe", "pattern": "t"})).unwrap();
    assert!(ok(&r), "{r}");
    let sub_id = r["sub_id"].as_str().unwrap().to_string();
    assert!(server.set_sub_hold_for_test(&sub_id, true));
    let mut pubc = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}})).unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(server.subs_queued_for_test(&sub_id), Some(1));

    // Same TCP connection re-hellos as bob: old sub + 1 held live purged.
    let r = a.rpc(&json!({"op": "hello", "agent": "bob", "token": "tok-bob"})).unwrap();
    assert!(ok(&r), "{r}");
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["subs"], json!(0), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(1), "{out}");
    assert_eq!(out["stats"]["drops"], json!(1), "{out}");

    // No sub: new posts queue nothing for this connection.
    let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 2}})).unwrap();
    assert!(ok(&r), "{r}");
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["deliveries"], json!(1), "{out}");
    // Connection usable under new identity: fresh sub (no replay) + live.
    let r = a.rpc(&json!({"op": "subscribe", "pattern": "t", "from_seq": 2})).unwrap();
    assert!(ok(&r), "{r}");
    let sub2 = r["sub_id"].as_str().unwrap().to_string();
    assert!(server.set_sub_hold_for_test(&sub2, true));
    let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 3}})).unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(server.subs_queued_for_test(&sub2), Some(1));
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["deliveries"], json!(2), "{out}");
    assert!(server.set_sub_hold_for_test(&sub2, false));
    let _ = a.rpc(&json!({"op": "unsubscribe", "sub_id": sub2}));
    server.set_fixed_now(None);
}

// Ordinary path preserved: valid subscribe + in-order live + stats/subs
// accounting + clean unsubscribe (no lifecycle interference).
#[test]
fn ordinary_authorized_delivery_preserved_after_hardening() {
    let (addr, _wal, server) = start_handle("ordinary-preserved");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, rep, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 0);
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=2 {
        let r = p.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": n}})).unwrap();
        assert!(ok(&r), "{r}");
    }
    for n in 1..=2u64 {
        let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(fr["msg"]["seq"], json!(n));
        assert_eq!(fr["sub_id"], json!(sub_id));
    }
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["deliveries"], json!(2), "{out}");
    assert_eq!(out["stats"]["drops"], json!(0), "{out}");
    let subs = p.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(subs["subs"][0]["delivered"], json!(2), "{subs}");
    assert!(ok(&s.unsubscribe(&sub_id).unwrap()));
    server.set_fixed_now(None);
}

// Ordinary replay preserved: 2 retained posts replay in order with
// replays accounting; writer policy allows (authorized, unexpired).
#[test]
fn ordinary_replay_preserved_after_writer_hardening() {
    let (addr, _wal, server) = start_handle("ordinary-replay");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=2 {
        let r = p.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": n}})).unwrap();
        assert!(ok(&r), "{r}");
    }
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, rep, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 2);
    for n in 1..=2u64 {
        let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(fr["msg"]["seq"], json!(n));
        assert_eq!(fr["sub_id"], json!(sub_id));
    }
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["replays"], json!(2), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(0), "{out}");
    assert_eq!(out["stats"]["drops"], json!(0), "{out}");
    assert!(ok(&s.unsubscribe(&sub_id).unwrap()));
    server.set_fixed_now(None);
}

// Writer expiry: 2 held live queued while valid, then the clock passes
// exp while still held. Release drops both at the writer (no delivery),
// counting drops; the sub remains until next RPC revalidation prunes it.
#[test]
fn writer_drops_held_live_after_expiry() {
    let wal = wal_path("writer-expiry");
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    let tokens = TokenStore::from_json_str(&format!(
        r#"{{"tok-alice-exp": {{"agent": "alice", "publish": ["*"], "subscribe": ["*"], "exp": {}}}, "tok-bob": {{"agent": "bob", "publish": ["*"], "subscribe": ["*"]}}}}"#,
        T0 + 10.0
    ))
    .unwrap();
    let server = Server::new(wal.clone(), tokens).expect("fresh WAL");
    server.set_fixed_now(Some(T0));
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));

    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice-exp").unwrap();
    let (sub_id, rep, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 0);
    assert!(handle.set_sub_hold_for_test(&sub_id, true));
    let mut pubc = Client::connect(&addr, "bob", "tok-bob").unwrap();
    for n in 1..=2 {
        let r = pubc.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": n}})).unwrap();
        assert!(ok(&r), "{r}");
    }
    assert_eq!(handle.subs_queued_for_test(&sub_id), Some(2));
    handle.set_fixed_now(Some(T0 + 20.0));
    assert!(handle.set_sub_hold_for_test(&sub_id, false));
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    let out = pubc.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["deliveries"], json!(2), "{out}");
    assert_eq!(out["stats"]["drops"], json!(2), "{out}");
    assert_eq!(out["stats"]["subs"], json!(1), "{out}");
    let r = s.unsubscribe(&sub_id).unwrap();
    assert_eq!(r["error"], json!("token expired"), "{r}");
    handle.set_fixed_now(None);
}
