//! Native subscriptions: `subscribe`/`unsubscribe`/`subs` + replay/live.
//!
//! No Python, no production IO: each test pins its own WAL, fixture tokens,
//! ephemeral loopback port, and fixed clock. Exercises actual wire
//! connections (auth denial, replay+live interleaving, expiry, queue
//! saturation with a non-reading peer, disconnect cleanup, WAL failure
//! isolation) plus the native CLI `sub`/`subs`/`unsubscribe` surfaces.
//! See `docs/NATIVE_SUBSCRIPTIONS.md` for the contract and deliberate
//! divergences (control reliability, atomic catch-up, strict numerics).

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use agent_bus::acl::TokenStore;
use agent_bus::wal::snapshot_path_for;
use agent_bus::wire::{Client, Server, StreamingConn};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-subs-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn open_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["board.build"], "subscribe": ["board.build"]},
            "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]}
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

fn cli_bin() -> String {
    env!("CARGO_BIN_EXE_agent-bus").to_string()
}

fn run_cli(addr: &str, agent: &str, token: &str, args: &[&str]) -> (i32, String, String) {
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

// Exact subscribe replays retained history in seq order with a catch-up
// cursor (topic_seq/oldest/retained/truncated) and per-frame sub_id.
#[test]
fn subscribe_exact_replays_history_with_cursor() {
    let (addr, _wal, server) = start_handle("exact-replay");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=3 {
        let r = post(&mut p, "board.build", json!({"n": n}));
        assert!(ok(&r), "{r}");
        assert_eq!(r["seq"], json!(n));
    }
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, replayed, cursor) = s.subscribe("board.build", 0, 0).unwrap();
    assert_eq!(replayed, 3);
    assert_eq!(sub_id.len(), 12);
    let cur = cursor.expect("exact cursor");
    assert_eq!(cur["topic"], json!("board.build"));
    assert_eq!(cur["topic_seq"], json!(3));
    assert_eq!(cur["oldest_seq"], json!(1));
    assert_eq!(cur["retained"], json!(3));
    assert_eq!(cur["truncated"], json!(false));
    for n in 1..=3u64 {
        let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(fr["event"], json!("msg"));
        assert_eq!(fr["sub_id"], json!(sub_id));
        assert_eq!(fr["topic"], json!("board.build"));
        assert_eq!(fr["msg"]["seq"], json!(n));
        assert_eq!(fr["msg"]["payload"], json!({"n": n}));
    }
    let r = s.unsubscribe(&sub_id).unwrap();
    assert!(ok(&r), "{r}");
    // Stats truthfully counts replay (not deliveries) + live sub.
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["replays"], json!(3), "{out}");
    assert_eq!(out["stats"]["subs"], json!(0), "{out}");
    server.set_fixed_now(None);
}

// Glob subscribe fans out across sorted matching topics, no cursor.
#[test]
fn subscribe_glob_matches_multiple_topics_sorted() {
    let (addr, _wal, server) = start_handle("glob-sorted");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut p, "other.c", json!({"n": 0}))));
    assert!(ok(&post(&mut p, "board.b", json!({"n": 2}))));
    assert!(ok(&post(&mut p, "board.a", json!({"n": 1}))));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, replayed, cursor) = s.subscribe("board.*", 0, 0).unwrap();
    assert_eq!(replayed, 2);
    assert!(cursor.is_none(), "glob has no cursor");
    let f1 = s.recv(Some(Duration::from_secs(5))).unwrap();
    let f2 = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(f1["topic"], json!("board.a"));
    assert_eq!(f2["topic"], json!("board.b"));
    assert_eq!(f1["sub_id"], json!(sub_id));
    assert_eq!(f2["sub_id"], json!(sub_id));
    let _ = s.unsubscribe(&sub_id);
    server.set_fixed_now(None);
}

// Conservative grant cover: `board.*` grant covers `board.build` but not
// `other.*`; unauthenticated subscribe is refused with a receipt.
#[test]
fn subscribe_denied_without_grant_and_auth_required() {
    let (addr, _wal, server) = start_handle("deny");
    server.set_fixed_now(Some(T0));
    let mut bob = Client::connect(&addr, "bob", "tok-bob").unwrap();
    // Bob's grant covers board.build (allowed) but not other.* (denied).
    let r = bob
        .rpc(&json!({"op": "subscribe", "pattern": "board.build", "from_seq": 0}))
        .unwrap();
    // Raw Client cannot complete subscribe (replay-before-reply needs a
    // streaming reader): it reads the first replay/live frame as the
    // response and fails req_id matching, or gets the control when no
    // replay exists. For an empty topic there is no replay, so the control
    // arrives first and parses. Either way, no silent success.
    // Empty board.build has no replay: control arrives, parses ok.
    assert!(ok(&r) || r.get("error").is_some(), "{r}");
    // Denied pattern returns an explicit req_id-bearing error (never a drop).
    let r = bob
        .rpc(&json!({"op": "subscribe", "pattern": "other.*", "from_seq": 0}))
        .unwrap();
    assert_eq!(r["error"], json!("subscribe denied: other.*"), "{r}");
    assert!(r.get("req_id").is_some(), "{r}");
    // Streaming denial surfaces as a refusal (not a hang).
    let mut s = StreamingConn::connect(&addr, "bob", "tok-bob").unwrap();
    let e = s.subscribe("other.*", 0, 0).unwrap_err();
    assert!(e.to_string().contains("subscribe denied"), "{e}");
    // Unauthenticated subscribe is refused.
    let mut raw = Client::raw(&addr).unwrap();
    let r = raw
        .rpc(&json!({"op": "subscribe", "pattern": "board.build"}))
        .unwrap();
    assert_eq!(r["error"], json!("auth required (send hello first)"), "{r}");
    server.set_fixed_now(None);
}

// Strict numerics: floats/bools/strings/null are req_id-bearing errors,
// never truncating coercions or dropped connections (Python `int(... or 0)`
// leniency is a deliberate correction).
#[test]
fn subscribe_strict_from_seq_tail_validation() {
    let (addr, _wal, server) = start_handle("strict-nums");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for (field, bad) in [
        ("from_seq", json!("abc")),
        ("from_seq", json!(3.7)),
        ("from_seq", json!(true)),
        ("from_seq", json!(null)),
        ("tail", json!("2")),
        ("tail", json!(-1)),
        ("tail", json!(false)),
    ] {
        let mut op = json!({"op": "subscribe", "pattern": "board.build"});
        op[field] = bad.clone();
        let r = c.rpc(&op).unwrap();
        let err = r.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert!(
            err.contains(field),
            "field={field} bad={bad} resp={r}"
        );
        assert!(r.get("req_id").is_some(), "{r}");
    }
    // Missing means 0 (empty topic, no replay, control parses).
    let r = c
        .rpc(&json!({"op": "subscribe", "pattern": "board.build"}))
        .unwrap();
    assert!(ok(&r), "{r}");
    server.set_fixed_now(None);
}

// from_seq/tail replay filtering: `tail` takes the last N per topic,
// then `from_seq` filters (matching Python `msgs[-tail:]` + `seq>`).
#[test]
fn from_seq_tail_replay_filtering() {
    let (addr, _wal, server) = start_handle("from-tail");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=5 {
        assert!(ok(&post(&mut p, "t", json!({"n": n}))));
    }
    // from_seq=2 replays 3,4,5.
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id1, rep, _) = s.subscribe("t", 2, 0).unwrap();
    assert_eq!(rep, 3);
    for n in 3..=5u64 {
        let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(fr["msg"]["seq"], json!(n));
    }
    let _ = s.unsubscribe(&id1);
    // tail=2 replays 4,5.
    let (id2, rep, _) = s.subscribe("t", 0, 2).unwrap();
    assert_eq!(rep, 2);
    for n in 4..=5u64 {
        let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(fr["msg"]["seq"], json!(n));
    }
    let _ = s.unsubscribe(&id2);
    // from_seq=4 + tail=2: last two are 4,5, filtered to >4 gives 5.
    let (id3, rep, _) = s.subscribe("t", 4, 2).unwrap();
    assert_eq!(rep, 1);
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["msg"]["seq"], json!(5));
    let _ = s.unsubscribe(&id3);
    server.set_fixed_now(None);
}

// Expiry: replay skips expired payloads; the cursor stays live-only
// (sync expiry, matching native `topics`, so gap detection sees expiry
// loss as unavailable rather than hiding it in `retained`).
#[test]
fn replay_skips_expired_with_live_cursor() {
    let (addr, _wal, server) = start_handle("expiry");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // m1 expires at T0+1, m2 lives.
    let r = p
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}, "ttl_ms": 1000.0}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert!(ok(&post(&mut p, "t", json!({"n": 2}))));
    server.set_fixed_now(Some(T0 + 2.0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, rep, cur) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 1);
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["msg"]["payload"], json!({"n": 2}));
    let cur = cur.expect("exact cursor");
    assert_eq!(cur["topic_seq"], json!(2));
    // Live-only: oldest is the surviving seq2, retained 1.
    assert_eq!(cur["oldest_seq"], json!(2));
    assert_eq!(cur["retained"], json!(1));
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// Retained cap: 1005 posts keep the last 1000; replay from 0 returns
// 1000 with oldest=6 (high-water preserved, prefix evicted).
#[test]
fn retained_cap_evicts_prefix_with_cursor_evidence() {
    let (addr, _wal, server) = start_handle("retain-cap");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=1005 {
        let r = post(&mut p, "t", json!({"n": n}));
        assert!(ok(&r), "{r}");
    }
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    // Widen the streaming deadline for the 1000-frame replay drain.
    s.set_rpc_timeout(Duration::from_secs(30)).unwrap();
    let (id, rep, cur) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 1000);
    let cur = cur.expect("exact cursor");
    assert_eq!(cur["topic_seq"], json!(1005));
    assert_eq!(cur["retained"], json!(1000));
    assert_eq!(cur["truncated"], json!(false));
    // First replayed is seq6 (prefix evicted), last is 1005.
    let f1 = s.recv(Some(Duration::from_secs(10))).unwrap();
    assert_eq!(f1["msg"]["seq"], json!(6));
    // Drain the rest (999 more) to prove the full retained window.
    for _ in 0..999 {
        let _ = s.recv(Some(Duration::from_secs(10))).unwrap();
    }
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// Live delivery: posts after subscribe arrive in commit order with
// deliveries counted (replay excluded) and per-sub delivered.
#[test]
fn live_delivery_after_subscribe_in_order() {
    let (addr, _wal, server) = start_handle("live-order");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, rep, _) = s.subscribe("board.build", 0, 0).unwrap();
    assert_eq!(rep, 0);
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=2 {
        assert!(ok(&post(&mut p, "board.build", json!({"n": n}))));
    }
    for n in 1..=2u64 {
        let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(fr["topic"], json!("board.build"));
        assert_eq!(fr["sub_id"], json!(id));
        assert_eq!(fr["msg"]["seq"], json!(n));
    }
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(2), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(2), "{out}");
    assert_eq!(out["stats"]["subs"], json!(1), "{out}");
    let subs = p.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(subs["subs"][0]["delivered"], json!(2), "{subs}");
    assert_eq!(subs["subs"][0]["dropped"], json!(0), "{subs}");
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// Idempotency: retained retry returns dup with no new seq/WAL/posts and
// no duplicate fan-out (live arrives once).
#[test]
fn no_duplicate_fanout_on_retained_retry() {
    let (addr, _wal, server) = start_handle("no-dup");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, _, _) = s.subscribe("t", 0, 0).unwrap();
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = p
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}, "msg_id": "dup1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    assert_eq!(r1["seq"], json!(1));
    let f1 = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(f1["msg"]["seq"], json!(1));
    // Retry same sender/topic/id/payload: dup, same seq, no new live.
    let r2 = p
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}, "msg_id": "dup1"}))
        .unwrap();
    assert_eq!(r2["dup"], json!(true), "{r2}");
    assert_eq!(r2["seq"], json!(1), "{r2}");
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(1), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(1), "{out}");
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// Durability: WAL failure returns an error with no visible state, no
// posts count, and no live delivery (safe retry after clearing).
#[test]
fn wal_failure_no_delivery_safe_retry() {
    use agent_bus::wal::APPEND_FAIL_AFTER_LINE;
    let (addr, _wal, server) = start_handle("wal-fail");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, _, _) = s.subscribe("t", 0, 0).unwrap();
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    server.set_append_failpoint(APPEND_FAIL_AFTER_LINE);
    let r = p.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}})).unwrap();
    assert!(r.get("error").is_some(), "{r}");
    assert!(r["error"].as_str().unwrap().contains("wal append failed"), "{r}");
    server.set_append_failpoint(0);
    // No live for the failed post.
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(0), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(0), "{out}");
    // Retry succeeds with seq1 (reservation rolled back, no gap).
    let r = post(&mut p, "t", json!({"n": 1}));
    assert_eq!(r["seq"], json!(1), "{r}");
    s.set_rpc_timeout(Duration::from_secs(5)).unwrap();
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["msg"]["seq"], json!(1));
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// Unsubscribe isolation: one connection's release never removes another's
// sub; foreign/unknown ids are idempotent ok (never errors).
#[test]
fn unsubscribe_isolation_across_connections() {
    let (addr, _wal, server) = start_handle("unsub-iso");
    server.set_fixed_now(Some(T0));
    let mut a = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let mut b = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (ida, _, _) = a.subscribe("t", 0, 0).unwrap();
    let (idb, _, _) = b.subscribe("t", 0, 0).unwrap();
    assert_ne!(ida, idb);
    // Foreign unsubscribe is ok but a no-op.
    let r = a.unsubscribe(&idb).unwrap();
    assert!(ok(&r), "{r}");
    // Unknown id is also ok.
    let r = a.unsubscribe("deadbeefcafe").unwrap();
    assert!(ok(&r), "{r}");
    // Both still live: post reaches both.
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut p, "t", json!({"n": 1}))));
    assert_eq!(a.recv(Some(Duration::from_secs(5))).unwrap()["msg"]["seq"], json!(1));
    assert_eq!(b.recv(Some(Duration::from_secs(5))).unwrap()["msg"]["seq"], json!(1));
    // Own unsubscribe removes only own.
    assert!(ok(&a.unsubscribe(&ida).unwrap()));
    assert!(ok(&post(&mut p, "t", json!({"n": 2}))));
    a.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = a.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    assert_eq!(b.recv(Some(Duration::from_secs(5))).unwrap()["msg"]["seq"], json!(2));
    let _ = b.unsubscribe(&idb);
    server.set_fixed_now(None);
}

// Subs listing: admin sees all, others see only their claimed agent's
// rows with age/delivered/dropped/queued.
#[test]
fn subs_listing_admin_vs_own() {
    let (addr, _wal, server) = start_handle("subs-list");
    server.set_fixed_now(Some(T0));
    let mut a = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (ida, _, _) = a.subscribe("board.build", 0, 0).unwrap();
    let mut b = StreamingConn::connect(&addr, "bob", "tok-bob").unwrap();
    let (idb, _, _) = b.subscribe("board.build", 0, 0).unwrap();
    server.set_fixed_now(Some(T0 + 10.0));
    // Admin sees both.
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let out = admin.rpc(&json!({"op": "subs"})).unwrap();
    assert!(ok(&out), "{out}");
    assert_eq!(out["subs"].as_array().unwrap().len(), 2, "{out}");
    // Alice sees only hers.
    let mut ac = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = ac.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(out["subs"].as_array().unwrap().len(), 1, "{out}");
    assert_eq!(out["subs"][0]["sub_id"], json!(ida), "{out}");
    assert_eq!(out["subs"][0]["agent"], json!("alice"), "{out}");
    assert_eq!(out["subs"][0]["pattern"], json!("board.build"), "{out}");
    assert_eq!(out["subs"][0]["age_s"], json!(10.0), "{out}");
    assert!(out["subs"][0]["delivered"].is_number(), "{out}");
    assert!(out["subs"][0]["dropped"].is_number(), "{out}");
    assert!(out["subs"][0]["queued"].is_number(), "{out}");
    // Bob sees only his.
    let mut bc = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = bc.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(out["subs"][0]["sub_id"], json!(idb), "{out}");
    let _ = a.unsubscribe(&ida);
    let _ = b.unsubscribe(&idb);
    server.set_fixed_now(None);
}

// Disconnect without unsubscribe releases owned subs and writer resources
// (server stays healthy for new streams).
#[test]
fn disconnect_releases_subs_and_writer() {
    let (addr, _wal, server) = start_handle("disconnect");
    server.set_fixed_now(Some(T0));
    {
        let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
        let (_id, _, _) = s.subscribe("t", 0, 0).unwrap();
        // Drop without unsubscribe (socket close).
    }
    // Poll for cleanup (server removes on EOF; loopback close is fast but
    // asynchronous across the reader thread).
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut subs = 1;
    for _ in 0..50 {
        let out = c.rpc(&json!({"op": "stats"})).unwrap();
        subs = out["stats"]["subs"].as_u64().unwrap_or(99) as usize;
        if subs == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(subs, 0, "owned sub leaked after disconnect");
    // Server still serves new streams (no leaked writer wedging the port).
    let mut s2 = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id2, _, _) = s2.subscribe("t", 0, 0).unwrap();
    assert!(ok(&post(&mut c, "t", json!({"n": 1}))));
    assert_eq!(s2.recv(Some(Duration::from_secs(5))).unwrap()["msg"]["seq"], json!(1));
    let _ = s2.unsubscribe(&id2);
    server.set_fixed_now(None);
}

// Bounded replay truncation: 6 topics x 850 (5100 total) glob-replays
// exactly 5000 (SUBS_REPLAY_CAP), sorted by topic, with stats/replays
// evidence. Per-topic retained cap is 1000, so truncation only triggers
// across topics; exact patterns never truncate (max 1000 < 5000).
#[test]
fn glob_replay_truncates_at_5000_with_sorted_evidence() {
    let (addr, _wal, server) = start_handle("truncate-5000");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for ti in 0..6 {
        let topic = format!("t{ti}");
        for n in 1..=850 {
            let r = post(&mut p, &topic, json!({"n": n}));
            assert!(ok(&r), "{r}");
        }
    }
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    s.set_rpc_timeout(Duration::from_secs(30)).unwrap();
    let (sub_id, replayed, cursor) = s.subscribe("t*", 0, 0).unwrap();
    assert_eq!(replayed, 5000);
    assert!(cursor.is_none(), "glob has no cursor");
    // First 5 topics full (4250), 6th partial 750 (seq 1..750).
    let f1 = s.recv(Some(Duration::from_secs(10))).unwrap();
    assert_eq!(f1["topic"], json!("t0"));
    assert_eq!(f1["msg"]["seq"], json!(1));
    // Drain to the truncation boundary: frames 2..5000.
    let mut last = f1;
    for _ in 1..5000 {
        last = s.recv(Some(Duration::from_secs(10))).unwrap();
    }
    assert_eq!(last["topic"], json!("t5"));
    assert_eq!(last["msg"]["seq"], json!(750), "{last}");
    assert_eq!(last["sub_id"], json!(sub_id));
    // Stats pins the bounded replay (not deliveries).
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["replays"], json!(5000), "{out}");
    let _ = s.unsubscribe(&sub_id);
    server.set_fixed_now(None);
}

// Actual non-reading peer: 1000 small posts to a subscriber that never
// calls recv. Publishers must never block (all posts ok); the queue stays
// bounded (<=2000) and stats stay truthful (numbers, never `?`).
// Socket buffers absorb small floods (writer drains faster than WAL-fsync
// publishers), so drops may be 0 here; deterministic eviction is pinned
// by `bounded_queue_evicts_with_drop_accounting_under_backpressure` and
// the `ConnOutbox` unit tests.
#[test]
fn non_reading_peer_never_blocks_publishers() {
    let (addr, _wal, server) = start_handle("nonreading-1000");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, rep, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 0);
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=1000 {
        let r = post(&mut p, "t", json!({"n": n}));
        assert!(ok(&r), "publisher blocked/dropped at {n}: {r}");
    }
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(1000), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(1000), "{out}");
    assert!(out["stats"]["drops"].is_number(), "{out}");
    assert_eq!(out["stats"]["subs"], json!(1), "{out}");
    let subs = p.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(subs["subs"][0]["sub_id"], json!(sub_id), "{subs}");
    assert_eq!(subs["subs"][0]["delivered"], json!(1000), "{subs}");
    assert!(subs["subs"][0]["dropped"].is_number(), "{subs}");
    let queued = subs["subs"][0]["queued"].as_u64().unwrap();
    assert!(queued <= 2000, "queue unbounded: {subs}");
    // Server healthy for new streams (slow peer wedges nothing).
    let mut s2 = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    s2.set_rpc_timeout(Duration::from_secs(30)).unwrap();
    let (id2, rep2, _) = s2.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep2, 1000);
    let _ = s2.unsubscribe(&id2);
    let _ = s.unsubscribe(&sub_id);
    server.set_fixed_now(None);
}

// Deterministic backpressure: small queue (50) + held writer (no drain
// races) + 4 concurrent publishers x 50 (200 total). The held writer
// blocks before each pop while publishers enqueue non-blocking, so the
// bounded queue fills to exactly 50 with explicit accounting:
// deliveries 200 (every queued frame, including replacements),
// drops 150 (200-50, no drain), queued 50 (full). Queued = deliveries -
// drops - drained (drained 0 while held); a deliberate correction vs
// Python which counts only non-evicted enqueues (see NATIVE_SUBSCRIPTIONS.md).
// Prior timing form (20ms delay, no hold) failed under load with
// delivered 200/dropped 1/queued 0 (writer drained during RPC checks);
// the hold gate replaces that scheduling assumption with synchronization.
#[test]
fn bounded_queue_evicts_with_drop_accounting_under_backpressure() {
    let (addr, _wal, server) = start_handle("backpressure-200");
    server.set_fixed_now(Some(T0));
    server.set_subs_queue_max_for_test(50);
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, rep, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep, 0);
    assert!(server.set_sub_hold_for_test(&sub_id, true));
    let mut handles = Vec::new();
    for tid in 0..4 {
        let a = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&a, "alice", "tok-alice").unwrap();
            for i in 0..50 {
                let r = c
                    .rpc(&json!({"op": "post", "topic": "t", "payload": {"tid": tid, "i": i}}))
                    .unwrap();
                assert!(ok(&r), "{r}");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Synchronous depth (no RPC drain window) while held: exactly full.
    assert_eq!(server.subs_queued_for_test(&sub_id), Some(50));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["posts"], json!(200), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(200), "{out}");
    let drops = out["stats"]["drops"].as_u64().unwrap();
    assert_eq!(drops, 150, "held queue must evict exactly 200-50: {out}");
    assert_eq!(out["stats"]["subs"], json!(1), "{out}");
    let subs = p.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(subs["subs"][0]["sub_id"], json!(sub_id), "{subs}");
    assert_eq!(subs["subs"][0]["delivered"], json!(200), "{subs}");
    let sub_dropped = subs["subs"][0]["dropped"].as_u64().unwrap();
    assert_eq!(sub_dropped, drops, "per-sub/global drop mismatch: {subs} vs {out}");
    let queued = subs["subs"][0]["queued"].as_u64().unwrap();
    assert_eq!(queued, 50, "held queue must stay full: {subs}");
    assert!(server.set_sub_hold_for_test(&sub_id, false));
    let _ = s.unsubscribe(&sub_id);
    server.set_fixed_now(None);
}

// Atomic catch-up under concurrent publication: 500 pre-fill + 4x25
// concurrent posts during subscribe. Total 600 < 1000 (no eviction),
// so the subscriber must receive exactly 1..600 in order, once each,
// regardless of snapshot timing (replay S + live 600-S).
#[test]
fn atomic_catchup_no_gaps_or_dups_under_concurrent_posts() {
    let (addr, _wal, server) = start_handle("atomic-catchup");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=500 {
        assert!(ok(&post(&mut p, "t", json!({"n": n}))));
    }
    // Spawn concurrent publishers before subscribing (overlap the replay).
    let mut handles = Vec::new();
    for tid in 0..4 {
        let a = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&a, "alice", "tok-alice").unwrap();
            for i in 0..25 {
                let r = c
                    .rpc(&json!({"op": "post", "topic": "t", "payload": {"tid": tid, "i": i}}))
                    .unwrap();
                assert!(ok(&r), "{r}");
            }
        }));
    }
    // Subscribe concurrently with the 100 in-flight posts.
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    s.set_rpc_timeout(Duration::from_secs(30)).unwrap();
    let (sub_id, replayed, _) = s.subscribe("t", 0, 0).unwrap();
    for h in handles {
        h.join().unwrap();
    }
    // Drain all 600 (replay + pending/live) in order.
    let mut seqs = Vec::with_capacity(600);
    // First `replayed` arrive as replay, rest as live; all via recv.
    for _ in 0..600 {
        let fr = s.recv(Some(Duration::from_secs(10))).unwrap();
        assert_eq!(fr["sub_id"], json!(sub_id));
        assert_eq!(fr["topic"], json!("t"));
        seqs.push(fr["msg"]["seq"].as_u64().unwrap());
    }
    // Exactly 1..600 once each, in order (no gaps, no dups).
    assert_eq!(replayed + (600 - replayed), 600);
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    let expect: Vec<u64> = (1..=600).collect();
    assert_eq!(sorted, expect, "gaps or dups in catch-up");
    assert_eq!(seqs, expect, "live interleaved before replay");
    let _ = s.unsubscribe(&sub_id);
    server.set_fixed_now(None);
}

// Reliable control under saturation: same-connection unsubscribe
// enqueues its receipt while the outbox is held full (50 live, writer
// blocked, no drain races), evicting oldest live to make room (never
// dropped). The unsubscribe runs in a background thread while held;
// the main thread waits for the eviction (drops 150 -> 151, queued
// still 50, sub already removed) before releasing, proving held-and-full
// enqueue deterministically. Prior timing form (20ms delay) failed under
// load with dropped 1/queued 0; the hold gate + eviction wait replaces
// that scheduling assumption with synchronization.
#[test]
fn control_unsubscribe_succeeds_while_flooded() {
    let (addr, _wal, server) = start_handle("control-flood");
    server.set_fixed_now(Some(T0));
    server.set_subs_queue_max_for_test(50);
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, _, _) = s.subscribe("t", 0, 0).unwrap();
    assert!(server.set_sub_hold_for_test(&sub_id, true));
    let mut handles = Vec::new();
    for tid in 0..4 {
        let a = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&a, "alice", "tok-alice").unwrap();
            for i in 0..50 {
                let r = c
                    .rpc(&json!({"op": "post", "topic": "t", "payload": {"tid": tid, "i": i}}))
                    .unwrap();
                assert!(ok(&r), "{r}");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(server.subs_queued_for_test(&sub_id), Some(50));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out0 = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out0["stats"]["drops"], json!(150), "no saturation: {out0}");
    assert_eq!(out0["stats"]["deliveries"], json!(200), "held deliveries must be exact: {out0}");
    let subs = p.rpc(&json!({"op": "subs"})).unwrap();
    let queued = subs["subs"][0]["queued"].as_u64().unwrap();
    assert_eq!(queued, 50, "queue not backlogged: {subs}");
    assert_eq!(subs["subs"][0]["delivered"], json!(200), "per-sub delivered must be exact: {subs}");
    assert_eq!(subs["subs"][0]["dropped"], json!(150), "per-sub dropped must match global: {subs}");
    let outbox = server.outbox_for_test(&sub_id).expect("outbox captured while sub live");
    let (tx, rx) = std::sync::mpsc::channel();
    let sub_clone = sub_id.clone();
    let unsub_handle = std::thread::spawn(move || {
        let r = s.unsubscribe(&sub_clone);
        let _ = tx.send(r.map(|v| v.to_string()));
        s
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut saw_eviction = false;
    while std::time::Instant::now() < deadline {
        let out = p.rpc(&json!({"op": "stats"})).unwrap();
        let drops = out["stats"]["drops"].as_u64().unwrap();
        let subs_n = out["stats"]["subs"].as_u64().unwrap();
        if drops == 151 && subs_n == 0 && outbox.len() == 50 {
            saw_eviction = true;
            break;
        }
        assert!(
            rx.try_recv().is_err(),
            "unsubscribe receipt arrived while still held (hold did not block writer)"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(saw_eviction, "control never enqueued while held and full");
    assert!(rx.try_recv().is_err(), "receipt must wait for release");
    outbox.set_hold(false);
    let mut s = unsub_handle.join().unwrap();
    let raw = rx.recv_timeout(Duration::from_secs(10)).expect("receipt after release").expect("unsubscribe ok");
    let r: Value = serde_json::from_str(&raw).unwrap();
    assert!(ok(&r), "{r}");
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["subs"], json!(0), "{out}");
    assert_eq!(out["stats"]["deliveries"], json!(200), "{out}");
    assert_eq!(outbox.len(), 0, "writer must drain control after dropping stale live");
    assert_eq!(
        out["stats"]["drops"],
        json!(200),
        "150 flood + 1 control eviction + 49 writer policy drops for removed sub: {out}"
    );
    assert!(ok(&post(&mut p, "t", json!({"n": 201}))));
    s.set_rpc_timeout(Duration::from_millis(500)).unwrap();
    loop {
        match s.recv(Some(Duration::from_millis(500))) {
            Ok(fr) => {
                let seq = fr["msg"]["seq"].as_u64().unwrap();
                assert!(seq <= 200, "post-unsubscribe live leaked: {fr}");
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => panic!("unexpected recv error: {e:?}"),
        }
    }
    server.set_fixed_now(None);
}

// Flooded disconnect: dropping a connection with a full 50-queue
// (slow writer) releases owned subs and joins the writer (no leak,
// no wedge). Close must terminate the throttled writer and free the
// subscription.
#[test]
fn flooded_disconnect_releases_subs_and_writer() {
    let (addr, _wal, server) = start_handle("flood-disc");
    server.set_fixed_now(Some(T0));
    server.set_subs_queue_max_for_test(50);
    server.set_writer_delay_for_test(20_000);
    {
        let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
        let (_id, _, _) = s.subscribe("t", 0, 0).unwrap();
        let mut handles = Vec::new();
        for tid in 0..4 {
            let a = addr.clone();
            handles.push(std::thread::spawn(move || {
                let mut c = Client::connect(&a, "alice", "tok-alice").unwrap();
                for i in 0..50 {
                    let r = c
                        .rpc(&json!({"op": "post", "topic": "t", "payload": {"tid": tid, "i": i}}))
                        .unwrap();
                    assert!(ok(&r), "{r}");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Drop with a full queue and throttled writer (no unsubscribe).
    }
    server.set_writer_delay_for_test(0);
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut subs = 1;
    for _ in 0..50 {
        let out = c.rpc(&json!({"op": "stats"})).unwrap();
        subs = out["stats"]["subs"].as_u64().unwrap_or(99) as usize;
        if subs == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(subs, 0, "flooded sub leaked after disconnect");
    // Server healthy: new streams work (fast writer restored).
    server.set_subs_queue_max_for_test(2000);
    let mut s2 = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    s2.set_rpc_timeout(Duration::from_secs(30)).unwrap();
    let (id2, rep2, _) = s2.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep2, 200);
    let _ = s2.unsubscribe(&id2);
    server.set_fixed_now(None);
}

// Native CLI `sub` against an isolated broker: --once replays retained
// history (3 lines, exit 0, always unsubscribes); bare --tail peeks the
// latest N (2 lines, seq 4,5); --new-only skips replay (0 lines).
#[test]
fn cli_sub_once_tail_and_new_only_against_ephemeral_server() {
    let (addr, _wal, server) = start_handle("cli-sub");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=5 {
        assert!(ok(&post(&mut p, "t", json!({"n": n}))));
    }
    // --once: full replay, 5 lines, exit 0, unsubscribes.
    let (st, stdout, stderr) = run_cli(&addr, "alice", "tok-alice", &["sub", "t", "--once", "--format", "json"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "stdout={stdout}");
    for (i, line) in lines.iter().enumerate() {
        let fr: Value = serde_json::from_str(line).unwrap();
        assert_eq!(fr["topic"], json!("t"), "{fr}");
        assert_eq!(fr["msg"]["seq"], json!((i + 1) as u64), "{fr}");
        assert!(fr["sub_id"].is_string(), "{fr}");
    }
    assert!(!stdout.contains("tok-alice") && !stderr.contains("tok-alice"));
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["subs"], json!(0), "CLI sub leaked: {out}");
    // Bare --tail 2: latest 2 only (seq 4,5), exit 0.
    let (st, stdout, stderr) = run_cli(&addr, "alice", "tok-alice", &["sub", "t", "--tail", "2", "--format", "json"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "stdout={stdout}");
    let f1: Value = serde_json::from_str(lines[0]).unwrap();
    let f2: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(f1["msg"]["seq"], json!(4), "{f1}");
    assert_eq!(f2["msg"]["seq"], json!(5), "{f2}");
    // --new-only: skips replay (0 lines, waits 1s for new, exit 0).
    let (st, stdout, stderr) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &["sub", "t", "--new-only", "--timeout", "1", "--format", "json"],
    );
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    assert!(stdout.lines().count() == 0, "new-only replayed: {stdout}");
    // Usage errors: missing pattern, bad values, glob + --new-only.
    for args in [
        vec!["sub"],
        vec!["sub", "t", "--from-seq", "abc"],
        vec!["sub", "t", "--tail", "-1"],
        vec!["sub", "t", "--format", "yaml"],
    ] {
        let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &args);
        assert_eq!(st, 2, "{args:?} stderr={stderr}");
    }
    let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &["sub", "t*", "--new-only"]);
    assert_eq!(st, 1, "stderr={stderr}");
    assert!(stderr.contains("single topic"), "stderr={stderr}");
    server.set_fixed_now(None);
}

// Native CLI `subs` against an isolated broker: lists live subs (json +
// short) with delivered/dropped/queued numbers, then empty after
// unsubscribe.
#[test]
fn cli_subs_lists_live_subscriptions_on_ephemeral_server() {
    let (addr, _wal, server) = start_handle("cli-subs");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, _, _) = s.subscribe("board.build", 0, 0).unwrap();
    // JSON lists the live sub with numeric counters.
    let (st, stdout, stderr) = run_cli(&addr, "alice", "tok-alice", &["subs", "--format", "json"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    assert!(!stdout.contains("tok-alice") && !stderr.contains("tok-alice"));
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&resp), "{resp}");
    assert_eq!(resp["subs"].as_array().unwrap().len(), 1, "{resp}");
    assert_eq!(resp["subs"][0]["sub_id"], json!(sub_id), "{resp}");
    assert_eq!(resp["subs"][0]["agent"], json!("alice"), "{resp}");
    assert_eq!(resp["subs"][0]["pattern"], json!("board.build"), "{resp}");
    assert!(resp["subs"][0]["delivered"].is_number(), "{resp}");
    assert!(resp["subs"][0]["dropped"].is_number(), "{resp}");
    assert!(resp["subs"][0]["queued"].is_number(), "{resp}");
    // Short renders one line with dlv/drop/q.
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["subs", "--format", "short"]);
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains(&sub_id), "{stdout}");
    assert!(stdout.contains("board.build"), "{stdout}");
    assert!(stdout.contains("dlv="), "{stdout}");
    // Usage errors exit 2.
    for args in [vec!["subs", "--format", "yaml"], vec!["subs", "extra"], vec!["subs", "--bogus"]] {
        let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &args);
        assert_eq!(st, 2, "{args:?} stderr={stderr}");
    }
    // After unsubscribe, empty.
    let _ = s.unsubscribe(&sub_id);
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["subs", "--format", "json"]);
    assert_eq!(st, 0, "{stdout}");
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(resp["subs"].as_array().unwrap().len(), 0, "{resp}");
    server.set_fixed_now(None);
}

// Native CLI `unsubscribe` against an isolated broker: idempotent ok for
// foreign/unknown ids (per-connection isolation: a one-shot CLI conn owns
// nothing, so it never removes another conn's sub), never an error.
#[test]
fn cli_unsubscribe_is_idempotent_and_isolated_on_ephemeral_server() {
    let (addr, _wal, server) = start_handle("cli-unsub");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (sub_id, _, _) = s.subscribe("t", 0, 0).unwrap();
    // Foreign unsubscribe via CLI (different conn) is ok but a no-op.
    let (st, stdout, stderr) = run_cli(&addr, "alice", "tok-alice", &["unsubscribe", &sub_id]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&resp), "{resp}");
    // Unknown id is also ok.
    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["unsubscribe", "deadbeefcafe"]);
    assert_eq!(st, 0, "{stdout}");
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&resp), "{resp}");
    // Sub still live: post reaches it (isolation preserved).
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut p, "t", json!({"n": 1}))));
    assert_eq!(s.recv(Some(Duration::from_secs(5))).unwrap()["msg"]["seq"], json!(1));
    // Usage errors exit 2.
    for args in [vec!["unsubscribe"], vec!["unsubscribe", "a", "b"], vec!["unsubscribe", "x", "--bogus"]] {
        // Note: unsubscribe takes no flags; --bogus is an unknown option.
        // The "a b" case is two positionals (takes one).
        let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &args);
        // "a b" and missing/flag cases all exit 2 (usage).
        assert_eq!(st, 2, "{args:?} stderr={stderr}");
    }
    let _ = s.unsubscribe(&sub_id);
    server.set_fixed_now(None);
}
