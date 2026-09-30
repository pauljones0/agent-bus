//! Post `msg_id` retry idempotency + native `ping` health.
//!
//! No Python, no production IO, no wall sleeps: each test pins its own WAL,
//! fixture tokens, ephemeral loopback port, and fixed clock. Proves the
//! retained-history dedup window (`RETAIN_PER_TOPIC`, live-only,
//! newest-wins) with ACL-first disclosure, conflict refusal, failed-append
//! safety, concurrency serialization, replay/compaction survival, and
//! honest expiry/eviction limits (never fabricated receipts). Also proves
//! the native CLI `ping` (json/short, `--count`) and `post --msg-id`
//! against ephemeral servers plus malformed/error/disconnect negatives.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use agent_bus::acl::TokenStore;
use agent_bus::history::RETAIN_PER_TOPIC;
use agent_bus::wal::{compact, replay, BusState, APPEND_FAIL_AFTER_LINE, APPEND_FAIL_OPEN};
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-idem-{}-{}-{}", name, std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn rand_suffix() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    (std::process::id(), std::time::SystemTime::now()).hash(&mut h);
    h.finish()
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

fn start_with_handle(name: &str, tokens: TokenStore) -> (String, PathBuf, Server) {
    let wal = wal_path(name);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(agent_bus::wal::snapshot_path_for(&wal));
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

fn stats_posts(c: &mut Client) -> u64 {
    let s = c.rpc(&json!({"op": "stats"})).unwrap();
    assert!(ok(&s), "{s}");
    s["stats"]["posts"].as_u64().unwrap()
}

fn fetch_msgs(c: &mut Client, topic: &str) -> Value {
    c.rpc(&json!({"op": "fetch", "topic": topic, "from_seq": 0}))
        .unwrap()
}

// Retry with identical sender/topic/id/payload returns the original receipt.
#[test]
fn retry_same_payload_returns_original_without_new_seq() {
    let (addr, _wal, server) = start_handle("retry-same");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 1}, "msg_id": "r1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    assert_eq!(r1["seq"], json!(1));
    assert!(r1.get("dup").is_none(), "{r1}");
    assert_eq!(stats_posts(&mut c), 1);

    let r2 = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 1}, "msg_id": "r1"}))
        .unwrap();
    assert!(ok(&r2), "{r2}");
    assert_eq!(r2["id"], json!("r1"));
    assert_eq!(r2["seq"], json!(1), "must return original seq, not a new one");
    assert_eq!(r2["dup"], json!(true));
    assert_eq!(stats_posts(&mut c), 1, "dup must not advance posts counter");

    let f = fetch_msgs(&mut c, "board.build");
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"].as_array().unwrap().len(), 1);
    assert_eq!(f["messages"][0]["seq"], json!(1));
    assert_eq!(f["messages"][0]["id"], json!("r1"));
    server.set_fixed_now(None);
}

// Same id with different payload is a conflict, not a new message.
#[test]
fn conflicting_payload_refused_without_mutation() {
    let (addr, _wal, server) = start_handle("conflict-payload");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1, "msg_id": "c1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    assert_eq!(stats_posts(&mut c), 1);

    let r2 = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 2, "msg_id": "c1"}))
        .unwrap();
    assert!(r2.get("error").is_some(), "{r2}");
    assert!(
        r2["error"].as_str().unwrap().contains("msg_id conflict"),
        "{r2}"
    );
    assert!(r2.get("seq").is_none(), "conflict must not disclose a receipt: {r2}");
    assert_eq!(stats_posts(&mut c), 1);

    // Next new post still gets seq 2 (conflict advanced nothing).
    let r3 = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 3}))
        .unwrap();
    assert_eq!(r3["seq"], json!(2), "{r3}");
    let f = fetch_msgs(&mut c, "board.build");
    assert_eq!(f["messages"].as_array().unwrap().len(), 2);
    server.set_fixed_now(None);
}

// Different sender or different corr/reply with same id also conflicts.
#[test]
fn conflicting_sender_and_corr_refused() {
    let (addr, _wal, server) = start_handle("conflict-sender");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = a
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 1},
            "msg_id": "s1", "corr_id": "k1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");

    // Same sender, same payload, different corr -> conflict.
    let r2 = a
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 1},
            "msg_id": "s1", "corr_id": "k2"}))
        .unwrap();
    assert!(r2["error"].as_str().unwrap().contains("msg_id conflict"), "{r2}");

    // Different sender, same topic/id/payload -> conflict (no mutation).
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let r3 = b
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 1},
            "msg_id": "s1", "corr_id": "k1"}))
        .unwrap();
    assert!(r3["error"].as_str().unwrap().contains("different sender"), "{r3}");

    assert_eq!(stats_posts(&mut a), 1);
    server.set_fixed_now(None);
}

// Missing corr and explicit null corr are the same for retry equality.
#[test]
fn missing_vs_null_corr_matches_as_retry() {
    let (addr, _wal, server) = start_handle("corr-null");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "n1", "corr_id": null}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    // Retry omits corr_id entirely: still a retry, not a conflict.
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "n1"}))
        .unwrap();
    assert!(ok(&r2), "{r2}");
    assert_eq!(r2["seq"], r1["seq"]);
    assert_eq!(r2["dup"], json!(true));
    server.set_fixed_now(None);
}

// Auto ids (missing/empty/null/non-string) never dedup.
#[test]
fn auto_ids_always_new() {
    let (addr, _wal, server) = start_handle("auto-ids");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let a = c.rpc(&json!({"op": "post", "topic": "t", "payload": 1})).unwrap();
    let b = c.rpc(&json!({"op": "post", "topic": "t", "payload": 1})).unwrap();
    assert!(ok(&a) && ok(&b), "{a} {b}");
    assert_ne!(a["seq"], b["seq"]);
    assert_ne!(a["id"], b["id"]);

    for (label, req) in [
        ("empty", json!({"op": "post", "topic": "t", "payload": 1, "msg_id": ""})),
        ("null", json!({"op": "post", "topic": "t", "payload": 1, "msg_id": null})),
        ("number", json!({"op": "post", "topic": "t", "payload": 1, "msg_id": 123})),
    ] {
        let r = c.rpc(&req).unwrap();
        assert!(ok(&r), "{label}: {r}");
        assert!(r.get("dup").is_none(), "{label}: {r}");
    }
    assert_eq!(stats_posts(&mut c), 5);
    server.set_fixed_now(None);
}

// Same id on different topics is allowed (per-topic window).
#[test]
fn same_id_different_topics_allowed() {
    let (addr, _wal, server) = start_handle("diff-topics");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1, "msg_id": "shared"}))
        .unwrap();
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "board.announce", "payload": 1, "msg_id": "shared"}))
        .unwrap();
    assert!(ok(&r1) && ok(&r2), "{r1} {r2}");
    assert_eq!(r1["seq"], json!(1));
    assert_eq!(r2["seq"], json!(1));
    // Each retries independently.
    let d1 = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1, "msg_id": "shared"}))
        .unwrap();
    assert_eq!(d1["dup"], json!(true));
    assert_eq!(d1["seq"], json!(1));
    server.set_fixed_now(None);
}

// TTL is not part of retry equality; the original expiry is preserved.
#[test]
fn ttl_ignored_for_retry_preserves_original_expiry() {
    let (addr, _wal, server) = start_handle("ttl-ignored");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "ttl1", "ttl_ms": 100_000}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    // Same payload, different ttl -> still a retry (ttl ignored).
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "ttl1", "ttl_ms": 200_000}))
        .unwrap();
    assert!(ok(&r2), "{r2}");
    assert_eq!(r2["dup"], json!(true));
    assert_eq!(r2["seq"], r1["seq"]);
    // Original expiry preserved (T0+100), not T0+200.
    let f = fetch_msgs(&mut c, "t");
    assert_eq!(f["messages"][0]["exp"], json!(T0 + 100.0), "{f}");
    server.set_fixed_now(None);
}

// Expired originals are outside the window: retry becomes new, never old seq.
#[test]
fn expired_retry_becomes_new_never_fabricates() {
    let (addr, _wal, server) = start_handle("expired-new");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "e1", "ttl_ms": 1000}))
        .unwrap();
    assert_eq!(r1["seq"], json!(1));
    // Still live at +0.5: retry returns original.
    server.set_fixed_now(Some(T0 + 0.5));
    let r2 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "e1"}))
        .unwrap();
    assert_eq!(r2["seq"], json!(1));
    assert_eq!(r2["dup"], json!(true));
    // Past expiry at +2: same id becomes a NEW post (seq 2, no dup).
    server.set_fixed_now(Some(T0 + 2.0));
    let r3 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "e1"}))
        .unwrap();
    assert!(ok(&r3), "{r3}");
    assert_eq!(r3["seq"], json!(2), "expired retry must be new, not fabricated old seq");
    assert!(r3.get("dup").is_none(), "{r3}");
    server.set_fixed_now(None);
}

// ACL runs before any receipt disclosure: denied callers learn nothing.
#[test]
fn acl_denied_before_receipt_disclosure() {
    let (addr, _wal, server) = start_handle("acl-first");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = a
        .rpc(&json!({"op": "post", "topic": "board.secret", "payload": 1, "msg_id": "k1"}))
        .unwrap();
    assert!(ok(&r1), "{r1}");
    // Bob has no publish grant for board.secret: same id+payload still denied,
    // never dup/conflict and never the original seq.
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let r2 = b
        .rpc(&json!({"op": "post", "topic": "board.secret", "payload": 1, "msg_id": "k1"}))
        .unwrap();
    assert_eq!(r2["error"], json!("publish denied: board.secret"), "{r2}");
    assert!(r2.get("seq").is_none() && r2.get("dup").is_none(), "{r2}");
    server.set_fixed_now(None);
}

// Failed WAL appends leave no trace: the next retry posts new (not poisoned),
// and dup retries need no WAL (succeed even under failpoint).
#[test]
fn failed_append_does_not_poison_retry() {
    let (addr, wal, server) = start_handle("fail-retry");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();

    for mode in [APPEND_FAIL_OPEN, APPEND_FAIL_AFTER_LINE] {
        let before = stats_posts(&mut c);
        server.set_append_failpoint(mode);
        let id = format!("f{mode}");
        let r = c
            .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": id}))
            .unwrap();
        assert!(r.get("error").is_some(), "mode {mode}: {r}");
        assert_eq!(stats_posts(&mut c), before, "failed append must not count");
        server.set_append_failpoint(0);
        // Retry after failure posts NEW (no dup, no conflict); posts +1.
        let r2 = c
            .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": id}))
            .unwrap();
        assert!(ok(&r2), "mode {mode}: {r2}");
        assert!(r2.get("dup").is_none(), "mode {mode}: {r2}");
        assert_eq!(stats_posts(&mut c), before + 1, "retry posts new");
        // WAL has no torn tail from the failed attempt.
        assert_eq!(
            agent_bus::wal::tail_status(&wal).unwrap(),
            agent_bus::wal::TailStatus::Clean
        );
    }
    // Dup retry needs no WAL: succeeds even with failpoint armed.
    server.set_append_failpoint(APPEND_FAIL_OPEN);
    let d = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "f1"}))
        .unwrap();
    assert!(ok(&d), "{d}");
    assert_eq!(d["dup"], json!(true));
    server.set_append_failpoint(0);
    server.set_fixed_now(None);
}

// Concurrent duplicates serialize: exactly one new, rest dup with same seq.
#[test]
fn concurrent_duplicates_serialize_one_new() {
    let (addr, _wal, server) = start_handle("concurrent-dup");
    server.set_fixed_now(Some(T0));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let addr = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
            c.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 7}, "msg_id": "race1"}))
                .unwrap()
        }));
    }
    let mut replies = Vec::new();
    for h in handles {
        replies.push(h.join().unwrap());
    }
    let news: Vec<&Value> = replies.iter().filter(|r| ok(r) && r.get("dup").is_none()).collect();
    let dups: Vec<&Value> =
        replies.iter().filter(|r| ok(r) && r.get("dup") == Some(&json!(true))).collect();
    assert_eq!(news.len(), 1, "exactly one winner: {replies:?}");
    assert_eq!(dups.len(), 7, "{replies:?}");
    for d in &dups {
        assert_eq!(d["seq"], news[0]["seq"]);
        assert_eq!(d["id"], json!("race1"));
    }
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert_eq!(stats_posts(&mut c), 1);
    let f = fetch_msgs(&mut c, "t");
    assert_eq!(f["messages"].as_array().unwrap().len(), 1);
    server.set_fixed_now(None);
}

// Replay + compaction preserve the live window (ephemeral WAL fixtures).
#[test]
fn replay_and_compaction_preserve_live_window() {
    let (addr, wal, server) = start_handle("replay-window");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r1 = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": 1, "msg_id": "w1"}))
        .unwrap();
    assert_eq!(r1["seq"], json!(1));
    drop(c);

    // Replay into fresh state at the same clock: live entry survives.
    let mut s = BusState::new();
    replay(&wal, &mut s, T0).expect("wal replays");
    let found = s.topics["t"].find_live_by_id("w1", T0).expect("live after replay");
    assert_eq!(found.seq, 1);

    // Compact + replay again: still live with the same seq.
    compact(&wal, &s, T0).unwrap();
    let mut s2 = BusState::new();
    replay(&wal, &mut s2, T0).expect("compacted wal replays");
    let found2 = s2.topics["t"].find_live_by_id("w1", T0).expect("live after compact");
    assert_eq!(found2.seq, 1);

    // Expired at a later clock is outside the window after replay.
    let mut s3 = BusState::new();
    replay(&wal, &mut s3, T0 + 10_000.0).expect("wal replays");
    // w1 has no expiry, so still live; craft an expired check via direct WAL:
    // (expiry eviction is covered by expired_retry_becomes_new_never_fabricates).
    assert!(s3.topics["t"].find_live_by_id("w1", T0 + 10_000.0).is_some());
    server.set_fixed_now(None);
}

// Evicted ids are outside the window: retry becomes new (bounded retention).
#[test]
fn evicted_id_outside_window_becomes_new() {
    // Build a WAL with RETAIN+1 posts where seq 1 carries id "old".
    // Single open + single fsync keeps the fixture fast and ephemeral.
    let wal = wal_path("evict-window");
    let _ = std::fs::remove_file(&wal);
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&wal)
            .unwrap();
        for seq in 1..=(RETAIN_PER_TOPIC as u64 + 1) {
            let id = if seq == 1 { "old".to_string() } else { format!("id{seq}") };
            let rec = json!({"t": "post", "topic": "t",
                "msg": {"seq": seq, "id": id, "sender": "alice", "ts": T0,
                    "exp": null, "payload": {"n": seq}}});
            f.write_all(serde_json::to_vec(&rec).unwrap().as_slice()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        f.flush().unwrap();
        f.sync_all().unwrap();
    }
    let server = Server::new(wal.clone(), open_tokens()).expect("evict WAL starts");
    server.set_fixed_now(Some(T0));
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));

    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Head is RETAIN+1; oldest retained is seq 2 (seq 1 evicted).
    let f = fetch_msgs(&mut c, "t");
    assert!(f["cursor"]["gap"] == json!(true), "{f}");
    // Retry of evicted "old" with its ORIGINAL payload becomes NEW (seq
    // RETAIN+2), never the fabricated old seq 1. This is the documented
    // bounded-window limit: outside retention, at-least-once may duplicate.
    let r = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}, "msg_id": "old"}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(r["seq"], json!((RETAIN_PER_TOPIC as u64) + 2), "{r}");
    assert!(r.get("dup").is_none(), "{r}");
    handle.set_fixed_now(None);
    let _ = std::fs::remove_file(&wal);
}

// Ping wire contract: server_ts + authed, never touches presence.
#[test]
fn ping_returns_server_ts_and_authed_without_touching_presence() {
    let (addr, _wal, server) = start_handle("ping-wire");
    server.set_fixed_now(Some(T0));
    // Unauthenticated ping: ok + authed false + server_ts.
    let mut raw = Client::raw(&addr).unwrap();
    let r = raw.rpc(&json!({"op": "ping"})).unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(r["authed"], json!(false));
    assert_eq!(r["server_ts"], json!(T0));

    // Authenticated ping: authed true, same clock.
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r2 = a.rpc(&json!({"op": "ping"})).unwrap();
    assert_eq!(r2["authed"], json!(true));
    assert_eq!(r2["server_ts"], json!(T0));

    // Ping never touches presence: age keeps growing past the ping.
    server.set_fixed_now(Some(T0 + 100.0));
    let _ = a.rpc(&json!({"op": "ping"})).unwrap();
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let out = b.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["age_s"], json!(100.0), "{out}");

    // Non-finite clock: ping fails (no fabricated timestamp).
    server.set_fixed_now(Some(f64::NAN));
    let r3 = a.rpc(&json!({"op": "ping"})).unwrap();
    assert_eq!(r3["error"], json!("non-finite time"), "{r3}");
    server.set_fixed_now(None);
}

// --- native CLI helpers (ephemeral servers only, never production) ---

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

// CLI ping: json + short + count on an ephemeral server, no leaks.
#[test]
fn cli_ping_json_short_and_count_on_ephemeral_server() {
    let (addr, _wal, server) = start_handle("cli-ping");
    server.set_fixed_now(Some(T0));

    let (st, stdout, stderr) = run_cli(&addr, "alice", "tok-alice", &["ping"]);
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    assert!(!stdout.contains("tok-alice") && !stderr.contains("tok-alice"));
    let resp: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&resp), "{resp}");
    assert_eq!(resp["authed"], json!(true));
    assert_eq!(resp["server_ts"], json!(T0));

    let (st, stdout, _) = run_cli(&addr, "alice", "tok-alice", &["ping", "--format", "short"]);
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains("pong authed=True"), "{stdout}");
    assert!(stdout.contains(&T0.to_string()), "{stdout}");

    let (st, stdout, _) =
        run_cli(&addr, "alice", "tok-alice", &["ping", "--count", "3", "--format", "json"]);
    assert_eq!(st, 0, "{stdout}");
    assert_eq!(stdout.trim().lines().count(), 3, "{stdout}");

    // Usage errors exit 2.
    for args in [
        vec!["ping", "--count", "0"],
        vec!["ping", "--count", "-2"],
        vec!["ping", "--count", "abc"],
        vec!["ping", "--format", "yaml"],
        vec!["ping", "--bogus"],
        vec!["ping", "extra"],
    ] {
        let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &args);
        assert_eq!(st, 2, "{args:?} stderr={stderr}");
    }
    server.set_fixed_now(None);
}

// CLI ping truthful exit 1: missing env, bad auth, no broker, broker error.
#[test]
fn cli_ping_exit_1_on_transport_auth_and_broker_errors() {
    let (addr, _wal, server) = start_handle("cli-ping-err");
    server.set_fixed_now(Some(T0));

    // Missing token.
    let (host, port) = addr.rsplit_once(':').unwrap();
    let out = Command::new(cli_bin())
        .args(["ping"])
        .env("AGENT_BUS_AGENT", "alice")
        .env_remove("AGENT_BUS_TOKEN")
        .env_remove("AGENT_BUS_SOCK")
        .env("AGENT_BUS_HOST", host)
        .env("AGENT_BUS_PORT", port)
        .output()
        .unwrap();
    assert_eq!(out.status.code().unwrap(), 1);

    // Bad token.
    let (st, _, _) = run_cli(&addr, "alice", "wrong-token", &["ping"]);
    assert_eq!(st, 1);

    // No broker (unused port).
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap().to_string();
        drop(l);
        a
    };
    let (st, _, stderr) = run_cli(&dead, "alice", "tok-alice", &["ping"]);
    assert_eq!(st, 1, "{stderr}");

    // Broker clock broken (NAN fails hello first, still exit 1 truthfully;
    // ping-after-hello errors are covered by the scripted error fixture).
    server.set_fixed_now(Some(f64::NAN));
    let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &["ping"]);
    assert_eq!(st, 1, "{stderr}");
    assert!(stderr.contains("error:"), "{stderr}");
    server.set_fixed_now(None);
}

// CLI ping against malformed / error / disconnecting fixtures exits 1 (never 0/2).
#[test]
fn cli_ping_malformed_and_disconnect_fixtures_exit_1() {
    use std::io::{BufRead, BufReader, Write as _};

    // Malformed: hello ok, ping gets non-JSON bytes.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            // hello
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let hello_id = serde_json::from_str::<Value>(&line)
                .ok()
                .and_then(|v| v.get("req_id").cloned())
                .unwrap_or(json!(1));
            let _ = writer.write_all(
                serde_json::to_vec(&json!({"req_id": hello_id, "ok": true, "agent": "alice"}))
                    .unwrap()
                    .as_slice(),
            );
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();
            // ping -> malformed
            line.clear();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let _ = writer.write_all(b"not-json{{{\n");
            let _ = writer.flush();
            break;
        }
    });
    let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &["ping"]);
    assert_eq!(st, 1, "malformed ping reply must exit 1, stderr={stderr}");

    // Disconnect: hello ok, ping gets EOF (close without reply).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let hello_id = serde_json::from_str::<Value>(&line)
                .ok()
                .and_then(|v| v.get("req_id").cloned())
                .unwrap_or(json!(1));
            let _ = writer.write_all(
                serde_json::to_vec(&json!({"req_id": hello_id, "ok": true, "agent": "alice"}))
                    .unwrap()
                    .as_slice(),
            );
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();
            // Close without answering ping.
            break;
        }
    });
    let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &["ping"]);
    assert_eq!(st, 1, "disconnect on ping must exit 1, stderr={stderr}");

    // Broker error: hello ok, ping gets {"error": ...} (e.g. non-finite).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let hello_id = serde_json::from_str::<Value>(&line)
                .ok()
                .and_then(|v| v.get("req_id").cloned())
                .unwrap_or(json!(1));
            let _ = writer.write_all(
                serde_json::to_vec(&json!({"req_id": hello_id, "ok": true, "agent": "alice"}))
                    .unwrap()
                    .as_slice(),
            );
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();
            line.clear();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let ping_id = serde_json::from_str::<Value>(&line)
                .ok()
                .and_then(|v| v.get("req_id").cloned())
                .unwrap_or(json!(2));
            let _ = writer.write_all(
                serde_json::to_vec(&json!({"req_id": ping_id, "error": "non-finite time"}))
                    .unwrap()
                    .as_slice(),
            );
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();
            break;
        }
    });
    let (st, _, stderr) = run_cli(&addr, "alice", "tok-alice", &["ping"]);
    assert_eq!(st, 1, "broker ping error must exit 1, stderr={stderr}");
    assert!(stderr.contains("non-finite"), "{stderr}");
}

// CLI ping validates the authenticated reply: authed must be boolean true,
// and a present server_ts must be a finite number. Missing server_ts stays
// accepted for the documented older native reply.
#[test]
fn cli_ping_validates_authed_and_server_ts() {
    use std::io::{BufRead, BufReader, Write as _};

    fn run_with_reply(reply: Value, args: &[&str]) -> (i32, String, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    break;
                }
                let hello_id = serde_json::from_str::<Value>(&line)
                    .ok()
                    .and_then(|v| v.get("req_id").cloned())
                    .unwrap_or(json!(1));
                let _ = writer.write_all(
                    serde_json::to_vec(&json!({"req_id": hello_id, "ok": true, "agent": "alice"}))
                        .unwrap()
                        .as_slice(),
                );
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
                line.clear();
                if reader.read_line(&mut line).is_err() {
                    break;
                }
                let ping_id = serde_json::from_str::<Value>(&line)
                    .ok()
                    .and_then(|v| v.get("req_id").cloned())
                    .unwrap_or(json!(2));
                let mut out = reply.clone();
                out["req_id"] = ping_id;
                let _ = writer.write_all(serde_json::to_vec(&out).unwrap().as_slice());
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
                break;
            }
        });
        run_cli(&addr, "alice", "tok-alice", args)
    }

    // Missing/false/non-boolean authed never proves authenticated health.
    for reply in [
        json!({"ok": true, "server_ts": 1234.0}),
        json!({"ok": true, "authed": false, "server_ts": 1234.0}),
        json!({"ok": true, "authed": "true", "server_ts": 1234.0}),
    ] {
        let (st, stdout, stderr) = run_with_reply(reply.clone(), &["ping"]);
        assert_eq!(
            st, 1,
            "reply {reply} must exit 1, stdout={stdout} stderr={stderr}"
        );
        assert!(
            stdout.trim().is_empty(),
            "failed ping must not print pong: {stdout}"
        );
        assert!(
            stderr.contains("authed"),
            "stderr must name authed: {stderr}"
        );
    }

    // Present server_ts must be a finite number.
    for ts in [Value::Null, json!("later"), json!({"time": 1234})] {
        let reply = json!({"ok": true, "authed": true, "server_ts": ts});
        let (st, stdout, stderr) = run_with_reply(reply.clone(), &["ping"]);
        assert_eq!(
            st, 1,
            "reply {reply} must exit 1, stdout={stdout} stderr={stderr}"
        );
        assert!(
            stdout.trim().is_empty(),
            "failed ping must not print pong: {stdout}"
        );
        assert!(
            stderr.contains("server_ts"),
            "stderr must name server_ts: {stderr}"
        );
    }

    // Current shape passes in both formats.
    let (st, stdout, stderr) = run_with_reply(
        json!({"ok": true, "authed": true, "server_ts": 1234.0}),
        &["ping"],
    );
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let (st, stdout, _) = run_with_reply(
        json!({"ok": true, "authed": true, "server_ts": 1234.0}),
        &["ping", "--format", "short"],
    );
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains("pong authed=True"), "{stdout}");

    // Documented older native reply (server_ts absent) stays accepted.
    let (st, stdout, stderr) = run_with_reply(json!({"ok": true, "authed": true}), &["ping"]);
    assert_eq!(
        st, 0,
        "older reply must stay accepted: stdout={stdout} stderr={stderr}"
    );
    let (st, stdout, _) = run_with_reply(
        json!({"ok": true, "authed": true}),
        &["ping", "--format", "short"],
    );
    assert_eq!(st, 0, "{stdout}");
    assert!(stdout.contains("server_ts=?"), "{stdout}");
}

// CLI post --msg-id: retry returns dup, conflict refused, absent stays auto.
#[test]
fn cli_post_msg_id_retry_conflict_and_auto() {
    let (addr, _wal, server) = start_handle("cli-msgid");
    server.set_fixed_now(Some(T0));

    let (st, stdout, stderr) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &["post", "board.build", r#"{"n":1}"#, "--msg-id", "cli1"],
    );
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let r1: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&r1), "{r1}");
    assert_eq!(r1["seq"], json!(1));

    // Retry same payload + id -> dup with same seq.
    let (st, stdout, _) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &["post", "board.build", r#"{"n":1}"#, "--msg-id", "cli1"],
    );
    assert_eq!(st, 0, "{stdout}");
    let r2: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(r2["seq"], json!(1));
    assert_eq!(r2["dup"], json!(true));

    // Conflicting payload -> exit 1 with msg_id conflict.
    let (st, _, stderr) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &["post", "board.build", r#"{"n":2}"#, "--msg-id", "cli1"],
    );
    assert_eq!(st, 1, "{stderr}");
    assert!(stderr.contains("msg_id conflict"), "{stderr}");

    // Absent --msg-id keeps old auto behavior: distinct seqs.
    let (st, stdout, _) =
        run_cli(&addr, "alice", "tok-alice", &["post", "board.build", r#"{"n":1}"#]);
    assert_eq!(st, 0, "{stdout}");
    let a1: Value = serde_json::from_str(stdout.trim()).unwrap();
    let (st, stdout, _) =
        run_cli(&addr, "alice", "tok-alice", &["post", "board.build", r#"{"n":1}"#]);
    assert_eq!(st, 0, "{stdout}");
    let a2: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_ne!(a1["seq"], a2["seq"]);
    assert!(a1.get("dup").is_none() && a2.get("dup").is_none());
    server.set_fixed_now(None);
}

// Frozen immutable CLI still works against the new broker (no breakage).
#[test]
#[ignore = "requires an explicitly supplied historical CLI via AGENT_BUS_COMPAT_CLI"]
fn frozen_cli_still_works_against_new_broker() {
    let frozen = std::env::var_os("AGENT_BUS_COMPAT_CLI")
        .map(std::path::PathBuf::from)
        .expect("set AGENT_BUS_COMPAT_CLI to a historical native CLI executable");
    assert!(frozen.is_absolute(), "historical CLI path must be absolute");
    let (addr, _wal, server) = start_handle("frozen-compat");
    server.set_fixed_now(Some(T0));
    let (host, port) = addr.rsplit_once(':').unwrap();
    let run = |args: &[&str]| {
        Command::new(&frozen)
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
            .expect("spawn frozen CLI")
    };
    // Old post (no --msg-id) still succeeds.
    let out = run(&["post", "board.build", r#"{"n":1}"#]);
    assert_eq!(out.status.code().unwrap(), 0, "stderr={}", String::from_utf8_lossy(&out.stderr));
    // Old show still drains.
    let out = run(&["show", "board.build", "--since-seq", "0", "--format", "json"]);
    assert_eq!(out.status.code().unwrap(), 0, "stderr={}", String::from_utf8_lossy(&out.stderr));
    // Old agents still works (ping was unsupported there; agents remains).
    let out = run(&["agents", "--format", "json"]);
    assert_eq!(out.status.code().unwrap(), 0, "stderr={}", String::from_utf8_lossy(&out.stderr));
    server.set_fixed_now(None);
}
