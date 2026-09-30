//! Independent token-admin review: durable issue/revoke/claim over live wire.
//!
//! Owner: muse (`native-token-admin-independent-review`, claim1383).
//! Target: builder-owned `tokens.rs` + `wire.rs` token ops + `agent-bus.rs`
//! CLI (`native-token-admin-persistence`, claim1343). This file never edits
//! production sources; it exercises them through disposable token files and
//! private broker instances only (temp dirs, ephemeral loopback ports).
//!
//! Desired-behavior gates (not today-only snapshots): each test pins the
//! contract from `docs/NATIVE_TOKEN_ADMIN.md` + legacy `broker.py` text
//! (issue/restart, revoke revalidation, claim exactly-once, persist
//! rollback-or-poison, malformed no-op, auth negatives, topic-rate
//! first-match order). Failures are preserved as fail-before-repair
//! evidence for builder/root; see the companion review doc.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use agent_bus::acl::TokenStore;
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn tmpdir(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "agent-bus-tokenrev-{}-{}-{}",
        name,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn write_tokens(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("tokens.json");
    std::fs::write(&path, text).unwrap();
    path
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

/// File-backed server on an ephemeral port. Returns the held handle (for
/// failpoints/poison), the addr, and the paths. The listener is bound
/// before spawn so connects never race the accept loop.
fn start_file_backed(name: &str, tokens_text: &str) -> (Server, String, PathBuf, PathBuf) {
    let dir = tmpdir(name);
    let tokens_path = write_tokens(&dir, tokens_text);
    let wal = dir.join("wal.log");
    let _ = std::fs::remove_file(&wal);
    let store = TokenStore::from_json_str(tokens_text).expect("fixture tokens valid");
    let server = Server::new(wal.clone(), store)
        .expect("fresh WAL starts clean")
        .with_tokens_path(tokens_path.clone());
    let held = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    (held, addr, tokens_path, wal)
}

fn hello_raw(addr: &str, agent: &str, token: &str) -> Value {
    let mut c = Client::raw(addr).unwrap();
    c.rpc(&json!({"op": "hello", "agent": agent, "token": token}))
        .unwrap()
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn err_str(v: &Value) -> String {
    v.get("error")
        .map(|e| match e {
            Value::String(s) => s.clone(),
            _ => e.to_string(),
        })
        .unwrap_or_default()
}

fn is_hex16(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn assert_token_shape(token: &str, agent: &str) {
    let prefix = format!("tok-{agent}-");
    assert!(
        token.starts_with(&prefix),
        "token {token:?} must start with {prefix:?}"
    );
    let hex = &token[prefix.len()..];
    assert!(is_hex16(hex), "token {token:?} must end with 16 hex chars");
}

const ADMIN_TOKENS: &str = r#"{
    "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
    "_meta_note": "review-meta-preserved"
}"#;

#[test]
fn issue_and_restart_durability() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("issue-durable", ADMIN_TOKENS);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();

    // Issue without TTL: no expiry, fixed defaults, fresh secret.
    let r = admin
        .rpc(&json!({"op": "token_issue", "agent": "alice"}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(r["agent"], json!("alice"));
    assert_eq!(r["exp"], json!(null));
    let tok = r["token"].as_str().unwrap().to_string();
    assert_token_shape(&tok, "alice");

    // File gained the entry, kept meta, stayed 0600.
    let text = read_text(&tokens_path);
    assert!(text.contains(&tok), "file must contain new token");
    assert!(text.contains("_meta_note"), "meta must survive rewrite");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&tokens_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "tokens file must stay 0600, got {mode:o}");
    }

    // New token authenticates and publishes over the live wire.
    let mut alice = Client::connect(&addr, "alice", &tok).unwrap();
    let p = alice
        .rpc(&json!({"op": "post", "topic": "board.x", "payload": {"n": 1}}))
        .unwrap();
    assert!(ok(&p), "{p}");

    // TTL issue: exp is finite and in the future.
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let rt = admin
        .rpc(&json!({"op": "token_issue", "agent": "bob", "ttl_s": 3600}))
        .unwrap();
    assert!(ok(&rt), "{rt}");
    let exp = rt["exp"].as_f64().expect("ttl issue must set exp");
    assert!(exp.is_finite(), "exp must be finite");
    assert!(
        exp > before && exp <= before + 3610.0,
        "exp {exp} must be ~now+3600 (before={before})"
    );

    // Restart durability: the file alone reloads both tokens (fresh WAL,
    // fresh server, no shared memory with the first).
    let file_text = read_text(&tokens_path);
    let dir2 = tmpdir("issue-restart");
    let wal2 = dir2.join("wal.log");
    let store2 = TokenStore::from_json_str(&file_text).expect("rewritten file reloads");
    assert_eq!(store2.len(), 3, "admin + alice + bob must reload");
    let server2 = Server::new(wal2, store2).expect("restart on fresh WAL ok");
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    std::thread::spawn(move || server2.serve(listener2));
    assert!(Client::connect(&addr2, "alice", &tok).is_ok());
    let bob_tok = rt["token"].as_str().unwrap();
    assert!(Client::connect(&addr2, "bob", bob_tok).is_ok());
    // Revoked/unknown stays refused after restart.
    assert_eq!(
        hello_raw(&addr2, "mallory", "tok-missing")["error"],
        json!("auth failed")
    );
}

#[test]
fn revoke_and_revalidation_clears_stale_auth() {
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-alice": {"agent": "alice", "publish": ["board.*"], "subscribe": ["board.*"]}
    }"#;
    let (_held, addr, tokens_path, _wal) = start_file_backed("revoke-reval", fixture);

    // Alice holds an already-authenticated connection.
    let mut alice = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let p0 = alice
        .rpc(&json!({"op": "post", "topic": "board.a", "payload": 1}))
        .unwrap();
    assert!(ok(&p0), "{p0}");

    // Admin revokes while Alice is connected.
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let rv = admin
        .rpc(&json!({"op": "token_revoke", "token": "tok-alice"}))
        .unwrap();
    assert_eq!(
        rv,
        json!({"ok": true, "revoked": true, "req_id": rv["req_id"]}),
        "{rv}"
    );
    assert!(!read_text(&tokens_path).contains("tok-alice"));

    // Stale connection must NOT silently retain creds: next authed op
    // fails with the hello string, ping reports authed:false.
    let p1 = alice
        .rpc(&json!({"op": "post", "topic": "board.a", "payload": 2}))
        .unwrap();
    assert_eq!(p1["error"], json!("auth failed"), "{p1}");
    let ping = alice.rpc(&json!({"op": "ping"})).unwrap();
    assert_eq!(ping["authed"], json!(false), "{ping}");
    assert_eq!(ping["ok"], json!(true));

    // Reconnect with the revoked token always fails.
    assert_eq!(
        hello_raw(&addr, "alice", "tok-alice")["error"],
        json!("auth failed")
    );

    // Unknown revoke is a safe replay (revoked:false, no error).
    let unk = admin
        .rpc(&json!({"op": "token_revoke", "token": "tok-does-not-exist"}))
        .unwrap();
    assert_eq!(unk["ok"], json!(true));
    assert_eq!(unk["revoked"], json!(false), "{unk}");
}

#[test]
fn claim_exactly_once_under_concurrent_callers() {
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-claim": {"agent": "bootstrap", "claim": "newcomer-*", "publish": ["*"], "subscribe": ["*"]}
    }"#;
    let (_held, addr, tokens_path, _wal) = start_file_backed("claim-race", fixture);

    // Four distinct claimants race for one wanted name.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let mut handles = Vec::new();
    for i in 1..=4 {
        let b = barrier.clone();
        let a = addr.clone();
        handles.push(std::thread::spawn(move || {
            let who = format!("newcomer-{i}");
            let mut c = Client::connect(&a, &who, "tok-claim").expect("claim hello ok");
            b.wait();
            c.rpc(&json!({"op": "token_claim", "agent": "race-winner"}))
                .expect("rpc ok")
        }));
    }
    let mut oks = 0;
    let mut takens = 0;
    let mut winner_tok = String::new();
    for h in handles {
        let r = h.join().expect("claimer thread ok");
        if ok(&r) {
            oks += 1;
            assert_eq!(r["agent"], json!("race-winner"));
            assert_eq!(r["exp"], json!(null));
            winner_tok = r["token"].as_str().unwrap().to_string();
            assert_token_shape(&winner_tok, "race-winner");
        } else {
            assert_eq!(r["error"], json!("name taken"), "{r}");
            takens += 1;
        }
    }
    assert_eq!(oks, 1, "exactly one concurrent claim must win");
    assert_eq!(takens, 3);

    // File holds exactly one entry for the wanted agent; winner works.
    let text = read_text(&tokens_path);
    let root: Value = serde_json::from_str(&text).unwrap();
    let n = root
        .as_object()
        .unwrap()
        .values()
        .filter(|v| v.get("agent") == Some(&json!("race-winner")))
        .count();
    assert_eq!(n, 1, "file must hold exactly one race-winner entry");
    assert!(Client::connect(&addr, "race-winner", &winner_tok).is_ok());

    // Second claim for the same name (serial) stays taken, even from a
    // fresh claimant within quota.
    let mut c5 = Client::connect(&addr, "newcomer-5", "tok-claim").unwrap();
    let r2 = c5
        .rpc(&json!({"op": "token_claim", "agent": "race-winner"}))
        .unwrap();
    assert_eq!(r2["error"], json!("name taken"), "{r2}");
}

#[test]
fn persistence_pre_rename_rollback_safe_retry_and_dir_fsync_poisons() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("persist-fail", ADMIN_TOKENS);
    let before = read_bytes(&tokens_path);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();

    // Pre-rename failpoints: memory/disk coherent, safe retry, no poison.
    for (mode, want) in [
        (
            agent_bus::tokens::TOKENS_FAIL_TMP_WRITE,
            "persist failed: tmp write",
        ),
        (
            agent_bus::tokens::TOKENS_FAIL_RENAME,
            "persist failed: rename",
        ),
    ] {
        _held.set_tokens_failpoint(mode);
        let r = admin
            .rpc(&json!({"op": "token_issue", "agent": "retry-me"}))
            .unwrap();
        assert_eq!(err_str(&r), want, "{r}");
        assert!(
            _held.token_poisoned().is_none(),
            "pre-rename must not poison"
        );
        assert_eq!(
            read_bytes(&tokens_path),
            before,
            "pre-rename failure must leave file untouched"
        );
    }
    _held.set_tokens_failpoint(agent_bus::tokens::TOKENS_FAIL_NONE);
    let retry = admin
        .rpc(&json!({"op": "token_issue", "agent": "retry-me"}))
        .unwrap();
    assert!(ok(&retry), "retry after rollback must succeed: {retry}");
    let mid = read_bytes(&tokens_path);
    assert_ne!(mid, before);

    // Post-rename dir-fsync: destination uncertain -> poison, further
    // mutations refuse, reads/auth stay available.
    _held.set_tokens_failpoint(agent_bus::tokens::TOKENS_FAIL_DIR_FSYNC);
    let poisoned = admin
        .rpc(&json!({"op": "token_issue", "agent": "uncertain"}))
        .unwrap();
    assert_eq!(
        err_str(&poisoned),
        "persist failed: dir fsync",
        "{poisoned}"
    );
    let reason = _held.token_poisoned().expect("dir-fsync must poison");
    assert!(reason.contains("dir fsync"), "{reason}");
    _held.set_tokens_failpoint(agent_bus::tokens::TOKENS_FAIL_NONE);

    let again = admin
        .rpc(&json!({"op": "token_issue", "agent": "another"}))
        .unwrap();
    assert_eq!(err_str(&again), "token store poisoned", "{again}");
    let rvr = admin
        .rpc(&json!({"op": "token_revoke", "token": "tok-admin"}))
        .unwrap();
    assert_eq!(err_str(&rvr), "token store poisoned", "{rvr}");

    // Reads/auth stay: existing tokens still hello, ping stays authed.
    assert!(hello_raw(&addr, "root", "tok-admin").get("ok") == Some(&json!(true)));
    let ping = admin.rpc(&json!({"op": "ping"})).unwrap();
    assert_eq!(ping["authed"], json!(true), "{ping}");
}

#[test]
fn malformed_inputs_cause_no_durable_change() {
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-alice": {"agent": "alice", "publish": ["board.*"], "subscribe": ["board.*"]},
        "tok-claim": {"agent": "bootstrap", "claim": "newcomer-*", "publish": ["*"], "subscribe": ["*"]}
    }"#;
    let (_held, addr, tokens_path, _wal) = start_file_backed("malformed-noop", fixture);
    let before = read_bytes(&tokens_path);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let mut claimer = Client::connect(&addr, "newcomer-1", "tok-claim").unwrap();

    // Issue negatives: names, ttl, claim smuggling, bad grants.
    let long = "a".repeat(33);
    let bad_issues: Vec<Value> = vec![
        json!({"op": "token_issue", "agent": ""}),
        json!({"op": "token_issue", "agent": "*"}),
        json!({"op": "token_issue", "agent": "a*b"}),
        json!({"op": "token_issue", "agent": long}),
        json!({"op": "token_issue"}),
        json!({"op": "token_issue", "agent": "x", "ttl_s": "2"}),
        json!({"op": "token_issue", "agent": "x", "ttl_s": -1}),
        json!({"op": "token_issue", "agent": "x", "ttl_s": true}),
        json!({"op": "token_issue", "agent": "x", "claim": "newcomer-*"}),
        json!({"op": "token_issue", "agent": "x", "publish": "board.*"}),
        json!({"op": "token_issue", "agent": "x", "topic_rates": [1]}),
    ];
    for req in &bad_issues {
        let r = admin.rpc(req).unwrap();
        assert!(
            r.get("error").is_some(),
            "must refuse malformed issue {req}: {r}"
        );
        assert!(!ok(&r));
    }

    // Revoke negatives: token field shape.
    for req in [
        json!({"op": "token_revoke"}),
        json!({"op": "token_revoke", "token": ""}),
        json!({"op": "token_revoke", "token": 42}),
        json!({"op": "token_revoke", "token": null}),
    ] {
        let r = admin.rpc(&req).unwrap();
        assert_eq!(r["error"], json!("bad token"), "{req} -> {r}");
    }

    // Claim negatives: name shape (quota/presence paths untouched).
    for req in [
        json!({"op": "token_claim", "agent": ""}),
        json!({"op": "token_claim", "agent": "*bad"}),
        json!({"op": "token_claim"}),
    ] {
        let r = claimer.rpc(&req).unwrap();
        assert!(r.get("error").is_some(), "{req} -> {r}");
    }

    assert_eq!(
        read_bytes(&tokens_path),
        before,
        "no malformed input may change the durable file"
    );
    // No phantom entries: file still holds exactly the 3 fixtures.
    let store = TokenStore::from_json_str(&read_text(&tokens_path)).unwrap();
    assert_eq!(store.len(), 3);
}

#[test]
fn admin_and_claim_authorization_negatives() {
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-alice": {"agent": "alice", "publish": ["board.*"], "subscribe": ["board.*"]},
        "tok-claim": {"agent": "bootstrap", "claim": "newcomer-*", "publish": ["*"], "subscribe": ["*"]}
    }"#;
    let (_held, addr, tokens_path, _wal) = start_file_backed("auth-neg", fixture);
    let before = read_bytes(&tokens_path);

    // Non-admin cannot issue/revoke.
    let mut alice = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for req in [
        json!({"op": "token_issue", "agent": "mallory"}),
        json!({"op": "token_revoke", "token": "tok-alice"}),
    ] {
        let r = alice.rpc(&req).unwrap();
        assert_eq!(r["error"], json!("admin required"), "{req} -> {r}");
    }

    // Non-claim holder cannot claim (admin has no claim pattern either).
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    for (who, c) in [("alice", &mut alice), ("admin", &mut admin)] {
        let r = c
            .rpc(&json!({"op": "token_claim", "agent": "someone"}))
            .unwrap();
        assert_eq!(r["error"], json!("claim token required"), "{who} -> {r}");
    }

    // Unauthenticated connections cannot reach token auth at all.
    let mut raw = Client::raw(&addr).unwrap();
    for req in [
        json!({"op": "token_issue", "agent": "x"}),
        json!({"op": "token_revoke", "token": "tok-alice"}),
        json!({"op": "token_claim", "agent": "x"}),
    ] {
        let r = raw.rpc(&req).unwrap();
        assert_eq!(
            r["error"],
            json!("auth required (send hello first)"),
            "{req} -> {r}"
        );
    }

    // Denials precede mutation: file untouched.
    assert_eq!(read_bytes(&tokens_path), before);

    // Open mode refuses durable token mutation explicitly.
    let dir = tmpdir("auth-open");
    let otokens = write_tokens(&dir, ADMIN_TOKENS);
    let owal = dir.join("wal.log");
    let ostore = TokenStore::from_json_str(ADMIN_TOKENS).unwrap();
    let open = Server::new(owal, ostore)
        .unwrap()
        .with_open_mode(true)
        .with_tokens_path(otokens);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let oaddr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || open.serve(listener));
    // Auth precedes open-mode: non-admin still gets admin required.
    let mut oc = Client::connect(&oaddr, "anyone", "anything").unwrap();
    let r0 = oc.rpc(&json!({"op": "token_issue", "agent": "x"})).unwrap();
    assert_eq!(r0["error"], json!("admin required"), "{r0}");
    // Admin in open mode (hello as "*") reaches the open-mode refusal.
    let mut oc_admin = Client::connect(&oaddr, "*", "anything").unwrap();
    let r = oc_admin
        .rpc(&json!({"op": "token_issue", "agent": "x"}))
        .unwrap();
    assert_eq!(r["error"], json!("unsupported in open mode"), "{r}");

    // Missing persistence path refuses post-auth.
    let dir2 = tmpdir("auth-nopath");
    let wal2 = dir2.join("wal.log");
    let store2 = TokenStore::from_json_str(ADMIN_TOKENS).unwrap();
    let nopersist = Server::new(wal2, store2).unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    std::thread::spawn(move || nopersist.serve(listener2));
    // Admin hello works (in-memory store), mutation refuses for no path.
    let mut ac = Client::connect(&addr2, "root", "tok-admin").unwrap();
    let r2 = ac.rpc(&json!({"op": "token_issue", "agent": "x"})).unwrap();
    assert_eq!(
        r2["error"],
        json!("token persistence not configured"),
        "{r2}"
    );
}

#[test]
fn topic_rate_first_match_order_survives_mutation_and_restart() {
    // File order is deliberately non-sorted: z.* before a.*, m.* before b.*.
    // Sorted order would be a,z / b,m; first-match must follow file order.
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-a": {"agent": "a", "publish": ["*"], "subscribe": ["*"],
                   "topic_rates": {"z.*": 1, "a.*": 10}},
        "tok-b": {"agent": "b", "publish": ["*"], "subscribe": ["*"],
                   "topic_rates": {"m.*": 5, "b.*": 7}}
    }"#;
    let (_held, addr, tokens_path, _wal) = start_file_backed("rate-order", fixture);

    fn rule_order(text: &str, token: &str) -> Vec<String> {
        TokenStore::from_json_str(text)
            .unwrap()
            .get(token)
            .unwrap()
            .rate_config()
            .rules
            .iter()
            .map(|r| r.pattern_raw.clone())
            .collect()
    }

    let before_text = read_text(&tokens_path);
    assert_eq!(rule_order(&before_text, "tok-a"), vec!["z.*", "a.*"]);
    assert_eq!(rule_order(&before_text, "tok-b"), vec!["m.*", "b.*"]);
    // First-match proof: a topic matching both rules selects the file-first.
    let store0 = TokenStore::from_json_str(&before_text).unwrap();
    // "a.x" matches only a.* here; use overlapping patterns via direct select:
    // z.* vs a.* are disjoint, so order is proven by rule position + persisted
    // text order below (overlapping e2e rate test lives in rate_wire.rs).
    assert_eq!(
        store0.get("tok-a").unwrap().rate_config().select("z.1"),
        Some(("z.*", 1.0))
    );

    // Unrelated mutation (new issue) must not reorder existing tokens.
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let r = admin
        .rpc(&json!({"op": "token_issue", "agent": "c"}))
        .unwrap();
    assert!(ok(&r), "{r}");
    let after_text = read_text(&tokens_path);
    assert_eq!(rule_order(&after_text, "tok-a"), vec!["z.*", "a.*"]);
    assert_eq!(rule_order(&after_text, "tok-b"), vec!["m.*", "b.*"]);
    // Text order preserved too (not sorted rewrite).
    let za = after_text.find("\"z.*\"").unwrap();
    let aa = after_text.find("\"a.*\"").unwrap();
    assert!(za < aa, "tok-a file order z.* before a.* must survive");
    let mm = after_text.find("\"m.*\"").unwrap();
    let bb = after_text.find("\"b.*\"").unwrap();
    assert!(mm < bb, "tok-b file order m.* before b.* must survive");

    // Restart reload keeps the same first-match order.
    let dir2 = tmpdir("rate-restart");
    let wal2 = dir2.join("wal.log");
    let store2 = TokenStore::from_json_str(&after_text).unwrap();
    let server2 = Server::new(wal2, store2).unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    std::thread::spawn(move || server2.serve(listener2));
    let mut a2 = Client::connect(&addr2, "a", "tok-a").unwrap();
    assert!(ok(&a2.rpc(&json!({"op": "ping"})).unwrap()));
    let reloaded = TokenStore::from_json_str(&after_text).unwrap();
    assert_eq!(
        reloaded
            .get("tok-a")
            .unwrap()
            .rate_config()
            .rules
            .iter()
            .map(|r| r.pattern_raw.as_str())
            .collect::<Vec<_>>(),
        vec!["z.*", "a.*"]
    );
}

#[test]
fn cli_token_roundtrip_against_private_broker() {
    // End-to-end native CLI path (same wire ops, real binary, env creds).
    let (_held, addr, tokens_path, _wal) = start_file_backed("cli-roundtrip", ADMIN_TOKENS);
    let bin = env!("CARGO_BIN_EXE_agent-bus").to_string();
    let (host, port) = addr.split_once(':').unwrap();

    fn run(
        bin: &str,
        host: &str,
        port: &str,
        agent: &str,
        token: &str,
        args: &[&str],
    ) -> (i32, String, String) {
        let out = std::process::Command::new(bin)
            .args(args)
            .env("AGENT_BUS_AGENT", agent)
            .env("AGENT_BUS_TOKEN", token)
            .env_remove("AGENT_BUS_SOCK")
            .env("AGENT_BUS_HOST", host)
            .env("AGENT_BUS_PORT", port)
            .output()
            .expect("cli runs");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    // token-issue via CLI prints reply JSON with the new secret on stdout.
    let (code, stdout, stderr) = run(
        &bin,
        host,
        port,
        "root",
        "tok-admin",
        &["token-issue", "cli-alice"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let reply: Value = serde_json::from_str(stdout.trim()).expect("stdout is reply JSON");
    assert!(ok(&reply), "{reply}");
    let tok = reply["token"].as_str().unwrap().to_string();
    assert_token_shape(&tok, "cli-alice");
    assert!(!stderr.contains(&tok), "secret must never hit stderr");

    // token-revoke via CLI reports revoked:true.
    let (code, stdout, _) = run(
        &bin,
        host,
        port,
        "root",
        "tok-admin",
        &["token-revoke", &tok],
    );
    assert_eq!(code, 0, "{stdout}");
    let rrv: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(rrv["revoked"], json!(true), "{rrv}");
    assert!(!read_text(&tokens_path).contains(&tok));

    // Usage errors exit 2 without touching the broker.
    let (code, _, stderr) = run(&bin, host, port, "root", "tok-admin", &["token-issue"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("FOR_AGENT"), "{stderr}");
}
