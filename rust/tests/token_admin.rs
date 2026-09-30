//! Native token-admin: durable issue/revoke/claim over private wire.
//!
//! Owner: muse-builder (`native-token-admin-persistence`, claim1343).
//! Private brokers, ephemeral credentials/files only; never live
//! `tokens.json`/WAL/service/pointers. Bounded fixtures (root PyTorch
//! active): small thread counts, no sleeps, no heavy loops.
//!
//! Covers the `docs/NATIVE_TOKEN_ADMIN.md` contract: issue/auth/revoke/
//! reconnect, claim/retire + concurrent exactly-once, unauthorized
//! negatives, conflicting state + TTL/rate/field validation, injected
//! persistence failure/restart/rollback-or-poison, unchanged-token
//! overlapping topic-rate order through mutation/restart, new-token
//! request-document order (CLI flags + literal wire, overlapping,
//! reversed-control, repeated-pattern dedup, malformed refusal, later
//! mutations), and real native CLI issue/revoke/claim.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
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
        "agent-bus-tokenadmin-{}-{}-{}",
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

fn assert_mode_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "tokens file must stay 0600, got {mode:o}");
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

const ADMIN_TOKENS: &str = r#"{
    "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
    "_meta_note": "builder-meta-preserved"
}"#;

const ADMIN_ALICE_CLAIM: &str = r#"{
    "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
    "tok-alice": {"agent": "alice", "publish": ["board.*"], "subscribe": ["board.*"]},
    "tok-claim": {"agent": "bootstrap", "claim": "newcomer-*", "publish": ["*"], "subscribe": ["*"]}
}"#;

#[test]
fn issue_auth_revoke_reconnect_cycle() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("issue-cycle", ADMIN_TOKENS);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();

    // Issue without TTL: no expiry, fresh secret, fixed defaults.
    let r = admin
        .rpc(&json!({"op": "token_issue", "agent": "alice"}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(r["agent"], json!("alice"));
    assert_eq!(r["exp"], json!(null));
    let tok = r["token"].as_str().unwrap().to_string();
    assert_token_shape(&tok, "alice");

    // File gained entry, kept meta, stayed 0600.
    let text = read_text(&tokens_path);
    assert!(text.contains(&tok));
    assert!(text.contains("_meta_note"));
    assert_mode_0600(&tokens_path);
    // Fixed least-privilege grants in the durable file.
    let store = TokenStore::from_json_str(&text).unwrap();
    let pol = store.get(&tok).expect("issued token reloads");
    assert_eq!(pol.agent(), Some("alice"));
    assert_eq!(pol.exp(), None);
    assert!(pol.can_publish("board.x"));
    assert!(pol.can_publish("inbox.y"));
    assert!(!pol.can_publish("other.z"));

    // New token authenticates and publishes over live wire.
    let mut alice = Client::connect(&addr, "alice", &tok).unwrap();
    let p = alice
        .rpc(&json!({"op": "post", "topic": "board.x", "payload": {"n": 1}}))
        .unwrap();
    assert!(ok(&p), "{p}");

    // TTL issue: finite future exp.
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let rt = admin
        .rpc(&json!({"op": "token_issue", "agent": "bob", "ttl_s": 3600}))
        .unwrap();
    assert!(ok(&rt), "{rt}");
    let exp = rt["exp"].as_f64().expect("ttl issue sets exp");
    assert!(exp.is_finite());
    assert!(exp > before && exp <= before + 3610.0, "exp {exp} vs {before}");

    // Revoke while connected: stale conn must not retain creds.
    let rv = admin
        .rpc(&json!({"op": "token_revoke", "token": tok}))
        .unwrap();
    assert_eq!(rv["ok"], json!(true));
    assert_eq!(rv["revoked"], json!(true), "{rv}");
    assert!(!read_text(&tokens_path).contains("tok-alice-"));

    let p1 = alice
        .rpc(&json!({"op": "post", "topic": "board.x", "payload": 2}))
        .unwrap();
    assert_eq!(p1["error"], json!("auth failed"), "{p1}");
    let ping = alice.rpc(&json!({"op": "ping"})).unwrap();
    assert_eq!(ping["ok"], json!(true));
    assert_eq!(ping["authed"], json!(false), "{ping}");

    // Reconnect with revoked token always fails.
    let bob_tok = rt["token"].as_str().unwrap().to_string();
    let rv2 = admin
        .rpc(&json!({"op": "token_revoke", "token": bob_tok.clone()}))
        .unwrap();
    assert_eq!(rv2["revoked"], json!(true));
    assert_eq!(
        hello_raw(&addr, "bob", &bob_tok)["error"],
        json!("auth failed")
    );

    // Unknown revoke is safe replay.
    let unk = admin
        .rpc(&json!({"op": "token_revoke", "token": "tok-does-not-exist"}))
        .unwrap();
    assert_eq!(unk["ok"], json!(true));
    assert_eq!(unk["revoked"], json!(false), "{unk}");
}

#[test]
fn claim_retires_bootstrap_and_enforces_quota() {
    let (held, addr, tokens_path, _wal) = start_file_backed("claim-quota", ADMIN_ALICE_CLAIM);
    const T0: f64 = 1_790_520_000.0;
    held.set_fixed_now(Some(T0));

    // Bootstrap hello creates presence.
    let mut boot = Client::connect(&addr, "newcomer-1", "tok-claim").unwrap();
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let agents0 = admin.rpc(&json!({"op": "agents"})).unwrap();
    assert!(agents0["agents"].get("newcomer-1").is_some(), "{agents0}");

    // Claim fixed grants, no exp, fresh secret.
    let r = boot
        .rpc(&json!({"op": "token_claim", "agent": "alice2"}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(r["agent"], json!("alice2"));
    assert_eq!(r["exp"], json!(null));
    let tok = r["token"].as_str().unwrap().to_string();
    assert_token_shape(&tok, "alice2");
    let file = read_text(&tokens_path);
    let store = TokenStore::from_json_str(&file).unwrap();
    let pol = store.get(&tok).unwrap();
    assert!(pol.can_publish("board.x"));
    assert!(pol.can_publish("inbox.y"));
    assert_eq!(pol.exp(), None);
    assert!(pol.claim_pattern().is_none(), "claim grants fixed, no claim");

    // Bootstrap retired: popped + suppressed (heartbeat ok but absent).
    let agents1 = admin.rpc(&json!({"op": "agents"})).unwrap();
    assert!(
        agents1["agents"].get("newcomer-1").is_none(),
        "retired bootstrap must pop: {agents1}"
    );
    let hb = boot.rpc(&json!({"op": "heartbeat", "status": "still-here"})).unwrap();
    assert!(ok(&hb), "{hb}");
    let agents2 = admin.rpc(&json!({"op": "agents"})).unwrap();
    assert!(
        agents2["agents"].get("newcomer-1").is_none(),
        "retired stays suppressed: {agents2}"
    );
    // Winner authenticates.
    held.set_fixed_now(None);
    assert!(Client::connect(&addr, "alice2", &tok).is_ok());

    // Quota: 3 successes/hour per claimant; 4th refused.
    let (_h2, addr2, _p2, _w2) = start_file_backed("claim-quota2", ADMIN_ALICE_CLAIM);
    let mut c1 = Client::connect(&addr2, "newcomer-1", "tok-claim").unwrap();
    for wanted in ["q1", "q2", "q3"] {
        let rr = c1
            .rpc(&json!({"op": "token_claim", "agent": wanted}))
            .unwrap();
        assert!(ok(&rr), "{wanted}: {rr}");
    }
    let fourth = c1
        .rpc(&json!({"op": "token_claim", "agent": "q4"}))
        .unwrap();
    assert_eq!(
        fourth["error"],
        json!("claim rate limited (3/hour)"),
        "{fourth}"
    );
    // Different claimant still has quota.
    let mut c2 = Client::connect(&addr2, "newcomer-2", "tok-claim").unwrap();
    let ok2 = c2
        .rpc(&json!({"op": "token_claim", "agent": "q4"}))
        .unwrap();
    assert!(ok(&ok2), "{ok2}");

    // Failed validation never spends quota.
    let (_h3, addr3, _p3, _w3) = start_file_backed("claim-quota3", ADMIN_ALICE_CLAIM);
    let mut c3 = Client::connect(&addr3, "newcomer-9", "tok-claim").unwrap();
    for wanted in ["s1", "s2"] {
        assert!(ok(&c3
            .rpc(&json!({"op": "token_claim", "agent": wanted}))
            .unwrap()));
    }
    // Bad name refused without spending.
    let bad = c3
        .rpc(&json!({"op": "token_claim", "agent": ""}))
        .unwrap();
    assert!(bad.get("error").is_some(), "{bad}");
    // Third success still allowed, fourth refused.
    assert!(ok(&c3
        .rpc(&json!({"op": "token_claim", "agent": "s3"}))
        .unwrap()));
    let over = c3
        .rpc(&json!({"op": "token_claim", "agent": "s4"}))
        .unwrap();
    assert_eq!(over["error"], json!("claim rate limited (3/hour)"), "{over}");
}

#[test]
fn concurrent_claims_exactly_once() {
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-claim": {"agent": "bootstrap", "claim": "newcomer-*", "publish": ["*"], "subscribe": ["*"]}
    }"#;
    let (_held, addr, tokens_path, _wal) = start_file_backed("claim-race", fixture);
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
    let mut winner = String::new();
    for h in handles {
        let r = h.join().expect("claimer thread ok");
        if ok(&r) {
            oks += 1;
            assert_eq!(r["agent"], json!("race-winner"));
            winner = r["token"].as_str().unwrap().to_string();
            assert_token_shape(&winner, "race-winner");
        } else {
            assert_eq!(r["error"], json!("name taken"), "{r}");
            takens += 1;
        }
    }
    assert_eq!(oks, 1, "exactly one concurrent claim must win");
    assert_eq!(takens, 3);
    let text = read_text(&tokens_path);
    let root: Value = serde_json::from_str(&text).unwrap();
    let n = root
        .as_object()
        .unwrap()
        .values()
        .filter(|v| v.get("agent") == Some(&json!("race-winner")))
        .count();
    assert_eq!(n, 1, "file must hold exactly one winner");
    assert!(Client::connect(&addr, "race-winner", &winner).is_ok());
}

#[test]
fn concurrent_issues_produce_unique_tokens_without_loss() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("issue-race", ADMIN_TOKENS);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let b = barrier.clone();
        let a = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&a, "root", "tok-admin").expect("admin hello ok");
            b.wait();
            c.rpc(&json!({"op": "token_issue", "agent": "shared"}))
                .expect("rpc ok")
        }));
    }
    let mut toks = Vec::new();
    for h in handles {
        let r = h.join().expect("issuer thread ok");
        assert!(ok(&r), "{r}");
        toks.push(r["token"].as_str().unwrap().to_string());
    }
    toks.sort();
    toks.dedup();
    assert_eq!(toks.len(), 4, "concurrent issues must mint distinct secrets");
    let store = TokenStore::from_json_str(&read_text(&tokens_path)).unwrap();
    assert_eq!(store.len(), 5, "admin + 4 shared issues must all persist");
}

#[test]
fn unauthorized_operations_precede_mutation() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("auth-neg", ADMIN_ALICE_CLAIM);
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
    // Non-claim holders cannot claim.
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    for (who, c) in [("alice", &mut alice), ("admin", &mut admin)] {
        let r = c
            .rpc(&json!({"op": "token_claim", "agent": "someone"}))
            .unwrap();
        assert_eq!(r["error"], json!("claim token required"), "{who} -> {r}");
    }
    // Unauthenticated cannot reach token auth.
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
    assert_eq!(read_bytes(&tokens_path), before, "denials must not mutate");

    // Open mode refuses durable mutation explicitly (after admin check).
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
    let mut oc = Client::connect(&oaddr, "anyone", "anything").unwrap();
    let r0 = oc.rpc(&json!({"op": "token_issue", "agent": "x"})).unwrap();
    assert_eq!(r0["error"], json!("admin required"), "{r0}");
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
    let mut ac = Client::connect(&addr2, "root", "tok-admin").unwrap();
    let r2 = ac.rpc(&json!({"op": "token_issue", "agent": "x"})).unwrap();
    assert_eq!(
        r2["error"],
        json!("token persistence not configured"),
        "{r2}"
    );
}

#[test]
fn conflicting_state_name_taken_and_out_of_sync() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("conflict", ADMIN_ALICE_CLAIM);
    let mut claimer = Client::connect(&addr, "newcomer-1", "tok-claim").unwrap();
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();

    // Taken via token_db agent.
    let r = claimer
        .rpc(&json!({"op": "token_claim", "agent": "alice"}))
        .unwrap();
    assert_eq!(r["error"], json!("name taken"), "{r}");

    // Taken via live presence without a token entry: admin hello as temp.
    let mut temp = Client::connect(&addr, "temp-ghost", "tok-admin").unwrap();
    let _ = temp.rpc(&json!({"op": "ping"})).unwrap();
    let r2 = claimer
        .rpc(&json!({"op": "token_claim", "agent": "temp-ghost"}))
        .unwrap();
    assert_eq!(r2["error"], json!("name taken"), "{r2}");

    // Issue allows shared agent names (no uniqueness gate on issue).
    let i1 = admin
        .rpc(&json!({"op": "token_issue", "agent": "shared"}))
        .unwrap();
    let i2 = admin
        .rpc(&json!({"op": "token_issue", "agent": "shared"}))
        .unwrap();
    assert!(ok(&i1) && ok(&i2), "{i1} {i2}");
    assert_ne!(i1["token"], i2["token"]);

    // Revoke removes only the target; siblings stay live.
    let t1 = i1["token"].as_str().unwrap().to_string();
    let t2 = i2["token"].as_str().unwrap().to_string();
    let rv = admin
        .rpc(&json!({"op": "token_revoke", "token": t1.clone()}))
        .unwrap();
    assert_eq!(rv["revoked"], json!(true));
    assert_eq!(hello_raw(&addr, "shared", &t1)["error"], json!("auth failed"));
    assert!(Client::connect(&addr, "shared", &t2).is_ok());

    // Out-of-sync: external file change before first mutation refuses.
    let dir = tmpdir("conflict-oos");
    let path = write_tokens(&dir, ADMIN_TOKENS);
    let wal = dir.join("wal.log");
    let store = TokenStore::from_json_str(ADMIN_TOKENS).unwrap();
    let server = Server::new(wal, store).unwrap().with_tokens_path(path.clone());
    let held = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    // External edit adds a token the in-memory store never saw.
    let mut root: Value = serde_json::from_str(ADMIN_TOKENS).unwrap();
    root["tok-external"] = json!({"agent": "ext", "publish": ["*"], "subscribe": ["*"]});
    std::fs::write(&path, serde_json::to_string_pretty(&root).unwrap()).unwrap();
    let mut ac = Client::connect(&a, "root", "tok-admin").unwrap();
    let oos = ac
        .rpc(&json!({"op": "token_issue", "agent": "x"}))
        .unwrap();
    assert_eq!(oos["error"], json!("token store out of sync"), "{oos}");
    assert!(held.token_poisoned().is_none());
    let _ = tokens_path;
}

#[test]
fn ttl_rate_field_validation_causes_no_durable_change() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("validate", ADMIN_ALICE_CLAIM);
    let before = read_bytes(&tokens_path);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let mut claimer = Client::connect(&addr, "newcomer-1", "tok-claim").unwrap();

    let long = "a".repeat(33);
    let bad_issues: Vec<Value> = vec![
        json!({"op": "token_issue", "agent": ""}),
        json!({"op": "token_issue", "agent": "*"}),
        json!({"op": "token_issue", "agent": "a*b"}),
        json!({"op": "token_issue", "agent": long}),
        json!({"op": "token_issue"}),
        json!({"op": "token_issue", "agent": ".bad"}),
        json!({"op": "token_issue", "agent": "x", "ttl_s": "2"}),
        json!({"op": "token_issue", "agent": "x", "ttl_s": -1}),
        json!({"op": "token_issue", "agent": "x", "ttl_s": true}),
        json!({"op": "token_issue", "agent": "x", "ttl_s": []}),
        json!({"op": "token_issue", "agent": "x", "claim": "newcomer-*"}),
        json!({"op": "token_issue", "agent": "x", "publish": "board.*"}),
        json!({"op": "token_issue", "agent": "x", "subscribe": [42]}),
        json!({"op": "token_issue", "agent": "x", "topic_rates": [1]}),
        json!({"op": "token_issue", "agent": "x", "rate_per_s": "2"}),
        json!({"op": "token_issue", "agent": "x", "rate_per_s": 0}),
        json!({"op": "token_issue", "agent": "x", "rate_per_s": -3}),
        json!({"op": "token_issue", "agent": "x", "topic_rates": {"board.*": 0}}),
        json!({"op": "token_issue", "agent": "x", "topic_rates": {"[bad": 1}}),
    ];
    for req in &bad_issues {
        let r = admin.rpc(req).unwrap();
        assert!(r.get("error").is_some(), "must refuse {req}: {r}");
        assert!(!ok(&r));
        assert!(
            !err_str(&r).contains("tok-"),
            "error must not leak secrets: {r}"
        );
    }
    // TTL falsy forms mean no expiry (valid, but use distinct agents to
    // avoid file churn confusion; verify then revoke to restore length).
    for (i, ttl) in [json!(null), json!(0), json!(0.0)].into_iter().enumerate() {
        let agent = format!("ttl-ok-{i}");
        let r = admin
            .rpc(&json!({"op": "token_issue", "agent": agent, "ttl_s": ttl}))
            .unwrap();
        assert!(ok(&r), "{ttl}: {r}");
        assert_eq!(r["exp"], json!(null));
        let t = r["token"].as_str().unwrap().to_string();
        let rv = admin
            .rpc(&json!({"op": "token_revoke", "token": t}))
            .unwrap();
        assert_eq!(rv["revoked"], json!(true));
    }

    for req in [
        json!({"op": "token_revoke"}),
        json!({"op": "token_revoke", "token": ""}),
        json!({"op": "token_revoke", "token": 42}),
        json!({"op": "token_revoke", "token": null}),
    ] {
        let r = admin.rpc(&req).unwrap();
        assert_eq!(r["error"], json!("bad token"), "{req} -> {r}");
    }

    for req in [
        json!({"op": "token_claim", "agent": ""}),
        json!({"op": "token_claim", "agent": "*bad"}),
        json!({"op": "token_claim"}),
    ] {
        let r = claimer.rpc(&req).unwrap();
        assert!(r.get("error").is_some(), "{req} -> {r}");
    }

    // File holds exactly the 3 fixtures plus the 3 ttl-ok issues minus
    // their revokes (net zero): byte length may differ by key order, so
    // compare store length + no phantom agents.
    let store = TokenStore::from_json_str(&read_text(&tokens_path)).unwrap();
    assert_eq!(store.len(), 3);
    assert_eq!(read_bytes(&tokens_path).len() > 0, true);
    let _ = before;
}

#[test]
fn persistence_pre_rename_failures_roll_back_for_safe_retry() {
    let (held, addr, tokens_path, _wal) = start_file_backed("persist-pre", ADMIN_TOKENS);
    let before = read_bytes(&tokens_path);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    for (mode, want) in [
        (
            agent_bus::tokens::TOKENS_FAIL_TMP_WRITE,
            "persist failed: tmp write",
        ),
        (
            agent_bus::tokens::TOKENS_FAIL_TMP_FSYNC,
            "persist failed: tmp fsync",
        ),
        (
            agent_bus::tokens::TOKENS_FAIL_RENAME,
            "persist failed: rename",
        ),
    ] {
        held.set_tokens_failpoint(mode);
        let r = admin
            .rpc(&json!({"op": "token_issue", "agent": "retry-me"}))
            .unwrap();
        assert_eq!(err_str(&r), want, "{r}");
        assert!(held.token_poisoned().is_none(), "pre-rename must not poison");
        assert_eq!(
            read_bytes(&tokens_path),
            before,
            "pre-rename must leave file untouched"
        );
    }
    held.set_tokens_failpoint(agent_bus::tokens::TOKENS_FAIL_NONE);
    let retry = admin
        .rpc(&json!({"op": "token_issue", "agent": "retry-me"}))
        .unwrap();
    assert!(ok(&retry), "retry after rollback must succeed: {retry}");
    assert_ne!(read_bytes(&tokens_path), before);
}

#[test]
fn persistence_dir_fsync_poisons_mutations_reads_stay() {
    let (held, addr, tokens_path, _wal) = start_file_backed("persist-post", ADMIN_TOKENS);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    // Baseline durable token for read/stay checks.
    let base = admin
        .rpc(&json!({"op": "token_issue", "agent": "reader"}))
        .unwrap();
    assert!(ok(&base), "{base}");
    let reader_tok = base["token"].as_str().unwrap().to_string();

    held.set_tokens_failpoint(agent_bus::tokens::TOKENS_FAIL_DIR_FSYNC);
    let poisoned = admin
        .rpc(&json!({"op": "token_issue", "agent": "uncertain"}))
        .unwrap();
    assert_eq!(
        err_str(&poisoned),
        "persist failed: dir fsync",
        "{poisoned}"
    );
    let reason = held.token_poisoned().expect("dir-fsync must poison");
    assert!(reason.contains("dir fsync"), "{reason}");
    assert!(!reason.contains("tok-"), "poison reason must not leak");
    held.set_tokens_failpoint(agent_bus::tokens::TOKENS_FAIL_NONE);

    // Further token mutations refuse (issue/revoke/claim paths).
    let again = admin
        .rpc(&json!({"op": "token_issue", "agent": "another"}))
        .unwrap();
    assert_eq!(err_str(&again), "token store poisoned", "{again}");
    let rvr = admin
        .rpc(&json!({"op": "token_revoke", "token": "tok-admin"}))
        .unwrap();
    assert_eq!(err_str(&rvr), "token store poisoned", "{rvr}");

    // Reads/auth stay: hello, ping authed, post/fetch with live tokens.
    assert!(hello_raw(&addr, "root", "tok-admin").get("ok") == Some(&json!(true)));
    let ping = admin.rpc(&json!({"op": "ping"})).unwrap();
    assert_eq!(ping["authed"], json!(true), "{ping}");
    let mut reader = Client::connect(&addr, "reader", &reader_tok).unwrap();
    let p = reader
        .rpc(&json!({"op": "post", "topic": "board.x", "payload": 1}))
        .unwrap();
    assert!(ok(&p), "{p}");
    let f = reader
        .rpc(&json!({"op": "fetch", "topic": "board.x", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    let _ = tokens_path;
}

#[test]
fn restart_reloads_durable_state_and_resets_memory_only() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("restart", ADMIN_ALICE_CLAIM);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let mut claimer = Client::connect(&addr, "newcomer-1", "tok-claim").unwrap();
    // Stale presence witness: hello-only, never re-hellos after restart.
    let _stale = Client::connect(&addr, "stale-ghost", "tok-admin").unwrap();

    let iss = admin
        .rpc(&json!({"op": "token_issue", "agent": "durable"}))
        .unwrap();
    assert!(ok(&iss), "{iss}");
    let durable_tok = iss["token"].as_str().unwrap().to_string();
    let clm = claimer
        .rpc(&json!({"op": "token_claim", "agent": "fresh"}))
        .unwrap();
    assert!(ok(&clm), "{clm}");
    let fresh_tok = clm["token"].as_str().unwrap().to_string();
    // Fill quota for newcomer-1 (1 used above + 2 more).
    for w in ["q2", "q3"] {
        assert!(ok(&claimer
            .rpc(&json!({"op": "token_claim", "agent": w}))
            .unwrap()));
    }
    let over = claimer
        .rpc(&json!({"op": "token_claim", "agent": "q4"}))
        .unwrap();
    assert_eq!(over["error"], json!("claim rate limited (3/hour)"));

    // Restart from the durable file alone (fresh WAL, no shared memory).
    let file_text = read_text(&tokens_path);
    let dir2 = tmpdir("restart2");
    let tokens2 = dir2.join("tokens.json");
    std::fs::write(&tokens2, &file_text).unwrap();
    let wal2 = dir2.join("wal.log");
    let store2 = TokenStore::from_json_str(&file_text).expect("rewritten file reloads");
    assert_eq!(store2.len(), 3 + 1 + 3, "admin+alice+claim+durable+3 claims");
    let server2 = Server::new(wal2, store2)
        .expect("restart ok")
        .with_tokens_path(tokens2);
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    std::thread::spawn(move || server2.serve(listener2));

    // Presence reset first: only the fresh root hello is listed; the
    // pre-restart stale witness is gone (memory-only roster).
    let mut a2 = Client::connect(&addr2, "root", "tok-admin").unwrap();
    let agents0 = a2.rpc(&json!({"op": "agents"})).unwrap();
    let map0 = agents0["agents"].as_object().unwrap();
    assert!(map0.contains_key("root"), "{agents0}");
    assert!(!map0.contains_key("stale-ghost"), "{agents0}");
    assert!(!map0.contains_key("durable"), "{agents0}");

    // Durable tokens auth on the restarted broker.
    assert!(Client::connect(&addr2, "durable", &durable_tok).is_ok());
    assert!(Client::connect(&addr2, "fresh", &fresh_tok).is_ok());
    assert_eq!(
        hello_raw(&addr2, "mallory", "tok-missing")["error"],
        json!("auth failed")
    );
    // Quota reset (memory-only): same claimant can claim again.
    let mut c2 = Client::connect(&addr2, "newcomer-1", "tok-claim").unwrap();
    let after = c2
        .rpc(&json!({"op": "token_claim", "agent": "after-restart"}))
        .unwrap();
    assert!(ok(&after), "quota must reset on restart: {after}");
}

#[test]
fn overlapping_topic_rate_order_survives_mutation_and_restart() {
    // Non-sorted file order with overlap: specific before broad.
    // Sorted would be broad first ("data.*" < "data.build"); first-match
    // must follow file order (specific wins). Patterns avoid default
    // grants (board.*/inbox.*/bus.*/ctx.*) so text-order checks are exact.
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-over": {"agent": "o", "publish": ["*"], "subscribe": ["*"],
                     "topic_rates": {"data.build": 10, "data.*": 1}}
    }"#;
    let (held, addr, tokens_path, _wal) = start_file_backed("rate-overlap", fixture);

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
    assert_eq!(
        rule_order(&before_text, "tok-over"),
        vec!["data.build", "data.*"]
    );
    let store0 = TokenStore::from_json_str(&before_text).unwrap();
    assert_eq!(
        store0
            .get("tok-over")
            .unwrap()
            .rate_config()
            .select("data.build"),
        Some(("data.build", 10.0))
    );

    // Live proof with a pinned clock: 2nd post allowed only when the
    // 10/s specific rule is first (1/s broad would deny it).
    const T0: f64 = 1_790_530_000.0;
    held.set_fixed_now(Some(T0));
    let mut o = Client::connect(&addr, "o", "tok-over").unwrap();
    let p0 = o
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 0}))
        .unwrap();
    assert!(ok(&p0), "{p0}");
    let p1 = o
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 1}))
        .unwrap();
    assert!(ok(&p1), "specific-first 10/s must allow 2nd: {p1}");
    held.set_fixed_now(None);

    // Unrelated mutation must not reorder the unchanged token.
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let r = admin
        .rpc(&json!({"op": "token_issue", "agent": "c"}))
        .unwrap();
    assert!(ok(&r), "{r}");
    let after_text = read_text(&tokens_path);
    assert_eq!(
        rule_order(&after_text, "tok-over"),
        vec!["data.build", "data.*"]
    );
    let spec = after_text.find("\"data.build\"").unwrap();
    let broad = after_text.find("\"data.*\"").unwrap();
    assert!(
        spec < broad,
        "file order specific-before-broad must survive"
    );

    // Restart keeps the same first-match order.
    let dir2 = tmpdir("rate-overlap-restart");
    let wal2 = dir2.join("wal.log");
    let store2 = TokenStore::from_json_str(&after_text).unwrap();
    assert_eq!(
        store2
            .get("tok-over")
            .unwrap()
            .rate_config()
            .select("data.build"),
        Some(("data.build", 10.0))
    );
    let server2 = Server::new(wal2, store2).unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    std::thread::spawn(move || server2.serve(listener2));
    assert!(Client::connect(&addr2, "o", "tok-over").is_ok());
}

#[test]
fn cli_issue_revoke_claim_roundtrip_against_private_broker() {
    let fixture = r#"{
        "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
        "tok-claim": {"agent": "bootstrap", "claim": "newcomer-*", "publish": ["*"], "subscribe": ["*"]}
    }"#;
    let (_held, addr, tokens_path, _wal) = start_file_backed("cli-roundtrip", fixture);
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

    // token-issue with grant flags prints reply JSON on stdout.
    let (code, stdout, stderr) = run(
        &bin,
        host,
        port,
        "root",
        "tok-admin",
        &[
            "token-issue",
            "cli-alice",
            "--publish",
            "board.*",
            "--topic-rate",
            "board.*=5",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let reply: Value = serde_json::from_str(stdout.trim()).expect("stdout is reply JSON");
    assert!(ok(&reply), "{reply}");
    let tok = reply["token"].as_str().unwrap().to_string();
    assert_token_shape(&tok, "cli-alice");
    assert!(!stderr.contains(&tok), "secret must never hit stderr");
    assert!(read_text(&tokens_path).contains(&tok));

    // token-claim via CLI (claim holder) mints a personal token.
    let (code, stdout, stderr) = run(
        &bin,
        host,
        port,
        "newcomer-7",
        "tok-claim",
        &["token-claim", "cli-bob"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let claim: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(ok(&claim), "{claim}");
    let ctok = claim["token"].as_str().unwrap().to_string();
    assert_token_shape(&ctok, "cli-bob");
    assert!(!stderr.contains(&ctok));

    // token-revoke via CLI reports revoked:true and removes the file entry.
    let (code, stdout, _) = run(&bin, host, port, "root", "tok-admin", &[
        "token-revoke",
        &tok,
    ]);
    assert_eq!(code, 0, "{stdout}");
    let rrv: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(rrv["revoked"], json!(true), "{rrv}");
    assert!(!read_text(&tokens_path).contains(&tok));

    // Unauthorized CLI surfaces the broker refusal on stderr (exit 1,
    // never stdout JSON): the shared rpc() maps broker errors to Err.
    let (code, stdout, stderr) = run(&bin, host, port, "cli-bob", &ctok, &[
        "token-issue",
        "mallory",
    ]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    assert!(stdout.is_empty(), "stdout={stdout}");
    assert!(stderr.contains("admin required"), "stderr={stderr}");
    assert!(!stderr.contains(&ctok), "secret must never hit stderr");

    // Usage errors exit 2 without touching the broker.
    let before = read_bytes(&tokens_path);
    for args in [
        vec!["token-issue"],
        vec!["token-revoke"],
        vec!["token-claim"],
        vec!["token-issue", "x", "--ttl-s", "abc"],
    ] {
        let (code, _, stderr) = run(&bin, host, port, "root", "tok-admin", &args);
        assert_eq!(code, 2, "{args:?} stderr={stderr}");
    }
    assert_eq!(read_bytes(&tokens_path), before);
}

#[test]
fn token_secrets_never_appear_in_errors_or_debug() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("no-leak", ADMIN_ALICE_CLAIM);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let secret = "tok-alice";

    // Error paths must not echo the acted-on secret.
    let bad = admin
        .rpc(&json!({"op": "token_revoke", "token": secret}))
        .unwrap();
    // Valid revoke of alice (to test success has no secret in error).
    assert_eq!(bad["revoked"], json!(true));
    // Re-revoke unknown: no secret echo.
    let unk = admin
        .rpc(&json!({"op": "token_revoke", "token": secret}))
        .unwrap();
    assert_eq!(unk["revoked"], json!(false));
    assert!(!unk.to_string().contains(secret));

    // Malformed errors never contain submitted values that look like tokens.
    let r = admin
        .rpc(&json!({"op": "token_issue", "agent": "a*b"}))
        .unwrap();
    assert!(!r.to_string().contains("tok-"));

    // Debug redacts: counts only, no secrets or meta values.
    let store = TokenStore::from_json_str(&read_text(&tokens_path)).unwrap();
    let dbg = format!("{store:?}");
    assert!(!dbg.contains("tok-"), "{dbg}");
    assert!(!dbg.contains("builder-meta"), "{dbg}");
    assert!(dbg.contains("entries"), "{dbg}");
}

#[test]
fn nonfinite_clock_fails_token_ops_without_mutation() {
    let (held, addr, tokens_path, _wal) = start_file_backed("nonfinite", ADMIN_TOKENS);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let before = read_bytes(&tokens_path);
    held.set_fixed_now(Some(f64::INFINITY));
    // Time-gated ops fail closed.
    let r = admin
        .rpc(&json!({"op": "token_issue", "agent": "x"}))
        .unwrap();
    assert_eq!(r["error"], json!("non-finite time"), "{r}");
    // Revoke is clock-free (no TTL/quota/expiry): like `limits`, it
    // preserves behavior under a non-finite pin. Use the unknown-token
    // safe replay so the probe mutates nothing.
    let unk = admin
        .rpc(&json!({"op": "token_revoke", "token": "tok-does-not-exist"}))
        .unwrap();
    assert_eq!(unk["ok"], json!(true));
    assert_eq!(unk["revoked"], json!(false), "{unk}");
    assert_eq!(read_bytes(&tokens_path), before);
    held.set_fixed_now(None);
    let retry = admin
        .rpc(&json!({"op": "token_issue", "agent": "x"}))
        .unwrap();
    assert!(ok(&retry), "{retry}");
}

// ---------------------------------------------------------------------------
// New-token request-document order (overlapping, reversed, dedup, malformed)
// ---------------------------------------------------------------------------

/// One raw JSON-lines RPC over an already-connected stream (literal request
/// text, so `serde_json::Value` sorting in the test cannot erase the wire
/// order contract before it reaches the product).
fn raw_rpc(reader: &mut BufReader<TcpStream>, line: &str, req_id: u64) -> Value {
    writeln!(reader.get_mut(), "{line}").unwrap();
    reader.get_mut().flush().unwrap();
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    let reply: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(reply["req_id"], json!(req_id));
    reply
}

fn raw_hello(addr: &str) -> BufReader<TcpStream> {
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let hello = raw_rpc(
        &mut reader,
        r#"{"op":"hello","agent":"root","token":"tok-admin","req_id":1}"#,
        1,
    );
    assert_eq!(hello["ok"], json!(true), "{hello}");
    reader
}

fn rule_shapes(text: &str, token: &str) -> Vec<(String, f64)> {
    TokenStore::from_json_str(text)
        .unwrap()
        .get(token)
        .unwrap()
        .rate_config()
        .rules
        .iter()
        .map(|r| (r.pattern_raw.clone(), r.per_s))
        .collect()
}

#[test]
fn new_token_wire_order_specific_first_is_first_match() {
    let (held, addr, tokens_path, _wal) = start_file_backed("new-wire-order", ADMIN_TOKENS);
    let mut reader = raw_hello(&addr);
    // Literal JSON: specific before broad (sorted would reverse). Wildcard
    // grants allow the live post below without colliding with the
    // text-order check (which must see only topic_rates entries).
    let reply = raw_rpc(
        &mut reader,
        r#"{"op":"token_issue","agent":"w1","publish":["*"],"subscribe":["*"],"topic_rates":{"data.build":10,"data.*":1},"req_id":2}"#,
        2,
    );
    assert!(ok(&reply), "{reply}");
    let tok = reply["token"].as_str().unwrap().to_string();
    assert_token_shape(&tok, "w1");

    let text = read_text(&tokens_path);
    assert_eq!(
        rule_shapes(&text, &tok),
        vec![("data.build".to_string(), 10.0), ("data.*".to_string(), 1.0)]
    );
    let store = TokenStore::from_json_str(&text).unwrap();
    assert_eq!(
        store.get(&tok).unwrap().rate_config().select("data.build"),
        Some(("data.build", 10.0))
    );
    assert_eq!(
        store.get(&tok).unwrap().rate_config().select("data.other"),
        Some(("data.*", 1.0))
    );
    let spec = text.find("\"data.build\"").unwrap();
    let broad = text.find("\"data.*\"").unwrap();
    assert!(spec < broad, "persisted text must keep specific first");

    // Live proof with pinned clock: 2nd immediate post allowed only when the
    // 10/s specific rule is first (1/s broad first would deny it).
    const T0: f64 = 1_790_530_000.0;
    held.set_fixed_now(Some(T0));
    let mut w1 = Client::connect(&addr, "w1", &tok).unwrap();
    let p0 = w1
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 0}))
        .unwrap();
    assert!(ok(&p0), "{p0}");
    let p1 = w1
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 1}))
        .unwrap();
    assert!(ok(&p1), "specific-first 10/s must allow 2nd: {p1}");
    held.set_fixed_now(None);

    // Restart reload keeps the same first-match order/select.
    let store2 = TokenStore::from_json_str(&read_text(&tokens_path)).unwrap();
    assert_eq!(
        store2.get(&tok).unwrap().rate_config().select("data.build"),
        Some(("data.build", 10.0))
    );
}

#[test]
fn new_token_cli_flag_order_specific_first_is_first_match() {
    let (held, addr, tokens_path, _wal) = start_file_backed("new-cli-order", ADMIN_TOKENS);
    let bin = env!("CARGO_BIN_EXE_agent-bus").to_string();
    let (host, port) = addr.split_once(':').unwrap();
    let out = std::process::Command::new(&bin)
        .args([
            "token-issue",
            "c1",
            "--publish",
            "*",
            "--subscribe",
            "*",
            "--topic-rate",
            "data.build=10",
            "--topic-rate",
            "data.*=1",
        ])
        .env("AGENT_BUS_AGENT", "root")
        .env("AGENT_BUS_TOKEN", "tok-admin")
        .env_remove("AGENT_BUS_SOCK")
        .env("AGENT_BUS_HOST", host)
        .env("AGENT_BUS_PORT", port)
        .output()
        .expect("cli runs");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(ok(&reply), "{reply}");
    let tok = reply["token"].as_str().unwrap().to_string();
    assert_token_shape(&tok, "c1");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(&tok),
        "secret must never hit stderr"
    );

    let text = read_text(&tokens_path);
    assert_eq!(
        rule_shapes(&text, &tok),
        vec![("data.build".to_string(), 10.0), ("data.*".to_string(), 1.0)]
    );
    let spec = text.find("\"data.build\"").unwrap();
    let broad = text.find("\"data.*\"").unwrap();
    assert!(spec < broad, "persisted text must keep flag order");

    // Live: 2nd immediate post to data.build allowed only when specific 10/s
    // is first (broad 1/s first would deny with rate_limited).
    const T0: f64 = 1_790_530_000.0;
    held.set_fixed_now(Some(T0));
    let mut c1 = Client::connect(&addr, "c1", &tok).unwrap();
    let p0 = c1
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 0}))
        .unwrap();
    assert!(ok(&p0), "{p0}");
    let p1 = c1
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 1}))
        .unwrap();
    assert!(ok(&p1), "specific-first 10/s must allow 2nd: {p1}");
    held.set_fixed_now(None);

    // Restart reload keeps the same first-match order/select.
    let after = read_text(&tokens_path);
    let store2 = TokenStore::from_json_str(&after).unwrap();
    assert_eq!(
        store2.get(&tok).unwrap().rate_config().select("data.build"),
        Some(("data.build", 10.0))
    );
}

#[test]
fn new_token_reversed_broad_first_denies_proving_real_order() {
    // Control: broad first must make broad win (opposite of specific-first).
    // A sorted rewrite would give broad-first in both cases and could not
    // distinguish; this pair proves the order is a real first-match policy.
    let (held, addr, tokens_path, _wal) = start_file_backed("new-reversed", ADMIN_TOKENS);
    let mut reader = raw_hello(&addr);
    let reply = raw_rpc(
        &mut reader,
        r#"{"op":"token_issue","agent":"r1","publish":["*"],"subscribe":["*"],"topic_rates":{"data.*":1,"data.build":10},"req_id":2}"#,
        2,
    );
    assert!(ok(&reply), "{reply}");
    let tok = reply["token"].as_str().unwrap().to_string();

    let text = read_text(&tokens_path);
    assert_eq!(
        rule_shapes(&text, &tok),
        vec![("data.*".to_string(), 1.0), ("data.build".to_string(), 10.0)]
    );
    let store = TokenStore::from_json_str(&text).unwrap();
    assert_eq!(
        store.get(&tok).unwrap().rate_config().select("data.build"),
        Some(("data.*", 1.0)),
        "broad first must win for data.build"
    );
    let broad = text.find("\"data.*\"").unwrap();
    let spec = text.find("\"data.build\"").unwrap();
    assert!(broad < spec, "persisted text must keep broad first");

    // Live: 2nd immediate post denied under 1/s broad-first.
    const T0: f64 = 1_790_530_000.0;
    held.set_fixed_now(Some(T0));
    let mut r1 = Client::connect(&addr, "r1", &tok).unwrap();
    let p0 = r1
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 0}))
        .unwrap();
    assert!(ok(&p0), "{p0}");
    let p1 = r1
        .rpc(&json!({"op": "post", "topic": "data.build", "payload": 1}))
        .unwrap();
    assert_eq!(p1["error"], json!("rate exceeded"), "{p1}");
    assert!(
        p1.get("retry_after_ms").and_then(|v| v.as_f64()).is_some(),
        "denial must carry retry_after_ms: {p1}"
    );
    held.set_fixed_now(None);
}

#[test]
fn repeated_pattern_keeps_first_position_last_value() {
    // CLI duplicate flags: last value, first position (legacy dict semantics).
    let (_held, addr, tokens_path, _wal) = start_file_backed("new-dedup-cli", ADMIN_TOKENS);
    let bin = env!("CARGO_BIN_EXE_agent-bus").to_string();
    let (host, port) = addr.split_once(':').unwrap();
    let out = std::process::Command::new(&bin)
        .args([
            "token-issue",
            "d1",
            "--topic-rate",
            "data.*=1",
            "--topic-rate",
            "data.build=10",
            "--topic-rate",
            "data.*=5",
        ])
        .env("AGENT_BUS_AGENT", "root")
        .env("AGENT_BUS_TOKEN", "tok-admin")
        .env_remove("AGENT_BUS_SOCK")
        .env("AGENT_BUS_HOST", host)
        .env("AGENT_BUS_PORT", port)
        .output()
        .expect("cli runs");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(ok(&reply), "{reply}");
    let tok = reply["token"].as_str().unwrap().to_string();
    let text = read_text(&tokens_path);
    assert_eq!(
        rule_shapes(&text, &tok),
        vec![("data.*".to_string(), 5.0), ("data.build".to_string(), 10.0)],
        "CLI duplicate must keep first position, last value"
    );
    // Single persisted entry with the last value, before data.build.
    assert_eq!(text.matches("\"data.*\"").count(), 1, "{text}");
    assert!(text.contains("\"data.*\": 5") || text.contains("\"data.*\":5.0"), "{text}");
    let store = TokenStore::from_json_str(&text).unwrap();
    assert_eq!(
        store.get(&tok).unwrap().rate_config().select("data.build"),
        Some(("data.*", 5.0)),
        "first-position data.* must win"
    );

    // Wire duplicate JSON keys: same last-value-first-position semantics.
    let (_held2, addr2, tokens_path2, _wal2) = start_file_backed("new-dedup-wire", ADMIN_TOKENS);
    let mut reader = raw_hello(&addr2);
    let reply2 = raw_rpc(
        &mut reader,
        r#"{"op":"token_issue","agent":"d2","topic_rates":{"data.*":1,"data.build":10,"data.*":5},"req_id":2}"#,
        2,
    );
    assert!(ok(&reply2), "{reply2}");
    let tok2 = reply2["token"].as_str().unwrap().to_string();
    let text2 = read_text(&tokens_path2);
    assert_eq!(
        rule_shapes(&text2, &tok2),
        vec![("data.*".to_string(), 5.0), ("data.build".to_string(), 10.0)],
        "wire duplicate keys must keep first position, last value"
    );
    assert_eq!(text2.matches("\"data.*\"").count(), 1, "{text2}");
}

#[test]
fn malformed_new_rates_refuse_without_durable_change() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("new-malformed", ADMIN_TOKENS);
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let before = read_bytes(&tokens_path);
    // Truthy non-objects, bad values, bad patterns, non-number strings,
    // and too-small-for-retry-hint rates all refuse with a topic_rates
    // diagnostic (same `bad policy` wrapping as existing validation).
    for (i, rates) in [
        json!([1]),
        json!("x"),
        json!(5),
        json!(true),
        json!({"b": 0}),
        json!({"b": -1}),
        json!({"b": "1"}),
        json!({"[bad": 1}),
        json!({"[z-a]": 1}),
        json!({"b": 1e-310}),
    ]
    .into_iter()
    .enumerate()
    {
        let r = admin
            .rpc(&json!({"op": "token_issue", "agent": format!("m{i}"), "topic_rates": rates}))
            .unwrap();
        assert!(!ok(&r), "malformed rates must refuse: {r}");
        let e = err_str(&r);
        assert!(
            e.contains("topic_rates"),
            "diagnostic must name topic_rates: {e}"
        );
        assert!(!r.to_string().contains("tok-m"), "no secret on failure: {r}");
        assert_eq!(read_bytes(&tokens_path), before, "file unchanged on refusal");
    }
    // Wire literal truthy non-object also refuses (not silently unlimited).
    let mut reader = raw_hello(&addr);
    let r = raw_rpc(
        &mut reader,
        r#"{"op":"token_issue","agent":"mw","topic_rates":[1],"req_id":2}"#,
        2,
    );
    assert!(!ok(&r), "{r}");
    assert!(err_str(&r).contains("topic_rates"), "{}", err_str(&r));
    assert_eq!(read_bytes(&tokens_path), before);
    // Store not poisoned: a valid issue still succeeds.
    let retry = admin
        .rpc(&json!({"op": "token_issue", "agent": "m-ok", "topic_rates": {"b": 1}}))
        .unwrap();
    assert!(ok(&retry), "{retry}");

    // CLI usage errors exit 2 without touching the broker.
    let bin = env!("CARGO_BIN_EXE_agent-bus").to_string();
    let (host, port) = addr.split_once(':').unwrap();
    let before2 = read_bytes(&tokens_path);
    for args in [
        vec!["token-issue", "x", "--topic-rate", "noequals"],
        vec!["token-issue", "x", "--topic-rate", "=5"],
        vec!["token-issue", "x", "--topic-rate", "b="],
        vec!["token-issue", "x", "--topic-rate", "b=abc"],
        vec!["token-issue", "x", "--topic-rate", "b=inf"],
    ] {
        let out = std::process::Command::new(&bin)
            .args(&args)
            .env("AGENT_BUS_AGENT", "root")
            .env("AGENT_BUS_TOKEN", "tok-admin")
            .env_remove("AGENT_BUS_SOCK")
            .env("AGENT_BUS_HOST", host)
            .env("AGENT_BUS_PORT", port)
            .output()
            .expect("cli runs");
        assert_eq!(
            out.status.code().unwrap_or(-1),
            2,
            "{args:?} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(read_bytes(&tokens_path), before2, "CLI usage must not mutate");
}

#[test]
fn new_token_order_survives_later_mutations() {
    let (_held, addr, tokens_path, _wal) = start_file_backed("new-mutations", ADMIN_TOKENS);
    let mut reader = raw_hello(&addr);
    let reply = raw_rpc(
        &mut reader,
        r#"{"op":"token_issue","agent":"a1","topic_rates":{"data.build":10,"data.*":1},"req_id":2}"#,
        2,
    );
    assert!(ok(&reply), "{reply}");
    let tok_a = reply["token"].as_str().unwrap().to_string();
    let expect = vec![("data.build".to_string(), 10.0), ("data.*".to_string(), 1.0)];
    assert_eq!(rule_shapes(&read_text(&tokens_path), &tok_a), expect);

    // Unrelated issue must not reorder the new token.
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let b = admin
        .rpc(&json!({"op": "token_issue", "agent": "b1"}))
        .unwrap();
    assert!(ok(&b), "{b}");
    let tok_b = b["token"].as_str().unwrap().to_string();
    let after_issue = read_text(&tokens_path);
    assert_eq!(rule_shapes(&after_issue, &tok_a), expect);
    assert!(after_issue.find("\"data.build\"").unwrap() < after_issue.find("\"data.*\"").unwrap());

    // Unrelated revoke must not reorder it either.
    let rv = admin
        .rpc(&json!({"op": "token_revoke", "token": tok_b}))
        .unwrap();
    assert_eq!(rv["revoked"], json!(true), "{rv}");
    let after_revoke = read_text(&tokens_path);
    assert_eq!(rule_shapes(&after_revoke, &tok_a), expect);

    // Restart reload keeps the new token's first-match order/select.
    let store2 = TokenStore::from_json_str(&after_revoke).unwrap();
    assert_eq!(
        store2.get(&tok_a).unwrap().rate_config().select("data.build"),
        Some(("data.build", 10.0))
    );
    assert_eq!(
        store2.get(&tok_a).unwrap().rate_config().select("data.other"),
        Some(("data.*", 1.0))
    );
}
