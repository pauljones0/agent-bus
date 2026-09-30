//! Native artifacts + quotas: `art_*` wire ops and `art-put`/`art-get` CLI.
//!
//! Ephemeral servers only (temp WAL + `<wal-parent>/artifacts`, loopback
//! TCP, fixture tokens, no production paths). Proves the
//! `crate::artifacts` + `wire` port matches the frozen `broker.py` /
//! `busclient.py` / `bus` contracts: 8 wire ops, `ART_MAX`/`CHUNK_MAX`
//! bounds, reservation quota with `art_used_bytes` live +
//! `quota_denied` live, dedup-still-charges, committer-charged admin
//! steal, any-authed-reads, owner-or-admin writes, strict sequential
//! chunks, private staging + atomic publish + WAL-before-ack, restart
//! usage-restore + staging-drop, disconnect abort, and CLI streaming
//! past 1 MiB with sha verification. See `docs/NATIVE_ARTIFACTS.md`.
//!
//! Bounds: small objects (bytes/KBs) except two 1 MiB+1 streaming
//! proofs (one put, one get); no 32 MiB stress without an estimate.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use agent_bus::acl::TokenStore;
use agent_bus::artifacts as art;
use agent_bus::wal::{replay_art_usage, snapshot_path_for};
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-artifacts-{name}-{}", std::process::id()));
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

fn quota_tokens(quota: u64) -> TokenStore {
    TokenStore::from_json_str(&format!(
        r#"{{
            "tok-alice": {{"agent": "alice", "publish": ["*"], "subscribe": ["*"],
                "art_quota_bytes": {quota}}},
            "tok-bob": {{"agent": "bob", "publish": ["*"], "subscribe": ["*"]}}
        }}"#
    ))
    .expect("fixture tokens valid")
}

fn admin_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]},
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
    let art_dir = wal.parent().unwrap().join("artifacts");
    let _ = std::fs::remove_dir_all(&art_dir);
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

fn put_bytes(c: &mut Client, raw: &[u8]) -> Value {
    c.rpc(&json!({"op": "art_put", "data_b64": art::base64_encode(raw)}))
        .unwrap()
}

fn cli_bin() -> String {
    env!("CARGO_BIN_EXE_agent-bus").to_string()
}

fn run_cli(
    addr: &str,
    agent: &str,
    token: &str,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
) -> (i32, Vec<u8>, String) {
    let (host, port) = addr.rsplit_once(':').expect("addr has port");
    let mut cmd = Command::new(cli_bin());
    cmd.args(args)
        .env("AGENT_BUS_AGENT", agent)
        .env("AGENT_BUS_TOKEN", token)
        .env_remove("AGENT_BUS_SOCK")
        .env("AGENT_BUS_HOST", host)
        .env("AGENT_BUS_PORT", port)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn().expect("spawn agent-bus");
    if let Some(input) = stdin_bytes {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input)
            .expect("stdin write");
    }
    let out = child.wait_with_output().expect("wait agent-bus");
    (
        out.status.code().unwrap_or(-1),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// Ordinary single-put/get/stat roundtrip, dedup still charges.
#[test]
fn put_get_stat_roundtrip_with_dedup_charge() {
    let (addr, _wal, server) = start_handle("put-get");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"native artifacts roundtrip";
    let p1 = put_bytes(&mut a, raw);
    assert!(ok(&p1), "{p1}");
    assert_eq!(p1["dedup"], json!(false), "{p1}");
    let sha = p1["sha"].as_str().unwrap().to_string();
    assert_eq!(sha, art::sha256_hex(raw));
    assert_eq!(p1["size"], json!(raw.len()));
    let g = a.rpc(&json!({"op": "art_get", "sha": sha})).unwrap();
    assert!(ok(&g), "{g}");
    assert_eq!(art::base64_decode(g["data_b64"].as_str().unwrap()).unwrap(), raw);
    let s = a.rpc(&json!({"op": "art_stat", "sha": sha})).unwrap();
    assert_eq!(s["size"], json!(raw.len()), "{s}");
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(raw.len()), "{lim}");
    // Dedup put succeeds, reports dedup, charges again (legacy).
    let p2 = put_bytes(&mut a, raw);
    assert!(ok(&p2), "{p2}");
    assert_eq!(p2["dedup"], json!(true), "{p2}");
    assert_eq!(p2["sha"], json!(sha));
    let lim2 = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim2["art_used_bytes"], json!(raw.len() * 2), "{lim2}");
    // Empty put stores empty (legacy allows len 0), charges 0.
    let pe = put_bytes(&mut a, b"");
    assert!(ok(&pe), "{pe}");
    assert_eq!(pe["size"], json!(0));
    server.set_fixed_now(None);
}

// Single-put negatives: bad base64, size cap, sha mismatch (no charge).
#[test]
fn put_rejects_malformed_without_charging() {
    let (addr, _wal, server) = start_handle("put-neg");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r = a.rpc(&json!({"op": "art_put", "data_b64": "!!!"})).unwrap();
    assert_eq!(r["error"], json!("bad base64"), "{r}");
    let r = a.rpc(&json!({"op": "art_put", "data_b64": 123})).unwrap();
    assert_eq!(r["error"], json!("bad base64"), "{r}");
    let want = "0".repeat(64);
    let r = a
        .rpc(&json!({"op": "art_put", "data_b64": art::base64_encode(b"x"), "sha": want}))
        .unwrap();
    assert_eq!(r["error"], json!("sha mismatch"), "{r}");
    // Falsy sha wants skip the check (legacy `if want`).
    for falsy in [json!(null), json!(""), json!(0), json!(false)] {
        let r = a
            .rpc(&json!({"op": "art_put", "data_b64": art::base64_encode(b"y"), "sha": falsy}))
            .unwrap();
        assert!(ok(&r), "{r}");
    }
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    // Four falsy puts of 1 byte each (x/y/y/y/y? first x mismatched, then 4 y).
    assert_eq!(lim["art_used_bytes"], json!(4), "{lim}");
    server.set_fixed_now(None);
}

// Range streaming: clamp, bounds, missing sha.
#[test]
fn range_clamps_and_validates_bounds() {
    let (addr, _wal, server) = start_handle("range");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"0123456789abcdef";
    let sha = put_bytes(&mut a, raw)["sha"].as_str().unwrap().to_string();
    let r = a
        .rpc(&json!({"op": "art_range", "sha": sha, "off": 4, "len": 4}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(art::base64_decode(r["data_b64"].as_str().unwrap()).unwrap(), b"4567");
    assert_eq!(r["off"], json!(4));
    assert_eq!(r["size"], json!(raw.len()));
    // Clamp past end, zero-len ok.
    let r = a
        .rpc(&json!({"op": "art_range", "sha": sha, "off": 14, "len": 100}))
        .unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(art::base64_decode(r["data_b64"].as_str().unwrap()).unwrap(), b"ef");
    let r = a.rpc(&json!({"op": "art_range", "sha": sha, "off": 0, "len": 0})).unwrap();
    assert!(ok(&r), "{r}");
    assert_eq!(r["data_b64"], json!(""));
    // Bad ranges, missing sha.
    for bad in [
        json!({"op": "art_range", "sha": sha, "off": 99, "len": 1}),
        json!({"op": "art_range", "sha": sha, "off": 0, "len": art::CHUNK_MAX + 1}),
        json!({"op": "art_range", "sha": sha, "off": -1, "len": 1}),
        json!({"op": "art_range", "sha": sha, "off": "x", "len": 1}),
        json!({"op": "art_range", "sha": "", "off": 0, "len": 1}),
        json!({"op": "art_range", "sha": "nope", "off": 0, "len": 1}),
    ] {
        let r = a.rpc(&bad).unwrap();
        assert!(r.get("error").is_some(), "{bad}: {r}");
    }
    server.set_fixed_now(None);
}

// Chunked upload roundtrip: init, strict sequential chunks, commit.
#[test]
fn chunked_upload_roundtrip_with_strict_offsets() {
    let (addr, _wal, server) = start_handle("chunked");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"The quick brown fox jumps over the lazy dog. Chunked.";
    let sha = art::sha256_hex(raw);
    let init = a
        .rpc(&json!({"op": "art_init", "size": raw.len(), "sha": sha}))
        .unwrap();
    assert!(ok(&init), "{init}");
    let uid = init["upload_id"].as_str().unwrap().to_string();
    // Wrong offset refused (must equal received).
    let r = a
        .rpc(&json!({"op": "art_chunk", "upload_id": uid, "off": 1, "data_b64": ""}))
        .unwrap();
    assert!(r["error"].as_str().unwrap().starts_with("bad off:"), "{r}");
    let mut off = 0u64;
    for chunk in raw.chunks(10) {
        let r = a
            .rpc(&json!({
                "op": "art_chunk", "upload_id": uid, "off": off,
                "data_b64": art::base64_encode(chunk),
            }))
            .unwrap();
        assert!(ok(&r), "{r}");
        off += chunk.len() as u64;
        assert_eq!(r["received"], json!(off));
    }
    // Incomplete commit refused before all bytes (new upload, partial).
    let init2 = a.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    let uid2 = init2["upload_id"].as_str().unwrap().to_string();
    let _ = a
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid2, "off": 0,
            "data_b64": art::base64_encode(b"12345"),
        }))
        .unwrap();
    let r = a.rpc(&json!({"op": "art_commit", "upload_id": uid2})).unwrap();
    assert!(r["error"].as_str().unwrap().starts_with("incomplete:"), "{r}");
    let _ = a.rpc(&json!({"op": "art_abort", "upload_id": uid2})).unwrap();
    // Complete commit publishes.
    let c = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert!(ok(&c), "{c}");
    assert_eq!(c["sha"], json!(sha));
    assert_eq!(c["dedup"], json!(false));
    let g = a.rpc(&json!({"op": "art_get", "sha": sha})).unwrap();
    assert_eq!(art::base64_decode(g["data_b64"].as_str().unwrap()).unwrap(), raw);
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(raw.len()), "{lim}");
    server.set_fixed_now(None);
}

// Chunk/commit/abort need owner-or-admin; others miss as unknown.
#[test]
fn upload_ownership_is_owner_or_admin() {
    let (addr, _wal, server) = start_with_handle("own", admin_tokens());
    server.set_fixed_now(Some(T0));
    let mut alice = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut bob = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let init = alice.rpc(&json!({"op": "art_init", "size": 3})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    // Bob (stranger) cannot chunk/commit/abort; misses as unknown.
    for op in ["art_chunk", "art_commit", "art_abort"] {
        let mut req = json!({"op": op, "upload_id": uid});
        if op == "art_chunk" {
            req["off"] = json!(0);
            req["data_b64"] = json!(art::base64_encode(b"abc"));
        }
        let r = bob.rpc(&req).unwrap();
        assert_eq!(r["error"], json!("unknown upload"), "{op}: {r}");
    }
    // Admin can chunk (owner-or-admin), then alice commits.
    let r = admin
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0,
            "data_b64": art::base64_encode(b"abc"),
        }))
        .unwrap();
    assert!(ok(&r), "{r}");
    let c = alice.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert!(ok(&c), "{c}");
    // Committed upload is gone for everyone (unknown).
    let r = alice.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert_eq!(r["error"], json!("unknown upload"), "{r}");
    server.set_fixed_now(None);
}

// Admin steal charges the committer, not the initiator (legacy).
#[test]
fn admin_commit_charges_committer() {
    let (addr, _wal, server) = start_with_handle("steal", admin_tokens());
    server.set_fixed_now(Some(T0));
    let mut alice = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut admin = Client::connect(&addr, "root", "tok-admin").unwrap();
    let raw = b"stolen bytes";
    let init = alice.rpc(&json!({"op": "art_init", "size": raw.len()})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let _ = alice
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0,
            "data_b64": art::base64_encode(raw),
        }))
        .unwrap();
    let c = admin.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert!(ok(&c), "{c}");
    let la = alice.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(la["art_used_bytes"], json!(0), "{la}");
    let lr = admin.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lr["art_used_bytes"], json!(raw.len()), "{lr}");
    server.set_fixed_now(None);
}

// Any authed agent reads any sha (no per-artifact ACL).
#[test]
fn reads_are_visible_to_any_authed_agent() {
    let (addr, _wal, server) = start_handle("vis");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let sha = put_bytes(&mut a, b"shared")["sha"].as_str().unwrap().to_string();
    assert!(ok(&b.rpc(&json!({"op": "art_get", "sha": sha})).unwrap()));
    assert!(ok(&b.rpc(&json!({"op": "art_stat", "sha": sha})).unwrap()));
    assert!(ok(&b
        .rpc(&json!({"op": "art_range", "sha": sha, "off": 0, "len": 2}))
        .unwrap()));
    server.set_fixed_now(None);
}

// Quota enforced at put/init/commit; counters live; malformed denies.
#[test]
fn quota_enforced_with_live_counters() {
    let (addr, _wal, server) = start_with_handle("quota", quota_tokens(10));
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Put 6 ok, put 5 over (6+5>10).
    assert!(ok(&put_bytes(&mut a, b"123456")));
    let r = put_bytes(&mut a, b"12345");
    assert_eq!(r["error"], json!("artifact quota exceeded"), "{r}");
    let st = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st["stats"]["quota_denied"], json!(1), "{st}");
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(6), "{lim}");
    assert_eq!(lim["art_quota_bytes"], json!(10), "{lim}");
    // Init pre-check denies over-quota sizes (no charge).
    let r = a.rpc(&json!({"op": "art_init", "size": 5})).unwrap();
    assert_eq!(r["error"], json!("artifact quota exceeded"), "{r}");
    // Init under, then commit over after filling via put.
    let init = a.rpc(&json!({"op": "art_init", "size": 4})).unwrap();
    assert!(ok(&init), "{init}");
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let _ = a
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0,
            "data_b64": art::base64_encode(b"wxyz"),
        }))
        .unwrap();
    assert!(ok(&put_bytes(&mut a, b"78")));
    let r = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert_eq!(r["error"], json!("artifact quota exceeded"), "{r}");
    // Upload survives the denied commit (retryable after quota bump).
    let r = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert!(ok(&r), "{r}");
    let st2 = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st2["stats"]["quota_denied"], json!(3), "{st2}");
    server.set_fixed_now(None);
}

// Malformed quota configs deny closed (legacy crashed the conn).
#[test]
fn malformed_quota_denies_closed() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-bad": {"agent": "bad", "publish": ["*"], "subscribe": ["*"],
                "art_quota_bytes": "ten"}
        }"#,
    )
    .unwrap();
    let (addr, _wal, server) = start_with_handle("badquota", tokens);
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "bad", "tok-bad").unwrap();
    let r = put_bytes(&mut c, b"x");
    assert_eq!(r["error"], json!("artifact quota exceeded"), "{r}");
    let lim = c.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_quota_bytes"], json!("ten"), "{lim}");
    assert_eq!(lim["art_used_bytes"], json!(0), "{lim}");
    server.set_fixed_now(None);
}

// Disconnect aborts owned pending uploads (staging unlinked).
// Cleanup contract is synchronous/ordered: production unlinks staging under
// the per-upload lock before exposing terminal/pop (restoring Python
// `pop+unlink` atomicity with no yield between), so `unknown upload` implies
// already unlinked. The test still waits for the complete condition
// (unknown + unlinked) within the existing bounded deadline (50 x 50ms) so
// scheduling between map removal and unlink cannot flake it; it does not
// widen the deadline or weaken the disappearance requirement.
#[test]
fn disconnect_aborts_owned_uploads() {
    let (addr, wal, server) = start_handle("disconnect");
    server.set_fixed_now(Some(T0));
    let uid = {
        let mut c1 = Client::connect(&addr, "alice", "tok-alice").unwrap();
        let init = c1.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
        let uid = init["upload_id"].as_str().unwrap().to_string();
        let _ = c1
            .rpc(&json!({
                "op": "art_chunk", "upload_id": uid, "off": 0,
                "data_b64": art::base64_encode(b"12345"),
            }))
            .unwrap();
        uid
    };
    let art_dir = wal.parent().unwrap().join("artifacts");
    let staging_path = art_dir.join(format!(".up-{uid}"));
    let mut clean = false;
    let mut c2 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for _ in 0..50 {
        let r = c2
            .rpc(&json!({
                "op": "art_chunk", "upload_id": uid, "off": 5,
                "data_b64": art::base64_encode(b"67890"),
            }))
            .unwrap();
        let unknown = r["error"] == json!("unknown upload");
        let unlinked = !staging_path.exists();
        if unknown && unlinked {
            clean = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        clean,
        "owned upload leaked after disconnect (unknown+unlink within deadline)"
    );
    server.set_fixed_now(None);
}

// Restart: usage restored from WAL, bytes survive, staging dropped.
#[test]
fn restart_restores_usage_and_bytes_but_drops_pending() {
    let (addr, wal, server) = start_handle("restart");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"restart-durable";
    let sha = put_bytes(&mut a, raw)["sha"].as_str().unwrap().to_string();
    let init = a.rpc(&json!({"op": "art_init", "size": 5})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let art_dir = wal.parent().unwrap().join("artifacts");
    assert!(art_dir.join(format!(".up-{uid}")).exists());
    drop(a);
    // Simulate boot: fresh store cleans staging, WAL replays usage.
    let usage = replay_art_usage(&wal).expect("art_own replays");
    assert_eq!(usage.get("alice"), Some(&(raw.len() as u64)));
    let fresh = art::ArtifactStore::new(art_dir.clone()).expect("reboot store");
    for (agent, size) in usage {
        fresh.restore_usage(&agent, size);
    }
    assert_eq!(fresh.usage_of("alice"), raw.len() as u64);
    assert_eq!(fresh.get_bytes(&sha).unwrap(), raw);
    assert!(!art_dir.join(format!(".up-{uid}")).exists());
    assert!(fresh.lookup_upload(&uid).is_none());
    // WAL holds the art_own receipt (commit-before-success proof).
    let text = std::fs::read_to_string(&wal).unwrap();
    assert!(text.contains("\"t\":\"art_own\""), "{text}");
    assert!(text.contains(&sha), "{text}");
    server.set_fixed_now(None);
}

// WAL failure rolls back the charge; retry dedups (put path).
#[test]
fn wal_failure_rolls_back_put_and_retry_dedups() {
    use agent_bus::wal::APPEND_FAIL_AFTER_LINE;
    let (addr, _wal, server) = start_handle("walfail-put");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"wal-fail-retry";
    server.set_append_failpoint(APPEND_FAIL_AFTER_LINE);
    let r = put_bytes(&mut a, raw);
    assert!(r.get("error").is_some(), "{r}");
    server.set_append_failpoint(agent_bus::wal::APPEND_FAIL_NONE);
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(0), "{lim}");
    // Retry publishes (orphan bytes dedup) and charges once.
    let r2 = put_bytes(&mut a, raw);
    assert!(ok(&r2), "{r2}");
    let lim2 = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim2["art_used_bytes"], json!(raw.len()), "{lim2}");
    server.set_fixed_now(None);
}

// WAL failure during commit keeps staging; retry commits clean.
#[test]
fn wal_failure_keeps_staging_for_commit_retry() {
    use agent_bus::wal::APPEND_FAIL_AFTER_LINE;
    let (addr, _wal, server) = start_handle("walfail-commit");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"commit-retry-bytes";
    let init = a.rpc(&json!({"op": "art_init", "size": raw.len()})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let _ = a
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0,
            "data_b64": art::base64_encode(raw),
        }))
        .unwrap();
    server.set_append_failpoint(APPEND_FAIL_AFTER_LINE);
    let r = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert!(r.get("error").is_some(), "{r}");
    server.set_append_failpoint(agent_bus::wal::APPEND_FAIL_NONE);
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(0), "{lim}");
    let r2 = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert!(ok(&r2), "{r2}");
    let lim2 = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim2["art_used_bytes"], json!(raw.len()), "{lim2}");
    server.set_fixed_now(None);
}

// Poisoned WAL refuses mutating puts/commits; reads stay available.
#[test]
fn poisoned_wal_refuses_mutations_but_reads_stay() {
    let (addr, _wal, server) = start_handle("poison");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let sha = put_bytes(&mut a, b"before-poison")["sha"]
        .as_str()
        .unwrap()
        .to_string();
    server.poison_for_test("artifacts-test");
    let r = put_bytes(&mut a, b"after");
    assert!(r["error"].as_str().unwrap().starts_with("wal poisoned"), "{r}");
    // Init/chunk/abort touch no WAL, so they stay available.
    let init = a.rpc(&json!({"op": "art_init", "size": 2})).unwrap();
    assert!(ok(&init), "{init}");
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let r = a
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0,
            "data_b64": art::base64_encode(b"hi"),
        }))
        .unwrap();
    assert!(ok(&r), "{r}");
    let r = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert!(r["error"].as_str().unwrap().starts_with("wal poisoned"), "{r}");
    let r = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert!(ok(&r), "{r}");
    assert!(ok(&a.rpc(&json!({"op": "art_get", "sha": sha})).unwrap()));
    assert!(ok(&a.rpc(&json!({"op": "art_stat", "sha": sha})).unwrap()));
    server.set_fixed_now(None);
}

// Auth required for every art op; responses never carry the token.
#[test]
fn auth_required_and_no_credential_leak() {
    let (addr, _wal, server) = start_handle("auth-leak");
    server.set_fixed_now(Some(T0));
    let mut raw = Client::raw(&addr).unwrap();
    for op in [
        json!({"op": "art_put", "data_b64": ""}),
        json!({"op": "art_get", "sha": "x"}),
        json!({"op": "art_init", "size": 1}),
        json!({"op": "art_chunk", "upload_id": "u", "off": 0, "data_b64": ""}),
        json!({"op": "art_commit", "upload_id": "u"}),
        json!({"op": "art_abort", "upload_id": "u"}),
        json!({"op": "art_range", "sha": "x", "off": 0, "len": 1}),
        json!({"op": "art_stat", "sha": "x"}),
    ] {
        let r = raw.rpc(&op).unwrap();
        assert_eq!(r["error"], json!("auth required (send hello first)"), "{op}: {r}");
    }
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let p = put_bytes(&mut a, b"leak-check");
    let sha = p["sha"].as_str().unwrap().to_string();
    for req in [
        json!({"op": "art_get", "sha": sha}),
        json!({"op": "art_stat", "sha": sha}),
        json!({"op": "art_range", "sha": sha, "off": 0, "len": 2}),
        json!({"op": "limits"}),
        json!({"op": "stats"}),
    ] {
        let text = serde_json::to_string(&a.rpc(&req).unwrap()).unwrap();
        assert!(!text.contains("tok-alice"), "{text}");
    }
    server.set_fixed_now(None);
}

// Every authed art op refreshes presence liveness (never `ping` only).
#[test]
fn art_ops_refresh_presence_liveness() {
    let (addr, _wal, server) = start_handle("presence");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    server.set_fixed_now(Some(T0 + 100.0));
    let sha = put_bytes(&mut a, b"touch")["sha"].as_str().unwrap().to_string();
    server.set_fixed_now(Some(T0 + 160.0));
    let _ = a.rpc(&json!({"op": "art_get", "sha": sha})).unwrap();
    let out = a.rpc(&json!({"op": "agents"})).unwrap();
    assert_eq!(out["agents"]["alice"]["age_s"], json!(0.0), "{out}");
    server.set_fixed_now(None);
}

// CLI file roundtrip: put file, get to OUT, bytes match, JSON receipts.
#[test]
fn cli_file_roundtrip_with_json_receipts() {
    let (addr, wal, server) = start_handle("cli-file");
    server.set_fixed_now(Some(T0));
    let dir = wal.parent().unwrap().to_path_buf();
    let src = dir.join("cli-src.bin");
    let dst = dir.join("cli-dst.bin");
    let raw = b"cli file bytes \x00\x01\x02 end";
    std::fs::write(&src, raw).unwrap();
    let (st, out, err) = run_cli(&addr, "alice", "tok-alice", &["art-put", src.to_str().unwrap()], None);
    assert_eq!(st, 0, "stderr={err}");
    let resp: Value = serde_json::from_slice(&out).unwrap();
    assert!(ok(&resp), "{resp:?}");
    let sha = resp["sha"].as_str().unwrap().to_string();
    assert!(!String::from_utf8_lossy(&out).contains("tok-alice"));
    assert!(!err.contains("tok-alice"));
    let (st, out, err) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &["art-get", &sha, dst.to_str().unwrap()],
        None,
    );
    assert_eq!(st, 0, "stderr={err}");
    let resp: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(resp["sha"], json!(sha));
    assert_eq!(std::fs::read(&dst).unwrap(), raw);
    server.set_fixed_now(None);
}

// CLI streaming past 1 MiB: stdin put, stdout get, sha verified.
#[test]
fn cli_streaming_past_threshold_with_verification() {
    let (addr, _wal, server) = start_handle("cli-stream");
    server.set_fixed_now(Some(T0));
    let mut raw = vec![0u8; (art::CLIENT_STREAM_THRESHOLD + 1) as usize];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let (st, out, err) = run_cli(&addr, "alice", "tok-alice", &["art-put", "-"], Some(&raw));
    assert_eq!(st, 0, "stderr={err}");
    let resp: Value = serde_json::from_slice(&out).unwrap();
    assert!(ok(&resp), "{resp:?}");
    let sha = resp["sha"].as_str().unwrap().to_string();
    assert_eq!(sha, art::sha256_hex(&raw));
    let (st, out, err) = run_cli(&addr, "bob", "tok-bob", &["art-get", &sha], None);
    assert_eq!(st, 0, "stderr={err}");
    assert_eq!(out, raw);
    server.set_fixed_now(None);
}

// CLI usage errors: missing args, unknown flags, missing file.
#[test]
fn cli_usage_errors_are_explicit() {
    let (addr, _wal, server) = start_handle("cli-usage");
    server.set_fixed_now(Some(T0));
    let (st, _, err) = run_cli(&addr, "alice", "tok-alice", &["art-put"], None);
    assert_eq!(st, 2, "{err}");
    let (st, _, err) = run_cli(&addr, "alice", "tok-alice", &["art-get"], None);
    assert_eq!(st, 2, "{err}");
    let (st, _, err) = run_cli(&addr, "alice", "tok-alice", &["art-put", "--nope", "x"], None);
    assert_eq!(st, 2, "{err}");
    let (st, _, err) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &["art-put", "/definitely/missing/cli-input.bin"],
        None,
    );
    assert_eq!(st, 2, "{err}");
    let (st, _, err) = run_cli(&addr, "alice", "tok-alice", &["art-get", &"0".repeat(64)], None);
    assert_eq!(st, 1, "{err}");
    assert!(err.contains("artifact not found"), "{err}");
    assert!(!err.contains("tok-alice"), "{err}");
    server.set_fixed_now(None);
}

// Malformed inputs are ordinary JSON errors (never panics/hangs).
#[test]
fn malformed_inputs_are_ordinary_errors() {
    let (addr, _wal, server) = start_handle("malformed");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let cases: Vec<(Value, &str)> = vec![
        (json!({"op": "art_init", "size": 0}), "bad size"),
        (json!({"op": "art_init", "size": -5}), "bad size"),
        (json!({"op": "art_init", "size": "10"}), "bad size"),
        (json!({"op": "art_init", "size": 10, "sha": "zzz"}), "sha mismatch"),
        (json!({"op": "art_chunk", "upload_id": "nope", "off": 0, "data_b64": ""}), "unknown upload"),
        (json!({"op": "art_commit", "upload_id": 123}), "unknown upload"),
        (json!({"op": "art_abort"}), "unknown upload"),
        (json!({"op": "art_get", "sha": 123}), "artifact not found"),
        (json!({"op": "art_stat", "sha": "../x"}), "artifact not found"),
        (json!({"op": "art_range", "sha": "x", "off": 1.5, "len": 1}), "bad range"),
    ];
    for (req, want) in cases {
        let r = a.rpc(&req).unwrap();
        let err = r.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert!(err.contains(want), "{req}: {r}");
    }
    server.set_fixed_now(None);
}

// Concurrent identical puts both succeed and both charge (dedup race safe).
#[test]
fn concurrent_identical_puts_both_charge() {
    let (addr, _wal, server) = start_handle("concurrent");
    server.set_fixed_now(Some(T0));
    let raw = b"concurrent identical bytes";
    let mut handles = Vec::new();
    for _ in 0..2 {
        let addr = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
            c.rpc(&json!({"op": "art_put", "data_b64": art::base64_encode(raw)})).unwrap()
        }));
    }
    for h in handles {
        let r = h.join().unwrap();
        assert!(ok(&r), "{r}");
    }
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(raw.len() * 2), "{lim}");
    server.set_fixed_now(None);
}

// Tampered objects repair or fail closed via wire (store validation).
#[test]
fn tampered_objects_repair_or_fail_closed_via_wire() {
    let (addr, wal, server) = start_handle("tamper-wire");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"wire tamper repair";
    let p1 = put_bytes(&mut a, raw);
    assert!(ok(&p1), "{p1}");
    let sha = p1["sha"].as_str().unwrap().to_string();
    let art_dir = wal.parent().unwrap().join("artifacts");
    let final_path = art_dir.join(&sha);
    // Same-size tamper repairs on next put (dedup false, correct bytes).
    let mut bad = raw.to_vec();
    bad[0] ^= 0xff;
    std::fs::write(&final_path, &bad).unwrap();
    let p2 = put_bytes(&mut a, raw);
    assert!(ok(&p2), "{p2}");
    assert_eq!(p2["dedup"], json!(false), "{p2}");
    let g = a.rpc(&json!({"op": "art_get", "sha": sha})).unwrap();
    assert!(ok(&g), "{g}");
    let got = art::base64_decode(g["data_b64"].as_str().unwrap()).unwrap();
    assert_eq!(got, raw);
    // Oversize tamper (sparse ART_MAX+1): get fails closed, stat reports.
    let sha_big = art::sha256_hex(b"wire-big");
    let big_path = art_dir.join(&sha_big);
    {
        let f = std::fs::File::create(&big_path).unwrap();
        f.set_len(art::ART_MAX + 1).unwrap();
    }
    let gb = a.rpc(&json!({"op": "art_get", "sha": sha_big})).unwrap();
    assert_eq!(
        gb.get("error").and_then(|e| e.as_str()),
        Some("artifact not found"),
        "{gb}"
    );
    let sb = a.rpc(&json!({"op": "art_stat", "sha": sha_big})).unwrap();
    assert!(ok(&sb), "{sb}");
    assert_eq!(sb["size"], json!(art::ART_MAX + 1), "{sb}");
    // Directory collision fails closed, preserved.
    let raw3 = b"wire dir collision";
    let sha_dir = art::sha256_hex(raw3);
    let dir_path = art_dir.join(&sha_dir);
    std::fs::create_dir_all(&dir_path).unwrap();
    let p3 = put_bytes(&mut a, raw3);
    assert!(p3.get("error").is_some(), "{p3}");
    assert!(dir_path.is_dir());
    let _ = std::fs::remove_dir_all(&dir_path);
    server.set_fixed_now(None);
}

// Abort unlink failure is observable (error, not silent ok), counted,
// retained for retry; retry succeeds and pops (bounded, no workers).
#[test]
fn abort_unlink_failure_is_observable_and_retryable() {
    let (addr, wal, server) = start_handle("abort-cleanup-fail");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let init = a.rpc(&json!({"op": "art_init", "size": 5})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let art_dir = wal.parent().unwrap().join("artifacts");
    let staging = art_dir.join(format!(".up-{uid}"));
    assert!(staging.exists());
    server.set_artifact_unlink_failpoint_for_test(1);
    let r = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    let err = r.get("error").and_then(|e| e.as_str()).unwrap_or("");
    assert!(
        err.starts_with("abort failed: staging cleanup failed:"),
        "{r}"
    );
    assert!(staging.exists(), "failed abort preserves staging for retry");
    let st = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st["stats"]["staging_cleanup_failed"], json!(1), "{st}");
    // Retained (not unknown): retry abort succeeds after clearing failpoint.
    let r2 = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert!(ok(&r2), "retry after injected failure must succeed: {r2}");
    assert!(!staging.exists());
    let r3 = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert_eq!(r3["error"], json!("unknown upload"), "{r3}");
    let st2 = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st2["stats"]["staging_cleanup_failed"], json!(1), "{st2}");
    server.set_fixed_now(None);
}

// Abort unlink failure via real IO error (directory at staging path,
// fails even as root): same observable, retryable, bounded semantics.
#[test]
fn abort_unlink_real_io_error_is_observable_and_retryable() {
    let (addr, wal, server) = start_handle("abort-cleanup-dir");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let init = a.rpc(&json!({"op": "art_init", "size": 3})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let art_dir = wal.parent().unwrap().join("artifacts");
    let staging = art_dir.join(format!(".up-{uid}"));
    assert!(staging.is_file());
    // Replace the staging file with a directory: `remove_file` fails
    // even as root (no permission trick, deterministic under UID 0).
    std::fs::remove_file(&staging).unwrap();
    std::fs::create_dir_all(&staging).unwrap();
    let r = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    let err = r.get("error").and_then(|e| e.as_str()).unwrap_or("");
    assert!(
        err.starts_with("abort failed: staging cleanup failed:"),
        "{r}"
    );
    assert!(staging.is_dir(), "failed abort preserves staging");
    let st = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st["stats"]["staging_cleanup_failed"], json!(1), "{st}");
    // Clear the obstruction (external sweep equivalent), retry succeeds
    // via `NotFound`-as-success (dir gone, file gone, goal achieved).
    std::fs::remove_dir(&staging).unwrap();
    let r2 = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert!(ok(&r2), "{r2}");
    let r3 = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert_eq!(r3["error"], json!("unknown upload"), "{r3}");
    server.set_fixed_now(None);
}

// Disconnect unlink failure retains the upload for explicit abort retry
// (never silently complete): counter proves the disconnect attempt ran,
// upload stays `Active` (not unknown), staging stays, retry pops.
#[test]
fn disconnect_unlink_failure_retains_for_abort_retry() {
    let (addr, wal, server) = start_handle("disconnect-cleanup-fail");
    server.set_fixed_now(Some(T0));
    let uid = {
        let mut c1 = Client::connect(&addr, "alice", "tok-alice").unwrap();
        let init = c1.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
        init["upload_id"].as_str().unwrap().to_string()
    };
    // Reconnect to set the failpoint, then drop a fresh owner conn whose
    // disconnect will attempt (and fail) the unlink. The init conn above
    // already disconnected successfully (no failpoint then, popped); to
    // exercise disconnect failure deterministically, init a second upload
    // on a new conn, set the failpoint, then drop that conn.
    let uid2 = {
        let mut c1 = Client::connect(&addr, "alice", "tok-alice").unwrap();
        let init = c1.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
        let uid2 = init["upload_id"].as_str().unwrap().to_string();
        server.set_artifact_unlink_failpoint_for_test(1);
        // `c1` drops here; server disconnect cleanup attempts the unlink
        // and fails (injected), retaining `Active` + counter.
        uid2
    };
    let _ = uid;
    let art_dir = wal.parent().unwrap().join("artifacts");
    let staging = art_dir.join(format!(".up-{uid2}"));
    // Poll the counter (bounded 50 x 50ms, like the existing disconnect
    // test) to prove the disconnect attempt ran and failed; upload must
    // stay present (abort retries, never unknown-while-present).
    let mut c2 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut observed = false;
    for _ in 0..50 {
        let st = c2.rpc(&json!({"op": "stats"})).unwrap();
        if st["stats"]["staging_cleanup_failed"] == json!(1) && staging.exists() {
            // Still `Active` (not unknown): chunk with wrong offset reports
            // `bad off`, proving presence; unknown would hide failure.
            let probe = c2
                .rpc(&json!({
                    "op": "art_chunk", "upload_id": uid2, "off": 999,
                    "data_b64": "",
                }))
                .unwrap();
            let err = probe.get("error").and_then(|e| e.as_str()).unwrap_or("");
            if err.starts_with("bad off:") {
                observed = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        observed,
        "disconnect unlink failure must retain Active + staging + counter within deadline"
    );
    // Explicit abort retry succeeds (failpoint auto-cleared), pops.
    let r = c2.rpc(&json!({"op": "art_abort", "upload_id": uid2})).unwrap();
    assert!(ok(&r), "{r}");
    assert!(!staging.exists());
    let r2 = c2.rpc(&json!({"op": "art_abort", "upload_id": uid2})).unwrap();
    assert_eq!(r2["error"], json!("unknown upload"), "{r2}");
    server.set_fixed_now(None);
}

// Commit unlink failure after durable WAL success preserves the receipt
// and charge (no uncharge, no recommit/double-charge): ok + same
// `sha`/`size`/`dedup` plus `staging_cleanup_error`, retained pending,
// late commit/chunk report already-committed (never unknown), cleanup
// retries via abort (bounded, no workers).
#[test]
fn commit_unlink_failure_preserves_receipt_and_charge() {
    let (addr, wal, server) = start_handle("commit-cleanup-fail");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"commit-cleanup-bytes";
    let init = a.rpc(&json!({"op": "art_init", "size": raw.len()})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let _ = a
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0,
            "data_b64": art::base64_encode(raw),
        }))
        .unwrap();
    let art_dir = wal.parent().unwrap().join("artifacts");
    let staging = art_dir.join(format!(".up-{uid}"));
    assert!(staging.exists());
    server.set_artifact_unlink_failpoint_for_test(1);
    let c = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    // Committed receipt preserved (ok, same sha/size/dedup), plus observable
    // cleanup error (never silently complete).
    assert!(ok(&c), "{c}");
    let sha = c["sha"].as_str().unwrap().to_string();
    assert_eq!(sha, art::sha256_hex(raw));
    assert_eq!(c["size"], json!(raw.len()));
    assert!(c.get("dedup").is_some(), "{c}");
    let cleanup_err = c
        .get("staging_cleanup_error")
        .and_then(|e| e.as_str())
        .unwrap_or("");
    assert!(
        cleanup_err.starts_with("staging cleanup failed:"),
        "{c}"
    );
    assert!(staging.exists(), "failed commit unlink preserves staging");
    // Charge kept (no uncharge after WAL success), WAL has the receipt.
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(raw.len()), "{lim}");
    let st = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st["stats"]["staging_cleanup_failed"], json!(1), "{st}");
    let text = std::fs::read_to_string(&wal).unwrap();
    assert_eq!(text.matches("\"t\":\"art_own\"").count(), 1, "{text}");
    assert!(text.contains(&sha), "{text}");
    // Late commit/chunk on pending report already-committed (never unknown
    // which would falsely imply unlinked, never ok which would double-charge).
    let c2 = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert_eq!(
        c2["error"],
        json!("already committed (staging cleanup pending; retry via art_abort)"),
        "{c2}"
    );
    let ch = a
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0, "data_b64": "",
        }))
        .unwrap();
    assert_eq!(
        ch["error"],
        json!("already committed (staging cleanup pending; retry via art_abort)"),
        "{ch}"
    );
    let lim2 = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim2["art_used_bytes"], json!(raw.len()), "{lim2}");
    // Abort retries the orphan cleanup: pops, keeps the charge (no uncharge),
    // no second WAL append, bytes stay readable.
    let ab = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert!(ok(&ab), "{ab}");
    assert!(!staging.exists());
    let lim3 = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim3["art_used_bytes"], json!(raw.len()), "{lim3}");
    let text2 = std::fs::read_to_string(&wal).unwrap();
    assert_eq!(text2.matches("\"t\":\"art_own\"").count(), 1, "{text2}");
    let g = a.rpc(&json!({"op": "art_get", "sha": sha})).unwrap();
    assert!(ok(&g), "{g}");
    let ab2 = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert_eq!(ab2["error"], json!("unknown upload"), "{ab2}");
    server.set_fixed_now(None);
}

// Abort treats already-gone staging (`NotFound`) as success (goal achieved,
// no counter bump, pops, unknown thereafter).
#[test]
fn abort_treats_already_gone_staging_as_success() {
    let (addr, wal, server) = start_handle("abort-notfound");
    server.set_fixed_now(Some(T0));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let init = a.rpc(&json!({"op": "art_init", "size": 4})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let art_dir = wal.parent().unwrap().join("artifacts");
    let staging = art_dir.join(format!(".up-{uid}"));
    assert!(staging.exists());
    // External sweep equivalent: staging already gone before abort.
    std::fs::remove_file(&staging).unwrap();
    let r = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert!(ok(&r), "{r}");
    let st = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st["stats"]["staging_cleanup_failed"], json!(0), "{st}");
    let r2 = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert_eq!(r2["error"], json!("unknown upload"), "{r2}");
    server.set_fixed_now(None);
}

// Global staging count bound denies with the count string and releases on
// abort (ordinary admission/rejection; staging denials touch no counter).
#[test]
fn staging_count_bound_denies_and_releases_on_wire() {
    let (addr, _wal, server) = start_handle("staging-count");
    server.set_fixed_now(Some(T0));
    server.set_staging_limits_for_test(art::StagingLimits::for_test(2, 8, 1 << 40, 1 << 40));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let u1 = a.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    assert!(ok(&u1), "{u1}");
    let u1 = u1["upload_id"].as_str().unwrap().to_string();
    let u2 = a.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    assert!(ok(&u2), "{u2}");
    let u2 = u2["upload_id"].as_str().unwrap().to_string();
    // Third init denied: bound hit, nothing reserved.
    let r = a.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    assert_eq!(r["error"], json!(art::STAGING_COUNT_ERROR), "{r}");
    // Abort one: the slot releases, the next init admits.
    assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": u1})).unwrap()));
    let u3 = a.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    assert!(ok(&u3), "{u3}");
    let u3 = u3["upload_id"].as_str().unwrap().to_string();
    // Denied inits never touched quota/cleanup counters (orthogonal).
    let st = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st["stats"]["quota_denied"], json!(0), "{st}");
    assert_eq!(st["stats"]["staging_cleanup_failed"], json!(0), "{st}");
    assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": u2})).unwrap()));
    assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": u3})).unwrap()));
    server.set_fixed_now(None);
}

// Per-owner count bound isolates agents; declared-byte bound denies with
// the bytes string and releases on abort (tiny configured limits).
#[test]
fn staging_per_owner_and_byte_bounds_on_wire() {
    let (addr, _wal, server) = start_handle("staging-owner-bytes");
    server.set_fixed_now(Some(T0));
    server.set_staging_limits_for_test(art::StagingLimits::for_test(8, 1, 1 << 40, 1 << 40));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut b = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let ua = a.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    assert!(ok(&ua), "{ua}");
    let ua = ua["upload_id"].as_str().unwrap().to_string();
    // Alice holds her 1 slot: her next init denies, bob's admits.
    let r = a.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    assert_eq!(r["error"], json!(art::STAGING_COUNT_ERROR), "{r}");
    let ub = b.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
    assert!(ok(&ub), "{ub}");
    let ub = ub["upload_id"].as_str().unwrap().to_string();
    assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": ua})).unwrap()));
    assert!(ok(&b.rpc(&json!({"op": "art_abort", "upload_id": ub})).unwrap()));
    // Byte bound: 60 admits, a further 50 (110 > 100) denies.
    server.set_staging_limits_for_test(art::StagingLimits::for_test(8, 8, 100, 1 << 40));
    let u60 = a.rpc(&json!({"op": "art_init", "size": 60})).unwrap();
    assert!(ok(&u60), "{u60}");
    let u60 = u60["upload_id"].as_str().unwrap().to_string();
    let r = a.rpc(&json!({"op": "art_init", "size": 50})).unwrap();
    assert_eq!(r["error"], json!(art::STAGING_BYTES_ERROR), "{r}");
    // Abort releases the bytes: the 50 admits afterwards.
    assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": u60})).unwrap()));
    let u50 = a.rpc(&json!({"op": "art_init", "size": 50})).unwrap();
    assert!(ok(&u50), "{u50}");
    let u50 = u50["upload_id"].as_str().unwrap().to_string();
    let st = a.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(st["stats"]["quota_denied"], json!(0), "{st}");
    assert_eq!(st["stats"]["staging_cleanup_failed"], json!(0), "{st}");
    assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": u50})).unwrap()));
    server.set_fixed_now(None);
}

// A retained commit-pending orphan keeps holding its staging reservation
// (aggregate retained state stays bounded): with a global limit of 1, no
// new init admits until the abort retry confirms cleanup and releases.
// Committed usage and the WAL receipt are untouched by the release.
#[test]
fn staging_pending_holds_reservation_until_abort_retry() {
    let (addr, wal, server) = start_handle("staging-pending-hold");
    server.set_fixed_now(Some(T0));
    server.set_staging_limits_for_test(art::StagingLimits::for_test(1, 8, 1 << 40, 1 << 40));
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let raw = b"pending-holds-slot";
    let init = a.rpc(&json!({"op": "art_init", "size": raw.len()})).unwrap();
    let uid = init["upload_id"].as_str().unwrap().to_string();
    let _ = a
        .rpc(&json!({
            "op": "art_chunk", "upload_id": uid, "off": 0,
            "data_b64": art::base64_encode(raw),
        }))
        .unwrap();
    server.set_artifact_unlink_failpoint_for_test(1);
    let c = a.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
    assert!(ok(&c), "{c}");
    assert!(c.get("staging_cleanup_error").is_some(), "{c}");
    // Pending holds the single slot: no new init admits.
    let r = a.rpc(&json!({"op": "art_init", "size": 1})).unwrap();
    assert_eq!(r["error"], json!(art::STAGING_COUNT_ERROR), "{r}");
    // Abort retry confirms cleanup, releases the slot, keeps the charge.
    let ab = a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap();
    assert!(ok(&ab), "{ab}");
    let u2 = a.rpc(&json!({"op": "art_init", "size": 1})).unwrap();
    assert!(ok(&u2), "{u2}");
    let u2 = u2["upload_id"].as_str().unwrap().to_string();
    let lim = a.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(raw.len()), "{lim}");
    let text = std::fs::read_to_string(&wal).unwrap();
    assert_eq!(text.matches("\"t\":\"art_own\"").count(), 1, "{text}");
    assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": u2})).unwrap()));
    server.set_fixed_now(None);
}

// Same-connection disconnect reaches the retained commit-pending cleanup
// arm (ownership is retained on `ok` + `staging_cleanup_error`): one
// bounded unlink attempt pops, releases the reservation, and keeps the
// committed receipt + charge (no uncharge, no second WAL append).
#[test]
fn disconnect_retries_commit_pending_cleanup_and_releases() {
    let (addr, wal, server) = start_handle("staging-pending-disconnect");
    server.set_fixed_now(Some(T0));
    server.set_staging_limits_for_test(art::StagingLimits::for_test(1, 8, 1 << 40, 1 << 40));
    let raw = b"disconnect-pending-slot";
    let (uid, sha) = {
        let mut c1 = Client::connect(&addr, "alice", "tok-alice").unwrap();
        let init = c1.rpc(&json!({"op": "art_init", "size": raw.len()})).unwrap();
        let uid = init["upload_id"].as_str().unwrap().to_string();
        let _ = c1
            .rpc(&json!({
                "op": "art_chunk", "upload_id": uid, "off": 0,
                "data_b64": art::base64_encode(raw),
            }))
            .unwrap();
        server.set_artifact_unlink_failpoint_for_test(1);
        let c = c1.rpc(&json!({"op": "art_commit", "upload_id": uid})).unwrap();
        assert!(ok(&c), "{c}");
        assert!(c.get("staging_cleanup_error").is_some(), "{c}");
        let sha = c["sha"].as_str().unwrap().to_string();
        // `c1` drops here: retained ownership drives one bounded
        // disconnect unlink attempt (the failpoint is already consumed,
        // so the real unlink succeeds).
        (uid, sha)
    };
    let art_dir = wal.parent().unwrap().join("artifacts");
    let staging = art_dir.join(format!(".up-{uid}"));
    // Poll the complete condition within the existing bounded deadline
    // (unknown + unlinked + single cleanup count, like the disconnect
    // abort test): proves the disconnect arm ran exactly once.
    let mut c2 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut clean = false;
    for _ in 0..50 {
        // Non-mutating probe (an `art_abort` probe would itself pop the
        // pending orphan and hide the disconnect arm): pending reports
        // `already committed...`, popped reports `unknown upload`.
        let probe = c2
            .rpc(&json!({
                "op": "art_chunk", "upload_id": uid, "off": 999,
                "data_b64": "",
            }))
            .unwrap();
        let unknown = probe["error"] == json!("unknown upload");
        let unlinked = !staging.exists();
        let st = c2.rpc(&json!({"op": "stats"})).unwrap();
        let counted_once = st["stats"]["staging_cleanup_failed"] == json!(1);
        if unknown && unlinked && counted_once {
            clean = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        clean,
        "disconnect must pop retained pending (unknown+unlink+count once)"
    );
    // Reservation released: a new init admits under the limit of 1.
    let u2 = c2.rpc(&json!({"op": "art_init", "size": 1})).unwrap();
    assert!(ok(&u2), "{u2}");
    let u2 = u2["upload_id"].as_str().unwrap().to_string();
    // Committed receipt + charge preserved, no double WAL/charge.
    let lim = c2.rpc(&json!({"op": "limits"})).unwrap();
    assert_eq!(lim["art_used_bytes"], json!(raw.len()), "{lim}");
    let text = std::fs::read_to_string(&wal).unwrap();
    assert_eq!(text.matches("\"t\":\"art_own\"").count(), 1, "{text}");
    assert!(text.contains(&sha), "{text}");
    let g = c2.rpc(&json!({"op": "art_get", "sha": sha})).unwrap();
    assert!(ok(&g), "{g}");
    assert!(ok(&c2.rpc(&json!({"op": "art_abort", "upload_id": u2})).unwrap()));
    server.set_fixed_now(None);
}

// Concurrent wire admissions respect the global count bound: 8 threads
// race a limit of 4, exactly 4 admit and 4 deny with the count string.
// Two-phase barriers keep every connection (and reservation) alive until
// all 8 inits have landed: without the hold, early disconnects would
// release slots and later inits would admit without contention.
#[test]
fn staging_concurrent_wire_admission_is_bounded() {
    let (addr, _wal, server) = start_handle("staging-wire-race");
    server.set_fixed_now(Some(T0));
    server.set_staging_limits_for_test(art::StagingLimits::for_test(4, 8, 1 << 40, 1 << 40));
    let start = std::sync::Arc::new(std::sync::Barrier::new(8));
    let release = std::sync::Arc::new(std::sync::Barrier::new(9));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let addr = addr.clone();
        let start = std::sync::Arc::clone(&start);
        let release = std::sync::Arc::clone(&release);
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
            start.wait();
            let r = c.rpc(&json!({"op": "art_init", "size": 10})).unwrap();
            tx.send(r).unwrap();
            release.wait();
        }));
    }
    drop(tx);
    // All 8 inits complete while every connection is still held open
    // (no abort, no disconnect release yet): exactly 4 admit. Counted
    // receives (never `for r in rx`): workers hold their `tx` until the
    // release barrier trips, so channel-close iteration would deadlock
    // against the main thread's own barrier arrival.
    let mut oks = Vec::new();
    let mut denied = 0;
    for _ in 0..8 {
        let r = rx.recv().expect("worker init result");
        if ok(&r) {
            oks.push(r["upload_id"].as_str().unwrap().to_string());
        } else {
            assert_eq!(r["error"], json!(art::STAGING_COUNT_ERROR), "{r}");
            denied += 1;
        }
    }
    assert_eq!(oks.len(), 4, "exactly the limit admits");
    assert_eq!(denied, 4);
    // Main aborts the 4 winners as their owner while workers are still
    // parked (deterministic release, no disconnect race), then lets the
    // workers drop (their disconnects find nothing and no-op).
    let mut a = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for uid in oks {
        assert!(ok(&a.rpc(&json!({"op": "art_abort", "upload_id": uid})).unwrap()));
    }
    release.wait();
    for h in handles {
        h.join().unwrap();
    }
    server.set_fixed_now(None);
}
