//! Focused serial positive lease tests: wire acquire/status/list/renew/
//! release, sorted live-only projection with fixed-clock expiry, ordinary
//! idempotent retry, exact JSON receipts with no token in list, and CLI
//! lifecycle roundtrip, stdin `--token-file -` positive, plus `--` /
//! `--opt=value` forms.
//!
//! Ephemeral loopback servers, private temp WALs, fixed clocks, ordinary
//! sizes. No races, failpoints, floods, stress, or live services.

use agent_bus::acl::TokenStore;
use agent_bus::claims::{ClaimStore, VecWal};
use agent_bus::wal::snapshot_path_for;
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const T0: f64 = 1_790_000_000.0;

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn wal_path(name: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-leases-{name}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn open_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["*"], "subscribe": ["*"]},
            "tok-test": {"agent": "tester", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .expect("fixture tokens valid")
}

fn start(name: &str) -> (String, PathBuf, Server) {
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

fn run_cli(addr: &str, args: &[&str], stdin_data: Option<&str>) -> (i32, String, String) {
    let (host, port) = addr.rsplit_once(':').unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-bus"));
    cmd.args(args);
    cmd.env("AGENT_BUS_AGENT", "tester");
    cmd.env("AGENT_BUS_TOKEN", "tok-test");
    cmd.env_remove("AGENT_BUS_SOCK");
    cmd.env("AGENT_BUS_HOST", host);
    cmd.env("AGENT_BUS_PORT", port);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn agent-bus");
    if let Some(data) = stdin_data {
        use std::io::Write;
        let _ = child.stdin.as_mut().unwrap().write_all(data.as_bytes());
    }
    let out = child.wait_with_output().expect("wait agent-bus");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn store_list_live_is_sorted_compact_and_read_only() {
    let s = ClaimStore::new();
    let mut w = VecWal::default();
    // Out-of-order acquires; b expires quickly.
    let _ = s.acquire(&mut w, "alice", "repo/b.rs", 1_000, None, T0).unwrap();
    let _ = s.acquire(&mut w, "alice", "repo/a.rs", 60_000, None, T0).unwrap();
    let _ = s.acquire(&mut w, "bob", "repo/c.rs", 60_000, None, T0).unwrap();
    let wal_before = w.records.len();
    let stored_before = s.stored_len();
    // Live at T0: sorted [a, b, c], compact rows without tokens.
    let live = s.list_live(T0);
    assert_eq!(wal_before, w.records.len(), "listing writes no WAL");
    assert_eq!(stored_before, s.stored_len(), "listing purges nothing");
    assert_eq!(live.len(), 3);
    assert_eq!(live[0].resource, "repo/a.rs");
    assert_eq!(live[1].resource, "repo/b.rs");
    assert_eq!(live[2].resource, "repo/c.rs");
    assert_eq!(live[0].holder, "alice");
    assert_eq!(live[2].holder, "bob");
    assert!(live.iter().all(|l| l.fencing >= 1));
    // After b expiry: live-only [a, c].
    let live2 = s.list_live(T0 + 2.0);
    assert_eq!(live2.len(), 2);
    assert_eq!(live2[0].resource, "repo/a.rs");
    assert_eq!(live2[1].resource, "repo/c.rs");
    // Non-finite clock fails closed with empty, no mutation.
    assert!(s.list_live(f64::NAN).is_empty());
    assert!(s.list_live(f64::INFINITY).is_empty());
    assert_eq!(stored_before, s.stored_len());
}

#[test]
fn wire_serial_lifecycle_with_exact_receipts_and_no_token_in_list() {
    let (addr, _wal, server) = start("lifecycle");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Acquire: exact flat receipt with token for caller use.
    let g = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/a.rs", "ttl_ms": 60_000}))
        .unwrap();
    assert!(ok(&g), "{g}");
    assert_eq!(g["owner"], json!("alice"));
    assert_eq!(g["resource"], json!("repo/a.rs"));
    let token = g["token"].as_str().expect("acquire token").to_string();
    assert_eq!(token.len(), 32);
    assert_eq!(g["fencing"], json!(1));
    assert_eq!(g["acquired_at"], json!(T0));
    assert_eq!(g["expires_at"], json!(T0 + 60.0));
    // Status held mirrors the lease.
    let st = c.rpc(&json!({"op": "claim_status", "resource": "repo/a.rs"})).unwrap();
    assert!(ok(&st), "{st}");
    assert_eq!(st["owner"], json!("alice"));
    assert_eq!(st["token"], json!(token));
    assert_eq!(st["fencing"], json!(1));
    // List: one sorted row, exact keys, never a token.
    let li = c.rpc(&json!({"op": "claim_list"})).unwrap();
    assert!(ok(&li), "{li}");
    let leases = li["leases"].as_array().unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0]["resource"], json!("repo/a.rs"));
    assert_eq!(leases[0]["holder"], json!("alice"));
    assert_eq!(leases[0]["fencing"], json!(1));
    assert_eq!(leases[0]["expires_at"], json!(T0 + 60.0));
    assert!(leases[0].get("token").is_none(), "{li}");
    assert!(leases[0].get("acquired_at").is_none(), "{li}");
    // Renew extends expiry, same fencing/token.
    server.set_fixed_now(Some(T0 + 10.0));
    let rn = c
        .rpc(&json!({"op": "claim_renew", "resource": "repo/a.rs", "token": token, "ttl_ms": 60_000}))
        .unwrap();
    assert!(ok(&rn), "{rn}");
    assert_eq!(rn["token"], json!(token));
    assert_eq!(rn["fencing"], json!(1));
    assert_eq!(rn["expires_at"], json!(T0 + 70.0));
    // Release frees; status free and list empty.
    let rel = c
        .rpc(&json!({"op": "claim_release", "resource": "repo/a.rs", "token": token}))
        .unwrap();
    assert!(ok(&rel), "{rel}");
    assert_eq!(rel["released"], json!(true));
    assert_eq!(rel["resource"], json!("repo/a.rs"));
    let st2 = c.rpc(&json!({"op": "claim_status", "resource": "repo/a.rs"})).unwrap();
    assert!(ok(&st2), "{st2}");
    assert_eq!(st2["live"], json!(false));
    let li2 = c.rpc(&json!({"op": "claim_list"})).unwrap();
    assert!(ok(&li2), "{li2}");
    assert_eq!(li2["leases"].as_array().unwrap().len(), 0);
    server.set_fixed_now(None);
}

#[test]
fn wire_list_sorted_live_only_and_no_wal_write() {
    let (addr, wal, server) = start("sorted");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    // Out-of-order acquires with ordinary TTLs.
    for (r, ttl) in [("repo/b.rs", 1_000), ("repo/a.rs", 60_000), ("repo/c.rs", 60_000)] {
        let g = c.rpc(&json!({"op": "claim_acquire", "resource": r, "ttl_ms": ttl})).unwrap();
        assert!(ok(&g), "{g}");
    }
    let before = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert!(before > 0);
    let li = c.rpc(&json!({"op": "claim_list"})).unwrap();
    let after = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert_eq!(after, before, "claim_list performs no WAL IO");
    let names: Vec<String> = li["leases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["resource"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["repo/a.rs", "repo/b.rs", "repo/c.rs"]);
    for l in li["leases"].as_array().unwrap() {
        assert!(l.get("token").is_none(), "{li}");
    }
    // Expire b, release a: only c remains.
    server.set_fixed_now(Some(T0 + 2.0));
    let li2 = c.rpc(&json!({"op": "claim_list"})).unwrap();
    let names2: Vec<String> = li2["leases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["resource"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names2, vec!["repo/a.rs", "repo/c.rs"]);
    let st_a = c.rpc(&json!({"op": "claim_status", "resource": "repo/a.rs"})).unwrap();
    let tok_a = st_a["token"].as_str().unwrap().to_string();
    let rel = c.rpc(&json!({"op": "claim_release", "resource": "repo/a.rs", "token": tok_a})).unwrap();
    assert!(ok(&rel));
    let li3 = c.rpc(&json!({"op": "claim_list"})).unwrap();
    let names3: Vec<String> = li3["leases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["resource"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names3, vec!["repo/c.rs"]);
    server.set_fixed_now(None);
}

#[test]
fn wire_idempotent_retry_returns_current_live_state() {
    let (addr, _wal, server) = start("idem");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let g = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/d.rs", "ttl_ms": 10_000, "idempotency_key": "k1"}))
        .unwrap();
    assert!(ok(&g), "{g}");
    let token = g["token"].as_str().unwrap().to_string();
    // Ordinary retry: same key + same ttl returns the live lease.
    let dup = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/d.rs", "ttl_ms": 10_000, "idempotency_key": "k1"}))
        .unwrap();
    assert!(ok(&dup), "{dup}");
    assert_eq!(dup["token"], json!(token));
    assert_eq!(dup["fencing"], g["fencing"]);
    // Renew extends, then retry past the original expiry still reports current.
    server.set_fixed_now(Some(T0 + 2.0));
    let rn = c
        .rpc(&json!({"op": "claim_renew", "resource": "repo/d.rs", "token": token, "ttl_ms": 20_000}))
        .unwrap();
    assert!(ok(&rn), "{rn}");
    server.set_fixed_now(Some(T0 + 12.0));
    let dup2 = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/d.rs", "ttl_ms": 10_000, "idempotency_key": "k1"}))
        .unwrap();
    assert!(ok(&dup2), "{dup2}");
    assert_eq!(dup2["token"], json!(token));
    assert_eq!(dup2["expires_at"], rn["expires_at"]);
    server.set_fixed_now(None);
}

#[test]
fn cli_positive_lifecycle_roundtrip_with_token_file() {
    let (addr, _wal, server) = start("cli-life");
    server.set_fixed_now(Some(T0));
    // Acquire JSON: token preserved for caller use.
    let (st, out, err) = run_cli(&addr, &["claim-acquire", "repo/cli.rs", "--ttl-ms", "60000", "--format", "json"], None);
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    let g: Value = serde_json::from_str(out.trim()).unwrap();
    assert!(ok(&g), "{g}");
    let token = g["token"].as_str().unwrap().to_string();
    assert!(!token.is_empty());
    // Status JSON mirrors; list JSON has no token.
    let (st, out, _) = run_cli(&addr, &["claim-status", "repo/cli.rs", "--format", "json"], None);
    assert_eq!(st, 0, "{out}");
    let sv: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(sv["token"], json!(token));
    let (st, out, _) = run_cli(&addr, &["claim-list", "--format", "json"], None);
    assert_eq!(st, 0, "{out}");
    assert!(!out.contains(&token), "list must never include tokens: {out}");
    let lv: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(lv["leases"].as_array().unwrap().len(), 1);
    // Renew via token file, short output without token.
    let dir = std::env::temp_dir().join(format!("agent-bus-leases-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&dir).unwrap();
    let tok_path = dir.join("tok");
    std::fs::write(&tok_path, format!("{token}\n")).unwrap();
    let tok_str = tok_path.to_string_lossy().to_string();
    let (st, out, err) = run_cli(
        &addr,
        &["claim-renew", "repo/cli.rs", "--token-file", &tok_str, "--ttl-ms", "60000", "--format", "short"],
        None,
    );
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    assert!(out.starts_with("renewed repo/cli.rs fencing="), "{out}");
    assert!(!out.contains(&token), "{out}");
    assert!(!err.contains(&token), "{err}");
    // Release via token file, then status/list short show free/empty.
    let (st, out, _) = run_cli(
        &addr,
        &["claim-release", "repo/cli.rs", "--token-file", &tok_str, "--format", "short"],
        None,
    );
    assert_eq!(st, 0, "{out}");
    assert_eq!(out.trim(), "released repo/cli.rs");
    let (st, out, _) = run_cli(&addr, &["claim-status", "repo/cli.rs", "--format", "short"], None);
    assert_eq!(st, 0, "{out}");
    assert_eq!(out.trim(), "free repo/cli.rs");
    let (st, out, _) = run_cli(&addr, &["claim-list", "--format", "short"], None);
    assert_eq!(st, 0, "{out}");
    assert!(out.trim().is_empty(), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
    server.set_fixed_now(None);
}

#[test]
fn cli_token_file_stdin_positive() {
    let (addr, _wal, server) = start("cli-stdin");
    server.set_fixed_now(Some(T0));
    // Acquire JSON to obtain a caller token.
    let (st, out, err) = run_cli(
        &addr,
        &["claim-acquire", "repo/stdin.rs", "--ttl-ms", "60000", "--format", "json"],
        None,
    );
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    let g: Value = serde_json::from_str(out.trim()).unwrap();
    assert!(ok(&g), "{g}");
    let token = g["token"].as_str().unwrap().to_string();
    // Renew via `--token-file -` (stdin); tiny ordinary padded input.
    let (st, out, err) = run_cli(
        &addr,
        &[
            "claim-renew",
            "repo/stdin.rs",
            "--token-file",
            "-",
            "--ttl-ms",
            "60000",
            "--format",
            "short",
        ],
        Some(&format!("  {token}  \n")),
    );
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    assert!(out.starts_with("renewed repo/stdin.rs fencing="), "{out}");
    assert!(!out.contains(&token), "{out}");
    assert!(!err.contains(&token), "{err}");
    // Release via `--token`, then free.
    let (st, out, err) = run_cli(
        &addr,
        &["claim-release", "repo/stdin.rs", "--token", &token, "--format", "short"],
        None,
    );
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    assert_eq!(out.trim(), "released repo/stdin.rs");
    server.set_fixed_now(None);
}

#[test]
fn cli_supported_argument_forms_equals_and_terminator() {
    let (addr, _wal, server) = start("cli-forms");
    server.set_fixed_now(Some(T0));
    // Equals forms reach the wire.
    let (st, out, err) = run_cli(
        &addr,
        &["claim-acquire", "repo/equals.rs", "--ttl-ms=60000", "--format=json"],
        None,
    );
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    let g: Value = serde_json::from_str(out.trim()).unwrap();
    assert!(ok(&g), "{g}");
    let token = g["token"].as_str().unwrap().to_string();
    // Terminator before a positional resource.
    let (st, out, err) = run_cli(&addr, &["claim-status", "--", "repo/equals.rs"], None);
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    let sv: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(sv["token"], json!(token));
    // Equals + terminator on list (no positionals).
    let (st, out, err) = run_cli(&addr, &["claim-list", "--format=short", "--"], None);
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    assert!(out.contains("repo/equals.rs holder=tester"), "{out}");
    assert!(!out.contains(&token), "{out}");
    // Token file via equals form.
    let dir = std::env::temp_dir().join(format!("agent-bus-leases-forms-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&dir).unwrap();
    let tok_path = dir.join("tok");
    std::fs::write(&tok_path, &token).unwrap();
    let tok_arg = format!("--token-file={}", tok_path.to_string_lossy());
    let (st, out, err) = run_cli(
        &addr,
        &["claim-renew", "repo/equals.rs", &tok_arg, "--ttl-ms=60000", "--format=short"],
        None,
    );
    assert_eq!(st, 0, "stdout={out} stderr={err}");
    assert!(out.starts_with("renewed repo/equals.rs"), "{out}");
    let (st, out, _) = run_cli(&addr, &["claim-release", "repo/equals.rs", &tok_arg], None);
    assert_eq!(st, 0, "{out}");
    let rel: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(rel["released"], json!(true));
    let _ = std::fs::remove_dir_all(&dir);
    server.set_fixed_now(None);
}
