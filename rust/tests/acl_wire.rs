//! ACL wire integration: `acl::TokenStore` enforced over live `wire::Server`.
//!
//! No Python, no production IO: each test pins its own WAL file, fixture
//! tokens, and ephemeral loopback port. Proves the reviewed `acl.rs`
//! policy (expiry, Unicode/bracket grants, malformed fail-closed,
//! authenticated ownership, redaction) is the live wire decision, that
//! missing/null KV grants load without falsely enabling KV wire ops, that
//! rate configs validate fail-closed with wire enforcement (see
//! `rate_wire.rs`), that quota fields stay preserved-but-unenforced,
//! and that token ops enforce admin/claim auth (see `token_admin.rs`).
//! RPC deadlines/bounds and post/claim durability are preserved from the
//! existing wire slice (see `integration.rs`, `native_cli.rs`,
//! `process_durability.rs`).

use std::net::TcpListener;
use std::path::PathBuf;

use agent_bus::acl::{AclError, TokenStore};
use agent_bus::wire::{load_tokens, Client, Server};
use serde_json::json;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-aclwire-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn start_with(name: &str, tokens: TokenStore) -> (String, PathBuf) {
    let wal = wal_path(name);
    let _ = std::fs::remove_file(&wal);
    let server = Server::new(wal.clone(), tokens).expect("fresh WAL starts clean");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    (addr, wal)
}

fn ok(v: &serde_json::Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Raw hello reply without the `Client::connect` fixed diagnostic, so the
/// test asserts the exact server `error` string (`auth failed`,
/// `token expired`, `agent/token mismatch`).
fn hello_raw(addr: &str, agent: &str, token: &str) -> serde_json::Value {
    let mut c = Client::raw(addr).unwrap();
    c.rpc(&json!({"op": "hello", "agent": agent, "token": token}))
        .unwrap()
}

#[test]
fn hello_enforces_expiry_and_name_errors_over_wire() {
    let t = now();
    let tokens = TokenStore::from_json_str(&format!(
        r#"{{"tok-live": {{"agent": "w", "publish": ["*"], "subscribe": ["*"], "exp": {}}},
            "tok-exp": {{"agent": "w", "publish": ["*"], "subscribe": ["*"], "exp": {}}},
            "tok-scoped": {{"agent": "owner", "publish": ["board.*"], "subscribe": ["board.*"]}}}}"#,
        t + 3600.0,
        t - 60.0
    ))
    .unwrap();
    let (addr, _wal) = start_with("hello-exp", tokens);
    // Live token hellos keep working over the wire.
    assert!(Client::connect(&addr, "w", "tok-live").is_ok());
    // Expired token is denied with the legacy string.
    assert_eq!(
        hello_raw(&addr, "w", "tok-exp")["error"],
        json!("token expired")
    );
    // Unknown token and empty name stay generic.
    assert_eq!(
        hello_raw(&addr, "w", "tok-missing")["error"],
        json!("auth failed")
    );
    assert_eq!(hello_raw(&addr, "", "tok-live")["error"], json!("auth failed"));
    // Wrong owner is a mismatch, not generic.
    assert_eq!(
        hello_raw(&addr, "intruder", "tok-scoped")["error"],
        json!("agent/token mismatch")
    );
    assert!(Client::connect(&addr, "owner", "tok-scoped").is_ok());
}

#[test]
fn expiry_now_eq_exp_stays_live() {
    // Exact boundary is deterministic in pure policy (wire passes the same
    // `TokenStore::authenticate` with `now > exp` only): at `now == exp`
    // the token is live, one millisecond later it expires.
    const FIXED: f64 = 1_790_473_200.0;
    let store = TokenStore::from_json_str(&format!(
        r#"{{"tok-edge": {{"agent": "w", "exp": {FIXED}}}}}"#
    ))
    .unwrap();
    assert!(store.authenticate("tok-edge", "w", FIXED).is_ok());
    assert!(store.authenticate("tok-edge", "w", FIXED - 0.001).is_ok());
    assert_eq!(
        store.authenticate("tok-edge", "w", FIXED + 0.001),
        Err(AclError::TokenExpired)
    );
    // Wire liveness with a future expiry proves the same check runs live
    // (wall-clock races make an exact-equality wire probe flaky by design).
    let live = TokenStore::from_json_str(&format!(
        r#"{{"tok-future": {{"agent": "w", "publish": ["*"], "subscribe": ["*"], "exp": {}}}}}"#,
        now() + 3600.0
    ))
    .unwrap();
    let (addr, _wal) = start_with("hello-edge-live", live);
    assert!(Client::connect(&addr, "w", "tok-future").is_ok());
}

#[test]
fn claim_unicode_and_brackets_match_over_wire() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-uni": {"agent": "bootstrap", "claim": "café-*", "publish": ["*"], "subscribe": ["*"]},
            "tok-bkt": {"agent": "bootstrap", "claim": "user-[ab]", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("claim-unicode", tokens);
    // Unicode scalar claim: é matches as one value.
    assert!(Client::connect(&addr, "café-1", "tok-uni").is_ok());
    assert_eq!(
        hello_raw(&addr, "cafe-1", "tok-uni")["error"],
        json!("agent/token mismatch")
    );
    // Bracket claim is a class, not literal text.
    assert!(Client::connect(&addr, "user-a", "tok-bkt").is_ok());
    assert!(Client::connect(&addr, "user-b", "tok-bkt").is_ok());
    assert_eq!(
        hello_raw(&addr, "user-c", "tok-bkt")["error"],
        json!("agent/token mismatch")
    );
    assert_eq!(
        hello_raw(&addr, "user-[ab]", "tok-bkt")["error"],
        json!("agent/token mismatch")
    );
}

#[test]
fn publish_unicode_and_brackets_match_over_wire() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-pub": {
                "agent": "w",
                "publish": ["café-*", "board.[ab]", "exact.topic"],
                "subscribe": ["*"]
            }
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("pub-unicode", tokens);
    let mut c = Client::connect(&addr, "w", "tok-pub").unwrap();
    assert!(ok(&c
        .rpc(&json!({"op": "post", "topic": "café-1", "payload": 1}))
        .unwrap()));
    assert!(ok(&c
        .rpc(&json!({"op": "post", "topic": "board.a", "payload": 1}))
        .unwrap()));
    assert!(ok(&c
        .rpc(&json!({"op": "post", "topic": "board.b", "payload": 1}))
        .unwrap()));
    assert!(ok(&c
        .rpc(&json!({"op": "post", "topic": "exact.topic", "payload": 1}))
        .unwrap()));
    // Bracket grant does not match outside the class or literally.
    for denied in ["board.c", "board.[ab]", "café", "cafe-1", "other.x", ""] {
        let r = c
            .rpc(&json!({"op": "post", "topic": denied, "payload": 1}))
            .unwrap();
        assert_eq!(r["error"], json!(format!("publish denied: {denied}")), "{r}");
    }
}

#[test]
fn fetch_exactness_and_coverage_over_wire() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-fetch": {
                "agent": "w",
                "publish": ["*"],
                "subscribe": ["board.*", "inbox.w"]
            }
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("fetch-exact", tokens);
    let mut c = Client::connect(&addr, "w", "tok-fetch").unwrap();
    assert!(ok(&c
        .rpc(&json!({"op": "fetch", "topic": "board.build", "from_seq": 0}))
        .unwrap()));
    assert!(ok(&c
        .rpc(&json!({"op": "fetch", "topic": "inbox.w", "from_seq": 0}))
        .unwrap()));
    // Exactness guard (legacy `*?[`), empty, and uncovered topics deny.
    for denied in ["", "board.*", "board.?", "board[0]", "inbox.other", "other.x"] {
        let r = c
            .rpc(&json!({"op": "fetch", "topic": denied, "from_seq": 0}))
            .unwrap();
        assert_eq!(r["error"], json!(format!("fetch denied: {denied}")), "{r}");
    }
    // `]` alone is not in the legacy guard: coverage alone decides.
    let r = c
        .rpc(&json!({"op": "fetch", "topic": "board]", "from_seq": 0}))
        .unwrap();
    assert_eq!(r["error"], json!("fetch denied: board]"));
}

#[test]
fn authenticated_ownership_comes_from_hello_over_wire() {
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-a": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-b": {"agent": "bob", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("ownership", tokens);
    let mut a = Client::connect(&addr, "alice", "tok-a").unwrap();
    // Payload sender/owner fields are ignored: the broker stamps hello agent.
    let p = a
        .rpc(&json!({
            "op": "post",
            "topic": "t",
            "payload": {"sender": "bob", "owner": "bob", "n": 1}
        }))
        .unwrap();
    assert!(ok(&p), "{p}");
    let f = a
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    let msgs = f["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["sender"], json!("alice"));
    // Claims are owned by the hello agent too.
    let grant = a
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/own.rs", "ttl_ms": 60_000}))
        .unwrap();
    assert!(ok(&grant), "{grant}");
    assert_eq!(grant["owner"], json!("alice"));
    let mut b = Client::connect(&addr, "bob", "tok-b").unwrap();
    let conflict = b
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/own.rs", "ttl_ms": 60_000}))
        .unwrap();
    assert_eq!(conflict["holder"], json!("alice"));
}

#[test]
fn wire_errors_and_diagnostics_never_echo_tokens() {
    let secret = "test-only-token";
    let tokens = TokenStore::from_json_str(&format!(
        r#"{{"{secret}": {{"agent": "w", "publish": ["board.*"], "subscribe": ["board.*"]}}}}"#
    ))
    .unwrap();
    // Store Debug is counts-only.
    let debug = format!("{tokens:?}");
    assert!(!debug.contains(secret), "{debug}");
    let (addr, _wal) = start_with("redact", tokens);
    // Wrong token, mismatch, and denied ops echo no secret bytes.
    for (agent, token) in [
        ("w", "tok-wrong"),
        ("intruder", secret),
        ("", secret),
        ("w", ""),
    ] {
        let r = hello_raw(&addr, agent, token);
        let text = serde_json::to_string(&r).unwrap();
        assert!(!text.contains(secret), "{text}");
        // Server hello errors are fixed legacy strings.
        assert!(
            r.get("error").is_some(),
            "hello must refuse, got {r}"
        );
    }
    let mut c = Client::connect(&addr, "w", secret).unwrap();
    for req in [
        json!({"op": "post", "topic": "other.x", "payload": 1}),
        json!({"op": "fetch", "topic": "other.x", "from_seq": 0}),
    ] {
        let r = c.rpc(&req).unwrap();
        let text = serde_json::to_string(&r).unwrap();
        assert!(!text.contains(secret), "{text}");
    }
    // Client hello refusal is a constant (evil-echo safe).
    let err = match Client::connect(&addr, "w", "tok-wrong") {
        Ok(_) => panic!("wrong token must refuse"),
        Err(e) => e,
    };
    assert!(!err.to_string().contains("tok-wrong"));
    assert!(!err.to_string().contains(secret));
}

#[test]
fn malformed_tokens_fail_closed_without_echo() {
    let dir = std::env::temp_dir().join(format!(
        "agent-bus-aclwire-malformed-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = "tok-malformed-secret-001";
    let cases: Vec<(&str, String)> = vec![
        ("bad-pattern", format!(r#"{{"{secret}": {{"agent": "w", "publish": ["board.["]}}}}"#)),
        (
            "bad-grant-type",
            format!(r#"{{"{secret}": {{"agent": "w", "publish": "board.*"}}}}"#),
        ),
        (
            "null-publish",
            format!(r#"{{"{secret}": {{"agent": "w", "publish": null}}}}"#),
        ),
        ("bad-root-array", "[1, 2]".to_string()),
        ("bad-root-text", "{not json".to_string()),
    ];
    for (name, text) in cases {
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, &text).unwrap();
        let err = load_tokens(&path).expect_err(&format!("{name} must fail"));
        let msg = err.to_string();
        assert!(
            msg.contains("tokens.json invalid"),
            "{name}: {msg}"
        );
        assert!(!msg.contains(secret), "{name} leaks: {msg}");
    }
    // Non-UTF8 file also fails closed.
    let raw_path = dir.join("non-utf8.json");
    std::fs::write(&raw_path, [0xff, 0xfe, 0x0a]).unwrap();
    assert!(load_tokens(&raw_path).is_err());
    // Missing file fails closed (open mode is the explicit opt-in).
    assert!(load_tokens(&dir.join("no-such.json")).is_err());
}

#[test]
fn kv_grant_shapes_enable_acl_enforced_kv_wire() {
    // Missing, null, explicit-empty, and explicit KV grants all parse,
    // and the wire enforces them (KV gap closed per native-kv-wire-wal
    // integration): fallback/empty deny `bus.k`, explicit `bus.*` allows.
    // Pub/sub still works (KV fields never break it).
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-missing": {"agent": "a", "publish": ["board.*"], "subscribe": ["board.*"]},
            "tok-nulled": {"agent": "b", "publish": ["board.*"], "subscribe": ["board.*"], "kv_read": null, "kv_write": null},
            "tok-empty": {"agent": "c", "publish": ["board.*"], "subscribe": ["board.*"], "kv_read": [], "kv_write": []},
            "tok-explicit": {"agent": "d", "publish": ["board.*"], "subscribe": ["board.*"], "kv_read": ["bus.*"], "kv_write": ["bus.*"]}
        }"#,
    )
    .unwrap();
    // Fallback shapes are visible in policy (missing/null share pub/sub).
    assert!(tokens.get("tok-missing").unwrap().kv_read_grants().is_none());
    assert!(tokens.get("tok-nulled").unwrap().kv_read_grants().is_none());
    assert_eq!(
        tokens.get("tok-empty").unwrap().kv_read_grants().unwrap().len(),
        0
    );
    let (addr, _wal) = start_with("kv-shapes", tokens);
    // Fallback (board.*) and explicit-empty deny `bus.k`/`bus.`; explicit
    // `bus.*` allows (get finds nothing yet, put/del succeed, list empty).
    for (agent, token, allowed) in [
        ("a", "tok-missing", false),
        ("b", "tok-nulled", false),
        ("c", "tok-empty", false),
        ("d", "tok-explicit", true),
    ] {
        let mut c = Client::connect(&addr, agent, token).unwrap();
        // Pub/sub still works (KV fields never break it).
        assert!(ok(&c
            .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1}))
            .unwrap()));
        if allowed {
            let get = c.rpc(&json!({"op": "kv_get", "key": "bus.k"})).unwrap();
            assert_eq!(get["found"], json!(false), "{agent}: {get}");
            let put = c
                .rpc(&json!({"op": "kv_put", "key": "bus.k", "value": 1}))
                .unwrap();
            assert!(ok(&put), "{agent}: {put}");
            let listed = c.rpc(&json!({"op": "kv_list", "prefix": "bus."})).unwrap();
            assert!(ok(&listed), "{agent}: {listed}");
            let del = c.rpc(&json!({"op": "kv_del", "key": "bus.k"})).unwrap();
            assert_eq!(del["found"], json!(true), "{agent}: {del}");
        } else {
            for (op, req) in [
                ("kv_get", json!({"op": "kv_get", "key": "bus.k"})),
                ("kv_put", json!({"op": "kv_put", "key": "bus.k", "value": 1})),
                ("kv_list", json!({"op": "kv_list", "prefix": "bus."})),
                ("kv_del", json!({"op": "kv_del", "key": "bus.k"})),
            ] {
                let r = c.rpc(&req).unwrap();
                assert!(
                    r["error"].as_str().unwrap().contains("denied"),
                    "{agent} {op} should deny: {r}"
                );
            }
        }
    }
}

#[test]
fn rate_quota_and_token_admin_fields_are_preserved_not_enforced() {
    // Zero rates reject at load (fail-closed, no panic, no silent
    // unlimited); valid rates load with raw echo + validated config for
    // wire enforcement (see rate_wire.rs); quota/token-admin stay
    // preserved-but-unenforced.
    for bad in [
        r#"{"t": {"agent": "w", "rate_per_s": 0}}"#,
        r#"{"t": {"agent": "w", "topic_rates": {"board.*": 0}}}"#,
    ] {
        let err = TokenStore::from_json_str(bad).expect_err("zero must reject");
        assert!(!err.to_string().contains("tok-"), "echoed: {err}");
    }
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-limited": {
                "agent": "w",
                "publish": ["*"],
                "subscribe": ["*"],
                "rate_per_s": 10,
                "topic_rates": {"board.*": 5},
                "art_quota_bytes": 1
            }
        }"#,
    )
    .unwrap();
    let policy = tokens.get("tok-limited").unwrap();
    assert!(policy.extra().contains_key("rate_per_s"));
    assert!(policy.extra().contains_key("topic_rates"));
    assert!(policy.extra().contains_key("art_quota_bytes"));
    assert_eq!(policy.rate_config().global, Some(10.0));
    assert_eq!(policy.rate_config().rules.len(), 1);
    // ACL-only callers still get Unsupported (buckets live in wire).
    assert!(matches!(
        policy.enforce_rate_limit("board.build"),
        Err(AclError::Unsupported(_))
    ));
    assert!(matches!(
        policy.enforce_artifact_quota(1),
        Err(AclError::Unsupported(_))
    ));
    assert!(matches!(
        policy.enforce_token_admin(),
        Err(AclError::Unsupported(_))
    ));
    let (addr, _wal) = start_with("rate-valid", tokens);
    let mut c = Client::connect(&addr, "w", "tok-limited").unwrap();
    // First post succeeds (burst 5); quota never blocks (still a gap).
    let r = c
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 0}}))
        .unwrap();
    assert!(ok(&r), "valid rate/quota must allow first: {r}");
    // Token ops are live (see token_admin.rs): non-admin/claimless callers
    // hit auth negatives, never unknown-op. Quota stays the gap.
    for (op, want) in [
        ("token_issue", "admin required"),
        ("token_revoke", "admin required"),
        ("token_claim", "claim token required"),
    ] {
        let r = c.rpc(&json!({"op": op})).unwrap();
        assert_eq!(r["error"], json!(want), "{op}: {r}");
    }
}

#[test]
fn admin_needs_explicit_grants_like_legacy() {
    // Legacy has no admin publish/subscribe bypass (admin bypasses only
    // rate limits): an admin without grants denies, with ["*"] allows.
    let tokens = TokenStore::from_json_str(
        r#"{
            "tok-admin-bare": {"agent": "*"},
            "tok-admin-open": {"agent": "*", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .unwrap();
    let (addr, _wal) = start_with("admin-grants", tokens);
    let mut bare = Client::connect(&addr, "anyone", "tok-admin-bare").unwrap();
    let r = bare
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1}))
        .unwrap();
    assert_eq!(r["error"], json!("publish denied: board.build"));
    let r = bare
        .rpc(&json!({"op": "fetch", "topic": "board.build", "from_seq": 0}))
        .unwrap();
    assert_eq!(r["error"], json!("fetch denied: board.build"));
    let mut open = Client::connect(&addr, "anyone", "tok-admin-open").unwrap();
    assert!(ok(&open
        .rpc(&json!({"op": "post", "topic": "board.build", "payload": 1}))
        .unwrap()));
    assert!(ok(&open
        .rpc(&json!({"op": "fetch", "topic": "board.build", "from_seq": 0}))
        .unwrap()));
}
