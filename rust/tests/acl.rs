//! Native ACL regressions: names, publish/subscribe, KV grants, wildcards.
//!
//! Pure in-memory policy tests with caller-provided JSON and time: no IO,
//! no threads, no env, no network, no broker, no filesystem. Every case
//! builds its policy from inline JSON fixtures and asserts decisions,
//! validation, and redaction without touching production state.

use agent_bus::acl::{
    covers, wildcard_match, AclError, Pattern, Policy, TokenStore,
};
use serde_json::json;

const NOW: f64 = 1_790_473_200.0;

fn policy(value: serde_json::Value) -> Policy {
    Policy::from_json(&value).expect("valid fixture policy")
}

fn newcomer() -> Policy {
    policy(json!({
        "agent": "newcomer-1",
        "publish": ["board.*", "inbox.*"],
        "subscribe": ["board.*", "inbox.newcomer-1"],
        "kv_read": ["bus.*", "ctx.*"],
        "kv_write": ["bus.*", "ctx.*"]
    }))
}

// ---------------------------------------------------------------------------
// Wildcards: *, ?, Unicode scalars
// ---------------------------------------------------------------------------

#[test]
fn star_matches_empty_dot_and_unicode() {
    assert_eq!(wildcard_match("", "*").unwrap(), true);
    assert_eq!(wildcard_match("board.build", "*").unwrap(), true);
    assert_eq!(wildcard_match("board.build", "board.*").unwrap(), true);
    assert_eq!(wildcard_match("board", "board.*").unwrap(), false);
    assert_eq!(wildcard_match("café-1", "café-*").unwrap(), true);
    assert_eq!(wildcard_match("", "board.*").unwrap(), false);
    // `**` collapses to `*`.
    assert_eq!(wildcard_match("a/b.c", "**").unwrap(), true);
}

#[test]
fn question_matches_exactly_one_scalar() {
    assert_eq!(wildcard_match("a", "?").unwrap(), true);
    assert_eq!(wildcard_match("", "?").unwrap(), false);
    assert_eq!(wildcard_match("ab", "?").unwrap(), false);
    assert_eq!(wildcard_match("board.X", "board.?").unwrap(), true);
    assert_eq!(wildcard_match("board.", "board.?").unwrap(), false);
    // Precomposed é is one scalar.
    assert_eq!(wildcard_match("é", "?").unwrap(), true);
    assert_eq!(wildcard_match("café", "caf?").unwrap(), true);
    // Case-sensitive: fnmatchcase, no folding.
    assert_eq!(wildcard_match("Board", "board").unwrap(), false);
}

#[test]
fn unicode_ranges_match_by_scalar_value() {
    // Greek alpha..omega includes beta, excludes ASCII.
    assert_eq!(wildcard_match("β", "[α-ω]").unwrap(), true);
    assert_eq!(wildcard_match("a", "[α-ω]").unwrap(), false);
    assert_eq!(wildcard_match("é", "[à-ÿ]").unwrap(), true);
    assert_eq!(wildcard_match("a", "[à-ÿ]").unwrap(), false);
}

// ---------------------------------------------------------------------------
// Wildcards: brackets
// ---------------------------------------------------------------------------

#[test]
fn brackets_match_sets_negations_and_ranges() {
    assert_eq!(wildcard_match("b", "[abc]").unwrap(), true);
    assert_eq!(wildcard_match("d", "[abc]").unwrap(), false);
    assert_eq!(wildcard_match("d", "[!abc]").unwrap(), true);
    assert_eq!(wildcard_match("b", "[!abc]").unwrap(), false);
    assert_eq!(wildcard_match("m", "[a-z]").unwrap(), true);
    assert_eq!(wildcard_match("5", "[a-z]").unwrap(), false);
    assert_eq!(wildcard_match("5", "[0-9]").unwrap(), true);
    // `^` is literal (only `!` negates).
    assert_eq!(wildcard_match("^", "[^ab]").unwrap(), true);
    assert_eq!(wildcard_match("c", "[^ab]").unwrap(), false);
    // Trailing/leading `-` is literal.
    assert_eq!(wildcard_match("-", "[a-]").unwrap(), true);
    assert_eq!(wildcard_match("-", "[-a]").unwrap(), true);
    assert_eq!(wildcard_match("b", "[a-]").unwrap(), false);
}

#[test]
fn brackets_leading_close_is_literal_member() {
    assert_eq!(wildcard_match("]", "[]]").unwrap(), true);
    assert_eq!(wildcard_match("a", "[]]").unwrap(), false);
    assert_eq!(wildcard_match("a", "[!]]").unwrap(), true);
    assert_eq!(wildcard_match("]", "[!]]").unwrap(), false);
}

#[test]
fn brackets_reject_unsupported_syntax_explicitly() {
    for bad in [
        "[",
        "[a",
        "[]",
        "[!]",
        "[z-a]",
        "a[b",
        "x[!]",
        "[a-b-c]",
        "[0-9-a-z]",
        "[a-b-c-d]",
    ] {
        let err = Pattern::new(bad).expect_err(&format!("{bad:?} must reject"));
        assert!(matches!(err, AclError::BadPattern(_)), "for {bad:?}: {err}");
        assert!(wildcard_match("anything", bad).is_err(), "for {bad:?}");
        // Rejection is explicit, never a literal match.
        assert!(
            !format!("{err}").is_empty(),
            "diagnostic must name the problem"
        );
    }
    // Unterminated `[` never matches literally (legacy would).
    assert!(wildcard_match("[", "[").is_err());
    assert!(wildcard_match("[]", "[]").is_err());
}

#[test]
fn brackets_reject_chained_ranges_without_widening() {
    // Chained/overlapping hyphen forms are ambiguous: legacy `fnmatch`
    // escapes the later `-` literally via its chunk join, while a naive
    // second-range parse would widen (e.g. `[0-9-a-z]` would match `:`).
    for bad in ["[a-b-c]", "[0-9-a-z]", "[a-a-b]", "[m-p-q-t]"] {
        assert!(
            Pattern::new(bad).is_err(),
            "{bad:?} must reject as overlapping"
        );
        assert!(wildcard_match("b", bad).is_err(), "for {bad:?}");
        assert!(wildcard_match(":", bad).is_err(), "for {bad:?}");
    }
    // Legacy supported single ranges plus literal `-` still work.
    assert_eq!(wildcard_match("b", "[a-c]").unwrap(), true);
    assert_eq!(wildcard_match("-", "[a-c-]").unwrap(), true);
    assert_eq!(wildcard_match("b", "[a-c-]").unwrap(), true);
    assert_eq!(wildcard_match("-", "[-a-c]").unwrap(), true);
    assert_eq!(wildcard_match("b", "[ab-cd]").unwrap(), true);
    assert_eq!(wildcard_match("a", "[ab-cd]").unwrap(), true);
    assert_eq!(wildcard_match("d", "[ab-cd]").unwrap(), true);
}

// ---------------------------------------------------------------------------
// Covers: conservative subscription logic
// ---------------------------------------------------------------------------

#[test]
fn covers_preserves_legacy_prefix_rules() {
    assert!(covers("board.build", "*"));
    assert!(covers("", "*"));
    assert!(covers("board.build", "board.build"));
    assert!(!covers("board.other", "board.build"));
    assert!(covers("board.build", "board.*"));
    assert!(covers("board.*", "board.*"));
    assert!(!covers("board", "board.*"));
    assert!(!covers("", "board.*"));
    // Middle `*` covers nothing, not even itself.
    assert!(!covers("board.*.x", "board.*.x"));
    assert!(!covers("board.a.x", "board.*.x"));
    // `?`/`[` are literal to covers (no `*` means exact only).
    assert!(covers("board.?", "board.?"));
    assert!(!covers("board.X", "board.?"));
    assert!(covers("board[0]", "board[0]"));
    assert!(!covers("board0", "board[0]"));
}

// ---------------------------------------------------------------------------
// Names: exact, admin, claim
// ---------------------------------------------------------------------------

#[test]
fn name_allowed_exact_admin_and_claim() {
    let exact = policy(json!({"agent": "muse-builder"}));
    assert!(exact.name_allowed("muse-builder"));
    assert!(!exact.name_allowed("muse-other"));
    assert!(!exact.name_allowed(""));

    let admin = policy(json!({"agent": "*"}));
    assert!(admin.name_allowed("anyone"));
    // Bare function preserves legacy (admin matches even empty);
    // authenticate() adds the hello empty-name guard.
    assert!(admin.name_allowed(""));

    let claimed = policy(json!({"agent": "bootstrap", "claim": "newcomer-*"}));
    assert!(claimed.name_allowed("bootstrap"));
    assert!(claimed.name_allowed("newcomer-7"));
    assert!(!claimed.name_allowed("other-7"));

    let empty_claim = policy(json!({"agent": "bootstrap", "claim": ""}));
    assert!(empty_claim.name_allowed("bootstrap"));
    assert!(!empty_claim.name_allowed("newcomer-7"));

    let missing = policy(json!({}));
    assert!(!missing.name_allowed("anyone"));
}

#[test]
fn authenticate_mirrors_hello_guards_without_echo() {
    let store = TokenStore::from_json_str(
        r#"{"tok-secret-001": {"agent": "muse-builder", "publish": ["board.*"]}}"#,
    )
    .unwrap();
    // Unknown token and empty name both fail as auth failed.
    assert_eq!(
        store.authenticate("tok-wrong", "muse-builder", NOW),
        Err(AclError::AuthFailed)
    );
    assert_eq!(
        store.authenticate("tok-secret-001", "", NOW),
        Err(AclError::AuthFailed)
    );
    assert_eq!(
        store.authenticate("tok-secret-001", "muse-other", NOW),
        Err(AclError::AgentMismatch)
    );
    assert!(store.authenticate("tok-secret-001", "muse-builder", NOW).is_ok());
    assert_eq!(format!("{}", AclError::AuthFailed), "auth failed");
    assert_eq!(format!("{}", AclError::AgentMismatch), "agent/token mismatch");
}

// ---------------------------------------------------------------------------
// Publish / subscribe / fetch
// ---------------------------------------------------------------------------

#[test]
fn can_publish_matches_any_grant_and_denies_empty() {
    let p = newcomer();
    assert!(p.can_publish("board.build"));
    assert!(p.can_publish("inbox.someone"));
    assert!(!p.can_publish("other.topic"));
    assert!(!p.can_publish(""));
    // Empty grant list denies everything.
    let denied = policy(json!({"agent": "x", "publish": []}));
    assert!(!denied.can_publish("board.build"));
}

#[test]
fn can_subscribe_uses_covers_and_denies_empty() {
    let p = newcomer();
    assert!(p.can_subscribe("board.build"));
    assert!(p.can_subscribe("board.*"));
    assert!(p.can_subscribe("inbox.newcomer-1"));
    assert!(!p.can_subscribe("inbox.other"));
    assert!(!p.can_subscribe(""));
    // Middle-star requests are covered only by prefix grants.
    assert!(p.can_subscribe("board.*.x"));
    let narrow = policy(json!({"agent": "x", "subscribe": ["board.*.x"]}));
    assert!(!narrow.can_subscribe("board.a.x"));
    assert!(!narrow.can_subscribe("board.*.x"));
}

#[test]
fn can_fetch_rejects_wildcard_topics_exactly_like_legacy() {
    let p = newcomer();
    assert!(p.can_fetch("board.build"));
    assert!(!p.can_fetch(""));
    assert!(!p.can_fetch("board.*"));
    assert!(!p.can_fetch("board.?"));
    assert!(!p.can_fetch("board[0]"));
    // `]` alone is not in the legacy `*?[` guard, so exactness passes
    // and only coverage decides (here uncovered).
    assert!(!p.can_fetch("board]"));
    let open = policy(json!({"agent": "*", "subscribe": ["*"]}));
    assert!(open.can_fetch("board]"));
    assert!(!open.can_fetch("board[0]"));
}

// ---------------------------------------------------------------------------
// KV: missing/null fallback vs explicit empty deny
// ---------------------------------------------------------------------------

#[test]
fn kv_missing_and_null_fall_back_to_pubsub() {
    // Missing kv_* falls back.
    let missing = policy(json!({
        "agent": "x",
        "publish": ["w.*"],
        "subscribe": ["r.*"]
    }));
    assert!(missing.kv_read_grants().is_none());
    assert!(missing.kv_write_grants().is_none());
    assert_eq!(
        missing.effective_kv_read().iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        vec!["r.*"]
    );
    assert_eq!(
        missing.effective_kv_write().iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        vec!["w.*"]
    );
    assert!(missing.can_kv_read("r.k"));
    assert!(!missing.can_kv_read("w.k"));
    assert!(missing.can_kv_write("w.k"));
    assert!(!missing.can_kv_write("r.k"));

    // Explicit null also falls back (JSON null == missing).
    let nulled = policy(json!({
        "agent": "x",
        "publish": ["w.*"],
        "subscribe": ["r.*"],
        "kv_read": null,
        "kv_write": null
    }));
    assert!(nulled.kv_read_grants().is_none());
    assert!(nulled.can_kv_read("r.k"));
    assert!(nulled.can_kv_write("w.k"));
}

#[test]
fn kv_explicit_empty_denies_without_fallback() {
    let denied = policy(json!({
        "agent": "x",
        "publish": ["*"],
        "subscribe": ["*"],
        "kv_read": [],
        "kv_write": []
    }));
    assert_eq!(denied.kv_read_grants().unwrap().len(), 0);
    assert!(!denied.can_kv_read("bus.k"));
    assert!(!denied.can_kv_write("bus.k"));
    assert!(!denied.can_kv_list("bus."));
    assert!(!denied.can_kv_list(""));
}

#[test]
fn kv_explicit_grants_replace_fallback() {
    let p = policy(json!({
        "agent": "x",
        "publish": ["w.*"],
        "subscribe": ["r.*"],
        "kv_read": ["ctx.*"],
        "kv_write": ["bus.*"]
    }));
    assert!(p.can_kv_read("ctx.k"));
    assert!(!p.can_kv_read("r.k"));
    assert!(p.can_kv_write("bus.k"));
    assert!(!p.can_kv_write("w.k"));
}

#[test]
fn kv_list_prefix_uses_covers_over_effective_read() {
    let p = newcomer();
    assert!(p.can_kv_list("bus."));
    assert!(p.can_kv_list("ctx.alpha"));
    assert!(!p.can_kv_list("other."));
    // Empty prefix is not covered by scoped grants (legacy behavior).
    assert!(!p.can_kv_list(""));
    let open = policy(json!({"agent": "*", "subscribe": ["*"]}));
    assert!(open.can_kv_list(""));
}

// ---------------------------------------------------------------------------
// Filtering before caps
// ---------------------------------------------------------------------------

#[test]
fn filter_helpers_apply_before_any_cap() {
    let p = newcomer();
    // Topics: only covered names survive, in order.
    let topics = ["board.a", "other.x", "board.b", "inbox.newcomer-1", "inbox.other"];
    assert_eq!(
        p.filter_topics(topics),
        vec!["board.a", "board.b", "inbox.newcomer-1"]
    );
    // Keys: only readable names survive, in order.
    let keys = ["bus.a", "other.x", "ctx.b"];
    assert_eq!(p.filter_keys(keys), vec!["bus.a", "ctx.b"]);

    // Before-cap proof: 1005 denied then 5 allowed must yield 5, not 0.
    // A caller that truncated to 1000 first would lose every allowed key.
    let mut many: Vec<String> = (0..1005).map(|i| format!("denied.{i}")).collect();
    many.extend((0..5).map(|i| format!("bus.{i}")));
    let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
    let visible = p.filter_keys(refs);
    assert_eq!(visible.len(), 5);
    assert!(visible.iter().all(|k| k.starts_with("bus.")));
}

// ---------------------------------------------------------------------------
// Malformed grants and roots
// ---------------------------------------------------------------------------

#[test]
fn malformed_grant_types_are_rejected() {
    // publish/subscribe: null and non-lists rejected (legacy would crash).
    for (field, bad) in [
        ("publish", json!(null)),
        ("publish", json!("board.*")),
        ("publish", json!(123)),
        ("publish", json!({"g": "board.*"})),
        ("subscribe", json!(null)),
        ("subscribe", json!("board.*")),
    ] {
        let err = Policy::from_json(&json!({"agent": "x", field: bad}))
            .expect_err(&format!("{field}={bad} must reject"));
        assert!(matches!(err, AclError::BadPolicy(_)), "{err}");
    }
    // List elements must be strings.
    let err = Policy::from_json(&json!({"agent": "x", "publish": ["board.*", 7]}))
        .expect_err("non-string grant must reject");
    assert!(matches!(err, AclError::BadPolicy(_)));
    // kv_* may be null (fallback) but not strings/numbers.
    assert!(Policy::from_json(&json!({"agent": "x", "kv_read": null})).is_ok());
    for bad in [json!("bus.*"), json!(7), json!({"g": 1})] {
        assert!(
            Policy::from_json(&json!({"agent": "x", "kv_read": bad})).is_err(),
            "kv_read={bad} must reject"
        );
    }
    // agent/claim must be strings; exp must be a number.
    for bad in [json!(7), json!(["x"]), json!({"a": 1}), json!(true)] {
        assert!(Policy::from_json(&json!({"agent": bad})).is_err());
        assert!(Policy::from_json(&json!({"agent": "x", "claim": bad})).is_err());
    }
    for bad in [json!("tomorrow"), json!([1.0]), json!(true)] {
        assert!(Policy::from_json(&json!({"agent": "x", "exp": bad})).is_err());
    }
    // Bad glob syntax inside grants rejects the policy.
    let err = Policy::from_json(&json!({"agent": "x", "publish": ["board.[", "ok.*"]}))
        .expect_err("bad glob must reject");
    assert!(matches!(err, AclError::BadPolicy(_)));
    assert!(format!("{err}").contains("publish[0]"));
    let err = Policy::from_json(&json!({"agent": "x", "claim": "[z-a]"}))
        .expect_err("bad claim must reject");
    assert!(matches!(err, AclError::BadPolicy(_)));
}

#[test]
fn malformed_token_roots_are_rejected() {
    assert!(matches!(
        TokenStore::from_root(&json!([1, 2])),
        Err(AclError::BadRoot(_))
    ));
    assert!(matches!(
        TokenStore::from_root(&json!("tok")),
        Err(AclError::BadRoot(_))
    ));
    assert!(matches!(
        TokenStore::from_json_str("{not json"),
        Err(AclError::BadRoot(_))
    ));
    // Non-object values are meta, not errors.
    let store = TokenStore::from_root(&json!({
        "_note": "rotation 2026-09",
        "tok-a": {"agent": "a", "publish": ["board.*"]}
    }))
    .unwrap();
    assert_eq!(store.len(), 1);
    assert_eq!(store.meta().get("_note").unwrap(), &json!("rotation 2026-09"));
}

#[test]
fn bad_entries_report_index_without_token_echo() {
    let secret = "tok-supersecret-9f8e7d6c5b4a";
    let root = json!({
        "_note": "meta stays",
        "tok-good": {"agent": "good", "publish": ["board.*"]},
        secret: {"agent": "bad", "publish": "not-a-list"}
    });
    let err = TokenStore::from_root(&root).expect_err("bad entry must reject");
    match &err {
        AclError::BadEntry { index, reason } => {
            // Index counts token (object) entries in sorted-key order:
            // good=0, bad=1 (`_` sorts before `t`, `g` before `s`).
            assert_eq!(*index, 1);
            assert!(reason.contains("publish"));
        }
        other => panic!("expected BadEntry, got {other:?}"),
    }
    let display = format!("{err}");
    let debug = format!("{err:?}");
    assert!(!display.contains(secret), "display leaks: {display}");
    assert!(!debug.contains(secret), "debug leaks: {debug}");
    assert!(display.contains("bad token entry 1"));
}

#[test]
fn bad_entry_index_uses_sorted_key_order_not_document_order() {
    // JSON text lists `tok-zzz-good` before `tok-aaa-bad`, but with
    // current serde features the map iterates in `BTreeMap` sorted-key
    // order, so the bad `tok-aaa-*` entry is index 0, not 1.
    let text = r#"{
        "tok-zzz-good": {"agent": "good", "publish": ["board.*"]},
        "tok-aaa-bad": {"agent": "bad", "publish": "not-a-list"}
    }"#;
    let err = TokenStore::from_json_str(text).expect_err("bad entry must reject");
    match &err {
        AclError::BadEntry { index, reason } => {
            assert_eq!(*index, 0);
            assert!(reason.contains("publish"));
        }
        other => panic!("expected BadEntry, got {other:?}"),
    }
    assert!(format!("{err}").contains("bad token entry 0"));
}

// ---------------------------------------------------------------------------
// Redaction, unknown fields, expiry, unsupported
// ---------------------------------------------------------------------------

#[test]
fn token_store_diagnostics_never_echo_secrets() {
    let secret = "test-only-token";
    let store = TokenStore::from_json_str(&format!(
        r#"{{"{secret}": {{"agent": "muse-builder", "publish": ["board.*"]}}}}"#
    ))
    .unwrap();
    // Debug shows counts only for both maps.
    let debug = format!("{store:?}");
    assert!(!debug.contains(secret), "store debug leaks: {debug}");
    assert!(debug.contains("entries"));
    assert!(debug.contains("meta"));
    // Auth failures never echo the presented token.
    for (token, claimed) in [
        ("tok-wrong", "muse-builder"),
        (secret, "muse-other"),
        ("", "muse-builder"),
    ] {
        let err = store.authenticate(token, claimed, NOW).expect_err("must fail");
        let display = format!("{err}");
        let err_debug = format!("{err:?}");
        assert!(!display.contains(token) || token.is_empty(), "{display}");
        assert!(!display.contains(secret), "{display}");
        assert!(!err_debug.contains(secret), "{err_debug}");
    }
}

#[test]
fn token_store_debug_redacts_meta_to_counts_with_sentinels() {
    // Non-secret sentinel meta keys/values must not appear in `Debug`:
    // both maps report counts only. Sentinels are chosen to be
    // obviously fake (not real tokens) while still proving redaction
    // across string/number/bool/array shapes.
    let sentinel_key = "_sentinel_meta_key_001";
    let sentinel_value = "sentinel-meta-value-001";
    let store = TokenStore::from_root(&json!({
        sentinel_key: sentinel_value,
        "_sentinel_num_002": 12345,
        "_sentinel_flag_003": true,
        "_sentinel_list_004": ["a", "b"],
        "tok-sentinel-entry-001": {"agent": "x", "publish": ["board.*"]}
    }))
    .unwrap();
    assert_eq!(store.len(), 1);
    assert_eq!(store.meta().len(), 4);
    let debug = format!("{store:?}");
    for sentinel in [
        sentinel_key,
        sentinel_value,
        "12345",
        "_sentinel_flag_003",
        "_sentinel_list_004",
        "tok-sentinel-entry-001",
    ] {
        assert!(!debug.contains(sentinel), "debug leaks {sentinel:?}: {debug}");
    }
    // Counts are visible: 1 entry, 4 meta.
    assert!(debug.contains("entries"), "{debug}");
    assert!(debug.contains('1'), "{debug}");
    assert!(debug.contains("meta"), "{debug}");
    assert!(debug.contains('4'), "{debug}");

    // Boundary: empty store and meta-only store also show counts only.
    let empty = TokenStore::from_root(&json!({})).unwrap();
    let debug_empty = format!("{empty:?}");
    assert!(debug_empty.contains("entries"), "{debug_empty}");
    assert!(debug_empty.contains("meta"), "{debug_empty}");

    let meta_only = TokenStore::from_root(&json!({
        "_sentinel_only_005": "sentinel-only-value-005"
    }))
    .unwrap();
    assert!(meta_only.is_empty());
    let debug_meta = format!("{meta_only:?}");
    assert!(
        !debug_meta.contains("sentinel-only-value-005"),
        "{debug_meta}"
    );
    assert!(!debug_meta.contains("_sentinel_only_005"), "{debug_meta}");
}

#[test]
fn authenticate_rejects_nonfinite_time_before_other_checks() {
    let store = TokenStore::from_json_str(
        r#"{"tok-live-001": {"agent": "x", "publish": ["board.*"]}}"#,
    )
    .unwrap();
    for now in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            store.authenticate("tok-live-001", "x", now),
            Err(AclError::NonFiniteTime),
            "now={now:?} must reject"
        );
        // Invalid clock wins even when other inputs would also fail.
        assert_eq!(
            store.authenticate("tok-missing", "x", now),
            Err(AclError::NonFiniteTime),
            "now={now:?} must win over unknown token"
        );
        assert_eq!(
            store.authenticate("tok-live-001", "", now),
            Err(AclError::NonFiniteTime),
            "now={now:?} must win over empty name"
        );
    }
    assert_eq!(format!("{}", AclError::NonFiniteTime), "non-finite time");
    // Finite clocks still authenticate.
    assert!(store.authenticate("tok-live-001", "x", NOW).is_ok());
}

#[test]
fn unknown_policy_fields_are_preserved_not_enforced() {
    let p = policy(json!({
        "agent": "x",
        "publish": ["board.*"],
        "rate_per_s": 5.0,
        "topic_rates": {"board.*": 1.0},
        "art_quota_bytes": 1024,
        "custom_future": {"nested": [1, 2]}
    }));
    assert_eq!(p.extra().get("rate_per_s").unwrap(), &json!(5.0));
    assert_eq!(p.extra().get("art_quota_bytes").unwrap(), &json!(1024));
    assert!(p.extra().contains_key("topic_rates"));
    assert!(p.extra().contains_key("custom_future"));
    // Enforcement is explicitly unsupported, never implied.
    assert!(matches!(
        p.enforce_rate_limit("board.build"),
        Err(AclError::Unsupported(_))
    ));
    assert!(matches!(
        p.enforce_artifact_quota(1),
        Err(AclError::Unsupported(_))
    ));
    assert!(matches!(p.enforce_token_admin(), Err(AclError::Unsupported(_))));
}

#[test]
fn expiry_boundary_matches_hello_now_gt_exp() {
    let live = policy(json!({"agent": "x", "exp": NOW}));
    assert!(!live.is_expired(NOW));
    assert!(!live.is_expired(NOW - 0.001));
    assert!(live.is_expired(NOW + 0.001));
    let none = policy(json!({"agent": "x"}));
    assert!(!none.is_expired(f64::MAX));
    assert!(!none.is_expired(NOW));

    let store = TokenStore::from_root(&json!({
        "tok-exp": {"agent": "x", "exp": NOW - 1.0},
        "tok-live": {"agent": "x", "exp": NOW}
    }))
    .unwrap();
    assert_eq!(
        store.authenticate("tok-exp", "x", NOW),
        Err(AclError::TokenExpired)
    );
    assert_eq!(format!("{}", AclError::TokenExpired), "token expired");
    assert!(store.authenticate("tok-live", "x", NOW).is_ok());
}

#[test]
fn error_display_strings_are_stable() {
    assert_eq!(
        format!("{}", AclError::BadRoot("x".to_string())),
        "bad token root: x"
    );
    assert_eq!(
        format!(
            "{}",
            AclError::BadEntry { index: 2, reason: "publish must be a list".to_string() }
        ),
        "bad token entry 2: publish must be a list"
    );
    assert!(format!("{}", AclError::BadPattern("p".to_string())).starts_with("bad pattern: "));
    assert!(format!("{}", AclError::Unsupported("r".to_string())).starts_with("unsupported: "));
    assert_eq!(format!("{}", AclError::NonFiniteTime), "non-finite time");
}
