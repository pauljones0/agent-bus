//! Native KV core regressions: validate-before-durability, mutate-after.
//!
//! Pure in-memory tests with caller-provided time: no IO, no threads, no
//! broker. Covers record shapes, TTL/expiry boundaries, failed-commit
//! preservation, JSON-null handling, sorted/capped lists, deterministic
//! replay (including the no-resurrection tombstone rule), snapshots, and
//! malformed-record tolerance.

use agent_bus::kv::{
    expired, expiry_for_ttl, KvError, KvStore, LineOutcome, KV_LIST_LIMIT,
};
use serde_json::{json, Value};

const NOW: f64 = 1_790_000_000.0;

fn commit_ok_put(store: &mut KvStore, key: &str, value: Value, ttl_ms: Option<i64>, now: f64) {
    let pending = store.prepare_put(key, value, ttl_ms, now).expect("valid put");
    store.commit_put(pending, |_: &str| Ok::<(), String>(())).expect("durable");
}

fn commit_ok_delete(store: &mut KvStore, key: &str) -> bool {
    let pending = store.prepare_delete(key).expect("valid delete");
    store.commit_delete(pending, |_: &str| Ok::<(), String>(())).expect("durable")
}

#[test]
fn prepare_rejects_empty_key_before_any_durability() {
    let store = KvStore::new();
    // Rejection happens at prepare time, so no pending value exists that
    // a caller could commit to durability.
    assert_eq!(
        store.prepare_put("", json!(1), None, NOW),
        Err(KvError::EmptyKey)
    );
    assert_eq!(store.prepare_delete(""), Err(KvError::EmptyKey));
    assert_eq!(format!("{}", KvError::EmptyKey), "key required");
}

#[test]
fn prepare_rejects_nonfinite_time_before_any_durability() {
    let store = KvStore::new();
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            store.prepare_put("k", json!(1), None, bad),
            Err(KvError::NonFiniteTime),
            "for now={bad}"
        );
        assert_eq!(
            store.prepare_put("k", json!(1), Some(1_000), bad),
            Err(KvError::NonFiniteTime),
            "for now={bad} with ttl"
        );
    }
    assert_eq!(format!("{}", KvError::NonFiniteTime), "non-finite time");

    // No pending value exists to commit, so durability is unreachable.
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "k", json!("old"), None, NOW);
    let before = store.clone();
    assert!(store.prepare_put("k", json!("new"), None, f64::NAN).is_err());
    assert_eq!(store, before);
}

#[test]
fn accepted_times_round_trip_between_json_and_state() {
    // Finite expiries must survive serde without the NaN/Inf->null
    // divergence: record JSON exp equals staged and stored exp.
    let cases: Vec<(Option<i64>, f64)> = vec![
        (None, NOW),
        (Some(0), NOW),
        (Some(1_500), NOW),
        (Some(-1_000), NOW),
        (Some(60_000), 0.0),
        (Some(i64::MAX), 1_000.0),
        (Some(i64::MIN), 1_000.0),
    ];
    for (ttl, now) in cases {
        let mut store = KvStore::new();
        let pending = store
            .prepare_put("k", json!({"n": 1}), ttl, now)
            .expect("finite times accepted");
        let parsed: Value = serde_json::from_str(pending.record_line()).unwrap();
        match pending.exp() {
            None => assert_eq!(parsed.get("exp"), Some(&Value::Null)),
            Some(e) => {
                assert!(e.is_finite());
                let json_exp = parsed.get("exp").and_then(|v| v.as_f64()).unwrap();
                assert_eq!(json_exp, e);
            }
        }
        store
            .commit_put(pending, |_: &str| Ok::<(), String>(()))
            .unwrap();
        let stored = store.stored("k").unwrap();
        assert_eq!(stored.exp, expiry_for_ttl(ttl, now));
        if let Some(e) = stored.exp {
            assert!(e.is_finite());
        }
    }
}

#[test]
fn ttl_rules_match_legacy_falsy_semantics() {
    assert_eq!(expiry_for_ttl(None, NOW), None);
    assert_eq!(expiry_for_ttl(Some(0), NOW), None);
    assert_eq!(expiry_for_ttl(Some(1_500), NOW), Some(NOW + 1.5));
    assert_eq!(expiry_for_ttl(Some(-1_000), NOW), Some(NOW - 1.0));

    let mut store = KvStore::new();
    commit_ok_put(&mut store, "plain", json!(1), None, NOW);
    commit_ok_put(&mut store, "zero", json!(1), Some(0), NOW);
    commit_ok_put(&mut store, "neg", json!(1), Some(-1_000), NOW);
    assert_eq!(store.stored("plain").unwrap().exp, None);
    assert_eq!(store.stored("zero").unwrap().exp, None);
    // Negative TTL is a valid write that is already expired for reads.
    assert_eq!(store.stored("neg").unwrap().exp, Some(NOW - 1.0));
    assert_eq!(store.get("neg", NOW), None);
}

#[test]
fn expiry_boundary_now_equal_exp_is_live() {
    assert!(!expired(None, NOW));
    assert!(!expired(Some(NOW), NOW));
    assert!(expired(Some(NOW), NOW + 0.001));
    assert!(!expired(Some(NOW + 10.0), NOW));

    let mut store = KvStore::new();
    commit_ok_put(&mut store, "k", json!("v"), Some(10_000), NOW);
    let exp = NOW + 10.0;
    assert_eq!(store.get("k", exp), Some(&json!("v")));
    assert_eq!(store.get("k", exp + 0.001), None);
}

#[test]
fn record_lines_are_canonical_compact_shapes() {
    let store = KvStore::new();
    let put = store
        .prepare_put("k", json!({"a": [1, null]}), Some(1_500), NOW)
        .unwrap();
    assert_eq!(
        put.record_line(),
        r#"{"t":"kv","key":"k","value":{"a":[1,null]},"exp":1790000001.5}"#
    );
    let bare = store.prepare_put("k", Value::Null, None, NOW).unwrap();
    assert_eq!(bare.record_line(), r#"{"t":"kv","key":"k","value":null,"exp":null}"#);
    let del = store.prepare_delete("k").unwrap();
    assert_eq!(del.record_line(), r#"{"t":"kv_del","key":"k"}"#);
}

#[test]
fn commit_put_applies_only_after_durability_succeeds() {
    let mut store = KvStore::new();
    let pending = store.prepare_put("k", json!([1, 2]), None, NOW).unwrap();
    assert_eq!(store.get("k", NOW), None);
    let mut seen: Vec<String> = Vec::new();
    store
        .commit_put(pending, |line: &str| {
            seen.push(line.to_string());
            Ok::<(), String>(())
        })
        .unwrap();
    assert_eq!(seen.len(), 1);
    let parsed: Value = serde_json::from_str(&seen[0]).unwrap();
    assert_eq!(parsed, json!({"t": "kv", "key": "k", "value": [1, 2], "exp": null}));
    assert_eq!(store.get("k", NOW), Some(&json!([1, 2])));
}

#[test]
fn failed_put_commit_preserves_prior_state() {
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "k", json!({"old": true}), Some(60_000), NOW);
    let before = store.clone();

    let pending = store.prepare_put("k", json!({"new": true}), None, NOW).unwrap();
    let err = store
        .commit_put(pending, |_: &str| Err::<(), String>("fsync failed".to_string()))
        .unwrap_err();
    assert_eq!(err, "fsync failed");
    assert_eq!(store, before);
    assert_eq!(store.get("k", NOW), Some(&json!({"old": true})));
    assert_eq!(store.stored("k").unwrap().exp, Some(NOW + 60.0));

    // A failed put for an absent key leaves it absent.
    let pending = store.prepare_put("ghost", json!(1), None, NOW).unwrap();
    let _ = store
        .commit_put(pending, |_: &str| Err::<(), String>("e".to_string()))
        .unwrap_err();
    assert_eq!(store.get("ghost", NOW), None);
    assert_eq!(store.len(), 1);
}

#[test]
fn failed_delete_commit_preserves_key() {
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "k", Value::Null, Some(60_000), NOW);
    let before = store.clone();

    let pending = store.prepare_delete("k").unwrap();
    assert!(pending.found());
    let err = store
        .commit_delete(pending, |_: &str| Err::<(), String>("e".to_string()))
        .unwrap_err();
    assert_eq!(err, "e");
    assert_eq!(store, before);
}

#[test]
fn delete_null_value_reports_found_true() {
    // Legacy correction: `pop(...) is not None` reported false for null.
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "k", Value::Null, None, NOW);
    assert_eq!(store.get("k", NOW), Some(&Value::Null));
    let pending = store.prepare_delete("k").unwrap();
    assert!(pending.found());
    assert!(store.commit_delete(pending, |_: &str| Ok::<(), String>(())).unwrap());
    assert_eq!(store.get("k", NOW), None);
    assert!(store.is_empty());
}

#[test]
fn delete_missing_key_reports_false_but_still_durables() {
    // Legacy appends kv_del even for absent keys; the tombstone survives.
    let mut store = KvStore::new();
    let pending = store.prepare_delete("ghost").unwrap();
    assert!(!pending.found());
    let mut calls = 0;
    let found = store
        .commit_delete(pending, |_: &str| {
            calls += 1;
            Ok::<(), String>(())
        })
        .unwrap();
    assert!(!found);
    assert_eq!(calls, 1);
}

#[test]
fn delete_reports_found_for_expired_but_stored_key() {
    // Legacy delete ignores expiry (presence-only pop); preserved.
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "k", json!(1), Some(1_000), NOW);
    assert_eq!(store.get("k", NOW + 5.0), None);
    assert!(store.stored("k").is_some());
    assert!(commit_ok_delete(&mut store, "k"));
}

#[test]
fn json_null_round_trips_through_value_paths() {
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "n", Value::Null, None, NOW);
    assert_eq!(store.get("n", NOW), Some(&Value::Null));
    assert_eq!(store.list("", NOW), vec!["n".to_string()]);
    let snap = store.snapshot(NOW);
    assert_eq!(snap.kv.get("n"), Some(&Value::Null));

    let mut restored = KvStore::new();
    restored.restore_snapshot(&store.snapshot_json(NOW)).unwrap();
    assert_eq!(restored.get("n", NOW), Some(&Value::Null));
}

#[test]
fn list_is_sorted_prefixed_live_and_capped() {
    let mut store = KvStore::new();
    for key in ["ctx.b", "bus.a", "ctx.a", "other", "ctx.exp"] {
        let ttl = if key == "ctx.exp" { Some(1_000) } else { None };
        commit_ok_put(&mut store, key, json!(1), ttl, NOW);
    }
    assert_eq!(store.list("ctx.", NOW + 5.0), vec!["ctx.a".to_string(), "ctx.b".to_string()]);
    assert_eq!(
        store.list("", NOW + 5.0),
        vec!["bus.a".to_string(), "ctx.a".to_string(), "ctx.b".to_string(), "other".to_string()]
    );
    assert!(store.list("zzz", NOW).is_empty());

    let mut big = KvStore::new();
    for i in 0..(KV_LIST_LIMIT + 5) {
        let key = format!("k-{i:05}");
        commit_ok_put(&mut big, &key, json!(i), None, NOW);
    }
    let keys = big.list("", NOW);
    assert_eq!(keys.len(), KV_LIST_LIMIT);
    assert_eq!(keys[0], "k-00000");
    assert_eq!(keys[KV_LIST_LIMIT - 1], format!("k-{:05}", KV_LIST_LIMIT - 1));
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn list_filtered_applies_policy_before_cap() {
    // Legacy filters per-key ACL before [:1000]. Capping first would
    // hide allowed keys behind 1000+ denied ones; the filtered API
    // must surface them.
    let mut store = KvStore::new();
    for i in 0..(KV_LIST_LIMIT + 5) {
        let key = format!("k-{i:05}");
        commit_ok_put(&mut store, &key, json!(i), None, NOW);
    }
    // Unfiltered convenience still caps first-1000 sorted keys.
    let unfiltered = store.list("", NOW);
    assert_eq!(unfiltered.len(), KV_LIST_LIMIT);
    assert_eq!(unfiltered[0], "k-00000");

    // Deny the first 1005 sorted keys, allow the last 5 beyond the cap.
    let denied_prefix = (0..(KV_LIST_LIMIT + 5 - 5))
        .map(|i| format!("k-{i:05}"))
        .collect::<std::collections::HashSet<_>>();
    let allowed = store.list_filtered("", NOW, |k| !denied_prefix.contains(k));
    assert_eq!(allowed.len(), 5);
    assert_eq!(allowed[0], format!("k-{:05}", KV_LIST_LIMIT));
    assert_eq!(allowed[4], format!("k-{:05}", KV_LIST_LIMIT + 4));

    // Prefix + live filtering still apply before the predicate.
    commit_ok_put(&mut store, "ctx.keep", json!(1), None, NOW);
    commit_ok_put(&mut store, "ctx.dead", json!(1), Some(1_000), NOW);
    let ctx = store.list_filtered("ctx.", NOW + 5.0, |_| true);
    assert_eq!(ctx, vec!["ctx.keep".to_string()]);

    // Cap applies after filtering: 1005 allowed keys yield 1000.
    let mut many = KvStore::new();
    for i in 0..(KV_LIST_LIMIT + 5) {
        commit_ok_put(&mut many, &format!("a-{i:05}"), json!(i), None, NOW);
    }
    assert_eq!(many.list_filtered("", NOW, |_| true).len(), KV_LIST_LIMIT);
}

#[test]
fn purge_expired_removes_only_expired() {
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "live", json!(1), None, NOW);
    commit_ok_put(&mut store, "soon", json!(1), Some(60_000), NOW);
    commit_ok_put(&mut store, "dead", json!(1), Some(1_000), NOW);
    assert_eq!(store.purge_expired(NOW + 5.0), 1);
    assert_eq!(store.len(), 2);
    assert_eq!(store.live_len(NOW + 5.0), 2);
    assert_eq!(store.purge_expired(NOW + 5.0), 0);
}

#[test]
fn replay_applies_record_order_for_put_and_delete() {
    let mut store = KvStore::new();
    let report = store.replay_lines(
        [
            r#"{"t":"kv","key":"a","value":1,"exp":null}"#,
            r#"{"t":"kv_del","key":"a"}"#,
            r#"{"t":"kv_del","key":"b"}"#,
            r#"{"t":"kv","key":"b","value":2,"exp":null}"#,
        ],
        NOW,
    );
    assert_eq!(report.puts, 2);
    assert_eq!(report.deletes, 2);
    assert_eq!(report.applied(), 4);
    assert_eq!(store.get("a", NOW), None);
    assert_eq!(store.get("b", NOW), Some(&json!(2)));
}

#[test]
fn replay_latest_expired_write_suppresses_older_value() {
    // No-resurrection rule: legacy skipped the expired put and left the
    // older live value behind; native applies it as a tombstone.
    let lines = [
        format!(r#"{{"t":"kv","key":"k","value":"old","exp":{}}}"#, NOW + 100.0),
        format!(r#"{{"t":"kv","key":"k","value":"new","exp":{}}}"#, NOW - 10.0),
    ];
    let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    let mut store = KvStore::new();
    let report = store.replay_lines(refs, NOW);
    assert_eq!(report.puts, 1);
    assert_eq!(report.expired_suppressed, 1);
    assert_eq!(store.get("k", NOW), None);
    assert!(store.stored("k").is_none());

    // Order still wins when the live write is newest.
    let lines = [
        format!(r#"{{"t":"kv","key":"k","value":"old","exp":{}}}"#, NOW - 10.0),
        format!(r#"{{"t":"kv","key":"k","value":"new","exp":{}}}"#, NOW + 100.0),
    ];
    let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    let mut store = KvStore::new();
    let report = store.replay_lines(refs, NOW);
    assert_eq!((report.puts, report.expired_suppressed), (1, 1));
    assert_eq!(store.get("k", NOW), Some(&json!("new")));
}

#[test]
fn replay_single_expired_put_stays_gone() {
    let line = format!(r#"{{"t":"kv","key":"k","value":1,"exp":{}}}"#, NOW - 1.0);
    let mut store = KvStore::new();
    assert_eq!(store.replay_line(&line, NOW), LineOutcome::ExpiredSuppressed);
    assert!(store.is_empty());
}

#[test]
fn replay_skips_malformed_and_ignores_blanks() {
    let mut store = KvStore::new();
    let report = store.replay_lines(
        [
            "",
            "   ",
            "{not json",
            "[1,2]",
            "42",
            r#""str""#,
            "null",
            "{}",
            r#"{"t":"post","topic":"x"}"#,
            r#"{"t":"kv","value":1}"#,
            r#"{"t":"kv","key":5,"value":1}"#,
            r#"{"t":"kv","key":"k","value":1,"exp":"soon"}"#,
            r#"{"t":"kv","key":"k","value":1,"exp":true}"#,
            r#"{"t":"kv_del"}"#,
            r#"{"t":"kv_del","key":null}"#,
            r#"{"t":"kv","key":"ok","value":1,"exp":null}"#,
        ],
        NOW,
    );
    assert_eq!(report.puts, 1);
    assert_eq!(report.malformed, 13);
    assert_eq!(store.get("ok", NOW), Some(&json!(1)));
    assert_eq!(store.len(), 1);
}

#[test]
fn replay_missing_value_defaults_to_null_and_ignores_extras() {
    let mut store = KvStore::new();
    assert_eq!(
        store.replay_line(r#"{"t":"kv","key":"n"}"#, NOW),
        LineOutcome::PutApplied
    );
    assert_eq!(store.get("n", NOW), Some(&Value::Null));

    assert_eq!(
        store.replay_line(
            r#"{"t":"kv","key":"x","value":7,"exp":null,"future":true}"#,
            NOW
        ),
        LineOutcome::PutApplied
    );
    assert_eq!(store.get("x", NOW), Some(&json!(7)));
}

#[test]
fn replay_is_deterministic_at_fixed_now() {
    let lines = [
        r#"{"t":"kv","key":"a","value":[1],"exp":null}"#,
        r#"{"t":"kv","key":"b","value":null,"exp":1790000600.0}"#,
        r#"{"t":"kv_del","key":"a"}"#,
        r#"{"t":"kv","key":"c","value":"x","exp":1000.0}"#,
        "garbage{",
    ];
    let mut first = KvStore::new();
    let r1 = first.replay_lines(lines, NOW);
    let mut second = KvStore::new();
    let r2 = second.replay_lines(lines, NOW);
    assert_eq!(r1, r2);
    assert_eq!(first, second);
    assert_eq!(first.snapshot_json(NOW), second.snapshot_json(NOW));
}

#[test]
fn snapshot_holds_live_only_and_restores() {
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "keep", json!({"v": 1}), None, NOW);
    commit_ok_put(&mut store, "ttl", json!(2), Some(60_000), NOW);
    commit_ok_put(&mut store, "dead", json!(3), Some(1_000), NOW);
    let snap = store.snapshot(NOW + 5.0);
    assert_eq!(snap.v, 1);
    assert_eq!(snap.kv.len(), 2);
    assert_eq!(snap.exp.len(), 1);
    assert_eq!(snap.exp.get("ttl"), Some(&(NOW + 60.0)));

    let doc: Value = serde_json::from_str(&store.snapshot_json(NOW + 5.0)).unwrap();
    assert_eq!(doc.get("v"), Some(&json!(1)));
    assert!(doc.get("kv").unwrap().is_object());
    assert!(doc.get("exp").unwrap().is_object());

    let mut restored = KvStore::new();
    let report = restored.restore_snapshot(&store.snapshot_json(NOW + 5.0)).unwrap();
    assert_eq!((report.loaded, report.skipped), (2, 0));
    assert_eq!(restored.get("keep", NOW + 5.0), Some(&json!({"v": 1})));
    assert_eq!(restored.get("ttl", NOW + 5.0), Some(&json!(2)));
    assert_eq!(restored.get("dead", NOW + 5.0), None);
}

#[test]
fn restore_keeps_expired_entries_invisible_like_legacy_load() {
    // The legacy boot path updates kv_store/kv_exp without filtering;
    // expiry is enforced at read time, not at restore time.
    let doc = format!(
        r#"{{"v":1,"kv":{{"old":1}},"exp":{{"old":{}}}}}"#,
        NOW - 10.0
    );
    let mut store = KvStore::new();
    let report = store.restore_snapshot(&doc).unwrap();
    assert_eq!((report.loaded, report.skipped), (1, 0));
    assert_eq!(store.get("old", NOW), None);
    assert_eq!(store.stored("old").unwrap().value, json!(1));
    assert_eq!(store.purge_expired(NOW), 1);
}

#[test]
fn restore_accepts_legacy_flat_documents() {
    let mut store = KvStore::new();
    let report = store.restore_snapshot(r#"{"a":1,"b":null}"#).unwrap();
    assert_eq!((report.loaded, report.skipped), (2, 0));
    assert_eq!(store.get("a", NOW), Some(&json!(1)));
    assert_eq!(store.get("b", NOW), Some(&Value::Null));
    assert_eq!(store.stored("a").unwrap().exp, None);
}

#[test]
fn restore_rejects_non_objects_without_touching_state() {
    for bad in ["[1,2]", "42", "null", "{oops", r#"{"v":1,"kv":[1]}"#] {
        let mut store = KvStore::new();
        commit_ok_put(&mut store, "k", json!(1), None, NOW);
        let err = store.restore_snapshot(bad).unwrap_err();
        assert!(matches!(err, KvError::BadSnapshot(_)), "for {bad}");
        assert_eq!(store.get("k", NOW), Some(&json!(1)));
        assert_eq!(store.len(), 1);
    }
    let mut store = KvStore::new();
    let err = store.restore_snapshot(r#"{"v":1,"kv":{},"exp":7}"#).unwrap_err();
    assert!(matches!(err, KvError::BadSnapshot(_)));
}

#[test]
fn restore_counts_orphaned_numeric_exp_as_skipped() {
    // Numeric exp without a matching kv value is inert and counted.
    let mut store = KvStore::new();
    let report = store
        .restore_snapshot(r#"{"v":1,"kv":{"a":1},"exp":{"ghost":5}}"#)
        .unwrap();
    assert_eq!((report.loaded, report.skipped), (1, 1));
    assert_eq!(store.stored("a").unwrap().exp, None);
    assert!(store.stored("ghost").is_none());
}

#[test]
fn restore_rejects_malformed_exp_atomically_preserving_state() {
    // Correction: a non-numeric exp for a stored key used to load the
    // key with no expiry (immortal) and count skipped. It now fails
    // atomically and leaves existing state untouched.
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "keep", json!("old"), None, NOW);
    let before = store.clone();
    let err = store
        .restore_snapshot(r#"{"v":1,"kv":{"good":1,"bad":2},"exp":{"good":1790000100.0,"bad":"soon"}}"#)
        .unwrap_err();
    assert!(matches!(err, KvError::BadSnapshot(_)), "got {err:?}");
    assert_eq!(store, before);
    assert_eq!(store.get("keep", NOW), Some(&json!("old")));
    assert!(store.stored("good").is_none());
    assert!(store.stored("bad").is_none());

    // Non-numeric orphaned exp also fails instead of silently skipping
    // corrupt data; state still preserved.
    let mut store = KvStore::new();
    commit_ok_put(&mut store, "k", json!(1), None, NOW);
    let before = store.clone();
    let err = store
        .restore_snapshot(r#"{"v":1,"kv":{"a":1},"exp":{"ghost":"soon"}}"#)
        .unwrap_err();
    assert!(matches!(err, KvError::BadSnapshot(_)));
    assert_eq!(store, before);
}

#[test]
fn restore_rejects_unsupported_snapshot_version_without_flat_fallback() {
    // Correction: legacy treated every non-v==1 object as flat, so a
    // future {"v":2,"kv":{...}} would load v/kv/exp as user keys.
    // Native fails; flat without top-level v still loads literally.
    for doc in [
        r#"{"v":2,"kv":{"a":1},"exp":{}}"#,
        r#"{"v":2}"#,
        r#"{"v":0,"kv":{}}"#,
        r#"{"v":"1","kv":{"a":1}}"#,
        r#"{"v":null,"a":1}"#,
    ] {
        let mut store = KvStore::new();
        commit_ok_put(&mut store, "keep", json!(1), None, NOW);
        let before = store.clone();
        let err = store.restore_snapshot(doc).unwrap_err();
        assert!(matches!(err, KvError::BadSnapshot(_)), "for {doc}");
        assert_eq!(store, before);
        assert!(store.stored("v").is_none());
        assert!(store.stored("kv").is_none());
    }

    // Flat without v still loads, even when it uses kv/exp as keys.
    let mut store = KvStore::new();
    let report = store.restore_snapshot(r#"{"kv":1,"exp":2,"a":3}"#).unwrap();
    assert_eq!((report.loaded, report.skipped), (3, 0));
    assert_eq!(store.get("kv", NOW), Some(&json!(1)));
    assert_eq!(store.get("exp", NOW), Some(&json!(2)));
}

#[test]
fn len_counts_stored_while_live_len_counts_live() {
    let mut store = KvStore::new();
    assert!(store.is_empty());
    commit_ok_put(&mut store, "a", json!(1), None, NOW);
    commit_ok_put(&mut store, "b", json!(1), Some(1_000), NOW);
    assert_eq!(store.len(), 2);
    assert_eq!(store.live_len(NOW), 2);
    assert_eq!(store.live_len(NOW + 5.0), 1);
}
