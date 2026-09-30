//! Offline snapshot+WAL migration: importer correctness + child-broker replay.
//!
//! Synthetic/quiescent copies ONLY: every fixture is written by the test
//! itself into an isolated temp dir (no production WAL/snapshot/tokens, no
//! live broker). Proves the `migration` importer preserves snapshot-only
//! keys while later WAL deletes/updates win, retains the expired-put
//! tombstone correction (no resurrection), fractional `exp`, and null
//! values, preserves posts/high-water/claims/opaque records, validates all
//! input before atomic publish (malformed/version/torn-tail fail with no
//! output and no key/value echo), re-runs deterministically, refuses
//! overwrite, and produces output that starts a real child broker without a
//! legacy snapshot sibling. Also proves fail-closed pre-append length (only
//! `NotFound` means zero).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_bus::acl::TokenStore;
use agent_bus::migration::migrate_legacy_to_wal;
use agent_bus::wal::{replay, snapshot_path_for, BusState};
use agent_bus::wire::{pre_append_len, Client, Server};
use serde_json::{json, Value};

const FIXED_NOW: f64 = 1_000_000.0;

fn tmpdir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "agent-bus-kvmig-{}-{}-{}",
        tag,
        std::process::id(),
        // Per-test uniqueness when several tests share a tag prefix.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn open_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-test": {"agent": "tester", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .expect("fixture tokens valid")
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn broker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus-broker"))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_fixture_tokens(dir: &Path) -> PathBuf {
    let path = dir.join("tokens.json");
    std::fs::write(
        &path,
        r#"{"tok-test": {"agent": "tester", "publish": ["*"], "subscribe": ["*"]}}"#,
    )
    .unwrap();
    path
}

fn spawn_broker(dir: &Path, wal: &Path, port: u16) -> Child {
    let tokens = write_fixture_tokens(dir);
    Command::new(broker_bin())
        .env_remove("AGENT_BUS_SOCK")
        .arg("serve")
        .arg("--wal")
        .arg(wal)
        .arg("--tokens")
        .arg(&tokens)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .env_remove("AGENT_BUS_OPEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("broker child spawns")
}

fn wait_ready(addr: &str) -> Client {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match Client::connect(addr, "tester", "tok-test") {
            Ok(c) => return c,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("broker at {addr} never became ready: {e}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn exited(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("poll child") {
            Some(status) => return Some(status),
            None => {
                if Instant::now() > deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn kill(child: &mut Child) {
    child.kill().expect("SIGKILL child");
    let status = child.wait().expect("reap child");
    assert!(!status.success(), "killed broker exits non-zero, got {status}");
}

fn spawn_ready(dir: &Path, wal: &Path) -> (Child, Client, String) {
    for attempt in 0..3 {
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let mut child = spawn_broker(dir, wal, port);
        if let Some(status) = exited(&mut child, Duration::from_millis(300)) {
            if attempt == 2 {
                panic!("broker on {addr} exited at startup: {status}");
            }
            continue;
        }
        let client = wait_ready(&addr);
        return (child, client, addr);
    }
    unreachable!("spawn_ready retries exhausted");
}

fn replay_output(out: &Path, now: f64) -> BusState {
    let mut s = BusState::new();
    replay(out, &mut s, now).expect("migrated output replays cleanly");
    s
}

#[test]
fn snapshot_plus_wal_ordering_tombstones_fractional_and_null() {
    // Legacy boot order: snapshot first, then WAL in file order. Snapshot-only
    // keys survive; later WAL deletes/updates win; an expired WAL put is a
    // tombstone that suppresses the snapshot value (no resurrection);
    // fractional exp and null values round-trip exactly.
    let dir = tmpdir("ordering");
    let snap_path = dir.join("kv.json");
    let wal_path = dir.join("legacy-wal.log");
    let out_path = dir.join("out").join("wal.log");
    let now = 1000.0;
    // Snapshot: live keys plus one already-expired (enforced at read time).
    std::fs::write(
        &snap_path,
        serde_json::to_string(&json!({
            "v": 1,
            "kv": {
                "ctx.snap_only": {"n": 1},
                "ctx.overwritten": "old",
                "ctx.deleted": 1,
                "ctx.suppressed": "snapshot-live",
                "ctx.expired_snap": "old-expired",
                "ctx.frac_snap": "frac-old"
            },
            "exp": {
                "ctx.expired_snap": 500.0,
                "ctx.frac_snap": 2000.5
            }
        }))
        .unwrap(),
    )
    .unwrap();
    // WAL: update, delete, new put, expired-put tombstone over a live snapshot
    // value, fractional-exp put, null put, and a null-overwrite.
    let frac_exp = 2000.125;
    let wal_lines = [
        json!({"t": "kv", "key": "ctx.overwritten", "value": "new", "exp": null}).to_string(),
        json!({"t": "kv_del", "key": "ctx.deleted"}).to_string(),
        json!({"t": "kv", "key": "ctx.wal_only", "value": [1, 2], "exp": null}).to_string(),
        // Newer expired put over a live snapshot value: must suppress, never
        // resurrect the snapshot value.
        json!({"t": "kv", "key": "ctx.suppressed", "value": "stale", "exp": 500.0}).to_string(),
        json!({"t": "kv", "key": "ctx.frac", "value": 1, "exp": frac_exp}).to_string(),
        json!({"t": "kv", "key": "ctx.null", "value": null, "exp": null}).to_string(),
        json!({"t": "kv", "key": "ctx.null_over", "value": null, "exp": null}).to_string(),
    ];
    std::fs::write(&wal_path, wal_lines.join("\n") + "\n").unwrap();
    let snap_before = std::fs::read(&snap_path).unwrap();
    let wal_before = std::fs::read(&wal_path).unwrap();

    let report = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_path, now)
        .expect("ordering migration succeeds");
    assert_eq!(report.snapshot_keys, 6, "{report:?}");
    assert_eq!(report.opaque, 0, "{report:?}");
    // Live at now=1000: snap_only, overwritten=new, wal_only, frac_snap
    // (exp 2000.5), frac (exp 2000.125), null, null_over. Gone: deleted,
    // suppressed (tombstone), expired_snap (expired at 500).
    assert_eq!(report.kv_live, 7, "{report:?}");

    // Source bytes preserved; no lock files created beside inputs.
    assert_eq!(std::fs::read(&snap_path).unwrap(), snap_before);
    assert_eq!(std::fs::read(&wal_path).unwrap(), wal_before);
    assert!(
        !dir.join("legacy-wal.log.lock").exists(),
        "importer must not lock/mutate sources"
    );

    let s = replay_output(&out_path, now);
    assert_eq!(s.kv.get("ctx.snap_only", now).unwrap(), &json!({"n": 1}));
    assert_eq!(s.kv.get("ctx.overwritten", now).unwrap(), &json!("new"));
    assert!(s.kv.get("ctx.deleted", now).is_none());
    assert!(
        s.kv.get("ctx.suppressed", now).is_none(),
        "expired WAL put must suppress snapshot value, not resurrect it"
    );
    assert!(s.kv.get("ctx.expired_snap", now).is_none());
    assert_eq!(s.kv.get("ctx.wal_only", now).unwrap(), &json!([1, 2]));
    assert_eq!(s.kv.get("ctx.null", now).unwrap(), &Value::Null);
    assert_eq!(s.kv.get("ctx.null_over", now).unwrap(), &Value::Null);
    // Fractional expiries preserved exactly (no rounding).
    assert_eq!(s.kv.stored("ctx.frac").unwrap().exp, Some(frac_exp));
    assert_eq!(s.kv.stored("ctx.frac_snap").unwrap().exp, Some(2000.5));
    // Output starts in-process without any snapshot sibling.
    assert!(!snapshot_path_for(&out_path).exists());
    let _server = Server::new(out_path.clone(), open_tokens()).expect("output starts clean");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preserves_posts_highwater_claims_and_opaque() {
    // Posts, per-topic high-water marks (including an empty topic), live and
    // retired claims, and opaque records all survive migration.
    let dir = tmpdir("preserve");
    let legacy = dir.join("legacy");
    std::fs::create_dir_all(&legacy).unwrap();
    let snap_path = legacy.join("kv.json");
    let wal_path = legacy.join("wal.log");
    let out_path = dir.join("migrated").join("wal.log");
    std::fs::write(&snap_path, r#"{"v":1,"kv":{"ctx.k":1},"exp":{}}"#).unwrap();
    let art_line = r#"{"t":"art_own","sha":"abc","agent":"alice","size":12}"#;
    let future_line = r#"{"t":"future_kind","x":[1,{"y":null}],"z":"keep-me"}"#;
    let wal_lines = [
        art_line.to_string(),
        json!({"t":"post","topic":"board.build","msg":{"seq":1,"id":"m1","sender":"alice","ts":10.0,"exp":null,"corr_id":"c1","reply_to":null,"payload":{"n":1}}}).to_string(),
        json!({"t":"post","topic":"board.build","msg":{"seq":2,"id":"m2","sender":"bob","ts":11.0,"exp":null,"payload":{"n":2}}}).to_string(),
        // Empty-topic high-water mark (no retained posts for this topic).
        json!({"t":"topic_seq","topic":"board.empty","seq":7}).to_string(),
        // Live lease (far-future expiry so it survives system-time replay).
        json!({"t":"claim_acquire","resource":"repo/live.rs","owner":"alice","token":"tok-live","fencing":3,"acquired_at":100.0,"expires_at":9000000000.0,"idem":"k1","ttl_ms":60000,"renew":false}).to_string(),
        // Retired lease: acquire then release.
        json!({"t":"claim_acquire","resource":"repo/old.rs","owner":"bob","token":"tok-old","fencing":1,"acquired_at":50.0,"expires_at":60.0,"idem":"k2","ttl_ms":60000,"renew":false}).to_string(),
        json!({"t":"claim_release","resource":"repo/old.rs","fencing":2}).to_string(),
        future_line.to_string(),
    ];
    std::fs::write(&wal_path, wal_lines.join("\n") + "\n").unwrap();

    let report = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_path, FIXED_NOW)
        .expect("preserve migration succeeds");
    assert_eq!(report.wal_posts, 2, "{report:?}");
    assert_eq!(report.wal_claims, 3, "{report:?}");
    assert_eq!(report.opaque, 2, "{report:?}");

    // Opaque records preserved verbatim in output bytes.
    let raw = std::fs::read_to_string(&out_path).unwrap();
    assert!(raw.contains(art_line), "art_own verbatim: {raw}");
    assert!(raw.contains(future_line), "future kind verbatim: {raw}");

    let s = replay_output(&out_path, FIXED_NOW);
    // Posts + correlation metadata + high-water marks.
    assert_eq!(s.topics["board.build"].seq, 2);
    assert_eq!(s.topics["board.build"].msgs.len(), 2);
    assert_eq!(s.topics["board.build"].msgs[0].corr_id, Some(json!("c1")));
    assert_eq!(s.topics["board.empty"].seq, 7);
    assert!(s.topics["board.empty"].msgs.is_empty());
    // Snapshot KV key survived alongside WAL state.
    assert_eq!(s.kv.get("ctx.k", FIXED_NOW).unwrap(), &json!(1));
    // Live lease intact; retired key stays retired (never resurrects).
    let live = s.claims.status("repo/live.rs", FIXED_NOW).expect("live lease");
    assert_eq!(live.owner, "alice");
    assert_eq!(live.token, "tok-live");
    assert_eq!(live.fencing, 3);
    assert!(s.claims.status("repo/old.rs", FIXED_NOW).is_none());
    let err = s
        .claims
        .acquire(
            &mut agent_bus::claims::VecWal::default(),
            "bob",
            "repo/old.rs",
            60_000,
            Some("k2"),
            FIXED_NOW,
        )
        .unwrap_err();
    assert!(err.retired, "{err:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn flat_snapshot_and_versioned_edge_keys_preserved() {
    // Flat documents (no top-level `v`) load literally, including keys named
    // `kv`/`exp`; versioned snapshots keep null values and fractional exp.
    let dir = tmpdir("flat");
    let legacy = dir.join("legacy");
    std::fs::create_dir_all(&legacy).unwrap();
    let snap_path = legacy.join("kv.json");
    let wal_path = legacy.join("w.log");
    let out_path = dir.join("migrated").join("out.log");
    // Flat: no `v`, so `kv`/`exp` are user keys, not metadata.
    std::fs::write(
        &snap_path,
        serde_json::to_string(&json!({
            "ctx.flat": "flat-value",
            "kv": "user-key-kv",
            "exp": "user-key-exp",
            "ctx.nul": null
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &wal_path,
        json!({"t": "kv", "key": "ctx.wal", "value": 1, "exp": null}).to_string() + "\n",
    )
    .unwrap();
    let report = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_path, FIXED_NOW)
        .expect("flat migration succeeds");
    assert_eq!(report.snapshot_keys, 4, "{report:?}");
    let s = replay_output(&out_path, FIXED_NOW);
    assert_eq!(s.kv.get("ctx.flat", FIXED_NOW).unwrap(), &json!("flat-value"));
    assert_eq!(s.kv.get("kv", FIXED_NOW).unwrap(), &json!("user-key-kv"));
    assert_eq!(s.kv.get("exp", FIXED_NOW).unwrap(), &json!("user-key-exp"));
    assert_eq!(s.kv.get("ctx.nul", FIXED_NOW).unwrap(), &Value::Null);
    assert_eq!(s.kv.get("ctx.wal", FIXED_NOW).unwrap(), &json!(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_wal_fails_with_no_output_and_no_echo() {
    // Three malformed shapes: invalid JSON, post without msg, kv without key.
    // Each fails closed with the line named, no output file, sources intact,
    // and no key/value/secret bytes in the diagnostic.
    for (tag, bad_line) in [
        ("bad-json", "{not json}".to_string()),
        (
            "post-no-msg",
            json!({"t": "post", "topic": "t", "secret": "SECRET-VALUE-123"}).to_string(),
        ),
        (
            "kv-no-key",
            json!({"t": "kv", "value": "SECRET-VALUE-456", "exp": null}).to_string(),
        ),
    ] {
        let dir = tmpdir(&format!("malformed-{tag}"));
        let legacy = dir.join("legacy");
        std::fs::create_dir_all(&legacy).unwrap();
        let snap_path = legacy.join("kv.json");
        let wal_path = legacy.join("w.log");
        let out_path = dir.join("migrated").join("out.log");
        std::fs::write(&snap_path, r#"{"v":1,"kv":{"ctx.a":1},"exp":{}}"#).unwrap();
        let good = json!({"t":"post","topic":"t","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}}).to_string();
        std::fs::write(&wal_path, format!("{good}\n{bad_line}\n")).unwrap();
        let snap_before = std::fs::read(&snap_path).unwrap();
        let wal_before = std::fs::read(&wal_path).unwrap();

        let err = match migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_path, FIXED_NOW)
        {
            Ok(_) => panic!("malformed WAL ({tag}) must fail"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("line 2"), "{tag}: {msg}");
        assert!(!out_path.exists(), "{tag}: no partial output");
        // No temp files left behind (output parent never created on
        // validation failure; if it exists, it must hold no temps).
        if let Some(parent) = out_path.parent() {
            if parent.exists() {
                for entry in std::fs::read_dir(parent).unwrap() {
                    let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                    assert!(!name.contains(".migrate."), "{tag}: temp left: {name}");
                }
            }
        }
        // Sources byte-identical; diagnostics carry no secrets.
        assert_eq!(std::fs::read(&snap_path).unwrap(), snap_before);
        assert_eq!(std::fs::read(&wal_path).unwrap(), wal_before);
        assert!(!msg.contains("SECRET-VALUE"), "{tag}: echo: {msg}");
        assert!(!msg.contains("ctx.a"), "{tag}: key echo: {msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn unsupported_snapshot_version_and_bad_exp_fail_without_echo() {
    // Version conflict plus malformed-exp: both fail atomically with fixed
    // reasons that never repeat the offending key or version value.
    let dir = tmpdir("snap-bad");
    let wal_path = dir.join("w.log");
    std::fs::write(
        &wal_path,
        json!({"t": "kv", "key": "ctx.a", "value": 1, "exp": null}).to_string() + "\n",
    )
    .unwrap();
    // Unsupported version.
    let bad_ver = dir.join("bad-ver.json");
    let out_ver = dir.join("out-ver.log");
    std::fs::write(
        &bad_ver,
        r#"{"v":2,"kv":{"SECRET-KEY-1":1},"exp":{}}"#,
    )
    .unwrap();
    let err = migrate_legacy_to_wal(Some(&bad_ver), &wal_path, &out_ver, FIXED_NOW)
        .expect_err("v2 snapshot must fail");
    let msg = err.to_string();
    assert!(msg.contains("unsupported snapshot version"), "{msg}");
    assert!(!msg.contains("SECRET-KEY-1"), "key echo: {msg}");
    assert!(!msg.contains("\"v\":2"), "value echo: {msg}");
    assert!(!out_ver.exists());
    // Malformed exp for a stored key.
    let bad_exp = dir.join("bad-exp.json");
    let out_exp = dir.join("out-exp.log");
    std::fs::write(
        &bad_exp,
        serde_json::to_string(&json!({
            "v": 1,
            "kv": {"SECRET-KEY-2": 1},
            "exp": {"SECRET-KEY-2": "not-a-number"}
        }))
        .unwrap(),
    )
    .unwrap();
    let err = migrate_legacy_to_wal(Some(&bad_exp), &wal_path, &out_exp, FIXED_NOW)
        .expect_err("bad exp must fail");
    let msg = err.to_string();
    assert!(msg.contains("malformed exp entry"), "{msg}");
    assert!(!msg.contains("SECRET-KEY-2"), "key echo: {msg}");
    assert!(!out_exp.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn torn_tail_and_unterminated_refuse_migration() {
    // Quiescent copies must end on a newline: a torn partial tail and a
    // complete-but-unterminated final record both fail with no output.
    let dir = tmpdir("tail");
    let legacy = dir.join("legacy");
    std::fs::create_dir_all(&legacy).unwrap();
    let snap_path = legacy.join("kv.json");
    std::fs::write(&snap_path, r#"{"v":1,"kv":{},"exp":{}}"#).unwrap();
    let good = json!({"t":"post","topic":"t","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}}).to_string();
    // Torn tail: partial final line, no newline.
    let torn_wal = legacy.join("torn.log");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&torn_wal).unwrap();
        f.write_all(good.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        f.write_all(b"{\"t\":\"post\",\"topic\":\"t\",\"msg\":{\"seq\":2").unwrap();
        f.sync_all().unwrap();
    }
    let torn_before = std::fs::read(&torn_wal).unwrap();
    let out_torn = dir.join("migrated-torn").join("out.log");
    let err = migrate_legacy_to_wal(Some(&snap_path), &torn_wal, &out_torn, FIXED_NOW)
        .expect_err("torn tail must fail");
    assert!(err.to_string().contains("torn partial tail"), "{}", err.to_string());
    assert!(!out_torn.exists());
    assert_eq!(std::fs::read(&torn_wal).unwrap(), torn_before);
    // Valid but unterminated: complete JSON, no trailing newline.
    let unter_wal = legacy.join("unter.log");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&unter_wal).unwrap();
        f.write_all(good.as_bytes()).unwrap();
        // No newline: a crash between the record write and the newline.
        f.sync_all().unwrap();
    }
    let out_unter = dir.join("migrated-unter").join("out.log");
    let err = migrate_legacy_to_wal(Some(&snap_path), &unter_wal, &out_unter, FIXED_NOW)
        .expect_err("unterminated tail must fail");
    assert!(
        err.to_string().contains("lacks terminating newline"),
        "{}",
        err.to_string()
    );
    assert!(!out_unter.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rerun_is_deterministic_and_overwrite_is_refused() {
    // Same inputs + same now to different outputs: byte-identical files.
    // Re-running onto an existing output, onto an input, or beside a legacy
    // sibling snapshot all fail with existing bytes untouched.
    let dir = tmpdir("rerun");
    let legacy = dir.join("legacy");
    std::fs::create_dir_all(&legacy).unwrap();
    let snap_path = legacy.join("kv.json");
    let wal_path = legacy.join("w.log");
    std::fs::write(
        &snap_path,
        r#"{"v":1,"kv":{"ctx.b":2,"ctx.a":1},"exp":{}}"#,
    )
    .unwrap();
    std::fs::write(
        &wal_path,
        format!(
            "{}\n{}\n",
            json!({"t":"post","topic":"t","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}}),
            json!({"t":"kv","key":"ctx.c","value":3,"exp":null}),
        ),
    )
    .unwrap();
    let migrated = dir.join("migrated");
    std::fs::create_dir_all(&migrated).unwrap();
    let out_a = migrated.join("a.log");
    let out_b = migrated.join("b.log");
    let ra = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_a, FIXED_NOW)
        .expect("first migration");
    let rb = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_b, FIXED_NOW)
        .expect("second migration");
    assert_eq!(ra, rb, "reports deterministic");
    let ba = std::fs::read(&out_a).unwrap();
    let bb = std::fs::read(&out_b).unwrap();
    assert_eq!(ba, bb, "re-run bytes identical");
    assert_eq!(ra.out_bytes, ba.len() as u64);
    // Overwrite refused; existing bytes untouched.
    let err = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_a, FIXED_NOW)
        .expect_err("overwrite must fail");
    assert!(err.to_string().contains("already exists"), "{}", err.to_string());
    assert_eq!(std::fs::read(&out_a).unwrap(), ba);
    // Output-is-input refused.
    let err = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &wal_path, FIXED_NOW)
        .expect_err("output==wal must fail");
    assert!(err.to_string().contains("equals input"), "{}", err.to_string());
    let err = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &snap_path, FIXED_NOW)
        .expect_err("output==snapshot must fail");
    assert!(err.to_string().contains("equals input"), "{}", err.to_string());
    // Sibling snapshot beside the output refuses (broker would refuse startup).
    let sib_dir = dir.join("sibdir");
    std::fs::create_dir_all(&sib_dir).unwrap();
    std::fs::write(sib_dir.join("kv.json"), r#"{"v":1,"kv":{},"exp":{}}"#).unwrap();
    let out_sib = sib_dir.join("wal.log");
    let err = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_sib, FIXED_NOW)
        .expect_err("sibling snapshot must fail");
    assert!(err.to_string().contains("sibling snapshot"), "{}", err.to_string());
    assert!(!out_sib.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn child_broker_serves_migrated_kv_history_claims_and_restarts() {
    // End-to-end: migrate synthetic legacy state, start a REAL child broker
    // on the output (no snapshot sibling), answer KV + history + claim
    // queries, SIGKILL, restart on the same output, and answer again.
    let dir = tmpdir("child");
    let snap_path = dir.join("legacy-kv.json");
    let wal_path = dir.join("legacy-wal.log");
    let out_path = dir.join("migrated").join("wal.log");
    std::fs::write(
        &snap_path,
        serde_json::to_string(&json!({
            "v": 1,
            "kv": {
                "ctx.snap_only": "snap-value",
                "ctx.will_delete": "gone",
                "ctx.will_update": "old"
            },
            "exp": {}
        }))
        .unwrap(),
    )
    .unwrap();
    let wal_lines = [
        json!({"t":"kv_del","key":"ctx.will_delete"}).to_string(),
        json!({"t":"kv","key":"ctx.will_update","value":"new","exp":null}).to_string(),
        json!({"t":"kv","key":"ctx.wal_only","value":{"deep":[1,2]},"exp":null}).to_string(),
        json!({"t":"post","topic":"board.build","msg":{"seq":1,"id":"m1","sender":"alice","ts":10.0,"exp":null,"payload":{"hello":1}}}).to_string(),
        json!({"t":"topic_seq","topic":"board.build","seq":1}).to_string(),
        json!({"t":"claim_acquire","resource":"repo/mig.rs","owner":"tester","token":"tok-mig","fencing":5,"acquired_at":100.0,"expires_at":9000000000.0,"idem":"mig-key","ttl_ms":60000,"renew":false}).to_string(),
        r#"{"t":"art_own","sha":"beef","agent":"alice","size":7}"#.to_string(),
    ];
    std::fs::write(&wal_path, wal_lines.join("\n") + "\n").unwrap();

    let report = migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_path, FIXED_NOW)
        .expect("child migration succeeds");
    assert_eq!(report.snapshot_keys, 3, "{report:?}");
    assert_eq!(report.opaque, 1, "{report:?}");
    // No legacy snapshot sibling beside the output: the broker must start.
    assert!(!snapshot_path_for(&out_path).exists());
    let raw = std::fs::read_to_string(&out_path).unwrap();
    assert!(raw.contains(r#""t":"art_own""#), "opaque survives: {raw}");

    let check_kv_claims = |c: &mut Client| {
        let got = c.rpc(&json!({"op": "kv_get", "key": "ctx.snap_only"})).unwrap();
        assert!(ok(&got), "{got}");
        assert_eq!(got["value"], json!("snap-value"));
        let gone = c.rpc(&json!({"op": "kv_get", "key": "ctx.will_delete"})).unwrap();
        assert_eq!(gone["found"], json!(false), "{gone}");
        let upd = c.rpc(&json!({"op": "kv_get", "key": "ctx.will_update"})).unwrap();
        assert_eq!(upd["value"], json!("new"), "{upd}");
        let walonly = c.rpc(&json!({"op": "kv_get", "key": "ctx.wal_only"})).unwrap();
        assert_eq!(walonly["value"], json!({"deep": [1, 2]}), "{walonly}");
        let st = c.rpc(&json!({"op": "claim_status", "resource": "repo/mig.rs"})).unwrap();
        assert!(ok(&st), "{st}");
        assert_eq!(st["owner"], json!("tester"));
        assert_eq!(st["token"], json!("tok-mig"));
        assert_eq!(st["fencing"], json!(5));
    };

    let broker_dir = dir.join("broker1");
    std::fs::create_dir_all(&broker_dir).unwrap();
    let (mut child, mut c, _addr) = spawn_ready(&broker_dir, &out_path);
    check_kv_claims(&mut c);
    let f1 = c.rpc(&json!({"op": "fetch", "topic": "board.build", "from_seq": 0})).unwrap();
    assert!(ok(&f1), "{f1}");
    assert_eq!(f1["messages"].as_array().unwrap().len(), 1, "{f1}");
    assert_eq!(f1["cursor"]["topic_seq"], json!(1));
    // A new post after migration continues the migrated high-water mark.
    let p2 = c.rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 2}})).unwrap();
    assert_eq!(p2["seq"], json!(2), "{p2}");
    drop(c);
    kill(&mut child);

    // Restart on the same migrated output: state + new ACK survive.
    let broker_dir2 = dir.join("broker2");
    std::fs::create_dir_all(&broker_dir2).unwrap();
    let (mut child2, mut c2, _addr2) = spawn_ready(&broker_dir2, &out_path);
    check_kv_claims(&mut c2);
    let f = c2.rpc(&json!({"op": "fetch", "topic": "board.build", "from_seq": 0})).unwrap();
    assert_eq!(f["messages"].as_array().unwrap().len(), 2, "{f}");
    let p3 = c2.rpc(&json!({"op": "post", "topic": "board.build", "payload": {"n": 3}})).unwrap();
    assert_eq!(p3["seq"], json!(3), "{p3}");
    drop(c2);
    kill(&mut child2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn snapshot_refusal_remains_until_verified_migration() {
    // The broker still refuses startup when a legacy snapshot sibling exists;
    // only the migrated WAL-only output starts. Migration does not lift the
    // refusal: it produces output that needs no sibling.
    let dir = tmpdir("refusal");
    let wal_path = dir.join("wal.log");
    let snap_path = snapshot_path_for(&wal_path);
    std::fs::write(&wal_path, "{\"t\":\"kv\",\"key\":\"ctx.wal\",\"value\":1,\"exp\":null}\n").unwrap();
    std::fs::write(&snap_path, r#"{"v":1,"kv":{"ctx.snap":1},"exp":{}}"#).unwrap();
    let err = match Server::new(wal_path.clone(), open_tokens()) {
        Ok(_) => panic!("snapshot sibling must still refuse startup"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("unsupported legacy KV snapshot"), "{}", err.to_string());
    // The verified path is migration to a sibling-free output, which starts.
    let out_path = dir.join("migrated").join("wal.log");
    migrate_legacy_to_wal(Some(&snap_path), &wal_path, &out_path, FIXED_NOW)
        .expect("verified migration succeeds");
    assert!(!snapshot_path_for(&out_path).exists());
    let _server = Server::new(out_path.clone(), open_tokens()).expect("migrated output starts");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pre_append_len_only_notfound_means_zero_and_append_fails_closed() {
    // Fail-closed metadata: missing file => 0; existing file => len; any
    // other error (symlink loop => FilesystemLoop here, reliable as root)
    // => Err. A running server whose WAL becomes unstatable fails the op
    // before any bytes, without poisoning or truncating.
    let dir = tmpdir("prelen");
    let missing = dir.join("no-such-file.log");
    assert_eq!(pre_append_len(&missing).expect("missing means zero"), 0);
    let file = dir.join("wal.log");
    std::fs::write(&file, b"12345").unwrap();
    assert_eq!(pre_append_len(&file).expect("existing len"), 5);
    // Symlink loop: stat fails with FilesystemLoop (not NotFound), even as root.
    let loop_path = dir.join("loop.log");
    std::os::unix::fs::symlink(&loop_path, &loop_path).expect("symlink loop");
    let err = pre_append_len(&loop_path).expect_err("loop must fail");
    assert!(err.contains("pre-length"), "{err}");
    assert!(!err.contains("loop.log.lock"), "no path echo beyond reason: {err}");

    // Live-server fail-before-append: start clean, then replace the WAL with
    // a symlink loop and prove the next mutation fails with the pre-length
    // error, leaves no poison, and leaves the loop untruncated/unreplaced.
    let live_wal = dir.join("live").join("wal.log");
    std::fs::create_dir_all(live_wal.parent().unwrap()).unwrap();
    let server = Server::new(live_wal.clone(), open_tokens()).expect("live starts");
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let put = c.rpc(&json!({"op": "kv_put", "key": "ctx.a", "value": 1})).unwrap();
    assert!(ok(&put), "{put}");
    drop(c);
    // Replace the WAL file with a symlink loop (sources are synthetic).
    std::fs::remove_file(&live_wal).unwrap();
    std::os::unix::fs::symlink(&live_wal, &live_wal).unwrap();
    let mut c2 = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let denied = c2.rpc(&json!({"op": "kv_put", "key": "ctx.b", "value": 2})).unwrap();
    let err_text = denied.get("error").and_then(|e| e.as_str()).unwrap_or("");
    assert!(err_text.contains("pre-length"), "fail before append: {denied}");
    // No poison (nothing was written, so no rollback was needed) and the
    // loop was not truncated into a regular empty file.
    assert!(handle.wal_poisoned().is_none(), "no poison without partial bytes");
    let meta = std::fs::symlink_metadata(&live_wal).unwrap();
    assert!(meta.file_type().is_symlink(), "loop must not be replaced/truncated");
    // Reads stay available (fail-closed writes, live reads).
    let got = c2.rpc(&json!({"op": "kv_get", "key": "ctx.a"})).unwrap();
    assert!(ok(&got), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_migrate_reports_counts_without_echo() {
    // The `migrate` binary reports counts-only JSON on success and a
    // sanitized refusal on malformed input (exit non-zero, no secrets).
    let dir = tmpdir("cli");
    let legacy = dir.join("legacy");
    std::fs::create_dir_all(&legacy).unwrap();
    let snap_path = legacy.join("kv.json");
    let wal_path = legacy.join("w.log");
    let out_path = dir.join("migrated").join("out.log");
    std::fs::write(
        &snap_path,
        r#"{"v":1,"kv":{"ctx.cli":1},"exp":{}}"#,
    )
    .unwrap();
    std::fs::write(
        &wal_path,
        json!({"t":"kv","key":"ctx.w","value":"SECRET-CLI-VALUE","exp":null}).to_string() + "\n",
    )
    .unwrap();
    let run = Command::new(broker_bin())
        .arg("migrate")
        .arg("--wal")
        .arg(&wal_path)
        .arg("--snapshot")
        .arg(&snap_path)
        .arg("--out")
        .arg(&out_path)
        .arg("--now")
        .arg(FIXED_NOW.to_string())
        .output()
        .expect("migrate CLI runs");
    assert!(run.status.success(), "stderr: {}", String::from_utf8_lossy(&run.stderr));
    let stdout = String::from_utf8_lossy(&run.stdout).to_string();
    let parsed: Value = serde_json::from_str(&stdout).expect("CLI prints JSON");
    assert_eq!(parsed["ok"], json!(true), "{stdout}");
    assert_eq!(parsed["snapshot_keys"], json!(1), "{stdout}");
    assert_eq!(parsed["kv_live"], json!(2), "{stdout}");
    assert!(!stdout.contains("SECRET-CLI-VALUE"), "no value echo: {stdout}");
    assert!(!stdout.contains("ctx.cli"), "no key echo: {stdout}");

    // Malformed input fails closed with sanitized stderr.
    let bad_wal = dir.join("bad.log");
    std::fs::write(&bad_wal, "{not json}\n").unwrap();
    let bad_out = dir.join("bad-out.log");
    let run = Command::new(broker_bin())
        .arg("migrate")
        .arg("--wal")
        .arg(&bad_wal)
        .arg("--out")
        .arg(&bad_out)
        .arg("--now")
        .arg(FIXED_NOW.to_string())
        .output()
        .expect("bad migrate runs");
    assert!(!run.status.success(), "malformed must exit non-zero");
    assert!(!bad_out.exists(), "no partial output on CLI failure");
    let stderr = String::from_utf8_lossy(&run.stderr).to_string();
    assert!(stderr.contains("migrate failed"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn publish_collision_preserves_destination_and_stale_temps() {
    // A destination appearing before the atomic publish fails with its
    // bytes unchanged; stale migration temps are never consumed and only
    // our own temp is cleaned. Then a fresh publish with many stale
    // collisions still succeeds, preserving every stale file.
    let dir = tmpdir("publish-collision");
    let wal_path = dir.join("w.log");
    std::fs::write(
        &wal_path,
        json!({"t": "kv", "key": "ctx.a", "value": 1, "exp": null}).to_string() + "\n",
    )
    .unwrap();
    // Pre-existing destination with committed bytes.
    let out_path = dir.join("out.log");
    let committed = b"committed destination bytes\n";
    std::fs::write(&out_path, committed).unwrap();
    // Stale temps covering the likely counter window (any candidate in
    // this range must be skipped, never truncated).
    let mut stales = Vec::new();
    for n in 0..100u32 {
        let stale = dir.join(format!("out.log.migrate.{}.{n}.tmp", std::process::id()));
        let content = format!("stale-{n}\n").into_bytes();
        std::fs::write(&stale, &content).unwrap();
        stales.push((stale, content));
    }
    let err = migrate_legacy_to_wal(None, &wal_path, &out_path, FIXED_NOW)
        .expect_err("existing destination must fail");
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(std::fs::read(&out_path).unwrap(), committed);
    for (path, content) in &stales {
        assert_eq!(std::fs::read(path).unwrap(), *content, "stale {path:?}");
    }
    // Fresh destination in a subdir with its own stale window: publish
    // succeeds, output is private on Unix, stales preserved.
    let fresh_dir = dir.join("fresh");
    std::fs::create_dir_all(&fresh_dir).unwrap();
    let fresh_out = fresh_dir.join("o.log");
    let mut fresh_stales = Vec::new();
    for n in 0..100u32 {
        let stale = fresh_dir.join(format!("o.log.migrate.{}.{n}.tmp", std::process::id()));
        let content = format!("fresh-stale-{n}\n").into_bytes();
        std::fs::write(&stale, &content).unwrap();
        fresh_stales.push((stale, content));
    }
    let report = migrate_legacy_to_wal(None, &wal_path, &fresh_out, FIXED_NOW)
        .expect("fresh publish with stale collisions succeeds");
    assert_eq!(report.kv_live, 1, "{report:?}");
    for (path, content) in &fresh_stales {
        assert_eq!(std::fs::read(path).unwrap(), *content, "fresh stale {path:?}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&fresh_out).unwrap().permissions().mode() & 0o077,
            0,
            "fresh output must stay private"
        );
    }
    // No new temps beyond the pre-created stales.
    for entry in std::fs::read_dir(&fresh_dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.contains(".migrate.") {
            assert!(
                name.starts_with("o.log.migrate."),
                "only expected stales remain: {name}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bare_relative_output_publishes_with_current_dir_fsync() {
    // Bare relative `--out` (no parent) must still fsync "." and publish.
    // Runs the CLI with CWD set to the scratch dir (no process-wide chdir).
    let dir = tmpdir("bare-relative");
    std::fs::write(
        dir.join("input.log"),
        json!({"t": "kv", "key": "ctx.bare", "value": 7, "exp": null}).to_string() + "\n",
    )
    .unwrap();
    let run = Command::new(broker_bin())
        .arg("migrate")
        .arg("--wal")
        .arg("input.log")
        .arg("--out")
        .arg("output.log")
        .arg("--now")
        .arg(FIXED_NOW.to_string())
        .current_dir(&dir)
        .output()
        .expect("bare migrate runs");
    assert!(
        run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let raw = std::fs::read(dir.join("output.log")).expect("bare output published");
    assert!(raw.windows(7).any(|w| w == b"ctx.bar"), "kv preserved");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.join("output.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0,
            "bare output must stay private"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn opaque_streaming_preserves_many_records_in_order() {
    // 100 opaque records interleaved with known records stream to the
    // output in WAL order without whole-prefix collection; known state
    // still regenerates canonically.
    let dir = tmpdir("opaque-stream");
    let wal_path = dir.join("w.log");
    let out_path = dir.join("out.log");
    let mut lines = Vec::new();
    for i in 0..100u32 {
        lines.push(format!(r#"{{"t":"future_kind","n":{i},"pad":"{:064}"}}"#, i));
        if i == 50 {
            lines.push(
                json!({"t":"post","topic":"t","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}}).to_string(),
            );
            lines.push(
                json!({"t": "kv", "key": "ctx.s", "value": i, "exp": null}).to_string(),
            );
        }
    }
    std::fs::write(&wal_path, lines.join("\n") + "\n").unwrap();
    let report =
        migrate_legacy_to_wal(None, &wal_path, &out_path, FIXED_NOW).expect("stream succeeds");
    assert_eq!(report.opaque, 100, "{report:?}");
    assert_eq!(report.wal_posts, 1, "{report:?}");
    let raw = std::fs::read_to_string(&out_path).unwrap();
    let mut last = 0usize;
    for i in 0..100u32 {
        let marker = format!(r#""n":{i}"#);
        let pos = raw[last..].find(&marker).unwrap_or_else(|| panic!("opaque {i} in order"));
        last += pos + marker.len();
    }
    // Known state regenerated after the opaque prefix.
    assert!(raw.contains(r#""t":"kv""#), "kv regenerated");
    assert!(raw.contains(r#""topic_seq""#), "high-water regenerated");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn valid_expired_posts_recover_high_water_while_malformed_expired_fail() {
    // Valid expired posts (full fields) recover high-water and are then
    // discarded; a malformed expired post with seq/exp but missing fields
    // fails instead of vanishing.
    let dir = tmpdir("expired-hw");
    let wal_path = dir.join("w.log");
    let out_path = dir.join("out.log");
    let valid_expired = |seq: u64| {
        json!({"t":"post","topic":"t","msg":{"seq":seq,"id":format!("e{seq}"),"sender":"a","ts":1.0,"exp":10.0,"payload":seq}}).to_string()
    };
    let live =
        json!({"t":"post","topic":"t","msg":{"seq":2,"id":"live","sender":"a","ts":1.0,"exp":null,"payload":2}}).to_string();
    std::fs::write(
        &wal_path,
        format!("{}\n{live}\n{}\n", valid_expired(1), valid_expired(3)),
    )
    .unwrap();
    migrate_legacy_to_wal(None, &wal_path, &out_path, FIXED_NOW).expect("valid expired migrate");
    let s = replay_output(&out_path, FIXED_NOW);
    assert_eq!(s.topics["t"].seq, 3, "high-water includes valid expired");
    assert_eq!(s.topics["t"].msgs.len(), 1, "only live retained");
    assert_eq!(s.topics["t"].msgs[0].seq, 2);
    // Malformed expired: seq+exp present, required fields missing.
    let bad_wal = dir.join("bad.log");
    let bad_out = dir.join("bad-out.log");
    std::fs::write(&bad_wal, "{\"t\":\"post\",\"topic\":\"t\",\"msg\":{\"seq\":1,\"exp\":0}}\n").unwrap();
    let err = migrate_legacy_to_wal(None, &bad_wal, &bad_out, FIXED_NOW)
        .expect_err("malformed expired must fail");
    assert!(err.to_string().contains("line 1"), "{err}");
    assert!(!bad_out.exists());
    let _ = std::fs::remove_dir_all(&dir);
}
