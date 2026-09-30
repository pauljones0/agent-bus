//! Ordinary status reads against an owned, private native broker. No live
//! services, target execution, stress, fault injection or Python helpers.
use agent_bus::acl::TokenStore;
use agent_bus::scheduler::status::{Cleanup, Outcome, Phase, StatusRecord};
use agent_bus::wire::{Client, OwnedBroker, Server};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    owner: Option<OwnedBroker>,
    root: PathBuf,
    port: u16,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "native-runs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let tokens = TokenStore::from_json_str(r#"{"test-token":{"agent":"tester","publish":["*"],"subscribe":["*"],"kv_read":["ctx.sched.*"],"kv_write":["ctx.sched.*"]},"no-read":{"agent":"reader","publish":[],"subscribe":[],"kv_read":[],"kv_write":[]}}"#).unwrap();
        let server = Server::new(root.join("wal.log"), tokens).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let owner = server
            .serve_owned(listener, Duration::from_secs(5))
            .unwrap();
        Self {
            owner: Some(owner),
            root,
            port,
        }
    }

    fn client(&self) -> Client {
        Client::connect(&format!("127.0.0.1:{}", self.port), "tester", "test-token").unwrap()
    }

    fn put(&self, id: &str, phase: &str, age: f64, cleanup: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let key = format!("ctx.sched.work.tester.{id}");
        let phase = match phase {
            "active" => Phase::Active,
            "terminal" => Phase::Terminal,
            _ => panic!("unexpected fixture phase"),
        };
        let cleanup = match cleanup {
            "pending" => Cleanup::Pending,
            "clean" => Cleanup::Clean,
            "uncertain" => Cleanup::Uncertain,
            _ => panic!("unexpected fixture cleanup"),
        };
        let terminal = phase == Phase::Terminal;
        let value = StatusRecord {
            task: "work".into(),
            agent: "tester".into(),
            run_id: id.into(),
            scheduler_pid: 1,
            child_pid: Some(2),
            scope_unit: None,
            phase,
            started_ts: now - age - 10.0,
            updated_ts: now - age,
            elapsed_s: 10.0,
            exit_code: terminal.then_some(0),
            timed_out: false,
            cancelled: false,
            outcome: terminal.then_some(if cleanup == Cleanup::Uncertain {
                Outcome::CleanupFailed
            } else {
                Outcome::Success
            }),
            cleanup,
            log_path: "fixture.log".into(),
            resources_requested: None,
            resources_observed: None,
        }
        .to_json();
        let reply = self
            .client()
            .rpc(&json!({"op":"kv_put","key":key,"value":value}))
            .unwrap();
        assert_eq!(reply["ok"], true);
    }

    fn run(&self, args: &[&str], allowed: bool) -> Output {
        Command::new(env!("CARGO_BIN_EXE_agent-bus"))
            .args(args)
            .env_remove("AGENT_BUS_SOCK")
            .env("AGENT_BUS_HOST", "127.0.0.1")
            .env("AGENT_BUS_PORT", self.port.to_string())
            .env("AGENT_BUS_AGENT", if allowed { "tester" } else { "reader" })
            .env(
                "AGENT_BUS_TOKEN",
                if allowed { "test-token" } else { "no-read" },
            )
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.shutdown();
        }
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn runs_distinguishes_new_active_from_old_done_heartbeat_and_terminal() {
    let fx = Fixture::new();
    let reply = fx
        .client()
        .rpc(&json!({"op":"heartbeat","status":"DONE old task"}))
        .unwrap();
    assert_eq!(reply["ok"], true);
    fx.put("old", "terminal", 120.0, "clean");
    fx.put("new", "active", 0.0, "pending");
    let output = fx.run(&["runs", "--format", "json"], true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let view: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rows = view["runs"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["record"]["run_id"], "new");
    assert_eq!(rows[0]["state"], "active");
    assert_eq!(rows[1]["state"], "terminal");
    assert_eq!(view["processes_checked"], false);
    assert_eq!(view["atomic_snapshot"], false);
    assert_eq!(view["possibly_truncated"], false);
    let presence = fx.run(&["agents"], true);
    assert!(presence.status.success());
    assert!(String::from_utf8_lossy(&presence.stdout).contains("DONE old task"));
    assert!(String::from_utf8_lossy(&presence.stderr).contains("heartbeat text, not task state"));
}

#[test]
fn runs_keeps_stale_report_and_cleanup_uncertainty_visible() {
    let fx = Fixture::new();
    fx.put("stale", "active", 61.0, "pending");
    fx.put("terminal", "terminal", 0.0, "uncertain");
    let output = fx.run(&["runs", "--format=json"], true);
    assert!(output.status.success());
    let view: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rows = view["runs"].as_array().unwrap();
    assert_eq!(rows[0]["state"], "unknown");
    assert_eq!(rows[0]["freshness"], "stale");
    assert_eq!(rows[0]["record"]["phase"], "active");
    assert_eq!(rows[1]["record"]["cleanup"], "uncertain");
    assert_eq!(rows[1]["record"]["outcome"], "cleanup_failed");
    let short = fx.run(&["runs"], true);
    assert!(short.status.success());
    let text = String::from_utf8(short.stdout).unwrap();
    assert!(text.contains("report=\"unknown\""));
    assert!(text.contains("cleanup=\"uncertain\""));
}

#[test]
fn runs_empty_prefix_is_unknown_and_prefix_narrows_visibility() {
    let fx = Fixture::new();
    fx.put("one", "active", 0.0, "pending");
    let empty = fx.run(&["runs", "ctx.sched.other."], true);
    assert!(empty.status.success());
    assert!(String::from_utf8_lossy(&empty.stdout).contains("state is unknown"));
    let output = fx.run(
        &["runs", "ctx.sched.work.tester.", "--format", "json"],
        true,
    );
    assert!(output.status.success());
    let view: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(view["prefix"], "ctx.sched.work.tester.");
    assert_eq!(view["runs"].as_array().unwrap().len(), 1);
}

#[test]
fn runs_refusal_is_an_error_without_a_successful_empty_view() {
    let fx = Fixture::new();
    let output = fx.run(&["runs", "--format", "json"], false);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn runs_usage_validation_does_not_need_credentials() {
    for args in [
        vec!["runs", "unrelated."],
        vec!["runs", "--format", "xml"],
        vec!["runs", "--wat"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
            .args(args)
            .env_remove("AGENT_BUS_TOKEN")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
