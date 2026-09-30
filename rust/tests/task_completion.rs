//! Focused task-completion checks: explicit worker evidence only.
//!
//! No live bus, no real `muse`, no Python. Tiny constructive fixtures cover a
//! valid `complete` file, a valid `needs_resume` file, a legacy no-report
//! run, CLI identity/receipt roundtrip, and unchanged process semantics when
//! a worker claims complete before a failure, plus actual scoped scheduler
//! rounds with a tiny native fake worker and an in-memory recording status
//! transport.

use agent_bus::scheduler::status::{
    Cleanup, Outcome, Phase, StatusRecord, StatusTransport, TERMINAL_TTL_MS,
};
use agent_bus::scheduler::{run_round_with_status, RunStatusConfig, SchedulerConfig};
use agent_bus::task_report::{
    create_report_context, read_task_completion, view_task_state, WorkerReport, WorkerState,
    ENV_AGENT, ENV_REPORT_PATH, ENV_RUN_ID, ENV_TASK, PROVENANCE, SCHEMA_VERSION,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;
use std::sync::{
    atomic::AtomicBool,
    Arc, Mutex,
};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "agent-bus-task-completion-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_json(path: &std::path::Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn base_record() -> StatusRecord {
    StatusRecord {
        task: "demo".into(),
        run_id: "run-1".into(),
        agent: "worker".into(),
        scheduler_pid: 1,
        child_pid: Some(2),
        scope_unit: Some("u.scope".into()),
        phase: Phase::Terminal,
        started_ts: 10.0,
        updated_ts: 12.0,
        elapsed_s: 2.0,
        exit_code: Some(0),
        timed_out: false,
        cancelled: false,
        outcome: Some(Outcome::Success),
        cleanup: Cleanup::Clean,
        log_path: "l".into(),
        resources_requested: None,
        resources_observed: None,
    }
}

#[test]
fn valid_complete_report_reads_complete() {
    let dir = tmpdir("complete");
    let report_path = dir.join("report.json");
    write_json(
        &report_path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "provenance": PROVENANCE,
            "run_id": "run-1",
            "task": "demo",
            "agent": "worker",
            "state": "complete",
            "summary": "indexed 12 files",
            "remaining": Value::Null,
            "inbox_cursor": 205,
        }),
    );
    let task = read_task_completion(Some(report_path.as_path()), "run-1", "demo", "worker");
    assert_eq!(task.state.as_str(), "complete");
    assert!(task.reason.is_none());
    let report = task.report.as_ref().expect("complete keeps report");
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.provenance, PROVENANCE);
    assert_eq!(report.run_id, "run-1");
    assert_eq!(report.summary, "indexed 12 files");
    assert!(report.remaining.is_none());
    assert_eq!(report.inbox_cursor, Some(205));
    // Status carries it separately; runs view derives it without inference.
    let rec = base_record();
    let value = rec.to_json_with_task(&task);
    assert_eq!(value["outcome"], json!("success"));
    assert_eq!(value["task_completion"]["state"], json!("complete"));
    let (state, reason) = view_task_state(&value);
    assert_eq!(state, "complete");
    assert_eq!(reason, Value::Null);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn valid_needs_resume_requires_specific_remaining() {
    let dir = tmpdir("resume");
    let good = dir.join("good.json");
    write_json(
        &good,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "provenance": PROVENANCE,
            "run_id": "run-2",
            "task": "demo",
            "agent": "worker",
            "state": "needs_resume",
            "summary": "indexed 4 of 12",
            "remaining": "index files 5-12; cursor 206",
            "inbox_cursor": 206,
        }),
    );
    let task = read_task_completion(Some(good.as_path()), "run-2", "demo", "worker");
    assert_eq!(task.state.as_str(), "needs_resume");
    let report = task.report.expect("resume keeps report");
    assert_eq!(report.remaining.as_deref(), Some("index files 5-12; cursor 206"));

    // needs_resume without remaining is invalid, not a silent complete.
    let bad_resume = dir.join("bad-resume.json");
    write_json(
        &bad_resume,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "provenance": PROVENANCE,
            "run_id": "run-2",
            "task": "demo",
            "agent": "worker",
            "state": "needs_resume",
            "summary": "indexed 4 of 12",
        }),
    );
    let unknown = read_task_completion(Some(bad_resume.as_path()), "run-2", "demo", "worker");
    assert_eq!(unknown.state.as_str(), "unknown");
    assert_eq!(unknown.reason.as_deref(), Some("invalid"));

    // complete claiming remaining work is invalid, not proof.
    let bad_complete = dir.join("bad-complete.json");
    write_json(
        &bad_complete,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "provenance": PROVENANCE,
            "run_id": "run-2",
            "task": "demo",
            "agent": "worker",
            "state": "complete",
            "summary": "indexed 12 files",
            "remaining": "leftover",
        }),
    );
    let unknown = read_task_completion(Some(bad_complete.as_path()), "run-2", "demo", "worker");
    assert_eq!(unknown.state.as_str(), "unknown");
    assert_eq!(unknown.reason.as_deref(), Some("invalid"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_and_missing_are_unknown_without_process_inference() {
    // Missing file never becomes complete from exit 0 or outcome success.
    let missing = read_task_completion(
        Some(std::path::Path::new("/nonexistent-task-report-xyz/report.json")),
        "r",
        "t",
        "a",
    );
    assert_eq!(missing.state.as_str(), "unknown");
    assert_eq!(missing.reason.as_deref(), Some("missing"));
    let none = read_task_completion(None, "r", "t", "a");
    assert_eq!(none.state.as_str(), "unknown");

    // Legacy record without the new field reads unknown even on success.
    let legacy = json!({
        "task": "demo", "agent": "worker", "run_id": "old",
        "phase": "terminal", "outcome": "success", "exit_code": 0,
        "started_ts": 1.0, "updated_ts": 2.0,
    });
    let (state, reason) = view_task_state(&legacy);
    assert_eq!(state, "unknown");
    assert_eq!(reason, json!("legacy"));

    // Mismatched identity never leaks worker text in the reason.
    let dir = tmpdir("mismatch");
    let path = dir.join("report.json");
    write_json(
        &path,
        &json!({
            "schema_version": SCHEMA_VERSION,
            "provenance": PROVENANCE,
            "run_id": "other-run",
            "task": "demo",
            "agent": "worker",
            "state": "complete",
            "summary": "secret-summary-must-not-leak",
        }),
    );
    let mismatch = read_task_completion(Some(path.as_path()), "run-1", "demo", "worker");
    assert_eq!(mismatch.state.as_str(), "unknown");
    assert_eq!(mismatch.reason.as_deref(), Some("mismatched"));
    assert!(mismatch.report.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_receipt_roundtrip_matches_scheduler_env_identity() {
    let dir = tmpdir("cli-roundtrip");
    let report_dir = dir.join("run");
    std::fs::create_dir(&report_dir).unwrap();
    let report_path = report_dir.join("report.json");
    let run = "cli-run-1";
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .args([
            "task-report",
            "--state",
            "complete",
            "--summary",
            "did the work",
            "--inbox-cursor",
            "207",
        ])
        .env(ENV_REPORT_PATH, &report_path)
        .env(ENV_RUN_ID, run)
        .env(ENV_TASK, "demo")
        .env(ENV_AGENT, "worker")
        .env_remove("AGENT_BUS_SOCK")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["ok"], json!(true));
    assert_eq!(receipt["run_id"], json!(run));
    assert_eq!(receipt["task"], json!("demo"));
    assert_eq!(receipt["agent"], json!("worker"));
    assert_eq!(receipt["state"], json!("complete"));
    // Scheduler read of the CLI-written file preserves identity and state.
    let task = read_task_completion(Some(report_path.as_path()), run, "demo", "worker");
    assert_eq!(task.state.as_str(), "complete");
    let report = task.report.unwrap();
    assert_eq!(report.summary, "did the work");
    assert_eq!(report.inbox_cursor, Some(207));
    // Final file stays for capture.
    assert!(report_path.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&report_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "CLI report file is owner-only");
    }

    // needs_resume roundtrip with remaining work.
    let report_dir2 = dir.join("run2");
    std::fs::create_dir(&report_dir2).unwrap();
    let report_path2 = report_dir2.join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .args([
            "task-report",
            "--state",
            "needs_resume",
            "--summary",
            "half done",
            "--remaining",
            "finish other half",
        ])
        .env(ENV_REPORT_PATH, &report_path2)
        .env(ENV_RUN_ID, "cli-run-2")
        .env(ENV_TASK, "demo")
        .env(ENV_AGENT, "worker")
        .env_remove("AGENT_BUS_SOCK")
        .output()
        .unwrap();
    assert!(output.status.success());
    let task = read_task_completion(Some(report_path2.as_path()), "cli-run-2", "demo", "worker");
    assert_eq!(task.state.as_str(), "needs_resume");
    assert_eq!(
        task.report.unwrap().remaining.as_deref(),
        Some("finish other half")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_rejects_state_rule_violations_and_missing_env() {
    let dir = tmpdir("cli-reject");
    let report_dir = dir.join("run");
    std::fs::create_dir(&report_dir).unwrap();
    let report_path = report_dir.join("report.json");
    // complete must not claim remaining.
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .args([
            "task-report",
            "--state",
            "complete",
            "--summary",
            "done",
            "--remaining",
            "leftover",
        ])
        .env(ENV_REPORT_PATH, &report_path)
        .env(ENV_RUN_ID, "r")
        .env(ENV_TASK, "t")
        .env(ENV_AGENT, "a")
        .env_remove("AGENT_BUS_SOCK")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!report_path.exists());
    // needs_resume requires remaining.
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .args(["task-report", "--state", "needs_resume", "--summary", "half"])
        .env(ENV_REPORT_PATH, &report_path)
        .env(ENV_RUN_ID, "r")
        .env(ENV_TASK, "t")
        .env(ENV_AGENT, "a")
        .env_remove("AGENT_BUS_SOCK")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    // Missing scheduler env never writes.
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .args(["task-report", "--state", "complete", "--summary", "done"])
        .env_remove(ENV_REPORT_PATH)
        .env_remove(ENV_RUN_ID)
        .env_remove(ENV_TASK)
        .env_remove(ENV_AGENT)
        .env_remove("AGENT_BUS_SOCK")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn worker_complete_does_not_change_process_failure() {
    // Simulate a terminal failure where the worker already asserted complete:
    // process outcome/cleanup come only from supervision, task stays separate.
    let report = WorkerReport {
        schema_version: SCHEMA_VERSION,
        provenance: PROVENANCE.to_string(),
        run_id: "run-9".to_string(),
        task: "demo".to_string(),
        agent: "worker".to_string(),
        state: WorkerState::Complete,
        summary: "worker thought it was done".to_string(),
        remaining: None,
        inbox_cursor: None,
    };
    let task = agent_bus::task_report::TaskCompletion::from_report(report);
    let mut rec = base_record();
    rec.run_id = "run-9".into();
    rec.exit_code = Some(7);
    rec.outcome = Some(Outcome::Failure);
    rec.cleanup = Cleanup::Clean;
    let value = rec.to_json_with_scope_and_task(None, &task);
    assert_eq!(value["outcome"], json!("failure"));
    assert_eq!(value["exit_code"], json!(7));
    assert_eq!(value["cleanup"], json!("clean"));
    assert_eq!(value["task_completion"]["state"], json!("complete"));
    let (state, _) = view_task_state(&value);
    assert_eq!(state, "complete");
}

#[test]
fn per_run_report_directories_are_unique_and_owned() {
    let run1 = unique_run_id("perrun1");
    let run2 = unique_run_id("perrun2");
    let ctx1 = create_report_context("demo", "worker", &run1).unwrap();
    let ctx2 = create_report_context("demo", "worker", &run2).unwrap();
    assert_ne!(ctx1.dir, ctx2.dir);
    assert_ne!(ctx1.path, ctx2.path);
    assert_eq!(ctx1.path.file_name().unwrap(), "report.json");
    assert!(ctx1.dir.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&ctx1.dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "report dir is owner-only");
    }
    // No reuse: recreating the same run refuses.
    assert!(create_report_context("demo", "worker", &run1).is_err());
    // Missing file in an owned directory reads unknown, not stale.
    let task = read_task_completion(Some(ctx1.path.as_path()), &run1, "demo", "worker");
    assert_eq!(task.state.as_str(), "unknown");
    let _ = std::fs::remove_dir_all(&ctx1.dir);
    let _ = std::fs::remove_dir_all(&ctx2.dir);
}

#[test]
fn cli_summary_help_value_is_data_not_help() {
    // A legitimate option value spelled --help must not trigger help.
    let dir = tmpdir("cli-help-value");
    let report_dir = dir.join("run");
    std::fs::create_dir(&report_dir).unwrap();
    let report_path = report_dir.join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .args(["task-report", "--state", "complete", "--summary", "--help"])
        .env(ENV_REPORT_PATH, &report_path)
        .env(ENV_RUN_ID, "help-run")
        .env(ENV_TASK, "demo")
        .env(ENV_AGENT, "worker")
        .env_remove("AGENT_BUS_SOCK")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cli treated --help value as help: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["ok"], json!(true));
    assert_eq!(receipt["state"], json!("complete"));
    let task = read_task_completion(Some(report_path.as_path()), "help-run", "demo", "worker");
    assert_eq!(task.state.as_str(), "complete");
    assert_eq!(task.report.as_ref().unwrap().summary, "--help");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn view_requires_outer_inner_agreement_and_accepts_unavailable() {
    // Outer complete but inner needs_resume is inconsistent, not proof.
    let rec = json!({
        "task": "demo", "agent": "worker", "run_id": "run-1",
        "task_completion": {
            "state": "complete", "reason": null,
            "report": {
                "schema_version": SCHEMA_VERSION,
                "provenance": PROVENANCE,
                "run_id": "run-1", "task": "demo", "agent": "worker",
                "state": "needs_resume",
                "summary": "half",
                "remaining": "rest",
                "inbox_cursor": null
            }
        }
    });
    let (state, reason) = view_task_state(&rec);
    assert_eq!(state, "unknown");
    assert_eq!(reason, json!("invalid"));
    // Enabled-but-uncreatable context keeps its distinct reason.
    let (state, reason) = view_task_state(&json!({
        "task_completion": {"state": "unknown", "reason": "unavailable", "report": null}
    }));
    assert_eq!(state, "unknown");
    assert_eq!(reason, json!("unavailable"));
}

// ---------------------------------------------------------------------------
// Actual scoped scheduler rounds with a tiny native fake worker.
// No production broker, no real muse, no shells: the fake is small Rust
// compiled with rustc, status uses an in-memory recording transport, and the
// real run_round_with_status scoped spawn/env/report/final-state wiring runs.
// These tests set process env to prove scrubbing; they serialize on a common
// mutex with RAII restoration (safe under default threads) and still run
// serially per coordinator cargo policy.
// ---------------------------------------------------------------------------

const FAKE_REPORT_WORKER_SRC: &str = r#"
fn cfg_value(cfg: &str, key: &str) -> Option<String> {
    for line in cfg.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key { return Some(v.trim().to_string()); }
        }
    }
    None
}
fn env_capture(var: &str) -> String {
    match std::env::var_os(var) {
        None => "ABSENT".to_string(),
        Some(v) => format!("PRESENT:{}", v.to_string_lossy()),
    }
}
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut prompt_file: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--prompt-file" { prompt_file = it.next().cloned(); break; }
    }
    let cfg_path = prompt_file.map(|p| p + ".fake-cfg").unwrap_or_else(|| "/dev/null".to_string());
    let cfg = std::fs::read_to_string(&cfg_path).unwrap_or_default();
    let mode = cfg_value(&cfg, "MODE").unwrap_or_else(|| "capture".to_string());
    if let Some(cap) = cfg_value(&cfg, "ENV_CAPTURE") {
        let content = format!(
            "PATH={}\nRUN_ID={}\nTASK={}\nAGENT={}\n",
            env_capture("AGENT_BUS_TASK_REPORT_PATH"),
            env_capture("AGENT_BUS_TASK_REPORT_RUN_ID"),
            env_capture("AGENT_BUS_TASK_REPORT_TASK"),
            env_capture("AGENT_BUS_TASK_REPORT_AGENT"),
        );
        let _ = std::fs::write(&cap, content);
    }
    if mode == "write_complete" {
        let path = std::env::var_os("AGENT_BUS_TASK_REPORT_PATH").unwrap_or_default();
        let run = std::env::var("AGENT_BUS_TASK_REPORT_RUN_ID").unwrap_or_default();
        let task = std::env::var("AGENT_BUS_TASK_REPORT_TASK").unwrap_or_default();
        let agent = std::env::var("AGENT_BUS_TASK_REPORT_AGENT").unwrap_or_default();
        if path.is_empty() || run.is_empty() || task.is_empty() || agent.is_empty() {
            std::process::exit(3);
        }
        let dest = std::path::PathBuf::from(path);
        let parent = dest.parent().unwrap_or(std::path::Path::new("."));
        let body = format!(
            "{{\"schema_version\":1,\"provenance\":\"worker-report\",\"run_id\":\"{}\",\"task\":\"{}\",\"agent\":\"{}\",\"state\":\"complete\",\"summary\":\"fake worker done\",\"remaining\":null,\"inbox_cursor\":999}}",
            json_escape(&run), json_escape(&task), json_escape(&agent)
        );
        let tmp = parent.join(format!(".report.json.tmp.{}", std::process::id()));
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = match opts.open(&tmp) {
                Ok(f) => f,
                Err(_) => std::process::exit(4),
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            use std::io::Write;
            if f.write_all(format!("{body}\n").as_bytes()).is_err() {
                let _ = std::fs::remove_file(&tmp);
                std::process::exit(4);
            }
        }
        if std::fs::rename(&tmp, &dest).is_err() {
            let _ = std::fs::remove_file(&tmp);
            std::process::exit(5);
        }
    }
    std::process::exit(0);
}
"#;

fn fake_report_worker_bin() -> String {
    static FAKE_BIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FAKE_BIN
        .get_or_init(|| {
            let dir =
                std::env::temp_dir().join(format!("agent-bus-fake-report-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let src = dir.join("fake_report_worker.rs");
            let out = dir.join("fake-report-worker");
            let rebuild = std::fs::read_to_string(&src).ok().as_deref() != Some(FAKE_REPORT_WORKER_SRC);
            if rebuild {
                std::fs::write(&src, FAKE_REPORT_WORKER_SRC).unwrap();
                let st = std::process::Command::new("rustc")
                    .args(["--edition", "2021", "-O", "-o"])
                    .arg(&out)
                    .arg(&src)
                    .stdin(std::process::Stdio::null())
                    .output()
                    .expect("rustc must be available");
                assert!(
                    st.status.success(),
                    "rustc failed: {}",
                    String::from_utf8_lossy(&st.stderr)
                );
            }
            out.to_string_lossy().into_owned()
        })
        .clone()
}

fn base_round_cfg(dir: &std::path::Path) -> SchedulerConfig {
    let template = dir.join("prompt.md");
    std::fs::write(&template, "You are AGENT_NAME, role AGENT_ROLE.").unwrap();
    SchedulerConfig {
        template_path: template.to_string_lossy().into_owned(),
        prompt_out: dir.join("rendered.md").to_string_lossy().into_owned(),
        workspace: dir.to_string_lossy().into_owned(),
        agent: "worker".into(),
        role: "test-role".into(),
        interval_secs: 60,
        initial_delay_secs: 0,
        round_steps: 5,
        round_timeout_secs: 30,
        log_path: dir.join("round.log").to_string_lossy().into_owned(),
        reasoning_effort: None,
        subagent_worktree_isolation: false,
        muse_bin: fake_report_worker_bin(),
        resource_policy: agent_bus::scheduler::ResourcePolicy::default(),
    }
}

#[derive(Clone, Default)]
struct MemState {
    puts: Vec<(String, Value, u64)>,
}

#[derive(Clone)]
struct MemTransport {
    state: Arc<Mutex<MemState>>,
}

impl MemTransport {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MemState::default())),
        }
    }
    fn puts(&self) -> Vec<(String, Value, u64)> {
        self.state.lock().unwrap().puts.clone()
    }
}

impl StatusTransport for MemTransport {
    fn put(
        &mut self,
        key: &str,
        value: Value,
        ttl_ms: u64,
        _cancel: &AtomicBool,
    ) -> Result<(), String> {
        self.state
            .lock()
            .unwrap()
            .puts
            .push((key.to_string(), value, ttl_ms));
        Ok(())
    }
}

fn clear_report_env() {
    for v in [ENV_REPORT_PATH, ENV_RUN_ID, ENV_TASK, ENV_AGENT] {
        std::env::remove_var(v);
    }
}

fn set_stale_report_env() {
    std::env::set_var(ENV_REPORT_PATH, "/stale/report.json");
    std::env::set_var(ENV_RUN_ID, "stale-run");
    std::env::set_var(ENV_TASK, "stale-task");
    std::env::set_var(ENV_AGENT, "stale-agent");
}

// Process-global report env is shared by all tests in this binary. The two
// actual-round tests install stale fixtures to prove scrubbing, so they
// serialize on one mutex and restore exact original bytes (absent vs
// present, UTF8 vs non-UTF8 via var_os/OsString) with RAII, even on panic.
// Ordinary isolation only; no race reproduction.
static REPORT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct ReportEnvGuard {
    saved: [(String, Option<std::ffi::OsString>); 4],
}

impl ReportEnvGuard {
    fn capture() -> Self {
        Self {
            saved: [
                (
                    ENV_REPORT_PATH.to_string(),
                    std::env::var_os(ENV_REPORT_PATH),
                ),
                (ENV_RUN_ID.to_string(), std::env::var_os(ENV_RUN_ID)),
                (ENV_TASK.to_string(), std::env::var_os(ENV_TASK)),
                (ENV_AGENT.to_string(), std::env::var_os(ENV_AGENT)),
            ],
        }
    }
}

impl Drop for ReportEnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.iter() {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn lock_report_env() -> std::sync::MutexGuard<'static, ()> {
    REPORT_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

static RUN_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// Per-fixture unique run IDs: pid + nanos + counter, so separate test
// processes or leftover failed fixtures never collide on global tmp names.
fn unique_run_id(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = RUN_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("r54-{}-{}-{}-{}", tag, std::process::id(), nanos, n)
}

fn parse_capture(path: &std::path::Path) -> HashMap<String, String> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut map = HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

#[test]
fn actual_enabled_rounds_wire_env_report_and_final_state() {
    let _lock = lock_report_env();
    let _env_guard = ReportEnvGuard::capture();
    clear_report_env();
    set_stale_report_env();
    let dir = tmpdir("actual-enabled");
    let cfg = base_round_cfg(&dir);
    let cap1 = dir.join("env1.txt");
    std::fs::write(
        format!("{}.fake-cfg", cfg.prompt_out),
        format!("MODE=write_complete\nENV_CAPTURE={}\n", cap1.display()),
    )
    .unwrap();
    let mut sc = RunStatusConfig::new("demo");
    sc.task_report = true;
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
    assert_eq!(code, 0);
    let puts = mem_c.puts();
    assert!(!puts.is_empty(), "enabled round emits status");
    let (key1, term1, ttl1) = puts.last().unwrap().clone();
    assert!(key1.starts_with("ctx.sched.demo.worker."));
    assert_eq!(ttl1, TERMINAL_TTL_MS);
    assert_eq!(term1["phase"], json!("terminal"));
    assert_eq!(term1["outcome"], json!("success"));
    assert_eq!(term1["cleanup"], json!("clean"));
    assert_eq!(term1["task_completion"]["state"], json!("complete"));
    let run1 = term1["run_id"].as_str().unwrap().to_string();
    let report1 = &term1["task_completion"]["report"];
    assert_eq!(report1["run_id"], json!(run1));
    assert_eq!(report1["task"], json!("demo"));
    assert_eq!(report1["agent"], json!("worker"));
    assert_eq!(report1["summary"], json!("fake worker done"));
    assert_eq!(report1["inbox_cursor"], json!(999));
    assert!(report1.get("remaining").is_none() || report1["remaining"].is_null());
    // Child saw fresh per-run identity, not stale parent env.
    let cap = parse_capture(&cap1);
    let worker_path = cap["PATH"].strip_prefix("PRESENT:").unwrap().to_string();
    assert!(!worker_path.contains("/stale/"));
    assert_eq!(cap["RUN_ID"], format!("PRESENT:{run1}"));
    assert_eq!(cap["TASK"], "PRESENT:demo");
    assert_eq!(cap["AGENT"], "PRESENT:worker");
    // Final file equals the terminal report; per-run dir left for capture.
    let file_json: Value =
        serde_json::from_slice(&std::fs::read(&worker_path).unwrap()).unwrap();
    assert_eq!(file_json["run_id"], json!(run1));
    assert_eq!(file_json["summary"], json!("fake worker done"));
    assert_eq!(file_json["state"], json!("complete"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&worker_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "round report file is owner-only");
    }
    let (view_state, view_reason) = view_task_state(&term1);
    assert_eq!(view_state, "complete");
    assert_eq!(view_reason, Value::Null);
    // Second round proves unique per-run identity.
    let cap2 = dir.join("env2.txt");
    std::fs::write(
        format!("{}.fake-cfg", cfg.prompt_out),
        format!("MODE=write_complete\nENV_CAPTURE={}\n", cap2.display()),
    )
    .unwrap();
    let mem2 = MemTransport::new();
    let mem2_c = mem2.clone();
    let code2 = run_round_with_status(&cfg, &sc, Box::new(mem2)).unwrap();
    assert_eq!(code2, 0);
    let puts2 = mem2_c.puts();
    let (_, term2, _) = puts2.last().unwrap().clone();
    let run2 = term2["run_id"].as_str().unwrap().to_string();
    assert_ne!(run1, run2, "per-run identity is unique");
    let cap2m = parse_capture(&cap2);
    let worker_path2 = cap2m["PATH"].strip_prefix("PRESENT:").unwrap().to_string();
    assert_ne!(worker_path, worker_path2);
    assert_eq!(term2["task_completion"]["state"], json!("complete"));
    let _ = std::fs::remove_dir_all(&dir);
    // _env_guard restores exact original bytes here (even on panic), then
    // _lock releases; no explicit clear that would lose inherited values.
}

#[test]
fn actual_disabled_round_scrubs_inherited_report_env() {
    let _lock = lock_report_env();
    let _env_guard = ReportEnvGuard::capture();
    clear_report_env();
    set_stale_report_env();
    let dir = tmpdir("actual-disabled");
    let cfg = base_round_cfg(&dir);
    let cap = dir.join("env.txt");
    std::fs::write(
        format!("{}.fake-cfg", cfg.prompt_out),
        format!("MODE=capture\nENV_CAPTURE={}\n", cap.display()),
    )
    .unwrap();
    let sc = RunStatusConfig::new("demo");
    assert!(!sc.task_report, "disabled by default");
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
    assert_eq!(code, 0);
    let puts = mem_c.puts();
    let (_, term, _) = puts.last().unwrap().clone();
    assert_eq!(term["outcome"], json!("success"));
    assert_eq!(term["cleanup"], json!("clean"));
    assert_eq!(term["task_completion"]["state"], json!("unknown"));
    assert_eq!(term["task_completion"]["reason"], json!("missing"));
    assert!(term["task_completion"]["report"].is_null());
    let capm = parse_capture(&cap);
    assert_eq!(capm["PATH"], "ABSENT");
    assert_eq!(capm["RUN_ID"], "ABSENT");
    assert_eq!(capm["TASK"], "ABSENT");
    assert_eq!(capm["AGENT"], "ABSENT");
    let _ = std::fs::remove_dir_all(&dir);
    // _env_guard restores exact original bytes here (even on panic), then
    // _lock releases; no explicit clear that would lose inherited values.
}
