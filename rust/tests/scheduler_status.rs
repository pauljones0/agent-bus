//! Scheduler run-status tests: bounded reporter, unique TTL records, wiring.
//!
//! No Python, no production IO, no real `muse`: fake workloads are small Rust
//! binaries compiled with `rustc`, bus interaction uses in-memory fakes plus
//! one ephemeral loopback `wire::Server`. Proves inbox43 bounds: supervision
//! never blocks on bus IO, reporter shutdown is bounded and joined, terminal
//! outcome/cleanup certainty reflect the real round, and default offline is
//! unchanged.

use agent_bus::scheduler::status::{
    new_run_id, status_key, NativeStatusTransport, ReporterOutcome, StatusRecord, StatusReporter,
    StatusTransport, ACTIVE_TTL_MS, STATUS_KEY_PREFIX, TERMINAL_TTL_MS,
};
use agent_bus::scheduler::{run_round, run_round_with_status, RunStatusConfig, SchedulerConfig};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

const FAKE_CHILD_SRC: &str = r#"
use std::time::Duration;
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
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut prompt_file: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--prompt-file" { prompt_file = it.next().cloned(); break; }
    }
    let cfg_path = prompt_file.map(|p| p + ".fake-cfg").unwrap_or_else(|| "/dev/null".to_string());
    let cfg = std::fs::read_to_string(&cfg_path).unwrap_or_default();
    if let Some(p) = cfg_value(&cfg, "DIRECT_PID_FILE") {
        let _ = std::fs::write(&p, std::process::id().to_string());
    }
    if let Some(f) = cfg_value(&cfg, "TOUCH") { let _ = std::fs::write(&f, "spawned"); }
    if let Some(m) = cfg_value(&cfg, "MARK") { println!("{m}"); }
    if let Some(s) = cfg_value(&cfg, "SLEEP_SECS") {
        std::thread::sleep(Duration::from_secs(s.parse().unwrap_or(0)));
    }
    let code: i32 = cfg_value(&cfg, "EXIT").and_then(|v| v.parse().ok()).unwrap_or(0);
    std::process::exit(code);
}
"#;

fn fake_child_bin() -> String {
    static FAKE_BIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FAKE_BIN
        .get_or_init(|| {
            let dir =
                std::env::temp_dir().join(format!("agent-bus-fake-status-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let src = dir.join("fake_status.rs");
            let out = dir.join("fake-status-child");
            let rebuild = std::fs::read_to_string(&src).ok().as_deref() != Some(FAKE_CHILD_SRC);
            if rebuild {
                std::fs::write(&src, FAKE_CHILD_SRC).unwrap();
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

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "agent-bus-status-test-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_cfg(dir: &std::path::Path) -> SchedulerConfig {
    let template = dir.join("prompt.md");
    std::fs::write(&template, "You are AGENT_NAME, role AGENT_ROLE.").unwrap();
    SchedulerConfig {
        template_path: template.to_string_lossy().into_owned(),
        prompt_out: dir.join("rendered.md").to_string_lossy().into_owned(),
        workspace: dir.to_string_lossy().into_owned(),
        agent: "test-agent".into(),
        role: "test-role".into(),
        interval_secs: 60,
        initial_delay_secs: 0,
        round_steps: 5,
        round_timeout_secs: 30,
        log_path: dir.join("round.log").to_string_lossy().into_owned(),
        reasoning_effort: None,
        subagent_worktree_isolation: false,
        muse_bin: fake_child_bin(),
        resource_policy: agent_bus::scheduler::ResourcePolicy::default(),
    }
}

fn write_cfg(cfg: &SchedulerConfig, body: &str) {
    std::fs::write(format!("{}.fake-cfg", cfg.prompt_out), body).unwrap();
}

#[derive(Clone, Default)]
struct MemState {
    puts: Vec<(String, Value, u64)>,
}

#[derive(Clone)]
struct MemTransport {
    state: Arc<Mutex<MemState>>,
    delay: Duration,
    fail_with: Option<String>,
    hang_active: bool,
}

impl MemTransport {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MemState::default())),
            delay: Duration::from_millis(0),
            fail_with: None,
            hang_active: false,
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
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let phase = value.get("phase").and_then(|v| v.as_str()).unwrap_or("");
        if self.hang_active && phase != "terminal" {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(30) {
                if cancel.load(Ordering::Relaxed) {
                    return Err("cancelled".to_string());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            return Err("hang timeout".to_string());
        }
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        if let Some(e) = &self.fail_with {
            return Err(e.clone());
        }
        self.state
            .lock()
            .unwrap()
            .puts
            .push((key.to_string(), value, ttl_ms));
        Ok(())
    }
}

#[test]
fn keys_unique_prefix_sanitized_finite_ttl() {
    assert_eq!(STATUS_KEY_PREFIX, "ctx.sched.");
    assert!(ACTIVE_TTL_MS > 0 && TERMINAL_TTL_MS > 0);
    let mut seen = HashSet::new();
    for _ in 0..50 {
        let id = new_run_id();
        let k = status_key("my task!", "ag/ent", &id).unwrap();
        assert!(k.starts_with("ctx.sched."));
        assert!(!k.contains(' ') && !k.contains('/'));
        assert!(seen.insert(k));
    }
    assert!(status_key("", "a", "r").is_err());
}

#[test]
fn default_round_has_no_bus_io() {
    let dir = tmpdir("default-no-bus");
    let cfg = base_cfg(&dir);
    write_cfg(&cfg, "EXIT=0\nMARK=default-mark\n");
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(log.contains("default-mark"));
    assert!(!log.contains("status reporting"));
}

#[test]
fn bus_status_requires_task() {
    let dir = tmpdir("requires-task");
    let cfg = base_cfg(&dir);
    write_cfg(&cfg, "EXIT=0\n");
    let sc = RunStatusConfig::new("");
    let mem = MemTransport::new();
    let r = run_round_with_status(&cfg, &sc, Box::new(mem));
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("--task"));
}

#[test]
fn terminal_success_record_typed() {
    let dir = tmpdir("success");
    let cfg = base_cfg(&dir);
    write_cfg(&cfg, "EXIT=0\n");
    let sc = RunStatusConfig::new("demo-task");
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
    assert_eq!(code, 0);
    let puts = mem_c.puts();
    assert!(!puts.is_empty());
    let (key, term, ttl) = puts.last().unwrap().clone();
    assert!(key.starts_with("ctx.sched.demo-task.test-agent."));
    assert_eq!(ttl, TERMINAL_TTL_MS);
    assert_eq!(term["phase"], json!("terminal"));
    assert_eq!(term["outcome"], json!("success"));
    assert_eq!(term["cleanup"], json!("clean"));
    assert_eq!(term["exit_code"], json!(0));
    assert_eq!(term["timed_out"], json!(false));
    assert!(term["child_pid"].is_number());
    assert!(term["scope_unit"].is_string());
    assert!(term.get("token").is_none());
    for (k, _, t) in puts.iter().take(puts.len().saturating_sub(1)) {
        assert_eq!(k, &key);
        assert_eq!(*t, ACTIVE_TTL_MS);
    }
}

#[test]
fn terminal_failure_and_timeout_distinguished() {
    let dir = tmpdir("failure");
    let cfg = base_cfg(&dir);
    write_cfg(&cfg, "EXIT=7\n");
    let sc = RunStatusConfig::new("t");
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
    assert_eq!(code, 7);
    let puts = mem_c.puts();
    let term = &puts.last().unwrap().1;
    assert_eq!(term["outcome"], json!("failure"));
    assert_eq!(term["exit_code"], json!(7));
    assert_eq!(term["cleanup"], json!("clean"));

    let dir2 = tmpdir("timeout");
    let mut cfg2 = base_cfg(&dir2);
    cfg2.round_timeout_secs = 1;
    write_cfg(&cfg2, "SLEEP_SECS=60\n");
    let sc2 = RunStatusConfig::new("t");
    let mem2 = MemTransport::new();
    let mem2_c = mem2.clone();
    let start = Instant::now();
    let code2 = run_round_with_status(&cfg2, &sc2, Box::new(mem2)).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(code2, 124);
    assert!(elapsed.as_secs() < 30, "timeout bound widened: {elapsed:?}");
    let puts2 = mem2_c.puts();
    let term2 = &puts2.last().unwrap().1;
    assert_eq!(term2["outcome"], json!("timeout"));
    assert_eq!(term2["timed_out"], json!(true));
    assert_eq!(term2["cleanup"], json!("clean"));
}

#[test]
fn slow_bus_does_not_delay_timeout_cleanup() {
    // Real transport against a scripted listener that accepts but never
    // replies: every RPC times out at its owned 1s bound (no thread, no
    // DNS). A 1s round timeout must complete within original wait/cleanup
    // bounds plus bounded status shutdown — an 8s cap, not a 20s allowance.
    let (listener, addr) = scripted_listener();
    std::thread::spawn(move || {
        for _ in 0..5 {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let _ = read_line_timeout(&mut reader, Duration::from_secs(10));
            std::thread::sleep(Duration::from_secs(10));
        }
    });
    let dir = tmpdir("slow-bus-real");
    let mut cfg = base_cfg(&dir);
    cfg.round_timeout_secs = 1;
    write_cfg(&cfg, "SLEEP_SECS=60\n");
    let mut sc = RunStatusConfig::new("slow-task");
    sc.interval = Duration::from_millis(100);
    let transport = NativeStatusTransport::new(&addr, "a", "tok");
    let start = Instant::now();
    let code = run_round_with_status(&cfg, &sc, Box::new(transport)).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(code, 124);
    assert!(
        elapsed < Duration::from_secs(8),
        "slow bus delayed supervision beyond bounded shutdown: {elapsed:?}"
    );
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(log.contains("round TIMEOUT"), "missing timeout line: {log}");
    assert!(
        log.contains("status reporting degraded"),
        "missing degraded line: {log}"
    );
}

#[test]
fn hanging_bus_shutdown_bounded_via_cancel() {
    let mut mem = MemTransport::new();
    mem.hang_active = true;
    let mem_c = mem.clone();
    let reporter = StatusReporter::new(Box::new(mem));
    let key = status_key("t", "a", &new_run_id()).unwrap();
    let active = json!({"phase": "active"});
    assert!(reporter.update(&key, active, ACTIVE_TTL_MS));
    std::thread::sleep(Duration::from_millis(200));
    let term = json!({"phase": "terminal"});
    let start = Instant::now();
    let outcome = reporter.shutdown(Some((key.clone(), term.clone(), TERMINAL_TTL_MS)));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "shutdown hung: {elapsed:?}"
    );
    assert_eq!(outcome.terminal_ok, Some(true));
    let puts = mem_c.puts();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].1["phase"], json!("terminal"));
}

#[test]
fn bus_failures_never_fail_round() {
    for fail in [
        "connection refused",
        "protocol error",
        "kv_put denied (grant missing)",
    ] {
        let dir = tmpdir("bus-fail");
        let cfg = base_cfg(&dir);
        write_cfg(&cfg, "EXIT=0\n");
        let sc = RunStatusConfig::new("t");
        let mut mem = MemTransport::new();
        mem.fail_with = Some(fail.to_string());
        let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
        assert_eq!(code, 0, "bus failure {fail} failed round");
        let log = std::fs::read_to_string(&cfg.log_path).unwrap();
        assert!(
            log.contains("status reporting degraded"),
            "missing degraded log: {log}"
        );
        assert!(log.contains("=== exit 0 ==="));
    }
}

#[test]
fn concurrent_runs_keep_unique_keys_no_pointer() {
    let shared = Arc::new(Mutex::new(MemState::default()));
    let mut handles = Vec::new();
    for i in 0..8 {
        let state = Arc::clone(&shared);
        handles.push(std::thread::spawn(move || {
            let mem = MemTransport {
                state,
                delay: Duration::from_millis(0),
                fail_with: None,
                hang_active: false,
            };
            let reporter = StatusReporter::new(Box::new(mem));
            let key = status_key("ct", "ca", &format!("run-{i}-{}", new_run_id())).unwrap();
            let _ = reporter.update(&key, json!({"phase": "active", "i": i}), ACTIVE_TTL_MS);
            let out = reporter.shutdown(Some((
                key,
                json!({"phase": "terminal", "i": i}),
                TERMINAL_TTL_MS,
            )));
            assert_eq!(out.terminal_ok, Some(true));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let puts = shared.lock().unwrap().puts.clone();
    let mut keys = HashSet::new();
    for (k, _, _) in &puts {
        assert!(k.starts_with("ctx.sched."));
        assert!(!k.ends_with("current") && !k.ends_with("latest"));
        assert!(!k.contains("current-run"));
        keys.insert(k.clone());
    }
    assert!(keys.len() >= 8, "keys collapsed: {keys:?}");
}

#[test]
fn active_refreshes_periodic_with_pending_cleanup() {
    let dir = tmpdir("active-periodic");
    let mut cfg = base_cfg(&dir);
    cfg.round_timeout_secs = 30;
    write_cfg(&cfg, "SLEEP_SECS=3\nEXIT=0\n");
    let mut sc = RunStatusConfig::new("periodic");
    sc.interval = Duration::from_millis(500);
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
    assert_eq!(code, 0);
    let puts = mem_c.puts();
    assert!(
        puts.len() >= 3,
        "expected starting+actives+terminal, got {}",
        puts.len()
    );
    let phases: Vec<String> = puts
        .iter()
        .map(|(_, v, _)| v["phase"].as_str().unwrap_or("?").to_string())
        .collect();
    assert_eq!(phases[0], "starting");
    assert_eq!(phases[phases.len() - 1], "terminal");
    assert!(phases.iter().any(|p| p == "active"));
    for (_, v, _) in puts.iter().take(puts.len() - 1) {
        assert_eq!(v["cleanup"], json!("pending"));
        assert!(v["outcome"].is_null());
    }
}

#[test]
fn loopback_native_transport_roundtrip_with_ttl() {
    use agent_bus::acl::TokenStore;
    use agent_bus::wire::{Client, Server};
    use std::net::TcpListener;
    let tokens = TokenStore::from_json_str(
        r#"{"tok-a": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]}}"#,
    )
    .unwrap();
    let wal = std::env::temp_dir().join(format!("agent-bus-status-wal-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&wal);
    let wal_file = wal.join("wal.log");
    let _ = std::fs::remove_file(&wal_file);
    let server = Server::new(wal_file, tokens).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    let mut t = NativeStatusTransport::new(&addr, "alice", "tok-a");
    let cancel = AtomicBool::new(false);
    let key = status_key("loop", "alice", &new_run_id()).unwrap();
    let rec = StatusRecord {
        task: "loop".into(),
        run_id: "r".into(),
        agent: "alice".into(),
        scheduler_pid: std::process::id(),
        child_pid: None,
        scope_unit: None,
        phase: agent_bus::scheduler::status::Phase::Active,
        started_ts: 1.0,
        updated_ts: 1.0,
        elapsed_s: 0.0,
        exit_code: None,
        timed_out: false,
        cancelled: false,
        outcome: None,
        cleanup: agent_bus::scheduler::status::Cleanup::Pending,
        log_path: "l".into(),
        resources_requested: None,
        resources_observed: None,
    };
    t.put(&key, rec.to_json(), 1000, &cancel).unwrap();
    let mut c = Client::connect(&addr, "alice", "tok-a").unwrap();
    let got = c.rpc(&json!({"op": "kv_get", "key": key})).unwrap();
    assert_eq!(got["found"], json!(true));
    assert_eq!(got["value"]["task"], json!("loop"));
    std::thread::sleep(Duration::from_millis(1500));
    let expired = c.rpc(&json!({"op": "kv_get", "key": key})).unwrap();
    assert_eq!(expired["found"], json!(false), "finite TTL not honored");
}

#[test]
fn cli_bus_status_requires_task() {
    let dir = tmpdir("cli-task");
    let cfg = base_cfg(&dir);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_agent-bus-scheduler"))
        .args([
            "--template",
            &cfg.template_path,
            "--workspace",
            &cfg.workspace,
            "--agent",
            &cfg.agent,
            "--role",
            &cfg.role,
            "--log",
            &cfg.log_path,
            "--bus-status",
            "--once",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--task"), "missing task hint: {err}");
}

#[test]
fn reporter_never_touches_heartbeat_keys() {
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let reporter = StatusReporter::new(Box::new(mem));
    let key = status_key("hb", "agent1", &new_run_id()).unwrap();
    let _ = reporter.update(&key, json!({"phase": "active"}), ACTIVE_TTL_MS);
    let out: ReporterOutcome = reporter.shutdown(Some((
        key.clone(),
        json!({"phase": "terminal"}),
        TERMINAL_TTL_MS,
    )));
    assert_eq!(out.terminal_ok, Some(true));
    for (k, v, _) in mem_c.puts() {
        assert!(k.starts_with("ctx.sched."));
        assert!(v.get("status").is_none() || v["phase"].is_string());
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (k, _, _) in mem_c.puts() {
        *counts.entry(k).or_default() += 1;
    }
    assert_eq!(counts.len(), 1);
}

fn scripted_listener() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    (listener, addr)
}

fn read_line_timeout(
    reader: &mut std::io::BufReader<std::net::TcpStream>,
    timeout: Duration,
) -> Option<String> {
    use std::io::BufRead as _;
    let _ = reader.get_ref().set_read_timeout(Some(timeout));
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line),
        Err(_) => None,
    }
}

#[test]
fn native_slow_bus_times_out_bounded() {
    let (listener, addr) = scripted_listener();
    std::thread::spawn(move || {
        for _ in 0..3 {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let Some(line) = read_line_timeout(&mut reader, Duration::from_secs(2)) else {
                continue;
            };
            if !line.contains("hello") {
                continue;
            }
            std::thread::sleep(Duration::from_secs(5));
            let mut writer = stream;
            use std::io::Write as _;
            let _ = writer.write_all(b"{\"ok\":true,\"agent\":\"a\",\"req_id\":1}\n");
            let _ = writer.flush();
            break;
        }
    });
    let mut t = NativeStatusTransport::new(&addr, "a", "tok");
    let cancel = AtomicBool::new(false);
    let key = status_key("slow", "a", &new_run_id()).unwrap();
    let start = Instant::now();
    let r = t.put(&key, json!({"phase": "active"}), ACTIVE_TTL_MS, &cancel);
    let elapsed = start.elapsed();
    assert!(r.is_err());
    assert_eq!(r.unwrap_err(), "timeout");
    assert!(
        elapsed < Duration::from_secs(3),
        "slow hello not bounded: {elapsed:?}"
    );
}

#[test]
fn native_malformed_reply_fails_sanitized() {
    let (listener, addr) = scripted_listener();
    std::thread::spawn(move || {
        for _ in 0..3 {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let Some(hello) = read_line_timeout(&mut reader, Duration::from_secs(2)) else {
                continue;
            };
            if !hello.contains("hello") {
                continue;
            }
            let req_id = serde_json::from_str::<Value>(&hello)
                .ok()
                .and_then(|v| v.get("req_id").cloned())
                .unwrap_or(json!(1));
            let mut writer = stream.try_clone().unwrap();
            use std::io::Write as _;
            let _ = writer.write_all(
                format!("{{\"ok\":true,\"agent\":\"a\",\"req_id\":{req_id}}}\n").as_bytes(),
            );
            let _ = writer.flush();
            let Some(_put) = read_line_timeout(&mut reader, Duration::from_secs(2)) else {
                break;
            };
            let _ = writer.write_all(b"not-json\n");
            let _ = writer.flush();
            break;
        }
    });
    let mut t = NativeStatusTransport::new(&addr, "a", "tok");
    let cancel = AtomicBool::new(false);
    let key = status_key("mal", "a", &new_run_id()).unwrap();
    let start = Instant::now();
    let r = t.put(&key, json!({"phase": "active"}), ACTIVE_TTL_MS, &cancel);
    let elapsed = start.elapsed();
    assert!(r.is_err());
    let e = r.unwrap_err();
    assert_eq!(e, "protocol error", "server text leaked: {e}");
    assert!(
        elapsed < Duration::from_secs(3),
        "malformed hung: {elapsed:?}"
    );
}

#[test]
fn native_unavailable_fails_fast() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let mut t = NativeStatusTransport::new(&addr, "a", "tok");
    let cancel = AtomicBool::new(false);
    let key = status_key("down", "a", &new_run_id()).unwrap();
    let start = Instant::now();
    let r = t.put(&key, json!({"phase": "active"}), ACTIVE_TTL_MS, &cancel);
    let elapsed = start.elapsed();
    assert!(r.is_err());
    assert_eq!(r.unwrap_err(), "connection refused");
    assert!(
        elapsed < Duration::from_secs(2),
        "bus-down not fast: {elapsed:?}"
    );
}

#[test]
fn backpressure_coalesces_to_bounded_puts() {
    // 50 rapid updates against a 200ms/put transport must not queue 50
    // puts: the single pending slot coalesces (latest wins), so shutdown
    // stays bounded and the put count stays small.
    let mut mem = MemTransport::new();
    mem.delay = Duration::from_millis(200);
    let mem_c = mem.clone();
    let reporter = StatusReporter::new(Box::new(mem));
    let key = status_key("bp", "a", &new_run_id()).unwrap();
    for i in 0..50 {
        assert!(reporter.update(&key, json!({"phase": "active", "i": i}), ACTIVE_TTL_MS));
    }
    let start = Instant::now();
    let outcome = reporter.shutdown(Some((key, json!({"phase": "terminal"}), TERMINAL_TTL_MS)));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "coalesced shutdown hung: {elapsed:?}"
    );
    assert_eq!(outcome.terminal_ok, Some(true));
    let puts = mem_c.puts();
    assert!(
        puts.len() <= 5,
        "backpressure not coalesced: {} puts for 50 updates",
        puts.len()
    );
    assert_eq!(puts.last().unwrap().1["phase"], json!("terminal"));
}

#[test]
fn cancelled_put_returns_fast_without_io() {
    // A set cancel flag short-circuits before any dial/RPC: no thread, no
    // socket, immediate "cancelled".
    let mut t = NativeStatusTransport::new("127.0.0.1:9", "a", "tok");
    let cancel = AtomicBool::new(true);
    let key = status_key("cx", "a", &new_run_id()).unwrap();
    let start = Instant::now();
    let r = t.put(&key, json!({"phase": "active"}), ACTIVE_TTL_MS, &cancel);
    let elapsed = start.elapsed();
    assert_eq!(r.unwrap_err(), "cancelled");
    assert!(
        elapsed < Duration::from_millis(200),
        "cancelled put did IO: {elapsed:?}"
    );
}

#[test]
fn cancelled_during_hello_starts_no_mutation() {
    // Hello->put boundary: cancel arriving during hello (peer sets the flag
    // before acking) must not open a fresh kv_put RPC. Transport returns
    // cancelled and the peer sees no second line (EOF/timeout, never kv_put).
    let (listener, addr) = scripted_listener();
    let cancel = Arc::new(AtomicBool::new(false));
    let peer_cancel = Arc::clone(&cancel);
    let peer = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = std::io::BufReader::new(stream);
        let mut hello = String::new();
        use std::io::BufRead as _;
        reader.read_line(&mut hello).unwrap();
        assert!(hello.contains("hello"), "handshake precondition: {hello}");
        let req_id = serde_json::from_str::<Value>(&hello)
            .ok()
            .and_then(|v| v.get("req_id").cloned())
            .unwrap_or(json!(1));
        peer_cancel.store(true, Ordering::SeqCst);
        use std::io::Write as _;
        writeln!(reader.get_mut(), "{{\"ok\":true,\"req_id\":{req_id}}}",).unwrap();
        reader.get_mut().flush().unwrap();
        let mut next = String::new();
        match reader.read_line(&mut next) {
            Ok(0) => None,
            Ok(_) if next.trim().is_empty() => None,
            Ok(_) => Some(serde_json::from_str::<Value>(&next).unwrap()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                None
            }
            Err(e) => panic!("peer read: {e}"),
        }
    });
    let mut t = NativeStatusTransport::new(&addr, "a", "tok");
    let key = status_key("hello-cancel", "a", &new_run_id()).unwrap();
    let r = t.put(&key, json!({"phase": "active"}), ACTIVE_TTL_MS, &cancel);
    drop(t);
    let mutation = peer.join().unwrap();
    assert!(
        cancel.load(Ordering::SeqCst),
        "peer must cancel during hello"
    );
    assert!(
        mutation.is_none(),
        "cancelled hello started mutation: {mutation:?}; result={r:?}"
    );
    assert_eq!(r.unwrap_err(), "cancelled");
}

#[test]
fn hostname_fails_fast_without_dns() {
    // Hostnames are explicitly unsupported: rejected without a lookup, so
    // even a resolvable name fails immediately with the literal-only error.
    let mut t = NativeStatusTransport::new("localhost:8379", "a", "tok");
    let cancel = AtomicBool::new(false);
    let key = status_key("hn", "a", &new_run_id()).unwrap();
    let start = Instant::now();
    let r = t.put(&key, json!({"phase": "active"}), ACTIVE_TTL_MS, &cancel);
    let elapsed = start.elapsed();
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err(),
        "unsupported broker address (need IP:port literal)"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "hostname path blocked (DNS?): {elapsed:?}"
    );
}

#[test]
fn repeated_failures_stay_fast_without_leak() {
    // Owned cleanup without thread counting (parallel-unsafe in this
    // binary; the root single-test binary proves no helper thread): 50
    // sequential refused puts must all fail fast with no slowdown or
    // exhaustion, proving each dial fully owns and releases its socket.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let mut t = NativeStatusTransport::new(&addr, "a", "tok");
    let cancel = AtomicBool::new(false);
    let start = Instant::now();
    for _ in 0..50 {
        let r = t.put(
            &status_key("th", "a", &new_run_id()).unwrap(),
            json!({"phase": "active"}),
            ACTIVE_TTL_MS,
            &cancel,
        );
        assert_eq!(r.unwrap_err(), "connection refused");
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "repeated failures slowed/leaked: {elapsed:?}"
    );
}

#[test]
fn timeout_round_with_real_server_delivers_terminal() {
    // Real transport end-to-end: 1s timeout round against a live native
    // server delivers a typed terminal timeout record within bounds.
    use agent_bus::acl::TokenStore;
    use agent_bus::wire::{Client, Server};
    let tokens = TokenStore::from_json_str(
        r#"{"tok-b": {"agent": "bob", "publish": ["*"], "subscribe": ["*"]}}"#,
    )
    .unwrap();
    let wal = std::env::temp_dir().join(format!("agent-bus-status-e2e-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&wal);
    let wal_file = wal.join("wal.log");
    let _ = std::fs::remove_file(&wal_file);
    let server = Server::new(wal_file, tokens).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    let dir = tmpdir("e2e-timeout");
    let mut cfg = base_cfg(&dir);
    cfg.round_timeout_secs = 1;
    cfg.agent = "bob".to_string();
    write_cfg(&cfg, "SLEEP_SECS=60\n");
    let sc = RunStatusConfig::new("e2e-task");
    let transport = NativeStatusTransport::new(&addr, "bob", "tok-b");
    let start = Instant::now();
    let code = run_round_with_status(&cfg, &sc, Box::new(transport)).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(code, 124);
    assert!(
        elapsed < Duration::from_secs(8),
        "real-server timeout round exceeded bounds: {elapsed:?}"
    );
    let mut c = Client::connect(&addr, "bob", "tok-b").unwrap();
    let list = c
        .rpc(&json!({"op": "kv_list", "prefix": "ctx.sched.e2e-task.bob."}))
        .unwrap();
    let keys = list["keys"].as_array().cloned().unwrap_or_default();
    assert_eq!(keys.len(), 1, "expected one terminal key: {list}");
    let got = c
        .rpc(&json!({"op": "kv_get", "key": keys[0]}))
        .unwrap();
    assert_eq!(got["value"]["phase"], json!("terminal"));
    assert_eq!(got["value"]["outcome"], json!("timeout"));
    assert_eq!(got["value"]["timed_out"], json!(true));
}
