//! Scheduler resource-policy integration: omitted defaults, valid
//! limits with zero swap, CLI validation before spawn, requested/observed
//! status, and fail-closed policy refusal before child launch.
//!
//! No real `muse`, no Python, no live broker mutation: workloads are small
//! Rust fixtures, status uses in-memory transports, and real scopes are tiny
//! owned fixtures only.

use agent_bus::scheduler::status::{status_key, StatusTransport, ACTIVE_TTL_MS, TERMINAL_TTL_MS};
use agent_bus::scheduler::{
    parse_cpu_quota_percent, parse_memory_bytes, resource_systemd_args, run_round,
    run_round_with_status, ResourcePolicy, RunStatusConfig, SchedulerConfig,
};
use serde_json::{json, Value};
use std::sync::{atomic::AtomicBool, Arc, Mutex};

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
                std::env::temp_dir().join(format!("agent-bus-fake-res-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let src = dir.join("fake_res.rs");
            let out = dir.join("fake-res-child");
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
        "agent-bus-res-test-{}-{}-{}",
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
        resource_policy: ResourcePolicy::default(),
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

#[test]
fn omitted_policy_preserves_default_round_and_null_status() {
    let dir = tmpdir("omitted");
    let cfg = base_cfg(&dir);
    assert!(cfg.resource_policy.is_empty());
    write_cfg(&cfg, "EXIT=0\nMARK=omitted-mark\n");
    let sc = RunStatusConfig::new("res-task");
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
    assert_eq!(code, 0);
    let puts = mem_c.puts();
    assert!(!puts.is_empty());
    let term = &puts.last().unwrap().1;
    assert_eq!(term["phase"], json!("terminal"));
    assert_eq!(term["outcome"], json!("success"));
    assert_eq!(term["resources_requested"], Value::Null);
    assert_eq!(term["resources_observed"], Value::Null);
}

#[test]
fn library_parsers_accept_valid_and_zero_swap() {
    assert_eq!(parse_cpu_quota_percent("100").unwrap(), 100);
    assert_eq!(
        parse_memory_bytes("4GiB", false, "--memory-max").unwrap(),
        4294967296
    );
    assert_eq!(
        parse_memory_bytes("0", true, "--memory-swap-max").unwrap(),
        0
    );
    let policy = ResourcePolicy {
        cpu_quota_percent: Some(100),
        memory_max_bytes: Some(4294967296),
        memory_swap_max_bytes: Some(0),
    };
    let argv = resource_systemd_args(&policy);
    assert_eq!(argv.len(), 6);
    assert_eq!(argv[1], "CPUQuota=100%");
    assert_eq!(argv[3], "MemoryMax=4294967296");
    assert_eq!(argv[5], "MemorySwapMax=0");
}

#[test]
fn cli_rejects_malformed_resource_values_before_spawn() {
    let dir = tmpdir("cli-validate");
    let cfg = base_cfg(&dir);
    let marker = dir.join("spawn-marker");
    write_cfg(
        &cfg,
        &format!("EXIT=0\nTOUCH={}\n", marker.to_string_lossy()),
    );
    for extra in [
        vec!["--cpu-quota-percent", "0"],
        vec!["--cpu-quota-percent", "100%"],
        vec!["--memory-max", "4G"],
        vec!["--memory-max", "0"],
        vec!["--memory-swap-max", "-1"],
        vec!["--memory-swap-max", "4GB"],
    ] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_agent-bus-scheduler"));
        cmd.args([
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
            "--muse-bin",
            &cfg.muse_bin,
            "--prompt-out",
            &cfg.prompt_out,
            "--once",
        ]);
        for a in &extra {
            cmd.arg(a);
        }
        let out = cmd.stdin(std::process::Stdio::null()).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "CLI must reject {extra:?} with exit 2"
        );
    }
    assert!(
        !marker.exists(),
        "rejected CLI values must not spawn the workload"
    );
}

#[test]
fn tiny_owned_scope_enforces_verified_policy_with_status() {
    let dir = tmpdir("verified");
    let mut cfg = base_cfg(&dir);
    cfg.resource_policy = ResourcePolicy {
        cpu_quota_percent: Some(100),
        memory_max_bytes: Some(512 * 1024 * 1024),
        memory_swap_max_bytes: Some(0),
    };
    write_cfg(&cfg, "EXIT=0\nMARK=verified-mark\n");
    let sc = RunStatusConfig::new("res-verified");
    let mem = MemTransport::new();
    let mem_c = mem.clone();
    let code = run_round_with_status(&cfg, &sc, Box::new(mem)).unwrap();
    assert_eq!(code, 0);
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(log.contains("verified-mark"), "{log}");
    let puts = mem_c.puts();
    let term = &puts.last().unwrap().1;
    assert_eq!(term["outcome"], json!("success"));
    assert_eq!(term["resources_requested"]["cpu_quota_percent"], json!(100));
    assert_eq!(
        term["resources_requested"]["memory_max_bytes"],
        json!(536870912u64)
    );
    assert_eq!(
        term["resources_requested"]["memory_swap_max_bytes"],
        json!(0)
    );
    assert_eq!(term["resources_observed"]["cpu_quota_percent"], json!(100));
    assert_eq!(
        term["resources_observed"]["memory_max_bytes"],
        json!(536870912u64)
    );
    assert_eq!(
        term["resources_observed"]["memory_swap_max_bytes"],
        json!(0)
    );
    assert_eq!(
        term["resources_observed"]["verification"],
        json!("verified")
    );
    assert!(term.get("token").is_none());
}

#[test]
fn refused_policy_fails_before_child_launch_without_claim() {
    // Force cgroup readback to miss by pointing the mount override at an
    // empty owned dir: the holder scope is real and owned, but verification
    // is UNAVAILABLE, so the workload must never spawn.
    let dir = tmpdir("refused");
    let cfg = base_cfg(&dir);
    let marker = dir.join("spawn-marker");
    write_cfg(
        &cfg,
        &format!("EXIT=0\nTOUCH={}\n", marker.to_string_lossy()),
    );
    let fake_mount = tmpdir("fake-cgroup");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_agent-bus-scheduler"));
    cmd.env_clear()
        .env(
            "XDG_RUNTIME_DIR",
            std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".to_string()),
        )
        .env(
            "AGENT_BUS_CGROUP_MOUNT",
            fake_mount.to_string_lossy().to_string(),
        )
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
            "--prompt-out",
            &cfg.prompt_out,
            "--muse-bin",
            &cfg.muse_bin,
            "--interval",
            "1",
            "--round-timeout",
            "30",
            "--cpu-quota-percent",
            "100",
            "--memory-max",
            "512MiB",
            "--memory-swap-max",
            "0",
            "--once",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Ok(dbus) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        if !dbus.is_empty() {
            cmd.env("DBUS_SESSION_BUS_ADDRESS", dbus);
        }
    }
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "refused policy must fail the round closed"
    );
    assert!(
        !marker.exists(),
        "workload must not spawn when policy verification fails"
    );
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(
        log.contains("resource policy UNAVAILABLE") || log.contains("resource policy FAILED"),
        "honest policy error missing: {log}"
    );
    assert!(!log.contains("=== exit 0 ==="), "{log}");
}

#[test]
fn status_keys_and_ttls_unchanged_with_policy() {
    let id = agent_bus::scheduler::status::new_run_id();
    let k = status_key("t", "a", &id).unwrap();
    assert!(k.starts_with("ctx.sched."));
    const { assert!(ACTIVE_TTL_MS > 0 && TERMINAL_TTL_MS > 0) };
    let dir = tmpdir("offline");
    let mut cfg = base_cfg(&dir);
    cfg.resource_policy.memory_swap_max_bytes = Some(0);
    write_cfg(&cfg, "EXIT=0\n");
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(!log.contains("status reporting"));
}
