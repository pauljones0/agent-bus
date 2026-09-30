//! Scheduler regression tests: template rendering, Muse argv preservation,
//! one-round execution with a natively compiled Rust fixture child,
//! prompt-failure skip, timeout cleanup with descendant reap, owned
//! systemd-scope containment of setsid-detached descendants (timeout,
//! successful-parent-exit, and scheduler-cancellation paths), argument
//! boundary preservation, unwritable-prompt errors, and null-stdin rounds.
//!
//! No real `muse` calls, no Python, no shell-script children: every spawned
//! test child is a small Rust binary compiled once from [`FAKE_CHILD_SRC`]
//! with `rustc` (direct [`std::process::Command`] invocation, no shell).
//! The fixture reads per-round configuration from `<prompt-out>.fake-cfg`
//! (`KEY=VALUE` lines), located via the `--prompt-file` argument the
//! scheduler always passes — so parallel tests in unique temp dirs never
//! share configuration through process-wide environment variables.

use agent_bus::scheduler::{
    muse_argv, render_file, render_prompt, run_round, SchedulerConfig, PROMPT_FAILURE_EXIT_CODE,
    TIMEOUT_EXIT_CODE,
};
use std::sync::OnceLock;
use std::time::Instant;

/// Rust source of the fixture child. Speaks the scheduler's `muse exec`
/// argv (reads `--prompt-file <p>`, loads `<p>.fake-cfg`) so argument
/// boundaries and config routing go through the real spawn path.
const FAKE_CHILD_SRC: &str = r#"
use std::time::Duration;

#[cfg(unix)]
extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
    fn setsid() -> i32;
}

fn cfg_value(cfg: &str, key: &str) -> Option<String> {
    for line in cfg.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Grandchild mode: `fake-child --grandchild <cfg-path>`.
    if args.first().map(|s| s.as_str()) == Some("--grandchild") {
        let cfg_path = args.get(1).cloned().unwrap_or_else(|| "/dev/null".to_string());
        let cfg = std::fs::read_to_string(&cfg_path).unwrap_or_default();
        #[cfg(unix)]
        if cfg_value(&cfg, "SETSID_DESCENDANT").as_deref() == Some("1") {
            // Escape the round's owned process group into a new session,
            // mimicking real Muse tool shells (own SID): killpg() of the
            // round's group can no longer reach this process. Only owned
            // cgroup/scope containment still can.
            unsafe {
                setsid();
            }
        }
        #[cfg(unix)]
        if cfg_value(&cfg, "IGNORE_TERM").as_deref() == Some("1") {
            // Ignore SIGTERM so the test proves SIGKILL escalation kills
            // descendants that do not cooperate with SIGTERM.
            unsafe {
                signal(15, 1);
            }
        }
        if let Some(p) = cfg_value(&cfg, "PID_FILE") {
            let _ = std::fs::write(&p, std::process::id().to_string());
        }
        let secs: u64 = cfg_value(&cfg, "GRANDCHILD_SLEEP")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        std::thread::sleep(Duration::from_secs(secs));
        return;
    }
    // Direct child: locate config next to `--prompt-file <path>`.
    let mut prompt_file: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--prompt-file" {
            prompt_file = it.next().cloned();
            break;
        }
    }
    let cfg_path = prompt_file
        .map(|p| p + ".fake-cfg")
        .unwrap_or_else(|| "/dev/null".to_string());
    let cfg = std::fs::read_to_string(&cfg_path).unwrap_or_default();
    if let Some(p) = cfg_value(&cfg, "DIRECT_PID_FILE") {
        std::fs::write(p, std::process::id().to_string()).unwrap();
    }
    if let Some(p) = cfg_value(&cfg, "ARGV_DUMP") {
        let _ = std::fs::write(&p, args.join("\n"));
    }
    if cfg_value(&cfg, "STDIN_CHECK").as_deref() == Some("1") {
        let mut buf = Vec::new();
        use std::io::Read as _;
        std::io::stdin().read_to_end(&mut buf).unwrap();
        if buf.is_empty() {
            std::process::exit(0);
        } else {
            std::process::exit(5);
        }
    }
    if let Some(f) = cfg_value(&cfg, "TOUCH") {
        let _ = std::fs::write(&f, "spawned");
    }
    if let Some(m) = cfg_value(&cfg, "MARK") {
        println!("{m}");
    }
    if cfg_value(&cfg, "SPAWN_DESCENDANT").as_deref() == Some("1") {
        let exe = std::env::current_exe().unwrap();
        let mut c = std::process::Command::new(&exe)
            .arg("--grandchild")
            .arg(&cfg_path)
            .spawn()
            .unwrap();
        if cfg_value(&cfg, "ORPHAN_EXIT").as_deref() == Some("1") {
            let pid_file = cfg_value(&cfg, "PID_FILE").unwrap();
            for _ in 0..300 {
                if std::path::Path::new(&pid_file).exists() {
                    std::process::exit(0);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            std::process::exit(6);
        }
        let secs: u64 = cfg_value(&cfg, "SLEEP_SECS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        std::thread::sleep(Duration::from_secs(secs));
        let _ = c.wait();
        return;
    }
    if let Some(s) = cfg_value(&cfg, "SLEEP_SECS") {
        let secs: u64 = s.parse().unwrap_or(0);
        std::thread::sleep(Duration::from_secs(secs));
    }
    let code: i32 = cfg_value(&cfg, "EXIT")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    std::process::exit(code);
}
"#;

/// Compile the Rust fixture child once per test-binary run; return its path.
fn fake_child_bin() -> String {
    static FAKE_BIN: OnceLock<String> = OnceLock::new();
    FAKE_BIN
        .get_or_init(|| {
            let dir =
                std::env::temp_dir().join(format!("agent-bus-fake-child-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let src = dir.join("fake_child.rs");
            let out = dir.join("fake-child");
            // Rebuild only when the embedded source changed.
            let rebuild = std::fs::read_to_string(&src).ok().as_deref() != Some(FAKE_CHILD_SRC);
            if rebuild {
                std::fs::write(&src, FAKE_CHILD_SRC).unwrap();
                let st = std::process::Command::new("rustc")
                    .args(["--edition", "2021", "-O", "-o"])
                    .arg(&out)
                    .arg(&src)
                    .stdin(std::process::Stdio::null())
                    .output()
                    .expect("rustc must be available to build the Rust fixture child");
                assert!(
                    st.status.success(),
                    "rustc fixture build failed: {}",
                    String::from_utf8_lossy(&st.stderr)
                );
            }
            out.to_string_lossy().into_owned()
        })
        .clone()
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "agent-bus-scheduler-test-{}-{}-{}",
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

/// Write the fixture config the Rust child loads via `<prompt-out>.fake-cfg`.
fn write_cfg(cfg: &SchedulerConfig, body: &str) {
    std::fs::write(format!("{}.fake-cfg", cfg.prompt_out), body).unwrap();
}

#[cfg(unix)]
fn pid_is_gone(pid: &str) -> bool {
    !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists()
}

#[test]
fn renders_template_substitution() {
    let out = render_prompt("hi AGENT_NAME (AGENT_ROLE)", "a", "r").unwrap();
    assert_eq!(out, "hi a (r)");
}

#[test]
fn empty_template_is_a_round_error_not_an_empty_prompt() {
    assert!(render_prompt("", "a", "r").is_err());
}

#[test]
fn muse_argv_default_omits_reasoning_effort() {
    let dir = tmpdir("argv");
    let cfg = base_cfg(&dir);
    assert_eq!(cfg.reasoning_effort, None);
    let argv = muse_argv(&cfg);
    assert_eq!(
        argv,
        vec![
            "exec",
            "--yolo",
            "--disable-sandbox",
            "--disable-web-tools",
            "--workspace",
            dir.to_str().unwrap(),
            "--max-model-steps",
            "5",
            "--prompt-file",
            &cfg.prompt_out,
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>()
    );
    assert!(
        !argv.iter().any(|a| a == "--reasoning-effort"),
        "default must inherit Muse config, not force a level: {argv:?}"
    );
}

#[test]
fn muse_argv_forwards_explicit_effort_unchanged() {
    let dir = tmpdir("argv-explicit");
    for effort in ["low", "medium", "high"] {
        let mut cfg = base_cfg(&dir);
        cfg.reasoning_effort = Some(effort.into());
        let argv = muse_argv(&cfg);
        let pos = argv
            .iter()
            .position(|a| a == "--reasoning-effort")
            .unwrap_or_else(|| panic!("explicit {effort} must add the flag: {argv:?}"));
        assert_eq!(argv[pos + 1], effort);
    }
}

#[test]
fn muse_argv_keeps_sota_isolation_and_effort() {
    let dir = tmpdir("argv-sota");
    let mut cfg = base_cfg(&dir);
    cfg.reasoning_effort = Some("medium".into());
    cfg.subagent_worktree_isolation = true;
    let argv = muse_argv(&cfg);
    assert!(argv.contains(&"--subagent-worktree-isolation".to_string()));
    assert!(argv.contains(&"medium".to_string()));
}

#[test]
fn default_round_omits_reasoning_effort_in_child_argv() {
    let dir = tmpdir("child-default-inherit");
    let cfg = base_cfg(&dir);
    let dump = dir.join("argv.txt");
    write_cfg(
        &cfg,
        &format!("EXIT=0\nARGV_DUMP={}\n", dump.to_string_lossy()),
    );
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let dumped = std::fs::read_to_string(&dump).unwrap();
    let argv: Vec<&str> = dumped.lines().collect();
    assert!(
        !argv.contains(&"--reasoning-effort"),
        "default child argv must omit the flag to inherit config: {argv:?}"
    );
    assert!(
        argv.contains(&"--prompt-file"),
        "prompt routing must survive the omitted flag: {argv:?}"
    );
}

#[test]
fn explicit_reasoning_effort_reaches_child_unchanged() {
    let dir = tmpdir("child-explicit-forward");
    let mut cfg = base_cfg(&dir);
    cfg.reasoning_effort = Some("high".into());
    let dump = dir.join("argv.txt");
    write_cfg(
        &cfg,
        &format!("EXIT=0\nARGV_DUMP={}\n", dump.to_string_lossy()),
    );
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let dumped = std::fs::read_to_string(&dump).unwrap();
    let argv: Vec<&str> = dumped.lines().collect();
    let pos = argv
        .iter()
        .position(|a| *a == "--reasoning-effort")
        .unwrap_or_else(|| panic!("explicit value must reach the child: {argv:?}"));
    assert_eq!(argv[pos + 1], "high");
}

#[test]
fn successful_round_renders_and_propagates_exit_zero() {
    let dir = tmpdir("ok");
    let cfg = base_cfg(&dir);
    write_cfg(&cfg, "EXIT=0\nMARK=child-output-mark\n");
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let rendered = std::fs::read_to_string(&cfg.prompt_out).unwrap();
    assert_eq!(rendered, "You are test-agent, role test-role.");
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(log.contains("=== round "), "missing round header: {log}");
    assert!(
        log.contains("child-output-mark"),
        "child output not appended: {log}"
    );
    assert!(log.contains("=== exit 0 ==="), "missing exit line: {log}");
}

#[test]
fn failing_child_exit_code_propagates_honestly() {
    let dir = tmpdir("fail");
    let cfg = base_cfg(&dir);
    write_cfg(&cfg, "EXIT=7\n");
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 7);
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(log.contains("=== exit 7 ==="), "missing exit line: {log}");
}

#[test]
fn missing_template_skips_round_with_exit_three_and_spawns_nothing() {
    let dir = tmpdir("badprompt");
    let marker = dir.join("spawn-marker");
    let mut cfg = base_cfg(&dir);
    cfg.template_path = dir.join("does-not-exist.md").to_string_lossy().into_owned();
    // The Rust fixture would touch this marker if spawned; it must never run.
    write_cfg(
        &cfg,
        &format!("EXIT=0\nTOUCH={}\n", marker.to_string_lossy()),
    );
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, PROMPT_FAILURE_EXIT_CODE);
    assert!(!marker.exists(), "child must not spawn on prompt failure");
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(log.contains("FAILED"), "missing failure line: {log}");
    assert!(
        log.contains(&format!("=== exit {PROMPT_FAILURE_EXIT_CODE} ===")),
        "missing exit line: {log}"
    );
}

#[test]
fn unwritable_prompt_out_returns_error_not_a_round_code() {
    let dir = tmpdir("badprompt-out");
    let mut cfg = base_cfg(&dir);
    // Point the rendered-prompt destination at an existing directory so the
    // prompt write fails: this is infra failure (`Err`), not a round exit.
    cfg.prompt_out = dir.to_string_lossy().into_owned();
    let r = run_round(&cfg);
    assert!(r.is_err(), "expected Err for unwritable prompt, got {r:?}");
}

#[test]
fn overrunning_child_is_killed_with_timeout_code() {
    let dir = tmpdir("timeout");
    let mut cfg = base_cfg(&dir);
    cfg.round_timeout_secs = 1;
    write_cfg(&cfg, "EXIT=0\nSLEEP_SECS=60\n");
    let start = Instant::now();
    let code = run_round(&cfg).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(code, TIMEOUT_EXIT_CODE);
    assert!(
        elapsed.as_secs() < 30,
        "timeout did not cut the round short: {elapsed:?}"
    );
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(log.contains("TIMEOUT"), "missing timeout line: {log}");
    assert!(
        log.contains(&format!("=== exit {TIMEOUT_EXIT_CODE} ===")),
        "missing exit line: {log}"
    );
}

#[test]
fn timeout_kills_descendants_and_next_round_runs() {
    let dir = tmpdir("descendants");
    let mut cfg = base_cfg(&dir);
    cfg.round_timeout_secs = 2;
    let pid_file = dir.join("grandchild.pid");
    write_cfg(
        &cfg,
        &format!(
            "SLEEP_SECS=60\nSPAWN_DESCENDANT=1\nIGNORE_TERM=1\nGRANDCHILD_SLEEP=60\nPID_FILE={}\n",
            pid_file.to_string_lossy()
        ),
    );
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, TIMEOUT_EXIT_CODE);
    // The fixture grandchild ignores SIGTERM, so only whole-group SIGKILL
    // reaps it: a kill-the-direct-child-only cleanup would orphan it.
    let pid = std::fs::read_to_string(&pid_file).expect("grandchild must have started");
    assert!(!pid.trim().is_empty(), "grandchild pid file is empty");
    #[cfg(unix)]
    assert!(
        pid_is_gone(&pid),
        "descendant {pid} still alive after timeout cleanup"
    );
    // The single-child slot must be free: a follow-up round runs cleanly.
    write_cfg(&cfg, "EXIT=0\nMARK=second-round-mark\n");
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(
        log.contains("second-round-mark"),
        "follow-up round did not run after cleanup: {log}"
    );
}

#[test]
fn argv_with_spaces_survive_exec_without_shell_splitting() {
    let dir = tmpdir("argv-spaces");
    let spaced = dir.join("ws with spaces");
    std::fs::create_dir_all(&spaced).unwrap();
    let mut cfg = base_cfg(&dir);
    cfg.workspace = spaced.to_string_lossy().into_owned();
    cfg.prompt_out = spaced.join("my prompt.md").to_string_lossy().into_owned();
    cfg.log_path = spaced.join("round log.log").to_string_lossy().into_owned();
    let dump = spaced.join("argv.txt");
    write_cfg(
        &cfg,
        &format!("EXIT=0\nARGV_DUMP={}\n", dump.to_string_lossy()),
    );
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let dumped = std::fs::read_to_string(&dump).unwrap();
    let argv: Vec<&str> = dumped.lines().collect();
    // Each Command argument arrives whole: paths with spaces are single argv
    // entries, never shell-split.
    assert!(
        argv.contains(&cfg.workspace.as_str()),
        "workspace not preserved whole: {argv:?}"
    );
    assert!(
        argv.contains(&cfg.prompt_out.as_str()),
        "prompt-out not preserved whole: {argv:?}"
    );
}

#[test]
fn child_stdin_is_null_for_unattended_rounds() {
    let dir = tmpdir("stdin-null");
    let cfg = base_cfg(&dir);
    // Fixture exits 0 only when stdin reads immediate EOF (null), 5 otherwise.
    write_cfg(&cfg, "STDIN_CHECK=1\n");
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0, "child stdin was not null (EOF expected)");
}

#[test]
fn render_file_reads_and_substitutes() {
    let dir = tmpdir("render-file");
    let tpl = dir.join("t.md");
    std::fs::write(&tpl, "n=AGENT_NAME r=AGENT_ROLE").unwrap();
    let out = render_file(tpl.to_str().unwrap(), "x", "y").unwrap();
    assert_eq!(out, "n=x r=y");
    assert!(render_file(dir.join("missing.md").to_str().unwrap(), "x", "y").is_err());
}

#[cfg(unix)]
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

// Cleanup only fixture processes whose executable path still matches this
// test binary's unique, rustc-built child. Failed regressions leave no jobs.
#[cfg(unix)]
fn cleanup_fixture(pid: &str) {
    let pid = pid.trim();
    if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        if cmdline.split(|b| *b == 0).next() == Some(fake_child_bin().as_bytes()) {
            unsafe { kill(pid.parse().unwrap(), 9) };
        }
    }
    for _ in 0..100 {
        if pid_is_gone(pid) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// User runtime dir for `systemctl --user` inside the env-cleared scheduler
/// child: the parent test env first, else `/run/user/<uid>` via `id`.
fn user_runtime_dir() -> String {
    static DIR: OnceLock<String> = OnceLock::new();
    DIR.get_or_init(|| {
        if let Ok(d) = std::env::var("XDG_RUNTIME_DIR") {
            if !d.is_empty() {
                return d;
            }
        }
        let uid = std::process::Command::new("id")
            .arg("-u")
            .stdin(std::process::Stdio::null())
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "1000".to_string());
        format!("/run/user/{uid}")
    })
    .clone()
}

fn scheduler_command(cfg: &SchedulerConfig) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agent-bus-scheduler"));
    command
        .env_clear()
        // Scope containment needs the user bus; env_clear wipes it, so pass
        // the runtime dir (and session address when present) explicitly.
        .env("XDG_RUNTIME_DIR", user_runtime_dir())
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
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Ok(dbus) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        if !dbus.is_empty() {
            command.env("DBUS_SESSION_BUS_ADDRESS", dbus);
        }
    }
    command
}

fn wait_for_exit(
    child: &mut std::process::Child,
    seconds: u64,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + std::time::Duration::from_secs(seconds);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(unix)]
#[test]
fn successful_child_does_not_leave_background_descendant() {
    let dir = tmpdir("orphan-on-success");
    let cfg = base_cfg(&dir);
    let pid_file = dir.join("grandchild.pid");
    write_cfg(
        &cfg,
        &format!(
            "SPAWN_DESCENDANT=1\nORPHAN_EXIT=1\nIGNORE_TERM=1\nPID_FILE={}\n",
            pid_file.display()
        ),
    );
    let result = run_round(&cfg);
    let pid = std::fs::read_to_string(pid_file).unwrap();
    let gone = pid_is_gone(&pid);
    cleanup_fixture(&pid);
    assert_eq!(result.unwrap(), 0);
    assert!(gone, "successful round left its descendant running");
}

#[cfg(unix)]
#[test]
fn successful_parent_exit_leaves_no_setsid_descendant() {
    let dir = tmpdir("orphan-setsid-success");
    let cfg = base_cfg(&dir);
    let pid_file = dir.join("grandchild.pid");
    write_cfg(
        &cfg,
        &format!(
            "SPAWN_DESCENDANT=1\nORPHAN_EXIT=1\nSETSID_DESCENDANT=1\nIGNORE_TERM=1\nGRANDCHILD_SLEEP=60\nPID_FILE={}\n",
            pid_file.display()
        ),
    );
    let result = run_round(&cfg);
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    let gone = pid_is_gone(&pid);
    cleanup_fixture(&pid);
    assert_eq!(result.unwrap(), 0);
    assert!(
        gone,
        "successful round left its setsid-detached descendant running"
    );
}

/// Active round scopes owned by this test process (`agent-bus-round-*` units
/// in `running` state whose name embeds our pid).
#[cfg(unix)]
fn live_round_scopes() -> Vec<String> {
    let pid = std::process::id().to_string();
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "--user",
            "list-units",
            "--type=scope",
            "--state=running",
            "--no-legend",
            "--plain",
        ])
        .stdin(std::process::Stdio::null())
        .output();
    let mut units = Vec::new();
    if let Ok(o) = out {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let name = line.split_whitespace().next().unwrap_or("");
            if name.starts_with("agent-bus-round-") && name.contains(pid.as_str()) {
                units.push(name.to_string());
            }
        }
    }
    units
}

#[cfg(unix)]
#[test]
fn failed_workload_spawn_leaves_no_live_holder_scope() {
    let before = live_round_scopes();
    let dir = tmpdir("spawn-fail-no-leak");
    let mut cfg = base_cfg(&dir);
    cfg.muse_bin = dir.join("missing-program").to_string_lossy().into_owned();
    let r = run_round(&cfg);
    assert!(r.is_err(), "expected Err for missing muse bin, got {r:?}");
    // A leaked holder would stay `running` for minutes; legitimate parallel
    // test scopes drain in seconds, so poll until only pre-existing units
    // remain before declaring a leak.
    let mut leaked = Vec::new();
    for _ in 0..20 {
        leaked = live_round_scopes()
            .into_iter()
            .filter(|u| !before.contains(u))
            .collect();
        if leaked.is_empty() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("workload spawn failure leaked live holder scopes: {leaked:?}");
}

#[cfg(unix)]
#[test]
fn timeout_kills_setsid_detached_descendant_and_next_round_runs() {
    let dir = tmpdir("timeout-setsid");
    let mut cfg = base_cfg(&dir);
    cfg.round_timeout_secs = 2;
    let pid_file = dir.join("grandchild.pid");
    write_cfg(
        &cfg,
        &format!(
            "SLEEP_SECS=60\nSPAWN_DESCENDANT=1\nSETSID_DESCENDANT=1\nIGNORE_TERM=1\nGRANDCHILD_SLEEP=60\nPID_FILE={}\n",
            pid_file.to_string_lossy()
        ),
    );
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, TIMEOUT_EXIT_CODE);
    // The fixture grandchild sits in its own session and ignores SIGTERM, so
    // neither the group fast path nor scope-stop SIGTERM removes it: only
    // scope-stop SIGKILL escalation reaps it.
    let pid = std::fs::read_to_string(&pid_file).expect("grandchild must have started");
    assert!(!pid.trim().is_empty(), "grandchild pid file is empty");
    assert!(
        pid_is_gone(&pid),
        "setsid descendant {pid} still alive after timeout cleanup"
    );
    // The single-child slot must be free: a follow-up round runs cleanly.
    write_cfg(&cfg, "EXIT=0\nMARK=second-round-mark\n");
    let code = run_round(&cfg).unwrap();
    assert_eq!(code, 0);
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(
        log.contains("second-round-mark"),
        "follow-up round did not run after cleanup: {log}"
    );
}

#[test]
fn scheduler_exits_on_infrastructure_error() {
    let dir = tmpdir("fatal-infra");
    let mut cfg = base_cfg(&dir);
    cfg.muse_bin = dir.join("missing-program").to_string_lossy().into_owned();
    let mut child = scheduler_command(&cfg).spawn().unwrap();
    let status = wait_for_exit(&mut child, 2);
    if status.is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(1),
        "scheduler must exit on infrastructure/cleanup errors, not retry"
    );
}

#[cfg(unix)]
#[test]
fn scheduler_sigterm_reaps_owned_child_and_descendant() {
    let dir = tmpdir("cancel-group");
    let cfg = base_cfg(&dir);
    let child_pid_file = dir.join("child.pid");
    let descendant_pid_file = dir.join("descendant.pid");
    write_cfg(
        &cfg,
        &format!(
            "SPAWN_DESCENDANT=1\nSLEEP_SECS=60\nIGNORE_TERM=1\nDIRECT_PID_FILE={}\nPID_FILE={}\n",
            child_pid_file.display(),
            descendant_pid_file.display()
        ),
    );
    let mut scheduler = scheduler_command(&cfg).spawn().unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    while !descendant_pid_file.exists() && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let child_pid = std::fs::read_to_string(child_pid_file).unwrap();
    let descendant_pid = std::fs::read_to_string(descendant_pid_file).unwrap();
    assert_eq!(unsafe { kill(scheduler.id() as i32, 15) }, 0);
    let status = wait_for_exit(&mut scheduler, 10);
    let child_gone = pid_is_gone(&child_pid);
    let descendant_gone = pid_is_gone(&descendant_pid);
    if status.is_none() {
        scheduler.kill().unwrap();
        scheduler.wait().unwrap();
    }
    cleanup_fixture(&child_pid);
    cleanup_fixture(&descendant_pid);
    assert_eq!(status.and_then(|s| s.code()), Some(143));
    assert!(
        child_gone && descendant_gone,
        "scheduler cancellation left owned processes running"
    );
}

#[cfg(unix)]
#[test]
fn scheduler_sigterm_kills_setsid_descendant() {
    let dir = tmpdir("cancel-setsid-group");
    let cfg = base_cfg(&dir);
    let child_pid_file = dir.join("child.pid");
    let descendant_pid_file = dir.join("descendant.pid");
    write_cfg(
        &cfg,
        &format!(
            "SPAWN_DESCENDANT=1\nSLEEP_SECS=60\nSETSID_DESCENDANT=1\nIGNORE_TERM=1\nDIRECT_PID_FILE={}\nPID_FILE={}\n",
            child_pid_file.display(),
            descendant_pid_file.display()
        ),
    );
    let mut scheduler = scheduler_command(&cfg).spawn().unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    while !descendant_pid_file.exists() && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let child_pid = std::fs::read_to_string(child_pid_file).unwrap();
    let descendant_pid = std::fs::read_to_string(descendant_pid_file).unwrap();
    assert_eq!(unsafe { kill(scheduler.id() as i32, 15) }, 0);
    let status = wait_for_exit(&mut scheduler, 20);
    let child_gone = pid_is_gone(&child_pid);
    let descendant_gone = pid_is_gone(&descendant_pid);
    if status.is_none() {
        scheduler.kill().unwrap();
        scheduler.wait().unwrap();
    }
    cleanup_fixture(&child_pid);
    cleanup_fixture(&descendant_pid);
    assert_eq!(status.and_then(|s| s.code()), Some(143));
    assert!(
        child_gone && descendant_gone,
        "scheduler cancellation left its setsid-detached descendant running"
    );
}

/// Active round scopes owned by one scheduler child pid.
#[cfg(unix)]
fn live_scopes_for_pid(pid: u32) -> Vec<String> {
    let needle = pid.to_string();
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "--user",
            "list-units",
            "--type=scope",
            "--state=running",
            "--no-legend",
            "--plain",
        ])
        .stdin(std::process::Stdio::null())
        .output();
    let mut units = Vec::new();
    if let Ok(o) = out {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let name = line.split_whitespace().next().unwrap_or("");
            if name.starts_with("agent-bus-round-") && name.contains(needle.as_str()) {
                units.push(name.to_string());
            }
        }
    }
    units
}

/// Single-round scheduler child with isolated fault env (per-process, safe
/// under parallel tests). Mirrors [`scheduler_command`] plus `--once`.
#[cfg(unix)]
fn scheduler_once_command(
    cfg: &SchedulerConfig,
    round_timeout: &str,
    extra_env: &[(&str, &str)],
) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agent-bus-scheduler"));
    command
        .env_clear()
        .env("XDG_RUNTIME_DIR", user_runtime_dir())
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
            round_timeout,
            "--once",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Ok(dbus) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        if !dbus.is_empty() {
            command.env("DBUS_SESSION_BUS_ADDRESS", dbus);
        }
    }
    for (k, v) in extra_env {
        command.env(k, v);
    }
    command
}

#[cfg(unix)]
#[test]
fn timeout_group_failure_still_stops_scope_and_reports_fault() {
    let dir = tmpdir("group-fault-scope");
    let cfg = base_cfg(&dir);
    let child_pid_file = dir.join("child.pid");
    write_cfg(
        &cfg,
        &format!("SLEEP_SECS=60\nDIRECT_PID_FILE={}\n", child_pid_file.display()),
    );
    let mut child = scheduler_once_command(&cfg, "1", &[("AGENT_BUS_FAIL_GROUP_CLEANUP", "1")])
        .spawn()
        .unwrap();
    let pid = child.id();
    let status = wait_for_exit(&mut child, 20);
    if status.is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(1),
        "group-cleanup fault must fail the round closed, not report timeout"
    );
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(
        log.contains("injected group-cleanup fault"),
        "group fault not reported: {log}"
    );
    if let Ok(cp) = std::fs::read_to_string(&child_pid_file) {
        let gone = pid_is_gone(&cp);
        cleanup_fixture(&cp);
        assert!(gone, "scope cleanup did not kill child after group fault");
    }
    let mut leaked = Vec::new();
    for _ in 0..20 {
        leaked = live_scopes_for_pid(pid);
        if leaked.is_empty() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("group fault leaked live holder scopes: {leaked:?}");
}

#[cfg(unix)]
#[test]
fn reaper_spawn_failure_leaves_no_live_holder_scope() {
    let dir = tmpdir("reaper-fault-no-leak");
    let cfg = base_cfg(&dir);
    write_cfg(&cfg, "EXIT=0\n");
    let mut child = scheduler_once_command(&cfg, "30", &[("AGENT_BUS_FAIL_REAPER_SPAWN", "1")])
        .spawn()
        .unwrap();
    let pid = child.id();
    let status = wait_for_exit(&mut child, 20);
    if status.is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(1),
        "reaper fault must fail the round, not run uncontained"
    );
    let log = std::fs::read_to_string(&cfg.log_path).unwrap();
    assert!(
        log.contains("reaper spawn FAILED"),
        "reaper fault not reported: {log}"
    );
    let mut leaked = Vec::new();
    for _ in 0..20 {
        leaked = live_scopes_for_pid(pid);
        if leaked.is_empty() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("reaper fault leaked live holder scopes: {leaked:?}");
}
