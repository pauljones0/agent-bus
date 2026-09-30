//! Independently verify cleanup evidence using only owned native fixtures.
#![cfg(target_os = "linux")]

use agent_bus::scheduler::status::StatusTransport;
use agent_bus::scheduler::{run_round_with_status, RunStatusConfig, SchedulerConfig};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const CHILD: &str = r#"
use std::process::{Command, Stdio};
use std::time::Duration;
unsafe extern "C" { fn signal(sig: i32, handler: usize) -> usize; fn setsid() -> i32; }
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--descendant") {
        unsafe { setsid(); signal(15, 1); }
        std::fs::write(&args[2], std::process::id().to_string()).unwrap();
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let prompt = args.iter().position(|a| a == "--prompt-file").map(|i| &args[i+1]).unwrap();
    if std::fs::read_to_string(prompt).unwrap().contains("leave-owned-descendant") {
        let pid_path = format!("{prompt}.descendant-pid");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--descendant", &pid_path]).stdin(Stdio::null())
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        for _ in 0..200 {
            if std::path::Path::new(&pid_path).exists() { return; }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill(); let _ = child.wait();
        std::process::exit(8);
    }
}
"#;

fn private_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "root-scheduler-cleanup-{}-{}-{label}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

fn child_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = private_dir("compiler");
        let source = dir.join("child.rs");
        let bin = dir.join("child");
        std::fs::write(&source, CHILD).unwrap();
        let output = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-O"])
            .arg(&source)
            .arg("-o")
            .arg(&bin)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        bin
    })
}

struct Records(Arc<Mutex<Vec<Value>>>);
impl StatusTransport for Records {
    fn put(&mut self, _: &str, value: Value, _: u64, _: &AtomicBool) -> Result<(), String> {
        self.0.lock().unwrap().push(value);
        Ok(())
    }
}

fn run_case(descendant: bool) -> (Value, PathBuf, Duration) {
    let dir = private_dir(if descendant { "forced" } else { "normal" });
    let template = dir.join("template.md");
    let prompt = dir.join("prompt.md");
    let log = dir.join("round.log");
    std::fs::write(
        &template,
        if descendant {
            "AGENT_NAME leave-owned-descendant"
        } else {
            "AGENT_NAME return normally"
        },
    )
    .unwrap();
    let mut cfg = SchedulerConfig::new(
        template.to_str().unwrap(),
        prompt.to_str().unwrap(),
        dir.to_str().unwrap(),
        "root-owned-fixture",
        "cleanup review",
        log.to_str().unwrap(),
    );
    cfg.muse_bin = child_bin().to_string_lossy().into_owned();
    cfg.round_timeout_secs = 10;
    let records = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let code = run_round_with_status(
        &cfg,
        &RunStatusConfig::new("root-cleanup-review"),
        Box::new(Records(records.clone())),
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(code, 0);
    let terminal = records
        .lock()
        .unwrap()
        .iter()
        .find(|r| r["phase"] == "terminal")
        .cloned()
        .unwrap();
    (terminal, prompt, elapsed)
}

#[test]
fn ordinary_success_reports_verified_scope_cleanup() {
    let (terminal, _, elapsed) = run_case(false);
    assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    assert_eq!(terminal["exit_code"], 0);
    assert_eq!(terminal["outcome"], "success");
    assert_eq!(terminal["cleanup"], "clean");
    assert_eq!(
        terminal["scope_cleanup"]["empty_verified"], true,
        "{terminal}"
    );
    assert!(
        matches!(
            terminal["scope_cleanup"]["active_state"].as_str(),
            Some("inactive") | Some("failed")
        ),
        "{terminal}"
    );
    assert_ne!(
        terminal["scope_cleanup"]["manager_result"], "timeout",
        "{terminal}"
    );
}

#[test]
fn successful_child_with_forced_descendant_cleanup_keeps_both_results() {
    let (terminal, prompt, elapsed) = run_case(true);
    let pid = std::fs::read_to_string(format!("{}.descendant-pid", prompt.display())).unwrap();
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()));
    if let Ok(stat) = stat {
        assert!(
            stat.rsplit_once(") ").unwrap().1.starts_with('Z'),
            "owned descendant is still live"
        );
    }
    assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    assert_eq!(terminal["exit_code"], 0);
    assert_eq!(terminal["outcome"], "success");
    assert_eq!(terminal["timed_out"], false);
    assert_eq!(terminal["cleanup"], "clean");
    assert_eq!(
        terminal["scope_cleanup"]["stop_requested"], true,
        "{terminal}"
    );
    assert_eq!(
        terminal["scope_cleanup"]["empty_verified"], true,
        "{terminal}"
    );
    assert_eq!(
        terminal["scope_cleanup"]["active_state"], "failed",
        "{terminal}"
    );
    assert_eq!(
        terminal["scope_cleanup"]["manager_result"], "timeout",
        "{terminal}"
    );
}
