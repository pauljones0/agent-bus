//! Independent resource checks: public API validation and real CLI child readback.
#![cfg(target_os = "linux")]

use agent_bus::scheduler::status::StatusTransport;
use agent_bus::scheduler::{
    run_round, run_round_with_status, ResourcePolicy, RunStatusConfig, SchedulerConfig,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

fn directory(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "root-resource-review-{}-{}-{label}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn config(dir: &Path) -> SchedulerConfig {
    SchedulerConfig::new(
        dir.join("template.md").to_str().unwrap(),
        dir.join("prompt.md").to_str().unwrap(),
        dir.to_str().unwrap(),
        "root-resource-review",
        "resource review",
        dir.join("round.log").to_str().unwrap(),
    )
}

struct Records(Arc<Mutex<Vec<Value>>>);
impl StatusTransport for Records {
    fn put(&mut self, _: &str, value: Value, _: u64, _: &AtomicBool) -> Result<(), String> {
        self.0.lock().unwrap().push(value);
        Ok(())
    }
}

#[test]
fn invalid_typed_policy_is_rejected_before_round_side_effects() {
    // Deliberately absent template: valid config returns the existing prompt
    // error code. Invalid config must be rejected before reading/rendering it.
    let control_dir = directory("control");
    assert_eq!(run_round(&config(&control_dir)).unwrap(), 3);
    for (policy, field) in [
        (
            ResourcePolicy {
                cpu_quota_percent: Some(0),
                ..Default::default()
            },
            "cpu_quota_percent",
        ),
        (
            ResourcePolicy {
                cpu_quota_percent: Some(1001),
                ..Default::default()
            },
            "cpu_quota_percent",
        ),
        (
            ResourcePolicy {
                memory_max_bytes: Some(0),
                ..Default::default()
            },
            "memory_max_bytes",
        ),
    ] {
        for with_status in [false, true] {
            let dir = directory("invalid");
            let mut cfg = config(&dir);
            cfg.resource_policy = policy.clone();
            let records = Arc::new(Mutex::new(Vec::new()));
            let result = if with_status {
                run_round_with_status(
                    &cfg,
                    &RunStatusConfig::new("root-resource-review"),
                    Box::new(Records(records.clone())),
                )
            } else {
                run_round(&cfg)
            };
            assert!(
                matches!(&result, Err(e) if e.contains("invalid resource policy") && e.contains(field)),
                "invalid {policy:?}, status={with_status}: {result:?}"
            );
            assert!(
                !Path::new(&cfg.log_path).exists(),
                "invalid config started a round"
            );
            assert!(!Path::new(&cfg.prompt_out).exists());
            assert!(records.lock().unwrap().is_empty());
        }
    }
}

const CHILD: &str = r#"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prompt = &args[args.iter().position(|a| a == "--prompt-file").unwrap() + 1];
    let cgroups = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let group = cgroups.lines().find_map(|s| s.strip_prefix("0::")).unwrap();
    let base = format!("/sys/fs/cgroup{group}");
    let mut observed = format!("{group}\n");
    for name in ["cpu.max", "memory.max", "memory.swap.max"] {
        observed.push_str(std::fs::read_to_string(format!("{base}/{name}")).unwrap().trim());
        observed.push('\n');
    }
    std::fs::write(format!("{prompt}.limits"), observed).unwrap();
}
"#;

fn child() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = directory("compiler");
        let source = dir.join("child.rs");
        let bin = dir.join("child");
        std::fs::write(&source, CHILD).unwrap();
        let output = Command::new("rustc")
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

#[test]
fn cli_limits_are_visible_to_the_actual_child_and_scope_is_cleaned() {
    for (cpu, swap, swap_bytes) in [(100u64, "0", 0u64), (125, "64MiB", 67108864)] {
        let dir = directory("cli");
        let cfg = config(&dir);
        std::fs::write(&cfg.template_path, "AGENT_NAME reads own cgroup").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_agent-bus-scheduler"))
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
                child().to_str().unwrap(),
                "--round-timeout",
                "15",
                "--once",
                "--cpu-quota-percent",
                &cpu.to_string(),
                "--memory-max",
                "512MiB",
                "--memory-swap-max",
                swap,
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{output:?}; {}",
            std::fs::read_to_string(&cfg.log_path).unwrap_or_default()
        );
        let observation = std::fs::read_to_string(format!("{}.limits", cfg.prompt_out)).unwrap();
        let lines: Vec<&str> = observation.lines().collect();
        assert_eq!(lines.len(), 4, "{observation}");
        let cpu_max: Vec<u64> = lines[1]
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(cpu_max.len(), 2);
        assert_eq!(cpu_max[0] * 100, cpu * cpu_max[1]);
        assert_eq!(lines[2].parse::<u64>().unwrap(), 536870912);
        assert_eq!(lines[3].parse::<u64>().unwrap(), swap_bytes);
        let unit = lines[0].rsplit('/').next().unwrap();
        assert!(
            unit.starts_with("agent-bus-round-root-resource-review-"),
            "{unit}"
        );
        let state = Command::new("systemctl")
            .args(["--user", "show", unit, "--property=ActiveState", "--value"])
            .output()
            .unwrap();
        assert!(state.status.success(), "{state:?}");
        assert!(
            matches!(
                String::from_utf8_lossy(&state.stdout).trim(),
                "inactive" | "failed"
            ),
            "{state:?}"
        );
        match std::fs::read_to_string(format!("/sys/fs/cgroup{}/cgroup.procs", lines[0])) {
            Ok(pids) => assert!(
                pids.trim().is_empty(),
                "owned scope remains populated: {pids}"
            ),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        }
    }
}
