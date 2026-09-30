//! Native replacement for `agents/crew-loop.sh` / `agents/sota-loop.sh`.
//!
//! Renders a prompt template with `AGENT_NAME`/`AGENT_ROLE` substitution
//! (no Python), then runs one `muse exec` round per interval with output
//! appended to a log file: exactly one owned child at a time, native
//! timeout cleanup, honest exit codes.
//!
//! Usage:
//! ```text
//! agent-bus-scheduler --template <md> --workspace <dir> --agent <name>
//!   --role <role> --log <file> [--interval <secs>] [--initial-delay <secs>]
//!   [--round-steps <n>] [--round-timeout <secs>]
//!   [--reasoning-effort <level>] [--subagent-worktree-isolation]
//!   [--muse-bin <path>] [--prompt-out <file>] [--once]
//!   [--bus-status --task <name>]
//!   [--cpu-quota-percent <1-1000>] [--memory-max <bytes>] [--memory-swap-max <bytes>]
//! ```
//!
//! Model config is inherited by default: `--reasoning-effort` is omitted
//! unless explicitly supplied, so rounds use the Muse configuration.
//! Pass `--reasoning-effort <level>` to forward one value unchanged.
//!
//! Legacy equivalents (explicit flags, not defaults):
//! - crew loop used `--reasoning-effort low`
//! - sota loop used `--reasoning-effort medium --subagent-worktree-isolation`
//!
//! `--once` runs a single round and exits with the round's exit code; it
//! exists for independent tests and one-off rounds. Without `--once` the
//! scheduler loops forever; a failed prompt render skips the round (exit 3
//! logged) and continues, matching the legacy scripts.
//!
//! `--bus-status` enables opt-in per-run KV lifecycle records (unique
//! `ctx.sched.<task>.<agent>.<run>` keys, finite TTLs) and requires
//! `--task`. Bus connection uses `AGENT_BUS_HOST`/`AGENT_BUS_PORT`/
//! `AGENT_BUS_AGENT`/`AGENT_BUS_TOKEN` like the native CLI, but the status
//! transport requires an `IP:port` literal (hostnames fail fast without DNS;
//! default `127.0.0.1:8379`). Without `--bus-status` no bus IO happens
//! (default offline preserved). See `docs/NATIVE_SCHEDULER_STATUS.md`.
//!
//! `--task-report` (requires `--bus-status --task`) adds explicit worker
//! task-completion evidence: the scheduler creates a unique per-run report
//! directory, passes its path plus expected run/task/agent identity to the
//! child, and includes the validated file separately as `task_completion`
//! in status records. The child writes with `agent-bus task-report --state
//! complete|needs_resume --summary ...`. Process outcome stays independent.
//! See `docs/NATIVE_TASK_COMPLETION.md`.
//!
//! Resource policy (Linux/systemd only, optional, backward-compatible):
//! `--cpu-quota-percent` takes plain digits 1..=1000 (100 = one CPU);
//! `--memory-max` / `--memory-swap-max` take `<digits>[KiB|MiB|GiB]`
//! (binary, plain digits are bytes). `--memory-swap-max 0` explicitly
//! forbids new swap; omitting a flag leaves that limit unset. Malformed,
//! overflow, out-of-range, or ambiguous values fail with exit 2 before any
//! workload spawns. Requested limits are applied to the exact round scope
//! before the workload and verified against actual cgroup files; a refused
//! or unverifiable policy fails the round closed. See
//! `docs/NATIVE_SCHEDULER_RESOURCE_POLICY.md`.

use agent_bus::scheduler::{
    install_shutdown_handlers, parse_cpu_quota_percent, parse_memory_bytes, run_round,
    run_round_with_status, shutdown_exit_code, sleep_until_shutdown, RunStatusConfig,
    SchedulerConfig,
};
use std::process::ExitCode;

fn usage() -> &'static str {
    "usage: agent-bus-scheduler --template <md> --workspace <dir> --agent <name> \
     --role <role> --log <file> [--interval <secs>] [--initial-delay <secs>] \
     [--round-steps <n>] [--round-timeout <secs>] [--reasoning-effort <level>] \
     [--subagent-worktree-isolation] [--muse-bin <path>] [--prompt-out <file>] [--once] \
     [--bus-status --task <name> [--task-report]] \
     [--cpu-quota-percent <1-1000>] [--memory-max <bytes>] [--memory-swap-max <bytes>]"
}

fn parse_u64(v: &str, flag: &str) -> Result<u64, String> {
    v.parse::<u64>()
        .map_err(|_| format!("{flag} expects a non-negative integer, got {v:?}"))
}

fn parse_u32(v: &str, flag: &str) -> Result<u32, String> {
    v.parse::<u32>()
        .map_err(|_| format!("{flag} expects a non-negative integer, got {v:?}"))
}

struct ParsedArgs {
    cfg: SchedulerConfig,
    once: bool,
    bus_status: bool,
    task: Option<String>,
    task_report: bool,
}

fn parse_args(raw: Vec<String>) -> Result<ParsedArgs, String> {
    let mut template: Option<String> = None;
    let mut workspace: Option<String> = None;
    let mut agent: Option<String> = None;
    let mut role: Option<String> = None;
    let mut log: Option<String> = None;
    let mut interval: Option<u64> = None;
    let mut initial_delay: Option<u64> = None;
    let mut steps: Option<u32> = None;
    let mut timeout: Option<u64> = None;
    let mut effort: Option<String> = None;
    let mut isolation = false;
    let mut muse_bin: Option<String> = None;
    let mut prompt_out: Option<String> = None;
    let mut once = false;
    let mut bus_status = false;
    let mut task: Option<String> = None;
    let mut task_report = false;
    let mut cpu_quota: Option<u32> = None;
    let mut memory_max: Option<u64> = None;
    let mut memory_swap_max: Option<u64> = None;

    let need_val = |flag: &str, v: Option<String>| -> Result<String, String> {
        v.ok_or_else(|| format!("{flag} expects a value"))
    };
    let mut args = raw.into_iter().peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--template" => template = Some(need_val("--template", args.next())?),
            "--workspace" => workspace = Some(need_val("--workspace", args.next())?),
            "--agent" => agent = Some(need_val("--agent", args.next())?),
            "--role" => role = Some(need_val("--role", args.next())?),
            "--log" => log = Some(need_val("--log", args.next())?),
            "--interval" => {
                interval = Some(parse_u64(
                    &need_val("--interval", args.next())?,
                    "--interval",
                )?)
            }
            "--initial-delay" => {
                initial_delay = Some(parse_u64(
                    &need_val("--initial-delay", args.next())?,
                    "--initial-delay",
                )?)
            }
            "--round-steps" => {
                steps = Some(parse_u32(
                    &need_val("--round-steps", args.next())?,
                    "--round-steps",
                )?)
            }
            "--round-timeout" => {
                timeout = Some(parse_u64(
                    &need_val("--round-timeout", args.next())?,
                    "--round-timeout",
                )?)
            }
            "--reasoning-effort" => effort = Some(need_val("--reasoning-effort", args.next())?),
            "--subagent-worktree-isolation" => isolation = true,
            "--muse-bin" => muse_bin = Some(need_val("--muse-bin", args.next())?),
            "--prompt-out" => prompt_out = Some(need_val("--prompt-out", args.next())?),
            "--once" => once = true,
            "--bus-status" => bus_status = true,
            "--task" => task = Some(need_val("--task", args.next())?),
            "--task-report" => task_report = true,
            "--cpu-quota-percent" => {
                cpu_quota = Some(parse_cpu_quota_percent(&need_val(
                    "--cpu-quota-percent",
                    args.next(),
                )?)?)
            }
            "--memory-max" => {
                memory_max = Some(parse_memory_bytes(
                    &need_val("--memory-max", args.next())?,
                    false,
                    "--memory-max",
                )?)
            }
            "--memory-swap-max" => {
                memory_swap_max = Some(parse_memory_bytes(
                    &need_val("--memory-swap-max", args.next())?,
                    true,
                    "--memory-swap-max",
                )?)
            }
            "--help" | "-h" => return Err("__help__".to_string()),
            other => return Err(format!("unknown argument: {other}\n{}", usage())),
        }
    }
    let (Some(template), Some(workspace), Some(agent), Some(role), Some(log)) =
        (template, workspace, agent, role, log)
    else {
        return Err(format!(
            "missing required --template/--workspace/--agent/--role/--log\n{}",
            usage()
        ));
    };
    let prompt_out = prompt_out.unwrap_or_else(|| format!("/tmp/prompt-{agent}.md"));
    let mut cfg = SchedulerConfig::new(&template, &prompt_out, &workspace, &agent, &role, &log);
    if let Some(v) = interval {
        cfg.interval_secs = v;
    }
    if let Some(v) = initial_delay {
        cfg.initial_delay_secs = v;
    }
    if let Some(v) = steps {
        cfg.round_steps = v;
    }
    if let Some(v) = timeout {
        cfg.round_timeout_secs = v;
    }
    if let Some(v) = effort {
        cfg.reasoning_effort = Some(v);
    }
    cfg.subagent_worktree_isolation = isolation;
    if let Some(v) = muse_bin {
        cfg.muse_bin = v;
    }
    cfg.resource_policy.cpu_quota_percent = cpu_quota;
    cfg.resource_policy.memory_max_bytes = memory_max;
    cfg.resource_policy.memory_swap_max_bytes = memory_swap_max;
    if bus_status && task.as_deref().map(|t| t.trim().is_empty()).unwrap_or(true) {
        return Err(format!("--bus-status requires --task <name>\n{}", usage()));
    }
    if task_report && !bus_status {
        return Err(format!(
            "--task-report requires --bus-status --task <name>\n{}",
            usage()
        ));
    }
    Ok(ParsedArgs {
        cfg,
        once,
        bus_status,
        task,
        task_report,
    })
}

fn main() -> ExitCode {
    if let Err(error) = install_shutdown_handlers() {
        eprintln!("agent-bus-scheduler: {error}");
        return ExitCode::FAILURE;
    }
    match parse_args(std::env::args().skip(1).collect()) {
        Ok(parsed) => run_scheduler(
            parsed.cfg,
            parsed.once,
            parsed.bus_status,
            parsed.task,
            parsed.task_report,
        ),
        Err(e) if e == "__help__" => {
            println!("{usage}", usage = usage());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("agent-bus-scheduler: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_scheduler(
    cfg: SchedulerConfig,
    once: bool,
    bus_status: bool,
    task: Option<String>,
    task_report: bool,
) -> ExitCode {
    if let Some(code) = sleep_until_shutdown(std::time::Duration::from_secs(cfg.initial_delay_secs))
    {
        return ExitCode::from(code.clamp(0, 255) as u8);
    }
    // Native transport is built per round (fresh connection per reporter);
    // credentials come from the environment and never appear in output.
    let status_cfg = if bus_status {
        let mut sc = RunStatusConfig::new(task.as_deref().unwrap_or(""));
        sc.task_report = task_report;
        Some(sc)
    } else {
        None
    };
    loop {
        let round_result = match &status_cfg {
            None => run_round(&cfg),
            Some(sc) => {
                let transport: Box<dyn agent_bus::scheduler::status::StatusTransport> =
                    match agent_bus::scheduler::status::NativeStatusTransport::from_env() {
                        Ok(t) => Box::new(t),
                        Err(e) => {
                            eprintln!("agent-bus-scheduler: bus-status unavailable: {e}");
                            return ExitCode::FAILURE;
                        }
                    };
                run_round_with_status(&cfg, sc, transport)
            }
        };
        match round_result {
            Ok(code) => {
                if once || shutdown_exit_code().is_some() {
                    return ExitCode::from(code.min(255).max(0) as u8);
                }
            }
            Err(e) => {
                // Fatal infra failure (log IO / spawn error): report honestly
                // instead of looping silently on a broken setup.
                eprintln!("agent-bus-scheduler: round FAILED: {e}");
                let _ =
                    agent_bus::scheduler::append_log(&cfg.log_path, &format!("round FAILED: {e}"));
                // Cleanup uncertainty must stop this scheduler. Retrying here
                // could start another agent over descendants still running.
                return ExitCode::FAILURE;
            }
        }
        if let Some(code) = sleep_until_shutdown(std::time::Duration::from_secs(cfg.interval_secs))
        {
            return ExitCode::from(code.clamp(0, 255) as u8);
        }
    }
}
