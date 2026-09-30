//! Native scheduler core: replaces `agents/crew-loop.sh` and
//! `agents/sota-loop.sh` Python prompt rendering and shell loop.
//!
//! Legacy loops did three things: `sleep`, a 4-line Python heredoc that only
//! substituted `AGENT_NAME`/`AGENT_ROLE` into a Markdown template, and one
//! `muse exec` round with output appended to a log. [`render_prompt`] covers
//! the substitution; [`SchedulerConfig`]/[`run_round`] cover the rest with
//! `std::fs` template reads and a `std::process::Command` spawn (no shell
//! command interpolation), one owned child at a time, and a native wait
//! timeout that kills an overrunning child before the next round.
//!
//! Timeout exit code follows the GNU `timeout` convention: 124.
//!
//! Process ownership has two layers. Each round's child is spawned as the
//! leader of a dedicated process group (via `setsid` in a `pre_exec` hook),
//! so a timed-out round can signal the whole group promptly. Because real
//! `muse` tool shells run in their own sessions/process groups (observed: a
//! tool shell with a different `SID` than its `muse` parent), `killpg` alone
//! cannot reach every descendant — so every round additionally owns a unique
//! transient systemd user scope holding a long-lived holder process. The
//! workload joins that scope with a raw-syscall `cgroup.procs` write in
//! `pre_exec`, before it can fork: containment proof is structural (a failed
//! write aborts the spawn), not a poll that a fast round could slip through.
//! Cgroup membership survives `setsid` and reparenting (even fully orphaned
//! daemons stay in the scope), so `systemctl --user stop <round-unit>` kills
//! all stragglers after a timeout, after a normal parent exit, and on
//! scheduler cancellation. Cleanup failures are fatal (`Err`), never silent,
//! so the scheduler refuses to overlap rounds on uncertain cleanup.
//!
//! Platform requirement: Linux with a running systemd user manager plus
//! `systemd-run`/`systemctl` (default `/usr/bin/systemd-run` and
//! `/usr/bin/systemctl`, overridable via `AGENT_BUS_SYSTEMD_RUN` and
//! `AGENT_BUS_SYSTEMCTL`). Without them rounds fail closed (`Err`) instead of
//! running uncontained.

use std::fs::OpenOptions;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "scheduler_status.rs"]
pub mod status;

// Raw libc bindings used for owned-process-group cleanup. Declared directly
// (no new crate dependency) because the scheduler must stay dependency-free.
#[cfg(unix)]
extern "C" {
    fn setsid() -> i32;
    fn killpg(pgrp: i32, sig: i32) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
}

static SHUTDOWN_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn record_shutdown(sig: i32) {
    // A lock-free atomic store is the only operation in the signal handler.
    SHUTDOWN_SIGNAL.store(sig, Ordering::Relaxed);
}

/// Install cancellation handlers in the standalone scheduler process. Library
/// callers keep their own signal policy; this is not installed by run_round.
pub fn install_shutdown_handlers() -> Result<(), String> {
    #[cfg(unix)]
    for sig in [2, 15] {
        // SAFETY: fixed signal numbers and a process-lifetime C handler. It
        // only records a flag; ordinary control flow performs cleanup.
        if unsafe { signal(sig, record_shutdown as *const () as usize) } == usize::MAX {
            return Err(format!(
                "cannot install cancellation handler: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

pub fn shutdown_exit_code() -> Option<i32> {
    let sig = SHUTDOWN_SIGNAL.load(Ordering::Relaxed);
    (sig != 0).then_some(128 + sig)
}

/// Sleep between rounds while remaining responsive to cancellation.
pub fn sleep_until_shutdown(duration: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        if let Some(code) = shutdown_exit_code() {
            return Some(code);
        }
        let left = duration.saturating_sub(start.elapsed());
        if left.is_zero() {
            return None;
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;
/// `killpg(pgid, 0)` performs existence probing with no signal delivery.
#[cfg(unix)]
const SIGNULL: i32 = 0;
/// Expected `errno` once no process survives in the probed group.
#[cfg(unix)]
const ESRCH: i32 = 3;
/// Grace period for descendants to exit on `SIGTERM` before `SIGKILL`.
#[cfg(unix)]
const TERM_GRACE: Duration = Duration::from_secs(2);
/// How long to wait for the group to read empty after `SIGKILL` before
/// declaring cleanup uncertain and failing closed.
#[cfg(unix)]
const REAP_GRACE: Duration = Duration::from_secs(5);

/// Timeout exit code, matching GNU `timeout`.
pub const TIMEOUT_EXIT_CODE: i32 = 124;
/// Exit code used when prompt generation fails (legacy scripts logged
/// `prompt generation FAILED (empty)` and `=== exit 3 ===`).
pub const PROMPT_FAILURE_EXIT_CODE: i32 = 3;

/// Optional per-round cgroup resource limits applied to the exact
/// holder/round scope before the workload spawns. All fields are `None` by
/// default (no explicit per-round limits; ancestor limits still apply). `Some(0)` for
/// swap is an explicit no-new-swap limit, not absence. Linux/systemd only;
/// other platforms fail closed at spawn time like all rounds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourcePolicy {
    /// CPU quota in percent (100 = one full CPU). Valid 1..=1000.
    pub cpu_quota_percent: Option<u32>,
    /// Hard memory ceiling in bytes. Must be > 0 when set.
    pub memory_max_bytes: Option<u64>,
    /// Swap ceiling in bytes. `Some(0)` forbids new swap; `None` omits.
    pub memory_swap_max_bytes: Option<u64>,
}

impl ResourcePolicy {
    /// True when no explicit per-round limit is requested.
    pub fn is_empty(&self) -> bool {
        self.cpu_quota_percent.is_none()
            && self.memory_max_bytes.is_none()
            && self.memory_swap_max_bytes.is_none()
    }

    /// Validate typed API input before any round side effects or spawning.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(cpu) = self.cpu_quota_percent {
            if !(1..=MAX_CPU_QUOTA_PERCENT).contains(&cpu) {
                return Err(format!(
                    "invalid resource policy: cpu_quota_percent must be 1..={MAX_CPU_QUOTA_PERCENT}, got {cpu}"
                ));
            }
        }
        if self.memory_max_bytes == Some(0) {
            return Err("invalid resource policy: memory_max_bytes must be > 0".to_string());
        }
        Ok(())
    }
}

/// Maximum CPU quota percent accepted by the scheduler CLI. This is a
/// scheduler typo guard, not a systemd maximum (systemd accepts larger).
pub const MAX_CPU_QUOTA_PERCENT: u32 = 1000;

/// Parse `--cpu-quota-percent` as plain decimal percent (no `%` suffix).
/// Rejects empty, non-digits, zero, overflow, and out-of-range values.
pub fn parse_cpu_quota_percent(s: &str) -> Result<u32, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "--cpu-quota-percent expects 1..={} (plain digits), got {s:?}",
            MAX_CPU_QUOTA_PERCENT
        ));
    }
    let v: u32 = s.parse().map_err(|_| {
        format!(
            "--cpu-quota-percent expects 1..={} (plain digits), got {s:?}",
            MAX_CPU_QUOTA_PERCENT
        )
    })?;
    if v == 0 || v > MAX_CPU_QUOTA_PERCENT {
        return Err(format!(
            "--cpu-quota-percent expects 1..={} (plain digits), got {s:?}",
            MAX_CPU_QUOTA_PERCENT
        ));
    }
    Ok(v)
}

/// Parse a byte count as decimal digits with optional `KiB`/`MiB`/`GiB`
/// suffix (binary 1024-based). Plain digits mean bytes. Rejects empty,
/// signs, spaces, fractional, unknown/ambiguous suffixes (`K`, `M`, `G`,
/// `KB`, `GB`, lowercase), overflow via checked arithmetic, and zero unless
/// `allow_zero` (swap only).
pub fn parse_memory_bytes(s: &str, allow_zero: bool, flag: &str) -> Result<u64, String> {
    let err = || format!("{flag} expects <digits>[KiB|MiB|GiB], got {s:?}");
    if s.is_empty() {
        return Err(err());
    }
    let split = s
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    let (digits, suffix) = s.split_at(split);
    if digits.is_empty() {
        return Err(err());
    }
    let base: u64 = digits.parse().map_err(|_| err())?;
    let mult: u64 = match suffix {
        "" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        _ => return Err(err()),
    };
    let bytes = base
        .checked_mul(mult)
        .ok_or_else(|| format!("{flag} overflows u64: {s:?}"))?;
    if bytes == 0 && !allow_zero {
        return Err(format!("{flag} must be > 0 bytes, got {s:?}"));
    }
    Ok(bytes)
}

/// `systemd-run -p` argv fragments for the requested policy, as separate
/// argv entries (no shell). Empty when no limit is requested.
pub fn resource_systemd_args(policy: &ResourcePolicy) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(p) = policy.cpu_quota_percent {
        out.push("-p".to_string());
        out.push(format!("CPUQuota={p}%"));
    }
    if let Some(b) = policy.memory_max_bytes {
        out.push("-p".to_string());
        out.push(format!("MemoryMax={b}"));
    }
    if let Some(b) = policy.memory_swap_max_bytes {
        out.push("-p".to_string());
        out.push(format!("MemorySwapMax={b}"));
    }
    out
}

/// Everything one scheduler invocation needs. Mirrors the legacy loop
/// positionals plus `AGENT_BUS_ROUND_STEPS`/`AGENT_BUS_ROUND_TIMEOUT` env
/// overrides. `--reasoning-effort` is omitted by default so rounds inherit
/// the Muse configuration; pass it explicitly to forward one value
/// unchanged (legacy crew used `low`, sota used `medium`).
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Markdown template containing `AGENT_NAME`/`AGENT_ROLE` placeholders.
    pub template_path: String,
    /// Rendered prompt destination (legacy: `/tmp/prompt-<name>.md`).
    pub prompt_out: String,
    /// `--workspace` value for `muse exec`.
    pub workspace: String,
    pub agent: String,
    pub role: String,
    /// Seconds between rounds.
    pub interval_secs: u64,
    /// Seconds to sleep before the first round.
    pub initial_delay_secs: u64,
    /// `--max-model-steps` value.
    pub round_steps: u32,
    /// Per-round wall-clock budget; overrunning child is killed.
    pub round_timeout_secs: u64,
    /// Log file rounds append to (round header, child output, exit line).
    pub log_path: String,
    /// Explicit `--reasoning-effort` value (`low`/`medium`/etc), forwarded
    /// unchanged. `None` (default) omits the flag so the round inherits
    /// the Muse configuration.
    pub reasoning_effort: Option<String>,
    /// Whether to pass `--subagent-worktree-isolation`.
    pub subagent_worktree_isolation: bool,
    /// Muse executable (real `muse`; tests inject a harmless fake).
    pub muse_bin: String,
    /// Optional per-round cgroup limits. Empty by default; ancestor limits apply.
    pub resource_policy: ResourcePolicy,
}

impl SchedulerConfig {
    /// Defaults matching `crew-loop.sh` (`ROUND_STEPS=50`,
    /// `ROUND_TIMEOUT=1200`, no isolation) except `--reasoning-effort`,
    /// which is omitted by default (`None`) so rounds inherit the Muse
    /// configuration instead of forcing `low`.
    pub fn new(
        template_path: &str,
        prompt_out: &str,
        workspace: &str,
        agent: &str,
        role: &str,
        log_path: &str,
    ) -> Self {
        Self {
            template_path: template_path.into(),
            prompt_out: prompt_out.into(),
            workspace: workspace.into(),
            agent: agent.into(),
            role: role.into(),
            interval_secs: 300,
            initial_delay_secs: 0,
            round_steps: 50,
            round_timeout_secs: 1200,
            log_path: log_path.into(),
            reasoning_effort: None,
            subagent_worktree_isolation: false,
            muse_bin: "muse".into(),
            resource_policy: ResourcePolicy::default(),
        }
    }
}

/// Substitute AGENT_NAME/AGENT_ROLE placeholders in a prompt template.
///
/// Returns an error on empty template or empty output instead of running a
/// round with a missing prompt (legacy scripts checked `-s` on the file).
pub fn render_prompt(template: &str, name: &str, role: &str) -> Result<String, String> {
    if template.is_empty() {
        return Err("prompt generation FAILED (empty template)".into());
    }
    let out = template
        .replace("AGENT_NAME", name)
        .replace("AGENT_ROLE", role);
    if out.trim().is_empty() {
        return Err("prompt generation FAILED (empty)".into());
    }
    Ok(out)
}

/// Read a template file and render it for `name`/`role`.
pub fn render_file(template_path: &str, name: &str, role: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(template_path)
        .map_err(|e| format!("prompt template read FAILED ({template_path}): {e}"))?;
    render_prompt(&text, name, role)
}

/// Argument vector for the `muse exec` child (excluding argv[0]).
/// No shell is involved; the caller passes this straight to [`Command`].
/// `--reasoning-effort` is only present when
/// [`SchedulerConfig::reasoning_effort`] is `Some`: default rounds omit
/// it and inherit the Muse configuration.
pub fn muse_argv(cfg: &SchedulerConfig) -> Vec<String> {
    let mut args = vec![
        "exec".to_string(),
        "--yolo".to_string(),
        "--disable-sandbox".to_string(),
        "--disable-web-tools".to_string(),
        "--workspace".to_string(),
        cfg.workspace.clone(),
    ];
    if let Some(effort) = cfg.reasoning_effort.as_ref() {
        args.push("--reasoning-effort".to_string());
        args.push(effort.clone());
    }
    args.push("--max-model-steps".to_string());
    args.push(cfg.round_steps.to_string());
    if cfg.subagent_worktree_isolation {
        args.push("--subagent-worktree-isolation".to_string());
    }
    args.push("--prompt-file".to_string());
    args.push(cfg.prompt_out.clone());
    args
}

/// Seconds-since-epoch UTC stamp for the `=== round ... ===` header.
pub fn utc_stamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => format!("{}", d.as_secs()),
        Err(_) => "unknown-time".to_string(),
    }
}

/// Append one line (plus trailing newline) to the log file.
pub fn append_log(log_path: &str, line: &str) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("log append FAILED ({log_path}): {e}"))?;
    writeln!(f, "{line}").map_err(|e| format!("log write FAILED ({log_path}): {e}"))?;
    Ok(())
}

/// `true` when no process survives in `pgid` (probed with `killpg(pgid, 0)`
/// returning `ESRCH`); `false` while any member — child or descendant — lives.
#[cfg(unix)]
fn group_is_empty(pgid: i32) -> bool {
    // SAFETY: `killpg` with sig 0 delivers nothing; it only reports whether
    // the group has members via its return value / `errno`.
    let r = unsafe { killpg(pgid, SIGNULL) };
    if r == 0 {
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(ESRCH)
}

/// Test-only fault seam: `AGENT_BUS_FAIL_GROUP_CLEANUP=1` forces group
/// cleanup to report failure without side effects, proving scope cleanup is
/// still attempted. Production never sets this.
fn group_cleanup_fault() -> Option<String> {
    match std::env::var("AGENT_BUS_FAIL_GROUP_CLEANUP") {
        Ok(v) if v == "1" => Some("round CLEANUP FAILED: injected group-cleanup fault".to_string()),
        _ => None,
    }
}

/// Combine owned-group and owned-scope cleanup outcomes. Both layers are
/// always attempted by the caller; neither error is silent.
fn combine_cleanup(group: Result<i32, String>, scope: Result<(), String>) -> Result<(), String> {
    match (group, scope) {
        (Ok(_), Ok(())) => Ok(()),
        (Ok(_), Err(s)) => Err(s),
        (Err(g), Ok(())) => Err(g),
        (Err(g), Err(s)) => Err(format!("{g}; {s}")),
    }
}

/// Signal the whole owned group (`SIGTERM`, grace, then `SIGKILL`), reap the
/// direct child, and verify every descendant exited. Returns the timeout exit
/// code on success; `Err` on uncertain cleanup so the caller refuses to start
/// another round over possibly live processes.
#[cfg(unix)]
fn kill_owned_group(child: &mut std::process::Child) -> Result<i32, String> {
    if let Some(err) = group_cleanup_fault() {
        return Err(err);
    }
    let pgid = child.id() as i32;
    if group_is_empty(pgid) {
        return Ok(TIMEOUT_EXIT_CODE);
    }
    // SAFETY: `pgid` is our own freshly spawned session leader, so signaling
    // it cannot reach scheduler-external processes.
    unsafe {
        killpg(pgid, SIGTERM);
    }
    let term_deadline = Instant::now() + TERM_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if group_is_empty(pgid) || Instant::now() >= term_deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!(
                    "round CLEANUP FAILED: wait during SIGTERM cleanup: {e}"
                ));
            }
        }
    }
    // SAFETY: same owned group as above.
    unsafe {
        killpg(pgid, SIGKILL);
    }
    // Reap the direct child so no zombie escapes into the next round's slot.
    // `wait` after `try_wait` reported exit may fail; that still means the
    // direct child is gone, so only a hard wait error fails closed.
    match child.try_wait() {
        Ok(Some(_)) => {
            let _ = child.wait();
        }
        Ok(None) => {
            child
                .wait()
                .map_err(|e| format!("round CLEANUP FAILED: reap owned child {pgid}: {e}"))?;
        }
        Err(e) => {
            return Err(format!(
                "round CLEANUP FAILED: wait owned child {pgid}: {e}"
            ));
        }
    }
    let deadline = Instant::now() + REAP_GRACE;
    loop {
        if group_is_empty(pgid) {
            return Ok(TIMEOUT_EXIT_CODE);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "round CLEANUP FAILED: process group {pgid} survives SIGKILL; \
                 refusing next round over possibly live descendants"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Portable fallback where process groups are unavailable: kill and reap the
/// direct child. Descendant cleanup is only guaranteed on Unix.
#[cfg(not(unix))]
fn kill_owned_group(child: &mut std::process::Child) -> Result<i32, String> {
    if let Some(err) = group_cleanup_fault() {
        return Err(err);
    }
    let _ = child.kill();
    child
        .wait()
        .map_err(|e| format!("round CLEANUP FAILED: reap owned child: {e}"))?;
    Ok(TIMEOUT_EXIT_CODE)
}

/// `systemd-run` binary containing the round (`AGENT_BUS_SYSTEMD_RUN` wins).
fn systemd_run_bin() -> String {
    std::env::var("AGENT_BUS_SYSTEMD_RUN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/usr/bin/systemd-run".to_string())
}

/// `systemctl` binary driving scope cleanup (`AGENT_BUS_SYSTEMCTL` wins).
fn systemctl_bin() -> String {
    std::env::var("AGENT_BUS_SYSTEMCTL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/usr/bin/systemctl".to_string())
}

/// `TimeoutStopSec` set on every owned scope: `stop` escalates `SIGTERM` to
/// `SIGKILL` after this long, bounding straggler cleanup.
#[cfg(unix)]
const SCOPE_STOP_TIMEOUT_SECS: &str = "3";
/// How long to wait for a freshly spawned scope to report `active` before the
/// round is declared uncontained and fails closed.
#[cfg(unix)]
const SCOPE_VERIFY_GRACE: Duration = Duration::from_secs(2);
/// How long `stop` plus re-polling may take before cleanup is declared
/// uncertain and fails closed.
#[cfg(unix)]
const SCOPE_STOP_GRACE: Duration = Duration::from_secs(10);
/// Bound for any single `systemctl` control call so a wedged user manager
/// cannot hang a round forever.
#[cfg(unix)]
const TOOL_CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-process scope-name counter; combined with pid + nanos it makes every
/// round's unit unique, so cleanup never touches another round's unit.
#[cfg(unix)]
static SCOPE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Keep one unit-name character class: anything outside it becomes `-`, so a
/// hostile agent name cannot inject flags or paths into unit selection.
#[cfg(unix)]
fn sanitize_unit_fragment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Unique transient scope unit for one round. Uniqueness is the identity
/// proof: no other scheduler, round, or external job can own this name, so
/// `stop <unit>` only ever signals this round's processes.
#[cfg(unix)]
fn new_scope_unit(agent: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SCOPE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "agent-bus-round-{}-{}-{}-{}.scope",
        sanitize_unit_fragment(agent),
        std::process::id(),
        nanos,
        n
    )
}

/// Run one short-lived `systemctl`/`systemd-run` control call with stdin null
/// and a hard timeout. Returns `(exit_code, stdout, stderr)`.
#[cfg(unix)]
fn run_tool(bin: &str, args: &[&str], timeout: Duration) -> Result<(i32, String, String), String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("containment tool spawn FAILED ({bin}): {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // The child has exited, so its pipes are at EOF: drain them
                // directly (`wait_with_output` here would fail — `try_wait`
                // already reaped the child — and drop the output this
                // containment layer parses).
                use std::io::Read as _;
                let mut so = String::new();
                let mut se = String::new();
                if let Some(mut h) = child.stdout.take() {
                    let _ = h.read_to_string(&mut so);
                }
                if let Some(mut h) = child.stderr.take() {
                    let _ = h.read_to_string(&mut se);
                }
                let _ = child.wait();
                return Ok((status.code().unwrap_or(1), so, se));
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "containment tool TIMEOUT ({bin} {} exceeded {timeout:?})",
                        args.join(" ")
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("containment tool wait FAILED ({bin}): {e}"));
            }
        }
    }
}

/// `true` only when the user manager answers `is-system-running` with
/// `running` (or `degraded`): otherwise no scope can be created and rounds
/// must fail closed.
#[cfg(unix)]
fn user_manager_available() -> bool {
    match run_tool(
        &systemctl_bin(),
        &["--user", "is-system-running"],
        TOOL_CALL_TIMEOUT,
    ) {
        Ok((_, stdout, _)) => matches!(stdout.trim(), "running" | "degraded"),
        Err(_) => false,
    }
}

#[cfg(unix)]
struct ScopeState {
    load_state: String,
    active_state: String,
    manager_result: Option<String>,
}

/// Preserve placement callers' state interface; cleanup additionally records
/// the manager result from the same query, with no post-cleanup tool call.
#[cfg(unix)]
fn scope_state(unit: &str) -> Result<(String, String), String> {
    let state = scope_state_observed(unit)?;
    Ok((state.load_state, state.active_state))
}

#[cfg(unix)]
fn scope_state_observed(unit: &str) -> Result<ScopeState, String> {
    let (code, stdout, stderr) = run_tool(
        &systemctl_bin(),
        &[
            "--user",
            "show",
            unit,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "Result",
        ],
        TOOL_CALL_TIMEOUT,
    )?;
    if code != 0 {
        return Err(format!(
            "scope query FAILED ({unit} exit {code}): {}",
            stderr.trim()
        ));
    }
    parse_scope_state(unit, &stdout)
}

/// Parse KEY=value lines order-independently. A missing Result is unknown;
/// it must not invalidate a gone-unit proof or be guessed as success.
#[cfg(unix)]
fn parse_scope_state(unit: &str, stdout: &str) -> Result<ScopeState, String> {
    let mut load = String::new();
    let mut active = String::new();
    let mut result = None;
    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("LoadState=") {
            load = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("ActiveState=") {
            active = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Result=") {
            result = (!v.trim().is_empty()).then(|| v.trim().to_string());
        }
    }
    if load.is_empty() || active.is_empty() {
        return Err(format!("scope query UNPARSEABLE ({unit}): {stdout:?}"));
    }
    Ok(ScopeState {
        load_state: load,
        active_state: active,
        manager_result: result,
    })
}

/// Pure decision from `(LoadState, ActiveState)`: `Some(true)` is provably
/// empty (unit gone), `Some(false)` is not empty (active or transitional),
/// `None` needs owned-cgroup verification (strict terminal state).
#[cfg(unix)]
fn scope_empty_from_state(load: &str, active: &str) -> Option<bool> {
    if load == "not-found" {
        return Some(true);
    }
    match active {
        "inactive" | "failed" => None,
        _ => Some(false),
    }
}

/// `true` when `cgroup.procs` at `path` holds no PIDs: a missing file (cgroup
/// removed) or whitespace-only counts as empty. Other IO errors are
/// uncertainty.
#[cfg(unix)]
fn cgroup_procs_is_empty(path: &str) -> Result<bool, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(content.split_whitespace().next().is_none()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(format!("cgroup read FAILED ({path}): {e}")),
    }
}

/// Evidence only when no process of this round's exact owned scope survives: the unit
/// is gone (`not-found`), or it is in a strict terminal state (`inactive` /
/// `failed`) with its retained cgroup verified empty. Transitional states
/// (`activating`, `deactivating`, `reloading`, unknown) are never empty — a
/// stop in progress does not prove all tasks exited. Any query failure is
/// uncertainty, reported as `Err` so the caller fails closed.
#[cfg(unix)]
fn scope_empty_observation(unit: &str) -> Result<Option<status::ScopeCleanup>, String> {
    let state = scope_state_observed(unit)?;
    let empty = match scope_empty_from_state(&state.load_state, &state.active_state) {
        Some(empty) => empty,
        None => match scope_cgroup_procs(unit)? {
            Some(path) => cgroup_procs_is_empty(&path)?,
            None => true,
        },
    };
    Ok(empty.then_some(status::ScopeCleanup {
        stop_requested: false,
        stop_exit_code: None,
        load_state: state.load_state,
        active_state: state.active_state,
        manager_result: state.manager_result,
        empty_verified: true,
    }))
}

/// Stop the owned scope and verify its cgroup drained. Tolerates the unit
/// already being gone (`stop` exit 5 with `not-loaded`); anything still alive
/// after the grace period is `Err` — the next round must not overlap it.
#[cfg(unix)]
fn stop_owned_scope(unit: &str) -> Result<(), String> {
    stop_owned_scope_observed(unit).map(|_| ())
}

#[cfg(unix)]
fn stop_owned_scope_observed(unit: &str) -> Result<status::ScopeCleanup, String> {
    if let Some(observation) = scope_empty_observation(unit)? {
        return Ok(observation);
    }
    // `stop` sends SIGTERM, waits the scope's TimeoutStopSec, then SIGKILLs
    // the whole cgroup — including setsid-detached and orphaned members that
    // killpg cannot reach. Its own exit code is advisory: only the re-poll
    // below proves emptiness.
    let stop_exit_code = run_tool(
        &systemctl_bin(),
        &["--user", "stop", unit],
        SCOPE_STOP_GRACE,
    )
    .ok()
    .map(|(code, _, _)| code);
    let deadline = Instant::now() + SCOPE_STOP_GRACE;
    loop {
        match scope_empty_observation(unit) {
            Ok(Some(mut observation)) => {
                observation.stop_requested = true;
                observation.stop_exit_code = stop_exit_code;
                return Ok(observation);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "round CLEANUP FAILED: scope {unit} survives stop; \
                         refusing next round over possibly live descendants"
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("round CLEANUP FAILED: {e}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Holder workload keeping the owned scope alive across creation: an absolute
/// `sleep` path plus a bounded duration. The holder only needs to outlive
/// scope creation (it cannot exit fast, so observing `active` is race-free);
/// if it dies mid-round the scope persists while round tasks remain, and
/// round-end `stop` reaps it either way.
#[cfg(unix)]
const HOLDER_BIN: &str = "/bin/sleep";
/// Upper bound on holder lifetime; a round may outlive it harmlessly.
#[cfg(unix)]
const HOLDER_SLEEP_SECS: &str = "300";
/// Cgroupfs mount point used to resolve a scope's `cgroup.procs`.
#[cfg(unix)]
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

// Raw syscalls for the spawn-time placement step. Declared directly (no new
// crate dependency) like the existing `setsid`/`killpg` bindings.
#[cfg(unix)]
extern "C" {
    fn getpid() -> i32;
    fn open(path: *const u8, flags: i32) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn close(fd: i32) -> i32;
}

/// An owned, verified-live scope plus the cgroup path round children are
/// placed into. Unique per round (see [`new_scope_unit`]).
#[cfg(unix)]
struct Holder {
    unit: String,
    cgroup_procs: String,
    resources_observed: Option<status::ResourceObservation>,
}

/// Successful scoped spawn: direct child plus owning scope and verified
/// resource observation (`None` when no limit was requested).
#[cfg(unix)]
struct ScopedSpawn {
    child: std::process::Child,
    scope_unit: String,
    resources_observed: Option<status::ResourceObservation>,
}

/// Spawn failure with optional resource observation for honest status.
/// `resources_observed` is `Some` only when a resource policy was requested
/// and cgroup readback was attempted (verified/failed/unavailable);
/// `None` means no policy or no readback attempted.
#[cfg(unix)]
struct SpawnFailure {
    msg: String,
    resources_observed: Option<status::ResourceObservation>,
}

#[cfg(unix)]
impl From<String> for SpawnFailure {
    fn from(msg: String) -> Self {
        Self {
            msg,
            resources_observed: None,
        }
    }
}

/// Parse `cpu.max` content (`<quota|max> <period>`) into
/// `(quota, period)`. `quota=None` means unlimited (`max`).
#[cfg(unix)]
fn parse_cpu_max(content: &str) -> Result<(Option<u64>, u64), String> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(format!("cpu.max UNPARSEABLE: {content:?}"));
    }
    let quota = if parts[0] == "max" {
        None
    } else {
        if parts[0].is_empty() || !parts[0].bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("cpu.max UNPARSEABLE: {content:?}"));
        }
        Some(
            parts[0]
                .parse::<u64>()
                .map_err(|_| format!("cpu.max UNPARSEABLE: {content:?}"))?,
        )
    };
    if parts[1].is_empty() || !parts[1].bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("cpu.max UNPARSEABLE: {content:?}"));
    }
    let period: u64 = parts[1]
        .parse::<u64>()
        .map_err(|_| format!("cpu.max UNPARSEABLE: {content:?}"))?;
    if period == 0 {
        return Err(format!("cpu.max UNPARSEABLE (zero period): {content:?}"));
    }
    Ok((quota, period))
}

/// Parse `memory.max` / `memory.swap.max` content (`<bytes|max>`).
/// Returns `None` for unlimited (`max`).
#[cfg(unix)]
fn parse_memory_max(content: &str, file: &str) -> Result<Option<u64>, String> {
    let t = content.trim();
    if t == "max" {
        return Ok(None);
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{file} UNPARSEABLE: {content:?}"));
    }
    t.parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{file} UNPARSEABLE: {content:?}"))
}

/// Derive the cgroup directory from a `cgroup.procs` path.
#[cfg(unix)]
fn cgroup_base_from_procs(procs: &str) -> String {
    procs
        .strip_suffix("/cgroup.procs")
        .unwrap_or(procs)
        .to_string()
}

/// Verify requested limits against actual cgroup files under `base`.
/// Only requested fields are read; omitted limits are unchecked.
/// Returns the observation plus `Ok` when every requested limit matches,
/// otherwise the observation plus an honest `Err`. IO errors yield
/// `Unavailable`, mismatches/parse errors yield `Failed`.
#[cfg(unix)]
fn verify_resources(
    policy: &ResourcePolicy,
    base: &str,
) -> (status::ResourceObservation, Result<(), String>) {
    use status::{ResourceObservation, ResourceVerification};
    let mut obs = ResourceObservation {
        cpu_quota_percent: None,
        memory_max_bytes: None,
        memory_swap_max_bytes: None,
        verification: ResourceVerification::Verified,
    };
    let mut failures: Vec<String> = Vec::new();
    let mut unavailable = false;

    if let Some(req) = policy.cpu_quota_percent {
        let path = format!("{base}/cpu.max");
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_cpu_max(&content) {
                Ok((None, _)) => {
                    failures.push(format!(
                        "resource policy FAILED: cpu requested {req}% observed unlimited (max)"
                    ));
                }
                Ok((Some(quota), period)) => {
                    let left = quota.checked_mul(100);
                    let right = (req as u64).checked_mul(period);
                    match (left, right) {
                        (Some(l), Some(r)) if l == r => {
                            obs.cpu_quota_percent = Some(req);
                        }
                        _ => {
                            let computed = quota
                                .checked_mul(100)
                                .filter(|v| v % period == 0)
                                .map(|v| v / period)
                                .and_then(|v| u32::try_from(v).ok());
                            obs.cpu_quota_percent = computed;
                            let seen = computed.map(|v| format!("{v}%")).unwrap_or_else(|| {
                                "non-integral or unrepresentable percentage".to_string()
                            });
                            failures.push(format!(
                                "resource policy FAILED: cpu requested {req}% observed {seen} (quota/period {quota}/{period})"
                            ));
                        }
                    }
                }
                Err(e) => {
                    failures.push(format!(
                        "resource policy FAILED: cpu {e} (requested {req}%)"
                    ));
                }
            },
            Err(e) => {
                unavailable = true;
                failures.push(format!(
                    "resource policy UNAVAILABLE: cgroup read FAILED ({path}): {e}"
                ));
            }
        }
    }

    if let Some(req) = policy.memory_max_bytes {
        let path = format!("{base}/memory.max");
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_memory_max(&content, "memory.max") {
                Ok(Some(got)) if got == req => {
                    obs.memory_max_bytes = Some(got);
                }
                Ok(Some(got)) => {
                    obs.memory_max_bytes = Some(got);
                    failures.push(format!(
                        "resource policy FAILED: memory requested {req} observed {got}"
                    ));
                }
                Ok(None) => {
                    failures.push(format!(
                        "resource policy FAILED: memory requested {req} observed unlimited (max)"
                    ));
                }
                Err(e) => {
                    failures.push(format!(
                        "resource policy FAILED: memory {e} (requested {req})"
                    ));
                }
            },
            Err(e) => {
                unavailable = true;
                failures.push(format!(
                    "resource policy UNAVAILABLE: cgroup read FAILED ({path}): {e}"
                ));
            }
        }
    }

    if let Some(req) = policy.memory_swap_max_bytes {
        let path = format!("{base}/memory.swap.max");
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_memory_max(&content, "memory.swap.max") {
                Ok(Some(got)) if got == req => {
                    obs.memory_swap_max_bytes = Some(got);
                }
                Ok(Some(got)) => {
                    obs.memory_swap_max_bytes = Some(got);
                    failures.push(format!(
                        "resource policy FAILED: swap requested {req} observed {got}"
                    ));
                }
                Ok(None) => {
                    failures.push(format!(
                        "resource policy FAILED: swap requested {req} observed unlimited (max)"
                    ));
                }
                Err(e) => {
                    failures.push(format!(
                        "resource policy FAILED: swap {e} (requested {req})"
                    ));
                }
            },
            Err(e) => {
                unavailable = true;
                failures.push(format!(
                    "resource policy UNAVAILABLE: cgroup read FAILED ({path}): {e}"
                ));
            }
        }
    }

    if unavailable {
        obs.verification = ResourceVerification::Unavailable;
    } else if !failures.is_empty() {
        obs.verification = ResourceVerification::Failed;
    } else {
        obs.verification = ResourceVerification::Verified;
    }
    let result = if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    };
    (obs, result)
}

/// Decimal pid rendering into a stack buffer (no allocation: this runs in the
/// `pre_exec` child context). Returns the byte count including `\n`.
#[cfg(unix)]
fn pid_line(pid: i32, buf: &mut [u8; 32]) -> usize {
    let mut digits = [0u8; 16];
    let mut len = 0usize;
    let mut n = pid as u32;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut i = 0;
    while i < len {
        buf[i] = digits[len - 1 - i];
        i += 1;
    }
    buf[i] = b'\n';
    i + 1
}

/// Query a scope's `ControlGroup` and resolve its `cgroup.procs` path.
/// `Ok(None)` means the unit retains no cgroup (empty `ControlGroup`).
#[cfg(unix)]
fn scope_cgroup_procs(unit: &str) -> Result<Option<String>, String> {
    let (code, stdout, stderr) = run_tool(
        &systemctl_bin(),
        &["--user", "show", unit, "-p", "ControlGroup"],
        TOOL_CALL_TIMEOUT,
    )?;
    if code != 0 {
        return Err(format!(
            "scope cgroup query FAILED ({unit} exit {code}): {}",
            stderr.trim()
        ));
    }
    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("ControlGroup=") {
            let v = v.trim();
            if v.is_empty() {
                return Ok(None);
            }
            let mount = std::env::var("AGENT_BUS_CGROUP_MOUNT")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| CGROUP_MOUNT.to_string());
            return Ok(Some(format!("{mount}{v}/cgroup.procs")));
        }
    }
    Err(format!(
        "scope cgroup query UNPARSEABLE ({unit}): {stdout:?}"
    ))
}

/// Best-effort post-spawn placement check: a live child must sit in the owned
/// scope's cgroup. An already-exited child is accepted on the structural
/// proof alone — `spawn` succeeding means the `pre_exec` placement write
/// succeeded before `exec`, so containment held for the whole (short) life
/// of the round. A live child outside the scope fails closed.
#[cfg(unix)]
fn verify_placement(child: &mut std::process::Child, holder: &Holder) -> Result<(), String> {
    match child.try_wait() {
        Ok(None) => {
            let pid = child.id();
            let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
                .map_err(|e| format!("placement verify FAILED (read /proc/{pid}/cgroup): {e}"))?;
            if cgroup.contains(&holder.unit) {
                return Ok(());
            }
            // Possible pid race is impossible here: the child is alive, so
            // this /proc entry is its own — a mismatch is a real escape.
            Err(format!(
                "containment FAILED: live child {pid} is outside scope {}; \
                 refusing uncontained round",
                holder.unit
            ))
        }
        Ok(Some(_)) => Ok(()),
        Err(e) => Err(format!("containment FAILED: wait owned child ({e})")),
    }
}

/// Test-only fault seam: `AGENT_BUS_FAIL_REAPER_SPAWN=1` simulates holder
/// reaper thread-spawn failure after the runner started, exercising owned
/// child/scope cleanup. Production never sets this.
#[cfg(unix)]
fn reaper_spawn_fault() -> bool {
    matches!(std::env::var("AGENT_BUS_FAIL_REAPER_SPAWN"), Ok(v) if v == "1")
}

/// Cleanup after a failed holder-reaper start: stop the already-created owned
/// scope (kills the holder), then ensure the runner child is reaped. Returns
/// the reaper error plus scope-stop failure when both occur.
#[cfg(unix)]
fn cleanup_reaper_failure(
    mut child: std::process::Child,
    unit: &str,
    reaper_err: String,
) -> String {
    let scope_result = stop_owned_scope(unit);
    let _ = child.kill();
    let _ = child.wait();
    match scope_result {
        Ok(()) => reaper_err,
        Err(s) => format!("{reaper_err}; {s}"),
    }
}

/// Start a detached holder scope and verify it `active`. The holder workload
/// (`sleep`, long-lived) cannot exit during creation, so — unlike wrapping
/// the round workload directly — observing `active` has no fast-round race:
/// either the scope provably exists before the workload spawns, or this
/// returns `Err` and nothing spawns. The holder runner is reaped by a
/// detached thread; round-end scope `stop` kills the holder itself.
///
/// When `policy` is non-empty, its `-p` properties are passed to the same
/// `systemd-run` invocation (no second launcher) and verified against actual
/// cgroup files before returning. A refused/mismatched/unreadable policy
/// stops the holder and fails closed with the observation.
#[cfg(unix)]
fn start_holder_scope(unit: &str, policy: &ResourcePolicy) -> Result<Holder, SpawnFailure> {
    if !user_manager_available() {
        return Err(SpawnFailure::from(
            "containment UNAVAILABLE: systemd user manager is not running; \
             refusing uncontained round (needs Linux + systemd --user)"
                .to_string(),
        ));
    }
    let holder_bin = std::env::var("AGENT_BUS_HOLDER_BIN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| HOLDER_BIN.to_string());
    let mut cmd = Command::new(systemd_run_bin());
    let mut holder_argv: Vec<String> = vec![
        "--user".to_string(),
        "--scope".to_string(),
        "--unit".to_string(),
        unit.to_string(),
        "-p".to_string(),
        "Delegate=yes".to_string(),
        "-p".to_string(),
        format!("TimeoutStopSec={SCOPE_STOP_TIMEOUT_SECS}"),
    ];
    holder_argv.extend(resource_systemd_args(policy));
    holder_argv.push("--".to_string());
    holder_argv.push(holder_bin);
    holder_argv.push(HOLDER_SLEEP_SECS.to_string());
    cmd.args(&holder_argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `pre_exec` runs in the forked child before `exec`. `setsid`
    // isolates the holder runner in its own session so round group signals
    // never touch it (round-end scope `stop` still reaps it).
    {
        use std::os::unix::process::CommandExt as _;
        unsafe {
            cmd.pre_exec(|| {
                if setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let child = cmd
        .spawn()
        .map_err(|e| SpawnFailure::from(format!("scope holder spawn FAILED: {e}")))?;
    if reaper_spawn_fault() {
        let reaper_err =
            "scope reaper spawn FAILED: injected fault (AGENT_BUS_FAIL_REAPER_SPAWN=1)".to_string();
        return Err(SpawnFailure::from(cleanup_reaper_failure(
            child, unit, reaper_err,
        )));
    }
    // The foreground runner blocks for the holder's whole life: reap it off
    // the round path so it never becomes a zombie while rounds proceed. The
    // Child is handed to the reaper via a channel after the thread exists, so
    // a spawn failure still owns the Child for cleanup instead of leaking it.
    let (tx, rx) = std::sync::mpsc::channel::<std::process::Child>();
    if let Err(e) = std::thread::Builder::new()
        .name("agent-bus-scope-reaper".to_string())
        .spawn(move || {
            if let Ok(c) = rx.recv() {
                let _ = c.wait_with_output();
            }
        })
    {
        let reaper_err = format!("scope reaper spawn FAILED: {e}");
        return Err(SpawnFailure::from(cleanup_reaper_failure(
            child, unit, reaper_err,
        )));
    }
    if let Err(send_err) = tx.send(child) {
        let child = send_err.0;
        let reaper_err =
            "scope reaper spawn FAILED: reaper thread exited before receiving child".to_string();
        return Err(SpawnFailure::from(cleanup_reaper_failure(
            child, unit, reaper_err,
        )));
    }
    let deadline = Instant::now() + SCOPE_VERIFY_GRACE;
    loop {
        match scope_state(unit) {
            Ok((_, active)) if active == "active" => {
                match scope_cgroup_procs(unit) {
                    Ok(Some(cgroup_procs)) => {
                        let cgroup_base = cgroup_base_from_procs(&cgroup_procs);
                        if policy.is_empty() {
                            return Ok(Holder {
                                unit: unit.to_string(),
                                cgroup_procs,
                                resources_observed: None,
                            });
                        }
                        let (observation, verified) = verify_resources(policy, &cgroup_base);
                        match verified {
                            Ok(()) => {
                                return Ok(Holder {
                                    unit: unit.to_string(),
                                    cgroup_procs,
                                    resources_observed: Some(observation),
                                });
                            }
                            Err(msg) => {
                                // Refused/mismatched/unreadable policy: stop
                                // the holder so no sleeper leaks, preserve
                                // reaper cleanup, and fail closed before any
                                // workload spawns. Observation is retained
                                // for honest status.
                                let msg = match stop_owned_scope(unit) {
                                    Ok(()) => msg,
                                    Err(cleanup) => format!("{msg}; {cleanup}"),
                                };
                                return Err(SpawnFailure {
                                    msg,
                                    resources_observed: Some(observation),
                                });
                            }
                        }
                    }
                    // The holder is live but unusable without its cgroup
                    // path: stop it so no sleeper leaks before refusing.
                    Ok(None) => {
                        let _ = stop_owned_scope(unit);
                        return Err(SpawnFailure::from(format!(
                            "scope cgroup query UNPARSEABLE ({unit}): empty ControlGroup"
                        )));
                    }
                    Err(e) => {
                        let _ = stop_owned_scope(unit);
                        return Err(SpawnFailure::from(e));
                    }
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            let _ = stop_owned_scope(unit);
            return Err(SpawnFailure::from(format!(
                "containment FAILED: holder scope {unit} never active; \
                 round refused"
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Spawn the round inside a fresh owned user scope and verify containment is
/// really in effect. Returns the direct child (the `muse` process itself, a
/// session/group leader for the fast group-signal path) plus the scope unit
/// that owns every descendant and the verified resource observation.
///
/// Containment proof is structural, not observational: the workload is moved
/// into the scope's cgroup by a raw-syscall write in `pre_exec`, before
/// `exec`. `spawn` succeeding therefore proves the round never ran outside
/// the scope — even an instantly-exiting workload was contained for its whole
/// life. (Polling a wrapped workload's unit for `active` cannot prove this:
/// a fast round's unit may be created, run, and garbage-collected between two
/// polls.) A live child found outside the scope fails closed, as does a
/// missing user manager, an unstartable holder, or a refused/unverified
/// resource policy (holder stopped, nothing spawns).
#[cfg(unix)]
fn spawn_scoped(
    cfg: &SchedulerConfig,
    out_log: std::fs::File,
    err_log: std::fs::File,
    report: Option<&crate::task_report::ReportContext>,
) -> Result<ScopedSpawn, SpawnFailure> {
    let unit = new_scope_unit(&cfg.agent);
    let holder = start_holder_scope(&unit, &cfg.resource_policy)?;
    let procs_path = std::ffi::CString::new(holder.cgroup_procs.clone()).map_err(|e| {
        let msg = format!("containment FAILED: bad cgroup path ({e})");
        let _ = stop_owned_scope(&holder.unit);
        SpawnFailure {
            msg,
            resources_observed: holder.resources_observed.clone(),
        }
    })?;
    let mut cmd = Command::new(&cfg.muse_bin);
    cmd.args(muse_argv(cfg))
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_log))
        .stderr(Stdio::from(err_log));
    // Worker-report identity: scrub any inherited values first so a
    // disabled, no-status, or nested round never sees stale identity, then
    // inject exactly the current enabled context. Native path bytes are
    // passed through; no tokens.
    cmd.env_remove(crate::task_report::ENV_REPORT_PATH);
    cmd.env_remove(crate::task_report::ENV_RUN_ID);
    cmd.env_remove(crate::task_report::ENV_TASK);
    cmd.env_remove(crate::task_report::ENV_AGENT);
    if let Some(ctx) = report {
        cmd.env(crate::task_report::ENV_REPORT_PATH, &ctx.path);
        cmd.env(crate::task_report::ENV_RUN_ID, &ctx.run_id);
        cmd.env(crate::task_report::ENV_TASK, &ctx.task);
        cmd.env(crate::task_report::ENV_AGENT, &ctx.agent);
    }
    // SAFETY: `pre_exec` runs in the forked child before `exec`, single-threaded
    // from this process's view except for detached scope-reaper threads that
    // block in `waitpid` holding no allocator locks. Only raw syscalls and a
    // stack buffer are used here — no allocation, no locking — so the write
    // cannot deadlock. `setsid` keeps the existing group-signal fast path;
    // the `cgroup.procs` write moves the child into the owned scope before it
    // can fork, so even its first descendant inherits containment. Any failure
    // aborts `spawn`: the workload never runs uncontained.
    {
        use std::os::unix::process::CommandExt as _;
        unsafe {
            cmd.pre_exec(move || {
                if setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // `open` flag 1 == O_WRONLY.
                let fd = open(procs_path.as_ptr() as *const u8, 1);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut buf = [0u8; 32];
                let n = pid_line(getpid(), &mut buf);
                let mut done = 0usize;
                while done < n {
                    let r = write(fd, buf[done..].as_ptr(), n - done);
                    if r <= 0 {
                        close(fd);
                        return Err(std::io::Error::last_os_error());
                    }
                    done += r as usize;
                }
                close(fd);
                Ok(())
            });
        }
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        // The holder is already live: stop its scope so the sleeper does not
        // leak behind a refused round.
        Err(e) => {
            let msg = format!("muse spawn FAILED ({}): {e}", cfg.muse_bin);
            let msg = match stop_owned_scope(&holder.unit) {
                Ok(()) => msg,
                Err(s) => format!("{msg}; {s}"),
            };
            return Err(SpawnFailure {
                msg,
                resources_observed: holder.resources_observed.clone(),
            });
        }
    };
    // Structural proof holds by construction, but a live child outside the
    // scope is a fail-closed escape: check while it can still be checked.
    if let Err(e) = verify_placement(&mut child, &holder) {
        let pgid = child.id() as i32;
        // SAFETY: `pgid` is our own freshly spawned session leader.
        unsafe {
            killpg(pgid, SIGTERM);
            killpg(pgid, SIGKILL);
        }
        let _ = child.wait();
        let _ = stop_owned_scope(&holder.unit);
        return Err(SpawnFailure {
            msg: e,
            resources_observed: holder.resources_observed.clone(),
        });
    }
    Ok(ScopedSpawn {
        child,
        scope_unit: holder.unit,
        resources_observed: holder.resources_observed,
    })
}

/// Scope-stop dispatcher: on Unix it drains the round's owned cgroup; elsewhere
/// rounds never start (see [`run_round`]), so this stays an honest `Err`.
#[cfg(unix)]
fn stop_scope_for(unit: &str) -> Result<status::ScopeCleanup, String> {
    stop_owned_scope_observed(unit)
}
#[cfg(not(unix))]
fn stop_scope_for(_unit: &str) -> Result<status::ScopeCleanup, String> {
    Err("containment UNAVAILABLE: rounds require Linux + systemd --user".into())
}

/// Structured wait outcome for status reporting (internal).
struct WaitResult {
    code: i32,
    timed_out: bool,
    cancelled: bool,
    scope_cleanup: status::ScopeCleanup,
}

struct WaitError {
    msg: String,
    cleanup_certain: bool,
    scope_cleanup: Option<status::ScopeCleanup>,
}

/// Both cleanup layers have already run. Preserve a scope proof even if the
/// separate process-group operation failed; overall cleanup stays uncertain.
fn combine_cleanup_observed(
    group: Result<i32, String>,
    scope: Result<status::ScopeCleanup, String>,
) -> Result<status::ScopeCleanup, WaitError> {
    match (group, scope) {
        (Ok(_), Ok(observation)) => Ok(observation),
        (Err(msg), Ok(observation)) => Err(WaitError {
            msg,
            cleanup_certain: false,
            scope_cleanup: Some(observation),
        }),
        (group, Err(scope)) => Err(WaitError {
            msg: combine_cleanup(group, Err(scope)).unwrap_err(),
            cleanup_certain: false,
            scope_cleanup: None,
        }),
    }
}

/// Periodic Active refresh context (status path only). `maybe_send` is cheap
/// (one `Instant` check plus one bounded regular-file read when task reports
/// are enabled; the byte cap bounds allocation, not a wall-clock deadline)
/// and `reporter.update` queues without blocking the loop.
struct ActiveStatus<'a> {
    reporter: &'a status::StatusReporter,
    key: String,
    task: String,
    run_id: String,
    agent: String,
    scheduler_pid: u32,
    log_path: String,
    started_ts: f64,
    start_instant: Instant,
    child_pid: u32,
    scope_unit: String,
    resources_requested: Option<ResourcePolicy>,
    resources_observed: Option<status::ResourceObservation>,
    report: Option<crate::task_report::ReportContext>,
    report_unavailable: bool,
    interval: Duration,
    last_sent: Instant,
    ttl_ms: u64,
}

impl<'a> ActiveStatus<'a> {
    fn maybe_send(&mut self) {
        if self.last_sent.elapsed() < self.interval {
            return;
        }
        let updated = status::now_f64();
        let rec = status::StatusRecord {
            task: self.task.clone(),
            run_id: self.run_id.clone(),
            agent: self.agent.clone(),
            scheduler_pid: self.scheduler_pid,
            child_pid: Some(self.child_pid),
            scope_unit: Some(self.scope_unit.clone()),
            phase: status::Phase::Active,
            started_ts: self.started_ts,
            updated_ts: updated,
            elapsed_s: self.start_instant.elapsed().as_secs_f64(),
            exit_code: None,
            timed_out: false,
            cancelled: false,
            outcome: None,
            cleanup: status::Cleanup::Pending,
            log_path: self.log_path.clone(),
            resources_requested: self.resources_requested.clone(),
            resources_observed: self.resources_observed.clone(),
        };
        // Task evidence is read fresh from the owned per-run file: bounded,
        // regular-file only. Missing/invalid stays unknown; an enabled but
        // uncreatable context stays unavailable.
        let task = match &self.report {
            Some(ctx) => ctx.read(),
            None if self.report_unavailable => crate::task_report::TaskCompletion::unknown(
                crate::task_report::REASON_UNAVAILABLE,
            ),
            None => crate::task_report::TaskCompletion::unknown(
                crate::task_report::REASON_MISSING,
            ),
        };
        // Queued update: dropped on reporter failure, never a round failure.
        // The task read above is synchronous bounded (allocation-capped,
        // not deadline-proven); only this queueing is non-blocking.
        let _ = self
            .reporter
            .update(&self.key, rec.to_json_with_task(&task), self.ttl_ms);
        self.last_sent = Instant::now();
    }
}

/// Opt-in run-status configuration. `SchedulerConfig` is unchanged so default
/// offline behavior and existing callers are untouched; pass this plus a
/// transport to [`run_round_with_status`].
#[derive(Debug, Clone)]
pub struct RunStatusConfig {
    /// Coordinator task name (`--task`, required with `--bus-status`).
    pub task: String,
    /// Interval between Active refreshes.
    pub interval: Duration,
    /// TTL for Starting/Active records.
    pub active_ttl_ms: u64,
    /// TTL for the Terminal record.
    pub terminal_ttl_ms: u64,
    /// Enable explicit worker task-completion reports (`--task-report`).
    /// False by default; when true the scheduler creates a unique per-run
    /// report directory, passes its path plus expected identity to the child,
    /// and includes the validated report separately in status records.
    pub task_report: bool,
}

impl RunStatusConfig {
    pub fn new(task: &str) -> Self {
        Self {
            task: task.to_string(),
            interval: status::DEFAULT_INTERVAL,
            active_ttl_ms: status::ACTIVE_TTL_MS,
            terminal_ttl_ms: status::TERMINAL_TTL_MS,
            task_report: false,
        }
    }
}

fn wait_with_timeout_inner(
    child: &mut std::process::Child,
    scope_unit: &str,
    timeout: Duration,
    mut active: Option<&mut ActiveStatus>,
) -> Result<WaitResult, WaitError> {
    let start = Instant::now();
    loop {
        if let Some(code) = shutdown_exit_code() {
            let group = kill_owned_group(child);
            let scope = stop_scope_for(scope_unit);
            let scope_cleanup = combine_cleanup_observed(group, scope)?;
            return Ok(WaitResult {
                code,
                timed_out: false,
                cancelled: true,
                scope_cleanup,
            });
        }
        if let Some(a) = active.as_deref_mut() {
            a.maybe_send();
        }
        match child.try_wait() {
            Ok(Some(st)) => {
                // A finished runner does not prove its background descendants
                // finished — especially ones in their own sessions. Stop the
                // owned scope before reusing this scheduler's single-round
                // slot, and fail closed when the cgroup does not drain.
                let code = st.code().unwrap_or(1);
                let scope_cleanup = stop_scope_for(scope_unit).map_err(|msg| WaitError {
                    msg,
                    cleanup_certain: false,
                    scope_cleanup: None,
                })?;
                return Ok(WaitResult {
                    code,
                    timed_out: false,
                    cancelled: shutdown_exit_code().is_some(),
                    scope_cleanup,
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // Own the cleanup: signal the group, reap, stop the owned
                    // scope and verify empty — fail closed on uncertainty so
                    // no descendant overlaps the next round's single-child
                    // slot. Both layers always run; both errors are reported.
                    let group = kill_owned_group(child);
                    let scope = stop_scope_for(scope_unit);
                    let scope_cleanup = combine_cleanup_observed(group, scope)?;
                    return Ok(WaitResult {
                        code: TIMEOUT_EXIT_CODE,
                        timed_out: true,
                        cancelled: shutdown_exit_code().is_some(),
                        scope_cleanup,
                    });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let group = kill_owned_group(child);
                let scope = stop_scope_for(scope_unit);
                match combine_cleanup_observed(group, scope) {
                    Ok(scope_cleanup) => {
                        return Err(WaitError {
                            msg: format!(
                                "child wait FAILED ({e}); owned group signalled, \
                                 scope stopped, child reaped"
                            ),
                            cleanup_certain: true,
                            scope_cleanup: Some(scope_cleanup),
                        });
                    }
                    Err(cleanup) => {
                        return Err(WaitError {
                            msg: format!("child wait FAILED ({e}); {}", cleanup.msg),
                            cleanup_certain: false,
                            scope_cleanup: cleanup.scope_cleanup,
                        });
                    }
                }
            }
        }
    }
}

/// Wait for an already-spawned scoped child up to `timeout`; on expiry
/// terminate the whole owned process group, then stop the owned scope and
/// verify every descendant — including setsid-detached and orphaned ones —
/// exited before returning.
///
/// Returns `Ok((exit_code, timed_out))`. A `try_wait` infrastructure error
/// never abandons a possibly live child: the group is signalled, the scope is
/// stopped, and the child reaped first; then the error is returned so the
/// caller logs honestly instead of overlapping the next round.
fn wait_with_timeout(
    child: &mut std::process::Child,
    scope_unit: &str,
    timeout: Duration,
) -> Result<(i32, bool), String> {
    match wait_with_timeout_inner(child, scope_unit, timeout, None) {
        Ok(r) => Ok((r.code, r.timed_out)),
        Err(e) => Err(e.msg),
    }
}

/// Run exactly one round: render the template to [`SchedulerConfig::prompt_out`],
/// spawn one `muse exec` child with output appended to the log, enforce the
/// round timeout, log the exit line, and return the exit code.
///
/// A failed prompt render logs `prompt generation FAILED ...` plus
/// `=== exit 3 ===` and returns [`PROMPT_FAILURE_EXIT_CODE`] without
/// spawning anything (legacy behavior: skip the round, keep looping).
/// Log-file IO, scope-runner spawn, containment, and cleanup failures are
/// returned as `Err` — including when the systemd user manager is unavailable,
/// so rounds never run uncontained.
pub fn run_round(cfg: &SchedulerConfig) -> Result<i32, String> {
    cfg.resource_policy.validate()?;
    if let Some(code) = shutdown_exit_code() {
        return Ok(code);
    }
    append_log(&cfg.log_path, &format!("=== round {} ===", utc_stamp()))?;
    let rendered = match render_file(&cfg.template_path, &cfg.agent, &cfg.role) {
        Ok(r) => r,
        Err(e) => {
            append_log(&cfg.log_path, &e)?;
            append_log(
                &cfg.log_path,
                &format!("=== exit {PROMPT_FAILURE_EXIT_CODE} ==="),
            )?;
            return Ok(PROMPT_FAILURE_EXIT_CODE);
        }
    };
    std::fs::write(&cfg.prompt_out, &rendered)
        .map_err(|e| format!("prompt write FAILED ({}): {e}", cfg.prompt_out))?;
    if rendered.trim().is_empty() {
        // `render_prompt` already rejects this; belt-and-braces in case the
        // helper ever changes without updating this call site.
        append_log(&cfg.log_path, "prompt generation FAILED (empty)")?;
        append_log(
            &cfg.log_path,
            &format!("=== exit {PROMPT_FAILURE_EXIT_CODE} ==="),
        )?;
        return Ok(PROMPT_FAILURE_EXIT_CODE);
    }

    let out_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.log_path)
        .map_err(|e| format!("log append FAILED ({}): {e}", cfg.log_path))?;
    let err_log = out_log
        .try_clone()
        .map_err(|e| format!("log clone FAILED ({}): {e}", cfg.log_path))?;
    // The round runs inside a fresh owned user scope (Unix): the workload —
    // `muse` plus every descendant, even ones in their own sessions — lives
    // in one cgroup that timeout, normal-exit, and cancellation paths stop
    // and verify empty. Unattended rounds never inherit the scheduler's
    // stdin; a child expecting terminal input would otherwise block.
    #[cfg(unix)]
    let (mut child, scope_unit) = match spawn_scoped(cfg, out_log, err_log, None) {
        Ok(v) => (v.child, v.scope_unit),
        Err(f) => {
            append_log(&cfg.log_path, &f.msg)?;
            append_log(&cfg.log_path, "=== exit CLEANUP-FAILED ===")?;
            return Err(f.msg);
        }
    };
    #[cfg(not(unix))]
    {
        let _ = (out_log, err_log);
        return Err("containment UNAVAILABLE: rounds require Linux + systemd --user".to_string());
    }
    let (code, timed_out) = match wait_with_timeout(
        &mut child,
        &scope_unit,
        Duration::from_secs(cfg.round_timeout_secs),
    ) {
        Ok(v) => v,
        Err(e) => {
            // Fail closed: descendants may still be live, so report the
            // cleanup failure instead of an exit code the next round could
            // silently overlap.
            append_log(&cfg.log_path, &e)?;
            append_log(&cfg.log_path, "=== exit CLEANUP-FAILED ===")?;
            return Err(e);
        }
    };
    if timed_out {
        append_log(&cfg.log_path, "round TIMEOUT: child killed")?;
    }
    if shutdown_exit_code().is_some() {
        append_log(
            &cfg.log_path,
            "round CANCELLED: owned process group cleaned",
        )?;
    }
    append_log(&cfg.log_path, &format!("=== exit {code} ==="))?;
    Ok(code)
}

/// Map an optional report context to its current task value. `Some` reads
/// the owned file; `None` with `unavailable` means the enabled context could
/// not be created, otherwise the run is report-disabled with no file.
fn task_for_context(
    ctx: &Option<crate::task_report::ReportContext>,
    unavailable: bool,
) -> crate::task_report::TaskCompletion {
    match ctx {
        Some(c) => c.read(),
        None if unavailable => {
            crate::task_report::TaskCompletion::unknown(crate::task_report::REASON_UNAVAILABLE)
        }
        None => crate::task_report::TaskCompletion::unknown(crate::task_report::REASON_MISSING),
    }
}

/// Run one round with opt-in bus status reporting. Same spawn, timeout,
/// signal, and owned-group + owned-scope cleanup as [`run_round`]; bus IO is
/// observability only (queued sends, sanitized logs, never a round failure)
/// with a bounded joined reporter shutdown on every path.
///
/// Prompt failures return `Ok(3)` without a status record (no run started).
/// Spawn failures report a terminal `infra_error` with `Uncertain` cleanup.
/// Terminal outcome and cleanup certainty always reflect the real
/// child/cleanup result, never reporter success or worker assertions.
///
/// When [`RunStatusConfig::task_report`] is true, a unique per-run report
/// directory is created, its path plus expected identity is passed to the
/// child, and the validated worker file is included separately as
/// `task_completion` in starting/active/terminal records (unknown when
/// missing, unusable, or unavailable). The file is left in place after the
/// round.
pub fn run_round_with_status(
    cfg: &SchedulerConfig,
    status_cfg: &RunStatusConfig,
    transport: Box<dyn status::StatusTransport>,
) -> Result<i32, String> {
    cfg.resource_policy.validate()?;
    if status_cfg.task.trim().is_empty() || cfg.agent.trim().is_empty() {
        return Err("bus-status requires --task and non-empty --agent".to_string());
    }
    if let Some(code) = shutdown_exit_code() {
        return Ok(code);
    }
    append_log(&cfg.log_path, &format!("=== round {} ===", utc_stamp()))?;
    let rendered = match render_file(&cfg.template_path, &cfg.agent, &cfg.role) {
        Ok(r) => r,
        Err(e) => {
            append_log(&cfg.log_path, &e)?;
            append_log(
                &cfg.log_path,
                &format!("=== exit {PROMPT_FAILURE_EXIT_CODE} ==="),
            )?;
            return Ok(PROMPT_FAILURE_EXIT_CODE);
        }
    };
    std::fs::write(&cfg.prompt_out, &rendered)
        .map_err(|e| format!("prompt write FAILED ({}): {e}", cfg.prompt_out))?;
    if rendered.trim().is_empty() {
        append_log(&cfg.log_path, "prompt generation FAILED (empty)")?;
        append_log(
            &cfg.log_path,
            &format!("=== exit {PROMPT_FAILURE_EXIT_CODE} ==="),
        )?;
        return Ok(PROMPT_FAILURE_EXIT_CODE);
    }

    let run_id = status::new_run_id();
    let key = status::status_key(&status_cfg.task, &cfg.agent, &run_id)?;
    let started_ts = status::now_f64();
    let start_instant = Instant::now();
    let scheduler_pid = std::process::id();
    let reporter = status::StatusReporter::new(transport);
    let resources_requested =
        (!cfg.resource_policy.is_empty()).then(|| cfg.resource_policy.clone());
    // Opt-in worker-report location: unique per run, never reused. Creation
    // failure keeps a distinct unavailable reason (not missing), never fails
    // the round; process outcome stays independent.
    let (report_ctx, report_unavailable): (
        Option<crate::task_report::ReportContext>,
        bool,
    ) = if status_cfg.task_report {
        match crate::task_report::create_report_context(&status_cfg.task, &cfg.agent, &run_id) {
            Ok(ctx) => (Some(ctx), false),
            Err(e) => {
                let _ = append_log(&cfg.log_path, &format!("task-report unavailable: {e}"));
                (None, true)
            }
        }
    } else {
        (None, false)
    };
    let starting_task = task_for_context(&report_ctx, report_unavailable);
    // Starting refresh (queued update; task read is synchronous bounded,
    // not deadline-proven); failure is observability loss only.
    {
        let rec = status::StatusRecord {
            task: status_cfg.task.clone(),
            run_id: run_id.clone(),
            agent: cfg.agent.clone(),
            scheduler_pid,
            child_pid: None,
            scope_unit: None,
            phase: status::Phase::Starting,
            started_ts,
            updated_ts: started_ts,
            elapsed_s: 0.0,
            exit_code: None,
            timed_out: false,
            cancelled: false,
            outcome: None,
            cleanup: status::Cleanup::Pending,
            log_path: cfg.log_path.clone(),
            resources_requested: resources_requested.clone(),
            resources_observed: None,
        };
        let _ = reporter.update(
            &key,
            rec.to_json_with_task(&starting_task),
            status_cfg.active_ttl_ms,
        );
    }

    let out_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.log_path)
        .map_err(|e| format!("log append FAILED ({}): {e}", cfg.log_path))?;
    let err_log = out_log
        .try_clone()
        .map_err(|e| format!("log clone FAILED ({}): {e}", cfg.log_path))?;
    #[cfg(unix)]
    let (mut child, scope_unit, resources_observed) = match spawn_scoped(
        cfg,
        out_log,
        err_log,
        report_ctx.as_ref(),
    ) {
        Ok(v) => (v.child, v.scope_unit, v.resources_observed),
        Err(f) => {
            let term = status::StatusRecord {
                task: status_cfg.task.clone(),
                run_id: run_id.clone(),
                agent: cfg.agent.clone(),
                scheduler_pid,
                child_pid: None,
                scope_unit: None,
                phase: status::Phase::Terminal,
                started_ts,
                updated_ts: status::now_f64(),
                elapsed_s: start_instant.elapsed().as_secs_f64(),
                exit_code: None,
                timed_out: false,
                cancelled: shutdown_exit_code().is_some(),
                outcome: Some(status::Outcome::InfraError),
                cleanup: status::Cleanup::Uncertain,
                log_path: cfg.log_path.clone(),
                resources_requested: resources_requested.clone(),
                resources_observed: f.resources_observed.clone(),
            };
            // Child never ran: no worker report expected, task stays unknown
            // (unavailable when the enabled context failed, else missing).
            let task = task_for_context(&report_ctx, report_unavailable);
            let outcome = reporter.shutdown(Some((
                key.clone(),
                term.to_json_with_task(&task),
                status_cfg.terminal_ttl_ms,
            )));
            log_reporter_outcome(&cfg.log_path, &outcome);
            append_log(&cfg.log_path, &f.msg)?;
            append_log(&cfg.log_path, "=== exit CLEANUP-FAILED ===")?;
            return Err(f.msg);
        }
    };
    #[cfg(not(unix))]
    {
        let _ = (out_log, err_log);
        let observed = resources_requested
            .as_ref()
            .map(|_| status::ResourceObservation {
                cpu_quota_percent: None,
                memory_max_bytes: None,
                memory_swap_max_bytes: None,
                verification: status::ResourceVerification::Unavailable,
            });
        let term = status::StatusRecord {
            task: status_cfg.task.clone(),
            run_id: run_id.clone(),
            agent: cfg.agent.clone(),
            scheduler_pid,
            child_pid: None,
            scope_unit: None,
            phase: status::Phase::Terminal,
            started_ts,
            updated_ts: status::now_f64(),
            elapsed_s: start_instant.elapsed().as_secs_f64(),
            exit_code: None,
            timed_out: false,
            cancelled: false,
            outcome: Some(status::Outcome::InfraError),
            cleanup: status::Cleanup::Uncertain,
            log_path: cfg.log_path.clone(),
            resources_requested: resources_requested.clone(),
            resources_observed: observed,
        };
        let task = task_for_context(&report_ctx, report_unavailable);
        let outcome = reporter.shutdown(Some((
            key.clone(),
            term.to_json_with_task(&task),
            status_cfg.terminal_ttl_ms,
        )));
        log_reporter_outcome(&cfg.log_path, &outcome);
        return Err("containment UNAVAILABLE: rounds require Linux + systemd --user".to_string());
    };
    // First Active (child + scope now known), then periodic refreshes in wait.
    {
        let rec = status::StatusRecord {
            task: status_cfg.task.clone(),
            run_id: run_id.clone(),
            agent: cfg.agent.clone(),
            scheduler_pid,
            child_pid: Some(child.id()),
            scope_unit: Some(scope_unit.clone()),
            phase: status::Phase::Active,
            started_ts,
            updated_ts: status::now_f64(),
            elapsed_s: start_instant.elapsed().as_secs_f64(),
            exit_code: None,
            timed_out: false,
            cancelled: false,
            outcome: None,
            cleanup: status::Cleanup::Pending,
            log_path: cfg.log_path.clone(),
            resources_requested: resources_requested.clone(),
            resources_observed: resources_observed.clone(),
        };
        let task = task_for_context(&report_ctx, report_unavailable);
        let _ = reporter.update(
            &key,
            rec.to_json_with_task(&task),
            status_cfg.active_ttl_ms,
        );
    }
    let mut active = ActiveStatus {
        reporter: &reporter,
        key: key.clone(),
        task: status_cfg.task.clone(),
        run_id: run_id.clone(),
        agent: cfg.agent.clone(),
        scheduler_pid,
        log_path: cfg.log_path.clone(),
        started_ts,
        start_instant,
        child_pid: child.id(),
        scope_unit: scope_unit.clone(),
        resources_requested: resources_requested.clone(),
        resources_observed: resources_observed.clone(),
        report: report_ctx.clone(),
        report_unavailable,
        interval: status_cfg.interval,
        last_sent: Instant::now(),
        ttl_ms: status_cfg.active_ttl_ms,
    };
    let waited = wait_with_timeout_inner(
        &mut child,
        &scope_unit,
        Duration::from_secs(cfg.round_timeout_secs),
        Some(&mut active),
    );
    // Terminal record reflects the real wait/cleanup result. Reporter
    // shutdown is bounded and joined before any log `?` can return early.
    let (term_rec, scope_cleanup) = match &waited {
        Ok(r) => {
            let outcome = if r.cancelled {
                status::Outcome::Cancelled
            } else if r.timed_out {
                status::Outcome::Timeout
            } else if r.code == 0 {
                status::Outcome::Success
            } else {
                status::Outcome::Failure
            };
            (
                status::StatusRecord {
                    task: status_cfg.task.clone(),
                    run_id: run_id.clone(),
                    agent: cfg.agent.clone(),
                    scheduler_pid,
                    child_pid: Some(active.child_pid),
                    scope_unit: Some(scope_unit.clone()),
                    phase: status::Phase::Terminal,
                    started_ts,
                    updated_ts: status::now_f64(),
                    elapsed_s: start_instant.elapsed().as_secs_f64(),
                    exit_code: Some(r.code),
                    timed_out: r.timed_out,
                    cancelled: r.cancelled,
                    outcome: Some(outcome),
                    cleanup: status::Cleanup::Clean,
                    log_path: cfg.log_path.clone(),
                    resources_requested: resources_requested.clone(),
                    resources_observed: resources_observed.clone(),
                },
                Some(&r.scope_cleanup),
            )
        }
        Err(e) => {
            let outcome = if e.msg.contains("CLEANUP FAILED") {
                status::Outcome::CleanupFailed
            } else {
                status::Outcome::InfraError
            };
            (
                status::StatusRecord {
                    task: status_cfg.task.clone(),
                    run_id: run_id.clone(),
                    agent: cfg.agent.clone(),
                    scheduler_pid,
                    child_pid: Some(active.child_pid),
                    scope_unit: Some(scope_unit.clone()),
                    phase: status::Phase::Terminal,
                    started_ts,
                    updated_ts: status::now_f64(),
                    elapsed_s: start_instant.elapsed().as_secs_f64(),
                    exit_code: None,
                    timed_out: false,
                    cancelled: shutdown_exit_code().is_some(),
                    outcome: Some(outcome),
                    cleanup: if e.cleanup_certain {
                        status::Cleanup::Clean
                    } else {
                        status::Cleanup::Uncertain
                    },
                    log_path: cfg.log_path.clone(),
                    resources_requested: resources_requested.clone(),
                    resources_observed: resources_observed.clone(),
                },
                e.scope_cleanup.as_ref(),
            )
        }
    };
    // Final worker evidence, read once after wait/cleanup. Process outcome
    // and cleanup above stay independent even when the worker claimed
    // complete before a failure. The per-run file is left for capture.
    let final_task = task_for_context(&report_ctx, report_unavailable);
    let rep_outcome = reporter.shutdown(Some((
        key.clone(),
        term_rec.to_json_with_scope_and_task(scope_cleanup, &final_task),
        status_cfg.terminal_ttl_ms,
    )));
    log_reporter_outcome(&cfg.log_path, &rep_outcome);
    match waited {
        Ok(r) => {
            if r.timed_out {
                append_log(&cfg.log_path, "round TIMEOUT: child killed")?;
            }
            if r.cancelled {
                append_log(
                    &cfg.log_path,
                    "round CANCELLED: owned process group cleaned",
                )?;
            }
            append_log(&cfg.log_path, &format!("=== exit {} ===", r.code))?;
            Ok(r.code)
        }
        Err(e) => {
            append_log(&cfg.log_path, &e.msg)?;
            append_log(&cfg.log_path, "=== exit CLEANUP-FAILED ===")?;
            Err(e.msg)
        }
    }
}

/// Best-effort degraded-reporting log line (sanitized, never fails the round).
fn log_reporter_outcome(log_path: &str, outcome: &status::ReporterOutcome) {
    let degraded = outcome.active_failed > 0 || outcome.terminal_ok == Some(false);
    if !degraded {
        return;
    }
    let detail = outcome.last_error.as_deref().unwrap_or("unknown");
    let _ = append_log(
        log_path,
        &format!(
            "status reporting degraded: active_ok={} active_failed={} terminal_ok={:?} last_error={}",
            outcome.active_ok, outcome.active_failed, outcome.terminal_ok, detail
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_name_and_role() {
        let out = render_prompt(
            "hello AGENT_NAME, you are AGENT_ROLE.",
            "muse-builder",
            "bus",
        )
        .unwrap();
        assert_eq!(out, "hello muse-builder, you are bus.");
    }

    #[test]
    fn empty_template_is_an_error_not_an_empty_round() {
        assert!(render_prompt("", "n", "r").is_err());
        assert!(render_prompt("   ", "n", "r").is_err());
    }

    #[test]
    fn argv_default_omits_reasoning_effort() {
        let cfg = SchedulerConfig::new("t", "p", "/ws", "n", "r", "l");
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
                "/ws",
                "--max-model-steps",
                "50",
                "--prompt-file",
                "p",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );
        assert!(
            !argv.iter().any(|a| a == "--reasoning-effort"),
            "default argv must not force a model config: {argv:?}"
        );
    }

    #[test]
    fn argv_forwards_explicit_reasoning_effort_unchanged() {
        for effort in ["low", "medium", "high"] {
            let mut cfg = SchedulerConfig::new("t", "p", "/ws", "n", "r", "l");
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
    fn argv_preserves_sota_isolation_flag() {
        let mut cfg = SchedulerConfig::new("t", "p", "/ws", "n", "r", "l");
        cfg.reasoning_effort = Some("medium".into());
        cfg.subagent_worktree_isolation = true;
        let argv = muse_argv(&cfg);
        assert!(argv.contains(&"--subagent-worktree-isolation".to_string()));
        assert!(argv.contains(&"medium".to_string()));
    }

    #[test]
    fn missing_template_is_an_error() {
        let r = render_file("/nonexistent-dir-xyz/no-template.md", "n", "r");
        assert!(r.is_err());
    }

    #[test]
    fn combine_cleanup_reports_both_layers() {
        assert!(combine_cleanup(Ok(124), Ok(())).is_ok());
        assert_eq!(
            combine_cleanup(Ok(124), Err("scope bad".to_string())),
            Err("scope bad".to_string())
        );
        assert_eq!(
            combine_cleanup(Err("group bad".to_string()), Ok(())),
            Err("group bad".to_string())
        );
        assert_eq!(
            combine_cleanup(Err("group bad".to_string()), Err("scope bad".to_string())),
            Err("group bad; scope bad".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn scope_result_is_optional_and_independent_of_required_state() {
        let state = parse_scope_state(
            "owned.scope",
            "Result=timeout\nActiveState=failed\nLoadState=loaded\n",
        )
        .unwrap();
        assert_eq!(state.manager_result.as_deref(), Some("timeout"));
        assert_eq!(state.load_state, "loaded");
        assert_eq!(state.active_state, "failed");
        for result in ["", "Result=\n"] {
            let state = parse_scope_state(
                "owned.scope",
                &format!("LoadState=not-found\nActiveState=inactive\n{result}"),
            )
            .unwrap();
            assert_eq!(state.manager_result, None);
        }
        assert!(parse_scope_state("owned.scope", "Result=success\n").is_err());
    }

    #[test]
    fn scope_proof_does_not_hide_a_group_cleanup_failure() {
        let observation = status::ScopeCleanup {
            stop_requested: true,
            stop_exit_code: Some(0),
            load_state: "loaded".into(),
            active_state: "failed".into(),
            manager_result: Some("timeout".into()),
            empty_verified: true,
        };
        let error =
            match combine_cleanup_observed(Err("group failed".into()), Ok(observation.clone())) {
                Err(error) => error,
                Ok(_) => panic!("scope emptiness must not hide group cleanup failure"),
            };
        assert!(!error.cleanup_certain);
        assert_eq!(error.msg, "group failed");
        assert_eq!(error.scope_cleanup, Some(observation));
        let error = match combine_cleanup_observed(
            Err("group failed".into()),
            Err("scope failed".into()),
        ) {
            Err(error) => error,
            Ok(_) => panic!("cleanup errors must fail closed"),
        };
        assert!(!error.cleanup_certain);
        assert_eq!(error.msg, "group failed; scope failed");
        assert_eq!(error.scope_cleanup, None);
    }

    #[cfg(unix)]
    #[test]
    fn transitional_scope_states_are_never_empty() {
        for active in [
            "active",
            "activating",
            "deactivating",
            "reloading",
            "maintenance",
            "unknown-state",
            "",
        ] {
            assert_eq!(
                scope_empty_from_state("loaded", active),
                Some(false),
                "transitional/active {active:?} must not prove emptiness"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn terminal_states_need_cgroup_proof_and_gone_is_empty() {
        assert_eq!(scope_empty_from_state("not-found", "inactive"), Some(true));
        assert_eq!(scope_empty_from_state("not-found", "active"), Some(true));
        assert_eq!(scope_empty_from_state("loaded", "inactive"), None);
        assert_eq!(scope_empty_from_state("loaded", "failed"), None);
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_procs_empty_check_handles_missing_and_pids() {
        let base = std::env::temp_dir().join(format!(
            "agent-bus-cgroup-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).unwrap();
        let empty = base.join("empty.procs");
        let pids = base.join("busy.procs");
        let missing = base.join("missing.procs");
        std::fs::write(&empty, "").unwrap();
        std::fs::write(&pids, "123\n456\n").unwrap();
        assert_eq!(
            cgroup_procs_is_empty(empty.to_str().unwrap()).unwrap(),
            true
        );
        assert_eq!(
            cgroup_procs_is_empty(pids.to_str().unwrap()).unwrap(),
            false
        );
        assert_eq!(
            cgroup_procs_is_empty(missing.to_str().unwrap()).unwrap(),
            true
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resource_policy_omitted_defaults_backward_compatible() {
        let policy = ResourcePolicy::default();
        assert!(policy.is_empty());
        assert_eq!(policy.cpu_quota_percent, None);
        assert_eq!(policy.memory_max_bytes, None);
        assert_eq!(policy.memory_swap_max_bytes, None);
        assert!(resource_systemd_args(&policy).is_empty());
        let cfg = SchedulerConfig::new("t", "p", "/ws", "n", "r", "l");
        assert!(cfg.resource_policy.is_empty());
        assert_eq!(cfg.reasoning_effort, None);
    }

    #[test]
    fn resource_policy_all_fields_and_zero_swap() {
        let policy = ResourcePolicy {
            cpu_quota_percent: Some(100),
            memory_max_bytes: Some(4 * 1024 * 1024 * 1024),
            memory_swap_max_bytes: Some(0),
        };
        assert!(!policy.is_empty());
        assert_eq!(policy.memory_swap_max_bytes, Some(0));
        let argv = resource_systemd_args(&policy);
        assert_eq!(
            argv,
            vec![
                "-p",
                "CPUQuota=100%",
                "-p",
                "MemoryMax=4294967296",
                "-p",
                "MemorySwapMax=0",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );
        for entry in &argv {
            assert!(!entry.contains(' '));
            assert!(!entry.contains(';') && !entry.contains('&') && !entry.contains('|'));
        }
    }

    #[test]
    fn cpu_quota_validation_rejects_malformed_overflow_out_of_range() {
        for (input, want) in [("1", 1), ("100", 100), ("1000", 1000), ("0100", 100)] {
            assert_eq!(parse_cpu_quota_percent(input).unwrap(), want, "{input:?}");
        }
        for bad in [
            "",
            "0",
            "1001",
            "100%",
            " 100",
            "100 ",
            "+100",
            "-1",
            "abc",
            "10.0",
            "4294967296",
            "18446744073709551615",
        ] {
            assert!(
                parse_cpu_quota_percent(bad).is_err(),
                "cpu {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn memory_bytes_validation_rejects_ambiguous_and_overflow() {
        assert_eq!(
            parse_memory_bytes("4294967296", false, "--memory-max").unwrap(),
            4294967296
        );
        assert_eq!(
            parse_memory_bytes("4GiB", false, "--memory-max").unwrap(),
            4294967296
        );
        assert_eq!(
            parse_memory_bytes("1KiB", false, "--memory-max").unwrap(),
            1024
        );
        assert_eq!(
            parse_memory_bytes("1MiB", false, "--memory-max").unwrap(),
            1048576
        );
        assert_eq!(
            parse_memory_bytes("0", true, "--memory-swap-max").unwrap(),
            0
        );
        assert_eq!(
            parse_memory_bytes("0KiB", true, "--memory-swap-max").unwrap(),
            0
        );
        assert!(parse_memory_bytes("0", false, "--memory-max").is_err());
        assert!(parse_memory_bytes("0GiB", false, "--memory-max").is_err());
        for bad in [
            "",
            "4G",
            "4GB",
            "4g",
            "4 Gib",
            "4Gi",
            "KiB",
            " 4GiB",
            "4GiB ",
            "+4GiB",
            "-1",
            "4.5GiB",
            "4 gib",
            "18446744073709551616",
            "18446744073709551615GiB",
            "16EiB",
        ] {
            assert!(
                parse_memory_bytes(bad, false, "--memory-max").is_err(),
                "memory {bad:?} must be rejected"
            );
            if bad != "0" {
                assert!(
                    parse_memory_bytes(bad, true, "--memory-swap-max").is_err()
                        || bad == "0KiB"
                        || bad == "0GiB",
                    "swap {bad:?} must be rejected"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_limit_parsers_handle_max_and_malformed() {
        assert_eq!(
            parse_cpu_max("100000 100000").unwrap(),
            (Some(100000), 100000)
        );
        assert_eq!(parse_cpu_max("max 100000").unwrap(), (None, 100000));
        for bad in [
            "",
            "100000",
            "100000 100000 extra",
            "abc 100000",
            "100000 0",
            "100000 abc",
        ] {
            assert!(parse_cpu_max(bad).is_err(), "cpu.max {bad:?} must fail");
        }
        assert_eq!(
            parse_memory_max("4294967296", "memory.max").unwrap(),
            Some(4294967296)
        );
        assert_eq!(parse_memory_max("max\n", "memory.max").unwrap(), None);
        assert_eq!(parse_memory_max("0", "memory.swap.max").unwrap(), Some(0));
        for bad in ["", "  ", "4GiB", "abc", "-1", "1.5"] {
            assert!(
                parse_memory_max(bad, "memory.max").is_err(),
                "memory {bad:?} must fail"
            );
        }
        assert_eq!(
            cgroup_base_from_procs("/sys/fs/cgroup/a/b/cgroup.procs"),
            "/sys/fs/cgroup/a/b"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_resources_matches_mismatch_and_unavailable() {
        use status::ResourceVerification;
        let mkbase = |tag: &str| {
            let base = std::env::temp_dir().join(format!(
                "agent-bus-res-verify-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&base).unwrap();
            base
        };
        // Verified: exact match including zero swap.
        let base = mkbase("ok");
        std::fs::write(base.join("cpu.max"), "100000 100000\n").unwrap();
        std::fs::write(base.join("memory.max"), "4294967296\n").unwrap();
        std::fs::write(base.join("memory.swap.max"), "0\n").unwrap();
        let policy = ResourcePolicy {
            cpu_quota_percent: Some(100),
            memory_max_bytes: Some(4294967296),
            memory_swap_max_bytes: Some(0),
        };
        let (obs, ok) = verify_resources(&policy, base.to_str().unwrap());
        assert!(ok.is_ok(), "verified case failed: {ok:?} obs={obs:?}");
        assert_eq!(obs.verification, ResourceVerification::Verified);
        assert_eq!(obs.cpu_quota_percent, Some(100));
        assert_eq!(obs.memory_max_bytes, Some(4294967296));
        assert_eq!(obs.memory_swap_max_bytes, Some(0));
        // Failed: cpu unlimited, memory mismatch, swap unlimited.
        let base2 = mkbase("fail");
        std::fs::write(base2.join("cpu.max"), "max 100000\n").unwrap();
        std::fs::write(base2.join("memory.max"), "1000\n").unwrap();
        std::fs::write(base2.join("memory.swap.max"), "max\n").unwrap();
        let (obs2, err2) = verify_resources(&policy, base2.to_str().unwrap());
        assert!(err2.is_err());
        assert_eq!(obs2.verification, ResourceVerification::Failed);
        assert_eq!(obs2.cpu_quota_percent, None);
        assert_eq!(obs2.memory_max_bytes, Some(1000));
        assert_eq!(obs2.memory_swap_max_bytes, None);
        let msg = err2.unwrap_err();
        assert!(
            msg.contains("cpu") && msg.contains("memory") && msg.contains("swap"),
            "{msg}"
        );
        // Unavailable: missing files.
        let base3 = mkbase("missing");
        let (obs3, err3) = verify_resources(&policy, base3.to_str().unwrap());
        assert!(err3.is_err());
        assert_eq!(obs3.verification, ResourceVerification::Unavailable);
        assert!(err3.unwrap_err().contains("UNAVAILABLE"));
        // Partial policy: only swap zero, other files ignored.
        let base4 = mkbase("partial");
        std::fs::write(base4.join("memory.swap.max"), "0\n").unwrap();
        let swap_only = ResourcePolicy {
            cpu_quota_percent: None,
            memory_max_bytes: None,
            memory_swap_max_bytes: Some(0),
        };
        let (obs4, ok4) = verify_resources(&swap_only, base4.to_str().unwrap());
        assert!(ok4.is_ok(), "{ok4:?}");
        assert_eq!(obs4.verification, ResourceVerification::Verified);
        assert_eq!(obs4.memory_swap_max_bytes, Some(0));
        assert_eq!(obs4.cpu_quota_percent, None);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&base2);
        let _ = std::fs::remove_dir_all(&base3);
        let _ = std::fs::remove_dir_all(&base4);
    }

    #[cfg(unix)]
    #[test]
    fn fractional_cpu_observation_is_not_reported_as_a_rounded_integer() {
        let base = std::env::temp_dir().join(format!(
            "root-resource-fractional-cpu-{}",
            std::process::id()
        ));
        std::fs::create_dir(&base).unwrap();
        let policy = ResourcePolicy {
            cpu_quota_percent: Some(100),
            ..Default::default()
        };
        for quota in [99999u64, 100001] {
            std::fs::write(base.join("cpu.max"), format!("{quota} 100000\n")).unwrap();
            let (observed, result) = verify_resources(&policy, base.to_str().unwrap());
            assert_eq!(observed.verification, status::ResourceVerification::Failed);
            assert_eq!(
                observed.cpu_quota_percent, None,
                "fractional observation must not be truncated"
            );
            let error = result.unwrap_err();
            assert!(
                error.contains(&format!("{quota}/100000")),
                "exact quota/period missing: {error}"
            );
        }
        std::fs::remove_dir_all(base).unwrap();
    }
}
