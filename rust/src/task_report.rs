//! Explicit worker task-completion reports: self-reported evidence only.
//!
//! Problem: scheduler `outcome:"success"` proves only child/process success.
//! A round can exit 0 while capacity is still held, and an ended `--once`
//! session never resumes on a later release. Heartbeat text, exit codes,
//! log parsing, and stale history must not be read as task state.
//!
//! This module adds a small opt-in protocol. The scheduler creates a unique
//! per-run directory, passes its path plus the expected run/task/agent
//! identity to the child in dedicated env vars, and later reads one bounded
//! regular JSON file from that directory. A native `task-report` CLI
//! validates `complete` vs `needs_resume` payloads and atomically writes the
//! file. The scheduler includes the validated report separately in its
//! existing run-status records; process `outcome`/`cleanup` stay independent.
//!
//! A worker assertion is never coordinator verification and never proves
//! accepted code or overall goal completion. Missing, unsupported, invalid,
//! unreadable, mismatched, or unavailable reports leave task completion
//! `unknown` with a fixed sanitized reason. Legacy records without the new
//! field also read as `unknown`. No new broker op or grant is required; the
//! worker never writes scheduler KV directly.
//!
//! Bounds: one 8 KiB regular file, fixed string caps, no helper threads, no
//! traversal from worker data, no stale reuse. Symlinks and non-regular files
//! are rejected; the byte cap bounds allocation, not a wall-clock IO
//! deadline. Same-user isolation is explicitly not claimed: identity matching
//! is not authentication.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Expected schema version in every report file.
pub const SCHEMA_VERSION: u32 = 1;
/// Expected provenance marker in every report file.
pub const PROVENANCE: &str = "worker-report";
/// Scheduler-supplied report file path for the child.
pub const ENV_REPORT_PATH: &str = "AGENT_BUS_TASK_REPORT_PATH";
/// Scheduler-supplied expected run id for the child.
pub const ENV_RUN_ID: &str = "AGENT_BUS_TASK_REPORT_RUN_ID";
/// Scheduler-supplied expected task name for the child.
pub const ENV_TASK: &str = "AGENT_BUS_TASK_REPORT_TASK";
/// Scheduler-supplied expected agent name for the child.
pub const ENV_AGENT: &str = "AGENT_BUS_TASK_REPORT_AGENT";
/// Maximum report file bytes accepted by the scheduler.
pub const MAX_REPORT_BYTES: usize = 8192;
/// Maximum summary characters accepted.
pub const MAX_SUMMARY_CHARS: usize = 1024;
/// Maximum remaining-work characters accepted.
pub const MAX_REMAINING_CHARS: usize = 2048;
/// Fixed file name inside the scheduler-supplied per-run directory.
pub const REPORT_FILE_NAME: &str = "report.json";
/// Prefix for scheduler-created per-run report directories under temp.
pub const REPORT_DIR_PREFIX: &str = "agent-bus-task-report-";

/// Sanitized unknown reasons. Fixed strings only, never worker text.
pub const REASON_MISSING: &str = "missing";
pub const REASON_UNSUPPORTED: &str = "unsupported";
pub const REASON_INVALID: &str = "invalid";
pub const REASON_UNREADABLE: &str = "unreadable";
pub const REASON_MISMATCHED: &str = "mismatched";
/// Scheduler-side reason when report support was enabled but the per-run
/// context could not be created. Distinct from `missing` (disabled or no
/// file); process outcome stays independent.
pub const REASON_UNAVAILABLE: &str = "unavailable";
/// Runs-view reason for records that predate the new field.
pub const REASON_LEGACY: &str = "legacy";

/// Worker-asserted state in the report file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Complete,
    NeedsResume,
}

impl WorkerState {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerState::Complete => "complete",
            WorkerState::NeedsResume => "needs_resume",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "complete" => Some(WorkerState::Complete),
            "needs_resume" => Some(WorkerState::NeedsResume),
            _ => None,
        }
    }
}

/// On-disk report file. Typed serde, never fragile text parsing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerReport {
    pub schema_version: u32,
    pub provenance: String,
    pub run_id: String,
    pub task: String,
    pub agent: String,
    pub state: WorkerState,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_cursor: Option<u64>,
}

/// Task completion state carried in status records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Complete,
    NeedsResume,
    Unknown,
}

impl TaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Complete => "complete",
            TaskState::NeedsResume => "needs_resume",
            TaskState::Unknown => "unknown",
        }
    }
}

/// Status-record view of task completion: self-reported evidence plus a
/// sanitized unknown reason. Process outcome stays separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskCompletion {
    pub state: TaskState,
    pub reason: Option<String>,
    pub report: Option<WorkerReport>,
}

impl TaskCompletion {
    pub fn unknown(reason: &str) -> Self {
        Self {
            state: TaskState::Unknown,
            reason: Some(reason.to_string()),
            report: None,
        }
    }

    pub fn from_report(report: WorkerReport) -> Self {
        let state = match report.state {
            WorkerState::Complete => TaskState::Complete,
            WorkerState::NeedsResume => TaskState::NeedsResume,
        };
        Self {
            state,
            reason: None,
            report: Some(report),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "reason": self.reason,
            "report": self.report.as_ref().map(report_json).unwrap_or(Value::Null),
        })
    }
}

fn report_json(report: &WorkerReport) -> Value {
    json!({
        "schema_version": report.schema_version,
        "provenance": report.provenance,
        "run_id": report.run_id,
        "task": report.task,
        "agent": report.agent,
        "state": report.state.as_str(),
        "summary": report.summary,
        "remaining": report.remaining,
        "inbox_cursor": report.inbox_cursor,
    })
}

/// Keep one directory-name character class for task/agent fragments.
pub fn sanitize_fragment(s: &str) -> String {
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

/// Validate one parsed report against scheduler-expected identity and the
/// explicit state/string contract. Returns the sanitized unknown reason on
/// failure, never worker text or env values.
///
/// String contract (shared by typed read, CLI, and docs): `summary` must be
/// non-empty with no leading/trailing whitespace and at most
/// `MAX_SUMMARY_CHARS` characters. `complete` must carry no `remaining` at
/// all (`None`/null; any present value, even empty or whitespace-only, is
/// invalid). `needs_resume` must carry a present, trimmed, non-empty
/// `remaining` of at most `MAX_REMAINING_CHARS` characters. Stored values
/// must already be trimmed; untrimmed input is invalid rather than silently
/// normalized with retained whitespace.
pub fn validate_report(
    report: &WorkerReport,
    expected_run: &str,
    expected_task: &str,
    expected_agent: &str,
) -> Result<(), &'static str> {
    if report.schema_version != SCHEMA_VERSION {
        return Err(REASON_UNSUPPORTED);
    }
    if report.provenance != PROVENANCE {
        return Err(REASON_INVALID);
    }
    if report.run_id != expected_run
        || report.task != expected_task
        || report.agent != expected_agent
    {
        return Err(REASON_MISMATCHED);
    }
    if report.run_id.trim().is_empty()
        || report.task.trim().is_empty()
        || report.agent.trim().is_empty()
    {
        return Err(REASON_INVALID);
    }
    if report.summary.is_empty() || report.summary != report.summary.trim() {
        return Err(REASON_INVALID);
    }
    if report.summary.chars().count() > MAX_SUMMARY_CHARS {
        return Err(REASON_INVALID);
    }
    match report.state {
        WorkerState::Complete => {
            if report.remaining.is_some() {
                return Err(REASON_INVALID);
            }
        }
        WorkerState::NeedsResume => {
            match &report.remaining {
                Some(raw) => {
                    if raw.is_empty() || raw != raw.trim() {
                        return Err(REASON_INVALID);
                    }
                    if raw.chars().count() > MAX_REMAINING_CHARS {
                        return Err(REASON_INVALID);
                    }
                }
                None => return Err(REASON_INVALID),
            }
        }
    }
    Ok(())
}

/// Open one report handle with symlink/fifo protections where available.
/// Unix opens with `O_NOFOLLOW|O_NONBLOCK` so a symlink fails closed at open
/// and a FIFO open does not block the supervisor; the caller still verifies
/// the opened handle is a regular file. Other platforms use a plain open.
#[cfg(unix)]
fn open_report(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_report(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Read and validate the per-run report at `report_path` against the
/// scheduler's own expected identity. Any missing, oversized, unreadable,
/// unparsable, unsupported, invalid, or mismatched input becomes `unknown`
/// with a fixed reason. No inference from exit codes, logs, or history.
///
/// Opens once, validates the opened handle is a regular file, then reads at
/// most `MAX_REPORT_BYTES + 1` bytes (consumption-bounded even if the file
/// grows mid-read; no separate stat-then-read TOCTOU). The byte cap bounds
/// allocation; it is not a wall-clock IO deadline.
pub fn read_task_completion(
    report_path: Option<&std::path::Path>,
    expected_run: &str,
    expected_task: &str,
    expected_agent: &str,
) -> TaskCompletion {
    use std::io::Read as _;
    let path = match report_path {
        Some(p) if !p.as_os_str().is_empty() => {
            // Match CLI/path contract: UTF8 whitespace-only is missing, not a
            // filename. Non-UTF8 bytes stay a real path (native preserved).
            if p.to_str().is_some_and(|s| s.trim().is_empty()) {
                return TaskCompletion::unknown(REASON_MISSING);
            }
            p
        }
        _ => return TaskCompletion::unknown(REASON_MISSING),
    };
    let file = match open_report(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return TaskCompletion::unknown(REASON_MISSING)
        }
        Err(_) => return TaskCompletion::unknown(REASON_UNREADABLE),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => return TaskCompletion::unknown(REASON_UNREADABLE),
    };
    if !meta.is_file() {
        return TaskCompletion::unknown(REASON_UNREADABLE);
    }
    let mut raw = Vec::new();
    let mut capped = (&file).take(MAX_REPORT_BYTES as u64 + 1);
    if capped.read_to_end(&mut raw).is_err() {
        return TaskCompletion::unknown(REASON_UNREADABLE);
    }
    if raw.len() > MAX_REPORT_BYTES {
        return TaskCompletion::unknown(REASON_INVALID);
    }
    let text = match String::from_utf8(raw) {
        Ok(t) => t,
        Err(_) => return TaskCompletion::unknown(REASON_INVALID),
    };
    let report: WorkerReport = match serde_json::from_str(&text) {
        Ok(r) => r,
        Err(_) => return TaskCompletion::unknown(REASON_INVALID),
    };
    match validate_report(&report, expected_run, expected_task, expected_agent) {
        Ok(()) => TaskCompletion::from_report(report),
        Err(reason) => TaskCompletion::unknown(reason),
    }
}

/// Scheduler-side per-run report location. Created fresh per run; never
/// reused across runs. The directory is left in place after the round so the
/// coordinator can capture the final file alongside bus status.
///
/// Native filesystem bytes are preserved end to end (`PathBuf` through temp
/// dir, child env, CLI, and file IO); use [`ReportContext::path_display`]
/// only for labeled display in receipts and logs.
#[derive(Clone, Debug)]
pub struct ReportContext {
    pub dir: std::path::PathBuf,
    pub path: std::path::PathBuf,
    pub run_id: String,
    pub task: String,
    pub agent: String,
}

impl ReportContext {
    pub fn read(&self) -> TaskCompletion {
        read_task_completion(Some(&self.path), &self.run_id, &self.task, &self.agent)
    }

    /// Lossy display rendering of the report path for receipts/logs only.
    /// File IO and child env use the native [`ReportContext::path`] bytes.
    pub fn path_display(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Lossy display rendering of the report directory for logs only.
    pub fn dir_display(&self) -> String {
        self.dir.to_string_lossy().into_owned()
    }
}

/// Create a unique per-run report directory under the system temp dir and
/// return its context. Fails without side effects beyond the mkdir attempt;
/// the caller degrades to `unknown` rather than failing the round.
///
/// Unix creates the directory owner-only (`0700`, best-effort tighten after
/// create); other platforms use the default directory permissions.
pub fn create_report_context(
    task: &str,
    agent: &str,
    run_id: &str,
) -> Result<ReportContext, String> {
    if task.trim().is_empty() || agent.trim().is_empty() || run_id.trim().is_empty() {
        return Err("task-report needs non-empty task/agent/run".to_string());
    }
    let dir = std::env::temp_dir().join(format!(
        "{}{}.{}.{}",
        REPORT_DIR_PREFIX,
        sanitize_fragment(task),
        sanitize_fragment(agent),
        run_id,
    ));
    // Fresh per run: an existing directory means stale reuse or collision.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&dir) {
            Ok(()) => {
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err("task-report directory already exists; refusing reuse".to_string())
            }
            Err(e) => return Err(format!("task-report directory create FAILED: {e}")),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::create_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err("task-report directory already exists; refusing reuse".to_string())
            }
            Err(e) => return Err(format!("task-report directory create FAILED: {e}")),
        }
    }
    let path = dir.join(REPORT_FILE_NAME);
    Ok(ReportContext {
        dir,
        path,
        run_id: run_id.to_string(),
        task: task.to_string(),
        agent: agent.to_string(),
    })
}

/// Atomically replace the scheduler-supplied report file. Writes one bounded
/// JSON object plus a trailing newline to a fresh temp file in the same
/// directory, then renames over the destination. Temp names are
/// scheduler-owned; no worker data becomes a path. The file contains the
/// supplied run/task/agent identity plus the worker payload; no tokens or
/// unrelated env are written. Unix creates the temp owner-only (`0600`).
pub fn write_report_atomic(path: &std::path::Path, report: &WorkerReport) -> Result<(), String> {
    let dest = path;
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "task-report path has no parent directory".to_string())?;
    let parent_meta = std::fs::symlink_metadata(parent)
        .map_err(|_| "task-report directory unreadable".to_string())?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err("task-report directory unreadable".to_string());
    }
    let bytes = serde_json::to_vec(report).map_err(|_| "task-report encode FAILED".to_string())?;
    // Budget every emitted byte: JSON plus the trailing newline must fit, so
    // a writer-accepted payload is always reader-accepted (never MAX+1).
    if bytes.len().saturating_add(1) > MAX_REPORT_BYTES {
        return Err("task-report exceeds size bound".to_string());
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(".{}.tmp.{}-{nanos}", REPORT_FILE_NAME, std::process::id()));
    // Fresh temp only; an existing temp name is never truncated.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|_| "task-report temp create FAILED".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    use std::io::Write as _;
    if file.write_all(&bytes).is_err() || file.write_all(b"\n").is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err("task-report temp write FAILED".to_string());
    }
    if file.sync_all().is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err("task-report temp sync FAILED".to_string());
    }
    drop(file);
    if std::fs::rename(&tmp, dest).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err("task-report replace FAILED".to_string());
    }
    Ok(())
}

/// Runs-view derivation from a generic status value. Uses only the explicit
/// `task_completion` object; never infers from exit codes, outcome strings,
/// heartbeats, or logs. Returns `(state, reason)` where reason is a JSON
/// string for unknown or null for known states.
///
/// Known states require a present, decodable report that validates against
/// the containing run identity, with outer/inner state agreement and a null
/// reason. A bare state without usable evidence is `unknown`/`invalid`, never
/// proof. Process outcome is never consulted.
pub fn view_task_state(record: &Value) -> (String, Value) {
    let obj = match record.as_object() {
        Some(o) => o,
        None => return ("unknown".to_string(), json!(REASON_MISSING)),
    };
    let completion = match obj.get("task_completion") {
        None => return ("unknown".to_string(), json!(REASON_LEGACY)),
        Some(Value::Null) => return ("unknown".to_string(), json!(REASON_LEGACY)),
        Some(v @ Value::Object(_)) => v,
        Some(_) => return ("unknown".to_string(), json!(REASON_INVALID)),
    };
    let state = completion.get("state").and_then(Value::as_str).unwrap_or("");
    match state {
        "complete" | "needs_resume" => {
            if completion.get("reason").is_some_and(|r| !r.is_null()) {
                return ("unknown".to_string(), json!(REASON_INVALID));
            }
            let report_value = match completion.get("report") {
                Some(v @ Value::Object(_)) => v,
                _ => return ("unknown".to_string(), json!(REASON_INVALID)),
            };
            let report: WorkerReport = match serde_json::from_value(report_value.clone()) {
                Ok(r) => r,
                Err(_) => return ("unknown".to_string(), json!(REASON_INVALID)),
            };
            let (task, agent, run) = match (
                obj.get("task").and_then(Value::as_str),
                obj.get("agent").and_then(Value::as_str),
                obj.get("run_id").and_then(Value::as_str),
            ) {
                (Some(t), Some(a), Some(r)) => (t, a, r),
                _ => return ("unknown".to_string(), json!(REASON_INVALID)),
            };
            if let Err(reason) = validate_report(&report, run, task, agent) {
                return ("unknown".to_string(), json!(reason));
            }
            if report.state.as_str() != state {
                return ("unknown".to_string(), json!(REASON_INVALID));
            }
            (state.to_string(), Value::Null)
        }
        "unknown" => {
            if completion.get("report").is_some_and(|r| !r.is_null()) {
                return ("unknown".to_string(), json!(REASON_INVALID));
            }
            let reason = completion.get("reason").and_then(Value::as_str).unwrap_or("");
            let safe = match reason {
                "missing" | "unsupported" | "invalid" | "unreadable" | "mismatched"
                | "unavailable" => reason,
                _ => REASON_INVALID,
            };
            ("unknown".to_string(), json!(safe))
        }
        _ => ("unknown".to_string(), json!(REASON_INVALID)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(state: WorkerState) -> WorkerReport {
        WorkerReport {
            schema_version: SCHEMA_VERSION,
            provenance: PROVENANCE.to_string(),
            run_id: "run-1".to_string(),
            task: "task-1".to_string(),
            agent: "agent-1".to_string(),
            state,
            summary: "did the work".to_string(),
            remaining: match state {
                WorkerState::Complete => None,
                WorkerState::NeedsResume => Some("resume step X".to_string()),
            },
            inbox_cursor: Some(205),
        }
    }

    #[test]
    fn complete_rejects_remaining_and_needs_resume_requires_it() {
        let mut ok_complete = sample(WorkerState::Complete);
        assert!(validate_report(&ok_complete, "run-1", "task-1", "agent-1").is_ok());
        ok_complete.remaining = Some("leftover".to_string());
        assert_eq!(
            validate_report(&ok_complete, "run-1", "task-1", "agent-1"),
            Err(REASON_INVALID)
        );
        let mut bad_resume = sample(WorkerState::NeedsResume);
        bad_resume.remaining = None;
        assert_eq!(
            validate_report(&bad_resume, "run-1", "task-1", "agent-1"),
            Err(REASON_INVALID)
        );
        bad_resume.remaining = Some("   ".to_string());
        assert_eq!(
            validate_report(&bad_resume, "run-1", "task-1", "agent-1"),
            Err(REASON_INVALID)
        );
    }

    #[test]
    fn version_identity_and_bounds_map_to_sanitized_reasons() {
        let mut version = sample(WorkerState::Complete);
        version.schema_version = 99;
        assert_eq!(
            validate_report(&version, "run-1", "task-1", "agent-1"),
            Err(REASON_UNSUPPORTED)
        );
        let mismatch = sample(WorkerState::Complete);
        assert_eq!(
            validate_report(&mismatch, "other", "task-1", "agent-1"),
            Err(REASON_MISMATCHED)
        );
        let mut empty = sample(WorkerState::Complete);
        empty.summary = "  ".to_string();
        assert_eq!(
            validate_report(&empty, "run-1", "task-1", "agent-1"),
            Err(REASON_INVALID)
        );
        let mut long = sample(WorkerState::Complete);
        long.summary = "x".repeat(MAX_SUMMARY_CHARS + 1);
        assert_eq!(
            validate_report(&long, "run-1", "task-1", "agent-1"),
            Err(REASON_INVALID)
        );
    }

    #[test]
    fn legacy_missing_and_malformed_views_are_unknown_without_inference() {
        let (state, reason) = view_task_state(&json!({"outcome": "success", "exit_code": 0}));
        assert_eq!(state, "unknown");
        assert_eq!(reason, json!("legacy"));
        let (state, _) = view_task_state(&Value::Null);
        assert_eq!(state, "unknown");
        // Correction: a bare state without a present, validated report is not
        // proof. The earlier assertion blessed `{"state":"complete"}` as
        // complete; source review shows missing/invalid evidence must stay
        // unknown, with outer/inner agreement checked against the run.
        let (state, reason) =
            view_task_state(&json!({"task_completion": {"state": "complete"}}));
        assert_eq!(state, "unknown");
        assert_eq!(reason, json!("invalid"));
        let (state, reason) =
            view_task_state(&json!({"task_completion": {"state": "unknown", "reason": "missing"}}));
        assert_eq!(state, "unknown");
        assert_eq!(reason, json!("missing"));
        let (state, reason) =
            view_task_state(&json!({"task_completion": {"state": "unknown", "reason": "evil"}}));
        assert_eq!(state, "unknown");
        assert_eq!(reason, json!("invalid"));
        // Unknown with an unexpected report is inconsistent, not proof.
        let (state, reason) = view_task_state(&json!({
            "task": "t", "agent": "a", "run_id": "r",
            "task_completion": {"state": "unknown", "reason": "missing",
                "report": {"schema_version": 1}}
        }));
        assert_eq!(state, "unknown");
        assert_eq!(reason, json!("invalid"));
        // Known states with a non-null reason are inconsistent.
        let (state, _) = view_task_state(&json!({
            "task_completion": {"state": "complete", "reason": "missing", "report": Value::Null}
        }));
        assert_eq!(state, "unknown");
    }

    #[test]
    fn strict_string_contract_rejects_untrimmed_and_present_empty_remaining() {
        // Untrimmed summary is invalid (not silently retained).
        let mut untrimmed = sample(WorkerState::Complete);
        untrimmed.summary = "  padded  ".to_string();
        assert_eq!(
            validate_report(&untrimmed, "run-1", "task-1", "agent-1"),
            Err(REASON_INVALID)
        );
        // Complete with any present remaining is invalid, even empty.
        for raw in ["", "   "] {
            let mut bad = sample(WorkerState::Complete);
            bad.remaining = Some(raw.to_string());
            assert_eq!(
                validate_report(&bad, "run-1", "task-1", "agent-1"),
                Err(REASON_INVALID),
                "complete remaining {raw:?}"
            );
        }
        // NeedsResume with untrimmed remaining is invalid.
        let mut bad_resume = sample(WorkerState::NeedsResume);
        bad_resume.remaining = Some("  step  ".to_string());
        assert_eq!(
            validate_report(&bad_resume, "run-1", "task-1", "agent-1"),
            Err(REASON_INVALID)
        );
    }
}
