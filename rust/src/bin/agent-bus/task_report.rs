//! Explicit worker task report: one bounded file per scheduler run.
//!
//! The scheduler passes its expected identity plus a unique per-run path in
//! `AGENT_BUS_TASK_REPORT_*` env. This command validates `complete` vs
//! `needs_resume` payloads and atomically replaces that file. Identity comes
//! only from env, never from flags, so a mismatched write is impossible here
//! (the scheduler still re-validates on read). No broker IO, no KV writes.
//!
//! Output never panics: stdout/stderr writes are checked and flushed
//! explicitly. The success receipt deliberately echoes the supplied
//! run/task/agent/path/state as confirmation; no tokens or unrelated env
//! are printed.

use agent_bus::task_report::{
    validate_report, write_report_atomic, WorkerReport, WorkerState, ENV_AGENT, ENV_REPORT_PATH,
    ENV_RUN_ID, ENV_TASK, MAX_REMAINING_CHARS, MAX_SUMMARY_CHARS, PROVENANCE, SCHEMA_VERSION,
};
use serde_json::json;

const USAGE: &str = "usage: agent-bus task-report --state complete|needs_resume --summary TEXT [--remaining TEXT] [--inbox-cursor N]\n\
    Identity and destination come only from scheduler env:\n\
    AGENT_BUS_TASK_REPORT_PATH, _RUN_ID, _TASK, _AGENT.\n\
    needs_resume requires --remaining; complete must not set it.\n";

/// Parse-aware help check for this command only: option values are skipped
/// first, so a legitimate value spelled `--help` (for example
/// `--summary --help`) is treated as data, not a help request. Unrelated
/// routes keep `super::wants_help` unchanged.
fn wants_help_task_report(argv: &[String]) -> bool {
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--state" | "--summary" | "--remaining" | "--inbox-cursor" => {
                i += 2;
                continue;
            }
            "--help" | "-h" => return true,
            _ => i += 1,
        }
    }
    false
}

/// Write one stdout payload plus flush; false means the receipt or usage
/// could not be delivered (caller returns 1, never panics).
fn emit_stdout(text: &str) -> bool {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes()).is_ok() && out.flush().is_ok()
}

/// Best-effort stderr line; failures are not further reportable and never
/// panic. The caller still returns its intended validation/IO exit code.
fn err_line(msg: &str) {
    use std::io::Write as _;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(msg.as_bytes());
    if !msg.ends_with('\n') {
        let _ = err.write_all(b"\n");
    }
    let _ = err.flush();
}

pub(super) fn command(argv: &[String]) -> i32 {
    if wants_help_task_report(argv) {
        if emit_stdout(USAGE) {
            return 0;
        }
        return 1;
    }
    let mut state: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut remaining: Option<String> = None;
    let mut remaining_set = false;
    let mut cursor: Option<String> = None;
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--state" => match super::take_value(argv, &mut i, "--state") {
                Ok(v) => state = Some(v),
                Err(e) => {
                    err_line(&e);
                    return 2;
                }
            },
            "--summary" => match super::take_value(argv, &mut i, "--summary") {
                Ok(v) => summary = Some(v),
                Err(e) => {
                    err_line(&e);
                    return 2;
                }
            },
            "--remaining" => match super::take_value(argv, &mut i, "--remaining") {
                Ok(v) => {
                    remaining = Some(v);
                    remaining_set = true;
                }
                Err(e) => {
                    err_line(&e);
                    return 2;
                }
            },
            "--inbox-cursor" => match super::take_value(argv, &mut i, "--inbox-cursor") {
                Ok(v) => cursor = Some(v),
                Err(e) => {
                    err_line(&e);
                    return 2;
                }
            },
            other => {
                err_line(&format!("error: invalid task-report argument '{other}'\n{USAGE}"));
                return 2;
            }
        }
        i += 1;
    }
    let state_raw = match state {
        Some(s) => s,
        None => {
            err_line(&format!("error: --state is required\n{USAGE}"));
            return 2;
        }
    };
    let worker_state = match WorkerState::parse(&state_raw) {
        Some(s) => s,
        None => {
            err_line(&format!(
                "error: --state must be complete or needs_resume\n{USAGE}"
            ));
            return 2;
        }
    };
    let summary_raw = match summary {
        Some(s) => s,
        None => {
            err_line(&format!("error: --summary is required\n{USAGE}"));
            return 2;
        }
    };
    let summary_trimmed = summary_raw.trim().to_string();
    if summary_trimmed.is_empty() {
        err_line("error: --summary must not be empty");
        return 2;
    }
    if summary_trimmed.chars().count() > MAX_SUMMARY_CHARS {
        err_line("error: --summary exceeds 1024 characters");
        return 2;
    }
    let remaining_trimmed: Option<String> = if remaining_set {
        let raw = remaining.unwrap_or_default();
        let trimmed = raw.trim().to_string();
        match worker_state {
            WorkerState::Complete => {
                err_line("error: complete must not set --remaining");
                return 2;
            }
            WorkerState::NeedsResume => {
                if trimmed.is_empty() {
                    err_line("error: needs_resume requires --remaining");
                    return 2;
                }
                if trimmed.chars().count() > MAX_REMAINING_CHARS {
                    err_line("error: --remaining exceeds 2048 characters");
                    return 2;
                }
                Some(trimmed)
            }
        }
    } else {
        match worker_state {
            WorkerState::Complete => None,
            WorkerState::NeedsResume => {
                err_line("error: needs_resume requires --remaining");
                return 2;
            }
        }
    };
    let inbox_cursor: Option<u64> = match cursor {
        None => None,
        Some(raw) => match parse_cursor(&raw) {
            Some(n) => Some(n),
            None => {
                err_line("error: --inbox-cursor must be decimal digits (u64)");
                return 2;
            }
        },
    };
    // Scheduler-owned identity: names only in errors, never values. The path
    // keeps native bytes via var_os; run/task/agent stay typed strings.
    let path = std::path::PathBuf::from(std::env::var_os(ENV_REPORT_PATH).unwrap_or_default());
    let run_id = std::env::var(ENV_RUN_ID).unwrap_or_default();
    let task = std::env::var(ENV_TASK).unwrap_or_default();
    let agent = std::env::var(ENV_AGENT).unwrap_or_default();
    let path_missing =
        path.as_os_str().is_empty() || path.to_str().is_some_and(|s| s.trim().is_empty());
    if path_missing
        || run_id.trim().is_empty()
        || task.trim().is_empty()
        || agent.trim().is_empty()
    {
        err_line(&format!(
            "error: task-report needs scheduler env {ENV_REPORT_PATH}, {ENV_RUN_ID}, {ENV_TASK}, {ENV_AGENT}"
        ));
        return 2;
    }
    let report = WorkerReport {
        schema_version: SCHEMA_VERSION,
        provenance: PROVENANCE.to_string(),
        run_id: run_id.clone(),
        task: task.clone(),
        agent: agent.clone(),
        state: worker_state,
        summary: summary_trimmed,
        remaining: remaining_trimmed,
        inbox_cursor,
    };
    // Belt-and-braces: CLI checks above already enforce the rules, but the
    // shared validator is authoritative before any write.
    if validate_report(&report, &run_id, &task, &agent).is_err() {
        err_line("error: task-report payload invalid");
        return 2;
    }
    match write_report_atomic(&path, &report) {
        Ok(()) => {
            let line = format!(
                "{}\n",
                super::compact(&json!({
                    "ok": true,
                    "path": path.to_string_lossy(),
                    "run_id": run_id,
                    "task": task,
                    "agent": agent,
                    "state": worker_state.as_str(),
                }))
            );
            if emit_stdout(&line) {
                0
            } else {
                1
            }
        }
        Err(e) => {
            err_line(&format!("error: {e}"));
            1
        }
    }
}

fn parse_cursor(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_parsing_rejects_non_digits_and_overflow() {
        assert_eq!(parse_cursor("0"), Some(0));
        assert_eq!(parse_cursor("205"), Some(205));
        assert_eq!(parse_cursor("18446744073709551615"), Some(u64::MAX));
        for bad in ["", " 205", "205 ", "+205", "-1", "20a", "18446744073709551616"] {
            assert_eq!(parse_cursor(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn help_recognition_skips_option_values() {
        let argv = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Bare help still triggers.
        assert!(wants_help_task_report(&argv(&[
            "agent-bus",
            "task-report",
            "--help"
        ])));
        assert!(wants_help_task_report(&argv(&[
            "agent-bus",
            "task-report",
            "--summary",
            "done",
            "-h"
        ])));
        // Values spelled --help are data, not help requests.
        assert!(!wants_help_task_report(&argv(&[
            "agent-bus",
            "task-report",
            "--state",
            "complete",
            "--summary",
            "--help"
        ])));
        assert!(!wants_help_task_report(&argv(&[
            "agent-bus",
            "task-report",
            "--state",
            "--help",
            "--summary",
            "done"
        ])));
        assert!(!wants_help_task_report(&argv(&[
            "agent-bus",
            "task-report",
            "--remaining",
            "--help",
            "--state",
            "needs_resume",
            "--summary",
            "half"
        ])));
    }
}
