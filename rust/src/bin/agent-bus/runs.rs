//! Read-only view of independent scheduler records. A report is not a local
//! process inspection; old terminal reports never replace newer active runs.
//!
//! Process evidence (`outcome`/`cleanup`) proves only child supervision.
//! Task evidence (`task_state`) is explicit worker self-reporting, never
//! inferred from exit codes, heartbeats, or logs; legacy records read as
//! task `unknown`.

use agent_bus::scheduler::status::{status_key, ACTIVE_TTL_MS, STATUS_KEY_PREFIX, TERMINAL_TTL_MS};
use serde_json::{json, Value};

const USAGE: &str = "usage: agent-bus runs [PREFIX] [--format short|json]\n\
    PREFIX defaults to ctx.sched. and must start with it.\n\
    Reports are independent, non-atomic reads; absent/stale means unknown.\n\
    Process outcome/cleanup and worker task_state are reported separately;\n\
    task_state is self-reported (complete/needs_resume/unknown), never proof.\n";
const LIST_CAP: usize = agent_bus::kv::KV_LIST_LIMIT;
const TOTAL_RECORD_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn command(argv: &[String]) -> i32 {
    if super::wants_help(argv) {
        print!("{USAGE}");
        return 0;
    }
    let mut prefix = None;
    let mut format = "short".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match super::take_value(argv, &mut i, "--format") {
                Ok(value) => format = value,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            value if !super::is_flag(value) && prefix.is_none() => prefix = Some(value.to_owned()),
            _ => {
                eprintln!("error: invalid runs argument\n{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let prefix = prefix.unwrap_or_else(|| STATUS_KEY_PREFIX.to_owned());
    if !prefix.starts_with(STATUS_KEY_PREFIX) || !["short", "json"].contains(&format.as_str()) {
        eprintln!("error: invalid runs prefix or format\n{USAGE}");
        return 2;
    }
    let result = read(&prefix);
    match result {
        Ok(view) => {
            if format == "json" {
                println!("{}", super::compact(&view));
            } else {
                println!("{}", short(&view));
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn read(prefix: &str) -> Result<Value, String> {
    let cfg = super::load_config()?;
    let mut client = super::connect(&cfg).map_err(|e| e.to_string())?;
    // Bound the list/get fan-out after connection and hello. Connection/DNS
    // behavior remains the shared CLI contract, not a new total-time claim.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let listed = read_rpc(
        &mut client,
        &json!({"op": "kv_list", "prefix": prefix}),
        deadline,
    )?;
    let keys = listed
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("invalid run listing: expected keys")?;
    if keys.len() > LIST_CAP {
        return Err("run listing exceeds supported broker cap".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for key in keys {
        let key = key
            .as_str()
            .filter(|k| k.starts_with(prefix))
            .ok_or("invalid run listing key")?;
        names.insert(key.to_owned());
    }
    // Delay output until every authorized read succeeds. Refusal or transport
    // failure must not become a plausible empty or partial successful view.
    let mut records = Vec::new();
    let mut record_bytes = 0usize;
    for key in names {
        let got = read_rpc(&mut client, &json!({"op": "kv_get", "key": key}), deadline)?;
        // kv_get has no echoed key in either broker. Client RPC correlation
        // binds this reply to the request; retain that request's exact key.
        let found = got
            .get("found")
            .and_then(Value::as_bool)
            .ok_or("invalid run read: expected found")?;
        let record = if found {
            got.get("value")
                .cloned()
                .ok_or("invalid run read: missing value")?
        } else {
            Value::Null
        };
        // Each RPC is bounded already; also bound aggregation across keys.
        // Refuse the whole view rather than silently dropping any run.
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| "cannot measure run record")?
            .len();
        record_bytes = record_bytes.saturating_add(bytes);
        if record_bytes > TOTAL_RECORD_BYTES {
            return Err("run records exceed the 8 MiB view budget; use a narrower prefix".into());
        }
        records.push((key, found, record));
    }
    let observed = super::now_secs();
    let rows: Vec<Value> = records
        .into_iter()
        .map(|(key, found, record)| row(&key, found, record, observed))
        .collect();
    Ok(json!({
        "source": "scheduler_reports", "prefix": prefix, "observed_ts": observed,
        "atomic_snapshot": false, "processes_checked": false,
        "possibly_truncated": keys.len() == LIST_CAP,
        "missing_means": "unknown", "runs": rows,
    }))
}

fn read_rpc(
    client: &mut agent_bus::wire::Client,
    request: &Value,
    deadline: std::time::Instant,
) -> Result<Value, String> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or("run listing deadline exceeded; use a narrower prefix")?;
    client
        .set_rpc_timeout(remaining.min(agent_bus::wire::CLIENT_RPC_TIMEOUT))
        .map_err(|e| e.to_string())?;
    super::rpc(client, request)
}

fn row(key: &str, found: bool, record: Value, now: f64) -> Value {
    let phase = record.get("phase").and_then(Value::as_str).unwrap_or("");
    let identity = ["task", "agent", "run_id"].map(|name| record.get(name).and_then(Value::as_str));
    let matches_identity = match identity {
        [Some(task), Some(agent), Some(run)] => status_key(task, agent, run).as_deref() == Ok(key),
        _ => false,
    };
    let started = record.get("started_ts").and_then(Value::as_f64);
    let updated = record.get("updated_ts").and_then(Value::as_f64);
    let clock_valid = matches!((started, updated), (Some(s), Some(u)) if s.is_finite() && u.is_finite() && s > 0.0 && u >= s)
        && now.is_finite()
        && now > 0.0;
    let age = updated.filter(|_| clock_valid).map(|t| now - t);
    let ttl = match phase {
        "starting" | "active" => Some(ACTIVE_TTL_MS as f64 / 1000.0),
        "terminal" => Some(TERMINAL_TTL_MS as f64 / 1000.0),
        _ => None,
    };
    let reason = if !found {
        "missing"
    } else if !matches_identity || ttl.is_none() {
        "invalid_record"
    } else if !clock_valid {
        "invalid_clock"
    } else if age.is_some_and(|a| a < 0.0) {
        "clock_skew"
    } else if age.is_some_and(|a| a > ttl.unwrap_or(0.0)) {
        "stale"
    } else {
        "fresh"
    };
    // Task evidence comes only from the explicit worker field; never from
    // process outcome, exit codes, or heartbeats. Legacy records lack the
    // field and read as unknown. The derived current task state is gated by
    // enclosing freshness: when the row itself is unknown (missing, invalid,
    // clock, skew, or stale), a known historical assertion is not presented
    // as current; the raw record below retains the original worker value.
    let (inner_state, inner_reason) = agent_bus::task_report::view_task_state(&record);
    let (task_state, task_reason) = if reason != "fresh" && inner_state != "unknown" {
        (
            "unknown".to_string(),
            serde_json::json!(agent_bus::task_report::REASON_INVALID),
        )
    } else {
        (inner_state, inner_reason)
    };
    json!({"key": key, "state": if reason == "fresh" { phase } else { "unknown" },
        "freshness": reason, "age_s": age,
        "task_state": task_state, "task_reason": task_reason, "record": record})
}

fn short(view: &Value) -> String {
    let mut lines = vec![
        "Scheduler reports (process outcome/cleanup != worker task_state; missing/stale means unknown):"
            .to_owned(),
    ];
    if view["possibly_truncated"] == true {
        lines.push("Listing reached the broker cap; use a narrower ctx.sched. prefix.".into());
    }
    if let Some(rows) = view["runs"].as_array() {
        for row in rows {
            let record = &row["record"];
            // JSON string formatting keeps names and control characters
            // unambiguous without trusting heartbeat or task text as state.
            // Existing outcome/cleanup stay as process evidence; task_state
            // is separate self-reported evidence, never proof.
            lines.push(format!(
                "{} agent={} task={} report={} age={} freshness={} outcome={} cleanup={} task_state={} task_reason={}",
                super::compact(&row["key"]),
                super::compact(&record["agent"]),
                super::compact(&record["task"]),
                super::compact(&row["state"]),
                super::fmt_age(&row["age_s"]),
                super::compact(&row["freshness"]),
                super::compact(&record["outcome"]),
                super::compact(&record["cleanup"]),
                super::compact(&row["task_state"]),
                super::compact(&row["task_reason"])
            ));
        }
        if rows.is_empty() {
            lines.push("No visible run records; process/task state is unknown.".into());
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(phase: &str, updated: f64) -> Value {
        json!({"task":"work","agent":"worker","run_id":"1", "phase":phase,
            "started_ts":1.0,"updated_ts":updated})
    }

    #[test]
    fn freshness_uses_phase_ttl_without_inventing_exit() {
        let key = "ctx.sched.work.worker.1";
        for (phase, age, state) in [
            ("starting", 60.0, "starting"),
            ("active", 60.0, "active"),
            ("active", 60.1, "unknown"),
            ("terminal", 3600.0, "terminal"),
            ("terminal", 3600.1, "unknown"),
        ] {
            let view = row(key, true, sample(phase, 100.0), 100.0 + age);
            assert_eq!(view["state"], state, "{phase} age={age}");
        }
    }

    #[test]
    fn absent_or_unsynchronized_reports_are_unknown() {
        let key = "ctx.sched.work.worker.1";
        let missing = row(key, false, Value::Null, 100.0);
        assert_eq!(missing["state"], "unknown");
        assert_eq!(missing["freshness"], "missing");
        let future = row(key, true, sample("active", 101.0), 100.0);
        assert_eq!(future["state"], "unknown");
        assert_eq!(future["freshness"], "clock_skew");
    }

    #[test]
    fn stale_known_task_is_not_current_but_raw_record_kept() {
        let key = "ctx.sched.work.worker.1";
        let mut rec = sample("terminal", 100.0);
        rec["task_completion"] = json!({
            "state": "complete", "reason": null,
            "report": {
                "schema_version": 1, "provenance": "worker-report",
                "run_id": "1", "task": "work", "agent": "worker",
                "state": "complete", "summary": "done",
                "remaining": null, "inbox_cursor": null
            }
        });
        // Fresh terminal presents the validated assertion as current.
        let fresh = row(key, true, rec.clone(), 100.0 + 10.0);
        assert_eq!(fresh["state"], "terminal");
        assert_eq!(fresh["freshness"], "fresh");
        assert_eq!(fresh["task_state"], "complete");
        // Stale terminal keeps the historical assertion in record but the
        // derived current task state is unknown.
        let stale = row(key, true, rec.clone(), 100.0 + 7200.0);
        assert_eq!(stale["state"], "unknown");
        assert_eq!(stale["freshness"], "stale");
        assert_eq!(stale["task_state"], "unknown");
        assert_eq!(stale["record"]["task_completion"]["state"], "complete");
    }
}
