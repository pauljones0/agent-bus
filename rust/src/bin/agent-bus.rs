//! agent-bus: native Rust coordination CLI (useful slice, not a full replacement).
//!
//! Speaks the JSON-lines wire (TCP or Unix socket) through the existing
//! public `agent_bus::wire::Client` (`rust/src/wire.rs`). The legacy `bus`
//! / `busclient.py` / `broker.py` are a text-only protocol reference; this
//! binary never shells out to Python and tests never touch the live bus.
//!
//! Credentials and addresses come only from the environment, mirroring the
//! transitional client (`busclient.py` `SOCK/HOST/PORT_DEFAULT` and
//! `Bus.__init__`, `bus --tcp`):
//!
//! - `AGENT_BUS_AGENT` (required), `AGENT_BUS_TOKEN` (required, never printed)
//! - `AGENT_BUS_HOST` (default `127.0.0.1`), `AGENT_BUS_PORT` (default `8379`)
//! - `AGENT_BUS_SOCK` (no default: Unix is used only when explicitly set
//!   and `--tcp` is absent; never silently falls back to TCP)
//! - Global `--tcp` forces TCP even when `AGENT_BUS_SOCK` is set.
//!
//! Supported verbs: `show` (exact-topic `--since-seq` or client-side
//! `--last`), `post` (with optional `--msg-id` for retry idempotency),
//! `request` (correlated `inbox.TARGET` post + `inbox.self` wait) and
//! `reply` (correlated post to a `reply_to` topic), `sub` (live pattern
//! streams with `--from-seq`/`--tail` replay,
//! `--count`/`--timeout`/`--once`/`--new-only`/`--follow`/`--since`),
//! `subs` (subscription listing), `unsubscribe` (per-connection isolated
//! release, idempotent ok), `heartbeat`, `agents`, `runs`, `task-report`
//! (local worker file, scheduler env only, no broker IO), `claims`
//! (advisory replay, exact-topic, `--stale`), `packets` (advisory window,
//! multi-topic `--tail`), `kv-get`, `kv-put`,
//! `kv-del`, `kv-list`, `stats`, `topics`, `limits`, `ping` (native `ping`
//! RPC health, `--count`/`--format`), `token-issue` (admin issue with
//! legacy grant flags), `token-revoke` (admin revoke), `token-claim`
//! (self-service claim), `art-put` (file/stdin upload, streaming past
//! 1 MiB), `art-get` (sha to file/stdout, range-streamed past 1 MiB),
//! `claim-acquire`/`claim-renew`/`claim-release`/`claim-status`/
//! `claim-list` (broker atomic leases, distinct from advisory `claims`).
//! Every other legacy verb fails explicitly with exit 2. See
//! `rust/README.md` for the source-backed compatibility table and
//! remaining gaps (no TLS; `show` keeps its finite exact-topic fetch
//! path, never live streams).
//!
//! Exit codes mirror the legacy CLI (`bus`): 0 success, 1 broker/transport/
//! auth refusal (`BusError` path, plus local `task-report` file IO), 2
//! usage/unsupported/history-gap or incomplete catch-up (`argparse` and
//! `show_history` paths, plus `task-report` validation).

use agent_bus::wire::{Client, StreamingConn};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global `--tcp` (force TCP instead of Unix socket), like legacy
/// `bus --tcp`. Set once in [`run`] before dispatch; read by
/// [`load_config`]. Process-local only, never inherited by children
/// (this CLI spawns none).
static FORCE_TCP: AtomicBool = AtomicBool::new(false);

#[path = "agent-bus/runs.rs"]
mod runs;
#[path = "agent-bus/task_report.rs"]
mod task_report;
#[path = "agent-bus/views.rs"]
mod views;

// ---------------------------------------------------------------------------
// entry
// ---------------------------------------------------------------------------

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let mut argv: Vec<String> = expand_equals_args(&std::env::args().collect::<Vec<_>>());
    // Global `--tcp` before the subcommand forces TCP even when
    // `AGENT_BUS_SOCK` is set. Stripped here so subcommands never see it.
    if argv.get(1).map(String::as_str) == Some("--tcp") {
        FORCE_TCP.store(true, Ordering::SeqCst);
        argv.remove(1);
    }
    let cmd = argv.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "" | "--help" | "-h" | "help" => {
            print!("{}", usage());
            0
        }
        // Credentials travel via env only: accepting `--token` would put a
        // secret on the command line (visible in `ps`), and the transitional
        // `--tls/--ca/--insecure` transports remain an explicit gap (TLS is
        // separate migration debt, never enabled here).
        "--agent" | "--token" | "--tls" | "--ca" | "--insecure" => {
            eprintln!(
                "error: global {cmd} is not accepted by this native slice; use \
                 AGENT_BUS_AGENT / AGENT_BUS_TOKEN / AGENT_BUS_HOST / AGENT_BUS_PORT / AGENT_BUS_SOCK"
            );
            2
        }
        s if is_flag(s) => {
            eprintln!("error: unknown option '{s}'\n{}", usage());
            2
        }
        "show" => cmd_show(&argv),
        "post" => cmd_post(&argv),
        "request" => cmd_request(&argv),
        "reply" => cmd_reply(&argv),
        "sub" => cmd_sub(&argv),
        "subs" => cmd_subs(&argv),
        "unsubscribe" => cmd_unsubscribe(&argv),
        "heartbeat" => cmd_heartbeat(&argv),
        "agents" => cmd_agents(&argv),
        "runs" => runs::command(&argv),
        "task-report" => task_report::command(&argv),
        "claims" => views::command_claims(&argv),
        "packets" => views::command_packets(&argv),
        "kv-get" => cmd_kv_get(&argv),
        "kv-put" => cmd_kv_put(&argv),
        "kv-del" => cmd_kv_del(&argv),
        "kv-list" => cmd_kv_list(&argv),
        "stats" => cmd_stats(&argv),
        "topics" => cmd_topics(&argv),
        "limits" => cmd_limits(&argv),
        "ping" => cmd_ping(&argv),
        "token-issue" => cmd_token_issue(&argv),
        "token-revoke" => cmd_token_revoke(&argv),
        "token-claim" => cmd_token_claim(&argv),
        "art-put" => cmd_art_put(&argv),
        "art-get" => cmd_art_get(&argv),
        "claim-acquire" => cmd_claim_acquire(&argv),
        "claim-renew" => cmd_claim_renew(&argv),
        "claim-release" => cmd_claim_release(&argv),
        "claim-status" => cmd_claim_status(&argv),
        "claim-list" => cmd_claim_list(&argv),
        other => {
            if let Some(hint) = unsupported_hint(other) {
                eprintln!(
                    "error: '{other}' is not supported by this native CLI slice \
                     (see rust/README.md compatibility table); {hint}; \
                     this CLI never shells out to Python"
                );
            } else {
                eprintln!("error: unknown command '{other}'\n{}", usage());
            }
            2
        }
    }
}

/// Closest in-slice alternative for each legacy verb that stays
/// unsupported here (`request`/`reply`/`claims`/`packets` are now
/// supported; token ops via `token-issue`/`token-revoke`/`token-claim`,
/// artifacts via `art-put`/`art-get`; atomic leases via
/// `claim-acquire`/`claim-renew`/`claim-release`/`claim-status`/
/// `claim-list`). `None` means the verb is entirely
/// unknown, not merely unsupported.
fn unsupported_hint(cmd: &str) -> Option<&'static str> {
    Some(match cmd {
        "whoami" => "your agent name is $AGENT_BUS_AGENT; use `agents` to confirm presence",
        _ => return None,
    })
}

/// Expand `--name=value` into `--name value` (argparse parity) before
/// dispatch. Every `--`-prefixed element already parses as an option,
/// never a positional, in all subcommands, so splitting changes no
/// working invocation; only the previous "unknown option" rejections
/// gain the space-form behavior (including its value validation).
/// Stops at the first bare `--` terminator (argparse parity): elements
/// after `--` are literal positionals (e.g. `kv-del -- --foo=bar` keeps
/// `--foo=bar` as one key), never split.
fn expand_equals_args(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut literal = false;
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            if !literal && a == "--" {
                literal = true;
                out.push(a.clone());
                continue;
            }
            if !literal {
                if let Some(rest) = a.strip_prefix("--") {
                    if !rest.is_empty() && !rest.starts_with('=') {
                        if let Some((name, value)) = rest.split_once('=') {
                            out.push(format!("--{name}"));
                            out.push(value.to_string());
                            continue;
                        }
                    }
                }
            }
        }
        out.push(a.clone());
    }
    out
}

fn usage() -> &'static str {
    "usage: agent-bus [--tcp] <command> [args]\n\
     \n\
     Env: AGENT_BUS_AGENT, AGENT_BUS_TOKEN (required, never logged),\n\
     AGENT_BUS_HOST (default 127.0.0.1), AGENT_BUS_PORT (default 8379),\n\
     AGENT_BUS_SOCK (no default: Unix socket used only when explicitly set).\n\
     Global --tcp forces TCP even when AGENT_BUS_SOCK is set.\n\
     \n\
     Supported slice:\n\
     \x20 show TOPIC (--since-seq N | --last N) [--format json|short|payload] [--sender NAME ...]\n\
     \x20 post TOPIC [PAYLOAD] [--durable] [--ttl-ms N] [--corr C] [--reply-to R] [--msg-id ID]\n\
     \x20 post TOPIC (--note TEXT [--event E] | --claim F,.. --task T | --release F,.. --task T)\n\
     \x20 request TARGET PAYLOAD [--timeout S] [--format json|payload]\n\
     \x20 reply DEST_TOPIC CORR_ID PAYLOAD\n\
     \x20 sub PATTERN [--from-seq N] [--tail N] [--count N] [--timeout S] [--format json|short|payload] [--once] [--new-only] [--follow] [--since AGE] [--full] [--maxlen N]\n\
     \x20 subs [--format json|short]\n\
     \x20 unsubscribe SUB_ID\n\
     \x20 heartbeat [STATUS]\n\
     \x20 agents [--format short|json]\n\
     \x20 runs [PREFIX] [--format short|json]\n\
     \x20 task-report --state complete|needs_resume --summary TEXT [--remaining TEXT] [--inbox-cursor N]\n\
     \x20 claims [TOPIC] [--format short|json] [--stale AGE] [--timeout S]\n\
     \x20 packets [TOPIC ...] [--tail N] [--format short|json]\n\
     \x20 kv-get KEY [--format json|short]\n\
     \x20 kv-put KEY VALUE [--durable] [--ttl-ms N]\n\
     \x20 kv-del KEY [--durable]\n\
     \x20 kv-list [PREFIX] [--format json|short] [--values]\n\
     \x20 stats [--format json|short]\n\
     \x20 topics [--format json|short]\n\
     \x20 limits [--format json|short]\n\
     \x20 ping [--count N] [--format json|short]\n\
     \x20 token-issue FOR_AGENT [--ttl-s F] [--publish P ...] [--subscribe S ...] [--kv-read K ...] [--kv-write K ...] [--art-quota-bytes I] [--rate-per-s F] [--topic-rate PAT=RATE ...]\n\
     \x20 token-revoke TOK\n\
     \x20 token-claim FOR_AGENT\n\
     \x20 art-put FILE ('-' reads stdin bytes)\n\
     \x20 art-get SHA [OUT]\n\
     \x20 claim-acquire RESOURCE --ttl-ms N [--idempotency-key K] [--format json|short]\n\
     \x20 claim-renew RESOURCE (--token T | --token-file P) --ttl-ms N [--format json|short]\n\
     \x20 claim-release RESOURCE (--token T | --token-file P) [--format json|short]\n\
     \x20 claim-status RESOURCE [--format json|short]\n\
     \x20 claim-list [--format json|short]\n\
     \n\
     PAYLOAD/VALUE of '-' reads stdin (JSON when it parses, else plain text).\n\
     --token-file P reads the lease token from file P ('-' reads stdin); never echoed.\n\
     Exit: 0 ok, 1 broker/transport/auth refusal, 2 usage/unsupported/history gap.\n\
     Anything else (whoami, ...) exits 2 explicitly.\n"
}

fn wants_help(args: &[String]) -> bool {
    args.iter().skip(2).any(|a| a == "--help" || a == "-h")
}

/// Option-word test: a bare `-` is the stdin marker / a positional, never a
/// flag (matching `argparse`, where `-` alone is positional).
fn is_flag(s: &str) -> bool {
    s.starts_with('-') && s != "-"
}

// ---------------------------------------------------------------------------
// config + transport (env only, token never logged)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Config {
    addr: String,
    agent: String,
    token: String,
    /// Unix socket path when selected (explicit `AGENT_BUS_SOCK`, no
    /// `--tcp`). `None` means TCP (`addr`). No default path: an unset or
    /// empty `AGENT_BUS_SOCK` never selects Unix, so existing TCP-only
    /// callers keep working even when `/tmp/agent-bus.sock` exists.
    unix_path: Option<String>,
}

fn load_config() -> Result<Config, String> {
    let agent = std::env::var("AGENT_BUS_AGENT").unwrap_or_default();
    if agent.is_empty() {
        return Err("missing AGENT_BUS_AGENT: export it (no --agent flag in this slice)".into());
    }
    // Empty-token message mirrors `Bus.__init__`'s "no token" BusError path.
    let token = std::env::var("AGENT_BUS_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Err("missing AGENT_BUS_TOKEN: export it (this slice takes no --token flag)".into());
    }
    let host = std::env::var("AGENT_BUS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("AGENT_BUS_PORT").unwrap_or_else(|_| "8379".to_string());
    // Address selection (coherent with legacy `bus --tcp` + `Bus.__init__`,
    // hardened to preserve TCP): `--tcp` forces TCP; else an explicitly
    // set non-empty `AGENT_BUS_SOCK` selects Unix; else TCP. Unlike legacy
    // existence-probing with a default path, an unset SOCK never selects
    // Unix, and Unix never silently falls back to TCP on dial failure.
    let unix_path = if FORCE_TCP.load(Ordering::SeqCst) {
        None
    } else {
        std::env::var("AGENT_BUS_SOCK")
            .ok()
            .filter(|s| !s.is_empty())
    };
    Ok(Config {
        addr: format!("{host}:{port}"),
        agent,
        token,
        unix_path,
    })
}

fn connect(cfg: &Config) -> Result<Client, String> {
    // `Client::connect*` sends hello and fails closed on refusal; the token
    // value never appears in the returned message (only the broker reply).
    if let Some(ref p) = cfg.unix_path {
        #[cfg(unix)]
        {
            return Client::connect_unix(std::path::Path::new(p), &cfg.agent, &cfg.token)
                .map_err(|e| format!("connect failed: {e}"));
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            return Err(
                "connect failed: unix sockets are not supported on this platform".to_string(),
            );
        }
    }
    Client::connect(&cfg.addr, &cfg.agent, &cfg.token).map_err(|e| format!("connect failed: {e}"))
}

fn connect_streaming(cfg: &Config) -> Result<StreamingConn, String> {
    if let Some(ref p) = cfg.unix_path {
        #[cfg(unix)]
        {
            return StreamingConn::connect_unix(std::path::Path::new(p), &cfg.agent, &cfg.token)
                .map_err(|e| format!("connect failed: {e}"));
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            return Err(
                "connect failed: unix sockets are not supported on this platform".to_string(),
            );
        }
    }
    StreamingConn::connect(&cfg.addr, &cfg.agent, &cfg.token)
        .map_err(|e| format!("connect failed: {e}"))
}

/// One connection worker for this single-command CLI process. It can only
/// dial and authenticate; no user request payload enters the worker. DNS,
/// Unix connect and hello may block independently of the request budget,
/// so the caller waits only until its absolute deadline. On timeout the
/// command returns immediately and main exits the process, ending any
/// remaining worker. This is deliberately not a reusable library worker
/// pool or a helper that callers can repeatedly abandon in a long-lived
/// process. Credentials remain in memory and are never logged.
fn connect_request_before(
    cfg: &Config,
    deadline: std::time::Instant,
) -> Result<StreamingConn, String> {
    let timed_out = || "request connection setup timed out; no request posted".to_string();
    if std::time::Instant::now() >= deadline {
        return Err(timed_out());
    }
    let cfg = cfg.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let _worker = std::thread::Builder::new()
        .name("request-connect".to_string())
        .spawn(move || {
            let result = connect_streaming(&cfg);
            // If the receiver has gone away, dropping this result also
            // closes any connection that completed after the deadline.
            let _ = sender.send(result);
        })
        .map_err(|e| format!("connection worker could not start: {e}; no request posted"))?;
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(timed_out)?;
    match receiver.recv_timeout(remaining) {
        Ok(result) if std::time::Instant::now() < deadline => result,
        Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(timed_out()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("connection worker ended without a result; no request posted".to_string())
        }
    }
}

/// One RPC: transport errors and broker `{"error": ...}` replies both become
/// `Err` strings safe for stderr (never containing the token).
fn rpc(client: &mut Client, req: &Value) -> Result<Value, String> {
    match client.rpc(req) {
        Ok(resp) => rpc_response(resp),
        Err(e) => Err(e.to_string()),
    }
}

/// Ordered `token_issue` RPC preserving `--topic-rate` flag order on the wire
/// (first-match policy). Same error mapping as [`rpc`].
fn rpc_ordered(
    client: &mut Client,
    req: &Value,
    ordered: &[(String, Value)],
) -> Result<Value, String> {
    match client.rpc_with_ordered_topic_rates(req, ordered) {
        Ok(resp) => rpc_response(resp),
        Err(e) => Err(e.to_string()),
    }
}

fn rpc_response(resp: Value) -> Result<Value, String> {
    if let Some(err) = resp.get("error") {
        return Err(err_text(err));
    }
    if resp.get("ok") == Some(&json!(true)) {
        return Ok(resp);
    }
    Err(format!("unexpected response: {}", compact(&resp)))
}

fn err_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        _ => compact(v),
    }
}

fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// JSON-or-text payload semantics (`bus.payload`: parse, fall back to string).
fn parse_payload(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_string()))
}

fn read_stdin() -> Result<String, String> {
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
        .map_err(|e| format!("stdin read failed: {e}"))?;
    Ok(buf)
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    if *i >= args.len() {
        return Err(format!("error: {flag} needs a value"));
    }
    Ok(args[*i].clone())
}

// ---------------------------------------------------------------------------
// show: exact-topic snapshot drain over fetch (pinned until_seq)
// ---------------------------------------------------------------------------

const SHOW_USAGE: &str = "usage: agent-bus show TOPIC (--since-seq N | --last N) [--format json|short|payload] [--sender NAME ...]\n\
 \n\
 Drains one bounded snapshot starting after N (0 starts history), pinning\n\
 until_seq to the first page's snapshot_seq so concurrent posts cannot shift\n\
 or truncate the window mid-drain. Retention gaps print a warning and exit 2,\n\
 except --last with a fully-populated tail (true tail, exits 0).\n\
 --last N drains from history and prints only the last N rendered rows\n\
 (client-side tail; sender filtering applies before slicing). Seq fetches\n\
 and --tail need live subscribe replay (see `sub`); this finite fetch path\n\
 keeps `fetch`, never streams.\n";

struct HistoryPage {
    messages: Vec<Value>,
    snapshot_seq: u64,
    next_seq: u64,
    has_more: bool,
    gap: bool,
    missing: u64,
    missing_ranges: Value,
}

fn cmd_show(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{SHOW_USAGE}");
        return 0;
    }
    let mut topic: Option<String> = None;
    let mut since_seq: Option<i64> = None;
    let mut last: Option<i64> = None;
    let mut format = "short".to_string();
    let mut senders: Vec<String> = Vec::new();
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--since-seq" => match take_value(argv, &mut i, "--since-seq") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => since_seq = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --since-seq {v}: want >= 0");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--sender" => match take_value(argv, &mut i, "--sender") {
                Ok(v) => senders.push(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            // Accepted for compatibility: show already prints full text.
            "--full" => {}
            "--last" => match take_value(argv, &mut i, "--last") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => last = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --last {v}: want >= 1");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--tail" | "--count" => {
                eprintln!("error: show --tail needs live subscribe replay (see `sub`); use --last N for the tail or --since-seq N to resume");
                return 2;
            }
            "--seq" => {
                eprintln!(
                    "error: show seq fetches need live subscribe (see `sub`); use --since-seq N"
                );
                return 2;
            }
            "--since" => {
                eprintln!("error: show --since needs --tail (see `sub`); use --last N for the tail or --since-seq N to resume");
                return 2;
            }
            s if is_flag(s) => {
                eprintln!("error: unknown show option '{s}'\n{SHOW_USAGE}");
                return 2;
            }
            _ => {
                if topic.is_some() {
                    eprintln!("error: show takes a single topic plus --since-seq N or --last N (seq fetches need live subscribe, see `sub`)");
                    return 2;
                }
                topic = Some(a.to_string());
            }
        }
        i += 1;
    }
    let Some(topic) = topic else {
        eprintln!("error: show needs a topic\n{SHOW_USAGE}");
        return 2;
    };
    if topic.chars().any(|c| c == '*' || c == '?' || c == '[') {
        eprintln!("error: show needs a single topic, not a pattern");
        return 2;
    }
    let since: i64;
    let mut last_n: Option<u64> = None;
    match (since_seq, last) {
        (Some(s), None) => since = s,
        (None, Some(n)) => {
            if n < 1 {
                eprintln!("error: bad --last {n}: want >= 1");
                return 2;
            }
            since = 0;
            last_n = Some(n as u64);
        }
        (None, None) => {
            eprintln!("error: show needs --since-seq N or --last N in this slice (seq/--tail need live subscribe, see `sub`)");
            return 2;
        }
        (Some(_), Some(_)) => {
            eprintln!("error: show takes --since-seq N or --last N, not both");
            return 2;
        }
    }
    if since < 0 {
        eprintln!("error: bad --since-seq {since}: want >= 0");
        return 2;
    }
    if !["json", "short", "payload"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short|payload");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    show_history(&mut client, &topic, since as u64, &format, &senders, last_n)
}

/// Drain one bounded snapshot; checkpoint only processed pages.
/// Mirrors `bus.show_history`: stderr note on completion, stderr gap warning
/// per gapped page, exit 2 on any gap or incomplete catch-up — except a
/// fully-populated `--last` tail, which is the true tail and exits 0
/// (the warning stays; a short tail still exits 2).
/// `last_n` buffers rendered rows and prints only the tail (client-side
/// `--last`; filtering still applies before slicing).
fn show_history(
    client: &mut Client,
    topic: &str,
    from_seq: u64,
    format: &str,
    senders: &[String],
    last_n: Option<u64>,
) -> i32 {
    let mut cursor = from_seq;
    let mut snapshot: Option<u64> = None;
    let mut had_gap = false;
    let mut buffered: Vec<String> = Vec::new();
    loop {
        let mut req = json!({"op": "fetch", "topic": topic, "from_seq": cursor, "limit": 500});
        if let Some(s) = snapshot {
            req["until_seq"] = json!(s);
        }
        let resp = match client.rpc(&req) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "error: history catch-up incomplete on '{topic}': {e}; resume with --since-seq {cursor}"
                );
                return 2;
            }
        };
        if let Some(err) = resp.get("error") {
            eprintln!(
                "error: history catch-up incomplete on '{topic}': {}; resume with --since-seq {cursor}",
                err_text(err)
            );
            return 2;
        }
        let page = match validate_history(&resp, topic, cursor, snapshot) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "error: history catch-up incomplete on '{topic}': {e}; resume with --since-seq {cursor}"
                );
                return 2;
            }
        };
        snapshot = Some(page.snapshot_seq);
        for msg in &page.messages {
            if !senders.is_empty() {
                let sender = msg.get("sender").and_then(|s| s.as_str()).unwrap_or("");
                if !senders.iter().any(|s| s == sender) {
                    continue;
                }
            }
            if last_n.is_some() {
                buffered.push(render_frame(topic, msg, format));
            } else {
                print_frame(topic, msg, format);
            }
        }
        // Pagination progress follows all examined messages even when sender
        // filtering hides rows (legacy `show_history` checkpoint rule).
        cursor = page.next_seq;
        if page.gap {
            had_gap = true;
            eprintln!(
                "warning: retention gap or expired history on '{topic}': {} unavailable message(s), ranges {}; showing survivors",
                page.missing,
                compact(&page.missing_ranges)
            );
        }
        if !page.has_more {
            let mut printed = 0usize;
            if let Some(n) = last_n {
                let skip = buffered.len().saturating_sub(n as usize);
                for row in buffered.iter().skip(skip) {
                    println!("{row}");
                    printed += 1;
                }
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
            eprintln!("note: snapshot on '{topic}' processed through {cursor}; next: --since-seq {cursor}");
            // A retention gap fails resume reads (the requested
            // range is incomplete), but a fully-populated --last
            // tail is the true tail: retention only drops oldest
            // rows, so the N newest survivors are the N newest
            // rows in existence. The warning above stays; only a
            // short tail (some of the requested rows expired)
            // still exits 2.
            let tail_complete = last_n.is_some_and(|n| printed as u64 == n);
            return if had_gap && !tail_complete { 2 } else { 0 };
        }
    }
}

/// Strict client-side completeness check, ported from
/// `busclient.Bus.fetch_history`: the cursor must pin the snapshot across
/// pages, message seqs must be strictly increasing within (from_seq, next_seq],
/// and the broker's gap/missing claims must reconcile with delivered bytes.
/// Anything else is an explicit error, never silent success.
fn validate_history(
    resp: &Value,
    topic: &str,
    from_seq: u64,
    pinned: Option<u64>,
) -> Result<HistoryPage, String> {
    let cursor = resp.get("cursor").and_then(|c| c.as_object());
    let messages = resp.get("messages").and_then(|m| m.as_array());
    let (Some(cursor), Some(messages)) = (cursor, messages) else {
        return Err("invalid history response: completeness unknown".into());
    };
    let int = |key: &str| cursor.get(key).and_then(|v| v.as_u64());
    let (from, next, snap, head) = match (
        int("from_seq"),
        int("next_seq"),
        int("snapshot_seq"),
        int("topic_seq"),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return Err("invalid history response: completeness unknown".into()),
    };
    let (has_more, gap) = match (
        cursor.get("has_more").and_then(|v| v.as_bool()),
        cursor.get("gap").and_then(|v| v.as_bool()),
    ) {
        (Some(h), Some(g)) => (h, g),
        _ => return Err("invalid history response: completeness unknown".into()),
    };
    if resp.get("topic").and_then(|v| v.as_str()) != Some(topic)
        || from != from_seq
        || !(from <= next && next <= snap && snap <= head)
        || pinned.is_some_and(|p| snap != p)
        || (has_more && next <= from)
    {
        return Err("invalid history cursor: completeness unknown".into());
    }
    let mut prev = from;
    for msg in messages {
        let seq = msg.get("seq").and_then(|v| v.as_u64());
        match seq {
            Some(s) if prev < s && s <= next => prev = s,
            _ => return Err("invalid history message order: completeness unknown".into()),
        }
    }
    let missing_claim = cursor.get("missing").and_then(|v| v.as_u64());
    let ranges = cursor.get("missing_ranges");
    let missing = next - from - messages.len() as u64;
    if missing_claim != Some(missing)
        || gap != (missing > 0)
        || !ranges.is_some_and(|r| r.is_array())
        || (!has_more && next != snap)
        || (has_more && prev != next)
    {
        return Err("invalid history coverage: completeness unknown".into());
    }
    Ok(HistoryPage {
        messages: messages.clone(),
        snapshot_seq: snap,
        next_seq: next,
        has_more,
        gap,
        missing,
        missing_ranges: ranges.cloned().unwrap_or(Value::Null),
    })
}

fn render_frame(topic: &str, msg: &Value, format: &str) -> String {
    match format {
        "short" => short_frame(msg),
        "payload" => payload_text(msg),
        _ => compact(&json!({"event": "msg", "topic": topic, "msg": msg})),
    }
}

fn print_frame(topic: &str, msg: &Value, format: &str) {
    println!("{}", render_frame(topic, msg, format));
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

// ---------------------------------------------------------------------------
// post
// ---------------------------------------------------------------------------

const POST_USAGE: &str = "usage: agent-bus post TOPIC [PAYLOAD] [--durable] [--ttl-ms N] [--corr C] [--reply-to R] [--msg-id ID]\n\
       agent-bus post TOPIC (--note TEXT [--event E] | --claim F,.. --task T | --release F,.. --task T)\n\
 \n\
 PAYLOAD of '-' reads stdin (JSON when it parses, else plain text, newlines\n\
 preserved). --durable asks the broker to fsync before ack.\n\
 --msg-id sets an explicit retry id: same sender/topic/id/payload returns\n\
 the original {id, seq} with dup:true instead of a new message; a\n\
 conflicting reuse is refused. Omit it for the old auto-id behavior.\n";

fn cmd_post(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{POST_USAGE}");
        return 0;
    }
    let mut topic: Option<String> = None;
    let mut payload_arg: Option<String> = None;
    let mut note: Option<String> = None;
    let mut event: Option<String> = None;
    let mut claim: Option<String> = None;
    let mut release: Option<String> = None;
    let mut task = String::new();
    let mut durable = false;
    let mut ttl_ms: Option<f64> = None;
    let mut corr: Option<String> = None;
    let mut reply_to: Option<String> = None;
    let mut msg_id: Option<String> = None;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--note" => match take_value(argv, &mut i, "--note") {
                Ok(v) => note = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--event" => match take_value(argv, &mut i, "--event") {
                Ok(v) => event = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--claim" => match take_value(argv, &mut i, "--claim") {
                Ok(v) => claim = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--release" => match take_value(argv, &mut i, "--release") {
                Ok(v) => release = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--task" => match take_value(argv, &mut i, "--task") {
                Ok(v) => task = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--durable" => durable = true,
            "--ttl-ms" => match take_value(argv, &mut i, "--ttl-ms") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(n) => ttl_ms = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --ttl-ms {v}: want a number");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--corr" => match take_value(argv, &mut i, "--corr") {
                Ok(v) => corr = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--reply-to" => match take_value(argv, &mut i, "--reply-to") {
                Ok(v) => reply_to = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--msg-id" => match take_value(argv, &mut i, "--msg-id") {
                Ok(v) => msg_id = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown post option '{s}'\n{POST_USAGE}");
                return 2;
            }
            _ => {
                if topic.is_none() {
                    topic = Some(a.to_string());
                } else if payload_arg.is_none() {
                    payload_arg = Some(a.to_string());
                } else {
                    eprintln!("error: post takes TOPIC and one PAYLOAD\n{POST_USAGE}");
                    return 2;
                }
            }
        }
        i += 1;
    }
    let Some(topic) = topic else {
        eprintln!("error: post needs a topic\n{POST_USAGE}");
        return 2;
    };
    // Mutual exclusion mirrors `bus post` (exit 1 there, kept here).
    let given = [
        payload_arg.is_some(),
        note.is_some(),
        claim.is_some(),
        release.is_some(),
    ];
    if given.iter().filter(|g| **g).count() > 1 {
        eprintln!("error: payload, --note, --claim and --release are mutually exclusive");
        return 1;
    }
    // Strictness divergence from legacy (which silently ignores --event with
    // a plain payload and --task without claim/release): an explicitly passed
    // flag must not vanish.
    if event.is_some() && note.is_none() {
        eprintln!("error: --event needs --note");
        return 2;
    }
    if !task.is_empty() && claim.is_none() && release.is_none() {
        eprintln!("error: --task needs --claim or --release");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let payload = if let Some(n) = note {
        let mut p = json!({"from": cfg.agent, "note": n});
        if let Some(e) = event {
            p["event"] = json!(e);
        }
        p
    } else if claim.is_some() || release.is_some() {
        let is_claim = claim.is_some();
        let which = claim.or(release).unwrap_or_default();
        let files: Vec<Value> = which
            .split(',')
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(|f| json!(f))
            .collect();
        json!({
            "from": cfg.agent,
            "event": if is_claim { "claim" } else { "release" },
            "task": task,
            "files": files,
        })
    } else if let Some(p) = payload_arg {
        if p == "-" {
            match read_stdin() {
                Ok(s) => parse_payload(&s),
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            }
        } else {
            parse_payload(&p)
        }
    } else {
        eprintln!("error: post needs a payload, --note, --claim or --release");
        return 1;
    };
    let mut req = json!({"op": "post", "topic": topic, "payload": payload});
    if durable {
        req["durable"] = json!(true);
    }
    if let Some(t) = ttl_ms {
        req["ttl_ms"] = json!(t);
    }
    if let Some(c) = corr {
        req["corr_id"] = json!(c);
    }
    if let Some(r) = reply_to {
        req["reply_to"] = json!(r);
    }
    if let Some(m) = msg_id {
        req["msg_id"] = json!(m);
    }
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &req) {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// request / reply (correlated inbox workflows over StreamingConn)
// ---------------------------------------------------------------------------

const REQUEST_USAGE: &str =
    "usage: agent-bus request TARGET PAYLOAD [--timeout S] [--format json|payload]\n\
 \n\
 Ask agent TARGET something: posts PAYLOAD to inbox.TARGET with a fresh\n\
 corr_id and reply_to=inbox.<self>, then waits on inbox.<self> for the\n\
 reply with the same corr_id. PAYLOAD of '-' reads stdin (bounded\n\
 8 MiB, JSON when it parses, else plain text). --timeout S (default 10,\n\
 positive finite seconds) is one end-to-end budget for setup/post/wait;\n\
 --format json prints the full reply msg, payload prints only its payload.\n\
 A broker receipt proves storage only, never peer acceptance. Timeout\n\
 reports the accepted post (seq/id) and no matching reply yet; it never\n\
 asserts the peer failed nor tells the caller to blindly resend. Inspect\n\
 history before resending; this command never retries automatically.\n";

const REPLY_USAGE: &str = "usage: agent-bus reply DEST_TOPIC CORR_ID PAYLOAD\n\
 \n\
 Post PAYLOAD to DEST_TOPIC with corr_id=CORR_ID (usually the request's\n\
 reply_to and corr_id). PAYLOAD of '-' reads stdin (bounded 8 MiB).\n\
 Prints the broker receipt. A receipt proves storage only.\n";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    s
}

#[cfg(unix)]
fn read_urandom16() -> std::io::Result<[u8; 16]> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut buf = [0u8; 16];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Fresh correlation id, 32 hex chars (uuid-like length, not auth).
/// Uses native OS randomness (`/dev/urandom` on Unix) and fails closed
/// when unavailable; no predictable time/PID fallback. Correlation is
/// routing, not authorization. No interpreter, no new dependency.
fn new_corr_id() -> Result<String, String> {
    #[cfg(unix)]
    {
        match read_urandom16() {
            Ok(b) => Ok(hex_encode(&b)),
            Err(e) => Err(format!("correlation randomness unavailable: {e}")),
        }
    }
    #[cfg(not(unix))]
    {
        Err("correlation randomness unavailable on this platform".to_string())
    }
}

/// Bounded stdin text (`CLIENT_RESP_LIMIT` bytes max). Fails closed on
/// IO error, oversize, or invalid UTF-8; never reads unbounded.
fn read_stdin_bounded(limit: usize) -> Result<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    let cap = limit.saturating_add(1) as u64;
    std::io::stdin()
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| format!("stdin read failed: {e}"))?;
    if buf.len() > limit {
        return Err(format!("stdin payload exceeds {limit} byte limit"));
    }
    String::from_utf8(buf).map_err(|_| "stdin payload is not valid UTF-8".to_string())
}

fn cmd_request(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("{REQUEST_USAGE}");
        return 0;
    }
    let mut target: Option<String> = None;
    let mut payload_arg: Option<String> = None;
    let mut timeout: f64 = 10.0;
    let mut format = "json".to_string();
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--timeout" {
            match take_value(argv, &mut i, "--timeout") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(n) if n.is_finite() && n > 0.0 => timeout = n,
                    _ => {
                        eprintln!("error: bad --timeout {v}: want positive seconds");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown request option '{a}'\n{REQUEST_USAGE}");
            return 2;
        }
        if target.is_none() {
            target = Some(a.to_string());
        } else if payload_arg.is_none() {
            payload_arg = Some(a.to_string());
        } else {
            eprintln!("error: request takes TARGET and one PAYLOAD\n{REQUEST_USAGE}");
            return 2;
        }
        i += 1;
    }
    let Some(target) = target else {
        eprintln!("error: request needs TARGET and PAYLOAD\n{REQUEST_USAGE}");
        return 2;
    };
    let Some(payload_arg) = payload_arg else {
        eprintln!("error: request needs TARGET and PAYLOAD\n{REQUEST_USAGE}");
        return 2;
    };
    if target.is_empty() {
        eprintln!("error: request TARGET must not be empty");
        return 2;
    }
    if target
        .chars()
        .any(|c| c == '*' || c == '?' || c == '[' || c.is_whitespace())
    {
        eprintln!("error: request TARGET must be a bare agent name, not a pattern");
        return 2;
    }
    if !["json", "payload"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|payload");
        return 2;
    }
    let timeout_dur = match std::time::Duration::try_from_secs_f64(timeout) {
        Ok(d) if !d.is_zero() && std::time::Instant::now().checked_add(d).is_some() => d,
        _ => {
            eprintln!("error: --timeout is outside the supported clock range");
            return 2;
        }
    };
    let limit = agent_bus::wire::CLIENT_RESP_LIMIT;
    let payload_value = if payload_arg == "-" {
        match read_stdin_bounded(limit) {
            Ok(s) => parse_payload(&s),
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    } else {
        if payload_arg.len() > limit {
            eprintln!("error: payload exceeds {limit} byte limit");
            return 1;
        }
        parse_payload(&payload_arg)
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let inbox_self = format!("inbox.{}", cfg.agent);
    let dest_topic = format!("inbox.{target}");
    let corr = match new_corr_id() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let Some(deadline) = std::time::Instant::now().checked_add(timeout_dur) else {
        eprintln!("error: --timeout is outside the supported clock range");
        return 2;
    };
    let remaining_budget = || deadline.checked_duration_since(std::time::Instant::now());
    let rpc_cap = agent_bus::wire::CLIENT_RPC_TIMEOUT;
    // This exclusive connection owns the subscription. Every return drops
    // it, releasing the subscription without an extra cleanup RPC that
    // could extend the wait beyond the request deadline.
    let mut conn = match connect_request_before(&cfg, deadline) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    conn.set_deadline(deadline);
    let head = {
        let Some(rem) = remaining_budget().filter(|d| !d.is_zero()) else {
            eprintln!(
                "error: request to {target} timed out during setup before post within {timeout}s \
                 (no storage claimed); inspect '{dest_topic}' history before sending"
            );
            return 1;
        };
        if let Err(e) = conn.set_rpc_timeout(rem.min(rpc_cap)) {
            eprintln!("error: {e}");
            return 1;
        }
        match conn
            .rpc(&json!({"op": "topics"}))
            .map_err(|e| e.to_string())
            .and_then(rpc_response)
        {
            Ok(listed) => {
                let mut head = 0u64;
                let Some(topics) = listed.get("topics").and_then(|v| v.as_array()) else {
                    eprintln!(
                        "error: inbox head response is missing its topics array; no request posted"
                    );
                    return 1;
                };
                for t in topics {
                    if t.get("topic").and_then(|v| v.as_str()) == Some(inbox_self.as_str()) {
                        let Some(seq) = t.get("seq").and_then(|v| v.as_u64()) else {
                            eprintln!("error: inbox head response has no valid sequence; no request posted");
                            return 1;
                        };
                        head = seq;
                        break;
                    }
                }
                head
            }
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    };
    let (sub_id, _replayed, _cursor) = {
        let Some(rem) = remaining_budget().filter(|d| !d.is_zero()) else {
            eprintln!(
                "error: request to {target} timed out during setup before post within {timeout}s \
                 (no storage claimed); inspect '{dest_topic}' history before sending"
            );
            return 1;
        };
        if let Err(e) = conn.set_rpc_timeout(rem.min(rpc_cap)) {
            eprintln!("error: {e}");
            return 1;
        }
        match conn.subscribe(&inbox_self, head, 0) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    };
    let post_req = json!({
        "op": "post", "topic": dest_topic, "payload": payload_value,
        "corr_id": corr, "reply_to": inbox_self,
    });
    let receipt = {
        let Some(rem) = remaining_budget().filter(|d| !d.is_zero()) else {
            eprintln!(
                "error: request to {target} timed out during setup before post within {timeout}s \
                 (no storage claimed); inspect '{dest_topic}' history before sending"
            );
            return 1;
        };
        if let Err(e) = conn.set_rpc_timeout(rem.min(rpc_cap)) {
            eprintln!("error: {e}; no request posted");
            return 1;
        }
        match conn.rpc(&post_req) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "error: request post uncertain (no broker receipt): {e}; \
                     inspect '{dest_topic}' history for corr_id {corr} before resending; \
                     this command never retries automatically"
                );
                return 1;
            }
        }
    };
    if let Some(err) = receipt.get("error") {
        eprintln!("error: {}", err_text(err));
        return 1;
    }
    if receipt.get("ok") != Some(&json!(true)) {
        eprintln!(
            "error: request post uncertain: invalid broker receipt; \
             inspect '{dest_topic}' history for corr_id {corr} before resending"
        );
        return 1;
    }
    let (Some(seq_s), Some(id_s)) = (
        receipt.get("seq").and_then(Value::as_u64),
        receipt
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty()),
    ) else {
        eprintln!(
            "error: request post uncertain: broker receipt lacks message identity; \
             inspect '{dest_topic}' history for corr_id {corr} before resending"
        );
        return 1;
    };
    let max_unrelated = agent_bus::subs::SUBS_QUEUE_MAX;
    let mut unrelated: usize = 0;
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match conn.recv(Some(remaining)) {
            Ok(fr) => {
                let got = fr
                    .get("msg")
                    .and_then(|m| m.get("corr_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if got == corr
                    && fr.get("sub_id").and_then(Value::as_str) == Some(sub_id.as_str())
                    && fr.get("topic").and_then(Value::as_str) == Some(inbox_self.as_str())
                {
                    let msg = fr.get("msg").cloned().unwrap_or(Value::Null);
                    if format == "payload" {
                        println!("{}", payload_text(&msg));
                    } else {
                        println!("{}", compact(&msg));
                    }
                    return 0;
                }
                unrelated += 1;
                if unrelated >= max_unrelated {
                    eprintln!(
                        "error: request to {target} accepted (post seq {seq_s} id {id_s}) \
                         but {max_unrelated} unrelated inbox messages arrived without a \
                         matching reply; check '{inbox_self}' for corr_id {corr} before resending"
                    );
                    return 1;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => {
                eprintln!(
                    "error: request to {target} accepted (post seq {seq_s} id {id_s} to {dest_topic}) \
                     but the reply wait failed: {e}; no matching reply received yet; \
                     a broker receipt proves storage only, not peer acceptance; \
                     check '{inbox_self}' for corr_id {corr} before resending"
                );
                return 1;
            }
        }
    }
    eprintln!(
        "error: request to {target} accepted (post seq {seq_s} id {id_s} to {dest_topic}) \
         but no reply with corr_id {corr} within {timeout}s; \
         a broker receipt proves storage only, not peer acceptance; \
         the peer may reply later on '{inbox_self}'; inspect before resending"
    );
    1
}

fn cmd_reply(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("{REPLY_USAGE}");
        return 0;
    }
    let mut dest: Option<String> = None;
    let mut corr: Option<String> = None;
    let mut payload_arg: Option<String> = None;
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown reply option '{a}'\n{REPLY_USAGE}");
            return 2;
        }
        if dest.is_none() {
            dest = Some(a.to_string());
        } else if corr.is_none() {
            corr = Some(a.to_string());
        } else if payload_arg.is_none() {
            payload_arg = Some(a.to_string());
        } else {
            eprintln!("error: reply takes DEST_TOPIC CORR_ID and one PAYLOAD\n{REPLY_USAGE}");
            return 2;
        }
        i += 1;
    }
    let Some(dest) = dest else {
        eprintln!("error: reply needs DEST_TOPIC CORR_ID PAYLOAD\n{REPLY_USAGE}");
        return 2;
    };
    let Some(corr) = corr else {
        eprintln!("error: reply needs DEST_TOPIC CORR_ID PAYLOAD\n{REPLY_USAGE}");
        return 2;
    };
    let Some(payload_arg) = payload_arg else {
        eprintln!("error: reply needs DEST_TOPIC CORR_ID PAYLOAD\n{REPLY_USAGE}");
        return 2;
    };
    if dest.is_empty() {
        eprintln!("error: reply DEST_TOPIC must not be empty");
        return 2;
    }
    if dest.chars().any(|c| c == '*' || c == '?' || c == '[') {
        eprintln!("error: reply DEST_TOPIC must be a single topic, not a pattern");
        return 2;
    }
    if corr.is_empty() {
        eprintln!("error: reply CORR_ID must not be empty");
        return 2;
    }
    let limit = agent_bus::wire::CLIENT_RESP_LIMIT;
    let payload_value = if payload_arg == "-" {
        match read_stdin_bounded(limit) {
            Ok(s) => parse_payload(&s),
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    } else {
        if payload_arg.len() > limit {
            eprintln!("error: payload exceeds {limit} byte limit");
            return 1;
        }
        parse_payload(&payload_arg)
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let req = json!({"op": "post", "topic": dest, "payload": payload_value, "corr_id": corr});
    match rpc(&mut client, &req) {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// sub / subs / unsubscribe (live streams over StreamingConn)
// ---------------------------------------------------------------------------

const SUB_USAGE: &str = "usage: agent-bus sub PATTERN [--from-seq N] [--tail N] [--count N] [--timeout S] [--format json|short|payload] [--once] [--new-only] [--follow] [--since AGE] [--full] [--maxlen N]\n\
 \n\
 PATTERN is exact or glob (`*?[` wildcards, conservative grant cover).\n\
 --from-seq N replays after N (0 replays retained history); --tail N replays\n\
 only the last N per topic. Bare --tail N peeks latest N then exits (sets\n\
 --count N + --once); add --follow to keep following after the replay.\n\
 --once exits after the replay backlog drains (broker `replayed` count).\n\
 --new-only skips replay (single topic only, waits for new posts).\n\
 --count N caps printed lines (0 infinite); --timeout S exits 0 after S\n\
 idle seconds per message (default: infinite unless --once, then 2s).\n\
 --since AGE (90s/30m/2h/1d, bare number seconds) filters to fresh frames.\n\
 --format short truncates payload text to 240 chars unless --full; --maxlen N\n\
 truncates whole short lines to N chars. Always unsubscribes on exit.\n";

fn cmd_sub(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{SUB_USAGE}");
        return 0;
    }
    let mut pattern: Option<String> = None;
    let mut from_seq: i64 = 0;
    let mut tail: i64 = 0;
    let mut count: i64 = 0;
    let mut timeout: Option<f64> = None;
    let mut format = "json".to_string();
    let mut once = false;
    let mut new_only = false;
    let mut follow = false;
    let mut since: Option<String> = None;
    let mut full = false;
    let mut maxlen: i64 = 0;
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--from-seq" => match take_value(argv, &mut i, "--from-seq") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => from_seq = n,
                    Err(_) => {
                        eprintln!("error: bad --from-seq {v}: want >= 0");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--tail" => match take_value(argv, &mut i, "--tail") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => tail = n,
                    Err(_) => {
                        eprintln!("error: bad --tail {v}: want >= 0");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--count" => match take_value(argv, &mut i, "--count") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => count = n,
                    Err(_) => {
                        eprintln!("error: bad --count {v}: want >= 0");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--timeout" => match take_value(argv, &mut i, "--timeout") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(n) if n.is_finite() && n > 0.0 => timeout = Some(n),
                    _ => {
                        eprintln!("error: bad --timeout {v}: want positive seconds");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--once" => once = true,
            "--new-only" => new_only = true,
            "--follow" => follow = true,
            "--since" => match take_value(argv, &mut i, "--since") {
                Ok(v) => since = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--full" => full = true,
            "--maxlen" => match take_value(argv, &mut i, "--maxlen") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => maxlen = n,
                    Err(_) => {
                        eprintln!("error: bad --maxlen {v}: want >= 0");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown sub option '{s}'\n{SUB_USAGE}");
                return 2;
            }
            _ => {
                if pattern.is_some() {
                    eprintln!("error: sub takes one PATTERN\n{SUB_USAGE}");
                    return 2;
                }
                pattern = Some(argv[i].clone());
            }
        }
        i += 1;
    }
    let Some(pattern) = pattern else {
        eprintln!("error: sub needs a PATTERN\n{SUB_USAGE}");
        return 2;
    };
    if from_seq < 0 {
        eprintln!("error: bad --from-seq {from_seq}: want >= 0");
        return 2;
    }
    if tail < 0 {
        eprintln!("error: bad --tail {tail}: want >= 0");
        return 2;
    }
    if count < 0 {
        eprintln!("error: bad --count {count}: want >= 0");
        return 2;
    }
    if maxlen < 0 {
        eprintln!("error: bad --maxlen {maxlen}: want >= 0");
        return 2;
    }
    if !["json", "short", "payload"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short|payload");
        return 2;
    }
    if new_only && pattern.chars().any(|c| c == '*' || c == '?' || c == '[') {
        eprintln!("error: --new-only needs a single topic, not a pattern");
        return 1;
    }
    // Bare --tail N peeks latest N then exits (legacy surprise fix).
    if tail > 0 && count == 0 && !follow && !once {
        count = tail;
        once = true;
    }
    let cutoff = match since.as_deref() {
        None => None,
        Some(s) => match parse_age(s) {
            Ok(secs) => Some(now_secs() - secs),
            Err(e) => {
                eprintln!("error: bad --since value: {e}");
                return 1;
            }
        },
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    // Pattern-matches-no-topics note (best-effort, like legacy).
    if let Ok(mut probe) = connect(&cfg) {
        if let Ok(listed) = rpc(&mut probe, &json!({"op": "topics"})) {
            if !pattern_matches_topics(&pattern, &listed) {
                eprintln!(
                    "note: pattern '{pattern}' matches no existing topics (see 'agent-bus topics')"
                );
            }
        }
    }
    // --new-only: from_seq = latest head (0 when empty), no tail.
    let (mut from_seq_u, mut tail_u) = (from_seq as u64, tail as u64);
    if new_only {
        match latest_seq(&cfg, &pattern) {
            Ok(n) => {
                from_seq_u = n;
                tail_u = 0;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    }
    let mut conn = match connect_streaming(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let (sub_id, replayed, _cursor) = match conn.subscribe(&pattern, from_seq_u, tail_u) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let limit: Option<u64> = if once { Some(replayed) } else { None };
    // Per-message wait: explicit --timeout, else infinite unless --once (2s drain).
    let drain = match (timeout, once) {
        (Some(s), _) => Some(std::time::Duration::from_secs_f64(s)),
        (None, false) => None,
        (None, true) => Some(std::time::Duration::from_secs(2)),
    };
    let mut n_printed: u64 = 0;
    let mut received: u64 = 0;
    loop {
        let fr = match conn.recv(drain) {
            Ok(fr) => fr,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => {
                eprintln!("error: stream failed: {e}");
                let _ = conn.unsubscribe(&sub_id);
                return 1;
            }
        };
        received += 1;
        if let Some(cut) = cutoff {
            if !frame_fresh(&fr, cut) {
                if let Some(lim) = limit {
                    if received >= lim {
                        break;
                    }
                }
                continue;
            }
        }
        let msg = fr.get("msg").cloned().unwrap_or(Value::Null);
        match format.as_str() {
            "short" => {
                let mut line = short_frame_width(&msg, if full { None } else { Some(240) });
                if maxlen > 0 && line.len() > maxlen as usize {
                    line.truncate(maxlen as usize);
                }
                println!("{line}");
            }
            "payload" => println!("{}", payload_text(&msg)),
            _ => println!("{}", compact(&fr)),
        }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        n_printed += 1;
        if count > 0 && n_printed >= count as u64 {
            break;
        }
        if let Some(lim) = limit {
            if received >= lim {
                break;
            }
        }
    }
    if count > 0
        && n_printed >= count as u64
        && tail == 0
        && from_seq == 0
        && !new_only
        && received < replayed
    {
        eprintln!("note: --count {count} capped oldest-first replay ({replayed} buffered); use --tail N for latest");
    }
    let _ = conn.unsubscribe(&sub_id);
    0
}

fn cmd_subs(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus subs [--format json|short]\n");
        return 0;
    }
    let mut format = "json".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown subs option '{s}'");
                return 2;
            }
            _ => {
                eprintln!("error: subs takes no PATTERN");
                return 2;
            }
        }
        i += 1;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "subs"})) {
        Ok(resp) => {
            if format == "short" {
                println!("{}", short_subs(&resp));
            } else {
                println!("{}", compact(&resp));
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_unsubscribe(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus unsubscribe SUB_ID\n");
        return 0;
    }
    let mut sub_id: Option<String> = None;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if is_flag(a) {
            eprintln!("error: unknown unsubscribe option '{a}'");
            return 2;
        }
        if sub_id.is_some() {
            eprintln!("error: unsubscribe takes one SUB_ID");
            return 2;
        }
        sub_id = Some(argv[i].clone());
        i += 1;
    }
    let Some(sub_id) = sub_id else {
        eprintln!("error: unsubscribe needs a SUB_ID");
        return 2;
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    // Idempotent ok (per-connection isolation: foreign/unknown ids are
    // no-ops, never errors). Single attempt, no retry.
    match rpc(&mut client, &json!({"op": "unsubscribe", "sub_id": sub_id})) {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// heartbeat + agents
// ---------------------------------------------------------------------------

fn cmd_heartbeat(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus heartbeat [STATUS]\n");
        return 0;
    }
    let mut status = "online".to_string();
    let mut positional = 0;
    for a in argv.iter().skip(2) {
        if is_flag(a) {
            eprintln!("error: unknown heartbeat option '{a}'");
            return 2;
        }
        positional += 1;
        if positional > 1 {
            eprintln!("error: heartbeat takes one STATUS");
            return 2;
        }
        status = a.clone();
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "heartbeat", "status": status})) {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

const AGENTS_USAGE: &str = "usage: agent-bus agents [--format short|json]\n";

fn cmd_agents(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{AGENTS_USAGE}");
        return 0;
    }
    let mut format = "short".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--hide-stale" | "--fresh-first" | "--sort-name" | "--limit" => {
                eprintln!(
                    "error: agents {} is not supported in this slice (only --format short|json)",
                    argv[i]
                );
                return 2;
            }
            s if is_flag(s) => {
                eprintln!("error: unknown agents option '{s}'\n{AGENTS_USAGE}");
                return 2;
            }
            s => {
                eprintln!("error: agents takes no positional argument (got '{s}')\n{AGENTS_USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want short|json");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "agents"})) {
        Ok(resp) => {
            if format == "short" {
                // Fresh-first ordering matches the legacy default.
                eprintln!("note: agents shows heartbeat text, not task state; use `agent-bus runs` for scheduler reports");
                println!("{}", short_agents(&resp));
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| compact(&resp))
                );
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// kv-get / kv-put / kv-list
// ---------------------------------------------------------------------------

fn cmd_kv_get(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus kv-get KEY [--format json|short]\n");
        return 0;
    }
    let mut key: Option<String> = None;
    let mut format = "json".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown kv-get option '{s}'");
                return 2;
            }
            _ => {
                if key.is_some() {
                    eprintln!("error: kv-get takes one KEY");
                    return 2;
                }
                key = Some(argv[i].clone());
            }
        }
        i += 1;
    }
    let Some(key) = key else {
        eprintln!("error: kv-get needs a KEY");
        return 2;
    };
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "kv_get", "key": key})) {
        Ok(resp) => {
            if format == "short" {
                match short_kv(&resp) {
                    Some(text) => {
                        println!("{text}");
                        0
                    }
                    None => {
                        eprintln!("error: key '{key}' not found");
                        1
                    }
                }
            } else {
                println!("{}", compact(&resp));
                0
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_kv_put(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus kv-put KEY VALUE [--durable] [--ttl-ms N]\n");
        return 0;
    }
    let mut positionals: Vec<String> = Vec::new();
    let mut durable = false;
    let mut ttl_ms: Option<f64> = None;
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--durable" => durable = true,
            "--ttl-ms" => match take_value(argv, &mut i, "--ttl-ms") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(n) => ttl_ms = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --ttl-ms {v}: want a number");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown kv-put option '{s}'");
                return 2;
            }
            _ => positionals.push(argv[i].clone()),
        }
        i += 1;
    }
    if positionals.len() != 2 {
        eprintln!("error: kv-put needs KEY and VALUE ('-' reads stdin)");
        return 2;
    }
    let value = if positionals[1] == "-" {
        match read_stdin() {
            Ok(s) => parse_payload(&s),
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    } else {
        parse_payload(&positionals[1])
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut req = json!({"op": "kv_put", "key": positionals[0], "value": value});
    if durable {
        req["durable"] = json!(true);
    }
    if let Some(t) = ttl_ms {
        req["ttl_ms"] = json!(t);
    }
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &req) {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_kv_del(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("usage: agent-bus kv-del KEY [--durable]\n");
        return 0;
    }
    let mut key = None;
    let mut durable = false;
    let mut literal = false;
    for arg in &argv[2..] {
        if !literal && arg == "--" {
            literal = true;
            continue;
        }
        match arg.as_str() {
            "--durable" if !literal => durable = true,
            s if !literal && is_flag(s) => {
                eprintln!("error: unknown kv-del option '{s}'");
                return 2;
            }
            _ if key.is_none() => key = Some(arg.as_str()),
            _ => {
                eprintln!("error: kv-del takes one KEY");
                return 2;
            }
        }
    }
    let Some(key) = key else {
        eprintln!("error: kv-del needs a KEY");
        return 2;
    };
    let cfg = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut request = json!({"op":"kv_del", "key":key});
    if durable {
        request["durable"] = json!(true);
    }
    // Mutations are single-attempt: a missing receipt leaves the outcome
    // uncertain, so the caller must inspect state before retrying.
    match rpc(&mut client, &request) {
        Ok(reply) if reply["key"].as_str() == Some(key) && reply["found"].is_boolean() => {
            println!("{}", compact(&reply));
            0
        }
        Ok(_) => {
            eprintln!("error: invalid kv-del receipt (expected matching key and boolean found)");
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_kv_list(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus kv-list [PREFIX] [--format json|short] [--values]\n");
        return 0;
    }
    let mut prefix = String::new();
    let mut format = "json".to_string();
    let mut values = false;
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--values" => values = true,
            s if is_flag(s) => {
                eprintln!("error: unknown kv-list option '{s}'");
                return 2;
            }
            _ => {
                if !prefix.is_empty() {
                    eprintln!("error: kv-list takes one PREFIX");
                    return 2;
                }
                prefix = argv[i].clone();
            }
        }
        i += 1;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let resp = match rpc(&mut client, &json!({"op": "kv_list", "prefix": prefix})) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if !values {
        if format == "short" {
            println!("{}", short_kv_list(&resp));
        } else {
            println!("{}", compact(&resp));
        }
        return 0;
    }
    // --values: fetch each key (legacy `bus kv-list --values` fan-out).
    let keys: Vec<String> = resp
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|ks| {
            ks.iter()
                .filter_map(|k| k.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut items: Vec<(String, bool, Value)> = Vec::new();
    for key in &keys {
        match rpc(&mut client, &json!({"op": "kv_get", "key": key})) {
            Ok(got) => {
                let found = got.get("found").and_then(|v| v.as_bool()).unwrap_or(false);
                let value = got.get("value").cloned().unwrap_or(Value::Null);
                items.push((key.clone(), found, value));
            }
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    }
    if format == "short" {
        println!("{}", short_kv_values(&items));
    } else {
        let mut map = serde_json::Map::new();
        for (k, found, v) in &items {
            if *found {
                map.insert(k.clone(), v.clone());
            }
        }
        println!("{}", compact(&json!({"keys": keys, "values": map})));
    }
    0
}

// ---------------------------------------------------------------------------
// stats / topics / limits (source-backed introspection)
// ---------------------------------------------------------------------------

fn cmd_stats(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus stats [--format json|short]\n");
        return 0;
    }
    let mut format = "json".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown stats option '{s}'");
                return 2;
            }
            s => {
                eprintln!("error: stats takes no positional argument (got '{s}')");
                return 2;
            }
        }
        i += 1;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "stats"})) {
        Ok(resp) => {
            if format == "short" {
                println!("{}", short_stats(&resp));
            } else {
                println!("{}", compact(&resp));
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_topics(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus topics [--format json|short]\n");
        return 0;
    }
    let mut format = "json".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown topics option '{s}'");
                return 2;
            }
            s => {
                eprintln!("error: topics takes no positional argument (got '{s}')");
                return 2;
            }
        }
        i += 1;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "topics"})) {
        Ok(resp) => {
            if format == "short" {
                println!("{}", short_topics(&resp, now_secs()));
            } else {
                println!("{}", compact(&resp));
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_limits(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("usage: agent-bus limits [--format json|short]\n");
        return 0;
    }
    let mut format = "json".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown limits option '{s}'");
                return 2;
            }
            s => {
                eprintln!("error: limits takes no positional argument (got '{s}')");
                return 2;
            }
        }
        i += 1;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "limits"})) {
        Ok(resp) => {
            if format == "short" {
                println!("{}", short_limits(&resp));
            } else {
                println!("{}", compact(&resp));
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// ping: native health via `ping` RPC (never `agents`)
// ---------------------------------------------------------------------------

const PING_USAGE: &str = "usage: agent-bus ping [--count N] [--format json|short]\n\
 \n\
 Sends N authenticated `ping` RPCs on one connection (default 1) and\n\
 prints one line per reply. `json` prints the compact broker reply\n\
 (legacy `bus ping` parity); `short` prints `pong authed=.. server_ts=..`.\n\
 Exit 0 only when every ping succeeds; 1 on transport/broker/auth\n\
 failure; 2 on usage errors.\n";

fn cmd_ping(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{PING_USAGE}");
        return 0;
    }
    let mut count: Option<i64> = None;
    let mut format = "json".to_string();
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--count" => match take_value(argv, &mut i, "--count") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => count = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --count {v}: want >= 1");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--format" => match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown ping option '{s}'\n{PING_USAGE}");
                return 2;
            }
            s => {
                eprintln!("error: ping takes no positional argument (got '{s}')\n{PING_USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let count = count.unwrap_or(1);
    if count < 1 {
        eprintln!("error: bad --count {count}: want >= 1");
        return 2;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    for n in 1..=count {
        match rpc(&mut client, &json!({"op": "ping"})) {
            Ok(resp) => {
                if let Err(e) = validate_authenticated_ping(&resp) {
                    eprintln!("error: ping {n}/{count} failed: {e}");
                    return 1;
                }
                if format == "short" {
                    println!("{}", short_ping(&resp));
                } else {
                    println!("{}", compact(&resp));
                }
            }
            Err(e) => {
                eprintln!("error: ping {n}/{count} failed: {e}");
                return 1;
            }
        }
    }
    0
}

const TOKEN_ISSUE_USAGE: &str = "usage: agent-bus token-issue FOR_AGENT [--ttl-s F] [--publish P ...] [--subscribe S ...] [--kv-read K ...] [--kv-write K ...] [--art-quota-bytes I] [--rate-per-s F] [--topic-rate PAT=RATE ...]\n\
 \n\
 FOR_AGENT is the new agent name (1..32, [A-Za-z0-9._-], leading alnum).\n\
 --ttl-s F sets expiry seconds (finite number; 0 means no expiry, broker\n\
 validates >0 otherwise). Repeatable grant flags append (legacy parity).\n\
 --topic-rate PAT=RATE repeats; RATE must be a finite number (broker\n\
 validates >0). Prints the broker reply JSON (new token only on success).\n";

const TOKEN_REVOKE_USAGE: &str = "usage: agent-bus token-revoke TOK\n\
 \n\
 TOK is the token value to revoke (never printed to stderr). Prints the\n\
 broker reply JSON ({ok, revoked}). Unknown tokens report revoked:false.\n";

const TOKEN_CLAIM_USAGE: &str = "usage: agent-bus token-claim FOR_AGENT\n\
 \n\
 FOR_AGENT is the desired personal agent name (self-service, claim-token\n\
 holders only). Prints the broker reply JSON (new token only on success).\n";

fn cmd_token_issue(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{TOKEN_ISSUE_USAGE}");
        return 0;
    }
    let mut for_agent: Option<String> = None;
    let mut ttl_s: Option<f64> = None;
    let mut publish: Vec<String> = Vec::new();
    let mut subscribe: Vec<String> = Vec::new();
    let mut kv_read: Vec<String> = Vec::new();
    let mut kv_write: Vec<String> = Vec::new();
    let mut art_quota_bytes: Option<i64> = None;
    let mut rate_per_s: Option<f64> = None;
    let mut topic_rates: Vec<(String, f64)> = Vec::new();
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--ttl-s" => match take_value(argv, &mut i, "--ttl-s") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(n) if n.is_finite() => ttl_s = Some(n),
                    Ok(_) => {
                        eprintln!("error: bad --ttl-s {v}: want a finite number");
                        return 2;
                    }
                    Err(_) => {
                        eprintln!("error: bad --ttl-s {v}: want a finite number");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--publish" => match take_value(argv, &mut i, "--publish") {
                Ok(v) => publish.push(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--subscribe" => match take_value(argv, &mut i, "--subscribe") {
                Ok(v) => subscribe.push(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--kv-read" => match take_value(argv, &mut i, "--kv-read") {
                Ok(v) => kv_read.push(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--kv-write" => match take_value(argv, &mut i, "--kv-write") {
                Ok(v) => kv_write.push(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--art-quota-bytes" => match take_value(argv, &mut i, "--art-quota-bytes") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => art_quota_bytes = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --art-quota-bytes {v}: want an integer");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--rate-per-s" => match take_value(argv, &mut i, "--rate-per-s") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(n) if n.is_finite() => rate_per_s = Some(n),
                    Ok(_) => {
                        eprintln!("error: bad --rate-per-s {v}: want a finite number");
                        return 2;
                    }
                    Err(_) => {
                        eprintln!("error: bad --rate-per-s {v}: want a finite number");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            "--topic-rate" => match take_value(argv, &mut i, "--topic-rate") {
                Ok(v) => {
                    let (pat, val) = match v.split_once('=') {
                        Some((p, r)) if !p.is_empty() && !r.is_empty() => (p, r),
                        _ => {
                            eprintln!("error: bad --topic-rate {v}: want PAT=RATE");
                            return 2;
                        }
                    };
                    match val.parse::<f64>() {
                        Ok(n) if n.is_finite() => topic_rates.push((pat.to_string(), n)),
                        _ => {
                            eprintln!(
                                "error: bad --topic-rate {v}: want PAT=RATE with finite RATE"
                            );
                            return 2;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            },
            s if is_flag(s) => {
                eprintln!("error: unknown token-issue option '{s}'\n{TOKEN_ISSUE_USAGE}");
                return 2;
            }
            _ => {
                if for_agent.is_some() {
                    eprintln!("error: token-issue takes a single FOR_AGENT\n{TOKEN_ISSUE_USAGE}");
                    return 2;
                }
                for_agent = Some(a.to_string());
            }
        }
        i += 1;
    }
    let Some(for_agent) = for_agent else {
        eprintln!("error: token-issue needs FOR_AGENT\n{TOKEN_ISSUE_USAGE}");
        return 2;
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut req = json!({"op": "token_issue", "agent": for_agent});
    if let Some(t) = ttl_s {
        req["ttl_s"] = json!(t);
    }
    if !publish.is_empty() {
        req["publish"] = json!(publish);
    }
    if !subscribe.is_empty() {
        req["subscribe"] = json!(subscribe);
    }
    if !kv_read.is_empty() {
        req["kv_read"] = json!(kv_read);
    }
    if !kv_write.is_empty() {
        req["kv_write"] = json!(kv_write);
    }
    if let Some(q) = art_quota_bytes {
        req["art_quota_bytes"] = json!(q);
    }
    if let Some(r) = rate_per_s {
        req["rate_per_s"] = json!(r);
    }
    // Preserve `--topic-rate` flag order on the wire (first-match policy):
    // a sorted `serde_json::Map` would reverse caller declaration order, so
    // dedup here (last value, first position, matching legacy `tr[pat]=float`)
    // and serialize via the ordered RPC. The broker also parses ordinary
    // ordered JSON wire from generic clients, so this is not a side channel.
    let ordered_rates: Option<Vec<(String, Value)>> = if topic_rates.is_empty() {
        None
    } else {
        let pairs: Vec<(String, Value)> = topic_rates
            .into_iter()
            .map(|(pat, rate)| (pat, json!(rate)))
            .collect();
        Some(agent_bus::rate::dedup_ordered_pairs(pairs))
    };
    let result = match ordered_rates {
        None => rpc(&mut client, &req),
        Some(ordered) => rpc_ordered(&mut client, &req, &ordered),
    };
    match result {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_token_revoke(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{TOKEN_REVOKE_USAGE}");
        return 0;
    }
    let mut tok: Option<String> = None;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            s if is_flag(s) => {
                eprintln!("error: unknown token-revoke option '{s}'\n{TOKEN_REVOKE_USAGE}");
                return 2;
            }
            _ => {
                if tok.is_some() {
                    eprintln!("error: token-revoke takes a single TOK\n{TOKEN_REVOKE_USAGE}");
                    return 2;
                }
                tok = Some(a.to_string());
            }
        }
        i += 1;
    }
    let Some(tok) = tok else {
        eprintln!("error: token-revoke needs TOK\n{TOKEN_REVOKE_USAGE}");
        return 2;
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(&mut client, &json!({"op": "token_revoke", "token": tok})) {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_token_claim(argv: &[String]) -> i32 {
    if wants_help(argv) {
        print!("{TOKEN_CLAIM_USAGE}");
        return 0;
    }
    let mut for_agent: Option<String> = None;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            s if is_flag(s) => {
                eprintln!("error: unknown token-claim option '{s}'\n{TOKEN_CLAIM_USAGE}");
                return 2;
            }
            _ => {
                if for_agent.is_some() {
                    eprintln!("error: token-claim takes a single FOR_AGENT\n{TOKEN_CLAIM_USAGE}");
                    return 2;
                }
                for_agent = Some(a.to_string());
            }
        }
        i += 1;
    }
    let Some(for_agent) = for_agent else {
        eprintln!("error: token-claim needs FOR_AGENT\n{TOKEN_CLAIM_USAGE}");
        return 2;
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match rpc(
        &mut client,
        &json!({"op": "token_claim", "agent": for_agent}),
    ) {
        Ok(resp) => {
            println!("{}", compact(&resp));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

const ART_PUT_USAGE: &str = "usage: agent-bus art-put FILE ('-' reads stdin bytes)\n";
const ART_GET_USAGE: &str = "usage: agent-bus art-get SHA [OUT]\n";

/// Upload bytes (legacy `bus art-put`, `bus:752-761` + `busclient`
/// `art_put_*`, 1077-1151): `-` reads stdin (bounded `ART_MAX+1`),
/// else the file (fast-fail past `ART_MAX`, full object buffered in
/// memory bounded 32 MiB); past 1 MiB uses init/chunk/commit
/// wire-chunking (256 KiB RPCs, sha pinned, not filesystem-streaming
/// IO), else a single `art_put`. Prints the broker JSON receipt
/// (`{ok,sha,size,dedup}`). Exit 0 ok, 1 broker/transport/auth/IO
/// refusal, 2 usage.
fn cmd_art_put(argv: &[String]) -> i32 {
    use agent_bus::artifacts as art;
    if wants_help(argv) {
        print!("{ART_PUT_USAGE}");
        return 0;
    }
    let mut file: Option<String> = None;
    let mut i = 2;
    let mut literal = false;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown art-put option '{a}'\n{ART_PUT_USAGE}");
            return 2;
        }
        if file.is_some() {
            eprintln!("error: art-put takes a single FILE\n{ART_PUT_USAGE}");
            return 2;
        }
        file = Some(a.to_string());
        i += 1;
    }
    let Some(file) = file else {
        eprintln!("error: art-put needs FILE\n{ART_PUT_USAGE}");
        return 2;
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let raw: Vec<u8> = if file == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        let limit = art::ART_MAX.saturating_add(1) as usize;
        match std::io::stdin().take(limit as u64).read_to_end(&mut buf) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("error: art-put stdin read failed: {e}");
                return 1;
            }
        }
        if buf.len() as u64 > art::ART_MAX {
            eprintln!("error: artifact too large (32MB cap)");
            return 1;
        }
        buf
    } else {
        match std::fs::metadata(&file) {
            Ok(m) if m.len() > art::ART_MAX => {
                eprintln!("error: artifact too large (32MB cap)");
                return 1;
            }
            Ok(m) if !m.is_file() => {
                eprintln!("error: art-put read failed: not a file: {file}");
                return 2;
            }
            Err(e) => {
                eprintln!("error: art-put read failed: {e}: {file}");
                return 2;
            }
            _ => {}
        }
        match std::fs::read(&file) {
            Ok(b) => {
                if b.len() as u64 > art::ART_MAX {
                    eprintln!("error: artifact too large (32MB cap)");
                    return 1;
                }
                b
            }
            Err(e) => {
                eprintln!("error: art-put read failed: {e}: {file}");
                return 2;
            }
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if raw.len() as u64 <= art::CLIENT_STREAM_THRESHOLD {
        match rpc(
            &mut client,
            &json!({"op": "art_put", "data_b64": art::base64_encode(&raw)}),
        ) {
            Ok(resp) => {
                println!("{}", compact(&resp));
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        }
    } else {
        let sha = art::sha256_hex(&raw);
        let size = raw.len() as u64;
        let init = match rpc(
            &mut client,
            &json!({"op": "art_init", "size": size, "sha": sha}),
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        let uid = match init.get("upload_id").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => {
                eprintln!("error: unexpected response: {}", compact(&init));
                return 1;
            }
        };
        let mut off: u64 = 0;
        for chunk in raw.chunks(art::PUT_STREAM_CHUNK) {
            let r = rpc(
                &mut client,
                &json!({
                    "op": "art_chunk", "upload_id": uid, "off": off,
                    "data_b64": art::base64_encode(chunk),
                }),
            );
            if let Err(e) = r {
                let _ = rpc(&mut client, &json!({"op": "art_abort", "upload_id": uid}));
                eprintln!("error: {e}");
                return 1;
            }
            off += chunk.len() as u64;
        }
        match rpc(&mut client, &json!({"op": "art_commit", "upload_id": uid})) {
            Ok(resp) => {
                println!("{}", compact(&resp));
                0
            }
            Err(e) => {
                let _ = rpc(&mut client, &json!({"op": "art_abort", "upload_id": uid}));
                eprintln!("error: {e}");
                1
            }
        }
    }
}

/// Download bytes (legacy `bus art-get`, `bus:762-770` + `busclient`
/// `art_get_*`, 1153-1179): `art_stat` for size, single `art_get` at
/// or under 1 MiB else wire-chunked `art_range`s (1 MiB RPCs, full
/// object buffered in memory bounded 32 MiB, not filesystem-streaming
/// IO) with sha verification (native always verifies; legacy
/// single-get did not). `OUT` writes the file and prints
/// `{sha,size,out}` JSON, else raw bytes go to stdout. Exit 0 ok, 1
/// broker/transport/auth/IO refusal or checksum mismatch, 2 usage.
fn cmd_art_get(argv: &[String]) -> i32 {
    use agent_bus::artifacts as art;
    if wants_help(argv) {
        print!("{ART_GET_USAGE}");
        return 0;
    }
    let mut sha: Option<String> = None;
    let mut out: Option<String> = None;
    let mut i = 2;
    let mut literal = false;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown art-get option '{a}'\n{ART_GET_USAGE}");
            return 2;
        }
        if sha.is_none() {
            sha = Some(a.to_string());
        } else if out.is_none() {
            out = Some(a.to_string());
        } else {
            eprintln!("error: art-get takes SHA [OUT]\n{ART_GET_USAGE}");
            return 2;
        }
        i += 1;
    }
    let Some(sha) = sha else {
        eprintln!("error: art-get needs SHA\n{ART_GET_USAGE}");
        return 2;
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let stat = match rpc(&mut client, &json!({"op": "art_stat", "sha": sha})) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let size = match stat.get("size").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => {
            eprintln!("error: unexpected response: {}", compact(&stat));
            return 1;
        }
    };
    if size > art::ART_MAX {
        eprintln!("error: artifact not found");
        return 1;
    }
    let raw: Vec<u8> = if size <= art::CLIENT_STREAM_THRESHOLD {
        let got = match rpc(&mut client, &json!({"op": "art_get", "sha": sha})) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        let enc = match got.get("data_b64").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                eprintln!("error: unexpected response: {}", compact(&got));
                return 1;
            }
        };
        match art::base64_decode(enc) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    } else {
        let mut buf = Vec::with_capacity(size.min(art::ART_MAX) as usize);
        let mut off: u64 = 0;
        while off < size {
            let want = (size - off).min(art::GET_STREAM_CHUNK);
            let got = match rpc(
                &mut client,
                &json!({"op": "art_range", "sha": sha, "off": off, "len": want}),
            ) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let enc = match got.get("data_b64").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    eprintln!("error: unexpected response: {}", compact(&got));
                    return 1;
                }
            };
            let chunk = match art::base64_decode(enc) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            if chunk.is_empty() && want > 0 {
                eprintln!("error: unexpected short range: {}", compact(&got));
                return 1;
            }
            buf.extend_from_slice(&chunk);
            off += chunk.len() as u64;
            if chunk.len() as u64 != want {
                break;
            }
        }
        buf
    };
    if raw.len() as u64 != size || art::sha256_hex(&raw) != sha {
        eprintln!("error: artifact checksum mismatch");
        return 1;
    }
    if let Some(path) = out {
        if let Err(e) = std::fs::write(&path, &raw) {
            eprintln!("error: art-get write failed: {e}: {path}");
            return 1;
        }
        println!(
            "{}",
            compact(&json!({"sha": sha, "size": raw.len(), "out": path}))
        );
        0
    } else {
        use std::io::Write;
        match std::io::stdout().write_all(&raw) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: art-get stdout failed: {e}");
                1
            }
        }
    }
}

// ---------------------------------------------------------------------------
// claim-acquire / claim-renew / claim-release / claim-status / claim-list
// (broker atomic leases, distinct from advisory post --claim / claims views)
// ---------------------------------------------------------------------------

const CLAIM_ACQUIRE_USAGE: &str = "usage: agent-bus claim-acquire RESOURCE --ttl-ms N [--idempotency-key K] [--format json|short]\n\
 \n\
 Acquire a broker atomic lease on RESOURCE for N ms (1..86400000). Owner is\n\
 the authed agent; exactly one winner on conflict. --idempotency-key K makes\n\
 retries safe: same K + same N returns the current live lease, retired after\n\
 release/expiry. JSON prints the broker receipt (with token for caller use);\n\
 short prints `acquired RESOURCE fencing=N expires_at=X` without the token.\n\
 Single RPC, never retried: a timeout leaves status uncertain, reconcile via\n\
 `claim-status`/`claim-list`, never resend. `--` ends options; `--opt=value`\n\
 works via global expansion.\n";

const CLAIM_RENEW_USAGE: &str = "usage: agent-bus claim-renew RESOURCE (--token T | --token-file P) --ttl-ms N [--format json|short]\n\
 \n\
 Renew a held lease to N ms from now. Token via --token (visible in ps) or\n\
 --token-file P (file path, '-' reads stdin, trimmed first line, never\n\
 echoed). JSON prints the broker receipt; short prints\n\
 `renewed RESOURCE fencing=N expires_at=X` without the token. Single RPC,\n\
 never retried: reconcile uncertain timeouts via `claim-status`.\n";

const CLAIM_RELEASE_USAGE: &str = "usage: agent-bus claim-release RESOURCE (--token T | --token-file P) [--format json|short]\n\
 \n\
 Release a held lease. Token via --token or --token-file (see claim-renew).\n\
 JSON prints `{ok,released,resource}`; short prints `released RESOURCE` or\n\
 `not-held RESOURCE` (free resources exit 0 with released:false). Single RPC,\n\
 never retried.\n";

const CLAIM_STATUS_USAGE: &str = "usage: agent-bus claim-status RESOURCE [--format json|short]\n\
 \n\
 Read one lease. JSON prints the broker reply as-is (native:\n\
 `{ok,owner,resource,token,fencing,expires_at}` held or `{ok,resource,\n\
 live:false}` free; legacy Python uses `{held,holder,fencing}` instead -\n\
 see docs/NATIVE_LEASES.md). Short prints `held RESOURCE holder=H\n\
 fencing=N expires_at=X` or `free RESOURCE` (`free RESOURCE fencing=N`\n\
 when the broker supplies free fencing), never the token. Read-only.\n";

const CLAIM_LIST_USAGE: &str = "usage: agent-bus claim-list [--format json|short]\n\
 \n\
 List live leases sorted by resource. JSON prints\n\
 `{ok,leases:[{resource,holder,fencing,expires_at}]}` (never tokens).\n\
 Short prints one `RESOURCE holder=H fencing=N expires_at=X` line per\n\
 lease, sorted, empty prints nothing. Read-only, any authed caller.\n";

/// Lease token input cap (bytes): `--token-file` path and stdin alike.
const LEASE_TOKEN_CAP: usize = 8192;

/// Read a lease token from `--token` or `--token-file` (mutually exclusive,
/// one required). `--token-file -` reads stdin (bounded 8 KiB); a path is
/// opened once and read bounded (same 8 KiB cap, enforced during the read).
/// Content is trimmed to its first line; errors never echo the token value.
fn read_lease_token(token: Option<String>, token_file: Option<String>) -> Result<String, String> {
    match (token, token_file) {
        (Some(_), Some(_)) => Err("claim token: --token and --token-file are mutually exclusive".to_string()),
        (None, None) => Err("claim token: need --token T or --token-file P".to_string()),
        (Some(t), None) => {
            if t.is_empty() {
                return Err("claim token: empty --token".to_string());
            }
            Ok(t)
        }
        (None, Some(p)) => {
            let raw = if p == "-" {
                read_stdin_bounded(LEASE_TOKEN_CAP).map_err(|e| format!("claim token: {e}"))?
            } else {
                read_token_file_bounded(&p, LEASE_TOKEN_CAP)
                    .map_err(|e| format!("claim token: {e}"))?
            };
            let line = raw.lines().next().unwrap_or("").trim();
            if line.is_empty() {
                return Err("claim token: empty token file/stdin".to_string());
            }
            Ok(line.to_string())
        }
    }
}

/// Read a token file with the same bounded semantics as stdin: the path is
/// opened once, the open handle's metadata must describe a regular file
/// (an over-cap length fails fast here), and the read itself takes at most
/// `limit + 1` bytes so growth after open still fails closed. UTF-8
/// required; the invalid-UTF-8 message matches the old `read_to_string`
/// wording so only the bound enforcement is new.
fn read_token_file_bounded(path: &str, limit: usize) -> Result<String, String> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|e| format!("file read failed: {e}: {path}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("file read failed: {e}: {path}"))?;
    if !meta.is_file() {
        return Err(format!("not a file: {path}"));
    }
    if meta.len() > limit as u64 {
        return Err(format!("file too large (8 KiB cap): {path}"));
    }
    let mut buf = Vec::new();
    let cap = limit.saturating_add(1) as u64;
    file.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| format!("file read failed: {e}: {path}"))?;
    if buf.len() > limit {
        return Err(format!("file too large (8 KiB cap): {path}"));
    }
    String::from_utf8(buf)
        .map_err(|_| format!("file read failed: stream did not contain valid UTF-8: {path}"))
}

/// Lease object for acquire/renew shorts: legacy wraps in `lease`, native is
/// flat. Returns the object holding resource/fencing/expires_at.
fn lease_obj<'a>(resp: &'a Value) -> &'a Value {
    if resp.get("lease").is_some_and(|v| v.is_object()) {
        resp.get("lease").unwrap()
    } else {
        resp
    }
}

fn short_claim_acquired(resp: &Value) -> Option<String> {
    let l = lease_obj(resp);
    let resource = l.get("resource").and_then(|v| v.as_str())?;
    let fencing = l.get("fencing")?;
    let expires = l.get("expires_at")?;
    if fencing.as_u64().is_none() || expires.as_f64().is_none() {
        return None;
    }
    Some(format!(
        "acquired {} fencing={} expires_at={}",
        resource,
        value_to_str(fencing),
        value_to_str(expires)
    ))
}

fn short_claim_renewed(resp: &Value) -> Option<String> {
    let l = lease_obj(resp);
    let resource = l.get("resource").and_then(|v| v.as_str())?;
    let fencing = l.get("fencing")?;
    let expires = l.get("expires_at")?;
    if fencing.as_u64().is_none() || expires.as_f64().is_none() {
        return None;
    }
    Some(format!(
        "renewed {} fencing={} expires_at={}",
        resource,
        value_to_str(fencing),
        value_to_str(expires)
    ))
}

fn short_claim_release(resp: &Value) -> Option<String> {
    let resource = resp.get("resource").and_then(|v| v.as_str())?;
    let released = resp.get("released").and_then(|v| v.as_bool())?;
    if released {
        Some(format!("released {resource}"))
    } else {
        Some(format!("not-held {resource}"))
    }
}

fn short_claim_status(resp: &Value) -> Option<String> {
    let resource = resp.get("resource").and_then(|v| v.as_str())?;
    // Free: native `live:false` or legacy `held:false`.
    if resp.get("live") == Some(&json!(false)) || resp.get("held") == Some(&json!(false)) {
        if let Some(f) = resp.get("fencing") {
            if f.as_u64().is_some() {
                return Some(format!("free {resource} fencing={}", value_to_str(f)));
            }
        }
        return Some(format!("free {resource}"));
    }
    // Held: native `owner` or legacy `holder`, plus fencing + expires_at.
    let holder = resp
        .get("owner")
        .or_else(|| resp.get("holder"))
        .and_then(|v| v.as_str())?;
    let fencing = resp.get("fencing")?;
    let expires = resp.get("expires_at")?;
    if fencing.as_u64().is_none() || expires.as_f64().is_none() {
        return None;
    }
    Some(format!(
        "held {resource} holder={holder} fencing={} expires_at={}",
        value_to_str(fencing),
        value_to_str(expires)
    ))
}

fn short_claim_list(resp: &Value) -> Option<String> {
    let leases = resp.get("leases").and_then(|v| v.as_array())?;
    let mut lines = Vec::new();
    for l in leases {
        let resource = l.get("resource").and_then(|v| v.as_str())?;
        let holder = l.get("holder").and_then(|v| v.as_str())?;
        let fencing = l.get("fencing")?;
        let expires = l.get("expires_at")?;
        if fencing.as_u64().is_none() || expires.as_f64().is_none() {
            return None;
        }
        lines.push(format!(
            "{resource} holder={holder} fencing={} expires_at={}",
            value_to_str(fencing),
            value_to_str(expires)
        ));
    }
    Some(lines.join("\n"))
}

/// Lease verb identity for fixed diagnostics.
#[derive(Clone, Copy)]
enum LeaseOp {
    Acquire,
    Renew,
    Release,
    Status,
    List,
}

impl LeaseOp {
    fn name(self) -> &'static str {
        match self {
            LeaseOp::Acquire => "claim-acquire",
            LeaseOp::Renew => "claim-renew",
            LeaseOp::Release => "claim-release",
            LeaseOp::Status => "claim-status",
            LeaseOp::List => "claim-list",
        }
    }

    /// Mutating verbs leave state uncertain on transport failure or an
    /// unrecognized reply, so their diagnostics carry reconcile guidance;
    /// reads just report the fixed category.
    fn mutating(self) -> bool {
        matches!(
            self,
            LeaseOp::Acquire | LeaseOp::Renew | LeaseOp::Release
        )
    }
}

/// Fixed broker-refusal category from a structured error reply. Only the
/// `claim_err` flag words (native `wire.rs`, same names as legacy
/// `broker.py` conflict/retired/expired/capacity) are reported: refusal
/// replies may carry the holder lease token plus arbitrary broker text,
/// so neither is echoed.
fn lease_refusal_category(resp: &Value) -> Option<&'static str> {
    if resp.get("conflict") == Some(&json!(true)) {
        Some("conflict")
    } else if resp.get("expired") == Some(&json!(true)) {
        Some("expired")
    } else if resp.get("retired") == Some(&json!(true)) {
        Some("retired")
    } else if resp.get("capacity") == Some(&json!(true)) {
        Some("capacity")
    } else {
        None
    }
}

/// Fixed diagnostic for a broker `{"error": ...}` lease reply. No broker
/// text or frame is echoed (replies may carry lease tokens); only the op
/// name and a fixed category word.
fn lease_refused(op: LeaseOp, resp: &Value) -> String {
    let mut msg = match lease_refusal_category(resp) {
        Some(cat) => format!("{} refused ({cat})", op.name()),
        None => format!("{} refused by broker", op.name()),
    };
    if op.mutating() {
        msg.push_str("; reconcile via claim-status (single RPC, no retry)");
    }
    msg
}

/// Fixed diagnostic for an unrecognized lease reply shape (short-format
/// fallback and non-ok replies without an `error` member). The raw frame
/// is never echoed: success-shaped replies carry lease tokens.
fn lease_unexpected(op: LeaseOp) -> String {
    if op.mutating() {
        format!(
            "{}: unexpected broker reply; mutation status uncertain, \
             reconcile via claim-status/claim-list, never resend \
             (single RPC, no retry, no advisory fallback)",
            op.name()
        )
    } else {
        format!("{}: unexpected broker reply (single RPC, no retry)", op.name())
    }
}

/// Lease RPC with fixed safe diagnostics. Success replies pass through
/// untouched (deliberate JSON receipts keep tokens for caller use).
/// Transport failures detail only locally-generated `wire::Client`/OS
/// strings (reviewed: `rpc_send_recv`/`read_response_line` fixed texts,
/// `describe_req_id` shapes, socket errors; no broker bytes or request
/// echo), so the detail is preserved with the op name. Broker refusals
/// and unrecognized shapes become fixed categories via [`lease_refused`]/
/// [`lease_unexpected`] and never echo broker text or frames. The shared
/// [`rpc_response`] (raw dumps for other verbs) is not used here.
fn lease_rpc(client: &mut Client, op: LeaseOp, req: &Value) -> Result<Value, String> {
    match client.rpc(req) {
        Ok(resp) => {
            if resp.get("error").is_some() {
                Err(lease_refused(op, &resp))
            } else if resp.get("ok") == Some(&json!(true)) {
                Ok(resp)
            } else {
                Err(lease_unexpected(op))
            }
        }
        Err(e) => {
            let mut msg = format!("{} transport failed: {e}", op.name());
            if op.mutating() {
                msg.push_str(
                    "; mutation status uncertain, \
                     reconcile via claim-status/claim-list, never resend \
                     (single RPC, no retry, no advisory fallback)",
                );
            }
            Err(msg)
        }
    }
}

fn cmd_claim_acquire(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("{CLAIM_ACQUIRE_USAGE}");
        return 0;
    }
    let mut resource: Option<String> = None;
    let mut ttl_ms: Option<u64> = None;
    let mut idem: Option<String> = None;
    let mut format = "json".to_string();
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--ttl-ms" {
            match take_value(argv, &mut i, "--ttl-ms") {
                Ok(v) => match v.parse::<u64>() {
                    Ok(n) => ttl_ms = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --ttl-ms {v}: want an integer");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--idempotency-key" {
            match take_value(argv, &mut i, "--idempotency-key") {
                Ok(v) => {
                    if v.is_empty() || v.len() > 256 {
                        eprintln!("error: bad --idempotency-key: want 1..256 chars");
                        return 2;
                    }
                    idem = Some(v);
                }
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown claim-acquire option '{a}'\n{CLAIM_ACQUIRE_USAGE}");
            return 2;
        }
        if resource.is_some() {
            eprintln!("error: claim-acquire takes a single RESOURCE\n{CLAIM_ACQUIRE_USAGE}");
            return 2;
        }
        resource = Some(a.to_string());
        i += 1;
    }
    let Some(resource) = resource else {
        eprintln!("error: claim-acquire needs RESOURCE\n{CLAIM_ACQUIRE_USAGE}");
        return 2;
    };
    let Some(ttl) = ttl_ms else {
        eprintln!("error: claim-acquire needs --ttl-ms N\n{CLAIM_ACQUIRE_USAGE}");
        return 2;
    };
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut req = json!({"op": "claim_acquire", "resource": resource, "ttl_ms": ttl});
    if let Some(k) = idem {
        req["idempotency_key"] = json!(k);
    }
    // Single attempt: an uncertain timeout must be reconciled via
    // claim-status/claim-list, never resent (no advisory fallback).
    match lease_rpc(&mut client, LeaseOp::Acquire, &req) {
        Ok(resp) => {
            if format == "short" {
                match short_claim_acquired(&resp) {
                    Some(s) => {
                        println!("{s}");
                        0
                    }
                    None => {
                        eprintln!("error: {}", lease_unexpected(LeaseOp::Acquire));
                        1
                    }
                }
            } else {
                println!("{}", compact(&resp));
                0
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_claim_renew(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("{CLAIM_RENEW_USAGE}");
        return 0;
    }
    let mut resource: Option<String> = None;
    let mut token: Option<String> = None;
    let mut token_file: Option<String> = None;
    let mut ttl_ms: Option<u64> = None;
    let mut format = "json".to_string();
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--token" {
            match take_value(argv, &mut i, "--token") {
                Ok(v) => token = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--token-file" {
            match take_value(argv, &mut i, "--token-file") {
                Ok(v) => token_file = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--ttl-ms" {
            match take_value(argv, &mut i, "--ttl-ms") {
                Ok(v) => match v.parse::<u64>() {
                    Ok(n) => ttl_ms = Some(n),
                    Err(_) => {
                        eprintln!("error: bad --ttl-ms {v}: want an integer");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown claim-renew option '{a}'\n{CLAIM_RENEW_USAGE}");
            return 2;
        }
        if resource.is_some() {
            eprintln!("error: claim-renew takes a single RESOURCE\n{CLAIM_RENEW_USAGE}");
            return 2;
        }
        resource = Some(a.to_string());
        i += 1;
    }
    let Some(resource) = resource else {
        eprintln!("error: claim-renew needs RESOURCE\n{CLAIM_RENEW_USAGE}");
        return 2;
    };
    let Some(ttl) = ttl_ms else {
        eprintln!("error: claim-renew needs --ttl-ms N\n{CLAIM_RENEW_USAGE}");
        return 2;
    };
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let tok = match read_lease_token(token, token_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match lease_rpc(
        &mut client,
        LeaseOp::Renew,
        &json!({"op": "claim_renew", "resource": resource, "token": tok, "ttl_ms": ttl}),
    ) {
        Ok(resp) => {
            if format == "short" {
                match short_claim_renewed(&resp) {
                    Some(s) => {
                        println!("{s}");
                        0
                    }
                    None => {
                        eprintln!("error: {}", lease_unexpected(LeaseOp::Renew));
                        1
                    }
                }
            } else {
                println!("{}", compact(&resp));
                0
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_claim_release(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("{CLAIM_RELEASE_USAGE}");
        return 0;
    }
    let mut resource: Option<String> = None;
    let mut token: Option<String> = None;
    let mut token_file: Option<String> = None;
    let mut format = "json".to_string();
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--token" {
            match take_value(argv, &mut i, "--token") {
                Ok(v) => token = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--token-file" {
            match take_value(argv, &mut i, "--token-file") {
                Ok(v) => token_file = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown claim-release option '{a}'\n{CLAIM_RELEASE_USAGE}");
            return 2;
        }
        if resource.is_some() {
            eprintln!("error: claim-release takes a single RESOURCE\n{CLAIM_RELEASE_USAGE}");
            return 2;
        }
        resource = Some(a.to_string());
        i += 1;
    }
    let Some(resource) = resource else {
        eprintln!("error: claim-release needs RESOURCE\n{CLAIM_RELEASE_USAGE}");
        return 2;
    };
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let tok = match read_lease_token(token, token_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match lease_rpc(
        &mut client,
        LeaseOp::Release,
        &json!({"op": "claim_release", "resource": resource, "token": tok}),
    ) {
        Ok(resp) => {
            if format == "short" {
                match short_claim_release(&resp) {
                    Some(s) => {
                        println!("{s}");
                        0
                    }
                    None => {
                        eprintln!("error: {}", lease_unexpected(LeaseOp::Release));
                        1
                    }
                }
            } else {
                println!("{}", compact(&resp));
                0
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_claim_status(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("{CLAIM_STATUS_USAGE}");
        return 0;
    }
    let mut resource: Option<String> = None;
    let mut format = "json".to_string();
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown claim-status option '{a}'\n{CLAIM_STATUS_USAGE}");
            return 2;
        }
        if resource.is_some() {
            eprintln!("error: claim-status takes a single RESOURCE\n{CLAIM_STATUS_USAGE}");
            return 2;
        }
        resource = Some(a.to_string());
        i += 1;
    }
    let Some(resource) = resource else {
        eprintln!("error: claim-status needs RESOURCE\n{CLAIM_STATUS_USAGE}");
        return 2;
    };
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match lease_rpc(
        &mut client,
        LeaseOp::Status,
        &json!({"op": "claim_status", "resource": resource}),
    ) {
        Ok(resp) => {
            if format == "short" {
                match short_claim_status(&resp) {
                    Some(s) => {
                        println!("{s}");
                        0
                    }
                    None => {
                        eprintln!("error: {}", lease_unexpected(LeaseOp::Status));
                        1
                    }
                }
            } else {
                println!("{}", compact(&resp));
                0
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_claim_list(argv: &[String]) -> i32 {
    if argv
        .iter()
        .skip(2)
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--help" || a == "-h")
    {
        print!("{CLAIM_LIST_USAGE}");
        return 0;
    }
    let mut format = "json".to_string();
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && is_flag(a) {
            eprintln!("error: unknown claim-list option '{a}'\n{CLAIM_LIST_USAGE}");
            return 2;
        }
        eprintln!("error: claim-list takes no positional argument (got '{a}')\n{CLAIM_LIST_USAGE}");
        return 2;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match lease_rpc(
        &mut client,
        LeaseOp::List,
        &json!({"op": "claim_list"}),
    ) {
        Ok(resp) => {
            if format == "short" {
                match short_claim_list(&resp) {
                    Some(s) => {
                        println!("{s}");
                        0
                    }
                    None => {
                        eprintln!("error: {}", lease_unexpected(LeaseOp::List));
                        1
                    }
                }
            } else {
                println!("{}", compact(&resp));
                0
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// Authenticated CLI health gate: this CLI always `hello`s first, so a
/// healthy reply must prove authentication (`authed` boolean true). A
/// present `server_ts` must be a finite number; a missing `server_ts`
/// stays accepted for the documented older native reply. Wire `ping`
/// before `hello` still returns `authed:false` unchanged; that path is
/// not this CLI check.
fn validate_authenticated_ping(resp: &Value) -> Result<(), String> {
    if resp.get("authed") != Some(&Value::Bool(true)) {
        return Err("ping reply not authenticated (want authed:true boolean)".to_string());
    }
    match resp.get("server_ts") {
        None => Ok(()),
        Some(Value::Number(n)) if n.as_f64().is_some_and(|f| f.is_finite()) => Ok(()),
        Some(_) => {
            Err("ping reply has invalid server_ts (want finite number or absent)".to_string())
        }
    }
}

/// One-line health: `pong authed=True server_ts=...` (`?` when the broker
/// omits `server_ts`, e.g. a pre-idempotency native build).
fn short_ping(resp: &Value) -> String {
    let authed = resp
        .get("authed")
        .map(value_to_str)
        .unwrap_or_else(|| "?".to_string());
    let ts = resp
        .get("server_ts")
        .map(value_to_str)
        .unwrap_or_else(|| "?".to_string());
    format!("pong authed={authed} server_ts={ts}")
}

// ---------------------------------------------------------------------------
// short/plain renderers (ported from busclient.py pure helpers)
// ---------------------------------------------------------------------------

/// Python `str()` for scalar JSON, compact JSON for containers.
/// (Divergence: Python `repr` renders containers with single quotes; JSON is
/// unambiguous and matches every `short_*` scalar path exactly.)
fn value_to_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => compact(other),
    }
}

/// Python truthiness for `found`/`online`/tag presence checks.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i != 0
            } else if let Some(u) = n.as_u64() {
                u != 0
            } else {
                n.as_f64().is_some_and(|f| f != 0.0)
            }
        }
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// Compact age like `5s`/`12m`/`2.5h` (`busclient._fmt_age`); non-numeric
/// input passes through as text.
fn fmt_age(v: &Value) -> String {
    let num: Option<f64> = match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    };
    match num {
        None => value_to_str(v),
        Some(mut a) => {
            if a < 0.0 {
                a = 0.0;
            }
            if a < 120.0 {
                format!("{a:.0}s")
            } else if a < 7200.0 {
                format!("{:.0}m", a / 60.0)
            } else {
                format!("{:.1}h", a / 3600.0)
            }
        }
    }
}

/// Readable one-line payload (`busclient._summarize_payload`): dicts with a
/// body key (`note`/`q`/`msg`/`detail`/`status`/`working_on`) render
/// `[event re task] body`; tag-only dicts render tags plus up to 4 scalar
/// `k=v` pairs; double-encoded JSON strings unwrap; else compact JSON.
fn summarize_payload(payload: &Value) -> String {
    if let Value::String(s) = payload {
        if s.trim_start().starts_with('{') {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(s) {
                if [
                    "note",
                    "q",
                    "msg",
                    "detail",
                    "status",
                    "working_on",
                    "event",
                    "re",
                    "task",
                    "help",
                ]
                .iter()
                .any(|k| map.contains_key(*k))
                {
                    return summarize_payload(&Value::Object(map));
                }
            }
        }
        return s.clone();
    }
    if let Value::Object(map) = payload {
        // First EXISTING body key (nested `.get` defaults, not first truthy).
        let mut body: Option<&Value> = None;
        for k in ["note", "q", "msg", "detail", "status", "working_on"] {
            if let Some(v) = map.get(k) {
                body = Some(v);
                break;
            }
        }
        let mut tags: Vec<String> = Vec::new();
        for k in ["event", "re", "task"] {
            if let Some(v) = map.get(k) {
                if truthy(v) {
                    tags.push(value_to_str(v));
                }
            }
        }
        if let Some(h) = map.get("help") {
            if truthy(h) {
                tags.insert(0, format!("help:{}", value_to_str(h)));
            }
        }
        if let Some(Value::String(b)) = body {
            if !b.trim().is_empty() {
                let prefix = if tags.is_empty() {
                    String::new()
                } else {
                    format!("[{}] ", tags.join(" "))
                };
                return format!("{prefix}{b}");
            }
        }
        if !tags.is_empty() {
            let mut pairs = Vec::new();
            for (k, v) in map {
                if ["from", "event", "re", "task", "help"].contains(&k.as_str()) || pairs.len() >= 4
                {
                    continue;
                }
                match v {
                    Value::Bool(b) => {
                        pairs.push(format!("{k}={}", if *b { "True" } else { "False" }))
                    }
                    Value::Null => pairs.push(format!("{k}=None")),
                    Value::Number(n) => pairs.push(format!("{k}={n}")),
                    Value::String(s) => {
                        let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
                        let trunc: String = flat.chars().take(40).collect();
                        pairs.push(format!("{k}={trunc}"));
                    }
                    _ => {}
                }
            }
            let mut out = format!("[{}]", tags.join(" "));
            if !pairs.is_empty() {
                out.push(' ');
                out.push_str(&pairs.join(" "));
            }
            return out;
        }
    }
    compact(payload)
}

/// `seq sender [age] payload...` (`busclient.short_frame`, `width=None`:
/// `show` promises the complete payload, never truncated).
fn short_frame(msg: &Value) -> String {
    short_frame_width(msg, None)
}

/// `short_frame` with `busclient.short_frame(width)` truncation: payload
/// text over `width` chars gains a `…` suffix (`sub` defaults to 240,
/// `--full` passes `None`). `--maxlen` truncates the whole line after.
fn short_frame_width(msg: &Value, width: Option<usize>) -> String {
    let payload = msg.get("payload").unwrap_or(&Value::Null);
    let mut text = summarize_payload(payload);
    text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(w) = width {
        if text.chars().count() > w {
            text = text.chars().take(w).collect::<String>() + "…";
        }
    }
    let seq = msg
        .get("seq")
        .map(value_to_str)
        .unwrap_or_else(|| "?".to_string());
    let sender = msg
        .get("sender")
        .map(value_to_str)
        .unwrap_or_else(|| "?".to_string());
    let mut head = format!("{seq} {sender}");
    // `as_f64` rejects bools, matching the `not isinstance(ts, bool)` guard.
    if let Some(ts) = msg.get("ts").and_then(|v| v.as_f64()) {
        head.push(' ');
        head.push_str(&fmt_age(&json!(now_secs() - ts)));
    }
    format!("{head} {text}")
}

/// Frame payload as one compact JSON line (`busclient.payload_text`).
fn payload_text(msg: &Value) -> String {
    compact(msg.get("payload").unwrap_or(&Value::Null))
}

/// One line per subscription: `sub_id agent pattern age dlv/drop/q`
/// (`busclient.short_subs`; broker supplies `age_s`).
fn short_subs(resp: &Value) -> String {
    let subs = resp.get("subs").and_then(|v| v.as_array());
    let missing = Value::String("?".to_string());
    let mut lines = Vec::new();
    for s in subs.into_iter().flatten() {
        let obj = match s.as_object() {
            Some(o) => o,
            None => continue,
        };
        let get = |k: &str| {
            obj.get(k)
                .map(value_to_str)
                .unwrap_or_else(|| "?".to_string())
        };
        let age = obj.get("age_s").unwrap_or(&missing);
        lines.push(format!(
            "{} {} {} age={} dlv={} drop={} q={}",
            get("sub_id"),
            get("agent"),
            get("pattern"),
            fmt_age(age),
            get("delivered"),
            get("dropped"),
            get("queued"),
        ));
    }
    lines.join("\n")
}

/// Parse `90s`/`30m`/`2h`/`1d` (bare number seconds) into float seconds
/// (`busclient.parse_age`). Errors on bad shape or non-positive.
fn parse_age(s: &str) -> Result<f64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err(format!("invalid age {s:?}; want like 90s, 30m, 2h, 1d"));
    }
    let (num, unit) = match t.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&t[..t.len() - c.len_utf8()], Some(c)),
        _ => (t, None),
    };
    let scale = match unit.map(|c| c.to_ascii_lowercase()) {
        None | Some('s') => 1.0,
        Some('m') => 60.0,
        Some('h') => 3600.0,
        Some('d') => 86400.0,
        Some(_) => return Err(format!("invalid age {s:?}; want like 90s, 30m, 2h, 1d")),
    };
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid age {s:?}; want like 90s, 30m, 2h, 1d"))?;
    if !n.is_finite() || n <= 0.0 {
        return Err(format!("invalid age {s:?}; must be positive"));
    }
    // Reject empty numeric part (`s` alone) and interior spaces.
    if num.trim().is_empty() || num.chars().any(|c| c.is_whitespace()) {
        return Err(format!("invalid age {s:?}; want like 90s, 30m, 2h, 1d"));
    }
    Ok(n * scale)
}

/// True when the frame's broker `ts` is at/after `cutoff` (frames without
/// a numeric `ts` are kept, matching `busclient.frame_fresh` leniency).
fn frame_fresh(fr: &Value, cutoff: f64) -> bool {
    let ts = fr.get("msg").and_then(|m| m.get("ts"));
    match ts {
        None => true,
        Some(Value::Bool(_)) => true,
        Some(v) => match v.as_f64() {
            Some(t) => t >= cutoff,
            None => true,
        },
    }
}

/// True when glob `pattern` matches any topic in a `topics` reply
/// (`busclient.pattern_matches_topics`, `fnmatchcase` semantics via the
/// shared `agent_bus::subs` matcher).
fn pattern_matches_topics(pattern: &str, topics_resp: &Value) -> bool {
    let topics = topics_resp.get("topics").and_then(|v| v.as_array());
    topics.into_iter().flatten().any(|t| {
        t.get("topic")
            .and_then(|v| v.as_str())
            .is_some_and(|name| agent_bus::subs::topic_matches(name, pattern))
    })
}

/// Highest seq on single `topic` (0 when empty/missing), for `--new-only`.
/// Uses the `topics` listing (same subscribe-cover visibility as `sub`).
fn latest_seq(cfg: &Config, topic: &str) -> Result<u64, String> {
    let mut client = connect(cfg).map_err(|e| e.to_string())?;
    let listed = rpc(&mut client, &json!({"op": "topics"}))?;
    let topics = listed.get("topics").and_then(|v| v.as_array());
    for t in topics.into_iter().flatten() {
        if t.get("topic").and_then(|v| v.as_str()) == Some(topic) {
            return Ok(t.get("seq").and_then(|v| v.as_u64()).unwrap_or(0));
        }
    }
    Ok(0)
}

/// Heartbeat status text (`busclient._agent_status_text`): JSON-object
/// heartbeat strings summarize like board payloads.
fn agent_status_text(status: &Value) -> String {
    if let Value::String(s) = status {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            if v.is_object() {
                return summarize_payload(&v);
            }
        }
        return s.clone();
    }
    value_to_str(status)
}

fn agent_info<'a>(resp: &'a Value, name: &str) -> Option<&'a serde_json::Map<String, Value>> {
    resp.get("agents")?.as_object()?.get(name)?.as_object()
}

/// One `name age status` line per agent, fresh-first (`busclient.short_agents`
/// with `fresh_first=True`, the legacy default). Stale entries (broker
/// `online: false`) carry a `(stale)` marker. Non-dict entries render from an
/// empty record instead of crashing (leniency; the broker always sends dicts).
fn short_agents(resp: &Value) -> String {
    let empty = serde_json::Map::new();
    let agents = resp
        .get("agents")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let mut names: Vec<&String> = agents.keys().collect();
    names.sort_by(|a, b| {
        let rank = |n: &str| -> (u8, u64) {
            let info = agent_info(resp, n);
            let online = info.and_then(|m| m.get("online")).is_none_or(truthy);
            let age = info
                .and_then(|m| m.get("age_s"))
                .and_then(|v| match v {
                    Value::Number(n) => n.as_f64(),
                    Value::String(s) => s.parse::<f64>().ok(),
                    _ => None,
                })
                .unwrap_or(f64::INFINITY);
            (u8::from(!online), age.to_bits())
        };
        // total_cmp over the bit patterns keeps the fresh-first order total.
        rank(a).0.cmp(&rank(b).0).then_with(|| {
            f64::from_bits(rank(a).1)
                .total_cmp(&f64::from_bits(rank(b).1))
                .then_with(|| a.cmp(b))
        })
    });
    let mut lines = Vec::new();
    for name in names {
        let info = agent_info(resp, name);
        let missing = Value::String("?".to_string());
        let age = info.and_then(|m| m.get("age_s")).unwrap_or(&missing);
        let online = info.and_then(|m| m.get("online")).is_none_or(truthy);
        let stale = if online { "" } else { " (stale)" };
        let status = info.and_then(|m| m.get("status")).unwrap_or(&Value::Null);
        lines.push(format!(
            "{name} {} {}{stale}",
            fmt_age(age),
            agent_status_text(status)
        ));
    }
    lines.join("\n")
}

/// Value-only `kv-get` rendering (`busclient.short_kv`): `None` when missing.
fn short_kv(resp: &Value) -> Option<String> {
    let obj = resp.as_object()?;
    if !obj.get("found").is_some_and(truthy) {
        return None;
    }
    match obj.get("value").unwrap_or(&Value::Null) {
        Value::String(s) => Some(s.clone()),
        v => Some(compact(v)),
    }
}

/// One key per line (`busclient.short_kv_list`).
fn short_kv_list(resp: &Value) -> String {
    match resp.get("keys").and_then(|v| v.as_array()) {
        Some(keys) => keys.iter().map(value_to_str).collect::<Vec<_>>().join("\n"),
        None => String::new(),
    }
}

/// One `key = value` line per triple (`busclient.short_kv_values`).
fn short_kv_values(items: &[(String, bool, Value)]) -> String {
    items
        .iter()
        .map(|(k, found, v)| {
            if !found {
                format!("{k} = <not-found>")
            } else if let Value::String(s) = v {
                format!("{k} = {s}")
            } else {
                format!("{k} = {}", compact(v))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compact byte count like `512B`/`1.5KB`/`5.2MB` (`busclient._fmt_bytes`);
/// negatives clamp to `0B`, non-numeric input passes through as text.
fn fmt_bytes(v: &Value) -> String {
    let num: Option<f64> = match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    };
    match num {
        None => value_to_str(v),
        Some(mut f) => {
            if !f.is_finite() {
                return value_to_str(v);
            }
            if f < 0.0 {
                f = 0.0;
            }
            if f < 1024.0 {
                format!("{f:.0}B")
            } else if f < 1024.0 * 1024.0 {
                format!("{:.1}KB", f / 1024.0)
            } else if f < 1024.0 * 1024.0 * 1024.0 {
                format!("{:.1}MB", f / (1024.0 * 1024.0))
            } else {
                format!("{:.1}GB", f / (1024.0 * 1024.0 * 1024.0))
            }
        }
    }
}

/// One-line broker health summary (`busclient.short_stats`): missing
/// counters (native gaps like `drops`/`subs`) render as `?`, never as
/// zero-filled placeholders.
fn short_stats(resp: &Value) -> String {
    let empty = serde_json::Map::new();
    let st = resp
        .get("stats")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let missing = Value::String("?".to_string());
    let get = |k: &str| st.get(k).unwrap_or(&missing);
    [
        format!("up {}", fmt_age(get("uptime_s"))),
        format!("posts {}", value_to_str(get("posts"))),
        format!("drops {}", value_to_str(get("drops"))),
        format!("rl {}", value_to_str(get("rate_limited"))),
        format!("topics {}", value_to_str(get("topics"))),
        format!("subs {}", value_to_str(get("subs"))),
        format!("agents {}", value_to_str(get("agents"))),
        format!("kv {}", value_to_str(get("kv_keys"))),
        format!("wal {}", fmt_bytes(get("wal_bytes"))),
    ]
    .join(" ")
}

/// One line per topic: `name seq=N retained=M age=A`
/// (`busclient.short_topics` with an injected `now` clock).
fn short_topics(resp: &Value, now: f64) -> String {
    let topics = resp
        .get("topics")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut lines = Vec::new();
    for t in &topics {
        let Some(obj) = t.as_object() else { continue };
        let missing = Value::String("?".to_string());
        // `as_f64` rejects bools, matching `not isinstance(ts, bool)`.
        let age = match obj.get("last_ts").and_then(|v| v.as_f64()) {
            Some(ts) => fmt_age(&json!(now - ts)),
            None => "?".to_string(),
        };
        lines.push(format!(
            "{} seq={} retained={} age={age}",
            obj.get("topic")
                .map(value_to_str)
                .unwrap_or_else(|| "?".to_string()),
            value_to_str(obj.get("seq").unwrap_or(&missing)),
            value_to_str(obj.get("retained").unwrap_or(&missing)),
        ));
    }
    lines.join("\n")
}

/// One-line quota/rate summary (`busclient.short_limits`): `None` quota/
/// rate render as `∞`, non-empty `topic_rates` adds `+N topic-rates`.
fn short_limits(resp: &Value) -> String {
    let obj = resp.as_object();
    let missing = Value::String("?".to_string());
    let used = obj
        .and_then(|m| m.get("art_used_bytes"))
        .unwrap_or(&missing);
    let quota_s = match obj.and_then(|m| m.get("art_quota_bytes")) {
        None | Some(Value::Null) => "\u{221e}".to_string(),
        Some(v) => fmt_bytes(v),
    };
    let rate_s = match obj.and_then(|m| m.get("rate_per_s")) {
        None | Some(Value::Null) => "\u{221e}".to_string(),
        Some(v) => format!("{}/s", value_to_str(v)),
    };
    let extra = match obj.and_then(|m| m.get("topic_rates")) {
        Some(Value::Object(m)) if !m.is_empty() => format!(" +{} topic-rates", m.len()),
        _ => String::new(),
    };
    format!("art {}/{} rate {}{extra}", fmt_bytes(used), quota_s, rate_s)
}

#[cfg(test)]
mod lease_format_tests {
    //! Pure formatter checks for the lease short renderers, the bounded
    //! token-file read, and the fixed lease diagnostics. Success fixtures
    //! transcribe the frozen legacy `broker.py:1380-1493` reply shapes
    //! (passive text reference) plus the native flat shape; ordinary
    //! positive values only, no broker, no CLI execution, no failure
    //! injection. Refusal fixtures assert the fixed category words and
    //! that token/error text is omitted, as pure string checks.
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    const FAKE_TOKEN: &str = "tok-legacy-fake-0123456789abcdef";

    #[test]
    fn short_accepts_legacy_wrapped_acquire() {
        // broker.py claim_acquire success: {ok, lease:{...}, dup}.
        let resp = json!({
            "ok": true,
            "lease": {
                "resource": "repo/legacy.rs",
                "owner": "alice",
                "token": FAKE_TOKEN,
                "fencing": 7,
                "acquired_at": 1790000000.0,
                "expires_at": 1790000060.5
            },
            "dup": false
        });
        let out = short_claim_acquired(&resp).expect("wrapped acquire renders");
        assert_eq!(out, "acquired repo/legacy.rs fencing=7 expires_at=1790000060.5");
        assert!(!out.contains("tok-legacy"), "{out}");
    }

    #[test]
    fn short_accepts_native_flat_acquire() {
        // Native wire.rs op_acquire success shape (existing schema).
        let resp = json!({
            "ok": true,
            "owner": "alice",
            "resource": "repo/native.rs",
            "token": FAKE_TOKEN,
            "fencing": 1,
            "acquired_at": 1790000000.0,
            "expires_at": 1790000060.5
        });
        let out = short_claim_acquired(&resp).expect("flat acquire renders");
        assert_eq!(out, "acquired repo/native.rs fencing=1 expires_at=1790000060.5");
        assert!(!out.contains("tok-legacy"), "{out}");
    }

    #[test]
    fn short_accepts_legacy_wrapped_renew() {
        // broker.py claim_renew success: {ok, lease:{...}}.
        let resp = json!({
            "ok": true,
            "lease": {
                "resource": "repo/legacy.rs",
                "owner": "alice",
                "token": FAKE_TOKEN,
                "fencing": 7,
                "expires_at": 1790000120.5
            }
        });
        let out = short_claim_renewed(&resp).expect("wrapped renew renders");
        assert_eq!(out, "renewed repo/legacy.rs fencing=7 expires_at=1790000120.5");
        assert!(!out.contains("tok-legacy"), "{out}");
    }

    #[test]
    fn short_accepts_legacy_held_and_free_status() {
        // broker.py claim_status held: {ok, held, resource, holder, token,
        // fencing, expires_at}; free: {ok, held:false, resource, fencing}.
        let held = json!({
            "ok": true,
            "held": true,
            "resource": "repo/legacy.rs",
            "holder": "alice",
            "token": FAKE_TOKEN,
            "fencing": 7,
            "expires_at": 1790000060.5
        });
        let out = short_claim_status(&held).expect("held renders");
        assert_eq!(
            out,
            "held repo/legacy.rs holder=alice fencing=7 expires_at=1790000060.5"
        );
        assert!(!out.contains("tok-legacy"), "{out}");
        let free = json!({
            "ok": true,
            "held": false,
            "resource": "repo/legacy.rs",
            "fencing": 7
        });
        let out = short_claim_status(&free).expect("free with fencing renders");
        assert_eq!(out, "free repo/legacy.rs fencing=7");
        // Native free shape (no fencing supplied) still renders bare.
        let native_free = json!({"ok": true, "resource": "repo/n.rs", "live": false});
        let out = short_claim_status(&native_free).expect("native free renders");
        assert_eq!(out, "free repo/n.rs");
    }

    #[test]
    fn short_accepts_release_and_list_shapes() {
        // broker.py claim_release / claim_list success shapes (shared with
        // native; list is legacy parity).
        let rel = json!({"ok": true, "released": true, "resource": "repo/a.rs"});
        assert_eq!(short_claim_release(&rel).as_deref(), Some("released repo/a.rs"));
        let free = json!({"ok": true, "released": false, "resource": "repo/a.rs"});
        assert_eq!(short_claim_release(&free).as_deref(), Some("not-held repo/a.rs"));
        let li = json!({
            "ok": true,
            "leases": [
                {"resource": "repo/a.rs", "holder": "alice", "fencing": 1,
                 "expires_at": 1790000060.5},
                {"resource": "repo/b.rs", "holder": "bob", "fencing": 2,
                 "expires_at": 1790000070.5}
            ]
        });
        let out = short_claim_list(&li).expect("list renders");
        assert_eq!(
            out,
            "repo/a.rs holder=alice fencing=1 expires_at=1790000060.5\n\
             repo/b.rs holder=bob fencing=2 expires_at=1790000070.5"
        );
    }

    #[test]
    fn token_file_read_returns_first_trimmed_line() {
        // Tiny ordinary token file through the public entry point.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("agent-bus-r81-token-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tok");
        std::fs::write(&path, "  tok-tiny-01  \nsecond-line-ignored\n").unwrap();
        let got = read_lease_token(None, Some(path.to_string_lossy().to_string()))
            .expect("tiny token file reads");
        assert_eq!(got, "tok-tiny-01");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lease_diagnostics_use_fixed_categories_without_token_or_broker_text() {
        // Refusal-shaped replies carry holder tokens + broker text; the
        // fixed diagnostics must report only op + category word.
        for (flag, cat) in [
            ("conflict", "conflict"),
            ("expired", "expired"),
            ("retired", "retired"),
            ("capacity", "capacity"),
        ] {
            // Computed flag key (json! literal keys cannot interpolate).
            let mut obj = serde_json::Map::new();
            obj.insert("ok".into(), json!(false));
            obj.insert("error".into(), json!(format!("broker says no ({flag})")));
            obj.insert(flag.into(), json!(true));
            obj.insert("holder".into(), json!("alice"));
            obj.insert("token".into(), json!(FAKE_TOKEN));
            obj.insert("fencing".into(), json!(7));
            obj.insert("expires_at".into(), json!(1790000060.5));
            let resp = Value::Object(obj);
            let msg = lease_refused(LeaseOp::Acquire, &resp);
            assert!(msg.contains(cat), "{msg}");
            assert!(msg.contains("claim-acquire"), "{msg}");
            assert!(!msg.contains(FAKE_TOKEN), "{msg}");
            assert!(!msg.contains("broker says no"), "{msg}");
        }
        let bare = json!({"error": "broker says no"});
        let msg = lease_refused(LeaseOp::Status, &bare);
        assert!(msg.contains("refused by broker"), "{msg}");
        assert!(!msg.contains("broker says no"), "{msg}");
        // Unexpected-shape guidance: mutating verbs warn + reconcile,
        // reads stay short; both name the single-RPC policy.
        let msg = lease_unexpected(LeaseOp::Renew);
        assert!(msg.contains("mutation status uncertain"), "{msg}");
        assert!(msg.contains("never resend"), "{msg}");
        assert!(msg.contains("no advisory fallback"), "{msg}");
        let msg = lease_unexpected(LeaseOp::List);
        assert!(msg.contains("unexpected broker reply"), "{msg}");
        assert!(msg.contains("single RPC, no retry"), "{msg}");
    }
}
