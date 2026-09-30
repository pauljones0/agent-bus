//! agent-bus-broker: native Rust broker binary plus one-shot client commands.
//!
//! - `serve`: replay the WAL (fail closed on corruption) and serve the
//!   JSON-lines wire (TCP, plus a Unix socket when configured) with
//!   transitional `tokens.json` grants. One owner holds every listener.
//! - `post` / `fetch`: one-shot authenticated client commands for migration
//!   verification against either broker (TCP `--addr` or Unix `--unix`).
//! - `migrate`: offline legacy snapshot+WAL import into a new WAL-only
//!   output (quiescent copies/synthetic only, never production paths).
//!
//! Env defaults mirror the transitional broker: `AGENT_BUS_WAL`
//! (default `./data/wal.log`), `AGENT_BUS_TOKENS` (default
//! `./tokens.json`), `AGENT_BUS_HOST`/`AGENT_BUS_PORT` (default
//! `127.0.0.1:8379`) for TCP, `AGENT_BUS_SOCK` (no default: Unix is
//! enabled only when `--unix` or an explicit `AGENT_BUS_SOCK` is given)
//! for the Unix socket, `AGENT_BUS_OPEN=1` for the dev-only open mode.
//! TLS remains separate migration debt (never enabled here).

use std::net::TcpListener;

use agent_bus::acl::TokenStore;
use agent_bus::wire::{load_tokens, Client, Server};
use serde_json::{json, Value};

fn usage() -> &'static str {
    "usage: agent-bus-broker [serve [--wal P] [--tokens P] [--listen ADDR] [--unix PATH]]\n       agent-bus-broker post [--addr A | --unix P] --agent N --token T --topic TOP --payload JSON [--ttl-ms N] [--corr-id C] [--reply-to R]\n       agent-bus-broker fetch [--addr A | --unix P] --agent N --token T --topic TOP [--from-seq N] [--limit N] [--until_seq N]\n       agent-bus-broker migrate --wal P --out P [--snapshot P] [--now F]"
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn env(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.get(1).map(String::as_str).unwrap_or("serve");
    match cmd {
        "serve" => {
            let wal = arg(args, "--wal").unwrap_or_else(|| env("AGENT_BUS_WAL", "./data/wal.log"));
            let tokens_path =
                arg(args, "--tokens").unwrap_or_else(|| env("AGENT_BUS_TOKENS", "./tokens.json"));
            let listen = arg(args, "--listen").unwrap_or_else(|| {
                format!("{}:{}", env("AGENT_BUS_HOST", "127.0.0.1"), env("AGENT_BUS_PORT", "8379"))
            });
            // Unix is opt-in (no default path): an explicit `--unix` flag
            // wins, else an explicitly set `AGENT_BUS_SOCK`, else TCP-only.
            // This preserves existing TCP-only `serve` when Unix is not
            // configured, and never implicitly binds the production default
            // `/tmp/agent-bus.sock`.
            let unix_path: Option<String> = arg(args, "--unix")
                .or_else(|| std::env::var("AGENT_BUS_SOCK").ok().filter(|s| !s.is_empty()));
            let open = std::env::var("AGENT_BUS_OPEN").as_deref() == Ok("1");
            let tokens: TokenStore = if open {
                eprintln!("[broker] OPEN MODE: any token accepted (dev only)");
                TokenStore::from_json_str("{}").expect("empty token store is valid")
            } else {
                load_tokens(std::path::Path::new(&tokens_path))
                    .map_err(|e| format!("load tokens {tokens_path}: {e}"))?
            };
            let server = Server::new(std::path::PathBuf::from(&wal), tokens)
                .map_err(|e| format!("replay {wal}: {e}"))?
                .with_open_mode(open)
                .with_tokens_path(std::path::PathBuf::from(&tokens_path));
            let listener =
                TcpListener::bind(&listen).map_err(|e| format!("bind {listen}: {e}"))?;
            // Normal SIGINT/SIGTERM shutdown reuses the reviewed scheduler
            // signal pattern (raw `signal` binding + atomic flag; the C
            // handler only records, so no blocking joins, locks, or log
            // formatting ever run in the handler). All joins happen below
            // on this normal thread. See `docs/NATIVE_BROKER_LIFECYCLE.md`.
            if let Err(e) = agent_bus::scheduler::install_shutdown_handlers() {
                return Err(format!("install signal handlers: {e}"));
            }
            #[cfg(unix)]
            let mut broker = match unix_path {
                Some(ref p) => {
                    eprintln!("[broker] listening on {listen} + unix {p} (wal={wal})");
                    server
                        .serve_owned_dual(
                            listener,
                            std::path::Path::new(p),
                            agent_bus::wire::MAINTENANCE_INTERVAL_DEFAULT,
                        )
                        .map_err(|e| format!("owned serve: {e}"))?
                }
                None => {
                    eprintln!("[broker] listening on {listen} (wal={wal})");
                    server
                        .serve_owned(listener, agent_bus::wire::MAINTENANCE_INTERVAL_DEFAULT)
                        .map_err(|e| format!("owned serve: {e}"))?
                }
            };
            #[cfg(not(unix))]
            let mut broker = {
                if let Some(p) = unix_path {
                    return Err(format!(
                        "unix socket {p} requested but unix sockets are not supported on this platform"
                    ));
                }
                eprintln!("[broker] listening on {listen} (wal={wal})");
                server
                    .serve_owned(listener, agent_bus::wire::MAINTENANCE_INTERVAL_DEFAULT)
                    .map_err(|e| format!("owned serve: {e}"))?
            };
            // Wait for the first shutdown signal in bounded 50ms slices
            // (same responsiveness as the scheduler wait); then stop
            // admitting, join every connection/writer/maintenance thread,
            // and exit with the conventional 128+signal status.
            loop {
                if let Some(code) = agent_bus::scheduler::shutdown_exit_code() {
                    eprintln!("[broker] signal received, shutting down...");
                    broker.stop_and_join();
                    eprintln!("[broker] bye");
                    std::process::exit(code);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        "post" => {
            let mut c = connect(args)?;
            let mut req = json!({
                "op": "post",
                "topic": need(args, "--topic")?,
                "payload": need(args, "--payload")
                    .and_then(|p| serde_json::from_str::<Value>(&p).map_err(|e| e.to_string()))?,
            });
            if let Some(t) = arg(args, "--ttl-ms") {
                req["ttl_ms"] = json!(t.parse::<f64>().map_err(|e| e.to_string())?);
            }
            if let Some(corr) = arg(args, "--corr-id") {
                req["corr_id"] = json!(corr);
            }
            if let Some(reply) = arg(args, "--reply-to") {
                req["reply_to"] = json!(reply);
            }
            let resp = c.rpc(&req).map_err(|e| e.to_string())?;
            println!("{resp}");
            if resp.get("ok") == Some(&json!(true)) { Ok(()) } else { Err("post refused".into()) }
        }
        "fetch" => {
            let mut c = connect(args)?;
            let mut req = json!({"op": "fetch", "topic": need(args, "--topic")?});
            for (flag, key) in [("--from-seq", "from_seq"), ("--limit", "limit"), ("--until-seq", "until_seq")] {
                if let Some(v) = arg(args, flag) {
                    req[key] = json!(v.parse::<u64>().map_err(|e| e.to_string())?);
                }
            }
            let resp = c.rpc(&req).map_err(|e| e.to_string())?;
            println!("{resp}");
            if resp.get("ok") == Some(&json!(true)) { Ok(()) } else { Err("fetch refused".into()) }
        }
        "migrate" => {
            let wal = need(args, "--wal")?;
            let out = need(args, "--out")?;
            let snapshot = arg(args, "--snapshot");
            let now = match arg(args, "--now") {
                None => now_f64(),
                Some(s) => s.parse::<f64>().map_err(|e| format!("bad --now: {e}"))?,
            };
            if !now.is_finite() {
                return Err("bad --now: non-finite time".into());
            }
            let report = agent_bus::migration::migrate_legacy_to_wal(
                snapshot.as_deref().map(std::path::Path::new),
                std::path::Path::new(&wal),
                std::path::Path::new(&out),
                now,
            )
            .map_err(|e| format!("migrate failed: {e}"))?;
            println!(
                "{}",
                json!({
                    "ok": true,
                    "snapshot_keys": report.snapshot_keys,
                    "snapshot_skipped": report.snapshot_skipped,
                    "wal_posts": report.wal_posts,
                    "wal_claims": report.wal_claims,
                    "opaque": report.opaque,
                    "kv_live": report.kv_live,
                    "out_bytes": report.out_bytes,
                })
            );
            Ok(())
        }
        _ => Err(usage().into()),
    }
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    arg(args, name).ok_or_else(|| format!("missing {name}\n{}", usage()))
}

fn connect(args: &[String]) -> Result<Client, String> {
    let agent = need(args, "--agent")?;
    let token = need(args, "--token")?;
    // Explicit `--unix` wins; else explicit `--addr` (preserved TCP);
    // else an explicitly set `AGENT_BUS_SOCK`; else the legacy missing
    // `--addr` error. Unix never silently falls back to TCP.
    if let Some(p) = arg(args, "--unix") {
        #[cfg(unix)]
        {
            return Client::connect_unix(std::path::Path::new(&p), &agent, &token)
                .map_err(|e| e.to_string());
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            return Err("unix sockets are not supported on this platform".to_string());
        }
    }
    if let Some(addr) = arg(args, "--addr") {
        return Client::connect(&addr, &agent, &token).map_err(|e| e.to_string());
    }
    if let Ok(p) = std::env::var("AGENT_BUS_SOCK") {
        if !p.is_empty() {
            #[cfg(unix)]
            {
                return Client::connect_unix(std::path::Path::new(&p), &agent, &token)
                    .map_err(|e| e.to_string());
            }
            #[cfg(not(unix))]
            {
                return Err("unix sockets are not supported on this platform".to_string());
            }
        }
    }
    Err(format!("missing --addr\n{}", usage()))
}

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(e) = run(&args) {
        eprintln!("agent-bus-broker: {e}");
        std::process::exit(1);
    }
}
