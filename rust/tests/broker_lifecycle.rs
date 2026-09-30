//! Owned broker lifecycle: start/stop/drop/join, graceful post/fetch plus
//! replay, maintenance exit, and SIGINT/SIGTERM of test-owned children.
//!
//! Benign functional checks only: small authenticated post/fetch on
//! ephemeral loopback ports with private temp WAL/tokens, then graceful
//! stop and WAL replay. No stress/exhaustion/races, no malicious
//! payloads, no live-service or protected-process interaction. Signals go
//! only to child brokers this file spawned (via their owned `Child` PID).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_bus::acl::TokenStore;
use agent_bus::wire::{Client, Server, StreamingConn};
use serde_json::{json, Value};

#[cfg(unix)]
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

fn broker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus-broker"))
}

fn tmpdir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "agent-bus-lifecycle-{name}-{}-{}",
        std::process::id(),
        name.len()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn fixture_store() -> TokenStore {
    TokenStore::from_json_str(
        r#"{"tok-test": {"agent": "tester", "publish": ["*"], "subscribe": ["*"]}}"#,
    )
    .expect("fixture tokens valid")
}

fn fresh_server(name: &str) -> (Server, PathBuf) {
    let dir = tmpdir(name);
    let wal = dir.join("wal.log");
    let server = Server::new(wal.clone(), fixture_store()).expect("fresh WAL starts clean");
    (server, wal)
}

fn serve_ephemeral(server: &Server, interval: Duration) -> (agent_bus::wire::OwnedBroker, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let broker = server
        .serve_owned(listener, interval)
        .expect("first serve_owned starts");
    (broker, addr)
}

fn wait_live(broker: &agent_bus::wire::OwnedBroker, want: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while broker.live_connections() != want {
        assert!(
            Instant::now() < deadline,
            "live connections never reached {want}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn write_fixture_tokens(dir: &Path) -> PathBuf {
    let path = dir.join("tokens.json");
    std::fs::write(
        &path,
        r#"{"tok-test": {"agent": "tester", "publish": ["*"], "subscribe": ["*"]}}"#,
    )
    .unwrap();
    path
}

fn spawn_broker(dir: &Path, wal: &Path, port: u16) -> Child {
    let tokens = write_fixture_tokens(dir);
    Command::new(broker_bin())
        .arg("serve")
        .arg("--wal")
        .arg(wal)
        .arg("--tokens")
        .arg(&tokens)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        // TCP-only children: an ambient `AGENT_BUS_SOCK` must never add an
        // unexpected Unix listener to these preserved lifecycle paths.
        .env_remove("AGENT_BUS_SOCK")
        .env_remove("AGENT_BUS_OPEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("broker child spawns")
}

fn wait_ready(addr: &str) -> Client {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match Client::connect(addr, "tester", "tok-test") {
            Ok(c) => return c,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("broker at {addr} never became ready: {e}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn exited(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("poll child") {
            Some(status) => return Some(status),
            None => {
                if Instant::now() > deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Spawn on a fresh port until the broker answers; returns child + client.
fn spawn_ready(dir: &Path, wal: &Path) -> (Child, Client, String) {
    for attempt in 0..3 {
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let mut child = spawn_broker(dir, wal, port);
        if let Some(status) = exited(&mut child, Duration::from_millis(300)) {
            if attempt == 2 {
                panic!("broker on {addr} exited at startup: {status}");
            }
            continue;
        }
        let client = wait_ready(&addr);
        return (child, client, addr);
    }
    unreachable!("spawn_ready retries exhausted");
}

#[cfg(unix)]
fn signal_child(child: &Child, sig: i32) {
    // SAFETY: signals only the PID of a child this test spawned and still
    // owns (not yet waited, so no PID reuse); fixed signal numbers only,
    // targeting no pre-existing or protected process.
    let pid = child.id() as i32;
    let r = unsafe { kill(pid, sig) };
    assert_eq!(r, 0, "signal {sig} reaches test-owned broker pid {pid}");
}

#[test]
fn owned_start_stop_join_idempotent() {
    let (server, _wal) = fresh_server("start-stop");
    let (mut broker, addr) = serve_ephemeral(&server, Duration::from_millis(10));
    assert!(!broker.is_stopping());
    assert_eq!(broker.live_connections(), 0);
    broker.stop();
    assert!(broker.is_stopping());
    broker.stop();
    broker.stop_and_join();
    broker.stop_and_join();
    assert!(broker.is_stopping());
    assert_eq!(broker.live_connections(), 0);
    // Listener is closed: new peers are refused.
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "port closed after join"
    );
    // Sequential reuse is allowed once fully joined.
    let (broker2, _addr2) = serve_ephemeral(&server, Duration::from_millis(10));
    broker2.shutdown();
}

#[test]
fn owned_drop_stops_and_joins() {
    let (server, _wal) = fresh_server("drop-stop");
    let (broker, addr) = serve_ephemeral(&server, Duration::from_millis(10));
    drop(broker);
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "port closed after drop"
    );
    // Drop's fallback join released the serving guard.
    let (broker2, _addr2) = serve_ephemeral(&server, Duration::from_millis(10));
    broker2.shutdown();
}

#[test]
fn owned_duplicate_start_rejected() {
    let (server, _wal) = fresh_server("dup-start");
    let (broker, _addr) = serve_ephemeral(&server, Duration::from_millis(10));
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let err = match server.serve_owned(listener2, Duration::from_millis(10)) {
        Ok(_) => panic!("second live owner must be rejected"),
        Err(e) => e,
    };
    assert!(err.contains("already serving"), "{err}");
    broker.shutdown();
    // After full shutdown a new owner may start.
    let (broker3, _addr3) = serve_ephemeral(&server, Duration::from_millis(10));
    broker3.shutdown();
}

#[test]
fn joined_handle_cannot_release_replacement_owner() {
    let (server, _wal) = fresh_server("replacement-owner");
    let (mut previous, _) = serve_ephemeral(&server, Duration::from_millis(10));
    previous.stop_and_join();
    let (current, _) = serve_ephemeral(&server, Duration::from_millis(10));

    // Repeated cleanup and Drop belong to the previous generation only.
    previous.stop_and_join();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(server.serve_owned(listener, Duration::from_millis(10)).is_err());
    drop(previous);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(server.serve_owned(listener, Duration::from_millis(10)).is_err());
    current.shutdown();

    // The replacement's own cleanup still releases its guard.
    let (next, _) = serve_ephemeral(&server, Duration::from_millis(10));
    next.shutdown();
}

#[test]
fn graceful_post_fetch_stop_replay() {
    let (server, wal) = fresh_server("graceful-replay");
    let handle = server.clone();
    let (mut broker, addr) = serve_ephemeral(&server, Duration::from_millis(10));
    let mut c = Client::connect(&addr, "tester", "tok-test").unwrap();
    let p = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}}))
        .unwrap();
    assert!(ok(&p), "{p}");
    assert_eq!(p["seq"], json!(1), "{p}");
    let f = c
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"].as_array().unwrap().len(), 1);
    assert_eq!(f["messages"][0]["payload"], json!({"n": 1}));
    // One live subscription on a second connection exercises ordinary
    // per-connection cleanup at shutdown.
    let mut s = StreamingConn::connect(&addr, "tester", "tok-test").unwrap();
    let (_sub_id, replayed, _cursor) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(replayed, 1);
    assert_eq!(handle.subs_len_for_test(), 1);
    wait_live(&broker, 2);
    // Keep both clients connected: owned shutdown itself must disconnect
    // them, remove their subscriptions and join their handlers/writers.
    broker.stop_and_join();
    assert_eq!(broker.live_connections(), 0);
    assert_eq!(handle.subs_len_for_test(), 0, "shutdown removed owned subs");
    drop(c);
    drop(s);
    drop(server);
    drop(handle);
    // Replay on the same WAL: the gracefully stopped post is durable.
    let server2 = Server::new(wal.clone(), fixture_store()).expect("replay after graceful stop");
    let (broker2, addr2) = serve_ephemeral(&server2, Duration::from_millis(10));
    let mut c2 = Client::connect(&addr2, "tester", "tok-test").unwrap();
    let f2 = c2
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f2), "{f2}");
    assert_eq!(f2["messages"].as_array().unwrap().len(), 1);
    assert_eq!(f2["messages"][0]["seq"], json!(1));
    assert_eq!(f2["messages"][0]["payload"], json!({"n": 1}));
    drop(c2);
    broker2.shutdown();
}

#[test]
fn maintenance_exits_with_broker() {
    let (server, _wal) = fresh_server("maint-exit");
    let (mut broker, _addr) = serve_ephemeral(&server, Duration::from_millis(10));
    std::thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    broker.stop_and_join();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "maintenance joined promptly"
    );
    // Worker + guard released: a new owner with a fresh worker starts.
    let (broker2, _addr2) = serve_ephemeral(&server, Duration::from_millis(10));
    broker2.shutdown();
}

#[cfg(unix)]
#[test]
fn sigterm_child_broker_graceful() {
    let dir = tmpdir("sigterm");
    let wal = dir.join("wal.log");
    let (mut child, mut c, _addr) = spawn_ready(&dir, &wal);
    let p = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}}))
        .unwrap();
    assert!(ok(&p), "{p}");
    drop(c);
    signal_child(&child, SIGTERM);
    let status =
        exited(&mut child, Duration::from_secs(15)).expect("SIGTERM broker exits promptly");
    assert_eq!(
        status.code(),
        Some(128 + SIGTERM),
        "SIGTERM exit status {status}"
    );
    // The acknowledged post replays after graceful shutdown.
    let (mut child2, mut c2, _addr2) = spawn_ready(&dir, &wal);
    let f = c2
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"].as_array().unwrap().len(), 1);
    assert_eq!(f["messages"][0]["payload"], json!({"n": 1}));
    drop(c2);
    signal_child(&child2, SIGTERM);
    let status2 = exited(&mut child2, Duration::from_secs(15)).expect("restart broker exits");
    assert_eq!(
        status2.code(),
        Some(128 + SIGTERM),
        "restart exit {status2}"
    );
}

#[cfg(unix)]
#[test]
fn sigint_child_broker_graceful() {
    let dir = tmpdir("sigint");
    let wal = dir.join("wal.log");
    let (mut child, mut c, _addr) = spawn_ready(&dir, &wal);
    let p = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 7}}))
        .unwrap();
    assert!(ok(&p), "{p}");
    drop(c);
    signal_child(&child, SIGINT);
    let status = exited(&mut child, Duration::from_secs(15)).expect("SIGINT broker exits promptly");
    assert_eq!(
        status.code(),
        Some(128 + SIGINT),
        "SIGINT exit status {status}"
    );
    // Restart proves the WAL is clean and the ack replayed.
    let (mut child2, mut c2, _addr2) = spawn_ready(&dir, &wal);
    let f = c2
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"][0]["payload"], json!({"n": 7}));
    drop(c2);
    signal_child(&child2, SIGTERM);
    let status2 = exited(&mut child2, Duration::from_secs(15)).expect("restart broker exits");
    assert_eq!(
        status2.code(),
        Some(128 + SIGTERM),
        "restart exit {status2}"
    );
}
