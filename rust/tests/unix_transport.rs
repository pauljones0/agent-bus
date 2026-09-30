//! Native Unix-domain transport: owned broker listeners, shared wire
//! client/streaming, broker serve CLI, and native agent-bus CLI.
//!
//! Benign functional checks only, `cfg(unix)` only: actual local Unix
//! broker startup on unique private temp socket paths, authenticated
//! ping/post/fetch plus durable replay, streaming subscribe delivery,
//! preserved TCP behavior, simultaneous TCP+Unix under one owner,
//! stop/drop socket cleanup, and normal owned restart after cleanup.
//! No production endpoints, no pre-existing PIDs, no fault/stress/race
//! trials, no malicious framing. Serial-friendly: unique paths per test.
//!
//! Legacy contracts (read as passive text, never executed):
//! `broker.py` listens simultaneously on TCP `HOST:PORT` plus Unix
//! `AGENT_BUS_SOCK` (default `/tmp/agent-bus.sock`); `busclient.py`
//! prefers Unix unless `--tcp`/`--tls`, when the socket path exists.
//! Native hardening (documented in `NATIVE_UNIX_TRANSPORT.md`): Unix is
//! opt-in via explicit `--unix`/`AGENT_BUS_SOCK` (no default-path probe),
//! pre-existing paths are never unlinked (explicit config error), and
//! Unix never silently falls back to TCP.

#![cfg(unix)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use agent_bus::acl::TokenStore;
use agent_bus::wire::{Client, Server, StreamingConn};
use serde_json::{json, Value};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn broker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus-broker"))
}

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus"))
}

fn tmpdir(name: &str) -> PathBuf {
    for _ in 0..1000 {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "agent-bus-r69-unix-{name}-{}-{n}",
            std::process::id()
        ));
        match std::fs::create_dir(&p) {
            Ok(()) => return p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create owned fixture directory: {e}"),
        }
    }
    panic!("cannot allocate a unique fixture directory");
}

fn sock_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.sock"))
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

fn fresh_server(dir: &Path) -> Server {
    let wal = dir.join("wal.log");
    Server::new(wal, fixture_store()).expect("fresh WAL starts clean")
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn wait_unix(path: &Path) -> Client {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match Client::connect_unix(path, "tester", "tok-test") {
            Ok(c) => return c,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("unix broker at {} never ready: {e}", path.display());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn wait_tcp(addr: &str) -> Client {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match Client::connect(addr, "tester", "tok-test") {
            Ok(c) => return c,
            Err(e) => {
                if Instant::now() > deadline {
                    panic!("tcp broker at {addr} never ready: {e}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
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

#[test]
fn unix_start_ping_post_fetch_replay() {
    let dir = tmpdir("ping-replay");
    let server = fresh_server(&dir);
    let sock = sock_path(&dir, "bus");
    let mut broker = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("unix serve starts");
    assert!(sock.exists(), "socket appears while serving");
    let mut c = Client::connect_unix(&sock, "tester", "tok-test").unwrap();
    let ping = c.rpc(&json!({"op": "ping"})).unwrap();
    assert!(ok(&ping), "{ping}");
    assert_eq!(ping.get("authed"), Some(&json!(true)), "{ping}");
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
    drop(c);
    broker.stop_and_join();
    assert!(!sock.exists(), "owned socket removed after stop");
    drop(server);
    // Durable replay on the same WAL via a fresh Unix path.
    let wal = dir.join("wal.log");
    let server2 = Server::new(wal, fixture_store()).expect("replay after unix stop");
    let sock2 = sock_path(&dir, "bus2");
    let broker2 = server2
        .serve_owned_unix(&sock2, Duration::from_millis(10))
        .expect("second unix serve starts");
    let mut c2 = Client::connect_unix(&sock2, "tester", "tok-test").unwrap();
    let f2 = c2
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f2), "{f2}");
    assert_eq!(f2["messages"][0]["seq"], json!(1));
    assert_eq!(f2["messages"][0]["payload"], json!({"n": 1}));
    drop(c2);
    broker2.shutdown();
    assert!(!sock2.exists(), "second socket removed after drop");
}

#[test]
fn unix_streaming_subscribe_delivery() {
    let dir = tmpdir("stream");
    let server = fresh_server(&dir);
    let sock = sock_path(&dir, "bus");
    let broker = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("unix serve starts");
    let mut s = StreamingConn::connect_unix(&sock, "tester", "tok-test").unwrap();
    let (_sub_id, replayed, _cursor) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(replayed, 0);
    let mut c = Client::connect_unix(&sock, "tester", "tok-test").unwrap();
    let p = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"hello": "unix"}}))
        .unwrap();
    assert!(ok(&p), "{p}");
    let msg = s
        .recv(Some(Duration::from_secs(5)))
        .expect("live delivery arrives");
    assert_eq!(msg["topic"], json!("t"));
    assert_eq!(msg["msg"]["payload"], json!({"hello": "unix"}));
    drop(c);
    drop(s);
    broker.shutdown();
    assert!(!sock.exists(), "socket removed after shutdown");
}

#[test]
fn tcp_preserved_after_unix_changes() {
    // Ordinary TCP control alongside the new Unix paths: same authenticated
    // ping/post/fetch through the preserved `serve_owned`/`Client::connect`.
    let dir = tmpdir("tcp-control");
    let wal = dir.join("wal.log");
    let server = Server::new(wal, fixture_store()).expect("fresh WAL starts clean");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let broker = server
        .serve_owned(listener, Duration::from_millis(10))
        .expect("tcp serve still starts");
    let mut c = Client::connect(&addr, "tester", "tok-test").unwrap();
    let ping = c.rpc(&json!({"op": "ping"})).unwrap();
    assert!(ok(&ping), "{ping}");
    let p = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"via": "tcp"}}))
        .unwrap();
    assert!(ok(&p), "{p}");
    let f = c
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"][0]["payload"], json!({"via": "tcp"}));
    drop(c);
    broker.shutdown();
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "shutdown closes the owned TCP listener"
    );
}

#[test]
fn dual_tcp_and_unix_one_owner() {
    let dir = tmpdir("dual");
    let server = fresh_server(&dir);
    let sock = sock_path(&dir, "bus");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut broker = server
        .serve_owned_dual(listener, &sock, Duration::from_millis(10))
        .expect("dual serve starts");
    // A second owner while dual is live must be rejected (one guard).
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(server
        .serve_owned(listener2, Duration::from_millis(10))
        .is_err());
    // Both transports share one state: post via TCP, fetch via Unix.
    let mut tcp = Client::connect(&addr, "tester", "tok-test").unwrap();
    let mut unix = Client::connect_unix(&sock, "tester", "tok-test").unwrap();
    let p = tcp
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 3}}))
        .unwrap();
    assert!(ok(&p), "{p}");
    let f = unix
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"][0]["payload"], json!({"n": 3}));
    // And the reverse direction.
    let p2 = unix
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 4}}))
        .unwrap();
    assert!(ok(&p2), "{p2}");
    let f2 = tcp
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 1}))
        .unwrap();
    assert!(ok(&f2), "{f2}");
    assert_eq!(f2["messages"][0]["payload"], json!({"n": 4}));
    drop(tcp);
    drop(unix);
    broker.stop_and_join();
    assert!(!sock.exists(), "dual shutdown removes owned socket");
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "dual shutdown closes TCP"
    );
    // Sequential reuse after full join.
    let listener3 = TcpListener::bind("127.0.0.1:0").unwrap();
    let broker2 = server
        .serve_owned(listener3, Duration::from_millis(10))
        .expect("new owner starts after dual join");
    broker2.shutdown();
}

#[test]
fn unix_stop_drop_cleanup_and_restart() {
    let dir = tmpdir("restart");
    let server = fresh_server(&dir);
    let sock = sock_path(&dir, "bus");
    // Explicit stop removes the socket; the same path restarts cleanly.
    let mut broker = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("first unix serve starts");
    assert!(sock.exists());
    broker.stop_and_join();
    assert!(!sock.exists(), "stop removes owned socket");
    let broker2 = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("restart on same path after cleanup");
    let mut c = Client::connect_unix(&sock, "tester", "tok-test").unwrap();
    let ping = c.rpc(&json!({"op": "ping"})).unwrap();
    assert!(ok(&ping), "{ping}");
    drop(c);
    // Drop without explicit stop still removes the socket.
    drop(broker2);
    assert!(!sock.exists(), "drop removes owned socket");
    // And a third generation may start.
    let broker3 = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("third generation starts");
    broker3.shutdown();
    assert!(!sock.exists());
}

#[test]
fn unix_existing_paths_rejected_without_removal() {
    let dir = tmpdir("existing");
    let server = fresh_server(&dir);
    // A regular file is never unlinked; startup fails explicitly.
    let file = dir.join("plain.txt");
    std::fs::write(&file, b"keep me").unwrap();
    let err = match server.serve_owned_unix(&file, Duration::from_millis(10)) {
        Ok(_) => panic!("existing regular file must be rejected"),
        Err(e) => e,
    };
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    // A live socket owned by someone else is likewise preserved.
    let sock = sock_path(&dir, "other");
    let held = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let err2 = match server.serve_owned_unix(&sock, Duration::from_millis(10)) {
        Ok(_) => panic!("existing socket must be rejected"),
        Err(e) => e,
    };
    assert!(err2.contains("already exists"), "{err2}");
    assert!(sock.exists(), "other owner's socket preserved");
    drop(held);
    assert!(sock.exists(), "still preserved after failed start");
    std::fs::remove_file(&sock).unwrap();
    // After the blocker is gone the same path serves normally.
    let broker = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("path serves after blocker removed");
    broker.shutdown();
    assert!(!sock.exists());
}

#[test]
fn unix_cli_uses_sock_env_and_tcp_override() {
    let dir = tmpdir("cli");
    let server = fresh_server(&dir);
    let sock = sock_path(&dir, "bus");
    let broker = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("unix serve starts");
    let tcp_dir = tmpdir("cli-tcp");
    let tcp_server = fresh_server(&tcp_dir);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let tcp_broker = tcp_server
        .serve_owned(listener, Duration::from_millis(10))
        .expect("TCP control starts");
    // Distinct owned brokers make the selected transport observable in
    // message history; no fixed or presumed-unused endpoint is contacted.
    let out = Command::new(cli_bin())
        .args(["post", "transport", r#"{"via":"unix"}"#])
        .env("AGENT_BUS_AGENT", "tester")
        .env("AGENT_BUS_TOKEN", "tok-test")
        .env("AGENT_BUS_HOST", "127.0.0.1")
        .env("AGENT_BUS_PORT", addr.port().to_string())
        .env("AGENT_BUS_SOCK", &sock)
        .output()
        .expect("spawn agent-bus Unix post");
    assert_eq!(
        out.status.code(),
        Some(0),
        "unix post succeeds: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let mut unix = Client::connect_unix(&sock, "tester", "tok-test").unwrap();
    let mut tcp = Client::connect(&addr.to_string(), "tester", "tok-test").unwrap();
    let fetch = json!({"op":"fetch", "topic":"transport", "from_seq":0});
    let unix_before = unix.rpc(&fetch).unwrap();
    let tcp_before = tcp.rpc(&fetch).unwrap();
    assert!(ok(&unix_before) && ok(&tcp_before));
    assert_eq!(unix_before["messages"].as_array().unwrap().len(), 1);
    assert_eq!(unix_before["messages"][0]["payload"], json!({"via":"unix"}));
    assert!(tcp_before["messages"].as_array().unwrap().is_empty());
    // The same environment plus --tcp selects the independent TCP broker.
    let out2 = Command::new(cli_bin())
        .arg("--tcp")
        .args(["post", "transport", r#"{"via":"tcp"}"#])
        .env("AGENT_BUS_AGENT", "tester")
        .env("AGENT_BUS_TOKEN", "tok-test")
        .env("AGENT_BUS_HOST", "127.0.0.1")
        .env("AGENT_BUS_PORT", addr.port().to_string())
        .env("AGENT_BUS_SOCK", &sock)
        .output()
        .expect("spawn agent-bus --tcp post");
    assert_eq!(out2.status.code(), Some(0), "TCP override succeeds");
    let tcp_after = tcp.rpc(&fetch).unwrap();
    let unix_after = unix.rpc(&fetch).unwrap();
    assert!(ok(&tcp_after) && ok(&unix_after));
    assert_eq!(tcp_after["messages"].as_array().unwrap().len(), 1);
    assert_eq!(tcp_after["messages"][0]["payload"], json!({"via":"tcp"}));
    assert_eq!(unix_after["messages"], unix_before["messages"]);
    drop(tcp);
    drop(unix);
    tcp_broker.shutdown();
    broker.shutdown();
    assert!(!sock.exists());
}

#[test]
fn unix_child_broker_dual_serve_graceful() {
    // Test-owned child via the real `serve` CLI with `--listen` + `--unix`:
    // both transports answer, SIGTERM exits 143, socket is cleaned.
    let dir = tmpdir("child-dual");
    let wal = dir.join("wal.log");
    let tokens = write_fixture_tokens(&dir);
    let sock = sock_path(&dir, "bus");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(broker_bin())
        .arg("serve")
        .arg("--wal")
        .arg(&wal)
        .arg("--tokens")
        .arg(&tokens)
        .arg("--listen")
        .arg(&addr)
        .arg("--unix")
        .arg(&sock)
        .env_remove("AGENT_BUS_SOCK")
        .env_remove("AGENT_BUS_OPEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("dual broker child spawns");
    let mut tcp = wait_tcp(&addr);
    let mut unix = wait_unix(&sock);
    let p = tcp
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 9}}))
        .unwrap();
    assert!(ok(&p), "{p}");
    let f = unix
        .rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0}))
        .unwrap();
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"][0]["payload"], json!({"n": 9}));
    drop(tcp);
    drop(unix);
    // Signal only this test-owned child PID (never pre-existing).
    let pid = child.id() as i32;
    let r = unsafe { libc_kill(pid, 15) };
    assert_eq!(r, 0, "SIGTERM reaches test-owned child {pid}");
    let status = exited(&mut child, Duration::from_secs(15)).expect("child exits promptly");
    assert_eq!(status.code(), Some(143), "SIGTERM exit {status}");
    assert!(!sock.exists(), "child shutdown removes owned socket");
}

#[cfg(unix)]
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[cfg(unix)]
unsafe fn libc_kill(pid: i32, sig: i32) -> i32 {
    // SAFETY: signals only the PID of a child this test spawned and still
    // owns (not yet waited, so no PID reuse); SIGTERM only.
    unsafe { kill(pid, sig) }
}
