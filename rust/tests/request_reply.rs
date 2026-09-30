//! Native request/reply CLI: owned-broker end-to-end workflows.
//!
//! Benign functional checks only: tiny isolated TCP/Unix brokers with two
//! test-owned peers, normal correlated replies, unrelated inbox traffic,
//! JSON/payload formatting, stdin `-`, equals/terminator parsing, and
//! legacy envelope compatibility. No production endpoints, no fault or
//! race trials, no malformed framing. Serial-friendly: unique paths and
//! ports per test.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use agent_bus::acl::TokenStore;
use agent_bus::wire::{Client, Server};
use serde_json::{json, Value};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus"))
}

fn tmpdir(name: &str) -> PathBuf {
    for _ in 0..1000 {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "agent-bus-r70-reqrep-{name}-{}-{n}",
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

#[cfg(unix)]
fn sock_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.sock"))
}

fn fixture_store_two() -> TokenStore {
    TokenStore::from_json_str(
        r#"{"tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["*"], "subscribe": ["*"]}}"#,
    )
    .expect("fixture tokens valid")
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli_tcp(
    addr: &str,
    agent: &str,
    token: &str,
    args: &[&str],
    stdin_data: Option<&str>,
) -> Run {
    let (host, port) = addr.rsplit_once(':').unwrap();
    let mut cmd = Command::new(cli_bin());
    cmd.args(args);
    cmd.env("AGENT_BUS_AGENT", agent);
    cmd.env("AGENT_BUS_TOKEN", token);
    cmd.env("AGENT_BUS_HOST", host);
    cmd.env("AGENT_BUS_PORT", port);
    cmd.env_remove("AGENT_BUS_SOCK");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn agent-bus");
    if let Some(data) = stdin_data {
        use std::io::Write;
        let _ = child.stdin.as_mut().unwrap().write_all(data.as_bytes());
    }
    let out = child.wait_with_output().expect("wait agent-bus");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[cfg(unix)]
fn run_cli_unix(
    sock: &Path,
    fallback_addr: &str,
    agent: &str,
    token: &str,
    args: &[&str],
    stdin_data: Option<&str>,
) -> Run {
    let mut cmd = Command::new(cli_bin());
    cmd.args(args);
    cmd.env("AGENT_BUS_AGENT", agent);
    cmd.env("AGENT_BUS_TOKEN", token);
    let (host, port) = fallback_addr.rsplit_once(':').unwrap();
    cmd.env("AGENT_BUS_HOST", host);
    cmd.env("AGENT_BUS_PORT", port);
    cmd.env("AGENT_BUS_SOCK", sock);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn agent-bus");
    if let Some(data) = stdin_data {
        use std::io::Write;
        let _ = child.stdin.as_mut().unwrap().write_all(data.as_bytes());
    }
    let out = child.wait_with_output().expect("wait agent-bus");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn fetch_all(client: &mut Client, topic: &str) -> Value {
    client
        .rpc(&json!({"op": "fetch", "topic": topic, "from_seq": 0}))
        .unwrap()
}

fn wait_for_request(
    client: &mut Client,
    helper_inbox: &str,
    expect_reply_to: &str,
    deadline: Instant,
) -> (String, Value) {
    loop {
        let f = fetch_all(client, helper_inbox);
        assert!(ok(&f), "fetch {helper_inbox}: {f}");
        for m in f["messages"].as_array().unwrap() {
            if m.get("reply_to").and_then(|v| v.as_str()) == Some(expect_reply_to) {
                let corr = m
                    .get("corr_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                assert!(!corr.is_empty(), "request carries corr_id: {m}");
                return (corr, m.clone());
            }
        }
        if Instant::now() > deadline {
            panic!("request to {helper_inbox} with reply_to {expect_reply_to} never appeared");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn request_reply_tcp_json_success_with_unrelated() {
    let dir = tmpdir("tcp-json");
    let wal = dir.join("wal.log");
    let server = Server::new(wal, fixture_store_two()).expect("fresh WAL starts clean");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let broker = server
        .serve_owned(listener, Duration::from_millis(10))
        .expect("tcp serve starts");
    let mut bob = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let mut alice_probe = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let unrelated_before = bob
        .rpc(&json!({"op": "post", "topic": "inbox.alice", "payload": {"unrelated": 1}}))
        .unwrap();
    assert!(ok(&unrelated_before), "{unrelated_before}");
    let (host, port) = addr.rsplit_once(':').unwrap();
    let req_child = Command::new(cli_bin())
        .args([
            "request",
            "bob",
            r#"{"q":"hi"}"#,
            "--timeout",
            "10",
            "--format",
            "json",
        ])
        .env("AGENT_BUS_AGENT", "alice")
        .env("AGENT_BUS_TOKEN", "tok-alice")
        .env("AGENT_BUS_HOST", host)
        .env("AGENT_BUS_PORT", port)
        .env_remove("AGENT_BUS_SOCK")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("request CLI spawns");
    let deadline = Instant::now() + Duration::from_secs(10);
    let (corr, req_msg) = wait_for_request(&mut bob, "inbox.bob", "inbox.alice", deadline);
    // Seeing the stored request establishes that its inbox subscription
    // exists, so this ordinary unrelated message is delivered during wait.
    let unrelated_during = bob
        .rpc(&json!({"op": "post", "topic": "inbox.alice", "payload": {"unrelated": 2}}))
        .unwrap();
    assert!(ok(&unrelated_during), "{unrelated_during}");
    assert_eq!(req_msg["payload"], json!({"q": "hi"}), "{req_msg}");
    assert_eq!(req_msg["sender"], json!("alice"), "{req_msg}");
    assert_eq!(req_msg["reply_to"], json!("inbox.alice"), "{req_msg}");
    let rep = run_cli_tcp(
        &addr,
        "bob",
        "tok-bob",
        &["reply", "inbox.alice", &corr, r#"{"a":"ok"}"#],
        None,
    );
    assert_eq!(rep.status, 0, "stdout={} stderr={}", rep.stdout, rep.stderr);
    let receipt: Value = serde_json::from_str(&rep.stdout).unwrap();
    assert!(ok(&receipt), "{receipt}");
    let out = req_child.wait_with_output().expect("request CLI exits");
    let status = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(status, 0, "stdout={stdout} stderr={stderr}");
    assert!(stderr.is_empty(), "stderr={stderr}");
    let reply_msg: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(reply_msg["corr_id"], json!(corr), "{reply_msg}");
    assert_eq!(reply_msg["payload"], json!({"a": "ok"}), "{reply_msg}");
    assert_eq!(reply_msg["sender"], json!("bob"), "{reply_msg}");
    let bob_box = fetch_all(&mut bob, "inbox.bob");
    assert!(ok(&bob_box), "{bob_box}");
    assert_eq!(
        bob_box["messages"].as_array().unwrap().len(),
        1,
        "{bob_box}"
    );
    let alice_box = fetch_all(&mut alice_probe, "inbox.alice");
    assert!(ok(&alice_box), "{alice_box}");
    let msgs = alice_box["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 3, "{alice_box}");
    assert_eq!(msgs[0]["payload"], json!({"unrelated": 1}));
    assert_eq!(msgs[1]["payload"], json!({"unrelated": 2}));
    assert_eq!(msgs[2]["payload"], json!({"a": "ok"}));
    assert_eq!(msgs[2]["corr_id"], json!(corr));
    drop(bob);
    drop(alice_probe);
    broker.shutdown();
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "shutdown closes TCP"
    );
}

#[cfg(unix)]
#[test]
fn request_reply_unix_payload_stdin_success() {
    let dir = tmpdir("unix-payload");
    let wal = dir.join("wal.log");
    let server = Server::new(wal, fixture_store_two()).expect("fresh WAL starts clean");
    let sock = sock_path(&dir, "bus");
    let broker = server
        .serve_owned_unix(&sock, Duration::from_millis(10))
        .expect("unix serve starts");
    let fallback_server = Server::new(dir.join("tcp-wal.log"), fixture_store_two()).unwrap();
    let fallback_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fallback_addr = fallback_listener.local_addr().unwrap().to_string();
    let fallback = fallback_server
        .serve_owned(fallback_listener, Duration::from_millis(10))
        .unwrap();
    let (fallback_host, fallback_port) = fallback_addr.rsplit_once(':').unwrap();
    let mut bob = Client::connect_unix(&sock, "bob", "tok-bob").unwrap();
    let mut alice_probe = Client::connect_unix(&sock, "alice", "tok-alice").unwrap();
    let unrelated_before = bob
        .rpc(&json!({"op": "post", "topic": "inbox.alice", "payload": {"unrelated": 1}}))
        .unwrap();
    assert!(ok(&unrelated_before), "{unrelated_before}");
    let mut req_child = Command::new(cli_bin())
        .args(["request", "bob", "-", "--timeout=8", "--format=payload"])
        .env("AGENT_BUS_AGENT", "alice")
        .env("AGENT_BUS_TOKEN", "tok-alice")
        .env("AGENT_BUS_HOST", fallback_host)
        .env("AGENT_BUS_PORT", fallback_port)
        .env("AGENT_BUS_SOCK", &sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("request CLI spawns");
    {
        use std::io::Write;
        req_child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(br#"{"q":"unix"}"#)
            .unwrap();
        drop(req_child.stdin.take());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let (corr, req_msg) = wait_for_request(&mut bob, "inbox.bob", "inbox.alice", deadline);
    let unrelated_during = bob
        .rpc(&json!({"op": "post", "topic": "inbox.alice", "payload": {"unrelated": 2}}))
        .unwrap();
    assert!(ok(&unrelated_during), "{unrelated_during}");
    assert_eq!(req_msg["payload"], json!({"q": "unix"}), "{req_msg}");
    let rep = run_cli_unix(
        &sock,
        &fallback_addr,
        "bob",
        "tok-bob",
        &["reply", "inbox.alice", &corr, "--", r#"{"a":"unix-ok"}"#],
        None,
    );
    assert_eq!(rep.status, 0, "stdout={} stderr={}", rep.stdout, rep.stderr);
    let out = req_child.wait_with_output().expect("request CLI exits");
    let status = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(status, 0, "stdout={stdout} stderr={stderr}");
    assert!(stderr.is_empty(), "stderr={stderr}");
    assert_eq!(stdout.trim(), r#"{"a":"unix-ok"}"#, "stdout={stdout}");
    let alice_box = fetch_all(&mut alice_probe, "inbox.alice");
    assert!(ok(&alice_box), "{alice_box}");
    assert_eq!(alice_box["messages"].as_array().unwrap().len(), 3);
    let mut tcp_probe = Client::connect(&fallback_addr, "alice", "tok-alice").unwrap();
    for topic in ["inbox.alice", "inbox.bob"] {
        let untouched = fetch_all(&mut tcp_probe, topic);
        assert!(ok(&untouched));
        assert!(untouched["messages"].as_array().unwrap().is_empty());
    }
    drop(tcp_probe);
    drop(bob);
    drop(alice_probe);
    broker.shutdown();
    fallback.shutdown();
    assert!(!sock.exists(), "shutdown removes socket");
}

#[test]
fn request_timeout_reports_stored_without_peer_proof() {
    let dir = tmpdir("tcp-timeout");
    let wal = dir.join("wal.log");
    let server = Server::new(wal, fixture_store_two()).expect("fresh WAL starts clean");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let broker = server
        .serve_owned(listener, Duration::from_millis(10))
        .expect("tcp serve starts");
    let r = run_cli_tcp(
        &addr,
        "alice",
        "tok-alice",
        &[
            "request",
            "bob",
            r#"{"q":"late"}"#,
            "--timeout",
            "1",
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
    assert!(r.stderr.contains("accepted"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("no reply"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("storage only"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("seq"), "stderr={}", r.stderr);
    assert!(
        !r.stderr.to_lowercase().contains("peer failed"),
        "stderr={}",
        r.stderr
    );
    assert!(!r.stderr.contains("is bob online"), "stderr={}", r.stderr);
    assert!(!r.stderr.contains("retry with"), "stderr={}", r.stderr);
    let mut bob = Client::connect(&addr, "bob", "tok-bob").unwrap();
    let bob_box = fetch_all(&mut bob, "inbox.bob");
    assert!(ok(&bob_box), "{bob_box}");
    assert_eq!(
        bob_box["messages"].as_array().unwrap().len(),
        1,
        "{bob_box}"
    );
    assert_eq!(bob_box["messages"][0]["payload"], json!({"q": "late"}));
    let mut alice = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let alice_box = fetch_all(&mut alice, "inbox.alice");
    assert!(ok(&alice_box), "{alice_box}");
    assert!(
        alice_box["messages"].as_array().unwrap().is_empty(),
        "{alice_box}"
    );
    drop(bob);
    drop(alice);
    broker.shutdown();
}

#[test]
fn reply_posts_corr_envelope_with_text_and_json() {
    let dir = tmpdir("tcp-reply");
    let wal = dir.join("wal.log");
    let server = Server::new(wal, fixture_store_two()).expect("fresh WAL starts clean");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let broker = server
        .serve_owned(listener, Duration::from_millis(10))
        .expect("tcp serve starts");
    let r1 = run_cli_tcp(
        &addr,
        "bob",
        "tok-bob",
        &["reply", "inbox.alice", "c1", r#"{"x":1}"#],
        None,
    );
    assert_eq!(r1.status, 0, "stdout={} stderr={}", r1.stdout, r1.stderr);
    let r2 = run_cli_tcp(
        &addr,
        "bob",
        "tok-bob",
        &["reply", "inbox.alice", "c2", "hello"],
        None,
    );
    assert_eq!(r2.status, 0, "stdout={} stderr={}", r2.stdout, r2.stderr);
    let r3 = run_cli_tcp(
        &addr,
        "bob",
        "tok-bob",
        &["reply", "inbox.alice", "c3", "-"],
        Some(r#"{"y":2}"#),
    );
    assert_eq!(r3.status, 0, "stdout={} stderr={}", r3.stdout, r3.stderr);
    let r4 = run_cli_tcp(
        &addr,
        "bob",
        "tok-bob",
        &["reply", "inbox.alice", "c4", "--", "--weird-payload"],
        None,
    );
    assert_eq!(r4.status, 0, "stdout={} stderr={}", r4.stdout, r4.stderr);
    let mut alice = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let box_all = fetch_all(&mut alice, "inbox.alice");
    assert!(ok(&box_all), "{box_all}");
    let msgs = box_all["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 4, "{box_all}");
    assert_eq!(msgs[0]["corr_id"], json!("c1"));
    assert_eq!(msgs[0]["payload"], json!({"x": 1}));
    assert_eq!(msgs[1]["corr_id"], json!("c2"));
    assert_eq!(msgs[1]["payload"], json!("hello"));
    assert_eq!(msgs[2]["corr_id"], json!("c3"));
    assert_eq!(msgs[2]["payload"], json!({"y": 2}));
    assert_eq!(msgs[3]["corr_id"], json!("c4"));
    assert_eq!(msgs[3]["payload"], json!("--weird-payload"));
    for m in msgs {
        assert_eq!(m["sender"], json!("bob"), "{m}");
    }
    drop(alice);
    broker.shutdown();
}

#[test]
fn request_reply_arg_validation_before_network() {
    let untouched = TcpListener::bind("127.0.0.1:0").unwrap();
    untouched.set_nonblocking(true).unwrap();
    let owned_addr = untouched.local_addr().unwrap().to_string();
    let cases: Vec<Vec<&str>> = vec![
        vec!["request"],
        vec!["request", "bob"],
        vec!["request", "bob", r#"{"a":1}"#, "--timeout", "bad"],
        vec!["request", "bob", r#"{"a":1}"#, "--timeout", "0"],
        vec!["request", "bob", r#"{"a":1}"#, "--format", "bad"],
        vec!["request", "b*b", r#"{"a":1}"#],
        vec!["request", "bob", r#"{"a":1}"#, "--unknown"],
        vec!["reply"],
        vec!["reply", "inbox.alice"],
        vec!["reply", "inbox.alice", "c1"],
        vec!["reply", "", "c1", r#"{"a":1}"#],
        vec!["reply", "inbox.alice", "", r#"{"a":1}"#],
        vec!["reply", "inbox.*", "c1", r#"{"a":1}"#],
    ];
    for args in cases {
        let r = run_cli_tcp(&owned_addr, "alice", "tok-alice", &args, None);
        assert_eq!(
            r.status, 2,
            "args={args:?} stdout={} stderr={}",
            r.stdout, r.stderr
        );
        assert!(r.stdout.is_empty(), "args={args:?} stdout={}", r.stdout);
        assert!(
            r.stderr.contains("error") || r.stderr.contains("usage") || r.stderr.contains("bad"),
            "args={args:?} stderr={}",
            r.stderr
        );
    }
    assert_eq!(
        untouched.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn request_equals_and_terminator_parsing_complete_owned_exchanges() {
    let dir = tmpdir("arguments");
    let server = Server::new(dir.join("wal.log"), fixture_store_two()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let broker = server
        .serve_owned(listener, Duration::from_millis(10))
        .unwrap();
    let mut bob = Client::connect(&addr, "bob", "tok-bob").unwrap();
    for (target, args, expected) in [
        (
            "worker1",
            vec![
                "request",
                "worker1",
                r#"{"a":1}"#,
                "--timeout=10",
                "--format=json",
            ],
            json!({"a":1}),
        ),
        (
            "worker2",
            vec!["request", "worker2", "--", "--foo"],
            json!("--foo"),
        ),
    ] {
        let cli_addr = addr.clone();
        let requester =
            std::thread::spawn(move || run_cli_tcp(&cli_addr, "alice", "tok-alice", &args, None));
        let (corr, msg) = wait_for_request(
            &mut bob,
            &format!("inbox.{target}"),
            "inbox.alice",
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(msg["payload"], expected);
        assert!(ok(&bob.rpc(&json!({"op":"post", "topic":"inbox.alice", "corr_id":corr, "payload":{"answer":target}})).unwrap()));
        let run = requester.join().unwrap();
        assert_eq!(run.status, 0, "{}", run.stderr);
        let reply: Value = serde_json::from_str(&run.stdout).unwrap();
        assert_eq!(reply["corr_id"], corr);
        assert_eq!(reply["payload"], json!({"answer":target}));
    }
    let r3 = run_cli_tcp(
        &addr,
        "bob",
        "tok-bob",
        &["reply", "inbox.alice", "c1", "--", "--bar"],
        None,
    );
    assert_eq!(r3.status, 0, "stdout={} stderr={}", r3.stdout, r3.stderr);
    let inbox = fetch_all(&mut bob, "inbox.alice");
    let messages = inbox["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[2]["payload"], "--bar");
    drop(bob);
    broker.shutdown();
}

#[test]
fn streaming_replay_survives_control_rpcs_and_selective_unsubscribe() {
    use agent_bus::wire::StreamingConn;

    let dir = tmpdir("stream-replay");
    let server = Server::new(dir.join("wal.log"), fixture_store_two()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let broker = server
        .serve_owned(listener, Duration::from_millis(10))
        .unwrap();
    let mut writer = Client::connect(&addr, "bob", "tok-bob").unwrap();
    assert!(ok(&writer
        .rpc(&json!({"op":"post", "topic":"board.sample", "payload":"café"}))
        .unwrap()));
    let mut reader = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (exact, first_count, _) = reader.subscribe("board.sample", 0, 0).unwrap();
    let (glob, second_count, _) = reader.subscribe("board.*", 0, 0).unwrap();
    assert_eq!((first_count, second_count), (1, 1));
    assert!(ok(&reader.rpc(&json!({"op":"ping"})).unwrap()));
    assert!(ok(&reader.unsubscribe(&exact).unwrap()));
    let replay = reader.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(replay["sub_id"], glob);
    assert_eq!(replay["msg"]["seq"], 1);
    assert_eq!(replay["msg"]["payload"], "café");
    assert!(ok(&writer
        .rpc(&json!({"op":"post", "topic":"board.sample", "payload":"次"}))
        .unwrap()));
    let live = reader.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(live["sub_id"], glob);
    assert_eq!(live["msg"]["seq"], 2);
    assert_eq!(live["msg"]["payload"], "次");
    assert!(ok(&reader.unsubscribe(&glob).unwrap()));
    assert!(ok(&reader.rpc(&json!({"op":"ping"})).unwrap()));
    drop(reader);
    drop(writer);
    broker.shutdown();
}
