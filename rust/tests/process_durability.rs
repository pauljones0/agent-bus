//! Real-process durability: broker child kill/restart over an isolated WAL.
//!
//! Unlike `integration.rs` (in-process restart simulation on shared threads),
//! these tests spawn the actual `agent-bus-broker` binary as a child process,
//! SIGKILL it, and restart on the same WAL file. Each test pins its own temp
//! dir (WAL + private fixture `tokens.json`) and an ephemeral loopback port.
//! No Python, no production IO, no live broker.
//!
//! Covered: durable-ACK messages and leases survive SIGKILL with sequence
//! continuity; a startup torn-tail repair followed by a new ACK survives a
//! second kill/restart; a fully malformed WAL fails closed at startup; a
//! second broker process on the same WAL is rejected while the first holds
//! the kernel lease; a SIGKILLed owner's lease file is never unlinked and
//! its inode is stable across the replacement owner.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_bus::wire::Client;
use serde_json::json;

fn broker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus-broker"))
}

fn tmpdir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "agent-bus-proc-{name}-{}-{}",
        std::process::id(),
        name.len()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
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
        .env_remove("AGENT_BUS_SOCK")
        .arg("serve")
        .arg("--wal")
        .arg(wal)
        .arg("--tokens")
        .arg(&tokens)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
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

fn kill(child: &mut Child) {
    child.kill().expect("SIGKILL child");
    let status = child.wait().expect("reap child");
    assert!(!status.success(), "killed broker exits non-zero, got {status}");
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

fn ok(v: &serde_json::Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

/// Spawn on a fresh port until the broker answers; returns child + client.
fn spawn_ready(dir: &Path, wal: &Path) -> (Child, Client, String) {
    for attempt in 0..3 {
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let mut child = spawn_broker(dir, wal, port);
        // If the child dies immediately (bad WAL, lock held), surface it.
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

#[test]
fn durable_ack_survives_sigkill_and_sequence_continues() {
    let dir = tmpdir("ack-kill");
    let wal = dir.join("wal.log");
    let (mut child, mut c, _addr) = spawn_ready(&dir, &wal);
    let p1 = c.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}})).unwrap();
    assert_eq!(p1["seq"], json!(1), "{p1}");
    let p2 = c.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 2}})).unwrap();
    assert_eq!(p2["seq"], json!(2), "{p2}");
    let grant = c
        .rpc(&json!({"op": "claim_acquire", "resource": "repo/a.rs", "ttl_ms": 600_000}))
        .unwrap();
    assert!(ok(&grant), "{grant}");
    let token = grant["token"].as_str().unwrap().to_string();
    drop(c);
    kill(&mut child);

    // Restart on the same WAL: ACKed posts, the live lease, and the next
    // sequence number must all survive the kill.
    let (mut child2, mut c2, _addr2) = spawn_ready(&dir, &wal);
    let f = c2.rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0})).unwrap();
    assert!(ok(&f), "{f}");
    assert_eq!(f["messages"].as_array().unwrap().len(), 2);
    assert_eq!(f["cursor"]["topic_seq"], json!(2));
    let st = c2.rpc(&json!({"op": "claim_status", "resource": "repo/a.rs"})).unwrap();
    assert!(ok(&st), "{st}");
    assert_eq!(st["token"], json!(token));
    assert_eq!(st["owner"], json!("tester"));
    let p3 = c2.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 3}})).unwrap();
    assert_eq!(p3["seq"], json!(3), "{p3}");
    drop(c2);
    kill(&mut child2);
}

#[test]
fn torn_tail_repair_survives_second_kill() {
    let dir = tmpdir("torn-kill");
    let wal = dir.join("wal.log");
    let (mut child, mut c, _addr) = spawn_ready(&dir, &wal);
    let p1 = c.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}})).unwrap();
    assert_eq!(p1["seq"], json!(1), "{p1}");
    drop(c);
    kill(&mut child);

    // Crash mid-append: partial final line, never ACKed.
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
        f.write_all(b"{\"t\":\"post\",\"topic\":\"t\",\"msg\":{\"seq\":99").unwrap();
        f.sync_all().unwrap();
    }
    // First restart repairs the torn tail at startup; the next ACKed post
    // continues the true sequence (2, not 99).
    let (mut child2, mut c2, _addr2) = spawn_ready(&dir, &wal);
    let p2 = c2.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 2}})).unwrap();
    assert_eq!(p2["seq"], json!(2), "{p2}");
    drop(c2);
    kill(&mut child2);

    // Second restart: the repaired history plus the new ACK survive again.
    let (mut child3, mut c3, _addr3) = spawn_ready(&dir, &wal);
    let f = c3.rpc(&json!({"op": "fetch", "topic": "t", "from_seq": 0})).unwrap();
    assert!(ok(&f), "{f}");
    let msgs = f["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[1]["seq"], json!(2));
    let p3 = c3.rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 3}})).unwrap();
    assert_eq!(p3["seq"], json!(3), "{p3}");
    drop(c3);
    kill(&mut child3);
}

#[test]
fn malformed_wal_fails_closed_at_startup() {
    let dir = tmpdir("malformed");
    let wal = dir.join("wal.log");
    std::fs::write(&wal, "{not json}\n").unwrap();
    let port = free_port();
    let mut child = spawn_broker(&dir, &wal, port);
    match exited(&mut child, Duration::from_secs(10)) {
        Some(status) => assert!(!status.success(), "malformed WAL must refuse startup"),
        None => {
            child.kill().ok();
            panic!("broker on malformed WAL stayed up; must fail closed");
        }
    }
}

#[test]
fn second_owner_rejected_while_first_holds_wal() {
    let dir = tmpdir("two-owners");
    let wal = dir.join("wal.log");
    let (mut first, mut c, _addr) = spawn_ready(&dir, &wal);
    let p = c.rpc(&json!({"op": "post", "topic": "t", "payload": 1})).unwrap();
    assert!(ok(&p), "{p}");

    // A second broker process on the same WAL must refuse startup while the
    // first holds the kernel lease on <wal>.lock.
    let port2 = free_port();
    let mut second = spawn_broker(&dir, &wal, port2);
    match exited(&mut second, Duration::from_secs(10)) {
        Some(status) => assert!(
            !status.success(),
            "second owner must be rejected, got {status}"
        ),
        None => {
            second.kill().ok();
            first.kill().ok();
            panic!("second broker stayed up on a held WAL; must be rejected");
        }
    }
    // The first owner is undisturbed and still serving ACKs.
    let p2 = c.rpc(&json!({"op": "post", "topic": "t", "payload": 2})).unwrap();
    assert_eq!(p2["seq"], json!(2), "{p2}");
    drop(c);
    kill(&mut first);
}

#[test]
fn killed_owner_releases_lease_without_unlink() {
    // SIGKILL runs no userspace drop: the kernel must release the lease
    // while the lease file itself survives with a stable inode, so a dead
    // owner can never remove its replacement's lock.
    use std::os::unix::fs::MetadataExt;
    let dir = tmpdir("kill-lease");
    let wal = dir.join("wal.log");
    let (mut child, mut c, _addr) = spawn_ready(&dir, &wal);
    let p1 = c.rpc(&json!({"op": "post", "topic": "t", "payload": 1})).unwrap();
    assert!(ok(&p1), "{p1}");
    // Lease artifact path mirrors wal.rs lock_path_for (<wal>.lock).
    let mut lock = wal.as_os_str().to_owned();
    lock.push(".lock");
    let lock = PathBuf::from(lock);
    assert!(lock.exists(), "lease file present while owner lives");
    let ino_before = std::fs::metadata(&lock).unwrap().ino();
    drop(c);
    kill(&mut child);

    assert!(lock.exists(), "SIGKILLed owner leaves lease file behind");
    assert_eq!(std::fs::metadata(&lock).unwrap().ino(), ino_before);
    // The replacement owner acquires the kernel-released lease on the same
    // inode and serves ACKs; the old owner removed nothing.
    let (mut child2, mut c2, _addr2) = spawn_ready(&dir, &wal);
    assert_eq!(
        std::fs::metadata(&lock).unwrap().ino(),
        ino_before,
        "stable lock inode across owners"
    );
    let p2 = c2.rpc(&json!({"op": "post", "topic": "t", "payload": 2})).unwrap();
    assert_eq!(p2["seq"], json!(2), "{p2}");
    drop(c2);
    kill(&mut child2);
}
