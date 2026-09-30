//! Independent native transport ownership check; private loopback only.
#![cfg(target_os = "linux")]
use agent_bus::scheduler::status::{NativeStatusTransport, StatusTransport};
use serde_json::json;
use std::collections::BTreeSet;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn listen(fd: i32, backlog: i32) -> i32;
}

fn threads() -> BTreeSet<String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn failed_native_status_put_leaves_no_unowned_dial_thread() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // Linux accepts backlog+1 pending connections. Hold one slot; the
    // candidate's successful pre-probe consumes the other. Its subsequent
    // dial must then hit its own budget, while this listener stays open.
    assert_eq!(unsafe { listen(listener.as_raw_fd(), 1) }, 0);
    let addr = listener.local_addr().unwrap();
    let occupied = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    let baseline = threads();
    let mut transport = NativeStatusTransport::new(
        &addr.to_string(),
        "root-private-fixture",
        "synthetic-fixture-token",
    );
    let started = Instant::now();
    let result = transport.put(
        "ctx.sched.fixture.agent.run",
        json!({"phase":"active"}),
        1000,
        &AtomicBool::new(false),
    );
    let elapsed = started.elapsed();
    let returned_threads = threads();
    // Drop only resources owned by this fixture before asserting. The
    // production broker is never contacted.
    drop(transport);
    drop(occupied);
    drop(listener);
    assert!(
        result.is_err(),
        "a non-responding private listener cannot acknowledge a put"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "status timeout escaped its advertised bound: {elapsed:?}"
    );
    assert_eq!(
        returned_threads, baseline,
        "returning from a failed status put must not leave an unjoined connection worker"
    );
}
