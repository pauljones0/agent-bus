//! Native lifecycle checks: no listener, client traffic or production state.
use agent_bus::acl::TokenStore;
use agent_bus::wire::Server;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(label: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "agent-bus-maintenance-review-{}-{stamp}-{label}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn server(&self) -> Server {
        let tokens = TokenStore::from_json_str("{}").unwrap();
        Server::new(self.0.join("wal.log"), tokens).unwrap()
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

// Two seconds is a small ordinary interval, not a load or timeout stress case.
// The one-second smoke deadline distinguishes waking from waiting for it;
// this is not a universal shutdown-latency guarantee under arbitrary load.
const INTERVAL: Duration = Duration::from_secs(2);
const STOP_DEADLINE: Duration = Duration::from_secs(1);

#[test]
fn explicit_shutdown_wakes_the_interval_wait() {
    let dir = OwnedDirectory::new("shutdown");
    let server = dir.server();
    let worker = server.spawn_maintenance_worker(INTERVAL);
    assert!(!worker.is_stopping());
    let started = Instant::now();
    worker.shutdown();
    assert!(
        started.elapsed() < STOP_DEADLINE,
        "shutdown waited for the cleanup interval: {:?}",
        started.elapsed()
    );
    assert!(server.maintenance_tick().is_empty());
}

#[test]
fn dropping_the_guard_wakes_the_interval_wait() {
    let dir = OwnedDirectory::new("drop");
    let server = dir.server();
    let worker = server.spawn_maintenance_worker(INTERVAL);
    let started = Instant::now();
    drop(worker);
    assert!(
        started.elapsed() < STOP_DEADLINE,
        "guard drop waited for the cleanup interval: {:?}",
        started.elapsed()
    );
    assert!(server.maintenance_tick().is_empty());
}

#[test]
fn zero_interval_still_stops_and_joins() {
    let dir = OwnedDirectory::new("zero");
    let server = dir.server();
    let worker = server.spawn_maintenance_worker(Duration::ZERO);
    let started = Instant::now();
    worker.shutdown();
    assert!(started.elapsed() < STOP_DEADLINE);
    assert!(server.maintenance_tick().is_empty());
}
