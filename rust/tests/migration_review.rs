//! Independent migration acceptance checks; synthetic files only.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "native-migration-root-review-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn cli(&self, wal: &Path, out: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_agent-bus-broker"))
            .env_clear()
            .env("PATH", "")
            .args(["migrate", "--wal"])
            .arg(wal)
            .arg("--out")
            .arg(out)
            .args(["--now", "1000"])
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn migration_preserves_an_existing_temporary_file() {
    let scratch = Scratch::new();
    let wal = scratch.0.join("input.log");
    let out = scratch.0.join("output.log");
    std::fs::write(&wal, b"").unwrap();
    // Simulate a stale temporary file left by a previous invocation using
    // this PID. No symlinks, concurrent writes, or external files are needed.
    let stale = scratch
        .0
        .join(format!("output.log.migrate.{}.0.tmp", std::process::id()));
    let original = b"retained bytes from a prior operation\n";
    std::fs::write(&stale, original).unwrap();
    let _result = agent_bus::migration::migrate_legacy_to_wal(None, &wal, &out, 1000.0);
    // Either refusal or a fresh unique temp is valid; consuming the existing
    // file is not. This is this test binary's only in-process migration call.
    assert_eq!(
        std::fs::read(&stale).ok().as_deref(),
        Some(original.as_slice())
    );
    assert_eq!(std::fs::read(&wal).unwrap(), b"");
}

#[test]
fn malformed_post_diagnostic_does_not_echo_a_stored_value() {
    let scratch = Scratch::new();
    let wal = scratch.0.join("input.log");
    let out = scratch.0.join("output.log");
    let marker = "synthetic-private-value-must-not-appear";
    let record = serde_json::json!({"t":"post","topic":"fixture","msg":{
        "seq":1,"id":"fixture-id","sender":"fixture-owner","ts":marker,
        "exp":null,"payload":null
    }});
    std::fs::write(&wal, format!("{record}\n")).unwrap();
    let before = std::fs::read(&wal).unwrap();
    let output = scratch.cli(&wal, &out);
    assert!(!output.status.success());
    assert!(!out.exists());
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !diagnostic.contains(marker),
        "diagnostic echoed the synthetic stored value"
    );
    assert!(diagnostic.contains("line 1"), "{diagnostic}");
}

#[test]
fn expired_post_must_validate_before_being_discarded() {
    let scratch = Scratch::new();
    let wal = scratch.0.join("input.log");
    let out = scratch.0.join("output.log");
    // Expiry does not turn missing required message fields into a valid WAL.
    let input = b"{\"t\":\"post\",\"topic\":\"fixture\",\"msg\":{\"seq\":1,\"exp\":0}}\n";
    std::fs::write(&wal, input).unwrap();
    let output = scratch.cli(&wal, &out);
    assert!(
        !output.status.success(),
        "malformed expired post was accepted"
    );
    assert!(!out.exists());
    assert_eq!(std::fs::read(&wal).unwrap(), input);
}

#[cfg(unix)]
#[test]
fn private_wal_migration_does_not_broaden_read_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let wal = scratch.0.join("input.log");
    let out = scratch.0.join("output.log");
    std::fs::write(
        &wal,
        b"{\"t\":\"kv\",\"key\":\"fixture\",\"value\":\"private fixture\"}\n",
    )
    .unwrap();
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = scratch.cli(&wal, &out);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::metadata(out).unwrap().permissions().mode() & 0o077,
        0,
        "migration made private WAL contents readable by group or other users"
    );
}
