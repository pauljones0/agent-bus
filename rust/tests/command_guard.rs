//! The fallback is this native test executable, never a real interpreter.
use std::process::Command;

#[test]
fn guard_refuses_without_echoing_arguments_or_consuming_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus-deny-python"))
        .args(["-c", "sensitive-command-argument"])
        .env("AGENT_BUS_TOKEN", "synthetic-secret-never-display")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("Rust-only task"));
    assert!(!error.contains("sensitive-command"));
    assert!(!error.contains("synthetic-secret"));
}

#[cfg(unix)]
#[test]
fn path_alias_refuses_before_native_fallback_is_started() {
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!(
        "agent-bus-command-guard-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let guarded = root.join("guarded");
    let fallback = root.join("fallback");
    std::fs::create_dir_all(&guarded).unwrap();
    std::fs::create_dir_all(&fallback).unwrap();
    for alias in ["python3", "pytest"] {
        symlink(
            env!("CARGO_BIN_EXE_agent-bus-deny-python"),
            guarded.join(alias),
        )
        .unwrap();
        // If PATH ordering breaks, this harmless native test runner is
        // selected. Its --list output and exit status distinguish it.
        symlink(std::env::current_exe().unwrap(), fallback.join(alias)).unwrap();
        let output = Command::new(alias)
            .arg("--list")
            .env("PATH", std::env::join_paths([&guarded, &fallback]).unwrap())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(126), "alias={alias}");
        assert!(output.stdout.is_empty(), "native fallback unexpectedly ran");
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("No interpreter was started"));
    }
    std::fs::remove_dir_all(root).unwrap();
}
