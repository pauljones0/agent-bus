//! Focused `cargo_guard` tests: pure arithmetic, floor decisions, path and
//! identity helpers, plus one tiny real `--version` smoke at adequate actual
//! capacity. Refusal control flow beyond these helpers is source-reviewed.
//! No disk filling, exhaustion, signals, races, broker suites, or Python.

use agent_bus::cargo_guard;
use agent_bus::cargo_guard::{DirProbe, NearestDirError};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

#[test]
fn floor_is_six_gib() {
    assert_eq!(cargo_guard::MIN_FREE_BYTES, 6 * 1024 * 1024 * 1024);
    assert_eq!(cargo_guard::MIN_FREE_BYTES, 6442450944);
}

#[test]
fn available_bytes_multiplies_and_refuses_overflow() {
    assert_eq!(cargo_guard::available_bytes(10, 4096), Some(40960));
    assert_eq!(cargo_guard::available_bytes(0, 4096), Some(0));
    assert_eq!(cargo_guard::available_bytes(123, 0), Some(0));
    assert_eq!(cargo_guard::available_bytes(u64::MAX, 2), None);
    assert_eq!(
        cargo_guard::available_bytes(u64::MAX, u64::MAX),
        None
    );
}

#[test]
fn floor_decisions_include_equality() {
    assert!(cargo_guard::meets_floor(6442450944, 6442450944));
    assert!(cargo_guard::meets_floor(6442450945, 6442450944));
    assert!(!cargo_guard::meets_floor(6442450943, 6442450944));
    assert!(cargo_guard::meets_min_floor(6442450944));
    assert!(cargo_guard::meets_min_floor(u64::MAX));
    assert!(!cargo_guard::meets_min_floor(0));
}

#[test]
fn target_dir_requires_nonempty_explicit_value() {
    assert!(cargo_guard::validate_target_dir_raw(None).is_err());
    assert!(cargo_guard::validate_target_dir_raw(Some(OsStr::new(""))).is_err());
    let ok = cargo_guard::validate_target_dir_raw(Some(OsStr::new("/tmp/target")))
        .unwrap();
    assert_eq!(ok, PathBuf::from("/tmp/target"));
}

#[test]
fn real_cargo_requires_absolute_shape() {
    assert!(cargo_guard::validate_real_cargo_raw(None).is_err());
    assert!(cargo_guard::validate_real_cargo_raw(Some(OsStr::new(""))).is_err());
    assert!(cargo_guard::validate_real_cargo_raw(Some(OsStr::new("cargo"))).is_err());
    assert!(
        cargo_guard::validate_real_cargo_raw(Some(OsStr::new("bin/cargo")))
            .is_err()
    );
    let ok =
        cargo_guard::validate_real_cargo_raw(Some(OsStr::new("/home/developer/.cargo/bin/cargo")))
            .unwrap();
    assert_eq!(ok, PathBuf::from("/home/developer/.cargo/bin/cargo"));
}

#[test]
fn exec_bit_checks_any_execute() {
    assert!(cargo_guard::has_exec_bit(0o755));
    assert!(cargo_guard::has_exec_bit(0o100));
    assert!(cargo_guard::has_exec_bit(0o111));
    assert!(!cargo_guard::has_exec_bit(0o644));
    assert!(!cargo_guard::has_exec_bit(0));
}

#[test]
fn file_identity_compares_dev_and_ino() {
    assert!(cargo_guard::same_file_identity(8, 123, 8, 123));
    assert!(!cargo_guard::same_file_identity(8, 123, 8, 124));
    assert!(!cargo_guard::same_file_identity(8, 123, 9, 123));
}

#[test]
fn same_executable_uses_canonical_or_identity() {
    let a = Path::new("/opt/guard/agent-bus-cargo-guard");
    let b = Path::new("/opt/guard/agent-bus-cargo-guard");
    let c = Path::new("/home/developer/.cargo/bin/rustup");
    // Same canonical path matches even with distinct identities.
    assert!(cargo_guard::is_same_executable(a, b, 1, 1, 2, 2));
    // Distinct canonical paths with matching identity (hardlink) match.
    assert!(cargo_guard::is_same_executable(a, c, 8, 99, 8, 99));
    // Distinct paths and identities do not match.
    assert!(!cargo_guard::is_same_executable(a, c, 8, 99, 8, 100));
}

#[test]
fn resolve_target_dir_joins_relative_against_cwd() {
    let cwd = Path::new("/home/developer/work");
    assert_eq!(
        cargo_guard::resolve_target_dir(Path::new("/tmp/target"), cwd),
        PathBuf::from("/tmp/target")
    );
    assert_eq!(
        cargo_guard::resolve_target_dir(Path::new("target"), cwd),
        PathBuf::from("/home/developer/work/target")
    );
    assert_eq!(
        cargo_guard::resolve_target_dir(Path::new("new/nested"), cwd),
        PathBuf::from("/home/developer/work/new/nested")
    );
}

#[test]
fn strict_picker_falls_back_only_through_missing() {
    let target = Path::new("/a/b/c");
    // Ordinary existing self.
    let got =
        cargo_guard::pick_nearest_existing_strict(target, |_| DirProbe::IsDir)
            .unwrap();
    assert_eq!(got, PathBuf::from("/a/b/c"));
    // New nested path: missing leaves fall back to an existing ancestor.
    let got = cargo_guard::pick_nearest_existing_strict(target, |p| {
        if p == Path::new("/a") {
            DirProbe::IsDir
        } else {
            DirProbe::Missing
        }
    })
    .unwrap();
    assert_eq!(got, PathBuf::from("/a"));
    // Existing non-directory refuses explicitly with the failing path.
    let err = cargo_guard::pick_nearest_existing_strict(target, |p| {
        if p == target {
            DirProbe::NotDir
        } else {
            DirProbe::IsDir
        }
    })
    .unwrap_err();
    assert_eq!(
        err,
        NearestDirError::NotDirectory(PathBuf::from("/a/b/c"))
    );
    // Unreadable ancestor refuses instead of falling back further.
    let err = cargo_guard::pick_nearest_existing_strict(target, |p| {
        if p == Path::new("/a/b") {
            DirProbe::Unreadable
        } else if p == Path::new("/a") {
            DirProbe::IsDir
        } else {
            DirProbe::Missing
        }
    })
    .unwrap_err();
    assert_eq!(err, NearestDirError::Unreadable(PathBuf::from("/a/b")));
    // Nothing exists.
    let err =
        cargo_guard::pick_nearest_existing_strict(target, |_| DirProbe::Missing)
            .unwrap_err();
    assert_eq!(err, NearestDirError::NoAncestor);
}

#[test]
fn target_dir_override_scan_respects_separator() {
    let args = |v: &[&str]| {
        v.iter()
            .map(|s| OsString::from(*s))
            .collect::<Vec<OsString>>()
    };
    assert!(!cargo_guard::has_target_dir_override(&[]));
    assert!(!cargo_guard::has_target_dir_override(&args(&["build"])));
    assert!(!cargo_guard::has_target_dir_override(&args(&[
        "build",
        "--target-dirfoo"
    ])));
    assert!(cargo_guard::has_target_dir_override(&args(&[
        "build",
        "--target-dir",
        "/tmp/x"
    ])));
    assert!(cargo_guard::has_target_dir_override(&args(&[
        "build",
        "--target-dir=/tmp/x"
    ])));
    assert!(!cargo_guard::has_target_dir_override(&args(&[
        "--",
        "--target-dir"
    ])));
    assert!(!cargo_guard::has_target_dir_override(&args(&[
        "build",
        "--",
        "--target-dir=/tmp/x"
    ])));
}

/// Tiny real wrapper smoke: `guard --version` execs the real Cargo and exits
/// 0 when both checked filesystems are above the floor. Requires adequate
/// actual capacity; below the floor the guard correctly refuses.
#[test]
fn wrapper_version_smoke_at_adequate_capacity() {
    let guard = env!("CARGO_BIN_EXE_agent-bus-cargo-guard");
    let real_cargo = std::env::var_os("AGENT_BUS_REAL_CARGO")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO")));
    assert!(real_cargo.is_absolute(), "real cargo must be absolute");
    // Reuse the ambient target dir when the release harness sets it, else a
    // harmless temp dir (`--version` writes nothing there; both sides only
    // need an above-floor statvfs reading).
    let target: PathBuf = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let output = std::process::Command::new(guard)
        .arg("--version")
        .env("AGENT_BUS_REAL_CARGO", &real_cargo)
        .env("CARGO_TARGET_DIR", &target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "guard --version refused; check capacity and config (target={} real={}) stderr={}",
        target.display(),
        real_cargo.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cargo"), "unexpected --version output");
}
