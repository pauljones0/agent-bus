//! Native Cargo disk-floor preflight guard core.
//!
//! Accidental-use protection for `cargo` invocations on capacity-constrained
//! agent rounds. This module contains the small testable helpers used by the
//! `agent-bus-cargo-guard` binary: constant floor, checked free-bytes
//! arithmetic, explicit path configuration validation, nearest-existing-dir
//! selection, resolved executable-identity comparison, and native `statvfs`
//! free-space reads.
//!
//! This is not OS confinement or a hard disk reservation. It is a conservative
//! preflight that refuses to `exec` the real Cargo when capacity is below the
//! floor, unreadable, unsupported, or ambiguous. It does not prevent a build
//! from crossing the floor once running, nor concurrent builds consuming space
//! after preflight. Scope is the target filesystem plus the current workspace
//! filesystem only; unknown custom Cargo subcommands may perform arbitrary
//! work elsewhere and are outside this capacity check.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// Minimum free bytes available to an ordinary user, required on both the
/// target filesystem and the current workspace filesystem before `exec`.
/// 6 GiB = 6 * 1024^3 = 6442450944. No environment lower-floor bypass.
pub const MIN_FREE_BYTES: u64 = 6442450944;

/// Environment variable naming the explicitly configured real Cargo binary.
/// Must be an absolute path to an existing executable file.
pub const REAL_CARGO_ENV: &str = "AGENT_BUS_REAL_CARGO";

/// Environment variable naming the explicit Cargo target directory.
/// Must be nonempty; no Cargo-config guessing is performed.
pub const TARGET_DIR_ENV: &str = "CARGO_TARGET_DIR";

/// Checked `f_bavail * f_frsize` free-bytes computation.
///
/// Returns `None` on overflow so callers refuse instead of treating unknown
/// capacity as enough.
pub fn available_bytes(bavail: u64, frsize: u64) -> Option<u64> {
    bavail.checked_mul(frsize)
}

/// True when `available` meets or exceeds `floor` (equality passes).
pub fn meets_floor(available: u64, floor: u64) -> bool {
    available >= floor
}

/// True when `available` meets [`MIN_FREE_BYTES`] (equality passes).
pub fn meets_min_floor(available: u64) -> bool {
    meets_floor(available, MIN_FREE_BYTES)
}

/// Validate a raw `CARGO_TARGET_DIR` value without filesystem guessing.
///
/// `None` or empty is refused. Any nonempty value is accepted here; relative
/// values are resolved against the current directory via
/// [`resolve_target_dir`], then existence is resolved via
/// [`nearest_existing_dir`] / [`pick_nearest_existing_strict`].
pub fn validate_target_dir_raw(value: Option<&OsStr>) -> Result<PathBuf, &'static str> {
    match value {
        None => Err("CARGO_TARGET_DIR is not set"),
        Some(v) if v.is_empty() => Err("CARGO_TARGET_DIR is empty"),
        Some(v) => Ok(PathBuf::from(v)),
    }
}

/// Validate a raw `AGENT_BUS_REAL_CARGO` value for presence and absoluteness.
///
/// Existence and executable-bit checks need the filesystem and are performed
/// by the binary after this pure shape check.
pub fn validate_real_cargo_raw(value: Option<&OsStr>) -> Result<PathBuf, &'static str> {
    match value {
        None => Err("AGENT_BUS_REAL_CARGO is not set"),
        Some(v) if v.is_empty() => Err("AGENT_BUS_REAL_CARGO is empty"),
        Some(v) => {
            let p = PathBuf::from(v);
            if !p.is_absolute() {
                return Err("AGENT_BUS_REAL_CARGO must be absolute");
            }
            Ok(p)
        }
    }
}

/// True when a Unix permission mode carries any execute bit.
pub fn has_exec_bit(mode: u32) -> bool {
    mode & 0o111 != 0
}

/// True when two `(dev, ino)` identities name the same file.
pub fn same_file_identity(a_dev: u64, a_ino: u64, b_dev: u64, b_ino: u64) -> bool {
    a_dev == b_dev && a_ino == b_ino
}

/// Resolved executable-identity comparison for self-recursion rejection.
///
/// True when canonical paths are equal (symlink-resolved textual identity) or
/// when device/inode identities match (hardlink identity). Callers must pass
/// canonicalized paths and `metadata` device/inode values; any resolution
/// failure is refused by the caller rather than treated as distinct.
pub fn is_same_executable(
    canonical_current: &Path,
    canonical_real: &Path,
    cur_dev: u64,
    cur_ino: u64,
    real_dev: u64,
    real_ino: u64,
) -> bool {
    canonical_current == canonical_real
        || same_file_identity(cur_dev, cur_ino, real_dev, real_ino)
}

/// Resolve a validated target dir against `cwd` before ancestor lookup.
///
/// Absolute targets are returned unchanged. Relative targets (including a
/// missing ordinary `target` directory) are joined onto `cwd` so ancestor
/// lookup walks real parents instead of reaching an empty path.
pub fn resolve_target_dir(target: &Path, cwd: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        cwd.join(target)
    }
}

/// True when cargo args carry a `--target-dir` override before the cargo `--`
/// separator. Both `--target-dir value` and `--target-dir=value` forms
/// refuse; anything at or after the first bare `--` is subcommand input and
/// is ignored here. Comparison is byte-exact on Unix so non-UTF8 args are
/// handled without lossy guessing.
pub fn has_target_dir_override(args: &[OsString]) -> bool {
    let mut after_sep = false;
    for arg in args {
        let s = arg.as_os_str();
        if !after_sep && s == OsStr::new("--") {
            after_sep = true;
            continue;
        }
        if after_sep {
            continue;
        }
        if s == OsStr::new("--target-dir") {
            return true;
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            if s.as_bytes().starts_with(b"--target-dir=") {
                return true;
            }
        }
        #[cfg(not(unix))]
        {
            if s.to_string_lossy().starts_with("--target-dir=") {
                return true;
            }
        }
    }
    false
}

/// Single-path probe outcome for strict nearest-directory lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirProbe {
    /// Exists and is a directory.
    IsDir,
    /// Exists but is not a directory.
    NotDir,
    /// Genuinely missing (`NotFound`); ancestor fallback is allowed.
    Missing,
    /// Permission or other I/O error; must refuse, never fall back.
    Unreadable,
}

/// Strict nearest-directory refusal, carrying the failing component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NearestDirError {
    /// No ancestor exists as a directory.
    NoAncestor,
    /// An existing component is not a directory.
    NotDirectory(PathBuf),
    /// A component could not be read (permission or other I/O error).
    Unreadable(PathBuf),
}

/// Pick the nearest existing directory along `path` and its ancestors.
///
/// `probe` is injected so tests can use a fake outcome without touching the
/// filesystem. Only [`DirProbe::Missing`] falls back to the parent; an
/// existing non-directory or an unreadable component refuses explicitly with
/// the failing path, and exhaustion refuses as [`NearestDirError::NoAncestor`].
pub fn pick_nearest_existing_strict<F>(
    path: &Path,
    mut probe: F,
) -> Result<PathBuf, NearestDirError>
where
    F: FnMut(&Path) -> DirProbe,
{
    let mut cur: Option<&Path> = Some(path);
    while let Some(p) = cur {
        match probe(p) {
            DirProbe::IsDir => return Ok(p.to_path_buf()),
            DirProbe::NotDir => return Err(NearestDirError::NotDirectory(p.to_path_buf())),
            DirProbe::Unreadable => return Err(NearestDirError::Unreadable(p.to_path_buf())),
            DirProbe::Missing => cur = p.parent(),
        }
    }
    Err(NearestDirError::NoAncestor)
}

/// Nearest existing directory for a (usually resolved) target path.
///
/// Returns the path itself when it exists as a directory, else the nearest
/// ancestor reached only through genuinely missing components. An existing
/// non-directory or a permission/other I/O error refuses explicitly instead
/// of silently checking a different filesystem.
pub fn nearest_existing_dir(path: &Path) -> Result<PathBuf, NearestDirError> {
    pick_nearest_existing_strict(path, |p| match std::fs::metadata(p) {
        Ok(m) if m.is_dir() => DirProbe::IsDir,
        Ok(_) => DirProbe::NotDir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DirProbe::Missing,
        Err(_) => DirProbe::Unreadable,
    })
}

/// Free bytes available to an ordinary user for `path` via native `statvfs`.
///
/// Computes `f_bavail * f_frsize` with checked arithmetic. Refuses with `Err`
/// on NUL-containing paths, `statvfs` failure, or arithmetic overflow.
/// Unsupported non-Unix platforms always refuse.
#[cfg(unix)]
pub fn free_bytes_for_path(path: &Path) -> Result<u64, &'static str> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    let c = CString::new(bytes).map_err(|_| "path contains NUL")?;
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path, `buf` is a valid writable
    // `statvfs` struct from the `libc` crate (no hand-rolled layout).
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err("statvfs failed");
    }
    let bavail = buf.f_bavail as u64;
    let frsize = buf.f_frsize as u64;
    available_bytes(bavail, frsize).ok_or("capacity overflow")
}

/// Non-Unix platforms have no reviewed `statvfs` path and always refuse.
#[cfg(not(unix))]
pub fn free_bytes_for_path(_path: &Path) -> Result<u64, &'static str> {
    Err("unsupported platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_constant_is_six_gib() {
        assert_eq!(MIN_FREE_BYTES, 6 * 1024 * 1024 * 1024);
        assert_eq!(MIN_FREE_BYTES, 6442450944);
    }
}
