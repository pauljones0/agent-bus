//! `agent-bus-cargo-guard`: native Cargo disk-floor preflight wrapper.
//!
//! Installed as a `cargo` symlink in the private PATH guard directory. Every
//! invocation requires an explicit nonempty `CARGO_TARGET_DIR` and an explicit
//! absolute `AGENT_BUS_REAL_CARGO`, refuses any `--target-dir` override
//! before the cargo `--` separator, checks free bytes available to an
//! ordinary user on both the target filesystem (relative targets resolved
//! against the current directory, then nearest existing directory through
//! genuinely missing components only) and the current workspace filesystem
//! via native `statvfs`, and `exec`s the real Cargo only when both readings
//! are at or above 6442450944 bytes (6 GiB).
//!
//! Arguments are preserved as `OsString`, and cwd, inherited
//! environment/PATH, and stdin/out/err are inherited. The real Cargo path is
//! never discovered via PATH, environment/tokens are never dumped,
//! interpreters are never invoked, and arbitrary full arguments are never
//! echoed. Self-recursion is rejected by resolved executable identity
//! (canonical paths plus device/inode), not only textual comparison.
//!
//! This is accidental-use protection, not OS confinement or a hard disk
//! reservation. It does not prevent a build from crossing the floor once
//! running, nor concurrent builds consuming space after preflight. Scope is
//! the target plus workspace filesystems only; unknown custom Cargo
//! subcommands may perform arbitrary work elsewhere and are outside this
//! check. The gate applies conservatively to every Cargo invocation,
//! including `--version`. See `docs/NATIVE_CARGO_GUARD.md`.

use agent_bus::cargo_guard;
use std::ffi::OsString;
use std::path::PathBuf;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    // Explicit real-Cargo configuration only; never PATH discovery.
    let real_cargo = match cargo_guard::validate_real_cargo_raw(std::env::var_os(
        cargo_guard::REAL_CARGO_ENV,
    )
    .as_deref())
    {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "agent-bus-cargo-guard: refusing cargo: AGENT_BUS_REAL_CARGO must name an absolute existing executable; check configuration"
            );
            return 1;
        }
    };
    if let Err(message) = check_real_cargo_executable(&real_cargo) {
        eprintln!("agent-bus-cargo-guard: refusing cargo: {message}");
        return 1;
    }
    match check_self_recursion(&real_cargo) {
        Ok(true) => {
            eprintln!(
                "agent-bus-cargo-guard: refusing cargo: real cargo resolves to self; refusing to recurse"
            );
            return 1;
        }
        Ok(false) => {}
        Err(message) => {
            eprintln!("agent-bus-cargo-guard: refusing cargo: {message}");
            return 1;
        }
    }

    // Preserve arguments as OsString for the later exec; also scan for a
    // `--target-dir` override before the cargo `--` separator. Cargo would
    // prefer that flag over CARGO_TARGET_DIR, so checking only the env value
    // would silently check the wrong filesystem.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if cargo_guard::has_target_dir_override(&args) {
        eprintln!(
            "agent-bus-cargo-guard: refusing cargo: --target-dir override is not accepted; set CARGO_TARGET_DIR explicitly and retry without the flag"
        );
        return 1;
    }

    // Explicit target directory only; never guess Cargo config.
    let target_dir = match cargo_guard::validate_target_dir_raw(std::env::var_os(
        cargo_guard::TARGET_DIR_ENV,
    )
    .as_deref())
    {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "agent-bus-cargo-guard: refusing cargo: CARGO_TARGET_DIR must be set to a nonempty explicit directory; refusing to guess Cargo config"
            );
            return 1;
        }
    };
    let workspace_dir = match std::env::current_dir() {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "agent-bus-cargo-guard: refusing cargo: unable to read current directory; need {} bytes free; refusing without a clear above-floor reading",
                cargo_guard::MIN_FREE_BYTES
            );
            return 1;
        }
    };
    // Resolve relative targets against the workspace before ancestor lookup
    // so a missing ordinary `target` directory checks the workspace
    // filesystem instead of falsely refusing on an empty parent.
    let effective_target = cargo_guard::resolve_target_dir(&target_dir, &workspace_dir);
    let target_existing = match cargo_guard::nearest_existing_dir(&effective_target) {
        Ok(p) => p,
        Err(cargo_guard::NearestDirError::NoAncestor) => {
            eprintln!(
                "agent-bus-cargo-guard: refusing cargo: no existing directory for target path; need {} bytes free; set CARGO_TARGET_DIR to an explicit usable directory",
                cargo_guard::MIN_FREE_BYTES
            );
            return 1;
        }
        Err(cargo_guard::NearestDirError::NotDirectory(p)) => {
            eprintln!(
                "agent-bus-cargo-guard: refusing cargo: target component '{}' exists but is not a directory; refusing without a clear above-floor reading",
                p.display()
            );
            return 1;
        }
        Err(cargo_guard::NearestDirError::Unreadable(p)) => {
            eprintln!(
                "agent-bus-cargo-guard: refusing cargo: unable to read target component '{}' (need {} bytes); refusing without a clear above-floor reading",
                p.display(),
                cargo_guard::MIN_FREE_BYTES
            );
            return 1;
        }
    };

    for dir in [&target_existing, &workspace_dir] {
        match cargo_guard::free_bytes_for_path(dir) {
            Ok(available) => {
                if !cargo_guard::meets_min_floor(available) {
                    eprintln!(
                        "agent-bus-cargo-guard: refusing cargo: filesystem '{}' has {} bytes available, need {} bytes; free space or use a filesystem above the floor",
                        dir.display(),
                        available,
                        cargo_guard::MIN_FREE_BYTES
                    );
                    return 1;
                }
            }
            Err(_) => {
                eprintln!(
                    "agent-bus-cargo-guard: refusing cargo: unable to determine free space for '{}' (need {} bytes); refusing without a clear above-floor reading",
                    dir.display(),
                    cargo_guard::MIN_FREE_BYTES
                );
                return 1;
            }
        }
    }

    // Reuse the preserved OsString args; inherit cwd, environment, and stdio.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(&real_cargo);
        cmd.args(&args);
        let err = cmd.exec();
        eprintln!("agent-bus-cargo-guard: failed to exec real cargo: {err}");
        return 1;
    }
    #[cfg(not(unix))]
    {
        let _ = (real_cargo, args);
        eprintln!(
            "agent-bus-cargo-guard: refusing cargo: unsupported platform; refusing without a clear above-floor reading"
        );
        return 1;
    }
}

/// Absolute existing executable-file check (follows symlinks; rustup dispatch
/// through a user's `.cargo/bin/cargo` is intentional and passes here).
#[cfg(unix)]
fn check_real_cargo_executable(path: &PathBuf) -> Result<(), &'static str> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path)
        .map_err(|_| "AGENT_BUS_REAL_CARGO must name an absolute existing executable; check configuration")?;
    if !meta.is_file() {
        return Err(
            "AGENT_BUS_REAL_CARGO must name an absolute existing executable; check configuration",
        );
    }
    if !cargo_guard::has_exec_bit(meta.permissions().mode()) {
        return Err(
            "AGENT_BUS_REAL_CARGO must name an absolute existing executable; check configuration",
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_real_cargo_executable(_path: &PathBuf) -> Result<(), &'static str> {
    Err("unsupported platform; refusing without a clear above-floor reading")
}

/// Self-recursion rejection via resolved identity: canonical paths plus
/// device/inode. Any resolution ambiguity refuses rather than execs.
#[cfg(unix)]
fn check_self_recursion(real_cargo: &PathBuf) -> Result<bool, &'static str> {
    use std::os::unix::fs::MetadataExt;

    let current = std::env::current_exe()
        .map_err(|_| "unable to resolve current executable; refusing to run without a clear identity check")?;
    let canonical_real = std::fs::canonicalize(real_cargo)
        .map_err(|_| "AGENT_BUS_REAL_CARGO must name an absolute existing executable; check configuration")?;
    // `current_exe` on Linux already resolves `/proc/self/exe`, but
    // canonicalize anyway so both sides are resolved the same way. If the
    // current side fails to canonicalize, refuse as ambiguous.
    let canonical_current = std::fs::canonicalize(&current)
        .map_err(|_| "unable to resolve current executable; refusing to run without a clear identity check")?;
    let cur_meta = std::fs::metadata(&canonical_current)
        .map_err(|_| "unable to resolve current executable; refusing to run without a clear identity check")?;
    let real_meta = std::fs::metadata(&canonical_real)
        .map_err(|_| "AGENT_BUS_REAL_CARGO must name an absolute existing executable; check configuration")?;
    Ok(cargo_guard::is_same_executable(
        &canonical_current,
        &canonical_real,
        cur_meta.dev() as u64,
        cur_meta.ino() as u64,
        real_meta.dev() as u64,
        real_meta.ino() as u64,
    ))
}

#[cfg(not(unix))]
fn check_self_recursion(_real_cargo: &PathBuf) -> Result<bool, &'static str> {
    Err("unsupported platform; refusing without a clear above-floor reading")
}
