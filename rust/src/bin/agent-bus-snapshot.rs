//! agent-bus-snapshot: local delivery-snapshot builder/verifier.
//!
//! Builds a NEW owned snapshot directory from an explicit source root plus a
//! machine-readable relative-path list, with one deterministic versioned JSON
//! manifest (path, byte length, SHA-256, Unix 0o777 mode). Verifies the staged
//! copy against its manifest, then atomically publishes via no-replace rename
//! on Linux (create requires Linux; other platforms fail early explicitly
//! rather than risk overwrite).
//!
//! Local only: no broker mutation, no network upload, no 32 MB art-put path.
//! No shell delegation, no credential capture, no symlink following.
//!
//! Caller must freeze the source tree and staging/dest parents first. Matching
//! hashes prove the staged bytes equal the manifest, not an atomic cross-file
//! capture or any source-to-test provenance. No directory fsync or crash
//! durability is claimed. See `--help` limits and `README.md`.

use agent_bus::artifacts::{is_valid_sha, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MANIFEST_VERSION: u32 = 1;
const DEFAULT_MANIFEST: &str = "snapshot-manifest.json";
const MAX_LIST_BYTES: u64 = 1_048_576;
const MAX_MANIFEST_BYTES: u64 = 8_388_608;
const MAX_FILES: usize = 20_000;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_FILE_BYTES: u64 = 1_073_741_824;
const MAX_TOTAL_BYTES: u64 = 8_589_934_592;
const IO_BUF: usize = 65_536;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ManifestEntry {
    path: String,
    len: u64,
    sha256: String,
    mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Manifest {
    version: u32,
    files: Vec<ManifestEntry>,
    file_count: usize,
    total_bytes: u64,
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cmd = if argv.len() < 2 {
        String::new()
    } else {
        match argv[1].to_str() {
            Some(s) => s.to_string(),
            None => {
                eprintln!("error: subcommand is not valid UTF-8\n{}", usage());
                return 2;
            }
        }
    };
    match cmd.as_str() {
        "" | "--help" | "-h" | "help" => {
            print!("{}", usage());
            0
        }
        "create" => cmd_create(&argv),
        "verify" => cmd_verify(&argv),
        other => {
            eprintln!("error: unknown subcommand '{other}'\n{}", usage());
            2
        }
    }
}

fn usage() -> String {
    format!(
        "agent-bus-snapshot: local delivery-snapshot builder/verifier (no broker I/O)\n\
         \n\
         usage:\n\
         \x20 agent-bus-snapshot create --source-root DIR --file-list LIST --dest NEWDIR [--manifest NAME]\n\
         \x20 agent-bus-snapshot verify --snapshot-root DIR [--manifest NAME]\n\
         \n\
         options: one-pass parsing, each known option consumed once. Both\n\
         --opt VALUE and --opt=VALUE forms; '--' terminates options (no\n\
         positionals; anything after '--' fails). Duplicate, missing, unknown,\n\
         or non-UTF-8 options fail with exit 2. Values are UTF-8, never\n\
         lossily renamed.\n\
         \n\
         file-list: UTF-8 text, one relative POSIX path per LF line. A trailing\n\
         \\r is stripped only when it is part of CRLF (followed by LF); any\n\
         other \\r, LF inside a name, or NUL fails. No trimming, no comments,\n\
         no empty lines (except the single trailing newline). Duplicate paths\n\
         fail. Each path: non-empty, relative, no leading '/', no empty\n\
         components ('//'), no '.' or '..' components, no trailing '/', UTF-8,\n\
         <=4096 bytes, no NUL/CR/LF. Backslash is an ordinary filename char.\n\
         Non-UTF-8 list bytes are refused, never renamed.\n\
         \n\
         bounds (finite, plain; cover R36 2.38 GiB/173 MiB + standby/sources):\n\
         list <=1 MiB, files <=20000, path <=4096 B, per-file <=1 GiB,\n\
         total <=8 GiB, manifest <=8 MiB, streaming 64 KiB.\n\
         Payload bytes are streamed; no whole-file materialization.\n\
         manifest: deterministic versioned JSON v1, files sorted by path bytes:\n\
         {{\"version\":1,\"files\":[{{\"path\":...,\"len\":...,\"sha256\":...,\"mode\":...}}],\"file_count\":N,\"total_bytes\":T}}\n\
         pretty-printed with trailing newline, no timestamps or absolute paths.\n\
         mode is decimal 0..511 (Unix 0o777 permission bits only). v1 requires\n\
         mode; manifests without mode are rejected. No ownership/ACL/xattr or\n\
         durability encoded.\n\
         \n\
         create (Linux only; other platforms fail early, never overwrite): dest\n\
         must be absent (file, dir, or symlink all refuse). Staging is an owned\n\
         sibling '<dest>.staging.<pid>' created fresh; any pre-existing staging\n\
         name refuses. Each listed path must be a regular file; symlinks (final\n\
         or any parent prefix under the source root) refuse. Source root,\n\
         file-list, and dest parent must exist; roots/parents that are symlinks\n\
         refuse. Parents above these explicit roots are trusted and not audited;\n\
         they must not be concurrently mutated. Bytes are streamed source->\n\
         staging with SHA-256 over the copied bytes, Unix 0o777 mode bits\n\
         preserved and recorded, size re-checked (pre/copy/dest must agree),\n\
         manifest written to staging, staging re-verified (len/sha256/mode),\n\
         then atomically published to dest with Linux renameat2 RENAME_NOREPLACE\n\
         only on success. Owned staging is removed on failure; pre-existing or\n\
         intervening dest is never overwritten or removed. Crash may leave owned\n\
         staging behind; no automatic crash cleanup. No directory fsync; rename\n\
         durability after crash is not claimed.\n\
         \n\
         verify: re-streams each listed snapshot file, compares len/sha256/mode\n\
         (mode 0o777 bits verified on Unix; range-checked everywhere), checks\n\
         version/counts/totals/sortedness. Extra unlisted files are ignored (not\n\
         an error). Symlinks refuse. Matching hashes prove manifest agreement\n\
         for the copied bytes, not an atomic source capture. Exit 0 verified, 1\n\
         mismatch/IO, 2 usage.\n\
         \n\
         limits: caller must freeze the source tree and staging/dest parents\n\
         first. No atomic cross-file guarantee; concurrent modification surfaces\n\
         only as observed size/hash/mode mismatches where re-checked. No\n\
         source-to-test provenance is claimed. Publication is atomic no-replace\n\
         on Linux (intervening dest fails, never overwritten); source-open and\n\
         prefix checks retain a TOCTOU window under concurrent mutation (freeze\n\
         required). Snapshot/staging parents are trusted, non-concurrently-\n\
         mutated; concurrent parent mutation is out of scope. No shell, no\n\
         credentials.\n\
         \n\
         exits: 0 success, 1 content/IO (incl. dest-exists, mismatch), 2 usage/bounds.\n"
    )
}

fn parse_options(
    argv: &[std::ffi::OsString],
    known: &[&str],
    required: &[&str],
) -> Result<std::collections::HashMap<String, String>, String> {
    use std::collections::{HashMap, HashSet};
    let known_set: HashSet<&str> = known.iter().copied().collect();
    let mut values: HashMap<String, String> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut i = 2;
    while i < argv.len() {
        let raw = &argv[i];
        let s = match raw.to_str() {
            Some(v) => v,
            None => return Err("argument is not valid UTF-8".to_string()),
        };
        if s == "--" {
            if i + 1 < argv.len() {
                match argv[i + 1].to_str() {
                    Some(rest) => {
                        return Err(format!("unexpected argument '{rest}' after '--'"));
                    }
                    None => {
                        return Err("unexpected non-UTF-8 argument after '--'".to_string());
                    }
                }
            }
            break;
        }
        if s.starts_with("--") {
            let (key, inline) = match s.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (s, None),
            };
            if !known_set.contains(key) {
                return Err(format!("unknown option '{s}'"));
            }
            if !seen.insert(key.to_string()) {
                return Err(format!("duplicate {key}"));
            }
            if let Some(v) = inline {
                values.insert(key.to_string(), v.to_string());
                i += 1;
            } else {
                if i + 1 >= argv.len() {
                    return Err(format!("missing value for {key}"));
                }
                match argv[i + 1].to_str() {
                    Some(v) => {
                        values.insert(key.to_string(), v.to_string());
                    }
                    None => {
                        return Err(format!("value for {key} is not valid UTF-8"));
                    }
                }
                i += 2;
            }
            continue;
        }
        if s.starts_with('-') && s.len() > 1 {
            return Err(format!("unknown option '{s}'"));
        }
        return Err(format!("unexpected argument '{s}'"));
    }
    for r in required {
        if !values.contains_key(*r) {
            return Err(format!("missing {r}"));
        }
    }
    Ok(values)
}

fn validate_rel_path(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("empty path".to_string());
    }
    if s.len() > MAX_PATH_BYTES {
        return Err(format!("path too long (>{MAX_PATH_BYTES}): {s}"));
    }
    if s.contains('\0') || s.contains('\r') || s.contains('\n') {
        return Err(format!("path contains NUL/CR/LF: {s}"));
    }
    if s.starts_with('/') {
        return Err(format!("absolute path refused: {s}"));
    }
    if s.ends_with('/') {
        return Err(format!("trailing slash refused: {s}"));
    }
    for comp in s.split('/') {
        if comp.is_empty() {
            return Err(format!("empty component ('//') refused: {s}"));
        }
        if comp == "." || comp == ".." {
            return Err(format!("'.'/'..' refused: {s}"));
        }
    }
    Ok(())
}

fn validate_manifest_name(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("empty manifest name".to_string());
    }
    if s.len() > 255 {
        return Err("manifest name too long (>255)".to_string());
    }
    if s.contains('\0') || s.contains('\r') || s.contains('\n') || s.contains('/') {
        return Err(format!("bad manifest name: {s}"));
    }
    if s == "." || s == ".." {
        return Err(format!("bad manifest name: {s}"));
    }
    Ok(())
}

fn hex32(sum: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in sum {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

fn ensure_dir_not_symlink(path: &Path, label: &str) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{label} unreadable '{}': {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{label} symlink refused: '{}'",
            path.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!("{label} not a directory: '{}'", path.display()));
    }
    Ok(())
}

fn ensure_prefixes_safe(root: &Path, rel: &str) -> Result<(), String> {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.len() <= 1 {
        return Ok(());
    }
    let mut cur = PathBuf::from(root);
    for comp in parts.iter().take(parts.len() - 1) {
        cur.push(comp);
        let meta = std::fs::symlink_metadata(&cur)
            .map_err(|e| format!("prefix unreadable '{}': {e}", cur.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("symlink prefix refused: '{}'", cur.display()));
        }
        if !meta.is_dir() {
            return Err(format!("prefix not a directory: '{}'", cur.display()));
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max: u64, label: &str) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{label} unreadable '{}': {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{label} symlink refused: '{}'", path.display()));
    }
    if !meta.is_file() {
        return Err(format!("{label} not a regular file: '{}'", path.display()));
    }
    let mut f =
        std::fs::File::open(path).map_err(|e| format!("{label} open failed: {e}"))?;
    let mut out = Vec::new();
    let mut buf = [0u8; IO_BUF];
    let mut total: u64 = 0;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{label} read failed: {e}"))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| format!("{label} too large"))?;
        if total > max {
            return Err(format!("{label} exceeds {max} bytes"));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn parse_file_list(raw: &[u8]) -> Result<Vec<String>, String> {
    if raw.len() as u64 > MAX_LIST_BYTES {
        return Err(format!("file-list exceeds {MAX_LIST_BYTES} bytes"));
    }
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let chunks: Vec<&[u8]> = raw.split(|b| *b == b'\n').collect();
    let trailing_empty = chunks.last().is_some_and(|c| c.is_empty()) && !raw.is_empty();
    let n = if trailing_empty {
        chunks.len().saturating_sub(1)
    } else {
        chunks.len()
    };
    if raw.is_empty() {
        return Err("file-list is empty".to_string());
    }
    for (idx, mut line) in chunks.into_iter().take(n).enumerate() {
        let followed_by_lf = trailing_empty || idx + 1 < n;
        if followed_by_lf && line.ends_with(b"\r") {
            line = &line[..line.len().saturating_sub(1)];
        }
        if line.is_empty() {
            return Err(format!("file-list line {} is empty", idx + 1));
        }
        let s = std::str::from_utf8(line)
            .map_err(|_| format!("file-list line {} is not UTF-8", idx + 1))?;
        if s.contains('\r') {
            return Err(format!("file-list line {} contains CR", idx + 1));
        }
        validate_rel_path(s)
            .map_err(|e| format!("file-list line {}: {e}", idx + 1))?;
        if !seen.insert(s.to_string()) {
            return Err(format!("file-list duplicate: {s}"));
        }
        out.push(s.to_string());
        if out.len() > MAX_FILES {
            return Err(format!("file-list exceeds {MAX_FILES} entries"));
        }
    }
    if out.is_empty() {
        return Err("file-list has no entries".to_string());
    }
    Ok(out)
}

#[cfg(unix)]
fn preserve_mode(src: &Path, dst: &Path) -> Result<u32, String> {
    use std::os::unix::fs::PermissionsExt;
    let src_mode = std::fs::symlink_metadata(src)
        .map_err(|e| format!("mode stat failed: {e}"))?
        .permissions()
        .mode()
        & 0o777;
    let dst_meta =
        std::fs::metadata(dst).map_err(|e| format!("dest stat failed: {e}"))?;
    let mut perms = dst_meta.permissions();
    perms.set_mode(src_mode);
    std::fs::set_permissions(dst, perms).map_err(|e| format!("chmod failed: {e}"))?;
    Ok(src_mode)
}

#[cfg(not(unix))]
fn preserve_mode(_src: &Path, _dst: &Path) -> Result<u32, String> {
    Ok(0)
}

fn copy_stream_hash(
    src: &Path,
    dst: &Path,
    max_file: u64,
    budget_total: u64,
) -> Result<(u64, String), String> {
    let mut fin =
        std::fs::File::open(src).map_err(|e| format!("open source failed: {e}"))?;
    let mut fout = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| format!("create staging file failed: {e}"))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; IO_BUF];
    let mut copied: u64 = 0;
    loop {
        let n = fin
            .read(&mut buf)
            .map_err(|e| format!("read source failed: {e}"))?;
        if n == 0 {
            break;
        }
        copied = copied
            .checked_add(n as u64)
            .ok_or_else(|| "file too large".to_string())?;
        if copied > max_file {
            return Err(format!("file exceeds {max_file} bytes"));
        }
        if copied > budget_total {
            return Err(format!("total exceeds {MAX_TOTAL_BYTES} bytes"));
        }
        h.update(&buf[..n]);
        fout.write_all(&buf[..n])
            .map_err(|e| format!("write staging failed: {e}"))?;
    }
    fout.flush()
        .map_err(|e| format!("flush staging failed: {e}"))?;
    fout.sync_all()
        .map_err(|e| format!("fsync staging failed: {e}"))?;
    drop(fout);
    let sum = h.finalize();
    Ok((copied, hex32(sum)))
}

fn hash_stream(path: &Path, max: u64) -> Result<(u64, String), String> {
    let mut f =
        std::fs::File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; IO_BUF];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| "file too large".to_string())?;
        if total > max {
            return Err(format!("file exceeds {max} bytes"));
        }
        h.update(&buf[..n]);
    }
    Ok((total, hex32(h.finalize())))
}

fn verify_snapshot(root: &Path, manifest_name: &str) -> Result<Manifest, String> {
    ensure_dir_not_symlink(root, "snapshot root")?;
    validate_manifest_name(manifest_name)?;
    let mpath = root.join(manifest_name);
    let raw = read_bounded(&mpath, MAX_MANIFEST_BYTES, "manifest")?;
    let text = std::str::from_utf8(&raw).map_err(|_| "manifest not UTF-8".to_string())?;
    let mf: Manifest =
        serde_json::from_str(text).map_err(|e| format!("manifest bad JSON: {e}"))?;
    if mf.version != MANIFEST_VERSION {
        return Err(format!("unsupported manifest version {}", mf.version));
    }
    if mf.files.len() != mf.file_count {
        return Err("manifest file_count mismatch".to_string());
    }
    if mf.files.len() > MAX_FILES {
        return Err(format!("manifest exceeds {MAX_FILES} entries"));
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut prev: Option<&str> = None;
    let mut sum: u64 = 0;
    for e in &mf.files {
        validate_rel_path(&e.path).map_err(|x| format!("manifest path: {x}"))?;
        if e.path == manifest_name {
            return Err("manifest lists its own name".to_string());
        }
        if !is_valid_sha(&e.sha256) {
            return Err(format!("bad sha256 for '{}'", e.path));
        }
        if e.len > MAX_FILE_BYTES {
            return Err(format!("entry too large: '{}'", e.path));
        }
        if e.mode > 0o777 {
            return Err(format!("bad mode for '{}'", e.path));
        }
        if !seen.insert(e.path.as_str()) {
            return Err(format!("manifest duplicate: '{}'", e.path));
        }
        if let Some(p) = prev {
            if p.as_bytes() >= e.path.as_bytes() {
                return Err("manifest not sorted".to_string());
            }
        }
        prev = Some(e.path.as_str());
        sum = sum
            .checked_add(e.len)
            .ok_or_else(|| "manifest total overflow".to_string())?;
        if sum > MAX_TOTAL_BYTES {
            return Err(format!("manifest total exceeds {MAX_TOTAL_BYTES}"));
        }
    }
    if sum != mf.total_bytes {
        return Err("manifest total_bytes mismatch".to_string());
    }
    if mf.total_bytes > MAX_TOTAL_BYTES {
        return Err(format!("manifest total exceeds {MAX_TOTAL_BYTES}"));
    }
    for e in &mf.files {
        ensure_prefixes_safe(root, &e.path)?;
        let p = root.join(&e.path);
        let meta = std::fs::symlink_metadata(&p)
            .map_err(|_| format!("missing: '{}'", e.path))?;
        if meta.file_type().is_symlink() {
            return Err(format!("symlink refused: '{}'", e.path));
        }
        if !meta.is_file() {
            return Err(format!("not a regular file: '{}'", e.path));
        }
        if meta.len() != e.len {
            return Err(format!(
                "size mismatch '{}': manifest {} disk {}",
                e.path,
                e.len,
                meta.len()
            ));
        }
        let (n, sha) = hash_stream(&p, MAX_FILE_BYTES)
            .map_err(|x| format!("hash '{}' failed: {x}", e.path))?;
        if n != e.len {
            return Err(format!("size drift '{}': {n} vs {}", e.path, e.len));
        }
        if sha != e.sha256 {
            return Err(format!("hash mismatch '{}'", e.path));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m2 = std::fs::symlink_metadata(&p)
                .map_err(|_| format!("stat failed: '{}'", e.path))?;
            if m2.file_type().is_symlink() {
                return Err(format!("symlink refused: '{}'", e.path));
            }
            let disk_mode = m2.permissions().mode() & 0o777;
            if disk_mode != e.mode {
                return Err(format!(
                    "mode mismatch '{}': manifest {:o} disk {:o}",
                    e.path, e.mode, disk_mode
                ));
            }
        }
    }
    Ok(mf)
}

#[cfg(target_os = "linux")]
extern "C" {
    fn renameat2(
        olddirfd: i32,
        oldpath: *const std::os::raw::c_char,
        newdirfd: i32,
        newpath: *const std::os::raw::c_char,
        flags: u32,
    ) -> i32;
}

#[cfg(target_os = "linux")]
fn publish_atomic(staging: &Path, dest: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    const AT_FDCWD: i32 = -100;
    const RENAME_NOREPLACE: u32 = 1;
    let old_c = CString::new(staging.as_os_str().as_bytes())
        .map_err(|_| "staging path contains NUL".to_string())?;
    let new_c = CString::new(dest.as_os_str().as_bytes())
        .map_err(|_| "dest path contains NUL".to_string())?;
    let ret = unsafe {
        renameat2(
            AT_FDCWD,
            old_c.as_ptr(),
            AT_FDCWD,
            new_c.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    if std::fs::symlink_metadata(dest).is_ok() {
        return Err(format!(
            "dest exists, atomic no-replace refused: '{}'",
            dest.display()
        ));
    }
    Err("publish failed (renameat2 no-replace)".to_string())
}

#[cfg(not(target_os = "linux"))]
fn publish_atomic(_staging: &Path, _dest: &Path) -> Result<(), String> {
    Err("atomic no-replace publish not supported on this platform; refusing to overwrite".to_string())
}

fn cmd_create(argv: &[std::ffi::OsString]) -> i32 {
    let known = ["--source-root", "--file-list", "--dest", "--manifest"];
    let required = ["--source-root", "--file-list", "--dest"];
    let opts = match parse_options(argv, &known, &required) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}\n{}", usage());
            return 2;
        }
    };
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "error: create requires Linux (atomic no-replace publish via renameat2); refusing on this platform"
        );
        return 1;
    }
    let source_root = opts.get("--source-root").cloned().unwrap_or_default();
    let file_list = opts.get("--file-list").cloned().unwrap_or_default();
    let dest = opts.get("--dest").cloned().unwrap_or_default();
    let manifest_name = opts
        .get("--manifest")
        .cloned()
        .unwrap_or_else(|| DEFAULT_MANIFEST.to_string());
    if let Err(e) = validate_manifest_name(&manifest_name) {
        eprintln!("error: {e}");
        return 2;
    }
    let src_root = PathBuf::from(&source_root);
    let list_path = PathBuf::from(&file_list);
    let dest_path = PathBuf::from(&dest);
    if let Err(e) = ensure_dir_not_symlink(&src_root, "source root") {
        eprintln!("error: {e}");
        return 1;
    }
    let list_raw = match read_bounded(&list_path, MAX_LIST_BYTES, "file-list") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let mut rels = match parse_file_list(&list_raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    for r in &rels {
        if r == &manifest_name {
            eprintln!("error: file-list contains manifest name '{r}'");
            return 2;
        }
    }
    rels.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    if std::fs::symlink_metadata(&dest_path).is_ok() {
        eprintln!(
            "error: dest exists, refusing to overwrite: '{}'",
            dest_path.display()
        );
        return 1;
    }
    let parent = match dest_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if let Err(e) = ensure_dir_not_symlink(&parent, "dest parent") {
        eprintln!("error: {e}");
        return 1;
    }
    let dest_name = match dest_path.file_name().and_then(|s| s.to_str()) {
        Some(s) => s.to_string(),
        None => {
            eprintln!("error: dest name unrepresentable (non-UTF-8 or empty)");
            return 2;
        }
    };
    if dest_name.is_empty() || dest_name == "." || dest_name == ".." {
        eprintln!("error: bad dest name");
        return 2;
    }
    let staging_name = format!("{dest_name}.staging.{}", std::process::id());
    let staging = parent.join(&staging_name);
    if std::fs::symlink_metadata(&staging).is_ok() {
        eprintln!(
            "error: staging exists, refusing to overwrite: '{}'",
            staging.display()
        );
        return 1;
    }
    if let Err(e) = std::fs::create_dir(&staging) {
        eprintln!("error: create staging failed: {e}");
        return 1;
    }
    let cleanup = |st: &Path| {
        let _ = std::fs::remove_dir_all(st);
    };
    let mut entries: Vec<ManifestEntry> = Vec::with_capacity(rels.len());
    let mut total: u64 = 0;
    for rel in &rels {
        if let Err(e) = ensure_prefixes_safe(&src_root, rel) {
            eprintln!("error: {e}");
            cleanup(&staging);
            return 1;
        }
        let src = src_root.join(rel);
        let smeta = match std::fs::symlink_metadata(&src) {
            Ok(m) => m,
            Err(_) => {
                eprintln!("error: missing source: '{rel}'");
                cleanup(&staging);
                return 1;
            }
        };
        if smeta.file_type().is_symlink() {
            eprintln!("error: source symlink refused: '{rel}'");
            cleanup(&staging);
            return 1;
        }
        if !smeta.is_file() {
            eprintln!("error: source not a regular file: '{rel}'");
            cleanup(&staging);
            return 1;
        }
        let pre_len = smeta.len();
        if pre_len > MAX_FILE_BYTES {
            eprintln!("error: source too large: '{rel}'");
            cleanup(&staging);
            return 1;
        }
        let budget = match MAX_TOTAL_BYTES.checked_sub(total) {
            Some(b) => b,
            None => {
                eprintln!("error: total exceeds {MAX_TOTAL_BYTES} bytes");
                cleanup(&staging);
                return 1;
            }
        };
        let dst = staging.join(rel);
        if let Some(dpar) = dst.parent() {
            if let Err(e) = std::fs::create_dir_all(dpar) {
                eprintln!("error: create staging dir failed: {e}");
                cleanup(&staging);
                return 1;
            }
        }
        let (copied, sha) = match copy_stream_hash(&src, dst.as_path(), MAX_FILE_BYTES, budget)
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: copy '{rel}' failed: {e}");
                cleanup(&staging);
                return 1;
            }
        };
        let dst_len = match std::fs::metadata(&dst) {
            Ok(m) => m.len(),
            Err(e) => {
                eprintln!("error: stat staging failed: {e}");
                cleanup(&staging);
                return 1;
            }
        };
        let post_len = match std::fs::symlink_metadata(&src) {
            Ok(m) if !m.file_type().is_symlink() && m.is_file() => m.len(),
            _ => {
                eprintln!("error: source changed during copy: '{rel}'");
                cleanup(&staging);
                return 1;
            }
        };
        if copied != pre_len || copied != dst_len || post_len != pre_len {
            eprintln!("error: size inconsistency (source changed?): '{rel}'");
            cleanup(&staging);
            return 1;
        }
        let mode = match preserve_mode(&src, &dst) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("error: {e}");
                cleanup(&staging);
                return 1;
            }
        };
        total = match total.checked_add(copied) {
            Some(t) => t,
            None => {
                eprintln!("error: total overflow");
                cleanup(&staging);
                return 1;
            }
        };
        if total > MAX_TOTAL_BYTES {
            eprintln!("error: total exceeds {MAX_TOTAL_BYTES} bytes");
            cleanup(&staging);
            return 1;
        }
        entries.push(ManifestEntry {
            path: rel.clone(),
            len: copied,
            sha256: sha,
            mode,
        });
    }
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mf = Manifest {
        version: MANIFEST_VERSION,
        files: entries,
        file_count: rels.len(),
        total_bytes: total,
    };
    let mut text = match serde_json::to_string_pretty(&mf) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: manifest serialize failed: {e}");
            cleanup(&staging);
            return 1;
        }
    };
    text.push('\n');
    let mpath = staging.join(&manifest_name);
    let mut mf_out = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&mpath)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: create manifest failed: {e}");
            cleanup(&staging);
            return 1;
        }
    };
    if let Err(e) = mf_out.write_all(text.as_bytes()) {
        eprintln!("error: write manifest failed: {e}");
        cleanup(&staging);
        return 1;
    }
    if let Err(e) = mf_out.sync_all() {
        eprintln!("error: fsync manifest failed: {e}");
        cleanup(&staging);
        return 1;
    }
    drop(mf_out);
    if let Err(e) = verify_snapshot(&staging, &manifest_name) {
        eprintln!("error: staging self-verify failed: {e}");
        cleanup(&staging);
        return 1;
    }
    if std::fs::symlink_metadata(&dest_path).is_ok() {
        eprintln!(
            "error: dest exists, refusing to overwrite: '{}'",
            dest_path.display()
        );
        cleanup(&staging);
        return 1;
    }
    if let Err(e) = publish_atomic(&staging, &dest_path) {
        eprintln!("error: {e}");
        cleanup(&staging);
        return 1;
    }
    println!(
        "created '{}' {} files {} bytes manifest '{manifest_name}'",
        dest_path.display(),
        mf.file_count,
        mf.total_bytes
    );
    0
}

fn cmd_verify(argv: &[std::ffi::OsString]) -> i32 {
    let known = ["--snapshot-root", "--manifest"];
    let required = ["--snapshot-root"];
    let opts = match parse_options(argv, &known, &required) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}\n{}", usage());
            return 2;
        }
    };
    let root = opts.get("--snapshot-root").cloned().unwrap_or_default();
    let manifest_name = opts
        .get("--manifest")
        .cloned()
        .unwrap_or_else(|| DEFAULT_MANIFEST.to_string());
    let root_path = PathBuf::from(&root);
    match verify_snapshot(&root_path, &manifest_name) {
        Ok(mf) => {
            println!(
                "verified '{}' {} files {} bytes manifest '{manifest_name}'",
                root_path.display(),
                mf.file_count,
                mf.total_bytes
            );
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
