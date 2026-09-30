//! Offline legacy snapshot+WAL importer into a new WAL-only output.
//!
//! Quiescent copies/synthetic fixtures ONLY: the caller passes explicitly
//! copied snapshot (`kv.json`) and WAL files taken while the legacy broker
//! is stopped or quiesced. This module never touches production paths, never
//! mutates its inputs (no repair, no lock files, no truncation), and never
//! reads the live broker. It writes exactly one new output path and refuses
//! to overwrite.
//!
//! Ordering matches the legacy boot path: the versioned (`{"v":1,..}`) or
//! flat snapshot loads first, then WAL records replay in file order, so
//! snapshot-only keys survive while later WAL deletes/updates win. KV
//! replays through the reviewed [`crate::kv`] core, retaining the native
//! expired-put tombstone correction (a newer expired put suppresses an
//! older live value instead of resurrecting it), fractional `exp`
//! preservation, and JSON-null as a first-class value. Posts, per-topic
//! high-water marks (`topic_seq`, including empty topics), live/retired
//! claims, and opaque records (`art_own` and unknown `t` tags, verbatim)
//! are all preserved.
//!
//! Validation is total before publish: the snapshot must parse as
//! versioned-1 or flat with every `exp` a finite number, and the WAL must
//! be fully valid JSON-lines with a clean tail (no torn bytes, no missing
//! final newline). Any malformed record, unsupported snapshot version, or
//! unclean tail fails before publication with no output file created and
//! source bytes untouched. Diagnostics name lines/counts only and never
//! echo keys, values, or secrets. Every known `post` validates fully
//! before expiry filtering (a malformed expired post fails); only valid
//! expired posts recover high-water marks and are then discarded.
//!
//! Output is a canonical WAL (same layout as [`crate::wal::compact`]:
//! opaque records verbatim first, then one live `kv` put per live key at
//! `now` sorted, then one `topic_seq` plus retained posts per topic sorted,
//! then regenerated claims). It starts under [`crate::wire::Server`]
//! without any legacy snapshot sibling. Publish is atomic no-clobber: an
//! exclusive private temp (`0600` from creation, `create_new` with
//! collision retries, never truncating a stale temp) in the output
//! directory is fsync-backed, then hard-linked to the destination (which
//! fails with `AlreadyExists` when the destination exists, leaving its
//! bytes unchanged), and the parent directory is fsync-backed (including
//! `"."` for bare relative outputs). Re-running with the same inputs and
//! `now` yields byte-identical output.
//!
//! Commit-state contract: failures before the hard-link leaves no output
//! (only the importer's own temp is removed; stale temps and sources are
//! untouched). A publish collision leaves the pre-existing destination
//! bytes unchanged. Once the hard-link lands the output is committed: a
//! later parent-fsync failure returns an error that names the published
//! path and states the output exists with uncertain durability, instead
//! of claiming no output was created.
//!
//! Resource bounds: the snapshot read consumes at most
//! [`MAX_SNAPSHOT_BYTES`] + 1 bytes (a metadata size check alone is not a
//! consumption bound), WAL scans stay bounded by one record
//! ([`crate::wal::MAX_RECORD_BYTES`]), and opaque records stream straight
//! to the temp output without collecting the whole opaque prefix in
//! memory. Opaque order and bytes are preserved as validated.
//!
//! Startup snapshot refusal stays in place: [`crate::wire::Server::new`]
//! still refuses when a `kv.json` sibling exists. Migration output must be
//! started in a directory without that sibling; this importer refuses to
//! create an output whose sibling snapshot already exists.
//!
//! Historical note: the pure [`crate::kv`] core replays leniently (skips +
//! counts malformed lines) for unit-test introspection, while the broker
//! (live [`crate::wal::replay`] and this importer) fails closed on any
//! malformed complete record. The importer upgrades every core skip into a
//! refusal.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::kv::KvError;
use crate::wal::{replay, snapshot_path_for, stream_opaque_records_to, tail_status, BusState, TailStatus};

/// Maximum snapshot bytes accepted (mirrors the wire frame cap: a snapshot
/// is one JSON document, so the whole file is bounded before parsing).
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;

/// What the importer restored and wrote (counts only, never keys/values).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationReport {
    /// Keys merged from the snapshot (including already-expired ones; expiry
    /// is enforced at read time, matching the legacy boot path).
    pub snapshot_keys: usize,
    /// Orphaned numeric `exp` entries in the snapshot with no matching `kv`.
    pub snapshot_skipped: usize,
    /// Retained posts restored from the WAL.
    pub wal_posts: usize,
    /// Claim records replayed from the WAL.
    pub wal_claims: usize,
    /// Opaque legacy records preserved verbatim.
    pub opaque: usize,
    /// Live KV keys written to the output at `now`.
    pub kv_live: usize,
    /// Output file bytes after atomic publish.
    pub out_bytes: u64,
}

/// Importer failure: lines/counts/paths only, never keys, values, or secrets.
#[derive(Debug)]
pub enum MigrationError {
    /// `now` was non-finite; expiry cannot be evaluated.
    NonFiniteNow,
    /// Snapshot exceeds [`MAX_SNAPSHOT_BYTES`].
    SnapshotTooLarge { bytes: u64, limit: usize },
    /// Snapshot cannot be read (including explicit-path missing).
    SnapshotRead(String),
    /// Snapshot parses but is structurally invalid (sanitized, no key echo).
    SnapshotInvalid(String),
    /// WAL cannot be opened/read (fail closed, never an empty broker).
    WalUnreadable(String),
    /// WAL has a structurally invalid complete record at this 1-based line.
    WalCorrupt { line: u64, reason: String },
    /// WAL tail is not clean (quiescent copies must end on a newline).
    WalTailUnclean(String),
    /// Output path already exists; refusing to overwrite.
    OutputExists(PathBuf),
    /// Output path equals an input path; refusing source mutation.
    OutputIsInput(PathBuf),
    /// Output sibling `kv.json` exists; the broker would refuse startup.
    OutputSiblingSnapshotExists(PathBuf),
    /// Output write/publish failure. Failures before the atomic hard-link
    /// remove only the importer's own temp and leave no output; once the
    /// link lands the output is committed and the error names the published
    /// path with its uncertain-durability state (see the module
    /// commit-state contract).
    OutputWrite(String),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::NonFiniteNow => write!(f, "non-finite migration time"),
            MigrationError::SnapshotTooLarge { bytes, limit } => {
                write!(f, "snapshot too large: {bytes} bytes exceeds {limit}-byte bound")
            }
            MigrationError::SnapshotRead(e) => write!(f, "snapshot read failed: {e}"),
            MigrationError::SnapshotInvalid(reason) => write!(f, "bad snapshot: {reason}"),
            MigrationError::WalUnreadable(e) => write!(f, "wal unreadable: {e}"),
            MigrationError::WalCorrupt { line, reason } => {
                write!(f, "wal corrupt at line {line}: {reason}")
            }
            MigrationError::WalTailUnclean(reason) => {
                write!(f, "wal tail unclean (quiescent copy must end on newline): {reason}")
            }
            MigrationError::OutputExists(p) => {
                write!(f, "output already exists, refusing to overwrite: {}", p.display())
            }
            MigrationError::OutputIsInput(p) => {
                write!(f, "output equals input, refusing source mutation: {}", p.display())
            }
            MigrationError::OutputSiblingSnapshotExists(p) => write!(
                f,
                "output sibling snapshot exists, broker would refuse startup: {}",
                p.display()
            ),
            MigrationError::OutputWrite(e) => write!(f, "output write failed: {e}"),
        }
    }
}

impl std::error::Error for MigrationError {}

/// Strip any key/value echo from a [`KvError::BadSnapshot`] detail.
///
/// The core includes the offending key for unit-test introspection
/// (`malformed exp for key "k"`) and the claimed version value; the broker
/// surface must never repeat those, so the importer reduces them to fixed
/// reasons. JSON-decode and object-shape reasons carry no content and pass
/// through with their line/column context intact.
fn sanitize_snapshot_detail(detail: &str) -> String {
    if detail.starts_with("malformed exp for key") {
        return "malformed exp entry".to_string();
    }
    if detail.starts_with("unsupported snapshot version") {
        return "unsupported snapshot version".to_string();
    }
    detail.to_string()
}

fn is_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    // Resolve symlinks/relative segments where both sides exist; the output
    // itself must not exist yet, so compare its canonical parent + file name
    // against the canonical input when possible.
    let canon = |p: &Path| std::fs::canonicalize(p).ok();
    match (canon(a), canon(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn output_canonical_path(out: &Path) -> Option<PathBuf> {
    let parent = out.parent().filter(|p| !p.as_os_str().is_empty())?;
    let canon_parent = std::fs::canonicalize(parent).ok()?;
    out.file_name().map(|n| canon_parent.join(n))
}

/// Read a snapshot file with a real consumption bound: at most
/// `limit + 1` bytes are ever pulled from the descriptor, so a large file
/// is rejected without first allocating it whole. A metadata size check
/// alone is not a bound (TOCTOU growth between stat and read), so the
/// `take` gate is the enforcement; metadata only supplies the diagnostic
/// byte count when available.
fn read_snapshot_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, MigrationError> {
    let mut f =
        File::open(path).map_err(|e| MigrationError::SnapshotRead(e.to_string()))?;
    let meta_len = f.metadata().map(|m| m.len()).ok();
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take(limit as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| MigrationError::SnapshotRead(e.to_string()))?;
    if raw.len() > limit {
        let bytes = meta_len.unwrap_or(raw.len() as u64).max(raw.len() as u64);
        return Err(MigrationError::SnapshotTooLarge { bytes, limit });
    }
    Ok(raw)
}

/// Create an exclusive private migration temp in the output directory.
///
/// Uses `create_new` (never truncate) with mode `0600` from creation on
/// Unix, retrying on collision so a stale temp from a prior run is never
/// consumed. Returns the created path (the only temp the caller may remove)
/// and its open handle.
fn create_private_migrate_tmp(out: &Path) -> Result<(PathBuf, File), String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let base = out.file_name().and_then(|s| s.to_str()).unwrap_or("wal");
    let dir = out.parent().filter(|p| !p.as_os_str().is_empty());
    for _ in 0..1000 {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let file = format!("{base}.migrate.{}.{n}.tmp", std::process::id());
        let candidate = dir
            .map(|p| p.join(&file))
            .unwrap_or_else(|| PathBuf::from(&file));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&candidate) {
            Ok(f) => return Ok((candidate, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("migration temp collision budget exhausted".to_string())
}

/// Atomically publish `tmp` (created by this call) to `out` without
/// clobbering: `hard_link` fails with `AlreadyExists` when `out` exists,
/// leaving its bytes unchanged. On success the temp name is unlinked,
/// leaving `out` as the committed output. On collision the temp is removed
/// and `OutputExists` is returned; on other link failures the temp is
/// removed and `OutputWrite` is returned.
fn publish_no_clobber(tmp: &Path, out: &Path) -> Result<(), MigrationError> {
    match std::fs::hard_link(tmp, out) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(tmp);
            Err(MigrationError::OutputExists(out.to_path_buf()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(tmp);
            Err(MigrationError::OutputWrite(format!("publish: {e}")))
        }
    }
}

/// Parent directory to fsync after publish: the output parent, or `"."`
/// for bare relative outputs (whose parent is empty but whose directory
/// entry still needs durability).
fn parent_fsync_dir(out: &Path) -> &Path {
    out.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Import a legacy snapshot (optional explicit copy) plus a quiescent WAL
/// copy into a new WAL-only output.
///
/// - `snapshot`: `Some` explicit snapshot copy (must exist and be valid),
///   or `None` for WAL-only migration. A missing explicit path fails; there
///   is no implicit sibling lookup, so production files are never read by
///   accident.
/// - `wal`: explicit quiescent WAL copy (must exist and be fully valid with
///   a clean tail). A missing WAL fails: migration needs an explicit copy,
///   not an assumed-empty broker.
/// - `out`: new output path (must not exist, must differ from both inputs,
///   and its `kv.json` sibling must not exist).
/// - `now`: caller-provided unix seconds (finite) for expiry evaluation and
///   live-set selection, matching the replay/compaction `< now` boundary.
///
/// On success the output starts under [`crate::wire::Server`] without any
/// snapshot sibling. Commit-state: failures before the atomic hard-link
/// leave no output (only the importer's own temp is removed); a publish
/// collision leaves the pre-existing destination unchanged; once the link
/// lands the output is committed and a later parent-fsync failure reports
/// the published path as existing with uncertain durability. Inputs are
/// never mutated.
pub fn migrate_legacy_to_wal(
    snapshot: Option<&Path>,
    wal: &Path,
    out: &Path,
    now: f64,
) -> Result<MigrationReport, MigrationError> {
    if !now.is_finite() {
        return Err(MigrationError::NonFiniteNow);
    }
    // Refuse source mutation before any IO: lexical plus canonical checks.
    if is_same_file(out, wal) {
        return Err(MigrationError::OutputIsInput(out.to_path_buf()));
    }
    if let Some(snap) = snapshot {
        if is_same_file(out, snap) {
            return Err(MigrationError::OutputIsInput(out.to_path_buf()));
        }
    }
    if let Some(out_canon) = output_canonical_path(out) {
        if let Ok(wal_canon) = std::fs::canonicalize(wal) {
            if out_canon == wal_canon {
                return Err(MigrationError::OutputIsInput(out.to_path_buf()));
            }
        }
        if let Some(snap) = snapshot {
            if let Ok(snap_canon) = std::fs::canonicalize(snap) {
                if out_canon == snap_canon {
                    return Err(MigrationError::OutputIsInput(out.to_path_buf()));
                }
            }
        }
    }
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(MigrationError::OutputExists(out.to_path_buf()));
    }
    // The broker would refuse startup here; fail before any expensive scan.
    let sibling = snapshot_path_for(out);
    if sibling.exists() {
        return Err(MigrationError::OutputSiblingSnapshotExists(sibling));
    }

    // Phase 1: validate all inputs fully before any output IO. The
    // snapshot read is consumption-bounded (take gate, not a stat check);
    // WAL replay and tail validation stream with one-record bounds.
    let mut state = BusState::new();
    let (snapshot_keys, snapshot_skipped) = match snapshot {
        None => (0, 0),
        Some(path) => {
            let raw = read_snapshot_bounded(path, MAX_SNAPSHOT_BYTES)?;
            let text = std::str::from_utf8(&raw)
                .map_err(|e| MigrationError::SnapshotInvalid(format!("invalid UTF-8: {e}")))?;
            match state.kv.restore_snapshot(text) {
                Ok(report) => (report.loaded, report.skipped),
                Err(KvError::BadSnapshot(detail)) => {
                    return Err(MigrationError::SnapshotInvalid(sanitize_snapshot_detail(
                        &detail,
                    )));
                }
                Err(e) => {
                    return Err(MigrationError::SnapshotInvalid(sanitize_snapshot_detail(
                        &e.to_string(),
                    )));
                }
            }
        }
    };

    // The WAL copy must exist explicitly; a missing file is an operator
    // error here, not a fresh start (fresh starts need no migration).
    if std::fs::symlink_metadata(wal).is_err() {
        // Distinguish unreadable-vs-missing without echoing bytes: the
        // message carries the OS reason only.
        let reason = std::fs::File::open(wal)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "wal not found".to_string());
        return Err(MigrationError::WalUnreadable(reason));
    }
    let (wal_posts, wal_claims) =
        replay(wal, &mut state, now).map_err(|e| match e {
            crate::wal::ReplayError::Open(io) => MigrationError::WalUnreadable(io.to_string()),
            crate::wal::ReplayError::Corrupt { line, detail } => {
                MigrationError::WalCorrupt { line, reason: detail }
            }
        })?;
    // Live replay tolerates a torn tail as unacked; a quiescent copy must
    // be clean, otherwise the copy itself may be mid-write torn.
    match tail_status(wal).map_err(|e| match e {
        crate::wal::ReplayError::Open(io) => MigrationError::WalUnreadable(io.to_string()),
        crate::wal::ReplayError::Corrupt { line, detail } => {
            MigrationError::WalCorrupt { line, reason: detail }
        }
    })? {
        TailStatus::Clean => {}
        TailStatus::ValidUnterminated => {
            return Err(MigrationError::WalTailUnclean(
                "final record lacks terminating newline".to_string(),
            ));
        }
        TailStatus::Torn { start } => {
            return Err(MigrationError::WalTailUnclean(format!(
                "torn partial tail at byte {start}"
            )));
        }
    }
    // Phase 2: atomic no-clobber publish to a new path only. Opaque
    // records stream straight to the temp output during this phase (no
    // whole-prefix Vec); a streaming corruption still fails before the
    // hard-link, with only our own temp removed.
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| MigrationError::OutputWrite(format!("create parent: {e}")))?;
        }
    }
    // Fast-path re-checks after parent creation (offline fail-closed).
    // These are not the atomic gate: the hard-link below is.
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(MigrationError::OutputExists(out.to_path_buf()));
    }
    if snapshot_path_for(out).exists() {
        return Err(MigrationError::OutputSiblingSnapshotExists(snapshot_path_for(
            out,
        )));
    }
    let (tmp, tmp_file) = create_private_migrate_tmp(out).map_err(MigrationError::OutputWrite)?;
    let write_outcome: Result<(usize, usize, u64), MigrationError> = (|| {
        let mut f = tmp_file;
        let opaque_count = stream_opaque_records_to(wal, &mut f).map_err(|e| match e {
            crate::wal::ReplayError::Open(io) => {
                MigrationError::OutputWrite(format!("stream opaque: {io}"))
            }
            crate::wal::ReplayError::Corrupt { line, detail } => {
                MigrationError::WalCorrupt { line, reason: detail }
            }
        })?;
        let kv_snap = state.kv.snapshot(now);
        let kv_live = kv_snap.kv.len();
        for (key, value) in &kv_snap.kv {
            let rec = serde_json::json!({
                "t": crate::kv::RECORD_PUT,
                "key": key,
                "value": value,
                "exp": kv_snap.exp.get(key),
            });
            let bytes = serde_json::to_vec(&rec).expect("kv put record serializes");
            f.write_all(&bytes)
                .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
            f.write_all(b"\n")
                .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
        }
        let mut topics: Vec<&String> = state.topics.keys().collect();
        topics.sort();
        for topic in topics {
            let t = &state.topics[topic];
            let mark = serde_json::json!({"t": "topic_seq", "topic": topic, "seq": t.seq});
            let bytes = serde_json::to_vec(&mark).expect("topic_seq record serializes");
            f.write_all(&bytes)
                .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
            f.write_all(b"\n")
                .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
            for msg in &t.msgs {
                let rec = serde_json::json!({"t": "post", "topic": topic, "msg": msg});
                let bytes = serde_json::to_vec(&rec).expect("post record serializes");
                f.write_all(&bytes)
                    .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
                f.write_all(b"\n")
                    .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
            }
        }
        write_canonical_claims(&mut f, &state.claims.snapshot(now))
            .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
        f.flush()
            .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
        f.sync_all()
            .map_err(|e| MigrationError::OutputWrite(format!("sync temp: {e}")))?;
        let len = f
            .metadata()
            .map(|m| m.len())
            .map_err(|e| MigrationError::OutputWrite(e.to_string()))?;
        Ok((opaque_count, kv_live, len))
    })();
    let (opaque_count, kv_live, tmp_len) = match write_outcome {
        Ok(v) => v,
        Err(e) => {
            // Pre-publish failure: only our own temp is removed; stale
            // temps, sources, and any pre-existing destination are untouched.
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    // Atomic no-clobber publish: the hard-link is the gate, not a
    // symlink_metadata check (check-then-rename races and Unix rename
    // silently replaces). A destination appearing before this point fails
    // here with its bytes unchanged.
    publish_no_clobber(&tmp, out)?;
    // Fsync the parent directory entry, including "." for bare relative
    // outputs. The link already landed, so the output is committed: a
    // failure here reports the published path as existing with uncertain
    // durability instead of claiming no output was created.
    if let Err(e) = File::open(parent_fsync_dir(out)).and_then(|d| d.sync_all()) {
        return Err(MigrationError::OutputWrite(format!(
            "output published at {} but parent fsync failed: {e} (output exists, durability uncertain)",
            out.display()
        )));
    }
    let out_bytes = std::fs::metadata(out)
        .map(|m| m.len())
        .unwrap_or(tmp_len);
    Ok(MigrationReport {
        snapshot_keys,
        snapshot_skipped,
        wal_posts,
        wal_claims,
        opaque: opaque_count,
        kv_live,
        out_bytes,
    })
}

/// Regenerate the minimal claim records that restore `snap` on replay.
///
/// Mirrors [`crate::wal::compact`] ordering (receipts sorted by
/// owner/resource/key, live sorted by resource, fencing sorted) so output is
/// deterministic and a retired key stays retired instead of resurrecting.
fn write_canonical_claims(
    f: &mut File,
    snap: &crate::claims::ClaimSnapshot,
) -> std::io::Result<()> {
    use std::collections::{HashMap, HashSet};
    let live: HashMap<&str, _> = snap.live.iter().map(|(r, l)| (r.as_str(), l)).collect();
    let fencing: HashMap<&str, u64> =
        snap.fencing.iter().map(|(r, n)| (r.as_str(), *n)).collect();
    let mut covered: HashSet<(&str, &str)> = HashSet::new();
    let mut referenced: HashSet<&str> = HashSet::new();
    for (owner, resource, key, token, rec_fencing, acquired_at, receipt_exp, ttl_ms) in
        &snap.receipts
    {
        referenced.insert(resource.as_str());
        let live_match = live.get(resource.as_str()).filter(|l| l.token == *token);
        if let Some(l) = live_match {
            covered.insert((resource.as_str(), token.as_str()));
            write_acquire(
                f,
                resource,
                owner,
                token,
                l.fencing,
                *acquired_at,
                l.expires_at,
                Some(key.clone()),
                Some(*ttl_ms),
                false,
            )?;
        } else {
            write_acquire(
                f,
                resource,
                owner,
                token,
                *rec_fencing,
                *acquired_at,
                *receipt_exp,
                Some(key.clone()),
                Some(*ttl_ms),
                false,
            )?;
            let fence = fencing
                .get(resource.as_str())
                .copied()
                .unwrap_or(*rec_fencing)
                .max(*rec_fencing);
            let rel =
                serde_json::json!({"t": "claim_release", "resource": resource, "fencing": fence});
            f.write_all(serde_json::to_vec(&rel).unwrap().as_slice())?;
            f.write_all(b"\n")?;
        }
    }
    for (resource, lease) in &snap.live {
        if covered.contains(&(resource.as_str(), lease.token.as_str())) {
            continue;
        }
        referenced.insert(resource.as_str());
        write_acquire(
            f,
            resource,
            &lease.owner,
            &lease.token,
            lease.fencing,
            lease.acquired_at,
            lease.expires_at,
            None,
            None,
            false,
        )?;
    }
    for (resource, fence) in &snap.fencing {
        if referenced.contains(resource.as_str()) {
            continue;
        }
        let rel = serde_json::json!({"t": "claim_release", "resource": resource, "fencing": fence});
        f.write_all(serde_json::to_vec(&rel).unwrap().as_slice())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_acquire(
    f: &mut File,
    resource: &str,
    owner: &str,
    token: &str,
    fencing: u64,
    acquired_at: f64,
    expires_at: f64,
    idem: Option<String>,
    ttl_ms: Option<u64>,
    renew: bool,
) -> std::io::Result<()> {
    let rec = serde_json::json!({"t": "claim_acquire", "resource": resource, "owner": owner,
        "token": token, "fencing": fencing, "acquired_at": acquired_at,
        "expires_at": expires_at, "idem": idem, "ttl_ms": ttl_ms, "renew": renew});
    f.write_all(serde_json::to_vec(&rec).unwrap().as_slice())?;
    f.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_snapshot_read_enforces_limit_on_consumption() {
        // Small-limit proof that the take gate (not a stat check) enforces
        // the bound: limit bytes pass, limit+1 fails without reading more.
        let dir = std::env::temp_dir().join(format!(
            "agent-bus-mig-bound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ok_path = dir.join("ok.json");
        let big_path = dir.join("big.json");
        std::fs::write(&ok_path, vec![b'a'; 64]).unwrap();
        std::fs::write(&big_path, vec![b'b'; 65]).unwrap();
        let ok = read_snapshot_bounded(&ok_path, 64).expect("limit bytes pass");
        assert_eq!(ok.len(), 64);
        match read_snapshot_bounded(&big_path, 64) {
            Err(MigrationError::SnapshotTooLarge { bytes, limit }) => {
                assert_eq!(limit, 64);
                assert!(bytes >= 65, "diagnostic bytes {bytes}");
            }
            other => panic!("limit+1 must fail with TooLarge, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_fsync_dir_covers_bare_relative_outputs() {
        assert_eq!(parent_fsync_dir(Path::new("output.log")), Path::new("."));
        assert_eq!(
            parent_fsync_dir(Path::new("sub/output.log")),
            Path::new("sub")
        );
        assert_eq!(
            parent_fsync_dir(Path::new("/tmp/x/output.log")),
            Path::new("/tmp/x")
        );
    }

    #[test]
    fn publish_no_clobber_leaves_destination_bytes_unchanged() {
        // Destination appearing before publish: link fails, dest bytes
        // unchanged, only our temp removed.
        let dir = std::env::temp_dir().join(format!(
            "agent-bus-mig-pub-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let tmp = dir.join("candidate.tmp");
        let dest = dir.join("dest.log");
        std::fs::write(&tmp, b"candidate bytes").unwrap();
        std::fs::write(&dest, b"committed bytes\n").unwrap();
        match publish_no_clobber(&tmp, &dest) {
            Err(MigrationError::OutputExists(p)) => assert_eq!(p, dest),
            other => panic!("existing dest must fail with OutputExists, got {other:?}"),
        }
        assert_eq!(std::fs::read(&dest).unwrap(), b"committed bytes\n");
        assert!(!tmp.exists(), "only our temp removed");
        // Fresh destination publishes and unlinks the temp name.
        let tmp2 = dir.join("candidate2.tmp");
        let dest2 = dir.join("dest2.log");
        std::fs::write(&tmp2, b"new bytes").unwrap();
        publish_no_clobber(&tmp2, &dest2).expect("fresh publish succeeds");
        assert_eq!(std::fs::read(&dest2).unwrap(), b"new bytes");
        assert!(!tmp2.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
