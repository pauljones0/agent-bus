//! fsync-backed WAL with sequence high-water marks.
//!
//! Record compatibility with the transitional Python broker WAL:
//! - `{"t":"post","topic":..,"msg":{..,"seq":N}}`
//! - `{"t":"topic_seq","topic":..,"seq":N}` — independent high-water mark,
//!   written even for empty topics so compaction never loses the next
//!   sequence number after expiry + restart.
//! - `{"t":"claim_acquire",..}` / `{"t":"claim_release",..}`
//! - `{"t":"kv","key":..,"value":..,"exp":..}` / `{"t":"kv_del","key":..}`
//!
//! Replay recovers high-water marks from expired post records too: a
//! consumer saved at cursor N must never skip a post-restart message that
//! reuses N. KV replays through the reviewed `crate::kv` core: live puts
//! set keys, deletes clear them, and already-expired puts are tombstones
//! that suppress older values (never resurrections). A structurally
//! invalid KV record fails closed like a malformed post does; the
//! `kv::LineOutcome::SkippedMalformed` case never becomes a silent skip
//! at this layer.
//!
//! Legacy KV snapshots (`kv.json` siblings of the WAL) are explicitly
//! unsupported: [`snapshot_path_for`] names the conventional path and the
//! wire server refuses startup when it exists, instead of silently
//! discarding snapshot-only keys. Native durability is WAL-only; tests
//! use synthetic fixture WALs without snapshots.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::claims::{ClaimStore, WalClaim};
use crate::history::{Msg, Topic};
use crate::kv::{KvStore, LineOutcome};

pub struct BusState {
    pub topics: HashMap<String, Topic>,
    pub claims: ClaimStore,
    pub kv: KvStore,
}

impl BusState {
    pub fn new() -> Self {
        BusState { topics: HashMap::new(), claims: ClaimStore::new(), kv: KvStore::new() }
    }

    pub fn topic(&mut self, name: &str) -> &mut Topic {
        self.topics.entry(name.to_string()).or_default()
    }

    /// Post a retained message; returns the sequence number.
    pub fn post(&mut self, topic: &str, msg: Msg) -> u64 {
        self.topic(topic).post(msg)
    }
}

impl Default for BusState {
    fn default() -> Self {
        Self::new()
    }
}

/// Append one JSON record line and fsync before returning: grants and posts
/// are durable before ack by default.
pub fn append_fsync(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    append_fsync_detailed(path, value, APPEND_FAIL_NONE).map_err(|e| e.source)
}

/// Append one pre-rendered canonical record line and fsync before returning.
///
/// The `kv` core renders its own canonical `kv`/`kv_del` lines via
/// `prepare_*`; the wire passes them here unchanged so the durable bytes
/// match the validated shape without a re-serialize round trip. The line
/// must be a single JSON object without a trailing newline; this function
/// appends the newline and fsyncs. Used as the durability callback for
/// `KvStore::commit_*`: memory mutates only after this succeeds.
pub fn append_line_fsync(path: &Path, line: &str) -> std::io::Result<()> {
    append_line_fsync_detailed(path, line, APPEND_FAIL_NONE).map_err(|e| e.source)
}

/// Deterministic append failure injection for durability tests.
/// Production passes [`APPEND_FAIL_NONE`]; the wire server holds a
/// per-server failpoint (test hook) and passes it here so partial
/// write/newline/fsync failures are exercised without filesystem tricks.
/// Each mode performs real partial bytes before failing, so rollback
/// (truncate to pre-length) is genuinely exercised:
/// - `NONE`: normal append+fsync.
/// - `FAIL_OPEN`: fail before opening (no bytes, `opened=false`).
/// - `FAIL_AFTER_LINE`: write the record bytes, then fail before the
///   newline (valid-unterminated tail, `opened=true`).
/// - `FAIL_AFTER_NEWLINE`: write record+newline, then fail before fsync
///   (complete but unsynced, `opened=true`).
/// - `FAIL_SYNC`: write record+newline+flush, then fail instead of fsync
///   (complete but unsynced, `opened=true`).
pub const APPEND_FAIL_NONE: u8 = 0;
pub const APPEND_FAIL_OPEN: u8 = 1;
pub const APPEND_FAIL_AFTER_LINE: u8 = 2;
pub const APPEND_FAIL_AFTER_NEWLINE: u8 = 3;
pub const APPEND_FAIL_SYNC: u8 = 4;

/// Detailed append failure: the IO error plus whether the file was
/// opened (possible partial bytes). The wire uses `opened` to decide
/// rollback: `false` needs no truncate (open failed, no bytes);
/// `true` must truncate to pre-length or poison (partial write may
/// have landed, and continued appends would corrupt/revive).
#[derive(Debug)]
pub struct AppendError {
    pub source: std::io::Error,
    pub opened: bool,
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for AppendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn simulated(detail: &str, opened: bool) -> AppendError {
    AppendError {
        source: std::io::Error::other(detail.to_string()),
        opened,
    }
}

/// Append with failure injection, reporting whether the file was opened.
/// See [`APPEND_FAIL_NONE`] for modes. Unknown modes behave as `NONE`.
pub fn append_fsync_detailed(
    path: &Path,
    value: &serde_json::Value,
    failpoint: u8,
) -> Result<(), AppendError> {
    let line = serde_json::to_string(value).expect("record serializes");
    append_line_fsync_detailed(path, &line, failpoint)
}

/// Append a pre-rendered line with failure injection.
/// See [`APPEND_FAIL_NONE`] for modes.
pub fn append_line_fsync_detailed(
    path: &Path,
    line: &str,
    failpoint: u8,
) -> Result<(), AppendError> {
    if failpoint == APPEND_FAIL_OPEN {
        return Err(simulated("simulated open failure", false));
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| AppendError { source: e, opened: false })?;
    // From here the file is open: any failure may have left partial
    // bytes, so `opened=true` obliges the caller to truncate or poison.
    let map_opened = |e: std::io::Error| AppendError { source: e, opened: true };
    f.write_all(line.as_bytes()).map_err(map_opened)?;
    if failpoint == APPEND_FAIL_AFTER_LINE {
        // Real partial: record bytes durable in page cache, no newline.
        let _ = f.flush();
        return Err(simulated("simulated failure after record bytes", true));
    }
    f.write_all(b"\n").map_err(map_opened)?;
    if failpoint == APPEND_FAIL_AFTER_NEWLINE {
        let _ = f.flush();
        return Err(simulated("simulated failure after newline", true));
    }
    f.flush().map_err(map_opened)?;
    if failpoint == APPEND_FAIL_SYNC {
        return Err(simulated("simulated fsync failure", true));
    }
    f.sync_all().map_err(map_opened)?;
    Ok(())
}

/// Truncate the WAL back to `len` and fsync the truncation.
/// The wire calls this after any `opened=true` append failure to
/// restore pre-append bytes (preventing torn-tail concatenation and
/// replay resurrection of the failed record). Returns the truncate
/// error for poison decisions.
pub fn truncate_to(path: &Path, len: u64) -> std::io::Result<()> {
    let f = OpenOptions::new().write(true).open(path)?;
    f.set_len(len)?;
    f.sync_all()?;
    Ok(())
}

/// Conventional legacy KV snapshot sibling for a WAL path: `<wal-dir>/kv.json`.
///
/// The transitional broker persists live KV both as WAL `kv`/`kv_del`
/// records and as a periodic `kv.json` snapshot (live-only, `{"v":1,..}`
/// or flat). Native durability is WAL-only and never reads or writes this
/// file; the wire server refuses startup when it exists so snapshot-only
/// keys are never silently discarded. Returns the sibling path even when
/// the WAL has no parent (current directory).
pub fn snapshot_path_for(wal_path: &Path) -> PathBuf {
    wal_path
        .parent()
        .map(|p| p.join("kv.json"))
        .unwrap_or_else(|| PathBuf::from("kv.json"))
}

/// Replay failure: the WAL cannot be faithfully restored.
///
/// A missing file is a fresh start (`Ok`), never an error. Every other
/// read or corruption problem fails closed so unreadable history never
/// looks like an empty broker.
#[derive(Debug)]
pub enum ReplayError {
    /// The WAL exists but cannot be opened (permissions, directory, ...).
    Open(std::io::Error),
    /// A complete record that parses but is structurally invalid, or a WAL
    /// that is not valid UTF-8 (`line == 0`).
    Corrupt { line: u64, detail: String },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::Open(e) => write!(f, "wal open failed: {e}"),
            ReplayError::Corrupt { line, detail } => {
                write!(f, "wal corrupt at line {line}: {detail}")
            }
        }
    }
}

impl std::error::Error for ReplayError {}

/// Maximum bytes accepted for one WAL record line, mirroring the wire frame
/// cap: a single record can never legitimately exceed one inbound frame, so
/// replay/compaction stream records with this per-record bound instead of
/// loading the whole file into memory.
pub const MAX_RECORD_BYTES: usize = 256 * 1024 * 1024;

/// What the WAL tail looked like after a streaming scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tail {
    /// Missing/empty file, or the final byte is a newline: appends are safe.
    Clean,
    /// The final record is complete JSON but lacks its terminating newline
    /// (a crash between the record write and the newline write, or a torn
    /// single-byte write). The record was fully written, so it replays; the
    /// file needs a newline appended before the next record.
    ValidUnterminated,
    /// The final bytes are not a complete record (a crash mid-append; that
    /// record was never acked, so dropping it is safe). The file needs
    /// truncation back to the last newline before the next append.
    Torn { start: u64 },
}

/// Outcome of [`repair_tail`] for tests and startup logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailRepair {
    /// Nothing to fix: missing/empty file or newline-terminated tail.
    Clean,
    /// Appended the missing newline after a complete final record.
    AppendedNewline,
    /// Truncated a torn partial tail starting at this byte offset.
    TruncatedTornTail { start: u64 },
}

/// Read-only tail status for offline migration: no repair, no mutation.
///
/// The importer refuses any non-clean tail so a quiescent copy is proven
/// append-safe before migration; live replay tolerates torn tails, but an
/// offline copy must be clean to rule out a mid-copy torn read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailStatus {
    /// Missing/empty file, or the final byte is a newline.
    Clean,
    /// Final record is complete JSON but lacks its terminating newline.
    ValidUnterminated,
    /// Final bytes are not a complete record, starting at this offset.
    Torn { start: u64 },
}

/// Inspect the WAL tail without repairing it (streaming, bounded by one
/// record like replay). Used by the offline importer to fail closed on
/// torn/unterminated quiescent copies instead of silently dropping bytes.
pub fn tail_status(path: &Path) -> Result<TailStatus, ReplayError> {
    let tail = for_each_record(path, &mut |_, _| Ok(()))?;
    Ok(match tail {
        Tail::Clean => TailStatus::Clean,
        Tail::ValidUnterminated => TailStatus::ValidUnterminated,
        Tail::Torn { start } => TailStatus::Torn { start },
    })
}

/// Collect opaque legacy records verbatim in WAL order (streaming, bounded).
///
/// Known record types (`post`, `topic_seq`, `claim_acquire`,
/// `claim_release`, `kv`, `kv_del`) are skipped here because the importer
/// regenerates them canonically from validated state; every other `t` tag
/// (including `art_own` and future kinds) is preserved byte-for-byte so
/// migration never drops stores this slice does not serve. Blank lines are
/// ignored like in replay. A malformed middle record fails closed; a torn
/// tail is not delivered (the importer refuses it via [`tail_status`]).
///
/// Prefer [`stream_opaque_records_to`] for migration/compaction output: it
/// writes opaque records straight to the destination without holding the
/// whole opaque prefix in memory.
pub fn collect_opaque_records(path: &Path) -> Result<Vec<String>, ReplayError> {
    let mut out = Vec::new();
    for_each_record(path, &mut |_, line| {
        let r: serde_json::Value =
            serde_json::from_str(line).expect("record validated by for_each_record");
        match r.get("t").and_then(|t| t.as_str()) {
            Some("post")
            | Some("topic_seq")
            | Some("claim_acquire")
            | Some("claim_release")
            | Some("kv")
            | Some("kv_del") => {}
            _ => out.push(line.to_string()),
        }
        Ok(())
    })?;
    Ok(out)
}

/// Stream opaque legacy records straight to `w` in WAL order, returning the
/// count. Same filter as [`collect_opaque_records`] (known types skipped,
/// all other `t` tags preserved as trimmed line plus newline, blank lines
/// ignored), but memory stays bounded by one record: the caller never holds
/// the whole opaque prefix. A malformed middle record fails closed; a torn
/// tail is not delivered. Write failures surface as [`ReplayError::Open`]
/// so the caller fails the output instead of publishing partial bytes.
pub fn stream_opaque_records_to(
    path: &Path,
    w: &mut impl Write,
) -> Result<usize, ReplayError> {
    let mut count = 0usize;
    for_each_record(path, &mut |_, line| {
        let r: serde_json::Value =
            serde_json::from_str(line).expect("record validated by for_each_record");
        match r.get("t").and_then(|t| t.as_str()) {
            Some("post")
            | Some("topic_seq")
            | Some("claim_acquire")
            | Some("claim_release")
            | Some("kv")
            | Some("kv_del") => {}
            _ => {
                w.write_all(line.as_bytes()).map_err(ReplayError::Open)?;
                w.write_all(b"\n").map_err(ReplayError::Open)?;
                count += 1;
            }
        }
        Ok(())
    })?;
    Ok(count)
}

/// Stream WAL records one at a time, calling `f` for each complete valid
/// record with its 1-based line number.
///
/// Corruption policy: only a torn tail is recoverable — final bytes that do
/// not form a complete record are reported via the returned [`Tail`] instead
/// of being delivered, because that record was never acked. Any other
/// invalid complete record fails closed instead of silently vanishing. A
/// read I/O error fails closed too: unreadable history must not look empty.
///
/// Memory is bounded by one record ([`MAX_RECORD_BYTES`]) plus the caller's
/// own retained state; the file itself is never loaded whole. Consumption
/// itself is bounded too: at most `limit + 1` bytes are ever buffered while
/// scanning for the next newline, so an oversize record is rejected without
/// first allocating the whole record.
fn for_each_record(
    path: &Path,
    f: &mut impl FnMut(u64, &str) -> Result<(), ReplayError>,
) -> Result<Tail, ReplayError> {
    for_each_record_limit(path, MAX_RECORD_BYTES, f)
}

/// Bounded-consumption variant of [`for_each_record`]: the scan buffer never
/// holds more than `limit + 1` bytes, and any record longer than `limit` is
/// rejected as corrupt at its 1-based line number. The public wrapper passes
/// [`MAX_RECORD_BYTES`]; tests pass a small limit to prove the bound without
/// allocating a huge record.
fn for_each_record_limit(
    path: &Path,
    limit: usize,
    f: &mut impl FnMut(u64, &str) -> Result<(), ReplayError>,
) -> Result<Tail, ReplayError> {
    use std::io::BufRead;
    let bound = limit.saturating_add(1);
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Tail::Clean),
        Err(e) => return Err(ReplayError::Open(e)),
    };
    let mut reader = std::io::BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();
    let mut lineno: u64 = 0;
    let mut consumed: u64 = 0; // bytes of completed lines (the tail starts here)
    let oversize = |line: u64| ReplayError::Corrupt {
        line,
        detail: format!("record exceeds {limit}-byte bound"),
    };
    loop {
        // Borrow the buffered chunk, copy out only what fits, then consume:
        // the buffer never exceeds `bound` bytes no matter how long the
        // underlying record is.
        enum Step {
            Eof,
            Line(Vec<u8>),
            NeedMore,
            Over { line: u64 },
        }
        // Scan the buffered chunk first (borrows `reader`), then copy out
        // only what fits and consume (a second short borrow): the scan
        // buffer never exceeds `bound` bytes.
        let step = {
            let (take, newline) = {
                let avail = reader.fill_buf().map_err(ReplayError::Open)?;
                if avail.is_empty() {
                    (0, None)
                } else {
                    (avail.len(), avail.iter().position(|&b| b == b'\n'))
                }
            };
            if take == 0 {
                Step::Eof
            } else if let Some(pos) = newline {
                let want = pos + 1;
                if buf.len() + want > bound {
                    Step::Over { line: lineno + 1 }
                } else {
                    let mut line = std::mem::take(&mut buf);
                    {
                        let avail = reader.fill_buf().map_err(ReplayError::Open)?;
                        line.extend_from_slice(&avail[..want]);
                    }
                    reader.consume(want);
                    Step::Line(line)
                }
            } else {
                let room = bound.saturating_sub(buf.len());
                if room == 0 {
                    Step::Over { line: lineno + 1 }
                } else {
                    let want = take.min(room);
                    {
                        let avail = reader.fill_buf().map_err(ReplayError::Open)?;
                        buf.extend_from_slice(&avail[..want]);
                    }
                    reader.consume(want);
                    if want < take {
                        // Cap reached with still more record bytes pending:
                        // the record provably exceeds the bound.
                        Step::Over { line: lineno + 1 }
                    } else {
                        Step::NeedMore
                    }
                }
            }
        };
        match step {
            Step::Eof => {
                if buf.is_empty() {
                    return Ok(Tail::Clean); // EOF on a newline boundary (or empty file)
                }
                lineno += 1;
                return finish_tail(&buf, consumed, lineno, f);
            }
            Step::NeedMore => continue,
            Step::Over { line } => return Err(oversize(line)),
            Step::Line(line) => {
                lineno += 1;
                consumed += line.len() as u64;
                // Strip the single trailing newline the scanner stopped at.
                let line_bytes = &line[..line.len() - 1];
                let text = std::str::from_utf8(line_bytes).map_err(|e| {
                    ReplayError::Corrupt {
                        line: lineno,
                        detail: format!("wal record is not valid UTF-8: {e}"),
                    }
                })?;
                let s = text.trim();
                if s.is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(s) {
                    Ok(_) => f(lineno, s)?,
                    Err(e) => {
                        return Err(ReplayError::Corrupt {
                            line: lineno,
                            detail: format!("invalid JSON record: {e}"),
                        });
                    }
                }
            }
        }
    }
}

/// Classify final bytes that end at EOF without a newline: a complete record
/// (valid JSON) replays but needs a newline before the next append; anything
/// else is a torn unacked write starting at `start`.
fn finish_tail(
    buf: &[u8],
    start: u64,
    lineno: u64,
    f: &mut impl FnMut(u64, &str) -> Result<(), ReplayError>,
) -> Result<Tail, ReplayError> {
    let text = match std::str::from_utf8(buf) {
        Ok(t) => t,
        Err(_) => return Ok(Tail::Torn { start }),
    };
    let s = text.trim();
    if s.is_empty() {
        return Ok(Tail::Clean);
    }
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(_) => {
            f(lineno, s)?;
            Ok(Tail::ValidUnterminated)
        }
        Err(_) => Ok(Tail::Torn { start }),
    }
}

/// Repair the WAL tail so the next append cannot concatenate onto partial
/// bytes: truncate a torn tail, or terminate a complete-but-unterminated
/// final record with a newline. The file is fsync-backed after either fix.
/// A missing file is a fresh start (`Clean`), never an error.
pub fn repair_tail(path: &Path) -> std::io::Result<TailRepair> {
    let tail = for_each_record(path, &mut |_, _| Ok(())).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("wal unreadable, refusing repair: {e}"))
    })?;
    match tail {
        Tail::Clean => Ok(TailRepair::Clean),
        Tail::ValidUnterminated => {
            let mut f = OpenOptions::new().append(true).open(path)?;
            f.write_all(b"\n")?;
            f.flush()?;
            f.sync_all()?;
            Ok(TailRepair::AppendedNewline)
        }
        Tail::Torn { start } => {
            let f = OpenOptions::new().write(true).open(path)?;
            f.set_len(start)?;
            f.sync_all()?;
            Ok(TailRepair::TruncatedTornTail { start })
        }
    }
}

/// Exclusive WAL writer ownership, established BEFORE repair/replay/append
/// so two broker processes can never share mutable WAL state.
///
/// Mechanism: a real OS advisory lease — `flock(LOCK_EX|LOCK_NB)` held on a
/// sibling `<wal>.lock` file for the guard's lifetime. The kernel releases
/// the lease when the holder's fd closes, including on process death, so a
/// SIGKILLed broker needs no reaper: the next starter acquires immediately.
/// A second opener fails closed with `AlreadyExists` instead of replaying
/// into a divergent copy. Separate `open()` descriptions conflict even
/// within one process, so an in-process second broker open is rejected
/// exactly like a cross-process one (in-process restart simulation is
/// therefore impossible; use real child-process restarts).
///
/// The lock file is never unlinked: its inode is stable across owners, so a
/// dead owner's late drop cannot remove a live successor's lock. A missing
/// WAL parent directory is created explicitly before locking — a broker that
/// cannot hold the lease fails here, never starts unprotected.
#[derive(Clone, Debug)]
pub struct WalLock {
    inner: std::sync::Arc<WalLockInner>,
}

#[derive(Debug)]
struct WalLockInner {
    lock_path: std::path::PathBuf,
    file: File,
}

impl WalLock {
    /// Sibling lock path this lease is held on (diagnostics/tests).
    pub fn path(&self) -> &Path {
        &self.inner.lock_path
    }
}

/// Sibling lock path for a WAL path (`<wal>.lock`, same directory).
pub fn lock_path_for(wal_path: &Path) -> std::path::PathBuf {
    let mut s = wal_path.as_os_str().to_owned();
    s.push(".lock");
    std::path::PathBuf::from(s)
}

// Minimal flock(2) binding without a new dependency: flock lives in the C
// library the binary already links, so a plain extern resolves.
mod flock {
    pub const LOCK_EX: std::os::raw::c_int = 2;
    pub const LOCK_NB: std::os::raw::c_int = 4;
    pub const LOCK_UN: std::os::raw::c_int = 8;
    extern "C" {
        pub fn flock(fd: std::os::raw::c_int, op: std::os::raw::c_int) -> std::os::raw::c_int;
    }
}

/// Acquire exclusive writer ownership of `wal_path`. See [`WalLock`].
///
/// Always returns `Some` on success: the parent directory is created
/// explicitly when missing, so there is no unprotected mode. (`Option` is
/// kept so the [`crate::wire::Server`] call site is unchanged.)
pub fn acquire_wal_lock(wal_path: &Path) -> std::io::Result<Option<WalLock>> {
    use std::os::unix::io::AsRawFd;
    let lock_path = lock_path_for(wal_path);
    if let Some(parent) = lock_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // Open (never truncate: the inode must stay stable across owners), then
    // take the kernel lease non-blocking. Each call opens independently, so
    // same-process second opens conflict like cross-process ones.
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)?;
    // SAFETY: flock on our own open fd with constant flags; only the return
    // value and errno are observed.
    let rc = unsafe { flock::flock(file.as_raw_fd(), flock::LOCK_EX | flock::LOCK_NB) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            // EWOULDBLOCK from LOCK_NB: another broker (possibly this
            // process) holds the lease.
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "wal {} locked by another broker process",
                    wal_path.display()
                ),
            ));
        }
        return Err(e);
    }
    Ok(Some(WalLock {
        inner: std::sync::Arc::new(WalLockInner { lock_path, file }),
    }))
}

impl Drop for WalLockInner {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // Release the kernel lease; the file itself is NEVER unlinked, so
        // this path cannot remove a successor's lock. (Close releases the
        // lease anyway; the explicit unlock keeps the semantics obvious.)
        unsafe {
            flock::flock(self.file.as_raw_fd(), flock::LOCK_UN);
        }
    }
}

/// Replay a WAL file into state. Returns (posts_restored, claim_records).
///
/// Fails closed on any unreadable or structurally invalid complete record;
/// only a missing file (fresh start) and a torn tail are tolerated.
/// Unknown record types (`art_own`, future kinds) are ignored so this
/// slice still starts on a legacy WAL; `kv`/`kv_del` records replay into
/// `state.kv` through the reviewed core (live puts, tombstone deletes,
/// expired-put suppression). KV counts are not returned; inspect
/// `state.kv` directly. A malformed KV record fails closed without
/// echoing the line (values may be sensitive).
pub fn replay(path: &Path, state: &mut BusState, now: f64) -> Result<(usize, usize), ReplayError> {
    let mut posts = 0;
    let mut claims = 0;
    for_each_record(path, &mut |lineno, line| {
        let r: serde_json::Value =
            serde_json::from_str(line).expect("record validated by for_each_record");
        let corrupt = |detail: String| ReplayError::Corrupt { line: lineno, detail };
        match r.get("t").and_then(|t| t.as_str()) {
            Some("post") => {
                let Some(topic) = r.get("topic").and_then(|t| t.as_str()) else {
                    return Err(corrupt("post record without topic".into()));
                };
                let Some(msg_v) = r.get("msg") else {
                    return Err(corrupt("post record without msg".into()));
                };
                // Validate every known post BEFORE expiry filtering: a
                // malformed expired record must fail, not vanish. Decode
                // first with a fixed safe reason (never the serde detail,
                // which echoes stored values); only then recover high-water
                // and filter valid expired payloads.
                if msg_v.get("seq").and_then(|s| s.as_u64()).is_none() {
                    return Err(corrupt("post msg without integer seq".into()));
                }
                let msg: Msg = match serde_json::from_value(msg_v.clone()) {
                    Ok(m) => m,
                    Err(_) => {
                        return Err(corrupt("post msg failed to decode".into()));
                    }
                };
                // Recover the high-water mark from the validated seq,
                // including from fully-expired prefixes.
                let t = state.topics.entry(topic.to_string()).or_default();
                t.seq = t.seq.max(msg.seq);
                if msg.exp.is_some_and(|e| now > e) {
                    return Ok(());
                }
                t.msgs.push(msg);
                // Incremental retention: replay memory stays bounded
                // by RETAIN_PER_TOPIC per topic even for a WAL with
                // millions of records for one topic.
                if t.msgs.len() > crate::history::RETAIN_PER_TOPIC {
                    let drop = t.msgs.len() - crate::history::RETAIN_PER_TOPIC;
                    t.msgs.drain(..drop);
                }
                posts += 1;
            }
            Some("topic_seq") => {
                let (Some(topic), Some(seq)) = (
                    r.get("topic").and_then(|t| t.as_str()),
                    r.get("seq").and_then(|s| s.as_u64()),
                ) else {
                    return Err(corrupt("topic_seq record without topic/seq".into()));
                };
                let t = state.topics.entry(topic.to_string()).or_default();
                t.seq = t.seq.max(seq);
            }
            Some("claim_acquire") => {
                // Strict replay: a structurally invalid claim record fails
                // closed like a malformed post does. Only the idempotency
                // metadata (`idem`, `ttl_ms`, `renew`) is optional; identity
                // and fencing fields must be present and non-empty.
                let (Some(resource), Some(owner), Some(token), Some(fencing), Some(acquired_at), Some(expires_at)) =
                    (
                        r.get("resource").and_then(|v| v.as_str()),
                        r.get("owner").and_then(|v| v.as_str()),
                        r.get("token").and_then(|v| v.as_str()),
                        r.get("fencing").and_then(|v| v.as_u64()),
                        r.get("acquired_at").and_then(|v| v.as_f64()),
                        r.get("expires_at").and_then(|v| v.as_f64()),
                    )
                else {
                    return Err(corrupt(
                        "claim_acquire record without resource/owner/token/fencing/acquired_at/expires_at".into(),
                    ));
                };
                if resource.is_empty() || owner.is_empty() || token.is_empty() {
                    return Err(corrupt("claim_acquire record with empty resource/owner/token".into()));
                }
                state.claims.apply(&WalClaim::Acquire {
                    resource: resource.into(),
                    owner: owner.into(),
                    token: token.into(),
                    fencing,
                    acquired_at,
                    expires_at,
                    idem: r.get("idem").and_then(|v| v.as_str()).map(str::to_string),
                    ttl_ms: r.get("ttl_ms").and_then(|v| v.as_u64()),
                    renew: r.get("renew").and_then(|v| v.as_bool()).unwrap_or(false),
                });
                claims += 1;
            }
            Some("claim_release") => {
                let (Some(resource), Some(fencing)) = (
                    r.get("resource").and_then(|v| v.as_str()),
                    r.get("fencing").and_then(|v| v.as_u64()),
                ) else {
                    return Err(corrupt("claim_release record without resource/fencing".into()));
                };
                if resource.is_empty() {
                    return Err(corrupt("claim_release record with empty resource".into()));
                }
                state.claims.apply(&WalClaim::Release { resource: resource.into(), fencing });
                claims += 1;
            }
            Some("kv") | Some("kv_del") => {
                // Reviewed core decides live/delete/tombstone; this layer
                // only upgrades its lenient skip into a fail-closed refusal
                // so a corrupt KV record can never silently vanish. The
                // diagnostic names the line, never the record bytes.
                match state.kv.replay_line(line, now) {
                    LineOutcome::PutApplied
                    | LineOutcome::DeleteApplied
                    | LineOutcome::ExpiredSuppressed
                    | LineOutcome::IgnoredBlank => {}
                    LineOutcome::SkippedMalformed => {
                        return Err(corrupt("malformed kv record".into()));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok((posts, claims))
}

/// Replay artifact quota usage from WAL `art_own` records (legacy
/// `broker.py:651-653`). Returns `agent -> bytes` sums (saturating on
/// overflow, so a huge WAL still starts with a conservative cap).
/// Missing file means fresh (empty); torn tail tolerated (like
/// [`replay`]); any other malformed complete record fails closed.
/// `art_own` records need `agent` (non-empty string) and `size`
/// (non-negative integer); `sha` is ignored for accounting (bytes
/// live in the artifact dir, not the WAL). Other `t` tags ignored.
/// The wire seeds its [`crate::artifacts::ArtifactStore`] from this
/// before serving; live charges append new `art_own` records.
pub fn replay_art_usage(path: &Path) -> Result<HashMap<String, u64>, ReplayError> {
    let mut usage: HashMap<String, u64> = HashMap::new();
    for_each_record(path, &mut |lineno, line| {
        let r: serde_json::Value =
            serde_json::from_str(line).expect("record validated by for_each_record");
        if r.get("t").and_then(|t| t.as_str()) != Some("art_own") {
            return Ok(());
        }
        let corrupt = |detail: String| ReplayError::Corrupt { line: lineno, detail };
        let agent = r.get("agent").and_then(|a| a.as_str()).ok_or_else(|| {
            corrupt("art_own record without agent".to_string())
        })?;
        if agent.is_empty() {
            return Err(corrupt("art_own record with empty agent".to_string()));
        }
        let size = r.get("size").and_then(|s| s.as_u64()).ok_or_else(|| {
            corrupt("art_own record without integer size".to_string())
        })?;
        let entry = usage.entry(agent.to_string()).or_insert(0);
        *entry = entry.saturating_add(size);
        Ok(())
    })?;
    Ok(usage)
}

/// Compact a WAL into canonical records.
///
/// Layout: opaque legacy records first (`art_own` and unknown kinds are
/// preserved verbatim so migration never drops stores this slice does not
/// serve), then one live `kv` put per live KV key (sorted, live-only at
/// `now`; expired puts and all `kv_del` tombstones are dropped because the
/// regenerated live set restores the same state), then one `topic_seq`
/// high-water mark per topic (even for empty topics), then retained posts,
/// then regenerated claim records. KV/post/claim interleaving has no replay
/// semantics (separate stores), so this fixed order is safe.
///
/// Claim output is bounded: one `claim_acquire` per idempotency receipt
/// (within the fail-closed bound, never the full record history). A receipt
/// whose lease is gone additionally gets a `claim_release` so replay
/// restores the retired state instead of resurrecting the lease; renewed
/// leases are written with their current live expiry. Live leases without a
/// receipt are written idem-less, and fencing-only resources are written as
/// a release carrying the fencing counter. The source WAL is read strictly:
/// an unfaithful read fails the compaction instead of rewriting history
/// from partial data. The temp file name is unique per process, and the
/// parent directory is fsync-backed after the rename (best effort on
/// platforms without directory fsync).
pub fn compact(path: &Path, state: &BusState, now: f64) -> std::io::Result<(u64, u64)> {
    let old = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let (tmp, mut f) = create_compact_tmp(path)?;
    let write_outcome: std::io::Result<()> = (|| {
        // Stream opaque legacy records straight to the temp file: the source
        // WAL is never held in memory whole, only one record at a time.
        // `kv`/`kv_del` are regenerated from live state below, never copied,
        // so expired puts and superseded tombstones do not accumulate.
        for_each_record(path, &mut |_, line| {
            let r: serde_json::Value = serde_json::from_str(line).expect("record validated by for_each_record");
            match r.get("t").and_then(|t| t.as_str()) {
                Some("post")
                | Some("topic_seq")
                | Some("claim_acquire")
                | Some("claim_release")
                | Some("kv")
                | Some("kv_del") => {}
                _ => {
                    // io::Error surfaces as ReplayError::Open: an unwritable
                    // temp file fails the compaction instead of partial output.
                    f.write_all(line.as_bytes()).map_err(ReplayError::Open)?;
                    f.write_all(b"\n").map_err(ReplayError::Open)?;
                }
            }
            Ok(())
        })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        write_canonical_kv(&mut f, &state.kv.snapshot(now))?;
        let mut topics: Vec<&String> = state.topics.keys().collect();
        topics.sort();
        for topic in topics {
            let t = &state.topics[topic];
            let mark = serde_json::json!({"t": "topic_seq", "topic": topic, "seq": t.seq});
            f.write_all(serde_json::to_vec(&mark).unwrap().as_slice())?;
            f.write_all(b"\n")?;
            for msg in &t.msgs {
                let rec = serde_json::json!({"t": "post", "topic": topic, "msg": msg});
                f.write_all(serde_json::to_vec(&rec).unwrap().as_slice())?;
                f.write_all(b"\n")?;
            }
        }
        write_canonical_claims(&mut f, &state.claims.snapshot(now))?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_outcome {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Fsync the parent directory entry, including "." for bare relative
    // paths (best effort: compact overwrites, so a missed fsync only
    // risks durability, never a half-published new path).
    let parent_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Ok(dir) = File::open(parent_dir) {
        let _ = dir.sync_all();
    }
    let new = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    Ok((old, new))
}

/// Regenerate one live `kv` put per key in `snap` (sorted, live-only).
///
/// Dropping expired puts and all deletes is safe: replay starts from empty,
/// so absent keys need no tombstone, and every live key is written with its
/// current value and expiry. Key order and Unicode escaping may differ from
/// the legacy writer (semantic compatibility only, never byte equality).
fn write_canonical_kv(f: &mut File, snap: &crate::kv::Snapshot) -> std::io::Result<()> {
    for (key, value) in &snap.kv {
        let rec = serde_json::json!({
            "t": crate::kv::RECORD_PUT,
            "key": key,
            "value": value,
            "exp": snap.exp.get(key),
        });
        f.write_all(serde_json::to_vec(&rec).unwrap().as_slice())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

/// Regenerate the minimal claim records that restore `snap` on replay.
fn write_canonical_claims(f: &mut File, snap: &crate::claims::ClaimSnapshot) -> std::io::Result<()> {
    use std::collections::{HashMap, HashSet};
    let live: HashMap<&str, _> =
        snap.live.iter().map(|(r, l)| (r.as_str(), l)).collect();
    let fencing: HashMap<&str, u64> =
        snap.fencing.iter().map(|(r, n)| (r.as_str(), *n)).collect();
    let mut covered: HashSet<(&str, &str)> = HashSet::new();
    let mut referenced: HashSet<&str> = HashSet::new();
    for (owner, resource, key, token, rec_fencing, acquired_at, receipt_exp, ttl_ms) in &snap.receipts {
        referenced.insert(resource.as_str());
        let live_match = live.get(resource.as_str()).filter(|l| l.token == *token);
        if let Some(l) = live_match {
            covered.insert((resource.as_str(), token.as_str()));
            write_acquire(f, resource, owner, token, l.fencing, *acquired_at, l.expires_at, Some(key.clone()), Some(*ttl_ms), false)?;
        } else {
            write_acquire(f, resource, owner, token, *rec_fencing, *acquired_at, *receipt_exp, Some(key.clone()), Some(*ttl_ms), false)?;
            let fence = fencing.get(resource.as_str()).copied().unwrap_or(*rec_fencing).max(*rec_fencing);
            let rel = serde_json::json!({"t": "claim_release", "resource": resource, "fencing": fence});
            f.write_all(serde_json::to_vec(&rel).unwrap().as_slice())?;
            f.write_all(b"\n")?;
        }
    }
    for (resource, lease) in &snap.live {
        if covered.contains(&(resource.as_str(), lease.token.as_str())) {
            continue;
        }
        referenced.insert(resource.as_str());
        write_acquire(f, resource, &lease.owner, &lease.token, lease.fencing, lease.acquired_at, lease.expires_at, None, None, false)?;
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

/// Create an exclusive private compaction temp in the WAL directory.
///
/// Uses `create_new` (never truncate) with mode `0600` from creation on
/// Unix, retrying on collision so a stale temp from a prior run is never
/// consumed. Returns the created path (the only temp the caller may remove)
/// and its open handle.
fn create_compact_tmp(path: &Path) -> std::io::Result<(PathBuf, File)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("wal");
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    for _ in 0..1000 {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let file = format!("{base}.compact.{}.{n}.tmp", std::process::id());
        let candidate = dir.map(|p| p.join(&file)).unwrap_or_else(|| PathBuf::from(&file));
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
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "compaction temp collision budget exhausted",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(id: &str, exp: Option<f64>) -> Msg {
        Msg { seq: 0, id: id.into(), sender: "a".into(), ts: 1.0, exp, payload: json!(id), corr_id: None, reply_to: None }
    }

    fn state_after_wal(path: &std::path::Path, now: f64) -> BusState {
        let mut s = BusState::new();
        replay(path, &mut s, now).expect("test WAL replays cleanly");
        s
    }

    fn waldir(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("agent-bus-wal-test-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p.join("wal.log")
    }

    #[test]
    fn ttl_restart_never_reuses_sequence() {
        // Retained seq1 + expired seq2 restores topic seq1... then the next
        // post must get seq3, never reuse seq2.
        let path = waldir("ttl-restart");
        let _ = std::fs::remove_file(&path);
        append_fsync(&path, &json!({"t":"post","topic":"b","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}})).unwrap();
        append_fsync(&path, &json!({"t":"post","topic":"b","msg":{"seq":2,"id":"b","sender":"a","ts":1.0,"exp":2.0,"payload":2}})).unwrap();
        let mut s = state_after_wal(&path, 100.0); // seq2 expired before restart
        assert_eq!(s.topics["b"].seq, 2); // high-water recovered from expired record
        assert_eq!(s.topics["b"].msgs.len(), 1);
        let next = s.post("b", msg("c", None));
        assert_eq!(next, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn total_expiry_restart_keeps_high_water() {
        let path = waldir("total-expiry");
        let _ = std::fs::remove_file(&path);
        for i in 1..=3u64 {
            append_fsync(&path, &json!({"t":"post","topic":"c","msg":{"seq":i,"id":i.to_string(),"sender":"a","ts":1.0,"exp":2.0,"payload":i}})).unwrap();
        }
        let mut s = state_after_wal(&path, 100.0);
        assert_eq!(s.topics["c"].seq, 3);
        assert!(s.topics["c"].msgs.is_empty());
        assert_eq!(s.post("c", msg("d", None)), 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ttl_compaction_preserves_high_water() {
        let path = waldir("ttl-compact");
        let _ = std::fs::remove_file(&path);
        let mut s = BusState::new();
        for i in 0..5 {
            let exp = if i < 3 { Some(2.0) } else { None };
            let seq = s.post("d", msg(&format!("m{i}"), exp));
            append_fsync(&path, &json!({"t":"post","topic":"d","msg":{"seq":seq,"id":format!("m{i}"),"sender":"a","ts":1.0,"exp":exp,"payload":i}})).unwrap();
        }
        s.topic("d").expire(100.0);
        compact(&path, &s, 100.0).unwrap();
        let mut s2 = state_after_wal(&path, 100.0);
        assert_eq!(s2.topics["d"].seq, 5);
        assert_eq!(s2.post("d", msg("new", None)), 6);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn claim_records_survive_compaction_and_restart() {
        use crate::claims::VecWal;
        let path = waldir("claim-restart");
        let _ = std::fs::remove_file(&path);
        let s = BusState::new();
        let mut w = VecWal::default();
        let lease = s.claims.acquire(&mut w, "alice", "repo/z.rs", 60_000, Some("k"), 50.0).unwrap();
        for rec in &w.records {
            let v = match rec {
                WalClaim::Acquire { resource, owner, token, fencing, acquired_at, expires_at, idem, ttl_ms, renew } => {
                    json!({"t":"claim_acquire","resource":resource,"owner":owner,"token":token,"fencing":fencing,"acquired_at":acquired_at,"expires_at":expires_at,"idem":idem,"ttl_ms":ttl_ms,"renew":renew})
                }
                WalClaim::Release { resource, fencing } => {
                    json!({"t":"claim_release","resource":resource,"fencing":fencing})
                }
            };
            append_fsync(&path, &v).unwrap();
        }
        // Honest restart path: replay the file into fresh state, compact
        // from the replayed state, then replay again.
        let s1 = state_after_wal(&path, 55.0);
        compact(&path, &s1, 55.0).unwrap();
        let s2 = state_after_wal(&path, 55.0);
        let live = s2.claims.status("repo/z.rs", 55.0).unwrap();
        assert_eq!(live.owner, "alice");
        assert_eq!(live.token, lease.token);
        assert_eq!(live.fencing, lease.fencing);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_a_fresh_start_not_an_error() {
        let path = waldir("missing").join("no-such-dir").join("wal.log");
        let mut s = BusState::new();
        let (posts, claims) = replay(&path, &mut s, 1.0).unwrap();
        assert_eq!((posts, claims), (0, 0));
        assert!(s.topics.is_empty());
    }

    #[test]
    fn corrupt_middle_record_fails_closed() {
        let path = waldir("corrupt-mid");
        let _ = std::fs::remove_file(&path);
        append_fsync(&path, &json!({"t":"post","topic":"e","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}})).unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        use std::io::Write as _;
        f.write_all(b"{not json}\n").unwrap();
        let mut s = BusState::new();
        let err = replay(&path, &mut s, 1.0).unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
        // Compaction must not rewrite history from an unfaithful read.
        assert!(compact(&path, &s, 1.0).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_post_record_fails_closed() {
        let path = waldir("corrupt-post");
        let _ = std::fs::remove_file(&path);
        append_fsync(&path, &json!({"t":"post","topic":"e"})).unwrap(); // no msg
        let mut s = BusState::new();
        assert!(replay(&path, &mut s, 1.0).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn torn_tail_is_tolerated_as_unacked() {
        use std::io::Write as _;
        let path = waldir("torn-tail");
        let _ = std::fs::remove_file(&path);
        append_fsync(&path, &json!({"t":"post","topic":"f","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}})).unwrap();
        // Simulate a crash mid-append: partial final line, no newline.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"t\":\"post\",\"topic\":\"f\",\"msg\":{\"seq\":2").unwrap();
        f.sync_all().unwrap();
        let s = state_after_wal(&path, 1.0);
        assert_eq!(s.topics["f"].seq, 1);
        assert_eq!(s.topics["f"].msgs.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn legacy_transitional_wal_replays_and_compacts() {
        // Hand-written fixture in the transitional broker's record shape
        // (data, not an executed oracle): kv/art records must be ignored by
        // replay yet preserved verbatim by compaction, and correlation
        // metadata must survive the round trip.
        use std::io::Write as _;
        let path = waldir("legacy");
        let _ = std::fs::remove_file(&path);
        let mut f = std::fs::create_dir_all(path.parent().unwrap())
            .and_then(|_| std::fs::File::create(&path))
            .unwrap();
        for line in [
            r#"{"t":"kv","key":"ctx.a","value":1,"exp":null}"#,
            r#"{"t":"post","topic":"board.build","msg":{"seq":1,"id":"m1","topic":"board.build","sender":"alice","ts":10.0,"exp":null,"corr_id":"c1","reply_to":null,"payload":{"n":1}}}"#,
            r#"{"t":"art_own","sha":"abc","agent":"alice","size":12}"#,
            r#"{"t":"topic_seq","topic":"board.build","seq":1}"#,
        ] {
            f.write_all(line.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        f.sync_all().unwrap();
        drop(f);
        let s = state_after_wal(&path, 20.0);
        assert_eq!(s.topics["board.build"].seq, 1);
        assert_eq!(s.topics["board.build"].msgs.len(), 1);
        assert_eq!(s.topics["board.build"].msgs[0].corr_id, Some(json!("c1")));
        compact(&path, &s, 20.0).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains(r#""t":"kv""#), "kv preserved: {raw}");
        assert!(raw.contains(r#""t":"art_own""#), "art_own preserved: {raw}");
        let s2 = state_after_wal(&path, 20.0);
        assert_eq!(s2.topics["board.build"].msgs[0].corr_id, Some(json!("c1")));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compaction_bounds_claim_records_and_keeps_retired_retired() {
        use crate::claims::VecWal;
        let path = waldir("claim-bound");
        let _ = std::fs::remove_file(&path);
        // Build a long record history: 30 renews + a release on one key.
        let live = BusState::new();
        let mut w = VecWal::default();
        let lease = live.claims.acquire(&mut w, "alice", "repo/q.rs", 60_000, Some("k"), 1.0).unwrap();
        for i in 0..30 {
            live.claims.renew(&mut w, "alice", "repo/q.rs", &lease.token, 60_000, 2.0 + i as f64).unwrap();
        }
        live.claims.release(&mut w, "alice", "repo/q.rs", &lease.token).unwrap();
        assert!(w.records.len() > 20);
        for rec in &w.records {
            let v = match rec {
                WalClaim::Acquire { resource, owner, token, fencing, acquired_at, expires_at, idem, ttl_ms, renew } => {
                    json!({"t":"claim_acquire","resource":resource,"owner":owner,"token":token,"fencing":fencing,"acquired_at":acquired_at,"expires_at":expires_at,"idem":idem,"ttl_ms":ttl_ms,"renew":renew})
                }
                WalClaim::Release { resource, fencing } => {
                    json!({"t":"claim_release","resource":resource,"fencing":fencing})
                }
            };
            append_fsync(&path, &v).unwrap();
        }
        let s1 = state_after_wal(&path, 500.0);
        compact(&path, &s1, 500.0).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let claim_lines = raw.lines().filter(|l| l.contains("claim_")).count();
        assert!(claim_lines <= 2, "bounded canonical claims, got {claim_lines}:\n{raw}");
        let s2 = state_after_wal(&path, 500.0);
        assert!(s2.claims.status("repo/q.rs", 500.0).is_none());
        // The retired key must not mint a new lease after compaction.
        let err = s2.claims.acquire(&mut VecWal::default(), "alice", "repo/q.rs", 60_000, Some("k"), 501.0).unwrap_err();
        assert!(err.retired, "{err:?}");
        // ...while a fresh key still acquires with monotonic fencing.
        let l2 = s2.claims.acquire(&mut VecWal::default(), "bob", "repo/q.rs", 60_000, None, 501.0).unwrap();
        assert!(l2.fencing > lease.fencing);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn repair_truncates_torn_tail_and_next_append_stays_clean() {
        use std::io::Write as _;
        let path = waldir("repair-torn");
        let _ = std::fs::remove_file(&path);
        append_fsync(&path, &json!({"t":"post","topic":"g","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}})).unwrap();
        let clean_len = std::fs::metadata(&path).unwrap().len();
        // Simulate a crash mid-append: partial final line, no newline.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"t\":\"post\",\"topic\":\"g\",\"msg\":{\"seq\":2").unwrap();
        f.sync_all().unwrap();
        drop(f);
        // Replay tolerates the torn tail, but the file is not append-safe yet.
        let s = state_after_wal(&path, 1.0);
        assert_eq!(s.topics["g"].seq, 1);
        assert!(matches!(repair_tail(&path).unwrap(), TailRepair::TruncatedTornTail { start } if start == clean_len));
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.ends_with(b"\n"));
        assert_eq!(raw.len() as u64, clean_len);
        // The next acknowledged record lands on a clean boundary.
        append_fsync(&path, &json!({"t":"post","topic":"g","msg":{"seq":2,"id":"b","sender":"a","ts":2.0,"exp":null,"payload":2}})).unwrap();
        let s2 = state_after_wal(&path, 2.0);
        assert_eq!(s2.topics["g"].seq, 2);
        assert_eq!(s2.topics["g"].msgs.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn repair_terminates_valid_unterminated_record() {
        use std::io::Write as _;
        let path = waldir("repair-unterminated");
        let _ = std::fs::remove_file(&path);
        // A complete record with no trailing newline (crash between the
        // record write and the newline write): it replays, but the next
        // append would concatenate onto it without a repair.
        let rec = json!({"t":"post","topic":"h","msg":{"seq":1,"id":"a","sender":"a","ts":1.0,"exp":null,"payload":1}});
        let bytes = serde_json::to_vec(&rec).unwrap();
        assert!(!bytes.ends_with(b"\n"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&bytes).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let s = state_after_wal(&path, 1.0);
        assert_eq!(s.topics["h"].seq, 1);
        assert_eq!(repair_tail(&path).unwrap(), TailRepair::AppendedNewline);
        assert_eq!(repair_tail(&path).unwrap(), TailRepair::Clean); // idempotent
        append_fsync(&path, &json!({"t":"post","topic":"h","msg":{"seq":2,"id":"b","sender":"a","ts":2.0,"exp":null,"payload":2}})).unwrap();
        let s2 = state_after_wal(&path, 2.0);
        assert_eq!(s2.topics["h"].seq, 2);
        assert_eq!(s2.topics["h"].msgs.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_claim_records_fail_closed() {
        let path = waldir("strict-claims");
        let _ = std::fs::remove_file(&path);
        // Missing token: structurally invalid, must fail like a bad post.
        append_fsync(&path, &json!({"t":"claim_acquire","resource":"repo/a.rs","owner":"alice","fencing":1,"acquired_at":1.0,"expires_at":60.0})).unwrap();
        let mut s = BusState::new();
        assert!(replay(&path, &mut s, 1.0).is_err());
        let _ = std::fs::remove_file(&path);
        // Empty resource: invalid, not silently skipped.
        append_fsync(&path, &json!({"t":"claim_acquire","resource":"","owner":"alice","token":"tok","fencing":1,"acquired_at":1.0,"expires_at":60.0})).unwrap();
        let mut s = BusState::new();
        assert!(replay(&path, &mut s, 1.0).is_err());
        let _ = std::fs::remove_file(&path);
        // Release without fencing: invalid.
        append_fsync(&path, &json!({"t":"claim_release","resource":"repo/a.rs"})).unwrap();
        let mut s = BusState::new();
        assert!(replay(&path, &mut s, 1.0).is_err());
        let _ = std::fs::remove_file(&path);
        // Optional idempotency metadata may be absent or null (compaction
        // writes explicit nulls for idem-less leases); replay accepts it.
        append_fsync(&path, &json!({"t":"claim_acquire","resource":"repo/a.rs","owner":"alice","token":"tok","fencing":1,"acquired_at":1.0,"expires_at":60.0,"idem":null,"ttl_ms":null})).unwrap();
        let mut s = BusState::new();
        let (_, nclaims) = replay(&path, &mut s, 1.0).expect("optional claim metadata replays");
        assert_eq!(nclaims, 1);
        assert!(s.claims.status("repo/a.rs", 1.0).is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn long_history_replays_with_incremental_retention() {
        // 2500 records for one topic: replay must restore the high-water
        // mark with only the newest RETAIN_PER_TOPIC payloads retained.
        use std::io::Write as _;
        let path = waldir("long-history");
        let _ = std::fs::remove_file(&path);
        let mut f = std::fs::File::create(&path).unwrap();
        for i in 1..=2500u64 {
            let rec = json!({"t":"post","topic":"big","msg":{"seq":i,"id":i.to_string(),"sender":"a","ts":1.0,"exp":null,"payload":i}});
            f.write_all(&serde_json::to_vec(&rec).unwrap()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        f.sync_all().unwrap();
        drop(f);
        let s = state_after_wal(&path, 2.0);
        assert_eq!(s.topics["big"].seq, 2500);
        assert_eq!(s.topics["big"].msgs.len(), crate::history::RETAIN_PER_TOPIC);
        assert_eq!(s.topics["big"].msgs.last().unwrap().seq, 2500);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bounded_consumption_rejects_oversize_at_right_line() {
        // Small-limit regression: an 8 KiB record scanned with a 64-byte
        // limit must fail at line 2 with the bound named — without ever
        // buffering the whole record (the scanner caps at limit + 1).
        // A full-limit scan then proves stream position stayed intact.
        use std::io::Write as _;
        let path = waldir("bounded-scan");
        let _ = std::fs::remove_file(&path);
        let mut f = std::fs::File::create(&path).unwrap();
        let small_a = json!({"t":"kv","key":"a","value":1});
        let big = "x".repeat(8192);
        let small_c = json!({"t":"kv","key":"c","value":3});
        for rec in [small_a.to_string(), format!("{{\"t\":\"kv\",\"key\":\"big\",\"value\":\"{big}\"}}"), small_c.to_string()] {
            f.write_all(rec.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        f.sync_all().unwrap();
        drop(f);
        let mut seen = Vec::new();
        let err = for_each_record_limit(&path, 64, &mut |n, line| {
            seen.push((n, line.to_string()));
            Ok(())
        })
        .unwrap_err();
        match err {
            ReplayError::Corrupt { line, detail } => {
                assert_eq!(line, 2, "oversize reported at its own line");
                assert!(detail.contains("64-byte bound"), "{detail}");
            }
            other => panic!("expected bounded Corrupt, got {other:?}"),
        }
        assert_eq!(seen.len(), 1, "line 1 delivered before the oversize line");
        assert_eq!(seen[0].0, 1);
        // Full-limit scan reads all three records in order: line numbers
        // and stream position were never disturbed by the bounded failure.
        let mut all = Vec::new();
        let tail = for_each_record_limit(&path, MAX_RECORD_BYTES, &mut |n, line| {
            all.push((n, line.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(tail, Tail::Clean);
        assert_eq!(all.len(), 3);
        assert_eq!((all[0].0, all[1].0, all[2].0), (1, 2, 3));
        assert!(all[1].1.contains("\"big\""));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wal_lease_second_owner_conflicts_same_process() {
        // Independent second opens conflict even in one process: separate
        // flock descriptions do not merge, so an in-process second broker
        // is rejected exactly like a cross-process one.
        let wal = waldir("lease-conflict");
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(lock_path_for(&wal));
        let first = acquire_wal_lock(&wal).unwrap().expect("first owner acquires");
        let err = acquire_wal_lock(&wal).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "{err}");
        drop(first);
        // Release is real: a later owner acquires cleanly after drop.
        let _again = acquire_wal_lock(&wal).unwrap().expect("re-acquire after drop");
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(lock_path_for(&wal));
    }

    #[test]
    fn wal_lease_missing_parent_created_explicitly() {
        // A missing WAL parent is created before locking: every running
        // broker holds the lease, never silently starts unprotected.
        let stem = waldir("lease-mkparent");
        let wal = stem.join("no-such-dir").join("wal.log");
        let _ = std::fs::remove_dir_all(stem.join("no-such-dir"));
        assert!(!wal.parent().unwrap().exists());
        let guard = acquire_wal_lock(&wal).unwrap().expect("lease held, not skipped");
        assert!(wal.parent().unwrap().is_dir(), "parent created explicitly");
        assert!(lock_path_for(&wal).exists());
        drop(guard);
        let _ = std::fs::remove_dir_all(stem.join("no-such-dir"));
    }

    #[test]
    fn wal_lease_inode_stable_never_unlinked() {
        // The lock inode is stable across owners and drops: there is no
        // unlink path, so a dead owner's late drop cannot remove a live
        // successor's lock.
        use std::os::unix::fs::MetadataExt;
        let wal = waldir("lease-inode");
        let _ = std::fs::remove_file(&wal);
        let lock = lock_path_for(&wal);
        let _ = std::fs::remove_file(&lock);
        let first = acquire_wal_lock(&wal).unwrap().expect("lock");
        let ino1 = std::fs::metadata(&lock).unwrap().ino();
        drop(first);
        let ino2 = std::fs::metadata(&lock).unwrap().ino();
        assert_eq!(ino1, ino2, "lock file survives drop with same inode");
        let second = acquire_wal_lock(&wal).unwrap().expect("replacement acquires");
        assert_eq!(std::fs::metadata(&lock).unwrap().ino(), ino1, "replacement reuses inode");
        drop(second);
        assert!(lock.exists(), "no drop path unlinks the lock");
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(&lock);
    }
}
