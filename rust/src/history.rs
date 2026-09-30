//! Durable exact-topic history with explicit retention-gap cursors.
//!
//! Mirrors the reviewed broker semantics:
//! - Per-topic sequence high-water marks outlive payload expiry/retention.
//! - A page cursor advances only through actually delivered messages
//!   (`next_seq` = last delivered seq when truncated, else snapshot).
//! - Missing ranges are explicit; a cursor older than the retained prefix
//!   reports a gap instead of silent success.

use serde::{Deserialize, Serialize};

pub const HISTORY_PAGE_LIMIT: usize = 1000;
pub const RETAIN_PER_TOPIC: usize = 1000;
/// Maximum compact-JSON bytes per history page (mirrors the Python broker).
pub const HISTORY_PAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Msg {
    pub seq: u64,
    pub id: String,
    pub sender: String,
    pub ts: f64,
    /// Absolute expiry unix time, or None for retained.
    pub exp: Option<f64>,
    pub payload: serde_json::Value,
    /// Correlation metadata carried by the transitional broker; preserved
    /// through compaction so a migration never drops request tracking.
    #[serde(default)]
    pub corr_id: Option<serde_json::Value>,
    #[serde(default)]
    pub reply_to: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default)]
pub struct Topic {
    /// Sequence high-water mark; never decreases, even when payloads expire.
    pub seq: u64,
    /// Retained payloads in seq order (at most RETAIN_PER_TOPIC).
    pub msgs: Vec<Msg>,
}

impl Topic {
    /// Append a message, assigning the next sequence number.
    pub fn post(&mut self, msg: Msg) -> u64 {
        self.post_stored(msg).seq
    }

    /// Append a message and return the stored copy with its sequence number,
    /// so the WAL record carries the same identity as memory.
    pub fn post_stored(&mut self, mut msg: Msg) -> Msg {
        self.seq += 1;
        msg.seq = self.seq;
        self.msgs.push(msg.clone());
        self.evict_overflow();
        msg
    }

    /// Reserve the next sequence number WITHOUT touching retained history.
    ///
    /// The caller must durably append the WAL record first, then either
    /// [`Topic::commit_reserved`] or [`Topic::rollback_reserved`]. Reserving
    /// never evicts, so a WAL failure at a full topic cannot lose the oldest
    /// retained message the way mutate-then-rollback would.
    pub fn reserve_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Commit a previously reserved sequence number: store the message and
    /// apply retention eviction. Only call after the record is durable.
    pub fn commit_reserved(&mut self, mut msg: Msg, seq: u64) -> Msg {
        debug_assert_eq!(seq, self.seq, "commit must follow its own reservation");
        msg.seq = seq;
        self.msgs.push(msg.clone());
        self.evict_overflow();
        msg
    }

    /// Roll back a reservation after a durable-append failure. Retained
    /// history is untouched: only the high-water mark steps back.
    pub fn rollback_reserved(&mut self, seq: u64) {
        if self.seq == seq {
            self.seq -= 1;
        }
    }

    fn evict_overflow(&mut self) {
        let over = self.msgs.len().saturating_sub(RETAIN_PER_TOPIC);
        if over > 0 {
            self.msgs.drain(..over);
        }
    }

    /// Drop expired payloads, preserving the high-water mark.
    pub fn expire(&mut self, now: f64) {
        self.msgs.retain(|m| m.exp.is_none_or(|e| now <= e));
    }

    /// Newest live message with this id, or `None` when absent/expired.
    ///
    /// Idempotency window helper: scans newest-first, skipping entries
    /// whose `exp` is past `now` (`now > exp`, matching fetch/expiry).
    /// Expired-only matches are outside the window (treated as not-found,
    /// never a fabricated receipt); evicted ids are absent by retention.
    /// Bounded by `RETAIN_PER_TOPIC`; no separate cache.
    pub fn find_live_by_id(&self, id: &str, now: f64) -> Option<&Msg> {
        self.msgs.iter().rev().find(|m| {
            m.id == id && m.exp.is_none_or(|e| now <= e)
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cursor {
    pub topic_seq: u64,
    pub snapshot_seq: u64,
    pub from_seq: u64,
    pub next_seq: u64,
    pub oldest_seq: u64,
    pub retained: u64,
    pub has_more: bool,
    pub gap: bool,
    pub missing: u64,
    pub missing_ranges: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page {
    pub topic: String,
    pub messages: Vec<Msg>,
    pub cursor: Cursor,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HistoryError {
    BadCursor(String),
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HistoryError::BadCursor(s) => write!(f, "{s}"),
        }
    }
}

/// One exact-topic snapshot page, independent of live subscriptions.
///
/// `until_seq` pins the snapshot across pages; pass `None` to snapshot at
/// head. The returned cursor covers only this page when truncated.
pub fn history_page(
    topic_name: &str,
    topic: &Topic,
    from_seq: u64,
    limit: usize,
    until_seq: Option<u64>,
    now: f64,
) -> Result<Page, HistoryError> {
    if !(1..=HISTORY_PAGE_LIMIT).contains(&limit) {
        return Err(HistoryError::BadCursor(format!(
            "limit must be between 1 and {HISTORY_PAGE_LIMIT}"
        )));
    }
    let head = topic.seq;
    let snapshot = until_seq.unwrap_or(head);
    if snapshot < from_seq || snapshot > head {
        return Err(HistoryError::BadCursor(
            "cursor or snapshot is ahead of topic head, or snapshot precedes cursor".into(),
        ));
    }
    let mut messages: Vec<Msg> = Vec::new();
    let mut more = false;
    let mut oldest = snapshot + 1;
    let mut retained: u64 = 0;
    let mut byte_count: usize = 0;
    for msg in &topic.msgs {
        if msg.seq > snapshot || msg.exp.is_some_and(|e| now > e) {
            continue;
        }
        oldest = oldest.min(msg.seq);
        retained += 1;
        if msg.seq <= from_seq || more {
            continue;
        }
        if messages.len() >= limit {
            more = true;
            continue;
        }
        let size = serde_json::to_vec(msg).map(|v| v.len()).unwrap_or(usize::MAX);
        if byte_count.saturating_add(size) > HISTORY_PAGE_BYTES {
            if messages.is_empty() {
                return Err(HistoryError::BadCursor(
                    "history message exceeds page byte limit; use exact-message retrieval".into(),
                ));
            }
            more = true;
            continue;
        }
        byte_count += size;
        messages.push(msg.clone());
    }
    // Cursor advances only through actually delivered frames, never
    // directly to the topic head when truncated.
    let next_seq = if more { messages.last().map(|m| m.seq).unwrap_or(from_seq) } else { snapshot };
    let mut expected = from_seq + 1;
    let mut gaps: Vec<(u64, u64)> = Vec::new();
    for msg in &messages {
        if msg.seq > expected {
            gaps.push((expected, msg.seq - 1));
        }
        expected = expected.max(msg.seq + 1);
    }
    if expected <= next_seq {
        gaps.push((expected, next_seq));
    }
    let missing: u64 = gaps.iter().map(|(a, b)| b - a + 1).sum();
    Ok(Page {
        topic: topic_name.to_string(),
        messages,
        cursor: Cursor {
            topic_seq: head,
            snapshot_seq: snapshot,
            from_seq,
            next_seq,
            oldest_seq: oldest,
            retained,
            has_more: more,
            gap: !gaps.is_empty(),
            missing,
            missing_ranges: gaps,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk(seq: u64, sender: &str) -> Msg {
        Msg { seq, id: format!("id{seq}"), sender: sender.into(), ts: 1.0, exp: None, payload: json!({"n": seq}), corr_id: None, reply_to: None }
    }

    pub(crate) fn blank_msg() -> Msg {
        Msg { seq: 0, id: String::new(), sender: "a".into(), ts: 1.0, exp: None, payload: json!(null), corr_id: None, reply_to: None }
    }

    fn topic_with(n: u64) -> Topic {
        let mut t = Topic::default();
        for _ in 0..n {
            t.post(blank_msg());
        }
        t
    }

    #[test]
    fn full_fetch_has_no_gap_and_snapshot_cursor() {
        let t = topic_with(5);
        let p = history_page("x", &t, 0, 500, None, 2.0).unwrap();
        assert_eq!(p.messages.len(), 5);
        assert!(!p.cursor.gap);
        assert!(!p.cursor.has_more);
        assert_eq!(p.cursor.next_seq, 5);
        assert_eq!(p.cursor.topic_seq, 5);
    }

    #[test]
    fn truncation_advances_only_through_delivered() {
        let t = topic_with(10);
        let p = history_page("x", &t, 0, 4, None, 2.0).unwrap();
        assert_eq!(p.messages.len(), 4);
        assert!(p.cursor.has_more);
        // Must be last delivered (4), never head (10).
        assert_eq!(p.cursor.next_seq, 4);
        // Resume from the page cursor with the pinned snapshot.
        let q = history_page("x", &t, p.cursor.next_seq, 500, Some(p.cursor.snapshot_seq), 2.0).unwrap();
        assert_eq!(q.messages.len(), 6);
        assert!(!q.cursor.has_more);
        assert_eq!(q.cursor.next_seq, 10);
    }

    #[test]
    fn expired_prefix_reports_gap_not_silent_success() {
        let mut t = Topic::default();
        for i in 0..4 {
            t.post(Msg { seq: 0, id: format!("id{i}"), sender: "a".into(), ts: 1.0, exp: Some(5.0), payload: json!(i), corr_id: None, reply_to: None });
        }
        t.post(Msg { seq: 0, id: "id4".into(), sender: "a".into(), ts: 6.0, exp: None, payload: json!(4), corr_id: None, reply_to: None });
        assert_eq!(t.seq, 5);
        let p = history_page("x", &t, 0, 500, None, 10.0).unwrap();
        assert_eq!(p.messages.len(), 1);
        assert!(p.cursor.gap);
        assert_eq!(p.cursor.missing_ranges, vec![(1, 4)]);
        assert_eq!(p.cursor.missing, 4);
    }

    #[test]
    fn cursor_ahead_of_head_is_an_error() {
        let t = topic_with(3);
        assert!(history_page("x", &t, 99, 10, None, 2.0).is_err());
        assert!(history_page("x", &t, 0, 10, Some(99), 2.0).is_err());
    }

    #[test]
    fn zero_replay_page_is_empty_without_consuming_live() {
        let t = topic_with(3);
        // from_seq == head: nothing new, cursor stays at snapshot.
        let p = history_page("x", &t, 3, 500, None, 2.0).unwrap();
        assert!(p.messages.is_empty());
        assert!(!p.cursor.has_more);
        assert_eq!(p.cursor.next_seq, 3);
    }

    #[test]
    fn expired_messages_are_skipped_but_keep_high_water() {
        let mut t = topic_with(3);
        t.expire(100.0); // no exp set; nothing dropped
        assert_eq!(t.msgs.len(), 3);
        t.msgs[0].exp = Some(1.0);
        t.expire(2.0);
        assert_eq!(t.msgs.len(), 2);
        assert_eq!(t.seq, 3); // high-water mark preserved
        let p = history_page("x", &t, 0, 500, None, 2.0).unwrap();
        assert!(p.cursor.gap);
        assert_eq!(p.cursor.missing_ranges, vec![(1, 1)]);
    }

    #[test]
    fn retained_cap_keeps_head_and_reports_retention_gap() {
        let mut t = Topic::default();
        for _ in 0..(RETAIN_PER_TOPIC as u64 + 5) {
            t.post(blank_msg());
        }
        assert_eq!(t.msgs.len(), RETAIN_PER_TOPIC);
        let head = t.seq;
        let p = history_page("x", &t, 0, RETAIN_PER_TOPIC, None, 2.0).unwrap();
        assert!(p.cursor.gap);
        assert_eq!(p.cursor.missing_ranges, vec![(1, head - RETAIN_PER_TOPIC as u64)]);
    }

    #[test]
    fn unused_msg_constructor_helper() {
        assert_eq!(mk(7, "s").seq, 7);
    }

    #[test]
    fn reserve_rollback_at_full_topic_loses_nothing() {
        // Fill the topic to its retention cap, then simulate a WAL-append
        // failure: reserve, then roll back. The old mutate-then-rollback
        // path evicted the oldest message before the failure; reserve must
        // leave retained history byte-identical.
        let mut t = Topic::default();
        for _ in 0..RETAIN_PER_TOPIC {
            t.post(blank_msg());
        }
        assert_eq!(t.msgs.len(), RETAIN_PER_TOPIC);
        let oldest = t.msgs[0].seq;
        let head = t.seq;
        let seq = t.reserve_seq();
        assert_eq!(seq, head + 1);
        assert_eq!(t.msgs.len(), RETAIN_PER_TOPIC); // reservation never evicts
        t.rollback_reserved(seq);
        assert_eq!(t.seq, head);
        assert_eq!(t.msgs.len(), RETAIN_PER_TOPIC);
        assert_eq!(t.msgs[0].seq, oldest);
        assert_eq!(t.msgs.last().unwrap().seq, head);
        // The commit path still evicts exactly one at capacity.
        let seq2 = t.reserve_seq();
        t.commit_reserved(blank_msg(), seq2);
        assert_eq!(t.msgs.len(), RETAIN_PER_TOPIC);
        assert_eq!(t.msgs[0].seq, oldest + 1);
        assert_eq!(t.seq, head + 1);
    }
}
