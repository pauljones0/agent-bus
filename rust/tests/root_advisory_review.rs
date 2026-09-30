//! Ordinary public reducer contracts; no live broker or target execution.
use agent_bus::advisory::{packet_state, short_packets};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn frame(seq: u64, payload: Value) -> Value {
    json!({"msg":{"id":format!("root-{seq}"),"seq":seq,"ts":seq,"sender":"worker","topic":"board.announce","payload":payload}})
}

fn names(text: &str) -> BTreeSet<String> {
    packet_state(&[frame(1, json!(text))], false).open.into_keys().collect()
}

#[test]
fn ordinary_packet_punctuation_and_unicode_names_remain_whole() {
    for (text, expected) in [
        ("[claim] packet=PLAN-A", vec!["PLAN-A"]),
        ("[claim] packet #A.2 + B_3", vec!["A.2", "B_3"]),
        ("[claim] packet: #Δ4 + 模块", vec!["Δ4", "模块"]),
        ("[claim] packet=A + by=worker", vec!["A"]),
        ("[claim] packet=#B note=ready", vec!["B"]),
    ] {
        assert_eq!(names(text), expected.into_iter().map(str::to_string).collect(), "{text}");
    }
}

#[test]
fn metadata_fields_never_turn_into_shorter_packet_names() {
    for text in ["[claim] packet=by=worker", "[claim] packet=#by = worker", "[claim] packet=Δ4=worker"] {
        let state = packet_state(&[frame(1, json!(text))], false);
        assert!(state.open.is_empty(), "{text}");
        assert_eq!(state.unparsed.len(), 1, "{text}");
    }
    assert_eq!(names("[claim] packet=by=worker; packet=A"), BTreeSet::from(["A".to_string()]));
}

#[test]
fn completed_and_ready_packets_keep_their_public_states() {
    let state = packet_state(&[
        frame(1, json!("[packet-ready] packet=A")),
        frame(2, json!("[packet-ready] #B")),
        frame(3, json!({"event":"claim","packet":"#A"})),
        frame(4, json!("[done] packet=A")),
    ], true);
    assert!(state.open.is_empty());
    assert_eq!(state.ready, ["B"]);
    assert_eq!(state.done, ["A"]);
    assert!(state.unparsed.is_empty());
    assert_eq!(short_packets(&state), "(no open packet claims)\nready unclaimed: B\ndone in window: A");
}
