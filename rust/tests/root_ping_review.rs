//! Independent native CLI health-reply contracts on ephemeral loopback sockets.
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

fn ping_reply(reply: Value) -> std::process::Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        for mut response in [json!({"ok":true,"agent":"review"}), reply] {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            let request: Value = serde_json::from_str(&line).unwrap();
            response["req_id"] = request["req_id"].clone();
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();
        }
    });
    let output = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .arg("ping")
        .env_remove("AGENT_BUS_SOCK")
        .env("AGENT_BUS_HOST", "127.0.0.1")
        .env("AGENT_BUS_PORT", address.port().to_string())
        .env("AGENT_BUS_AGENT", "review")
        .env("AGENT_BUS_TOKEN", "ephemeral-review-fixture")
        .output()
        .unwrap();
    peer.join().unwrap();
    output
}

#[test]
fn authenticated_ping_refuses_missing_false_or_malformed_authentication() {
    for reply in [
        json!({"ok":true,"server_ts":1234.0}),
        json!({"ok":true,"authed":false,"server_ts":1234.0}),
        json!({"ok":true,"authed":"true","server_ts":1234.0}),
    ] {
        let output = ping_reply(reply.clone());
        assert_eq!(
            output.status.code(),
            Some(1),
            "authenticated health check accepted contradictory reply {reply}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn present_ping_timestamp_must_be_a_finite_number() {
    for timestamp in [Value::Null, json!("later"), json!({"time":1234})] {
        let output = ping_reply(json!({"ok":true,"authed":true,"server_ts":timestamp}));
        assert_eq!(
            output.status.code(),
            Some(1),
            "malformed health timestamp was accepted: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn authenticated_ping_accepts_current_and_documented_older_reply_shapes() {
    for reply in [
        json!({"ok":true,"authed":true,"server_ts":1234.0}),
        json!({"ok":true,"authed":true}),
    ] {
        let output = ping_reply(reply);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
