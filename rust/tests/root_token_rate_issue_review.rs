//! New token policies preserve the caller's first-match topic rule order.
//! Private broker, disposable credentials, native CLI and direct JSON wire.
use agent_bus::acl::TokenStore;
use agent_bus::wire::Server;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ADMIN: &str = r#"{"review-admin":{"agent":"*","publish":["*"],"subscribe":["*"]}}"#;

fn private_broker() -> (PathBuf, std::net::SocketAddr) {
    let path = std::env::temp_dir().join(format!(
        "cc-new-token-rate-order-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    let tokens = path.join("tokens.json");
    std::fs::write(&tokens, ADMIN).unwrap();
    let server = Server::new(
        path.join("wal.log"),
        TokenStore::from_json_str(ADMIN).unwrap(),
    )
    .unwrap()
    .with_tokens_path(tokens.clone());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || server.serve(listener));
    (tokens, address)
}

fn assert_specific_rule_first(tokens: &std::path::Path, reply: &Value) {
    assert_eq!(reply["ok"], true, "issue failed");
    let token = reply["token"].as_str().unwrap();
    let text = std::fs::read_to_string(tokens).unwrap();
    let store = TokenStore::from_json_str(&text).unwrap();
    let config = store.get(token).unwrap().rate_config();
    let patterns: Vec<_> = config
        .rules
        .iter()
        .map(|r| r.pattern_raw.as_str())
        .collect();
    assert_eq!(patterns, ["data.build", "data.*"], "new policy reordered");
    assert_eq!(config.select("data.build"), Some(("data.build", 10.0)));
    assert_eq!(config.select("data.other"), Some(("data.*", 1.0)));
}

#[test]
fn cli_new_token_keeps_repeated_topic_rate_flag_order() {
    let (tokens, address) = private_broker();
    let out = Command::new(env!("CARGO_BIN_EXE_agent-bus"))
        .env_clear()
        .env("PATH", "")
        .env("AGENT_BUS_HOST", "127.0.0.1")
        .env("AGENT_BUS_PORT", address.port().to_string())
        .env("AGENT_BUS_AGENT", "review")
        .env("AGENT_BUS_TOKEN", "review-admin")
        .args([
            "token-issue",
            "new-worker",
            "--topic-rate",
            "data.build=10",
            "--topic-rate",
            "data.*=1",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_specific_rule_first(&tokens, &reply);
}

fn rpc(reader: &mut BufReader<TcpStream>, line: &str, req_id: u64) -> Value {
    writeln!(reader.get_mut(), "{line}").unwrap();
    reader.get_mut().flush().unwrap();
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    let reply: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(reply["req_id"], json!(req_id));
    reply
}

#[test]
fn wire_new_token_keeps_serialized_topic_rate_order() {
    let (tokens, address) = private_broker();
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let hello = rpc(
        &mut reader,
        r#"{"op":"hello","agent":"review","token":"review-admin","req_id":1}"#,
        1,
    );
    assert_eq!(hello["ok"], true);
    // Deliberately send literal JSON: converting through an unordered map
    // in the test would erase the contract before it reaches the product.
    let reply = rpc(
        &mut reader,
        r#"{"op":"token_issue","agent":"new-worker","topic_rates":{"data.build":10,"data.*":1},"req_id":2}"#,
        2,
    );
    assert_specific_rule_first(&tokens, &reply);
}
