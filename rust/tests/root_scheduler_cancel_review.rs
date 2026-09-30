//! Native handshake cancellation on a private, owned loopback peer.
use agent_bus::scheduler::status::{NativeStatusTransport, StatusTransport};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[test]
fn cancellation_during_hello_does_not_start_a_status_mutation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let peer_cancel = Arc::clone(&cancel);
    let peer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("private peer accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let hello: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(hello["op"], "hello", "handshake precondition");
        peer_cancel.store(true, Ordering::SeqCst);
        writeln!(
            reader.get_mut(),
            "{}",
            json!({"ok":true,"req_id":hello["req_id"]})
        )
        .unwrap();
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => {
                let request: Value = serde_json::from_str(&line).unwrap();
                writeln!(
                    reader.get_mut(),
                    "{}",
                    json!({"ok":true,"req_id":request["req_id"]})
                )
                .unwrap();
                Some(request)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                None
            }
            Err(e) => panic!("private peer read: {e}"),
        }
    });
    let mut transport = NativeStatusTransport::new(
        &address.to_string(),
        "root-fixture",
        "synthetic-fixture-token",
    );
    let result = transport.put(
        "ctx.sched.fixture.agent.run",
        json!({"phase":"active"}),
        1000,
        &cancel,
    );
    drop(transport);
    let mutation = peer.join().unwrap();
    assert!(
        cancel.load(Ordering::SeqCst),
        "peer must actually cancel during hello"
    );
    assert!(
        mutation.is_none(),
        "cancelled active update started a fresh mutation: {mutation:?}; result={result:?}"
    );
    assert!(result.is_err(), "cancelled put cannot report success");
}
