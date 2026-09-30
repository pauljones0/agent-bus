//! delivery-snapshot: owned-file create/verify checks.
//!
//! Tiny constructive tests only: small text/binary files plus one harmless
//! executable-bit fixture (never executed, only mode/bytes compared). Proves
//! copied byte/hash/mode equality, deterministic sorted manifest shape with
//! pinned SHA-256 vector and exact mode fields, verify success, accepted
//! spaces/Unicode/custom-manifest/CRLF usage, and existing-destination refusal
//! with pre-existing content unchanged. No races, stress, huge files, shell or
//! Python fixture execution, or live services.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn snapshot_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-bus-snapshot"))
}

fn tmpdir(name: &str) -> PathBuf {
    for _ in 0..1000 {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "agent-bus-r72-snap-{name}-{}-{n}",
            std::process::id()
        ));
        match std::fs::create_dir(&p) {
            Ok(()) => return p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create owned fixture directory: {e}"),
        }
    }
    panic!("cannot allocate a unique fixture directory");
}

struct OwnedFixture {
    path: PathBuf,
}

impl OwnedFixture {
    fn new(name: &str) -> (Self, PathBuf) {
        let p = tmpdir(name);
        (Self { path: p.clone() }, p)
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        let tmp = std::env::temp_dir();
        if !self.path.starts_with(&tmp) {
            return;
        }
        if let Some(name) = self.path.file_name().and_then(|s| s.to_str()) {
            if name.starts_with("agent-bus-r72-snap-") {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_snapshot(args: &[&str]) -> Run {
    let out = Command::new(snapshot_bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn owned snapshot binary");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[cfg(unix)]
fn mode_bits(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .unwrap_or_else(|e| panic!("stat '{}': {e}", p.display()))
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(p).unwrap().permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(p, perms).unwrap();
}

#[test]
fn create_copies_bytes_hash_mode_and_manifest_sorted() {
    let (_guard, root) = OwnedFixture::new("create");
    let src = root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::create_dir(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"hello snapshot\n").unwrap();
    std::fs::write(src.join("sub").join("b.bin"), [0u8, 1, 2, 3, 255, 254]).unwrap();
    let exe = src.join("run-fixture");
    std::fs::write(&exe, b"#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        set_mode(&src.join("a.txt"), 0o644);
        set_mode(&src.join("sub").join("b.bin"), 0o644);
        set_mode(&exe, 0o755);
    }
    // Unsorted input order proves manifest sorts deterministically.
    let list = root.join("list.txt");
    std::fs::write(&list, b"sub/b.bin\nrun-fixture\na.txt\n").unwrap();
    let dest = root.join("snap");
    let r = run_snapshot(&[
        "create",
        "--source-root",
        src.to_str().unwrap(),
        "--file-list",
        list.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "create failed: stdout={} stderr={}", r.stdout, r.stderr);
    // Byte equality.
    assert_eq!(
        std::fs::read(dest.join("a.txt")).unwrap(),
        b"hello snapshot\n"
    );
    assert_eq!(
        std::fs::read(dest.join("sub").join("b.bin")).unwrap(),
        vec![0u8, 1, 2, 3, 255, 254]
    );
    assert_eq!(
        std::fs::read(dest.join("run-fixture")).unwrap(),
        b"#!/bin/sh\nexit 0\n"
    );
    // Mode equality (executable bit preserved, non-exec stays non-exec).
    #[cfg(unix)]
    {
        assert_eq!(mode_bits(&dest.join("a.txt")), 0o644);
        assert_eq!(mode_bits(&dest.join("run-fixture")), 0o755);
        assert_eq!(
            mode_bits(&dest.join("run-fixture")),
            mode_bits(&exe),
            "exec mode must match source"
        );
    }
    // Manifest shape: versioned, sorted, counts/totals, hash and mode equality.
    let mraw = std::fs::read(dest.join("snapshot-manifest.json")).unwrap();
    let mtext = String::from_utf8(mraw.clone()).unwrap();
    assert!(mtext.ends_with('\n'), "manifest ends with newline");
    let v: serde_json::Value = serde_json::from_str(&mtext).unwrap();
    assert_eq!(v["version"], serde_json::json!(1));
    assert_eq!(v["file_count"], serde_json::json!(3));
    assert_eq!(v["total_bytes"], serde_json::json!(38));
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    let paths: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
    assert_eq!(paths, vec!["a.txt", "run-fixture", "sub/b.bin"]);
    let mut total = 0u64;
    for f in files {
        let p = f["path"].as_str().unwrap();
        let len = f["len"].as_u64().unwrap();
        let sha = f["sha256"].as_str().unwrap();
        let mode = f["mode"].as_u64().unwrap();
        let disk = std::fs::read(dest.join(p)).unwrap();
        assert_eq!(disk.len() as u64, len, "len for {p}");
        assert_eq!(agent_bus::artifacts::sha256_hex(&disk), sha, "hash for {p}");
        assert_eq!(sha.len(), 64);
        #[cfg(unix)]
        {
            let expected = match p {
                "a.txt" => 0o644,
                "sub/b.bin" => 0o644,
                "run-fixture" => 0o755,
                _ => panic!("unexpected path {p}"),
            };
            assert_eq!(mode, expected, "mode for {p}");
            assert_eq!(mode_bits(&dest.join(p)), expected as u32, "disk mode for {p}");
        }
        #[cfg(not(unix))]
        {
            assert_eq!(mode, 0, "mode for {p}");
        }
        total += len;
    }
    assert_eq!(v["total_bytes"].as_u64().unwrap(), total);
    assert_eq!(total, 38);
    // Deterministic: reversed input order yields byte-identical manifest.
    let list2 = root.join("list2.txt");
    std::fs::write(&list2, b"a.txt\nrun-fixture\nsub/b.bin\n").unwrap();
    let dest2 = root.join("snap2");
    let r2 = run_snapshot(&[
        "create",
        "--source-root",
        src.to_str().unwrap(),
        "--file-list",
        list2.to_str().unwrap(),
        "--dest",
        dest2.to_str().unwrap(),
    ]);
    assert_eq!(r2.code, 0, "second create failed: {}", r2.stderr);
    let mraw2 = std::fs::read(dest2.join("snapshot-manifest.json")).unwrap();
    assert_eq!(mraw, mraw2, "manifest must be byte-identical across input orders");
}

#[test]
fn manifest_pins_known_vector_and_exact_fields() {
    let (_guard, root) = OwnedFixture::new("pinned");
    let src = root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("abc.txt"), b"abc").unwrap();
    #[cfg(unix)]
    {
        set_mode(&src.join("abc.txt"), 0o644);
    }
    let list = root.join("list.txt");
    std::fs::write(&list, b"abc.txt\n").unwrap();
    let dest = root.join("snap");
    let r = run_snapshot(&[
        "create",
        "--source-root",
        src.to_str().unwrap(),
        "--file-list",
        list.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "create failed: {}", r.stderr);
    let mraw = std::fs::read(dest.join("snapshot-manifest.json")).unwrap();
    let mtext = String::from_utf8(mraw).unwrap();
    assert!(mtext.ends_with('\n'), "manifest ends with newline");
    let v: serde_json::Value = serde_json::from_str(&mtext).unwrap();
    assert_eq!(v["version"], serde_json::json!(1));
    assert_eq!(v["file_count"], serde_json::json!(1));
    assert_eq!(v["total_bytes"], serde_json::json!(3));
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    let f = &files[0];
    assert_eq!(f["path"], serde_json::json!("abc.txt"));
    assert_eq!(f["len"], serde_json::json!(3));
    assert_eq!(f["sha256"], serde_json::json!(ABC_SHA256));
    #[cfg(unix)]
    {
        assert_eq!(f["mode"], serde_json::json!(0o644));
        assert_eq!(mode_bits(&dest.join("abc.txt")), 0o644);
    }
    #[cfg(not(unix))]
    {
        assert_eq!(f["mode"], serde_json::json!(0));
    }
    let vrf = run_snapshot(&["verify", "--snapshot-root", dest.to_str().unwrap()]);
    assert_eq!(vrf.code, 0, "verify failed: stdout={} stderr={}", vrf.stdout, vrf.stderr);
}

#[test]
fn create_accepts_spaces_unicode_custom_manifest_crlf() {
    let (_guard, root) = OwnedFixture::new("accepted");
    let src = root.join("src");
    std::fs::create_dir(&src).unwrap();
    let spaced = src.join("sp ace.txt");
    let uni = src.join("ünicode.txt");
    std::fs::write(&spaced, b"spaced\n").unwrap();
    std::fs::write(&uni, b"unicode\n").unwrap();
    #[cfg(unix)]
    {
        set_mode(&spaced, 0o644);
        set_mode(&uni, 0o644);
    }
    let list = root.join("list.txt");
    std::fs::write(&list, "sp ace.txt\r\nünicode.txt\r\n".as_bytes()).unwrap();
    let dest = root.join("snap");
    let r = run_snapshot(&[
        "create",
        "--source-root",
        src.to_str().unwrap(),
        "--file-list",
        list.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
        "--manifest=custom-manifest.json",
        "--",
    ]);
    assert_eq!(r.code, 0, "create failed: stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(std::fs::read(dest.join("sp ace.txt")).unwrap(), b"spaced\n");
    assert_eq!(std::fs::read(dest.join("ünicode.txt")).unwrap(), b"unicode\n");
    assert!(
        dest.join("custom-manifest.json").exists(),
        "custom manifest must exist"
    );
    assert!(
        !dest.join("snapshot-manifest.json").exists(),
        "default manifest must not exist when custom is used"
    );
    let mraw = std::fs::read(dest.join("custom-manifest.json")).unwrap();
    let mtext = String::from_utf8(mraw).unwrap();
    assert!(mtext.ends_with('\n'));
    let v: serde_json::Value = serde_json::from_str(&mtext).unwrap();
    assert_eq!(v["version"], serde_json::json!(1));
    assert_eq!(v["file_count"], serde_json::json!(2));
    assert_eq!(v["total_bytes"], serde_json::json!(15));
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    #[cfg(unix)]
    {
        for f in files {
            assert_eq!(f["mode"], serde_json::json!(0o644));
        }
    }
    let vrf = run_snapshot(&[
        "verify",
        "--snapshot-root",
        dest.to_str().unwrap(),
        "--manifest=custom-manifest.json",
    ]);
    assert_eq!(vrf.code, 0, "verify failed: stdout={} stderr={}", vrf.stdout, vrf.stderr);
}

#[test]
fn verify_success_on_owned_snapshot() {
    let (_guard, root) = OwnedFixture::new("verify");
    let src = root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("only.txt"), b"verify me\n").unwrap();
    let list = root.join("list.txt");
    std::fs::write(&list, b"only.txt\n").unwrap();
    let dest = root.join("snap");
    let r = run_snapshot(&[
        "create",
        "--source-root",
        src.to_str().unwrap(),
        "--file-list",
        list.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "create failed: {}", r.stderr);
    let v = run_snapshot(&["verify", "--snapshot-root", dest.to_str().unwrap()]);
    assert_eq!(v.code, 0, "verify failed: stdout={} stderr={}", v.stdout, v.stderr);
    assert!(v.stdout.contains("verified"), "stdout={}", v.stdout);
}

#[test]
fn existing_destination_refused_with_content_unchanged() {
    let (_guard, root) = OwnedFixture::new("refuse");
    let src = root.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("new.txt"), b"new bytes\n").unwrap();
    let list = root.join("list.txt");
    std::fs::write(&list, b"new.txt\n").unwrap();
    let dest = root.join("snap");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("keep.txt"), b"original\n").unwrap();
    let before = std::fs::read(dest.join("keep.txt")).unwrap();
    let r = run_snapshot(&[
        "create",
        "--source-root",
        src.to_str().unwrap(),
        "--file-list",
        list.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1, "must refuse existing dest with exit 1, got {} stderr={}", r.code, r.stderr);
    assert!(
        r.stderr.contains("exists") || r.stderr.contains("refus"),
        "stderr={}",
        r.stderr
    );
    // Pre-existing content unchanged, no snapshot files added.
    assert_eq!(std::fs::read(dest.join("keep.txt")).unwrap(), before);
    assert!(
        !dest.join("snapshot-manifest.json").exists(),
        "must not write manifest into existing dest"
    );
    assert!(!dest.join("new.txt").exists(), "must not copy into existing dest");
    // No owned staging sibling left behind (dest-exists fails before staging).
    let parent = dest.parent().unwrap();
    for entry in std::fs::read_dir(parent).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(
            !name.starts_with("snap.staging."),
            "staging leak: {name}"
        );
    }
}
