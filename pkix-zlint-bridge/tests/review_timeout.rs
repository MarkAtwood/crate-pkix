//! Review regression test: BridgeConfig::timeout must bound the call.
//!
//! The fake "zlint" is a shell script generated at test time under
//! CARGO_TARGET_TMPDIR. It backgrounds a long-lived grandchild that
//! inherits stdout/stderr, then exits immediately. `run_subprocess`
//! sees the direct child exit, then blocks in `join()` on the reader
//! threads until the grandchild closes the pipes, so the configured
//! timeout is never applied. (Wrapper scripts, e.g. `docker run` or
//! `go run` shims around zlint, have exactly this shape.)
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::time::{Duration, Instant};

use pkix_zlint_bridge::{BridgeConfig, BridgeError, ZlintBridge};

/// Write an executable fake-zlint shell script under CARGO_TARGET_TMPDIR.
fn fake_zlint(name: &str, body: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("review-zlint-bridge");
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join(name);
    std::fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[test]
fn timeout_bounds_call_when_grandchild_holds_pipes() {
    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = fake_zlint("fake-zlint-forks.sh", "sleep 6 &\nexit 0\n");
    cfg.timeout = Duration::from_millis(500);
    let bridge = ZlintBridge::new(cfg).unwrap();

    let start = Instant::now();
    let r = bridge.enumerate_lints();
    let elapsed = start.elapsed();
    assert!(r.is_err());
    assert!(
        elapsed < Duration::from_secs(3),
        "configured 500ms timeout, but enumerate_lints took {elapsed:?} ({r:?})"
    );
}

/// On timeout the bridge kills the child's whole process group, so a
/// backgrounded grandchild does not outlive the call.
#[test]
fn timeout_kills_grandchildren() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("review-zlint-bridge");
    std::fs::create_dir_all(&dir).unwrap();
    let pidfile = dir.join("grandchild.pid");
    let _ = std::fs::remove_file(&pidfile);
    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = fake_zlint(
        "fake-zlint-hangs.sh",
        &format!("sleep 30 &\necho $! > '{}'\nsleep 30\n", pidfile.display()),
    );
    cfg.timeout = Duration::from_millis(500);
    let bridge = ZlintBridge::new(cfg).unwrap();

    let start = Instant::now();
    let r = bridge.enumerate_lints();
    assert!(
        matches!(r, Err(BridgeError::SubprocessTimeout { .. })),
        "got {r:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(3));

    let pid = std::fs::read_to_string(&pidfile).unwrap();
    let pid = pid.trim();
    // `kill -0` succeeds iff the process still exists. Allow a moment
    // for the kernel to finish tearing it down.
    let mut alive = true;
    for _ in 0..50 {
        alive = std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive, "grandchild {pid} survived the timeout kill");
}

/// Unbounded output is capped: a child that never stops writing fails
/// fast with OutputTooLarge instead of buffering until the timeout.
#[test]
fn stdout_over_cap_is_output_too_large() {
    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = fake_zlint("fake-zlint-yes.sh", "exec yes\n");
    cfg.timeout = Duration::from_secs(20);
    cfg.max_output_bytes = 64 * 1024;
    let bridge = ZlintBridge::new(cfg).unwrap();

    let start = Instant::now();
    let r = bridge.enumerate_lints();
    assert_eq!(r, Err(BridgeError::OutputTooLarge { limit: 64 * 1024 }));
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

/// Output at or under the cap still parses normally (the cap is
/// inclusive), including on stderr.
#[test]
fn output_within_cap_still_parses() {
    let line = r#"{"name":"e_review_check","description":"d","citation":"c","source":"s"}"#;
    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = fake_zlint(
        "fake-zlint-ok.sh",
        &format!("printf '%s\\n' '{line}'\necho warning >&2\n"),
    );
    cfg.max_output_bytes = line.len() + 1; // exactly the stdout size
    let bridge = ZlintBridge::new(cfg).unwrap();
    let lints = bridge.enumerate_lints().expect("within cap");
    assert_eq!(lints.len(), 1);
    assert_eq!(lints[0].check_id, "e_review_check");
}
