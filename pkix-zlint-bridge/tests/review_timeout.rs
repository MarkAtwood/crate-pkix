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

/// The single lint record `fake-zlint-ok.sh` emits on stdout.
///
/// Shared between [`SCRIPTS`], which bakes it into the script, and the test
/// that sizes its output cap to exactly this line plus a newline.
const OK_LINE: &str = r#"{"name":"e_review_check","description":"d","citation":"c","source":"s"}"#;

/// Every fake-zlint script, written once before any test spawns anything.
///
/// # Why this is a `LazyLock` and not a helper each test calls
///
/// These tests were flaky, failing perhaps one run in two with
/// `SubprocessFailed { stderr: "Text file busy (os error 26)" }` — `ETXTBSY`.
/// The cause is not this file truncating a script that is still running, which
/// was the first guess and is wrong. It is the long-standing interaction
/// between writing an executable and `fork` on Linux:
///
/// - the harness runs these four tests concurrently on separate threads;
/// - a thread writing a script holds a write file descriptor on it;
/// - another thread spawning a child `fork`s, and the child inherits a
///   duplicate of every descriptor the parent holds, including that one;
/// - `execve` refuses with `ETXTBSY` while any descriptor anywhere has the
///   file open for writing, and the inherited duplicate counts.
///
/// So the write and the `exec` need never touch the same file for this to
/// bite — one test writing its own script is enough to break another test's
/// spawn. Per-process directories and staging-plus-rename do not help, since
/// the descriptor is the problem rather than the path.
///
/// Doing every write inside one `LazyLock` fixes it by ordering: whichever
/// test reaches it first performs all four writes while the others block, and
/// once it releases, no write descriptor is ever open again for the rest of
/// the run. The tests still run in parallel.
static SCRIPTS: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("review-zlint-bridge");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, body) in [
        ("fake-zlint-forks.sh", "sleep 6 &\nexit 0\n".to_owned()),
        (
            "fake-zlint-hangs.sh",
            format!(
                "sleep 30 &\necho $! > '{}'\nsleep 30\n",
                dir.join("grandchild.pid").display()
            ),
        ),
        ("fake-zlint-yes.sh", "exec yes\n".to_owned()),
        (
            "fake-zlint-ok.sh",
            format!("printf '%s\\n' '{OK_LINE}'\necho warning >&2\n"),
        ),
    ] {
        let script = dir.join(name);
        std::fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
});

/// Path to a script written by [`SCRIPTS`].
///
/// Touching `SCRIPTS` is what guarantees every write has completed, so a
/// test must go through here rather than building the path itself.
fn fake_zlint(name: &str) -> std::path::PathBuf {
    SCRIPTS.join(name)
}

#[test]
fn timeout_bounds_call_when_grandchild_holds_pipes() {
    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = fake_zlint("fake-zlint-forks.sh");
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
    // The script writes the grandchild's pid here; the path is fixed inside
    // SCRIPTS because the script body has to name it literally. Removed
    // first so a stale file from an earlier run is not read as this run's.
    let pidfile = fake_zlint("grandchild.pid");
    let _ = std::fs::remove_file(&pidfile);
    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = fake_zlint("fake-zlint-hangs.sh");
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
    cfg.zlint_path = fake_zlint("fake-zlint-yes.sh");
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
    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = fake_zlint("fake-zlint-ok.sh");
    cfg.max_output_bytes = OK_LINE.len() + 1; // exactly the stdout size
    let bridge = ZlintBridge::new(cfg).unwrap();
    let lints = bridge.enumerate_lints().expect("within cap");
    assert_eq!(lints.len(), 1);
    assert_eq!(lints[0].check_id, "e_review_check");
}
