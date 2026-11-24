//! Review regression test: `all_lints` must not leak a fresh
//! `ZlintLintInfo` on every call. Uses a fake zlint shell script
//! (generated under CARGO_TARGET_TMPDIR) that prints a one-entry
//! `-list-lints-json` catalog, so it runs without zlint installed.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use pkix_policy_zlint::all_lints;
use pkix_zlint_bridge::{BridgeConfig, ZlintBridge};

#[test]
fn repeated_all_lints_reuses_leaked_metadata() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("review-policy-zlint");
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("fake-zlint-catalog.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf '%s\\n' '{\"name\":\"e_review_intern\",\"description\":\"d\",\"citation\":\"c\",\"source\":\"s\"}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // NOTE: writing an executable and then spawning it is safe here only
    // because this file contains exactly one test, so no other thread can be
    // forking while this write's file descriptor is open. On Linux a forked
    // child inherits that descriptor and `execve` then fails with ETXTBSY
    // ("Text file busy"), which is what made
    // pkix-zlint-bridge/tests/review_timeout.rs flaky until its writes were
    // moved into a single LazyLock that completes before any test spawns.
    // Adding a second test to this file reintroduces that race; do the same
    // thing there if you do.

    let mut cfg = BridgeConfig::default();
    cfg.zlint_path = script;
    let bridge = Arc::new(ZlintBridge::new(cfg).unwrap());

    let first = all_lints(bridge.clone()).expect("first enumeration");
    let second = all_lints(bridge).expect("second enumeration");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id(), "e_review_intern");
    // Same `&'static` backing storage: the second call did not leak a
    // new copy of the record.
    assert!(
        std::ptr::eq(first[0].id(), second[0].id()),
        "all_lints leaked a second copy of an identical catalog entry"
    );
}
