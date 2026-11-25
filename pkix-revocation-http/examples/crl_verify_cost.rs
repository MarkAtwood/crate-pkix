//! Measures how long one synchronous CRL verification takes, as a
//! function of CRL size.
//!
//! This is the measurement behind the "verification runs on the calling
//! task" section of `async_fetcher`'s module documentation, which is
//! the reason that module tells consumers to move the CPU half of a
//! revocation check onto a blocking pool. Numbers are
//! machine-dependent; the shape — roughly linear in the number of
//! revoked entries, because DER-decoding the list dominates — is not.
//!
//! Generate the fixtures first (needs `cryptography`; the
//! `pkix-difftest` venv has it):
//!
//! ```text
//! python3 -I examples/crl_verify_cost_fixtures.py /tmp/crlbench 1000 20000 100000
//! ```
//!
//! Then, with a release build (a debug build measures `der`'s unoptimised
//! decode path and overstates the cost several-fold):
//!
//! ```text
//! cargo run --release -p pkix-revocation-http --features crl \
//!     --example crl_verify_cost -- /tmp/crlbench
//! ```
use std::time::Instant;

use der::Decode as _;
use pkix_path::DefaultVerifier;
use pkix_revocation::{CrlChecker, RevocationChecker as _};
use x509_cert::Certificate;

fn main() {
    let dir = std::env::args().nth(1).expect("pass the fixture directory");
    let rd = |n: &str| std::fs::read(format!("{dir}/{n}")).expect("fixture");
    let ca = Certificate::from_der(&rd("ca.der")).unwrap();
    let leaf = Certificate::from_der(&rd("leaf.der")).unwrap();
    const NOW: u64 = 1_780_272_000;

    for n in [1000usize, 20000, 100000] {
        let bytes = rd(&format!("crl-{n}.der"));
        // Warm.
        for _ in 0..3 {
            let c = CrlChecker::new(bytes.as_slice(), NOW, DefaultVerifier).unwrap();
            let _ = c.check_revocation(&leaf, &ca);
        }
        let iters = if n >= 100000 { 20 } else { 100 };
        let t = Instant::now();
        for _ in 0..iters {
            let c = CrlChecker::new(bytes.as_slice(), NOW, DefaultVerifier).unwrap();
            let _ = c.check_revocation(&leaf, &ca);
        }
        let per = t.elapsed() / iters;
        println!(
            "{n:>7} entries ({:>7} KiB): {:>9.3} ms per verification",
            bytes.len() / 1024,
            per.as_secs_f64() * 1000.0
        );
    }
}
