//! Ad-hoc probe: validate real TLS chains against the host trust store.
//!
//! Answers "can this stack authenticate an arbitrary server today" with a
//! demonstration rather than an inventory. Reads the platform CA bundle
//! through `pkix-truststore`, then runs each PEM chain in the given
//! directory through `pkix-chain::verify_chain`.
//!
//! Usage: cargo run -p pkix-chain --example real_world_probe -- <bundle.pem> <dir-of-chains> [now_unix]
use std::time::{SystemTime, UNIX_EPOCH};

use pkix_chain::{verify_chain, DefaultVerifier, NoAiaFetcher, NoRevocation};
use pkix_path::ValidationPolicy;
use x509_cert::der::{Decode as _, DecodePem as _};
use x509_cert::Certificate;

fn main() {
    let mut args = std::env::args().skip(1);
    let bundle = args.next().expect("pass the CA bundle path");
    let dir = args.next().expect("pass a directory of .pem chains");
    let now = args.next().map_or_else(
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_secs()
        },
        |s| s.parse().expect("now_unix"),
    );

    let anchors = pkix_truststore::from_pem_file(&bundle).expect("load the platform CA bundle");
    println!("trust anchors loaded from {bundle}: {}", anchors.len());

    let policy = ValidationPolicy::new(now);
    let mut ok = 0;
    let mut fail = 0;

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("read chain dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pem"))
        .collect();
    entries.sort();

    for path in entries {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let pem = std::fs::read(&path).expect("read chain");
        // Split the PEM bundle into its certificates, leaf first.
        let chain: Vec<Certificate> = pem
            .split_inclusive(|b| *b == b'\n')
            .collect::<Vec<_>>()
            .split(|line| line.starts_with(b"-----END CERTIFICATE-----"))
            .filter_map(|block| {
                let mut buf: Vec<u8> = block.concat();
                if !buf.windows(5).any(|w| w == b"BEGIN") {
                    return None;
                }
                buf.extend_from_slice(b"-----END CERTIFICATE-----\n");
                Certificate::from_pem(&buf).ok()
            })
            .collect();

        if chain.is_empty() {
            println!("  {name:<18} SKIP (no certificates parsed)");
            continue;
        }

        match verify_chain(
            &chain,
            &anchors,
            &policy,
            &DefaultVerifier,
            &NoRevocation,
            &NoAiaFetcher,
        ) {
            Ok(_) => {
                ok += 1;
                println!("  {name:<18} OK   ({} certs supplied)", chain.len());
            }
            Err(e) => {
                fail += 1;
                println!("  {name:<18} FAIL ({} certs) {e}", chain.len());
            }
        }
    }
    println!("\nvalidated {ok} / {} chains ({fail} failed)", ok + fail);
    let _ = Certificate::from_der(&[]);
}
