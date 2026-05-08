//! `pkix-difftest` CLI entry point.
//!
//! Subcommands (v0.1, PKIX-7nsf.1):
//! - `single <chain.pem>` — verify one concatenated-PEM chain with the
//!   in-process `pkix-path` oracle and print the verdict.
//!
//! Future subcommands (TODO, tracked in sibling beads):
//! - `pkits <dir>`       — PKIX-7nsf.4 (corpus loader)
//! - `pem-tree <dir>`    — PKIX-7nsf.4
//! - `pem-multi <files…>`— PKIX-7nsf.4
//! - `run <corpus-spec> --oracles ...` — PKIX-7nsf.5 (classifier)
//!
//! Exit codes:
//! - 0  — chain validated successfully (verdict Pass).
//! - 1  — chain validated unsuccessfully (verdict Fail).
//! - 2  — harness error (malformed input, oracle could not run, etc.).
//!
//! The Pass/Fail-distinction-via-exit-code is deliberate: lets a shell
//! caller pipeline this binary in CI without parsing stdout. Note that this
//! exit-code shape is `single`-subcommand-only; once `run` lands and emits a
//! report, the natural exit semantic becomes "0 = report emitted, 2 = harness
//! failure" with verdict counts in the report itself.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use pkix_difftest::{oracles, Chain, OracleName, Verdict};

#[derive(Debug, Parser)]
#[command(
    name = "pkix-difftest",
    about = "PKIX path validation differential test harness",
    long_about = "Runs cert chains through pkix-path, openssl, and pyca/cryptography \
                  and reports verdict divergences. See pkix-difftest/README.md."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the pkix-path oracle on a single concatenated-PEM chain.
    ///
    /// The chain must be in concatenated-PEM form (multiple
    /// -----BEGIN CERTIFICATE----- blocks). Ordering is auto-detected.
    /// The trust anchor must be present as one of the certs in the chain.
    Single {
        /// Path to chain.pem.
        chain: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(verdict) => match verdict {
            Verdict::Pass => ExitCode::SUCCESS,
            Verdict::Fail { .. } => ExitCode::from(1),
        },
        Err(e) => {
            eprintln!("pkix-difftest: error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> std::io::Result<Verdict> {
    match &cli.cmd {
        Cmd::Single { chain: path } => {
            let chain = Chain::from_pem_file(path)?;
            let verdict = oracles::pkix_path::verify(&chain)?;
            // Stdout: one line per oracle, "<oracle>: <verdict>".
            // PKIX-7nsf.5 will replace this with a structured report; for
            // now, single-oracle single-chain humans expect one line.
            println!("{}: {verdict}", OracleName::PkixPath);
            Ok(verdict)
        }
    }
}
