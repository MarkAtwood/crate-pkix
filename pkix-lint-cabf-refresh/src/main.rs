//! `pkix-lint-cabf-refresh` CLI entry point.
//!
//! Maintainer-only tool. Transforms the output of `zlint -list-lints-json`
//! into a vendored OSCAL Catalog JSON file consumed at runtime by
//! `pkix-lint-cabf`.
//!
//! # Workflow (the human runs this; CI does not)
//!
//! ```text
//! zlint -list-lints-json > /tmp/zlint-lints.ndjson
//! cargo run -p pkix-lint-cabf-refresh -- \
//!     --zlint-output /tmp/zlint-lints.ndjson \
//!     --output-dir   pkix-lint-cabf/catalogs/ \
//!     --zlint-sha    "$(git -C ~/GIT/zlint rev-parse HEAD)"
//! ```
//!
//! # Status
//!
//! - PKIX-amgn.8.2 (this commit): skeleton only. The CLI parses arguments,
//!   prints them, and exits 0. No transform yet.
//! - PKIX-amgn.8.3 (next): implement the zlint NDJSON → OSCAL Catalog JSON
//!   transform.
//! - PKIX-amgn.8.4: vendor the first generated catalog into the repo.
//!
//! Exit codes:
//! - 0 — success (skeleton stage: arguments parsed and echoed).
//! - 2 — CLI usage error (clap default).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// Transform `zlint -list-lints-json` output into a vendored OSCAL Catalog JSON.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to a file containing the output of `zlint -list-lints-json`.
    ///
    /// The file is line-delimited JSON, one lint per line, with fields
    /// `{name, description, citation, source}`.
    #[arg(long, value_name = "PATH")]
    zlint_output: PathBuf,

    /// Directory under which the vendored OSCAL Catalog JSON will be written.
    ///
    /// Conventionally `pkix-lint-cabf/catalogs/`. The transform creates one
    /// OSCAL Catalog per zlint source (apple/cabf/rfc/…) under this directory.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,

    /// Git SHA of the zlint checkout that produced `--zlint-output`.
    ///
    /// Recorded in OSCAL Catalog metadata as provenance so the vendored JSON
    /// can be traced back to the source commit. Typically obtained via
    /// `git -C ~/GIT/zlint rev-parse HEAD`.
    #[arg(long, value_name = "SHA")]
    zlint_sha: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // PKIX-amgn.8.2: skeleton only. The actual transform lands in PKIX-amgn.8.3.
    // Echo arguments so smoke-testing the skeleton end-to-end (zlint emits the
    // input, this binary parses it back) confirms the CLI plumbing works.
    println!("pkix-lint-cabf-refresh: skeleton stage (PKIX-amgn.8.2)");
    println!("  zlint_output: {}", cli.zlint_output.display());
    println!("  output_dir:   {}", cli.output_dir.display());
    println!("  zlint_sha:    {}", cli.zlint_sha);
    println!("(transform logic lands in PKIX-amgn.8.3)");

    ExitCode::SUCCESS
}
