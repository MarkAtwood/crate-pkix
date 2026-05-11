//! `pkix-difftest` CLI entry point.
//!
//! Subcommands (PKIX-7nsf.1):
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

use pkix_difftest::classify::{classify, sort_by_severity, Classified};
use pkix_difftest::corpus::limbo::LimboCorpus;
use pkix_difftest::corpus::pem_multi::PemMultiCorpus;
use pkix_difftest::corpus::pem_tree::PemTreeCorpus;
use pkix_difftest::corpus::pkits::PkitsCorpus;
use pkix_difftest::corpus::Corpus;
use pkix_difftest::report::{write_json, write_markdown, MarkdownOptions};
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
    /// Run one or more oracles on a single concatenated-PEM chain.
    ///
    /// The chain must be in concatenated-PEM form (multiple
    /// -----BEGIN CERTIFICATE----- blocks). Ordering is auto-detected.
    /// The trust anchor must be present as one of the certs in the chain.
    Single {
        /// Path to chain.pem.
        chain: PathBuf,
        /// Comma-separated oracles to run, e.g. `pkix-path,openssl,pyca`.
        /// Default: `pkix-path`. Available: `pkix-path`, `openssl`, `pyca`.
        /// (pyca requires `pkix-difftest/python/setup-venv.sh` first.)
        #[arg(long, default_value = "pkix-path")]
        oracle: String,
    },
    /// Walk a corpus, run every oracle on every chain, classify, report.
    Run {
        #[command(subcommand)]
        corpus: CorpusCmd,
    },
}

#[derive(Debug, Subcommand)]
enum CorpusCmd {
    /// Run over the NIST PKITS corpus from a manifest directory.
    Pkits {
        /// Path to a directory containing `vectors.json` and `certs/`.
        dir: PathBuf,
        #[command(flatten)]
        opts: RunOpts,
    },
    /// Run over a directory tree of `chain.pem` files.
    PemTree {
        /// Path to a directory tree.
        dir: PathBuf,
        #[command(flatten)]
        opts: RunOpts,
    },
    /// Run over a single chain assembled from explicit cert files.
    PemMulti {
        /// One or more cert files (PEM or DER, auto-detected).
        files: Vec<PathBuf>,
        #[command(flatten)]
        opts: RunOpts,
    },
    /// Run over the x509-limbo corpus (`limbo.json`, ~9.7k testcases).
    ///
    /// Applies a default RFC-5280-shaped filter: drops CLIENT validation,
    /// any feature-tagged case (has-crl, pedantic-*, name-constraint-dn,
    /// max-chain-depth, denial-of-service, policy-constraints), and inline
    /// CRLs. See `pkix-difftest/src/corpus/limbo.rs` for the filter
    /// rationale. Per-testcase `validation_time` is pinned through every
    /// oracle via `Chain::validation_time_unix`.
    Limbo {
        /// Path to `limbo.json` (typically `~/GIT/x509-limbo/limbo.json`).
        manifest: PathBuf,
        #[command(flatten)]
        opts: RunOpts,
    },
}

#[derive(Debug, clap::Args)]
struct RunOpts {
    /// Comma-separated oracles. Default `pkix-path,openssl,pyca`.
    #[arg(long, default_value = "pkix-path,openssl,pyca")]
    oracles: String,
    /// Path to write the markdown report. Use `-` for stdout.
    #[arg(long)]
    output_md: Option<String>,
    /// Path to write the JSON report. Use `-` for stdout.
    #[arg(long)]
    output_json: Option<String>,
    /// Maximum samples per class section in the markdown report.
    #[arg(long, default_value_t = 10)]
    sample_size: usize,
    /// Optional title for the markdown report.
    #[arg(long)]
    title: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(SingleOrRun::Single(verdict)) => match verdict {
            Verdict::Pass => ExitCode::SUCCESS,
            Verdict::Fail { .. } => ExitCode::from(1),
        },
        // `run` mode emits a report; exit code 0 = report produced (the
        // verdicts within the report are signal, not error). Caller should
        // grep the JSON for `LooserThanWild` count > 0 to gate CI.
        Ok(SingleOrRun::ReportEmitted) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pkix-difftest: error: {e}");
            ExitCode::from(2)
        }
    }
}

enum SingleOrRun {
    Single(Verdict),
    ReportEmitted,
}

fn run(cli: &Cli) -> std::io::Result<SingleOrRun> {
    match &cli.cmd {
        Cmd::Single {
            chain: path,
            oracle,
        } => {
            let chain = Chain::from_pem_file(path)?;
            let names = parse_oracle_list(oracle)?;
            // Track the worst verdict for the exit code (Fail > Pass). Errors
            // short-circuit out of `run` because they are harness failures
            // distinct from a verdict.
            let mut worst = Verdict::Pass;
            for name in names {
                let verdict = run_oracle(name, &chain)?;
                println!("{name}: {verdict}");
                if matches!(verdict, Verdict::Fail { .. }) {
                    worst = verdict;
                }
            }
            Ok(SingleOrRun::Single(worst))
        }
        Cmd::Run { corpus } => {
            run_corpus(corpus)?;
            Ok(SingleOrRun::ReportEmitted)
        }
    }
}

fn run_corpus(cmd: &CorpusCmd) -> std::io::Result<()> {
    let (corpus, opts): (Box<dyn Corpus>, &RunOpts) = match cmd {
        CorpusCmd::Pkits { dir, opts } => (Box::new(PkitsCorpus::load(dir)?), opts),
        CorpusCmd::PemTree { dir, opts } => (Box::new(PemTreeCorpus::load(dir)?), opts),
        CorpusCmd::PemMulti { files, opts } => (
            Box::new(PemMultiCorpus::new(files.clone(), "pem-multi")),
            opts,
        ),
        CorpusCmd::Limbo { manifest, opts } => (Box::new(LimboCorpus::load(manifest)?), opts),
    };

    let oracle_names = parse_oracle_list(&opts.oracles)?;
    let mut classified: Vec<Classified> = Vec::new();
    let mut harness_errors: Vec<(String, std::io::Error)> = Vec::new();

    // Per-corpus iteration. Per-chain harness errors are collected and
    // reported at the end so a malformed entry does not abort the whole
    // run. Per-oracle harness errors are reported synchronously to stderr
    // and the chain is skipped from classification.
    for item_result in corpus.iter() {
        let item = match item_result {
            Ok(it) => it,
            Err(e) => {
                harness_errors.push(("(corpus loader)".to_string(), e));
                continue;
            }
        };
        let mut verdicts = Vec::with_capacity(oracle_names.len());
        let mut had_oracle_error = false;
        for &name in &oracle_names {
            match run_oracle(name, &item.chain) {
                Ok(v) => verdicts.push((name, v)),
                Err(e) => {
                    eprintln!("pkix-difftest: oracle {name} on chain {:?}: {e}", item.name);
                    harness_errors.push((item.name.clone(), e));
                    had_oracle_error = true;
                    break;
                }
            }
        }
        if had_oracle_error {
            continue;
        }
        classified.push(classify(item.name, verdicts, item.expected.as_ref()));
    }
    sort_by_severity(&mut classified);

    let md_opts = MarkdownOptions {
        sample_size: opts.sample_size,
        title: opts.title.clone(),
    };

    if let Some(target) = &opts.output_md {
        if target == "-" {
            write_markdown(&mut std::io::stdout(), &classified, &md_opts)?;
        } else {
            let mut f = std::fs::File::create(target)?;
            write_markdown(&mut f, &classified, &md_opts)?;
        }
    }
    if let Some(target) = &opts.output_json {
        if target == "-" {
            write_json(&mut std::io::stdout(), &classified)?;
        } else {
            let mut f = std::fs::File::create(target)?;
            write_json(&mut f, &classified)?;
        }
    }
    if opts.output_md.is_none() && opts.output_json.is_none() {
        // No outputs configured — emit markdown to stdout so the harness is
        // useful out of the box.
        write_markdown(&mut std::io::stdout(), &classified, &md_opts)?;
    }

    if !harness_errors.is_empty() {
        eprintln!(
            "pkix-difftest: {} harness error(s) during run; chains skipped from classification",
            harness_errors.len()
        );
    }
    Ok(())
}

fn run_oracle(name: OracleName, chain: &Chain) -> std::io::Result<Verdict> {
    match name {
        OracleName::PkixPath => oracles::pkix_path::verify(chain),
        OracleName::OpenSsl => oracles::openssl::verify(chain),
        OracleName::Pyca => oracles::pyca::verify(chain),
    }
}

fn parse_oracle_list(s: &str) -> std::io::Result<Vec<OracleName>> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_oracle_name)
        .collect()
}

fn parse_oracle_name(s: &str) -> std::io::Result<OracleName> {
    match s {
        "pkix-path" => Ok(OracleName::PkixPath),
        "openssl" => Ok(OracleName::OpenSsl),
        "pyca" => Ok(OracleName::Pyca),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown oracle: {other:?} (try pkix-path, openssl, pyca)"),
        )),
    }
}
