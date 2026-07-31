// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! `retectl` — operator-only rete-authoring CLI.
//!
//! The CA private key is only ever touched by this binary; it never ships to a node.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand};
use error_stack::{Report, ResultExt};

use flor::{
    cli::{compact_chain, print_error, print_error_lines, write_secret},
    config::compile::{CompileOpts, compile, layout, version},
    config::rete::{LoadOpts, RepoModel, load, validate},
    core::identity::{Ca, Kind, TrustDomain, build_id},
};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct Error(String);

#[derive(Parser, Debug)]
#[command(name = "retectl", about = "Florete operator CLI (rete authoring)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Certificate Authority operations (touches CA private key).
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Validate rete config: schema, cross-references, access consistency.
    Validate(ValidateArgs),
    /// Compile rete config into per-node artifacts.
    Compile(CompileArgs),
}

#[derive(Args, Debug)]
struct ValidateArgs {
    /// Repository root directory.
    #[arg(long, default_value = ".")]
    repo: PathBuf,

    /// Override file discovery with explicit paths or globs (repeatable).
    #[arg(short, long = "file", value_name = "FILE")]
    files: Vec<String>,
}

#[derive(Args, Debug)]
struct CompileArgs {
    /// Repository root directory.
    #[arg(long, default_value = ".")]
    repo: PathBuf,

    /// Override file discovery with explicit paths or globs (repeatable).
    #[arg(short, long = "file", value_name = "FILE")]
    files: Vec<String>,

    /// Where to write the compiled tree (default: `<repo>/.flor/compiled`).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum CaAction {
    /// Generate a fresh rete CA keypair and self-sign its root certificate.
    Init(CaInitArgs),
    /// Sign a CSR, applying the X.509 extension policy for the principal kind.
    ///
    /// The CSR's URI SAN must match the operator-supplied `(kind, name, scope)`.
    /// Mismatched, missing, or multiple SANs are rejected.
    Sign(CaSignArgs),
}

#[derive(Args, Debug)]
struct CaInitArgs {
    /// Rete trust domain. Doubles as the rete name.
    #[arg(long)]
    trust_domain: String,
    /// CA validity in days.
    #[arg(long, default_value_t = 3650)]
    validity_days: u32,
    /// Where to write the CA certificate PEM (safe to commit).
    #[arg(long)]
    out_cert: PathBuf,
    /// Where to write the CA private key PEM (mode 0600 on Unix; do **not** commit).
    #[arg(long)]
    out_key: PathBuf,
}

#[derive(Args, Debug)]
struct CaSignArgs {
    /// Path to the PEM-encoded CSR produced by `flor id keygen`.
    #[arg(long)]
    csr: PathBuf,
    /// Principal kind.
    #[arg(long, value_enum)]
    kind: Kind,
    /// Principal name (last path segment of the SPIFFE ID).
    #[arg(long)]
    name: String,
    /// Node name for node-scoped principals (only valid with `--kind service|vertex`).
    #[arg(long)]
    scope: Option<String>,
    /// Leaf certificate validity in days.
    #[arg(long, default_value_t = 90)]
    validity_days: u32,
    /// Path to the rete CA certificate.
    #[arg(long)]
    ca_cert: PathBuf,
    /// Path to the rete CA private key.
    #[arg(long)]
    ca_key: PathBuf,
    /// Where to write the signed leaf certificate PEM.
    #[arg(long)]
    out: PathBuf,
}

/// Full error-stack chains and logs are developer diagnostics for `retectl`
/// itself (source locations, internal trace) — not actionable for an
/// operator, who already gets the causal chain in the compact output. So
/// both are gated to debug builds rather than a user-facing flag. The log
/// level defaults to `Info`; override via `RUST_LOG` when tracing an issue.
#[cfg(debug_assertions)]
const DEBUG: bool = true;
#[cfg(not(debug_assertions))]
const DEBUG: bool = false;

fn main() {
    let cli = Cli::parse();

    if DEBUG {
        let _ = flor::logging::logger::init(flor::logging::logger::LevelFilter::INFO);
    }

    if let Err(e) = run(cli.cmd) {
        match e {
            CmdError::Single(report) => print_error(&report, DEBUG),
            CmdError::Many { stage, errors } => print_error_lines(&errors, stage),
        }
        std::process::exit(1);
    }
}

/// How a command failed — one error, or a collected set of them.
enum CmdError {
    /// A single failure, reported as its causal chain.
    Single(Report<Error>),
    /// A stage that runs to completion and collects every failure it finds
    /// (config load, validation), reported as a list. The `stage` names it in
    /// the summary line; the errors are already rendered.
    Many {
        stage: &'static str,
        errors: Vec<String>,
    },
}

impl From<Report<Error>> for CmdError {
    fn from(report: Report<Error>) -> Self {
        CmdError::Single(report)
    }
}

fn run(cmd: Cmd) -> Result<(), CmdError> {
    match cmd {
        Cmd::Ca { action } => match action {
            CaAction::Init(args) => ca_init(args),
            CaAction::Sign(args) => ca_sign(args),
        },
        Cmd::Validate(args) => cmd_validate(args),
        Cmd::Compile(args) => cmd_compile(args),
    }
}

fn cmd_validate(args: ValidateArgs) -> Result<(), CmdError> {
    load_valid_model(args.repo, args.files)?;
    println!("ok");
    Ok(())
}

/// `compile` writes artifacts an agent will act on, so it refuses anything
/// `validate` would reject: same load, same rules, then the projection.
fn cmd_compile(args: CompileArgs) -> Result<(), CmdError> {
    let out = args
        .out
        .unwrap_or_else(|| args.repo.join(".flor").join("compiled"));
    let model = load_valid_model(args.repo, args.files)?;

    // Read the counter off the tree before the write clears it.
    let opts = CompileOpts {
        version: version::next_version(&out)
            .change_context(Error("Failed to read the compiled version".into()))?,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };

    let artifacts =
        compile(&model, &opts).change_context(Error("Failed to compile rete config".into()))?;
    let written = layout::write(&out, &artifacts)
        .change_context(Error("Failed to write the compiled tree".into()))?;

    for path in &written {
        println!("{}", path.display());
    }
    println!(
        "Compiled {} node(s) at version {}",
        artifacts.len(),
        opts.version
    );
    Ok(())
}

/// Load the merged source and run the validator over it. The `Ok` model is one
/// every rule accepted — the guarantee `compile` builds on.
fn load_valid_model(repo: PathBuf, files: Vec<String>) -> Result<RepoModel, CmdError> {
    let opts = LoadOpts { repo, files };

    let model = load(&opts).map_err(|failures| {
        for f in &failures {
            log::error!("{f:?}");
        }
        CmdError::Many {
            stage: "load",
            errors: failures.iter().map(compact_chain).collect(),
        }
    })?;

    let violations = validate(&model);
    if !violations.is_empty() {
        return Err(CmdError::Many {
            stage: "validation",
            errors: violations
                .iter()
                .map(|v| format!("[{}] {}", v.rule, v.message))
                .collect(),
        });
    }

    Ok(model)
}

fn ca_init(args: CaInitArgs) -> Result<(), CmdError> {
    let td = TrustDomain::new(&args.trust_domain)
        .change_context(Error("Invalid trust domain".into()))?;
    let ca =
        Ca::init(&td, days(args.validity_days)).change_context(Error("CA init failed".into()))?;

    std::fs::write(&args.out_cert, ca.cert_pem().as_bytes())
        .change_context_lazy(|| Error(format!("Failed to write {}", args.out_cert.display())))?;
    write_secret(&args.out_key, ca.key_pem().as_bytes())
        .change_context(Error("Failed to write CA private key".into()))?;

    println!("Trust domain: {}", args.trust_domain);
    println!("Certificate:  {}", args.out_cert.display());
    println!("Private key:  {} (mode 0600)", args.out_key.display());
    Ok(())
}

fn ca_sign(args: CaSignArgs) -> Result<(), CmdError> {
    let cert_pem_bytes = std::fs::read(&args.ca_cert)
        .change_context_lazy(|| Error(format!("Failed to read {}", args.ca_cert.display())))?;
    let key_pem_bytes = std::fs::read(&args.ca_key)
        .change_context_lazy(|| Error(format!("Failed to read {}", args.ca_key.display())))?;
    let ca = Ca::from_pem(&cert_pem_bytes, &key_pem_bytes)
        .change_context(Error("Failed to load CA".into()))?;

    let id = build_id(
        ca.trust_domain(),
        args.kind,
        &args.name,
        args.scope.as_deref(),
    )
    .change_context(Error("Failed to build SPIFFE ID".into()))?;

    let csr_pem = std::fs::read(&args.csr)
        .change_context_lazy(|| Error(format!("Failed to read {}", args.csr.display())))?;
    let leaf_pem = ca
        .sign_csr(&csr_pem, &id, args.kind, days(args.validity_days))
        .change_context(Error("Failed to sign CSR".into()))?;

    std::fs::write(&args.out, leaf_pem.as_bytes())
        .change_context_lazy(|| Error(format!("Failed to write {}", args.out.display())))?;

    println!("SPIFFE ID:   {id}");
    println!("Certificate: {}", args.out.display());
    Ok(())
}

fn days(d: u32) -> Duration {
    Duration::from_secs(u64::from(d) * 24 * 3600)
}
