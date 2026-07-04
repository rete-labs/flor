// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! `retectl` — operator-only rete-authoring CLI.
//!
//! The CA private key is only ever touched by this binary; it never ships to a node.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use error_stack::{Report, ResultExt};

use flor::{
    cli::{print_error, write_secret},
    config::rete::{LoadOpts, load, validate},
    core::identity::{Ca, Kind, TrustDomain, build_id},
};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct Error(String);

#[derive(Parser, Debug)]
#[command(name = "retectl", about = "Florete operator CLI (rete authoring)")]
struct Cli {
    /// Enable debug logging (also prints full error chains on failure).
    #[arg(short, long, global = true)]
    verbose: bool,

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

fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Warn
    };
    let _ = flor::logging::logger::init(log_level);

    if let Err(e) = run(cli.cmd, cli.verbose) {
        print_error(&e, cli.verbose);
        std::process::exit(1);
    }
}

fn run(cmd: Cmd, verbose: bool) -> Result<(), Report<Error>> {
    match cmd {
        Cmd::Ca { action } => match action {
            CaAction::Init(args) => ca_init(args),
            CaAction::Sign(args) => ca_sign(args),
        },
        Cmd::Validate(args) => cmd_validate(args, verbose),
    }
}

fn cmd_validate(args: ValidateArgs, verbose: bool) -> Result<(), Report<Error>> {
    let opts = LoadOpts {
        repo: args.repo,
        files: args.files,
    };

    let model = load(&opts).map_err(|e| {
        print_error(&e, verbose);
        Report::new(Error("config load failed".into()))
    })?;

    let violations = validate(&model);

    if violations.is_empty() {
        println!("ok");
        return Ok(());
    }

    for v in &violations {
        eprintln!("  [{}] {}", v.rule, v.message);
    }
    Err(Report::new(Error(format!(
        "{} violation(s) found",
        violations.len()
    ))))
}

fn ca_init(args: CaInitArgs) -> Result<(), Report<Error>> {
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

fn ca_sign(args: CaSignArgs) -> Result<(), Report<Error>> {
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
