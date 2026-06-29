// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use error_stack::{Report, ResultExt};

use flor::{
    cli::{print_error, write_secret},
    core::identity::{Kind, TrustDomain, build_id, keygen_csr},
    logging,
    utils::home::rete_root,
    vertex,
};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

#[derive(Parser, Debug)]
#[command(name = "flor", about = "Florete node binary (daemon + node-local CLI)")]
struct Args {
    /// Show the full error-stack chain on failure (default: compact `: `-joined chain).
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Identity primitives.
    Id {
        #[command(subcommand)]
        action: IdAction,
    },
    /// Run a vertex from its compiled artifact.
    Vertex {
        #[command(subcommand)]
        action: VertexAction,
    },
}

#[derive(Subcommand, Debug)]
enum IdAction {
    /// Generate a keypair locally and emit a CSR for the operator to sign.
    Keygen(KeygenArgs),
}

#[derive(ClapArgs, Debug)]
struct KeygenArgs {
    /// Principal kind.
    #[arg(long, value_enum)]
    kind: Kind,
    /// Principal name (last path segment of the SPIFFE ID).
    #[arg(long)]
    name: String,
    /// Rete trust domain.
    #[arg(long)]
    trust_domain: String,
    /// Node name for node-scoped principals.
    #[arg(long)]
    scope: Option<String>,
    /// Where to write the PEM-encoded private key (mode 0600 on Unix).
    #[arg(long)]
    out_key: PathBuf,
    /// Where to write the PEM-encoded CSR.
    #[arg(long)]
    out_csr: PathBuf,
}

#[derive(Subcommand, Debug)]
enum VertexAction {
    /// Run a link vertex against its rete root.
    Run(VertexRunArgs),
}

#[derive(ClapArgs, Debug)]
struct VertexRunArgs {
    /// Rete scope: a subdirectory of `<flor-home>/retes/`, where flor-home is
    /// `$FLOR_HOME` if set, else `$HOME/.flor`. Auto-detected when exactly one
    /// rete is enrolled.
    #[arg(long)]
    rete: Option<String>,
    /// Vertex name — selects `mgmt/vertices/<name>.json` under the rete root.
    #[arg(long)]
    name: String,
}

fn main() {
    let args = Args::parse();
    let verbose = args.verbose;
    match args.cmd {
        Cmd::Id {
            action: IdAction::Keygen(keygen_args),
        } => {
            // Synchronous path — no tokio needed.
            if let Err(e) = run_id_keygen(keygen_args) {
                print_error(&e, verbose);
                std::process::exit(1);
            }
        }
        Cmd::Vertex {
            action: VertexAction::Run(vertex_args),
        } => {
            logging::logger::init(log::LevelFilter::Info).expect("Failed to initialize logger");
            if let Err(e) = run_vertex(vertex_args) {
                print_error(&e, verbose);
                std::process::exit(1);
            }
        }
    }
}

fn run_id_keygen(args: KeygenArgs) -> Result<(), Report<Error>> {
    let td = TrustDomain::new(&args.trust_domain)
        .change_context(Error("Invalid trust domain".into()))?;
    let id = build_id(&td, args.kind, &args.name, args.scope.as_deref())
        .change_context(Error("Failed to build SPIFFE ID".into()))?;
    let (key, csr_pem) = keygen_csr(&id).change_context(Error("Keygen failed".into()))?;

    write_secret(&args.out_key, key.serialize_pem().as_bytes())
        .change_context(Error("Failed to write private key".into()))?;
    std::fs::write(&args.out_csr, csr_pem.as_bytes()).change_context_lazy(|| {
        Error(format!("Failed to write CSR to {}", args.out_csr.display()))
    })?;

    println!("SPIFFE ID: {id}");
    println!("Key:       {}", args.out_key.display());
    println!("CSR:       {}", args.out_csr.display());
    Ok(())
}

fn run_vertex(args: VertexRunArgs) -> Result<(), Report<Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .change_context(Error("Failed to build tokio runtime".into()))?;
    rt.block_on(vertex_main(args))
}

async fn vertex_main(args: VertexRunArgs) -> Result<(), Report<Error>> {
    let root = rete_root(args.rete.as_deref())
        .change_context(Error("Failed to resolve the rete root".into()))?;
    let config = vertex::ConfigBundle::load(&root, &args.name).change_context_lazy(|| {
        Error(format!(
            "Failed to load vertex '{}' from {}",
            args.name,
            root.display()
        ))
    })?;
    log::info!("Running vertex '{}' from {}", args.name, root.display());
    vertex::run(config)
        .await
        .change_context_lazy(|| Error(format!("Vertex '{}' run failed", args.name)))
}
