// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use clap::{Args as ClapArgs, Parser, Subcommand};
use error_stack::{Report, ResultExt};

use flor::{
    AddrMap, AppConfigBundle, EndpointAddr, Socks5Targets, TcpDirectTargets,
    cli::{print_error, write_secret},
    core::{
        identity::{Kind, TrustDomain, build_id, keygen_csr},
        transport::{QuicConnector, QuicPublisher, TransportBundle},
    },
    logging,
    northbound::{
        inbound::{Error as InboundError, InboundBundle},
        outbound::{Error as OutboundError, OutboundBundle},
    },
    utils::report::ErrorReport,
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
    /// Run the demo (legacy, replaced by `agent run` once the daemon lands).
    Demo {
        /// Select node config.
        #[arg(long, default_value = "Alpha", value_parser = ["Alpha", "Beta"])]
        name: String,
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
    /// Cluster trust domain (e.g. `demo.flor`).
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

#[fundle::bundle]
struct AppBundle {
    #[forward(EndpointAddr, AddrMap, Socks5Targets, TcpDirectTargets)]
    pub config: AppConfigBundle,
    #[forward(QuicConnector, QuicPublisher)]
    pub transport: TransportBundle,
    pub inbound: InboundBundle,
    pub outbound: OutboundBundle,
}

fn main() {
    let args = Args::parse();
    let verbose = args.verbose;
    match args.cmd {
        Cmd::Id {
            action: IdAction::Keygen(keygen_args),
        } => {
            // Synchronous path — no tokio needed
            if let Err(e) = run_id_keygen(keygen_args) {
                print_error(&e, verbose);
                std::process::exit(1);
            }
        }
        Cmd::Demo { name } => {
            logging::logger::init(log::LevelFilter::Info).expect("Failed to initialize logger");
            if let Err(e) = run_demo(name) {
                log::error!("Demo failed: {e:?}");
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

fn run_demo(node_name: String) -> Result<(), Report<Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .change_context(Error("Failed to build tokio runtime".into()))?;
    rt.block_on(demo_main(node_name))
}

async fn demo_main(node_name: String) -> Result<(), Report<Error>> {
    // Initial demo services use workload names; TCP direct services use DNS-style names.
    // The transport currently uses service names directly as QUIC TLS SNI values.
    // Node configuration: (quic_addr, socks5_inbounds, tcp_direct_services)
    let service_map = HashMap::from([
        (
            "Alpha", // node name
            (
                "127.0.0.1:31337".parse::<SocketAddr>().unwrap(), // QUIC address
                vec![
                    ("alice", "127.0.0.1:1080".parse::<SocketAddr>().unwrap()),
                    ("bob", "127.0.0.1:1081".parse::<SocketAddr>().unwrap()),
                ], // SOCKS5 workloads
                vec![],                                           // TCP services (none on Alpha)
            ),
        ),
        (
            "Beta", // node name
            (
                "127.0.0.1:31440".parse::<SocketAddr>().unwrap(), // QUIC address
                vec![],                                           // SOCKS5 workloads (none on Beta)
                vec![(
                    "tcp-echo.beta.demo-cluster.rete".to_string(),
                    "127.0.0.1:32450".parse::<SocketAddr>().unwrap(),
                )], // TCP services
            ),
        ),
    ]);

    // Get current node config
    let (quic_addr, socks5_inbounds, tcp_outbounds) = service_map
        .get(node_name.as_str())
        .ok_or_else(|| Report::new(Error("Node not found in predefined service map".into())))?;
    let socks5_targets = socks5_inbounds
        .iter()
        .map(|(workload, addr)| (workload.to_string(), *addr))
        .collect::<HashMap<_, _>>();
    let tcp_direct_targets = tcp_outbounds.iter().cloned().collect::<HashMap<_, _>>();

    log::info!(
        "Node '{}' bound to {}. SOCKS5 workloads: {}. TCP services: {}.",
        node_name,
        quic_addr,
        socks5_inbounds
            .iter()
            .map(|(workload, _addr)| *workload)
            .collect::<Vec<_>>()
            .join(", "),
        tcp_outbounds
            .iter()
            .map(|(service, _target)| service.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );

    // For each workload or service a node hosts, emit (name, node_addr).
    let addr_map: HashMap<String, SocketAddr> = service_map
        .iter()
        .flat_map(|(_node, (addr, socks5_inbounds, tcp_outbounds))| {
            let workloads = socks5_inbounds
                .iter()
                .map(move |(workload, _listen_addr)| (workload.to_string(), *addr));
            let tcp_services = tcp_outbounds
                .iter()
                .map(move |(service, _target)| (service.clone(), *addr));

            workloads.chain(tcp_services)
        })
        .collect();

    let bundle_err = || Error("Failed to build app bundle".into());
    let app: AppBundle = AppBundle::builder()
        .config(|_| AppConfigBundle {
            endpoint_addr: EndpointAddr(*quic_addr),
            addr_map: AddrMap(addr_map.clone()),
            socks5_targets: Socks5Targets(socks5_targets.clone()),
            tcp_direct_targets: TcpDirectTargets(tcp_direct_targets.clone()),
        })
        .transport_try(|b| TransportBundle::try_new(b))
        .change_context_lazy(bundle_err)?
        .inbound_try_async(init_inbound)
        .await
        .change_context_lazy(bundle_err)?
        .outbound_try_async(init_outbound)
        .await
        .change_context_lazy(bundle_err)?
        .build();

    let endpoint_handle = app.transport.endpoint_handle;
    let socks5_handle = app.inbound.socks5_handle;
    let tcp_direct_handle = app.outbound.tcp_direct_handle;

    tokio::select! {
        result = endpoint_handle.wait() => {
            if let Err(e) = result {
                log::error!("Endpoint actor task failed: {e:?}");
            }
        }
        result = async {
            match socks5_handle {
                Some(h) => h.wait().await,
                None => std::future::pending().await,
            }
        } => {
            if let Err(e) = result {
                log::error!("Socks5 task failed: {e:?}");
            }
        }
        result = async {
            match tcp_direct_handle {
                Some(h) => h.wait().await,
                None => std::future::pending().await,
            }
        } => {
            if let Err(e) = result {
                log::error!("TCP direct outbound task failed: {e:?}");
            }
        }
    }

    Ok(())
}

// Workaround to avoid rust-analyzer issue with async closures.
async fn init_inbound(
    b: &AppBundleBuilder<fundle::Read, fundle::Set, fundle::Set, fundle::NotSet, fundle::NotSet>,
) -> Result<InboundBundle, ErrorReport<InboundError>> {
    InboundBundle::try_new(b).await
}

// Workaround to avoid rust-analyzer issue with async closures.
async fn init_outbound(
    b: &AppBundleBuilder<fundle::Read, fundle::Set, fundle::Set, fundle::Set, fundle::NotSet>,
) -> Result<OutboundBundle, ErrorReport<OutboundError>> {
    OutboundBundle::try_new(b).await
}
