// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use clap::{Args as ClapArgs, Parser, Subcommand};
use error_stack::{Report, ResultExt};

use flor::{
    AppConfigBundle,
    cli::{print_error, write_secret},
    core::{
        identity::{
            Kind, NodeScopableKind, TrustDomain, X509Bundle, X509Svid, build_id, build_id_on_node,
            keygen_csr, load_bundle_from_pem, load_svid_from_pem,
        },
        transport::{
            AddrMap, EndpointAddr, QuicConnector, QuicPublisher, TransportBundle, TrustBundle,
        },
    },
    logging,
    northbound::{
        inbound::{Error as InboundError, InboundBundle, Socks5Bindings},
        outbound::{Error as OutboundError, OutboundBundle, TcpDirectBindings},
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
        #[arg(long, default_value = "alpha", value_parser = ["alpha", "beta"])]
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

#[fundle::bundle]
struct AppBundle {
    #[forward(EndpointAddr, AddrMap, TrustBundle, Socks5Bindings, TcpDirectBindings)]
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

/// A list of SVIDs each paired with a local socket address — SOCKS5 caller
/// principals with their listen addresses, or TCP-direct services with their
/// upstream addresses.
type SvidBindings = Vec<(X509Svid, SocketAddr)>;

/// Demo trust domain — matches `scripts/dev-bootstrap.sh`.
const DEMO_TRUST_DOMAIN: &str = "demo.flor";
/// Directory the dev bootstrap mints CA + SVID material into.
const DEV_DIR: &str = ".flor-dev";

/// Read a file under `.flor-dev/`, with a hint to run the bootstrap if it's missing.
fn read_dev_file(rel: &std::path::Path) -> Result<Vec<u8>, Report<Error>> {
    let path = PathBuf::from(DEV_DIR).join(rel);
    std::fs::read(&path).change_context_lazy(|| {
        Error(format!(
            "Failed to read {}; run scripts/dev-bootstrap.sh to mint dev material",
            path.display()
        ))
    })
}

/// Load a node's principal SVID from `.flor-dev/<node>/<name>.{crt,key}`.
fn load_dev_svid(node: &str, name: &str) -> Result<X509Svid, Report<Error>> {
    let cert = read_dev_file(&PathBuf::from(node).join(format!("{name}.crt")))?;
    let key = read_dev_file(&PathBuf::from(node).join(format!("{name}.key")))?;
    load_svid_from_pem(&cert, &key)
        .change_context(Error(format!("Failed to load SVID for '{node}/{name}'")))
}

/// Load the rete trust bundle from `.flor-dev/ca.crt`.
fn load_dev_bundle(td: &TrustDomain) -> Result<X509Bundle, Report<Error>> {
    let ca = read_dev_file(std::path::Path::new("ca.crt"))?;
    load_bundle_from_pem(td, &ca).change_context(Error("Failed to load trust bundle".into()))
}

/// A demo node's declarative config: where its QUIC endpoint binds, the SOCKS5
/// principals it proxies for, and the TCP-direct services it serves.
struct NodeConfig {
    quic_addr: SocketAddr,
    /// SOCKS5 caller principals: `(name, local listen address)`.
    socks5: Vec<(&'static str, SocketAddr)>,
    /// TCP-direct services: `(name, local upstream address)`.
    services: Vec<(&'static str, SocketAddr)>,
}

fn sock(s: &str) -> SocketAddr {
    s.parse().expect("valid socket address literal")
}

/// Demo topology that matches `scripts/dev-bootstrap.sh`, keyed by node name
fn demo_topology() -> HashMap<&'static str, NodeConfig> {
    HashMap::from([
        (
            "alpha",
            NodeConfig {
                quic_addr: sock("127.0.0.1:31337"),
                socks5: vec![
                    ("alice", sock("127.0.0.1:1080")),
                    ("bob", sock("127.0.0.1:1081")),
                ],
                services: vec![],
            },
        ),
        (
            "beta",
            NodeConfig {
                quic_addr: sock("127.0.0.1:31440"),
                socks5: vec![],
                services: vec![("tcp-echo", sock("127.0.0.1:32450"))],
            },
        ),
    ])
}

/// Load this node's own SVIDs for a set of `(name, local addr)` entries, pairing
/// each loaded SVID with its address.
fn load_node_svids(
    node: &str,
    entries: &[(&str, SocketAddr)],
) -> Result<SvidBindings, Report<Error>> {
    entries
        .iter()
        .map(|(name, addr)| Ok((load_dev_svid(node, name)?, *addr)))
        .collect()
}

/// The SVIDs' SPIFFE IDs, comma-joined (the addresses are ignored).
fn principals(bindings: &SvidBindings) -> String {
    bindings
        .iter()
        .map(|(svid, _)| svid.spiffe_id().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

async fn demo_main(node: String) -> Result<(), Report<Error>> {
    let td = TrustDomain::new(DEMO_TRUST_DOMAIN)
        .change_context(Error("Invalid demo trust domain".into()))?;

    let topology = demo_topology();
    let config = topology
        .get(node.as_str())
        .ok_or_else(|| Report::new(Error(format!("Unknown demo node '{node}'"))))?;

    // Every service in the topology is a dialable target → its node's address.
    let mut addr_map = HashMap::new();
    for (host, cfg) in &topology {
        for (svc, _upstream) in &cfg.services {
            let id = build_id_on_node(&td, NodeScopableKind::Service, host, svc).change_context(
                Error(format!("Failed to build identity for service '{svc}'")),
            )?;
            addr_map.insert(id, cfg.quic_addr);
        }
    }

    let trust_bundle = Arc::new(load_dev_bundle(&td)?);

    // Load this node's own principal/service SVIDs from its `.flor-dev/<node>/` dir.
    let socks5_bindings = load_node_svids(&node, &config.socks5)?;
    let tcp_direct_bindings = load_node_svids(&node, &config.services)?;

    log::info!(
        "Node '{node}' bound to {}. SOCKS5 principals: {}. TCP services: {}.",
        config.quic_addr,
        principals(&socks5_bindings),
        principals(&tcp_direct_bindings),
    );

    let bundle_err = || Error("Failed to build app bundle".into());
    let app: AppBundle = AppBundle::builder()
        .config(|_| AppConfigBundle {
            endpoint_addr: EndpointAddr(config.quic_addr),
            addr_map: AddrMap(addr_map.clone()),
            trust_bundle: TrustBundle(trust_bundle.clone()),
            socks5_bindings: Socks5Bindings(socks5_bindings.clone()),
            tcp_direct_bindings: TcpDirectBindings(tcp_direct_bindings.clone()),
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
