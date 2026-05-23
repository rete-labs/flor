// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use clap::{Args as ClapArgs, Parser, Subcommand};
use error_stack::{Report, ResultExt};

use flor::{
    AddrMap, AppConfigBundle, EndpointAddr, Socks5Addr, TcpDirectTargets,
    cli::{print_error, write_secret},
    core::{
        identity::{Kind, TrustDomain, build_id, keygen_csr},
        transport::{
            QuicConnector, QuicPublisher, TransportBundle,
            endpoint::connection::{Accept, Open},
        },
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
        /// Select node config: Alpha, Beta, Gamma, or Delta
        #[arg(long, default_value = "Alpha", value_parser = ["Alpha", "Beta", "Gamma", "Delta"])]
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
    #[forward(EndpointAddr, AddrMap, Option<Socks5Addr>, TcpDirectTargets)]
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
    // Node configuration: (quic_addr, demo_served_workloads, socks5_addr, tcp_direct_targets)
    let service_map = HashMap::from([
        (
            "Alpha",
            (
                "127.0.0.1:31337".parse::<SocketAddr>().unwrap(),
                vec!["alice", "eve"],
                Some("127.0.0.1:1080".parse::<SocketAddr>().unwrap()),
                HashMap::new(),
            ),
        ),
        (
            "Beta",
            (
                "127.0.0.1:31338".parse::<SocketAddr>().unwrap(),
                vec!["bob"],
                None,
                HashMap::new(),
            ),
        ),
        (
            "Gamma",
            (
                "127.0.0.1:31339".parse::<SocketAddr>().unwrap(),
                vec!["carol"],
                None,
                HashMap::new(),
            ),
        ),
        (
            "Delta",
            (
                "127.0.0.1:31440".parse::<SocketAddr>().unwrap(),
                vec![],
                None,
                HashMap::from([(
                    "tcp-echo.demo.flor.local".to_string(),
                    "127.0.0.1:32440".parse::<SocketAddr>().unwrap(),
                )]),
            ),
        ),
    ]);
    // Directed workload connections: (client, server)
    let conn_list = vec![
        ("alice", "bob"),
        ("carol", "bob"),
        ("eve", "tcp-echo.demo.flor.local"),
    ];

    // Get current node config
    let (local_addr, served, socks5_addr, tcp_direct_targets) = service_map
        .get(node_name.as_str())
        .ok_or_else(|| Report::new(Error("Node not found in predefined service map".into())))?;

    log::info!(
        "Node '{}' bound to {} serving workloads: {}",
        node_name,
        local_addr,
        served.join(", ")
    );

    // For each service a node hosts, emit (service_name, node_addr)
    let addr_map: HashMap<String, SocketAddr> = service_map
        .iter()
        .flat_map(|(_node, (addr, services, _socks5, tcp_targets))| {
            let demo_services = services.iter().map(move |svc| (svc.to_string(), *addr));
            let tcp_direct_services = tcp_targets.keys().map(move |svc| (svc.to_string(), *addr));

            demo_services.chain(tcp_direct_services).collect::<Vec<_>>()
        })
        .collect();

    let served_names: Vec<String> = served.iter().map(|s| s.to_string()).collect();

    let bundle_err = || Error("Failed to build app bundle".into());
    let app: AppBundle = AppBundle::builder()
        .config(|_| AppConfigBundle {
            endpoint_addr: EndpointAddr(*local_addr),
            addr_map: AddrMap(addr_map.clone()),
            socks5_addr: socks5_addr.map(Socks5Addr),
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

    let acceptor_handle = if served_names.is_empty() {
        None
    } else {
        let mut acceptor = app
            .transport
            .endpoint_publisher
            .publish(served_names.clone())
            .await
            .change_context(Error("Failed to publish served services".into()))?;
        Some(tokio::spawn(async move {
            while let Some((service_name, conn)) = acceptor.accept().await {
                tokio::spawn(handle_connection(service_name, conn));
            }
        }))
    };

    // Fire-and-forget client connections; server keeps the process alive
    for (src, dst) in &conn_list {
        if served_names.contains(&src.to_string()) {
            let connector = app.transport.endpoint_connector.clone();
            let src = src.to_string();
            let dst = dst.to_string();
            tokio::spawn(async move {
                if let Err(e) = initiate_connection(&connector, &src, &dst).await {
                    log::error!("Connection {}=>{} failed: {:?}", src, dst, e);
                }
            });
        }
    }

    let endpoint_handle = app.transport.endpoint_handle;
    let socks5_handle = app.inbound.socks5_handle;
    let tcp_direct_handle = app.outbound.tcp_direct_handle;

    tokio::select! {
        result = async {
            match acceptor_handle {
                Some(h) => h.await,
                None => std::future::pending().await,
            }
        } => {
            if let Err(e) = result {
                log::error!("Acceptor task failed: {e:?}");
            }
        }
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

async fn handle_connection<C: Accept>(service_name: String, conn: C) {
    loop {
        // Accept a new bidirectional stream
        let stream = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                // Connection closed or error: exit the loop
                log::debug!("Stream accept error for {}: {:?}", service_name, e);
                break;
            }
        };

        let (mut send, mut recv) = stream;
        let mut buf = vec![0u8; 1024];

        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                // Successfully read n bytes
                let msg = String::from_utf8_lossy(&buf[..n]);
                log::info!("< [{}] {}", service_name, msg);

                let reply = format!("{} reporting!", service_name);
                if let Err(e) = send.write_all(reply.as_bytes()).await {
                    log::warn!("Failed to send reply to {}: {:?}", service_name, e);
                    // Continue: connection may still be usable for other streams
                } else {
                    log::info!("> [{}] {}", service_name, reply);
                }

                // Signal that we're done sending on this stream
                // Client may still send more streams on the same connection
                if let Err(_closed) = send.finish() {
                    log::warn!("Failed to finish stream to {service_name}");
                }
            }
            Ok(None) => {
                // Stream closed gracefully by peer
                log::debug!("Stream closed by peer for {}", service_name);
                // Continue: connection may have more streams
            }
            Err(e) => {
                // Read error: log and continue accepting streams
                log::debug!("Read error for {}: {:?}", service_name, e);
                // Don't break: connection might still accept new streams
            }
        }
    }
}

async fn initiate_connection(
    connector: &QuicConnector,
    src: &str,
    dst: &str,
) -> Result<(), Report<Error>> {
    // Establish connection to destination service
    let conn = connector
        .connect(dst)
        .await
        .change_context(Error(format!("Failed to connect to {dst}")))?;

    // Open a new bidirectional stream
    let (mut send, mut recv) = conn.open_bi().await.change_context(Error(format!(
        "Failed to open bidirectional stream to {dst}"
    )))?;

    // Send hello message
    let hello = format!("Hello from {src}");
    send.write_all(hello.as_bytes())
        .await
        .change_context(Error(format!("Failed to write hello message to {dst}")))?;
    log::info!("> [{}] {}", src, hello);

    // Signal we're done sending on this stream
    send.finish()
        .change_context(Error(format!("Failed to finish send stream to {dst}")))?;

    let mut buf = vec![0u8; 1024];
    match recv.read(&mut buf).await {
        Ok(Some(n)) => {
            // Successfully received response
            let msg = String::from_utf8_lossy(&buf[..n]);
            log::info!("< [{}] {}", dst, msg);
        }
        Ok(None) => {
            // Peer closed stream before sending response
            log::debug!("< [{}] Peer closed stream without response", dst);
        }
        Err(e) => {
            // Read error: log but don't fail the whole operation
            // The hello was already sent successfully
            log::debug!("< [{}] Read error: {:?}", dst, e);
        }
    }
    // Connection will be closed on Drop
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
