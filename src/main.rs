// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use clap::Parser;
use error_stack::{Report, ResultExt};

use flor::{
    core::transport::{
        QuicEndpoint, UdpResolver,
        endpoint::connection::{Accept, Open},
    },
    logging,
};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

#[derive(Parser, Debug)]
#[command(name = "flor", about = "Florete C1 Demo")]
struct Args {
    /// Select node config: Alpha, Beta, or Gamma
    #[arg(long, default_value = "Alpha", value_parser = ["Alpha", "Beta", "Gamma"])]
    name: String,
}

#[tokio::main]
async fn main() {
    logging::logger::init(log::LevelFilter::Info).expect("Failed to initialize logger");

    if let Err(e) = run().await {
        log::error!("Application failed: {e:?}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Report<Error>> {
    let args = Args::parse();
    let node_name = args.name;

    // Initial version uses workload names instead of identities.
    // Node configuration: which workloads are hosted at them
    let service_map = HashMap::from([
        (
            "Alpha",
            (
                "127.0.0.1:31337".parse::<SocketAddr>().unwrap(),
                vec!["alice"],
            ),
        ),
        (
            "Beta",
            (
                "127.0.0.1:31338".parse::<SocketAddr>().unwrap(),
                vec!["bob"],
            ),
        ),
        (
            "Gamma",
            (
                "127.0.0.1:31339".parse::<SocketAddr>().unwrap(),
                vec!["carol"],
            ),
        ),
    ]);
    // Directed workload connections: (client, server)
    let conn_list = vec![("alice", "bob"), ("carol", "bob")];

    // Get current node config
    let (local_addr, served) = service_map
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
        .flat_map(|(_node, (addr, services))| {
            services
                .iter()
                .map(move |svc| (svc.to_string(), *addr))
                .collect::<Vec<_>>()
        })
        .collect();
    let resolver = UdpResolver::new(addr_map);

    // Bind UDP socket
    let socket = tokio::net::UdpSocket::bind(local_addr)
        .await
        .change_context(Error("Failed to bind UDP socket".into()))?
        .into_std()
        .change_context(Error("Failed to convert UDP socket to std".into()))?;

    let endpoint = QuicEndpoint::new(
        served.iter().map(|s| s.to_string()).collect(),
        Arc::new(resolver),
        socket,
    )
    .change_context(Error("Failed to create endpoint".into()))?;

    let server_handle = tokio::spawn({
        let ep = endpoint.clone();
        async move {
            while let Some((service_name, conn)) = ep.accept().await {
                tokio::spawn(handle_connection(service_name, conn));
            }
        }
    });

    // Fire-and-forget client connections; server keeps the process alive
    for (src, dst) in &conn_list {
        if served.contains(src) {
            let ep = endpoint.clone();
            let src = src.to_string();
            let dst = dst.to_string();
            tokio::spawn(async move {
                if let Err(e) = initiate_connection(&ep, &src, &dst).await {
                    log::error!("Connection {}=>{} failed: {:?}", src, dst, e);
                }
            });
        }
    }

    let _ = server_handle.await;

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

async fn initiate_connection(ep: &QuicEndpoint, src: &str, dst: &str) -> Result<(), Report<Error>> {
    // Establish connection to destination service
    let conn = ep
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
