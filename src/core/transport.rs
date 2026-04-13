// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

pub mod endpoint;
pub mod resolver;
pub mod udp_resolver;

mod insecure_server_verifier;

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

pub use endpoint::QuicEndpoint;
pub use udp_resolver::UdpResolver;

use crate::core::transport::resolver::Resolver;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

#[fundle::bundle]
pub struct TransportModule {
    pub resolver: Arc<dyn Resolver>,
    pub endpoint: Arc<QuicEndpoint>,
}

impl TransportModule {
    pub async fn new(
        local_addr: &SocketAddr,
        served: &Vec<&str>,
        service_map: &HashMap<&str, (SocketAddr, Vec<&str>)>,
    ) -> Result<Self, Error> {
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

        let module = TransportModule::builder()
            .resolver(move |_| Arc::new(UdpResolver::new(addr_map.clone())))
            .endpoint_try_async(async |builder| {
                // Bind UDP socket
                let socket = tokio::net::UdpSocket::bind(local_addr)
                    .await
                    .map_err(|_| Error("Failed to bind UDP socket".into()))?
                    .into_std()
                    .map_err(|_| Error("Failed to convert UDP socket to std".into()))?;

                let endpoint = QuicEndpoint::new(
                    served.iter().map(|s| s.to_string()).collect(),
                    builder.resolver().clone(),
                    socket,
                )
                .map_err(|_| Error("Failed to create endpoint".into()))?;
                Ok(Arc::new(endpoint))
            })
            .await?
            .build();
        Ok(module)
    }
}
