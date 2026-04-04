use std::{collections::HashMap, net::SocketAddr};

use async_trait::async_trait;
use error_stack::Report;

use super::{Error, resolver::Resolver};

/// Simple UDP resolver that maintains star-like topology
pub struct UdpResolver {
    // Maps service name to UDP socket (host:port)
    addr_map: HashMap<String, SocketAddr>,
}

impl UdpResolver {
    pub fn new(addr_map: HashMap<String, SocketAddr>) -> Self {
        Self { addr_map }
    }
}

#[async_trait]
impl Resolver for UdpResolver {
    async fn resolve(&self, name: &str) -> Result<SocketAddr, Report<Error>> {
        self.addr_map
            .get(name)
            .copied()
            .ok_or_else(|| Report::new(Error::from(format!("Service not found: {name}"))))
    }
}
