// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr};

use async_trait::async_trait;
use error_stack::Report;

use super::{Error, resolver::Resolver};
use crate::core::identity::SpiffeId;

/// Simple UDP resolver that maintains star-like topology.
pub struct UdpResolver {
    // Maps a target identity to its node's UDP socket (host:port).
    addr_map: HashMap<SpiffeId, SocketAddr>,
}

impl UdpResolver {
    pub fn new(addr_map: HashMap<SpiffeId, SocketAddr>) -> Self {
        Self { addr_map }
    }
}

#[async_trait]
impl Resolver for UdpResolver {
    async fn resolve(&self, target: &SpiffeId) -> Result<SocketAddr, Report<Error>> {
        self.addr_map
            .get(target)
            .copied()
            .ok_or_else(|| Report::new(Error(format!("Target not found: {target}"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> SpiffeId {
        SpiffeId::new(s).expect("valid SPIFFE ID")
    }

    fn make_resolver() -> UdpResolver {
        let mut addr_map = HashMap::new();
        addr_map.insert(
            id("spiffe://demo.flor/service/a"),
            "127.0.0.1:8080".parse().unwrap(),
        );
        addr_map.insert(
            id("spiffe://demo.flor/service/b"),
            "192.168.1.100:9090".parse().unwrap(),
        );
        addr_map.insert(
            id("spiffe://demo.flor/service/c"),
            "[::1]:7070".parse().unwrap(),
        );
        UdpResolver::new(addr_map)
    }

    #[tokio::test]
    async fn resolve_existing_target() {
        let resolver = make_resolver();
        let result = resolver.resolve(&id("spiffe://demo.flor/service/a")).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_existing_target_ipv6() {
        let resolver = make_resolver();
        let result = resolver.resolve(&id("spiffe://demo.flor/service/c")).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "[::1]:7070".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_nonexistent_target() {
        let resolver = make_resolver();
        let missing = id("spiffe://demo.flor/service/nonexistent");
        let result = resolver.resolve(&missing).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("Target not found: {missing}"))
        );
    }

    #[tokio::test]
    async fn resolve_with_empty_map() {
        let resolver = UdpResolver::new(HashMap::new());
        let result = resolver
            .resolve(&id("spiffe://demo.flor/service/any"))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Target not found"));
    }

    #[tokio::test]
    async fn resolve_multiple_targets() {
        let resolver = make_resolver();

        let result_a = resolver.resolve(&id("spiffe://demo.flor/service/a")).await;
        assert!(result_a.is_ok());
        assert_eq!(result_a.unwrap(), "127.0.0.1:8080".parse().unwrap());

        let result_b = resolver.resolve(&id("spiffe://demo.flor/service/b")).await;
        assert!(result_b.is_ok());
        assert_eq!(result_b.unwrap(), "192.168.1.100:9090".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_distinguishes_scope() {
        // A node-scoped target is a different key than the rete-scoped one.
        let resolver = make_resolver();
        let node_scoped = id("spiffe://demo.flor/service/alpha/a");
        assert!(resolver.resolve(&node_scoped).await.is_err());
    }
}
