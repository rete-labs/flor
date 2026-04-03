// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr};

use async_trait::async_trait;
use error_stack::Report;

use super::{Error, resolver::Resolver};

/// Simple UDP resolver that maintains star-like topology.
pub struct UdpResolver {
    // Maps service name to UDP socket (host:port).
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
            .ok_or_else(|| Report::new(Error(format!("Service not found: {name}"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resolver() -> UdpResolver {
        let mut addr_map = HashMap::new();
        addr_map.insert("service_a".to_string(), "127.0.0.1:8080".parse().unwrap());
        addr_map.insert(
            "service_b".to_string(),
            "192.168.1.100:9090".parse().unwrap(),
        );
        addr_map.insert("service_c".to_string(), "[::1]:7070".parse().unwrap());
        UdpResolver::new(addr_map)
    }

    #[tokio::test]
    async fn resolve_existing_service() {
        let resolver = make_resolver();
        let result = resolver.resolve("service_a").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_existing_service_ipv6() {
        let resolver = make_resolver();
        let result = resolver.resolve("service_c").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "[::1]:7070".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_nonexistent_service() {
        let resolver = make_resolver();
        let result = resolver.resolve("nonexistent").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Service not found: nonexistent"));
    }

    #[tokio::test]
    async fn resolve_empty_name() {
        let resolver = make_resolver();
        let result = resolver.resolve("").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Service not found: "));
    }

    #[tokio::test]
    async fn resolve_with_empty_map() {
        let resolver = UdpResolver::new(HashMap::new());
        let result = resolver.resolve("any_service").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Service not found: any_service"));
    }

    #[tokio::test]
    async fn resolve_multiple_services() {
        let resolver = make_resolver();

        let result_a = resolver.resolve("service_a").await;
        assert!(result_a.is_ok());
        assert_eq!(result_a.unwrap(), "127.0.0.1:8080".parse().unwrap());

        let result_b = resolver.resolve("service_b").await;
        assert!(result_b.is_ok());
        assert_eq!(result_b.unwrap(), "192.168.1.100:9090".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_is_case_sensitive() {
        let resolver = make_resolver();
        // "Service_A" should not match "service_a"
        let result = resolver.resolve("Service_A").await;
        assert!(result.is_err());
    }
}
