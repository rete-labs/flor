// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// Node this service runs on.
    pub at: String,
    /// Vertex on that node (optional when node has exactly one vertex).
    pub via: Option<String>,
    /// Local address the service binds to; flor forwards here.
    pub addr: String,
    /// SOCKS5 port flor exposes for this service's outbound calls.
    pub socks5_proxy: Option<String>,
    /// Groups this service belongs to (ingress ACL — who may reach it).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Roles this service holds (egress ACL — what it may call).
    #[serde(default)]
    pub roles: Vec<String>,
    /// Scoping: `rete` (default) or `node`.
    pub scope: Option<ServiceScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceScope {
    Rete,
    Node,
}
