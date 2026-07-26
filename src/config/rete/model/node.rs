// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::net::SocketAddr;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub vertices: Vec<Vertex>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vertex {
    pub name: String,
    pub kind: VertexKind,
    #[serde(rename = "type")]
    pub vertex_type: VertexType,
    /// Where peers reach this vertex, and what it binds — the compiler uses it
    /// as authored for both, so it must be an address the node can bind.
    /// Absent on initiator-only nodes.
    pub address: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VertexKind {
    Link,
    Mesh,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VertexType {
    Quic,
    Udp,
}
