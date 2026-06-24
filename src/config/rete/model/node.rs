// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

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
    /// Listen address; absent on initiator-only nodes.
    pub address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VertexKind {
    Link,
    Mesh,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VertexType {
    Quic,
    Udp,
}
