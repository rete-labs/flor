// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Roles this user holds.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Devices where this user's flor agent runs.
    #[serde(default)]
    pub nodes: Vec<UserNode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserNode {
    /// Host node name.
    pub at: String,
    /// Vertex on that node (optional when node has exactly one vertex).
    pub via: Option<String>,
}
