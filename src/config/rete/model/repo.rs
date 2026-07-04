// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::collections::HashMap;

use super::{Group, Node, Rete, Role, Service, User};

/// The merged whole-view of a rete config repository.
///
/// All collections are unioned from every source file; the `rete` block is
/// the single canonical rete metadata entry.
#[derive(Debug)]
pub struct RepoModel {
    pub rete: Rete,
    pub nodes: HashMap<String, Node>,
    pub services: HashMap<String, Service>,
    pub groups: HashMap<String, Option<Group>>,
    pub roles: HashMap<String, Role>,
    pub users: HashMap<String, User>,
}
