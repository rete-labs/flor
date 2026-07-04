// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use serde::Deserialize;

use super::{Group, Node, Rete, Role, Service, Source, UniqueMap, User};

/// The shape of a single YAML source file.
///
/// Any file may contain any subset of the top-level collections.
/// `deny_unknown_fields` rejects typo'd keys (e.g. `servies:`) at parse time,
/// enforcing that unrecognized top-level keys are a hard error.
/// Collection fields use `UniqueMap` so that a duplicate key within the same
/// file (e.g. two `services.api` entries) is a parse-time error, never a
/// silent last-win.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFragment {
    pub source: Option<Source>,
    pub rete: Option<Rete>,
    pub nodes: Option<UniqueMap<String, Node>>,
    pub services: Option<UniqueMap<String, Service>>,
    pub groups: Option<UniqueMap<String, Option<Group>>>,
    pub roles: Option<UniqueMap<String, Role>>,
    pub users: Option<UniqueMap<String, User>>,
}
