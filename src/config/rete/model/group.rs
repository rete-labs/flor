// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use serde::Deserialize;

/// Group definition — currently a marker type with no fields in C0.
///
/// Groups may have metadata in later milestones; the null YAML value
/// (`coordinator-sync:` with no body) deserializes to `None` at the call site.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {}
