// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The rete's reserved names — a first-class part of the source vocabulary,
//! not a validator implementation detail.
//!
//! Two consumers share them: the [validator](super::validate) pins their
//! canonical `allow` / membership definitions (reserved-name protection,
//! management-node integrity), and the [compiler](crate::config::compile)
//! auto-assigns the reserved `node` role by [`ROLE_NODE`]. Keeping the spellings
//! in one place is what stops those two from drifting.

/// The management-plane coordinator service (in group [`GROUP_COORDINATOR_SYNC`]).
pub(crate) const SVC_COORDINATOR: &str = "coordinator";
/// The coordinator's publish endpoint (in group [`GROUP_COORDINATOR_PUBLISH`]).
pub(crate) const SVC_COORDINATOR_PUBLISHER: &str = "coordinator-publisher";
/// Group gating who may sync from the coordinator; the reserved [`ROLE_NODE`] grants it.
pub(crate) const GROUP_COORDINATOR_SYNC: &str = "coordinator-sync";
/// Group gating who may publish new state; the reserved [`ROLE_OPERATOR`] grants it.
pub(crate) const GROUP_COORDINATOR_PUBLISH: &str = "coordinator-publish";
/// Role every node principal implicitly holds — reaches the coordinator to sync.
pub(crate) const ROLE_NODE: &str = "node";
/// Role that may push new rete state; at least one user must hold it.
pub(crate) const ROLE_OPERATOR: &str = "operator";
