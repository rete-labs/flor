// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The compiled-artifact schema: the typed structs (and their serde glue) that
//! the wire format deserializes into and the compiler serializes from. Pure
//! data — the actions over it (validation, resolution) live beside this module.
//!
//! Submodules:
//! - [`envelope`] — the generic signed [`Envelope`], `Plane`/`PlaneTag`,
//!   `ArtifactKind`, `Signature`, and the [`Payload`] binding.
//! - [`vertex`] — the vertex payload types and their component structs.
//! - [`sid`] — serde glue for [`SpiffeId`](crate::core::identity::SpiffeId),
//!   which has no native serde impl in `spiffe` 0.15.

pub mod envelope;
pub mod sid;
pub mod vertex;

pub use envelope::{ArtifactKind, Envelope, Payload, Plane, PlaneTag, Signature};
pub use vertex::{VertexKind, VertexMgmtPayload};
