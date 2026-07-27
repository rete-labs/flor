// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Florete's compiled JSON artifacts — the signed configs exchanged between the
//! operator's compiler (`retectl compile`), `flor`, and (from B1) the
//! Coordinator.
//!
//! The schema ([`model`]) is plain `serde` (de)serialization into typed structs
//! keyed by SPIFFE ID, not a generic object engine: the same types are produced
//! on one side and parsed on the other. Actions over the schema live beside it
//! — currently [`validate`]. See ADR-0010 (object model).

pub mod model;
pub mod validate;
pub mod version;

pub use model::{Envelope, Payload, Plane, PlaneTag, Signature, VertexKind, VertexMgmtPayload};
pub use validate::Expect;

/// An artifact validation or resolution failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}
