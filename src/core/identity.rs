// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Florete identity primitives.
//!
//! SPIFFE-native: `SpiffeId` and `TrustDomain` are re-exported directly from the
//! `spiffe` crate. We add a [`Kind`]/[`Scope`] projection over the SPIFFE path so
//! the rest of the code base can reason about principal classes without parsing
//! strings ad hoc.
//!
//! See ADR 0005 in the florete docs for the design rationale.

pub mod ca;
pub mod csr;
pub mod kind;

pub use ca::Ca;
pub use csr::keygen_csr;
pub use kind::{Kind, Scope, kind_of, scope_of};
pub use spiffe::{SpiffeId, TrustDomain};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}
