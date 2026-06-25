// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Florete configuration schema.
//!
//! [`artifact`] holds the compiled, signed JSON artifacts that `flor` and the
//! coordinator consume.
//! [`rete`] holds the configuration for the Rete network, including the nodes and
//! their connections.

pub mod artifact;
pub mod rete;
