// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

pub mod logger;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);
