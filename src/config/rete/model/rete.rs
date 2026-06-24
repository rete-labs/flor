// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rete {
    /// Rete name; doubles as the SPIFFE trust domain.
    pub name: String,

    pub ca: Ca,

    pub signers: Signers,

    pub tls_principals: Option<TlsPrincipals>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Repo-relative include globs; replaces the default discovery set.
    pub include: Option<Vec<String>>,
    /// Repo-relative exclude globs; subtracted after include.
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ca {
    pub cert: PathBuf,
    pub validity_days: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signers {
    pub mgmt: MgmtSigners,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MgmtSigners {
    pub validity_days: Option<u32>,
    pub keys: Vec<SignerKey>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerKey {
    pub name: String,
    pub cert: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsPrincipals {
    pub validity_days: Option<u32>,
}
