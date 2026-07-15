// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Schema-version compatibility gate for compiled artifacts.
//!
//! `schema_version` is the `major.minor` version of the artifact contract. A
//! consumer gates every artifact against the version *it* understands
//! ([`SCHEMA_MAJOR`]/[`SCHEMA_MINOR`]), with deliberately **one-directional,
//! fail-closed** compatibility:
//!
//! - A **different major** is incompatible in either direction — reject.
//! - A **newer minor** than this build knows is rejected (asking the operator
//!   to upgrade flor), *not* silently accepted. Combined with the envelope's
//!   `deny_unknown_fields`, a newer producer can only add fields under a version
//!   bump; ignoring them would risk dropping a restriction the newer schema
//!   introduced (a security artifact must fail *closed*, never open).
//! - An **older-or-equal minor** within the known major is accepted, so a newer
//!   flor keeps reading older artifacts — the direction rolling upgrades need.
//!
//! Evolution is therefore: teach flor the new fields, then bump
//! [`SCHEMA_MINOR`]. That build reads both the old and the new minor; nodes
//! still on the old build reject the new artifact with a clear upgrade error
//! instead of misinterpreting it.
//!
//! This gate is the consumer half of the contract-wide policy in ADR-0012
//! (Version the Compiled-Artifact Contract): one `schema_version` covers every
//! `(plane, kind)` artifact, and producers stamp each artifact with the
//! *lowest* minor its content actually uses — never their newest — so skew
//! bites only nodes a new construct actually touches. How skew is then managed
//! differs per plane (mgmt rolls out consumers-first; the B1+ ctrl producer
//! emits within each consumer's advertised ceiling; relays never gate) — see
//! the ADR.

use error_stack::{Report, bail};
use serde::Deserialize;

use super::Error;

/// Major version of the compiled-artifact contract this build understands.
/// A different major is incompatible.
pub const SCHEMA_MAJOR: u64 = 1;

/// Highest minor of [`SCHEMA_MAJOR`] this build understands. Older-or-equal
/// minors are accepted; a newer minor is rejected (fail-closed).
pub const SCHEMA_MINOR: u64 = 0;

/// A parsed `major.minor` schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchemaVersion {
    major: u64,
    minor: u64,
}

impl SchemaVersion {
    fn parse(s: &str) -> Result<Self, Report<Error>> {
        let mut parts = s.split('.');
        let (Some(major), Some(minor), None) = (parts.next(), parts.next(), parts.next()) else {
            bail!(Error::new(format!(
                "Malformed schema_version {s:?}; expected \"MAJOR.MINOR\""
            )));
        };
        let parse_component = |part: &str, which: &str| {
            part.parse::<u64>().map_err(|_| {
                Report::new(Error::new(format!(
                    "Malformed schema_version {s:?}; {which} is not a number"
                )))
            })
        };
        Ok(Self {
            major: parse_component(major, "major")?,
            minor: parse_component(minor, "minor")?,
        })
    }
}

/// Check a `schema_version` string against what this build can consume, per the
/// module's fail-closed policy.
pub fn ensure_supported(schema_version: &str) -> Result<(), Report<Error>> {
    ensure_supported_against(schema_version, SCHEMA_MAJOR, SCHEMA_MINOR)
}

/// [`ensure_supported`] against an explicit reference version, so the policy is
/// testable at minors this build doesn't (yet) sit at.
fn ensure_supported_against(
    schema_version: &str,
    major: u64,
    minor: u64,
) -> Result<(), Report<Error>> {
    let v = SchemaVersion::parse(schema_version)?;
    if v.major != major {
        bail!(Error::new(format!(
            "Unsupported schema_version {schema_version:?}: this flor speaks the \
             {major}.x artifact contract, and major {} is incompatible",
            v.major
        )));
    }
    if v.minor > minor {
        bail!(Error::new(format!(
            "Unsupported schema_version {schema_version:?}: this flor understands \
             up to {major}.{minor} — upgrade flor to consume it"
        )));
    }
    Ok(())
}

/// Extracts a `schema_version` from raw artifact bytes and, if one is present,
/// checks it with [`ensure_supported`] — erroring on an unsupported version.
///
/// Best-effort by design, so it does not on its own guarantee a supported
/// version: if the bytes don't parse as JSON or carry no `schema_version`, it
/// returns `Ok` rather than an error.
pub fn precheck_schema_version(bytes: &[u8]) -> Result<(), Report<Error>> {
    #[derive(Deserialize)]
    struct Probe {
        schema_version: String,
    }
    match serde_json::from_slice::<Probe>(bytes) {
        Ok(probe) => ensure_supported(&probe.schema_version),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_current_version() {
        ensure_supported("1.0").unwrap();
    }

    #[test]
    fn accepts_older_and_equal_minors_within_the_major() {
        // A build that knows 1.2 reads 1.0/1.1/1.2 (rolling-upgrade direction).
        ensure_supported_against("1.0", 1, 2).unwrap();
        ensure_supported_against("1.1", 1, 2).unwrap();
        ensure_supported_against("1.2", 1, 2).unwrap();
    }

    #[test]
    fn rejects_a_newer_minor() {
        let err = ensure_supported_against("1.1", 1, 0).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("schema_version"), "{msg}");
        assert!(msg.contains("upgrade"), "{msg}");
    }

    #[test]
    fn rejects_a_different_major() {
        for (v, refm, refn) in [("2.0", 1, 0), ("0.9", 1, 0)] {
            let err = ensure_supported_against(v, refm, refn).unwrap_err();
            assert!(format!("{err:?}").contains("incompatible"), "{v}: {err:?}");
        }
    }

    #[test]
    fn rejects_malformed_versions() {
        for v in ["1", "1.0.0", "x.y", "1.x", "", "1."] {
            let err = ensure_supported(v).unwrap_err();
            assert!(
                format!("{err:?}").contains("Malformed schema_version"),
                "{v:?}: {err:?}"
            );
        }
    }

    #[test]
    fn probe_gates_bytes_by_version() {
        // Valid JSON with an unsupported version → clean upgrade error.
        let bytes = br#"{ "schema_version": "2.0", "other": true }"#;
        assert!(precheck_schema_version(bytes).is_err());

        // Valid JSON at a supported version → ok (ignores other fields).
        let bytes = br#"{ "schema_version": "1.0", "other": true }"#;
        precheck_schema_version(bytes).unwrap();

        // No schema_version / not JSON → defer to the strict parse (Ok here).
        precheck_schema_version(br#"{ "no_version": true }"#).unwrap();
        precheck_schema_version(b"not json at all").unwrap();
    }
}
