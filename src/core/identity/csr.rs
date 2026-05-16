// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Keypair + CSR generation for a SPIFFE principal.
//!
//! Produces a fresh Ed25519 keypair (PKCS#8) and a PEM CSR whose only Subject
//! Alternative Name is the principal's SPIFFE URI. The CSR carries no other
//! extensions: the signing CA constructs the final cert's SAN and extension
//! set itself, so any extra extensions in the CSR would be ignored (or
//! rejected). Keeping the CSR minimal is the explicit "CSR is a request, not
//! an authorization" rule (ADR-0005).

use error_stack::{Report, ResultExt};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519, SanType};

use crate::core::identity::{Error, SpiffeId};

/// Generate a fresh Ed25519 keypair and build a CSR whose only SAN is the
/// given SPIFFE URI.
///
/// Returns the generated [`KeyPair`] (caller decides how to persist the private
/// key) and the PEM-encoded CSR ready to be sent to a CA for signing.
pub fn keygen_csr(id: &SpiffeId) -> Result<(KeyPair, String), Report<Error>> {
    let key = KeyPair::generate_for(&PKCS_ED25519)
        .change_context(Error::new("Failed to generate keypair"))?;

    let mut params = CertificateParams::default();
    // Strip the default CN that rcgen inserts; SAN is the only identity carrier.
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names =
        vec![SanType::URI(id.to_string().try_into().change_context(
            Error::new("SPIFFE URI is not a valid IA5String"),
        )?)];

    let csr = params
        .serialize_request(&key)
        .change_context(Error::new("Failed to serialize CSR"))?;
    let pem = csr
        .pem()
        .change_context(Error::new("Failed to PEM-encode CSR"))?;

    Ok((key, pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::CertificateSigningRequestParams;

    #[test]
    fn keygen_csr_round_trips_uri_san() {
        let id = SpiffeId::new("spiffe://demo.flor/service/db").unwrap();
        let (_key, pem) = keygen_csr(&id).unwrap();

        let parsed = CertificateSigningRequestParams::from_pem(&pem).unwrap();
        let sans = &parsed.params.subject_alt_names;
        assert_eq!(sans.len(), 1, "expected exactly one SAN, got {sans:?}");
        match &sans[0] {
            SanType::URI(s) => assert_eq!(s.as_str(), "spiffe://demo.flor/service/db"),
            other => panic!("expected URI SAN, got {other:?}"),
        }
    }

    #[test]
    fn keygen_csr_uses_ed25519() {
        let id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let (key, _) = keygen_csr(&id).unwrap();
        assert_eq!(key.algorithm(), &PKCS_ED25519);
    }

    #[test]
    fn keygen_csr_produces_distinct_keys() {
        let id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let (k1, _) = keygen_csr(&id).unwrap();
        let (k2, _) = keygen_csr(&id).unwrap();
        assert_ne!(k1.serialize_der(), k2.serialize_der());
    }
}
