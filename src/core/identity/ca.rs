// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Cluster root CA: keypair + self-signed cert + signing primitives.
//!
//! One CA per cluster (C0/C1, no intermediate). The CA mints all six principal
//! kinds; the difference between a TLS-capable leaf (`User`/`Service`/`Node`/
//! `Vertex`) and a signing-only leaf (`ControlPlane`/`ManagementPlane`) is the
//! X.509 extension policy applied by [`Ca::sign_csr`] — see ADR-0005.
//!
//! ## CSR is a request, not an authorization
//!
//! [`Ca::sign_csr`] **requires** the CSR to carry exactly one URI SAN, and that
//! URI must match the SPIFFE URI built from the operator-supplied `(kind, id)`
//! pair. Missing, multiple, or mismatched SANs are hard errors. The cert's SAN
//! is built from the operator's flags, not copied from the CSR — the CSR
//! contributes only a public key (verified via its self-signature).

use std::time::Duration;

use error_stack::{Report, ResultExt};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ED25519, SanType,
};
use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;

use crate::core::identity::{Error, Kind, SpiffeId, TrustDomain};

/// A cluster root CA: holds the signing key and self-signed certificate.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_der: CertificateDer<'static>,
    cert_pem: String,
}

impl Ca {
    /// Generate a fresh CA keypair (Ed25519) and self-sign a root certificate
    /// for the given trust domain. The cert's URI SAN is `spiffe://<td>`.
    /// `validity` is the cert's lifetime starting from now; callers pick a
    /// sensible value for their context (operators long-lived, tests short).
    pub fn init(trust_domain: &TrustDomain, validity: Duration) -> Result<Self, Report<Error>> {
        let key = KeyPair::generate_for(&PKCS_ED25519)
            .change_context(Error::new("Failed to generate CA keypair"))?;

        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(
                DnType::CommonName,
                format!("{} Root CA", trust_domain.as_str()),
            );
            dn
        };
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.subject_alt_names = vec![SanType::URI(
            format!("spiffe://{}", trust_domain.as_str())
                .try_into()
                .change_context(Error::new("Trust domain does not form a valid SPIFFE URI"))?,
        )];
        params.not_before = now;
        params.not_after = now + validity;
        params.use_authority_key_identifier_extension = true;

        let cert = params
            .self_signed(&key)
            .change_context(Error::new("Failed to self-sign CA certificate"))?;
        let cert_pem = cert.pem();
        let cert_der = cert.der().clone();
        let issuer = Issuer::new(params, key);

        Ok(Self {
            issuer,
            cert_der,
            cert_pem,
        })
    }

    /// Re-hydrate a CA from on-disk PEM material.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, Report<Error>> {
        let key_pem_str = std::str::from_utf8(key_pem)
            .change_context(Error::new("CA key PEM is not valid UTF-8"))?;
        let cert_pem_str = std::str::from_utf8(cert_pem)
            .change_context(Error::new("CA cert PEM is not valid UTF-8"))?;

        let key = KeyPair::from_pem(key_pem_str)
            .change_context(Error::new("Failed to parse CA keypair from PEM"))?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key)
            .change_context(Error::new("Failed to parse CA certificate from PEM"))?;

        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem)
            .change_context(Error::new("Failed to decode CA certificate PEM block"))?;
        let cert_der = CertificateDer::from(pem.contents);

        Ok(Self {
            issuer,
            cert_der,
            cert_pem: cert_pem_str.to_string(),
        })
    }

    /// The CA certificate in PEM form (safe to publish; contains no secrets).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate in DER form.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The CA's signing keypair. Holds the CA private key — do not persist
    /// alongside the public cert.
    pub fn key(&self) -> &KeyPair {
        self.issuer.key()
    }

    /// Sign a CSR for the principal identified by `id`, applying the
    /// extension policy for `kind`. See module-level docs for the CSR-SAN
    /// validation rule.
    pub fn sign_csr(
        &self,
        csr_pem: &[u8],
        id: &SpiffeId,
        kind: Kind,
        validity: Duration,
    ) -> Result<CertificateDer<'static>, Report<Error>> {
        let csr_pem_str = std::str::from_utf8(csr_pem)
            .change_context(Error::new("CSR PEM is not valid UTF-8"))?;
        let csr = CertificateSigningRequestParams::from_pem(csr_pem_str)
            .change_context(Error::new("Failed to parse or verify CSR"))?;

        let expected_uri = id.to_string();
        let csr_uri = single_uri_san(
            csr.params.subject_alt_names.iter().map(|s| match s {
                SanType::URI(u) => Some(u.as_str()),
                _ => None,
            }),
            "CSR",
        )?;
        if csr_uri != expected_uri {
            return Err(Report::new(Error::new(format!(
                "CSR's SAN does not match operator-supplied identity: \
                 CSR claims {csr_uri:?}, operator authorized {expected_uri:?}",
            ))));
        }

        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names =
            vec![SanType::URI(id.to_string().try_into().change_context(
                Error::new("SPIFFE URI is not a valid IA5String"),
            )?)];
        params.not_before = now;
        params.not_after = now + validity;
        params.use_authority_key_identifier_extension = true;
        apply_kind_policy(&mut params, kind);

        let cert = params
            .signed_by(&csr.public_key, &self.issuer)
            .change_context(Error::new("Failed to issue certificate"))?;
        Ok(cert.der().clone())
    }

    /// Verify a leaf cert was issued by this CA and return its SPIFFE ID.
    ///
    /// Checks the signature against the CA's public key and extracts the
    /// single URI SAN. Does *not* check the validity window — callers that
    /// care should add a clock check.
    pub fn verify(&self, cert: &CertificateDer<'_>) -> Result<SpiffeId, Report<Error>> {
        let (_, ca) = x509_parser::parse_x509_certificate(self.cert_der.as_ref())
            .change_context(Error::new("Failed to parse CA certificate"))?;
        let (_, leaf) = x509_parser::parse_x509_certificate(cert.as_ref())
            .change_context(Error::new("Failed to parse leaf certificate"))?;

        leaf.verify_signature(Some(ca.public_key()))
            .change_context(Error::new(
                "Certificate signature does not verify against this CA",
            ))?;

        let san_ext = leaf
            .subject_alternative_name()
            .change_context(Error::new(
                "Failed to read Subject Alternative Name extension",
            ))?
            .ok_or_else(|| {
                Report::new(Error::new(
                    "Certificate has no Subject Alternative Name extension",
                ))
            })?;

        let uri = single_uri_san(
            san_ext.value.general_names.iter().map(|g| match g {
                x509_parser::extensions::GeneralName::URI(s) => Some(*s),
                _ => None,
            }),
            "Certificate",
        )?;

        SpiffeId::new(uri).change_context(Error::new(format!(
            "Certificate URI SAN {uri:?} is not a valid SPIFFE ID"
        )))
    }
}

/// Extract the sole URI SAN from a stream of SANs.
///
/// `sans` yields `Some(uri)` for each URI-type SAN, `None` for each SAN of
/// any other type. The result is the single URI SAN; any deviation (zero
/// URIs, two URIs, or URI mixed with other SAN types) is an error. `source`
/// names the artifact ("CSR" / "Certificate") for the error message.
fn single_uri_san<'a>(
    sans: impl IntoIterator<Item = Option<&'a str>>,
    source: &str,
) -> Result<&'a str, Report<Error>> {
    let mut uri: Option<&str> = None;
    let mut other_types = 0usize;
    for s in sans {
        match s {
            Some(u) => {
                if uri.is_some() {
                    return Err(Report::new(Error::new(format!(
                        "{source} has more than one URI SAN"
                    ))));
                }
                uri = Some(u);
            }
            None => other_types += 1,
        }
    }
    let uri = uri.ok_or_else(|| Report::new(Error::new(format!("{source} has no URI SAN"))))?;
    if other_types > 0 {
        return Err(Report::new(Error::new(format!(
            "{source} has SANs of types other than URI"
        ))));
    }
    Ok(uri)
}

fn apply_kind_policy(params: &mut CertificateParams, kind: Kind) {
    match kind {
        Kind::User | Kind::Service | Kind::Node | Kind::Vertex => {
            // TLS-capable leaf. `digitalSignature` is required for the TLS
            // CertificateVerify message; `keyEncipherment` covers RSA key
            // transport (harmless for Ed25519/ECDSA).
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
        }
        Kind::ControlPlane | Kind::ManagementPlane => {
            // Signing-only leaf. No EKU → TLS verifiers reject these certs at
            // handshake. Application-layer envelope verifiers accept them.
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::identity::csr::keygen_csr;

    fn td() -> TrustDomain {
        TrustDomain::new("demo.flor").unwrap()
    }

    fn day() -> Duration {
        Duration::from_secs(24 * 3600)
    }

    #[test]
    fn init_produces_self_signed_ca_cert() {
        let ca = Ca::init(&td(), day()).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(ca.cert_der().as_ref()).unwrap();
        assert!(parsed.is_ca());
        parsed.verify_signature(None).unwrap();

        // CA subject CN is descriptive, not just the bare trust domain.
        let subject = parsed.subject().to_string();
        assert!(subject.contains("demo.flor Root CA"), "{subject}");
    }

    #[test]
    fn key_usage_is_critical_on_ca_and_all_leaves() {
        // SPIFFE X.509-SVID spec requires keyUsage critical on SVIDs.
        // rcgen marks keyUsage critical whenever it's present; this test
        // locks that in.
        let ca = Ca::init(&td(), day()).unwrap();
        let (_, ca_parsed) = x509_parser::parse_x509_certificate(ca.cert_der().as_ref()).unwrap();
        let ca_ku = ca_parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
            .expect("CA has keyUsage");
        assert!(ca_ku.critical, "CA keyUsage must be critical");

        for (kind, uri) in [
            (Kind::User, "spiffe://demo.flor/user/alice"),
            (Kind::Service, "spiffe://demo.flor/service/db"),
            (
                Kind::ControlPlane,
                "spiffe://demo.flor/control-plane/primary",
            ),
        ] {
            let id = SpiffeId::new(uri).unwrap();
            let (_k, csr) = keygen_csr(&id).unwrap();
            let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
            let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).unwrap();
            let ku = parsed
                .extensions()
                .iter()
                .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
                .expect("leaf has keyUsage");
            assert!(ku.critical, "{kind:?} keyUsage must be critical");
        }
    }

    #[test]
    fn leaf_san_is_critical_but_ca_san_is_not() {
        // RFC 5280 §4.1.2.6 requires SAN critical when Subject is empty.
        // Our leaves have empty Subject; the CA has a CN.
        let ca = Ca::init(&td(), day()).unwrap();
        let id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let (_k, csr) = keygen_csr(&id).unwrap();
        let leaf = ca.sign_csr(csr.as_bytes(), &id, Kind::User, day()).unwrap();

        let (_, leaf_parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).unwrap();
        let leaf_san = leaf_parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .expect("leaf has SAN");
        assert!(leaf_san.critical, "leaf SAN must be critical");

        let (_, ca_parsed) = x509_parser::parse_x509_certificate(ca.cert_der().as_ref()).unwrap();
        let ca_san = ca_parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .expect("CA has SAN");
        assert!(!ca_san.critical, "CA SAN should not be critical");
    }

    #[test]
    fn round_trip_through_pem() {
        let ca = Ca::init(&td(), day()).unwrap();
        let cert_pem = ca.cert_pem().to_string();
        let key_pem = ca.key().serialize_pem();

        let leaf_id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let (_k, csr_pem) = keygen_csr(&leaf_id).unwrap();
        let leaf_der_a = ca
            .sign_csr(csr_pem.as_bytes(), &leaf_id, Kind::User, day())
            .unwrap();

        let ca2 = Ca::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        // Re-hydrated CA verifies the leaf signed by the original.
        let recovered = ca2.verify(&leaf_der_a).unwrap();
        assert_eq!(recovered, leaf_id);
    }

    #[test]
    fn sign_csr_round_trip_for_every_kind() {
        let ca = Ca::init(&td(), day()).unwrap();
        let cases = [
            (Kind::User, "spiffe://demo.flor/user/alice"),
            (Kind::Service, "spiffe://demo.flor/service/db"),
            (Kind::Node, "spiffe://demo.flor/node/alpha"),
            (Kind::Vertex, "spiffe://demo.flor/vertex/alpha/flor"),
            (
                Kind::ControlPlane,
                "spiffe://demo.flor/control-plane/primary",
            ),
            (
                Kind::ManagementPlane,
                "spiffe://demo.flor/management-plane/primary",
            ),
        ];
        for (kind, uri) in cases {
            let id = SpiffeId::new(uri).unwrap();
            let (_k, csr) = keygen_csr(&id).unwrap();
            let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
            assert_eq!(ca.verify(&leaf).unwrap(), id, "{kind:?}");
        }
    }

    #[test]
    fn tls_kinds_get_serverauth_clientauth_eku() {
        let ca = Ca::init(&td(), day()).unwrap();
        for (kind, uri) in [
            (Kind::User, "spiffe://demo.flor/user/alice"),
            (Kind::Service, "spiffe://demo.flor/service/db"),
            (Kind::Node, "spiffe://demo.flor/node/alpha"),
            (Kind::Vertex, "spiffe://demo.flor/vertex/alpha/flor"),
        ] {
            let id = SpiffeId::new(uri).unwrap();
            let (_k, csr) = keygen_csr(&id).unwrap();
            let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
            let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).unwrap();
            let eku = parsed
                .extended_key_usage()
                .unwrap()
                .expect("EKU extension present")
                .value;
            assert!(eku.server_auth, "{kind:?} missing serverAuth");
            assert!(eku.client_auth, "{kind:?} missing clientAuth");
        }
    }

    #[test]
    fn signing_kinds_have_no_eku() {
        let ca = Ca::init(&td(), day()).unwrap();
        for (kind, uri) in [
            (
                Kind::ControlPlane,
                "spiffe://demo.flor/control-plane/primary",
            ),
            (
                Kind::ManagementPlane,
                "spiffe://demo.flor/management-plane/primary",
            ),
        ] {
            let id = SpiffeId::new(uri).unwrap();
            let (_k, csr) = keygen_csr(&id).unwrap();
            let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
            let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).unwrap();
            assert!(
                parsed.extended_key_usage().unwrap().is_none(),
                "{kind:?} unexpectedly has EKU",
            );
            let ku = parsed.key_usage().unwrap().expect("keyUsage present").value;
            assert!(ku.digital_signature());
            assert!(!ku.key_encipherment());
        }
    }

    #[test]
    fn sign_csr_rejects_mismatched_san() {
        let ca = Ca::init(&td(), day()).unwrap();
        let csr_id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let (_k, csr) = keygen_csr(&csr_id).unwrap();
        let other_id = SpiffeId::new("spiffe://demo.flor/node/alpha").unwrap();
        let err = ca
            .sign_csr(csr.as_bytes(), &other_id, Kind::Node, day())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("does not match operator-supplied identity"),
            "{msg}"
        );
    }

    #[test]
    fn sign_csr_rejects_empty_san() {
        // Build a CSR with no SAN at all.
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

        let ca = Ca::init(&td(), day()).unwrap();
        let id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let err = ca
            .sign_csr(csr_pem.as_bytes(), &id, Kind::User, day())
            .unwrap_err();
        assert!(format!("{err:?}").contains("CSR has no URI SAN"), "{err:?}");
    }

    #[test]
    fn sign_csr_rejects_multiple_sans() {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![
            SanType::URI("spiffe://demo.flor/user/alice".try_into().unwrap()),
            SanType::URI("spiffe://demo.flor/user/mallory".try_into().unwrap()),
        ];
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

        let ca = Ca::init(&td(), day()).unwrap();
        let id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let err = ca
            .sign_csr(csr_pem.as_bytes(), &id, Kind::User, day())
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("more than one URI SAN"),
            "{err:?}",
        );
    }

    #[test]
    fn verify_rejects_cert_signed_by_other_ca() {
        let ca1 = Ca::init(&td(), day()).unwrap();
        let ca2 = Ca::init(&td(), day()).unwrap();
        let id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let (_k, csr) = keygen_csr(&id).unwrap();
        let leaf = ca1
            .sign_csr(csr.as_bytes(), &id, Kind::User, day())
            .unwrap();
        let err = ca2.verify(&leaf).unwrap_err();
        assert!(
            format!("{err:?}").contains("signature does not verify"),
            "{err:?}",
        );
    }
}
