// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Custom rustls verifiers that gate the mTLS handshake on the SPIFFE identity
//! in the leaf cert's URI SAN, per [ADR-0006] and [ADR-0007].
//!
//! Three pieces, one per rustls extension point (the "TLS client"/"TLS server"
//! roles below are the handshake roles, distinct from flor's inbound/outbound
//! components):
//!
//! - [`SpiffeServerCertVerifier`] (`ServerCertVerifier`, run by the **TLS client**):
//!   chain-validates the dialed peer's cert against the rete bundle, then requires
//!   the leaf SAN to equal the *expected target* `SpiffeId` the caller passed to
//!   `connect`. The SNI is **not** consulted — SAN is the authoritative gate.
//!   Per-call: the expected target changes every `connect`.
//! - [`SpiffeClientCertVerifier`] (`ClientCertVerifier`, run by the **TLS server**):
//!   wraps `WebPkiClientVerifier` for chain validation against the bundle, then
//!   checks the leaf carries a parseable SPIFFE SAN. The peer's `SpiffeId` is read
//!   later from the connection's `peer_identity()`, not surfaced here.
//! - [`SpiffeResolvesServerCert`] (`ResolvesServerCert`, run by the **TLS server**):
//!   picks which published SVID to present by looking the incoming SNI **string**
//!   up in a [`ServerCertRegistry`] — never by parsing an identity out of SNI.
//!
//! [ADR-0006]: https://florete.tech/docs/implementation/adr/0006-impl-mtls-in-quic-endpoint
//! [ADR-0007]: https://florete.tech/docs/implementation/adr/0007-decouple-naming-identity-routing

use std::fmt;
use std::sync::Arc;

use error_stack::{Report, ResultExt};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        ClientHello, ParsedCertificate, ResolvesServerCert, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};

use crate::core::identity::{SpiffeId, X509Bundle};
use crate::core::transport::Error;

/// Build a rustls [`RootCertStore`] from a rete trust bundle's authorities.
fn roots_from_bundle(bundle: &X509Bundle) -> Result<RootCertStore, Report<Error>> {
    let mut roots = RootCertStore::empty();
    for authority in bundle.authorities() {
        let der = CertificateDer::from(authority.as_bytes().to_vec());
        roots.add(der).change_context(Error(
            "Failed to add a trust-bundle authority to the root store".into(),
        ))?;
    }
    Ok(roots)
}

/// Extract the peer's [`SpiffeId`] from a leaf cert's single URI SAN, mapping a
/// missing/invalid SPIFFE SAN to a rustls verification failure.
///
/// Reuses `spiffe::cert::spiffe_id_from_der`, which enforces exactly one URI SAN
/// that parses as a SPIFFE ID — the same extraction the rest of the stack uses.
fn peer_spiffe_id(cert: &CertificateDer<'_>) -> Result<SpiffeId, rustls::Error> {
    spiffe::cert::spiffe_id_from_der(cert.as_ref()).map_err(|_| {
        rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
    })
}

/// The ring-backed crypto provider used for signature verification.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// ---------------------------------------------------------------------------
// SpiffeServerCertVerifier (TLS client — validates the peer we dialed)
// ---------------------------------------------------------------------------

/// Verifies the peer end of an mTLS connection we initiated: the cert chain must
/// validate against the rete bundle **and** the leaf SAN must equal the expected
/// target. Constructed per `connect` because `expected` is per-call.
#[derive(Debug)]
pub struct SpiffeServerCertVerifier {
    roots: RootCertStore,
    expected: SpiffeId,
    provider: Arc<CryptoProvider>,
}

impl SpiffeServerCertVerifier {
    /// Verify the dialed server against `bundle`, requiring its leaf SAN to be
    /// `expected` (the `SpiffeId` the caller asked `connect` to reach).
    pub fn new(bundle: &X509Bundle, expected: SpiffeId) -> Result<Self, Report<Error>> {
        Ok(Self {
            roots: roots_from_bundle(bundle)?,
            expected,
            provider: provider(),
        })
    }
}

impl ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        // SNI is a routing hint only (ADR-0007); the SAN below is the real gate.
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;

        let peer = peer_spiffe_id(end_entity)?;
        if peer != self.expected {
            // The chain is valid but for a different identity than we dialed.
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// SpiffeClientCertVerifier (TLS server — validates the peer that dialed us)
// ---------------------------------------------------------------------------

/// Verifies the peer that initiated an mTLS connection to us: delegates chain
/// validation to `WebPkiClientVerifier` over the rete bundle, then requires the
/// leaf to carry a parseable SPIFFE SAN. The peer identity itself is read later
/// from `peer_identity()` (ADR-0006).
#[derive(Debug)]
pub struct SpiffeClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
}

impl SpiffeClientCertVerifier {
    /// Build a verifier that accepts client certs chaining to `bundle`'s authorities.
    pub fn new(bundle: &X509Bundle) -> Result<Self, Report<Error>> {
        let roots = Arc::new(roots_from_bundle(bundle)?);
        let inner = WebPkiClientVerifier::builder(roots)
            .build()
            .change_context(Error("Failed to build client-cert verifier".into()))?;
        Ok(Self { inner })
    }
}

impl ClientCertVerifier for SpiffeClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        // Chain is valid; reject a peer whose leaf carries no SPIFFE identity.
        peer_spiffe_id(end_entity)?;
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// SpiffeResolvesServerCert (server side — picks which SVID to present)
// ---------------------------------------------------------------------------

/// The published-cert lookup the endpoint's registry implements. Keyed by the
/// SNI routing label (`sni_for(svid.spiffe_id())`); returns the cert to present,
/// or `None` for an unknown/unpublished SNI.
pub trait ServerCertRegistry: Send + Sync + fmt::Debug {
    /// The cert to present for `sni`, or `None` if nothing is published for it.
    fn cert_for_sni(&self, sni: &str) -> Option<Arc<CertifiedKey>>;
}

/// Picks the server cert by looking the incoming SNI up in the published-cert
/// registry — by lookup, never by parsing an identity out of SNI (ADR-0007).
#[derive(Debug)]
pub struct SpiffeResolvesServerCert {
    registry: Arc<dyn ServerCertRegistry>,
}

impl SpiffeResolvesServerCert {
    pub fn new(registry: Arc<dyn ServerCertRegistry>) -> Self {
        Self { registry }
    }
}

impl ResolvesServerCert for SpiffeResolvesServerCert {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // No SNI, or nothing published for it ⇒ no cert ⇒ handshake fails.
        let sni = client_hello.server_name()?;
        self.registry.cert_for_sni(sni)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustls::pki_types::UnixTime;

    use super::*;
    use crate::core::identity::{
        Ca, Kind, SpiffeId, TrustDomain, keygen_csr, load_bundle_from_pem,
    };

    fn td() -> TrustDomain {
        TrustDomain::new("demo.flor").unwrap()
    }

    fn day() -> Duration {
        Duration::from_secs(24 * 3600)
    }

    /// PEM → single DER cert body.
    fn pem_to_der(pem: &str) -> CertificateDer<'static> {
        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        CertificateDer::from(p.contents)
    }

    /// A CA plus a leaf cert (DER) it signed for `uri`/`kind`.
    fn ca_and_leaf(uri: &str, kind: Kind) -> (Ca, CertificateDer<'static>) {
        let ca = Ca::init(&td(), day()).unwrap();
        let id = SpiffeId::new(uri).unwrap();
        let (_k, csr) = keygen_csr(&id).unwrap();
        let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
        (ca, pem_to_der(&leaf))
    }

    fn bundle_of(ca: &Ca) -> X509Bundle {
        load_bundle_from_pem(&td(), ca.cert_pem().as_bytes()).unwrap()
    }

    fn now() -> UnixTime {
        UnixTime::now()
    }

    // --- SpiffeServerCertVerifier ---------------------------------------------

    #[test]
    fn server_verifier_accepts_expected_target_signed_by_bundle() {
        let (ca, leaf) = ca_and_leaf("spiffe://demo.flor/service/api", Kind::Service);
        let expected = SpiffeId::new("spiffe://demo.flor/service/api").unwrap();
        let v = SpiffeServerCertVerifier::new(&bundle_of(&ca), expected).unwrap();
        v.verify_server_cert(
            &leaf,
            &[],
            &ServerName::try_from("api.demo.flor.rete").unwrap(),
            &[],
            now(),
        )
        .expect("good cert with matching SAN accepted");
    }

    #[test]
    fn server_verifier_rejects_wrong_ca() {
        let (_ca, leaf) = ca_and_leaf("spiffe://demo.flor/service/api", Kind::Service);
        // Bundle from a *different* CA — chain validation must fail.
        let other_ca = Ca::init(&td(), day()).unwrap();
        let expected = SpiffeId::new("spiffe://demo.flor/service/api").unwrap();
        let v = SpiffeServerCertVerifier::new(&bundle_of(&other_ca), expected).unwrap();
        let err = v
            .verify_server_cert(
                &leaf,
                &[],
                &ServerName::try_from("api.demo.flor.rete").unwrap(),
                &[],
                now(),
            )
            .unwrap_err();
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "{err:?}"
        );
    }

    #[test]
    fn server_verifier_rejects_san_not_expected_target() {
        let (ca, leaf) = ca_and_leaf("spiffe://demo.flor/service/api", Kind::Service);
        // Chain is fine, but we expected a different identity than the leaf's SAN.
        let expected = SpiffeId::new("spiffe://demo.flor/service/db").unwrap();
        let v = SpiffeServerCertVerifier::new(&bundle_of(&ca), expected).unwrap();
        let err = v
            .verify_server_cert(
                &leaf,
                &[],
                &ServerName::try_from("db.demo.flor.rete").unwrap(),
                &[],
                now(),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
            ),
            "{err:?}"
        );
    }

    // --- SpiffeClientCertVerifier -----------------------------------------

    #[test]
    fn client_verifier_accepts_peer_signed_by_bundle() {
        let (ca, leaf) = ca_and_leaf("spiffe://demo.flor/user/alice", Kind::User);
        let v = SpiffeClientCertVerifier::new(&bundle_of(&ca)).unwrap();
        v.verify_client_cert(&leaf, &[], now())
            .expect("peer cert chaining to the bundle accepted");
    }

    #[test]
    fn client_verifier_rejects_wrong_ca() {
        let (_ca, leaf) = ca_and_leaf("spiffe://demo.flor/user/alice", Kind::User);
        let other_ca = Ca::init(&td(), day()).unwrap();
        let v = SpiffeClientCertVerifier::new(&bundle_of(&other_ca)).unwrap();
        let err = v.verify_client_cert(&leaf, &[], now()).unwrap_err();
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "{err:?}"
        );
    }

    // --- peer_spiffe_id (missing-SAN branch) ------------------------------

    #[test]
    fn peer_spiffe_id_rejects_cert_without_spiffe_san() {
        // A self-signed cert whose only SAN is a DNS name, not a SPIFFE URI.
        let cert = rcgen::generate_simple_self_signed(vec!["example.rete".to_string()]).unwrap();
        let der = CertificateDer::from(cert.cert);
        let err = peer_spiffe_id(&der).unwrap_err();
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
            ),
            "{err:?}"
        );
    }

    // `SpiffeResolvesServerCert::resolve` is two lines — read the SNI off the
    // `ClientHello`, delegate to the registry. A `ClientHello` can't be built
    // outside rustls's handshake, so there's nothing to unit-test here without
    // mocking the registry (which would only test the mock); it's covered by the
    // end-to-end mTLS flow.
}
