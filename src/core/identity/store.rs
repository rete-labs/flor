// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The per-scope **identity store**: the one module that knows where a node
//! keeps its trust anchor and its principals' material.
//!
//! Compiled artifacts carry no filesystem references — they name principals by
//! SPIFFE ID and nothing else — so *something* must turn an ID into cert and key
//! bytes. That something is this store, and its conventions live here alone:
//!
//! ```text
//! <scope root>/
//! ├── ca.crt        the rete CA
//! ├── rete.json     the trust-domain record
//! └── certs/        <leaf>.crt / <leaf>.key per local principal
//! ```
//!
//! `ca.crt` and `rete.json` together are the **trust anchor** — the CA plus the
//! domain it is an authority for. The trust domain is *read* from the store,
//! never inferred by sampling SPIFFE IDs out of a config: artifact IDs are
//! checked against the anchor, so they cannot also be its source.
//!
//! The whole tree is **enrollment-owned**: it arrives with the enrollment bundle
//! under an out-of-band integrity assumption, and no compiler or consumer writes
//! to it. Deriving `certs/<leaf>` from a name is a documented C0 shortcut — a
//! file-backed-storage detail. The designed replacement is a store shim (request
//! objects by ID through a small API; B1+ serves identity over a SPIFFE Workload
//! API instead), which is why every consumer goes through this type rather than
//! joining paths itself.

use std::path::{Path, PathBuf};

use error_stack::{Report, ResultExt};
use serde::Deserialize;

use super::{
    Error, SpiffeId, TrustDomain, X509Bundle, X509Svid, leaf_of, load_bundle_from_pem,
    load_svid_from_pem,
};

/// The rete CA certificate, at the scope root.
const CA_CERT_FILE: &str = "ca.crt";

/// The trust-domain record, beside the CA cert.
const RETE_RECORD_FILE: &str = "rete.json";

/// Where principal material lives, one `<leaf>.crt` / `<leaf>.key` pair each.
const CERTS_DIR: &str = "certs";

/// The store's trust-domain record (`rete.json`).
///
/// Enrollment-owned state, not a compiled artifact: it rides no schema ladder
/// and carries no `schema_version`, exactly like the `ca.crt` beside it. Closed
/// all the same, so a typo fails loudly. (Interrete later widens the anchor to
/// several domains; that is a field this record grows, not a reason to shape it
/// speculatively now.)
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReteRecord {
    trust_domain: String,
}

/// A node's identity store, rooted at one enrolled rete scope.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    trust_domain: TrustDomain,
}

impl Store {
    /// Open the store at `scope_root`, reading its trust-domain record.
    ///
    /// Reading `rete.json` up front is what makes [`trust_domain`](Self::trust_domain)
    /// infallible: a store that exists knows which domain it is an authority for.
    pub fn open(scope_root: &Path) -> Result<Self, Report<Error>> {
        let path = scope_root.join(RETE_RECORD_FILE);
        let bytes = std::fs::read(&path).change_context_lazy(|| {
            Error::new(format!(
                "Failed to read the trust-domain record {}",
                path.display()
            ))
        })?;
        let record: ReteRecord = serde_json::from_slice(&bytes).change_context_lazy(|| {
            Error::new(format!(
                "Failed to parse the trust-domain record {}",
                path.display()
            ))
        })?;
        let trust_domain = TrustDomain::new(&record.trust_domain).change_context_lazy(|| {
            Error::new(format!(
                "Trust-domain record {} names an invalid trust domain {:?}",
                path.display(),
                record.trust_domain
            ))
        })?;

        Ok(Self {
            root: scope_root.to_path_buf(),
            trust_domain,
        })
    }

    /// The rete this scope is enrolled into.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// The rete trust bundle, from the store's CA cert.
    pub fn trust_bundle(&self) -> Result<X509Bundle, Report<Error>> {
        let path = self.root.join(CA_CERT_FILE);
        let pem = std::fs::read(&path).change_context_lazy(|| {
            Error::new(format!("Failed to read the rete CA {}", path.display()))
        })?;
        load_bundle_from_pem(&self.trust_domain, &pem)
            .change_context_lazy(|| Error::new("Failed to load the rete trust bundle"))
    }

    /// The SVID of the principal `id`, from `certs/<leaf>.crt` and `.key`.
    ///
    /// Verifies the certificate actually certifies `id`: a consumer declares the
    /// identity it expects, and the store is what confirms the material matches
    /// — a mis-filed cert must not silently become someone else's identity.
    pub fn svid(&self, id: &SpiffeId) -> Result<X509Svid, Report<Error>> {
        let leaf = leaf_of(id)?;
        let certs = self.root.join(CERTS_DIR);
        let cert_path = certs.join(format!("{leaf}.crt"));
        let key_path = certs.join(format!("{leaf}.key"));

        let cert = std::fs::read(&cert_path).change_context_lazy(|| {
            Error::new(format!(
                "Failed to read the cert {} of principal {id}",
                cert_path.display()
            ))
        })?;
        let key = std::fs::read(&key_path).change_context_lazy(|| {
            Error::new(format!(
                "Failed to read the key {} of principal {id}",
                key_path.display()
            ))
        })?;

        let svid = load_svid_from_pem(&cert, &key).change_context_lazy(|| {
            Error::new(format!(
                "Failed to load the SVID of principal {id} from {}",
                cert_path.display()
            ))
        })?;
        if svid.spiffe_id() != id {
            return Err(Report::new(Error::new(format!(
                "Cert {} certifies {}, but {id} was expected",
                cert_path.display(),
                svid.spiffe_id()
            ))));
        }
        Ok(svid)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::{Ca, Kind, keygen_csr};
    use super::*;

    fn day() -> Duration {
        Duration::from_secs(24 * 3600)
    }

    fn td() -> TrustDomain {
        TrustDomain::new("demo.flor").unwrap()
    }

    fn id(s: &str) -> SpiffeId {
        SpiffeId::new(s).unwrap()
    }

    /// A populated store: CA, trust-domain record, and one filed principal.
    fn store_with(uri: &str, kind: Kind, filed_as: &str) -> (tempfile::TempDir, Ca) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();

        std::fs::write(root.join(CA_CERT_FILE), ca.cert_pem()).unwrap();
        std::fs::write(
            root.join(RETE_RECORD_FILE),
            r#"{ "trust_domain": "demo.flor" }"#,
        )
        .unwrap();

        let certs = root.join(CERTS_DIR);
        std::fs::create_dir_all(&certs).unwrap();
        let principal = id(uri);
        let (key, csr) = keygen_csr(&principal).unwrap();
        let leaf = ca
            .sign_csr(csr.as_bytes(), &principal, kind, day())
            .unwrap();
        std::fs::write(certs.join(format!("{filed_as}.crt")), leaf).unwrap();
        std::fs::write(certs.join(format!("{filed_as}.key")), key.serialize_pem()).unwrap();

        (dir, ca)
    }

    #[test]
    fn opens_and_reads_the_trust_domain_from_the_record() {
        let (dir, _ca) = store_with("spiffe://demo.flor/user/alice", Kind::User, "alice");
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.trust_domain(), &td());
    }

    #[test]
    fn trust_bundle_carries_the_ca_authority() {
        let (dir, _ca) = store_with("spiffe://demo.flor/user/alice", Kind::User, "alice");
        let bundle = Store::open(dir.path()).unwrap().trust_bundle().unwrap();
        assert_eq!(bundle.trust_domain(), &td());
        assert_eq!(bundle.authorities().len(), 1);
    }

    #[test]
    fn svid_resolves_a_node_scoped_principal_by_its_leaf() {
        // `/service/beta/tcp-echo` files under `tcp-echo`, not the whole path.
        let (dir, _ca) = store_with(
            "spiffe://demo.flor/service/beta/tcp-echo",
            Kind::Service,
            "tcp-echo",
        );
        let store = Store::open(dir.path()).unwrap();
        let svid = store
            .svid(&id("spiffe://demo.flor/service/beta/tcp-echo"))
            .unwrap();
        assert_eq!(
            svid.spiffe_id().to_string(),
            "spiffe://demo.flor/service/beta/tcp-echo"
        );
    }

    #[test]
    fn svid_rejects_a_cert_certifying_someone_else() {
        // bob's material filed under alice's leaf: the declared ID must win.
        let (dir, _ca) = store_with("spiffe://demo.flor/user/bob", Kind::User, "alice");
        let err = Store::open(dir.path())
            .unwrap()
            .svid(&id("spiffe://demo.flor/user/alice"))
            .unwrap_err();
        assert!(format!("{err:?}").contains("was expected"), "{err:?}");
    }

    #[test]
    fn svid_reports_the_missing_principal_by_id() {
        let (dir, _ca) = store_with("spiffe://demo.flor/user/alice", Kind::User, "alice");
        let err = Store::open(dir.path())
            .unwrap()
            .svid(&id("spiffe://demo.flor/user/carol"))
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("carol.crt"), "{msg}");
    }

    #[test]
    fn open_rejects_a_missing_record() {
        let dir = tempfile::tempdir().unwrap();
        let err = Store::open(dir.path()).unwrap_err();
        assert!(
            format!("{err:?}").contains("trust-domain record"),
            "{err:?}"
        );
    }

    #[test]
    fn open_rejects_an_unknown_field_in_the_record() {
        // Closed record: a typo'd or stray key fails loudly.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(RETE_RECORD_FILE),
            r#"{ "trust_domain": "demo.flor", "surprise": true }"#,
        )
        .unwrap();
        let err = Store::open(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("Failed to parse"), "{err:?}");
    }

    #[test]
    fn open_rejects_a_record_naming_an_invalid_trust_domain() {
        // Well-formed JSON is not enough: the value still has to be a trust
        // domain, and the anchor is worthless if it names something that can
        // never match a SPIFFE ID.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(RETE_RECORD_FILE),
            r#"{ "trust_domain": "not a domain" }"#,
        )
        .unwrap();
        let err = Store::open(dir.path()).unwrap_err();
        assert!(
            format!("{err:?}").contains("invalid trust domain"),
            "{err:?}"
        );
    }

    #[test]
    fn trust_bundle_rejects_a_ca_file_holding_no_certificate() {
        // The CA file is present but carries no CERTIFICATE block — a corrupt
        // or mis-copied anchor, distinct from an absent one.
        let (dir, _ca) = store_with("spiffe://demo.flor/user/alice", Kind::User, "alice");
        std::fs::write(dir.path().join(CA_CERT_FILE), b"not a pem cert").unwrap();
        let err = Store::open(dir.path()).unwrap().trust_bundle().unwrap_err();
        assert!(format!("{err:?}").contains("trust bundle"), "{err:?}");
    }
}
