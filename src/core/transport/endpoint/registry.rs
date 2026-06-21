// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The published-cert registry: shared state mapping each SNI routing label to
//! the service published under it.
//!
//! It belongs to neither the actor nor the endpoint alone — both hold the same
//! `Arc`. The actor writes it (publish / cleanup); the endpoint reads it to pick
//! the cert to present (via [`ServerCertRegistry`]) and to route each accepted
//! connection (via [`route`](PublishedServices::route)).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rustls::sign::CertifiedKey;
use tokio::sync::mpsc;

use crate::core::identity::SpiffeId;

use super::connection::QuicConnection;
use super::verifier::ServerCertRegistry;

/// Channel delivering accepted connections to a subscriber, each tagged with the
/// target identity it was dialed against.
pub(super) type Dispatch = mpsc::Sender<(SpiffeId, QuicConnection)>;

/// One published service: its identity, the cert the server presents for it, and
/// the channel delivering its accepted connections.
#[derive(Debug)]
struct PublishedEntry {
    spiffe_id: SpiffeId,
    certified_key: Arc<CertifiedKey>,
    dispatch: Dispatch,
}

/// A service to register: its routing label (`sni_for(spiffe_id)`), canonical
/// identity, and the cert to present. The dispatch channel is supplied once for
/// the whole batch by [`PublishedServices::publish`].
pub(super) struct Publication {
    pub(super) sni: String,
    pub(super) spiffe_id: SpiffeId,
    pub(super) certified_key: Arc<CertifiedKey>,
}

/// Registry of published services, keyed by SNI routing label.
#[derive(Debug)]
pub(super) struct PublishedServices(RwLock<HashMap<String, PublishedEntry>>);

impl PublishedServices {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(RwLock::new(HashMap::new())))
    }

    /// Resolve an accepted connection's SNI to the dialed service's identity and
    /// dispatch channel, or `None` if nothing is published for it.
    pub(super) fn route(&self, sni: &str) -> Option<(SpiffeId, Dispatch)> {
        let map = self.0.read().unwrap();
        let entry = map.get(sni)?;
        Some((entry.spiffe_id.clone(), entry.dispatch.clone()))
    }

    /// Register `services` under one `dispatch` channel, first reaping entries
    /// whose subscriber has dropped.
    ///
    /// All-or-nothing: if any routing label is already taken, nothing is inserted
    /// and the conflicting identities are returned.
    pub(super) fn publish(
        &self,
        services: Vec<Publication>,
        dispatch: Dispatch,
    ) -> Result<(), Vec<SpiffeId>> {
        let mut map = self.0.write().unwrap();
        map.retain(|_, entry| !entry.dispatch.is_closed());

        let conflicts: Vec<SpiffeId> = services
            .iter()
            .filter(|s| map.contains_key(&s.sni))
            .map(|s| s.spiffe_id.clone())
            .collect();
        if !conflicts.is_empty() {
            return Err(conflicts);
        }

        for service in services {
            map.insert(
                service.sni,
                PublishedEntry {
                    spiffe_id: service.spiffe_id,
                    certified_key: service.certified_key,
                    dispatch: dispatch.clone(),
                },
            );
        }
        Ok(())
    }
}

impl ServerCertRegistry for PublishedServices {
    fn cert_for_sni(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.0
            .read()
            .unwrap()
            .get(sni)
            .map(|entry| entry.certified_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: usize = 4;

    fn id(name: &str) -> SpiffeId {
        SpiffeId::new(format!("spiffe://demo.flor/service/{name}")).unwrap()
    }

    /// A throwaway `CertifiedKey` — the registry never inspects key material, so
    /// any valid one serves as a stand-in.
    fn stub_cert() -> Arc<CertifiedKey> {
        let c = rcgen::generate_simple_self_signed(vec!["stub.example".to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(c.cert);
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(c.signing_key.serialize_der()).unwrap();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
        Arc::new(CertifiedKey::new(vec![cert], signing_key))
    }

    /// A publication for `name`, registered under SNI `<name>.rete`.
    fn publication(name: &str) -> Publication {
        Publication {
            sni: format!("{name}.rete"),
            spiffe_id: id(name),
            certified_key: stub_cert(),
        }
    }

    #[test]
    fn route_and_cert_resolve_a_published_service() {
        let registry = PublishedServices::new();
        let (tx, _rx) = mpsc::channel(CAP);
        registry.publish(vec![publication("api")], tx).unwrap();

        let (target, _dispatch) = registry
            .route("api.rete")
            .expect("published service routes");
        assert_eq!(target, id("api"));
        assert!(registry.cert_for_sni("api.rete").is_some());

        assert!(registry.route("absent.rete").is_none());
        assert!(registry.cert_for_sni("absent.rete").is_none());
    }

    #[test]
    fn publish_conflict_is_atomic() {
        let registry = PublishedServices::new();
        let (tx1, _rx1) = mpsc::channel(CAP);
        registry.publish(vec![publication("api")], tx1).unwrap();

        // `api` conflicts, `db` is new — the whole batch must be rejected.
        let (tx2, _rx2) = mpsc::channel(CAP);
        let conflicts = registry
            .publish(vec![publication("api"), publication("db")], tx2)
            .unwrap_err();
        assert_eq!(conflicts, vec![id("api")]);
        assert!(
            registry.route("db.rete").is_none(),
            "db must not be partially registered when api conflicts"
        );
    }

    #[test]
    fn publish_reaps_dropped_subscribers() {
        let registry = PublishedServices::new();
        let (tx1, rx1) = mpsc::channel(CAP);
        registry.publish(vec![publication("api")], tx1).unwrap();

        // Subscriber drops its acceptor; re-publishing the same service succeeds
        // because the stale entry is reaped first.
        drop(rx1);
        let (tx2, _rx2) = mpsc::channel(CAP);
        registry
            .publish(vec![publication("api")], tx2)
            .expect("re-register after the previous subscriber dropped");
    }

    #[test]
    fn one_publish_shares_a_dispatch_channel() {
        let registry = PublishedServices::new();
        let (tx, rx) = mpsc::channel(CAP);
        registry
            .publish(vec![publication("api"), publication("db")], tx)
            .unwrap();

        // Both services route to senders on the same channel: dropping the single
        // receiver closes both.
        let (_, api) = registry.route("api.rete").unwrap();
        let (_, db) = registry.route("db.rete").unwrap();
        assert!(!api.is_closed());
        assert!(!db.is_closed());
        drop(rx);
        assert!(api.is_closed());
        assert!(db.is_closed());
    }
}
