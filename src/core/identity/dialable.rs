// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! [`Dialable`] — a SPIFFE identity that can be a connect target, plus its
//! `.rete` convenience-hostname codec.
//!
//! A [`Dialable`] wraps a [`SpiffeId`] whose [`Kind`] is `Service` or `Vertex` —
//! the only kinds reachable by name (see ADR-0007). Construction validates the
//! kind and the path shape, so [`Dialable::render`] is infallible. There is no
//! DNS-representability constraint on the type: trust domains may be dotted.
//!
//! ```text
//! spiffe://<td>/service/<svc>          <render>  <svc>.<td>.rete
//! spiffe://<td>/service/<node>/<svc>   <render>  <svc>.<node>.<td>.rete
//! spiffe://<td>/vertex/<node>/<name>   <render>  <name>.<node>.<td>.rete
//! ```
//!
//! [`render`](Dialable::render) is total over the two dialable kinds. The
//! mapping is deliberately **not** injective: a service and a vertex with the
//! same name on the same node render to the same hostname (the shared `.rete`
//! namespace of ADR-0006). [`resolve`](Dialable::resolve) is therefore the
//! inverse only for services — it always yields a `Service`, and recovers the
//! kind of a vertex hostname is left to a lookup against registered SVIDs.
//!
//! [`resolve`](Dialable::resolve) is **contextual**: it takes the caller's
//! [`TrustDomain`] and strips it as a suffix, so the residual label count alone
//! distinguishes rete-scoped (1 label) from node-scoped (2). This needs no
//! single-label-trust-domain assumption and works for dotted trust domains; a
//! hostname in a different trust domain is a foreign rete, unsupported in C0.

use error_stack::{Report, bail};

use crate::core::identity::{
    Error, Kind, NodeScopableKind, Scope, SpiffeId, TrustDomain, build_id_in_rete,
    build_id_on_node, kind_of, scope_of,
};

/// The Florete TLD that every convenience hostname ends with.
const RETE_TLD: &str = "rete";

/// A [`SpiffeId`] that can be a `connect` target: a `Service` or `Vertex`.
///
/// Fully parsed and validated at construction — the [`Kind`], [`Scope`], and leaf
/// name are extracted once and stored — so every accessor is infallible and a
/// constructed `Dialable` is always a well-formed service/vertex identity with a
/// `.rete` hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialable {
    id: SpiffeId,
    kind: Kind,
    scope: Scope,
    /// The leaf path segment — the service/vertex name.
    name: String,
}

impl Dialable {
    /// Wrap a [`SpiffeId`], requiring its kind to be `Service` or `Vertex` and
    /// its path to be a well-formed rete- or node-scoped shape. All structural
    /// pieces are parsed here so later use cannot fail.
    pub fn new(id: SpiffeId) -> Result<Self, Report<Error>> {
        let kind = kind_of(&id)?;
        if !matches!(kind, Kind::Service | Kind::Vertex) {
            bail!(Error::new(format!(
                "SPIFFE kind {kind} is not dialable: only service and vertex have a .rete hostname"
            )));
        }
        let scope = scope_of(&id)?;
        let name = leaf_name(&id)?.to_string();
        Ok(Self {
            id,
            kind,
            scope,
            name,
        })
    }

    /// The wrapped canonical identity.
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    /// The dialable kind (`Service` or `Vertex`).
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Synthesise the `.rete` convenience hostname. Infallible (everything was
    /// validated at construction). Trust domains may be dotted.
    pub fn render(&self) -> String {
        let td = self.id.trust_domain().as_str();
        match &self.scope {
            Scope::Rete => format!("{}.{td}.{RETE_TLD}", self.name),
            Scope::Node(node) => format!("{}.{node}.{td}.{RETE_TLD}", self.name),
        }
    }

    /// Resolve a `.rete` hostname to a service `Dialable`, using `ctx` (the
    /// caller's trust domain) as namespace context.
    ///
    /// Strips the `.rete` suffix and the `ctx` trust-domain suffix; the residual
    /// labels then unambiguously given the scope — 1 label is rete-scoped, 2 is
    /// node-scoped (`<svc>.<node>`). Always yields a `Service` (see module docs).
    /// A hostname whose trust-domain suffix is not `ctx` is a foreign rete and is
    /// rejected (cross-rete resolution is not implemented yet).
    pub fn resolve(host: &str, ctx: &TrustDomain) -> Result<Self, Report<Error>> {
        let stem = host.strip_suffix(&format!(".{RETE_TLD}")).ok_or_else(|| {
            Report::new(Error::new(format!(
                "Host {host:?} is not a .{RETE_TLD} convenience name"
            )))
        })?;

        let td = ctx.as_str();
        let residual = stem.strip_suffix(&format!(".{td}")).ok_or_else(|| {
            Report::new(Error::new(if stem == td {
                format!("Host {host:?} names the rete {td:?} but carries no service label")
            } else {
                format!("Host {host:?} is not in rete {td:?}; cross-rete resolution is unsupported")
            }))
        })?;

        let labels: Vec<&str> = residual.split('.').collect();
        if labels.iter().any(|l| l.is_empty()) {
            bail!(Error::new(format!("Host {host:?} has an empty DNS label")));
        }

        let id = match labels.as_slice() {
            [svc] => build_id_in_rete(ctx, Kind::Service, svc)?,
            [svc, node] => build_id_on_node(ctx, NodeScopableKind::Service, node, svc)?,
            _ => bail!(Error::new(format!(
                "Host {host:?} has {} labels before the rete suffix; expected 1 (rete-scoped) \
                 or 2 (node-scoped)",
                labels.len()
            ))),
        };
        Self::new(id)
    }
}

impl TryFrom<SpiffeId> for Dialable {
    type Error = Report<Error>;
    fn try_from(id: SpiffeId) -> Result<Self, Self::Error> {
        Self::new(id)
    }
}

impl TryFrom<&SpiffeId> for Dialable {
    type Error = Report<Error>;
    fn try_from(id: &SpiffeId) -> Result<Self, Self::Error> {
        Self::new(id.clone())
    }
}

/// The last path segment of a SPIFFE ID (the service/vertex name).
fn leaf_name(id: &SpiffeId) -> Result<&str, Report<Error>> {
    id.path()
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Report::new(Error::new("SPIFFE ID has no name segment")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> SpiffeId {
        SpiffeId::new(s).expect("valid SPIFFE ID")
    }

    fn td(s: &str) -> TrustDomain {
        TrustDomain::new(s).expect("valid trust domain")
    }

    fn dialable(s: &str) -> Dialable {
        Dialable::new(id(s)).expect("dialable")
    }

    #[test]
    fn render_rete_scoped_service() {
        assert_eq!(
            dialable("spiffe://demo-rete/service/api").render(),
            "api.demo-rete.rete"
        );
    }

    #[test]
    fn render_node_scoped_service() {
        assert_eq!(
            dialable("spiffe://demo-rete/service/beta/tcp-echo").render(),
            "tcp-echo.beta.demo-rete.rete"
        );
    }

    #[test]
    fn render_node_scoped_vertex() {
        // Vertex is dialable; renders to the same shape a node-scoped service
        // would (the shared `.rete` namespace per ADR-0006).
        assert_eq!(
            dialable("spiffe://rete-lovers/vertex/alpha/rete").render(),
            "rete.alpha.rete-lovers.rete"
        );
    }

    #[test]
    fn render_allows_dotted_trust_domain() {
        // No single-label constraint: dotted trust domains render fine (ADR-0007).
        assert_eq!(
            dialable("spiffe://demo.flor/service/api").render(),
            "api.demo.flor.rete"
        );
        assert_eq!(
            dialable("spiffe://demo.flor/service/beta/tcp-echo").render(),
            "tcp-echo.beta.demo.flor.rete"
        );
    }

    #[test]
    fn new_rejects_non_dialable_kinds() {
        for uri in [
            "spiffe://demo-rete/user/alice",
            "spiffe://demo-rete/node/alpha",
            "spiffe://demo-rete/control-plane/primary",
            "spiffe://demo-rete/management-plane/primary",
        ] {
            let err = Dialable::new(id(uri)).unwrap_err();
            assert!(
                format!("{err:?}").contains("not dialable"),
                "{uri}: {err:?}"
            );
        }
    }

    #[test]
    fn new_rejects_malformed_path_shape() {
        // Service kind but too many trailing segments — rejected so render is safe.
        let err = Dialable::new(id("spiffe://demo-rete/service/a/b/c")).unwrap_err();
        assert!(format!("{err:?}").contains("wrong shape"), "{err:?}");
    }

    #[test]
    fn kind_reports_service_and_vertex() {
        assert_eq!(
            dialable("spiffe://demo-rete/service/api").kind(),
            Kind::Service
        );
        assert_eq!(
            dialable("spiffe://rete-lovers/vertex/alpha/rete").kind(),
            Kind::Vertex
        );
    }

    #[test]
    fn resolve_rete_scoped() {
        assert_eq!(
            Dialable::resolve("api.demo-rete.rete", &td("demo-rete"))
                .unwrap()
                .id(),
            &id("spiffe://demo-rete/service/api")
        );
    }

    #[test]
    fn resolve_node_scoped() {
        assert_eq!(
            Dialable::resolve("tcp-echo.beta.demo-rete.rete", &td("demo-rete"))
                .unwrap()
                .id(),
            &id("spiffe://demo-rete/service/beta/tcp-echo")
        );
    }

    #[test]
    fn resolve_with_dotted_trust_domain() {
        // Contextual resolution: strip the known (dotted) trust-domain suffix,
        // residual disambiguates scope — no single-label assumption.
        assert_eq!(
            Dialable::resolve("api.demo.flor.rete", &td("demo.flor"))
                .unwrap()
                .id(),
            &id("spiffe://demo.flor/service/api")
        );
        assert_eq!(
            Dialable::resolve("tcp-echo.beta.demo.flor.rete", &td("demo.flor"))
                .unwrap()
                .id(),
            &id("spiffe://demo.flor/service/beta/tcp-echo")
        );
    }

    #[test]
    fn resolve_rejects_missing_tld() {
        let err = Dialable::resolve("api.demo-rete.com", &td("demo-rete")).unwrap_err();
        assert!(format!("{err:?}").contains("not a .rete"), "{err:?}");
    }

    #[test]
    fn resolve_rejects_foreign_rete() {
        // Host's trust-domain suffix doesn't match the caller's context.
        let err = Dialable::resolve("api.other-rete.rete", &td("demo-rete")).unwrap_err();
        assert!(
            format!("{err:?}").contains("cross-rete resolution is unsupported"),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_rejects_bare_rete_name() {
        // `<td>.rete` with no service label.
        let err = Dialable::resolve("demo-rete.rete", &td("demo-rete")).unwrap_err();
        assert!(
            format!("{err:?}").contains("carries no service label"),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_rejects_empty_label() {
        // Leading/consecutive dots produce an empty residual label.
        let err = Dialable::resolve("api..demo-rete.rete", &td("demo-rete")).unwrap_err();
        assert!(format!("{err:?}").contains("empty DNS label"), "{err:?}");
    }

    #[test]
    fn resolve_rejects_too_many_labels() {
        let err = Dialable::resolve("a.b.c.demo-rete.rete", &td("demo-rete")).unwrap_err();
        assert!(
            format!("{err:?}").contains("expected 1 (rete-scoped) or 2 (node-scoped)"),
            "{err:?}"
        );
    }

    #[test]
    fn roundtrip_render_resolve_for_service() {
        for (uri, rete) in [
            ("spiffe://demo-rete/service/api", "demo-rete"),
            ("spiffe://demo-rete/service/beta/tcp-echo", "demo-rete"),
            ("spiffe://demo.flor/service/api", "demo.flor"),
            ("spiffe://demo.flor/service/beta/tcp-echo", "demo.flor"),
        ] {
            let original = dialable(uri);
            let host = original.render();
            assert_eq!(
                Dialable::resolve(&host, &td(rete)).unwrap(),
                original,
                "{uri}"
            );
        }
    }
}
