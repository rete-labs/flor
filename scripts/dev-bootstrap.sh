#!/usr/bin/env bash
# Copyright (C) 2026 ReteLabs LLC.
# Licensed under Apache-2.0 or MIT at your option.
#
# Mint the dev mTLS material + compiled artifacts for the demo topology, into a
# gitignored `.flor-dev/` at the repo root — one rete root per node:
#
#   .flor-dev/ca.crt, ca.key             rete CA (trust bundle + signing key)
#   .flor-dev/retes/<scope>/             a rete root per node, for `flor vertex run`:
#       ca.crt, <name>.crt, <name>.key   flat identity material
#       mgmt/vertices/flor.json          the compiled vertex artifact
#
# `flor vertex run --rete <scope> --name flor` reads a rete root once
# `FLOR_HOME=.flor-dev` points the home dir at it (see scripts/e2e-relay.sh).
#
# Topology, trust domain `demo.flor` (dotted on purpose — exercises ADR-0007
# dotted-trust-domain support; override via $FLOR_DEV_TRUST_DOMAIN):
#   - alice, bob   on node alpha   (kind user,    rete-scoped) — SOCKS5 callers
#   - tcp-echo     on node beta    (kind service, node-scoped to beta) — target
#
# This is dev tooling only — it stitches together the same `flor` / `retectl`
# commands an operator runs by hand; the JSON it writes is what `retectl compile`
# will produce. It is deliberately *not* a subcommand of any shipped binary.
#
# Re-runnable: wipes and re-mints `.flor-dev/` on each invocation.
set -euo pipefail

# Repo root = parent of this script's dir, regardless of where we're invoked.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TRUST_DOMAIN="${FLOR_DEV_TRUST_DOMAIN:-demo.flor}"
DEV_DIR="$ROOT/.flor-dev"
RETES_DIR="$DEV_DIR/retes"

# Throwaway CSRs live in a temp dir; only key+cert are kept.
CSR_DIR="$(mktemp -d)"
trap 'rm -rf "$CSR_DIR"' EXIT

echo "==> Building flor + retectl"
cargo build --quiet --bin flor --bin retectl
FLOR="$ROOT/target/debug/flor"
RETECTL="$ROOT/target/debug/retectl"

echo "==> Resetting $DEV_DIR"
rm -rf "$DEV_DIR"
mkdir -p "$DEV_DIR"

echo "==> Initialising rete CA for trust domain '$TRUST_DOMAIN'"
"$RETECTL" ca init \
  --trust-domain "$TRUST_DOMAIN" \
  --out-cert "$DEV_DIR/ca.crt" \
  --out-key "$DEV_DIR/ca.key"

# Prepare a rete root per node (flat layout + the mgmt/vertices/ tree).
for scope in alpha beta; do
  mkdir -p "$RETES_DIR/$scope/mgmt/vertices"
  cp "$DEV_DIR/ca.crt" "$RETES_DIR/$scope/ca.crt"
done

# Mint one principal directly into a rete root: keygen a CSR locally, sign it.
#   $1 scope (rete root)   $2 kind   $3 name   $4 node-scope (empty = rete-scoped)
mint() {
  local scope="$1" kind="$2" name="$3" node="${4:-}"
  local root="$RETES_DIR/$scope"
  local csr="$CSR_DIR/$scope-$name.csr"

  local scope_args=()
  [[ -n "$node" ]] && scope_args=(--scope "$node")

  "$FLOR" id keygen \
    --kind "$kind" --name "$name" --trust-domain "$TRUST_DOMAIN" \
    "${scope_args[@]}" \
    --out-key "$root/$name.key" --out-csr "$csr"

  "$RETECTL" ca sign \
    --csr "$csr" --kind "$kind" --name "$name" "${scope_args[@]}" \
    --ca-cert "$DEV_DIR/ca.crt" --ca-key "$DEV_DIR/ca.key" \
    --out "$root/$name.crt"
}

echo "==> Minting principals into rete roots"
mint alpha user    alice
mint alpha user    bob
mint beta  service tcp-echo beta

# alpha — the initiator node: alice/bob reach tcp-echo (on beta) over SOCKS5.
cat >"$RETES_DIR/alpha/mgmt/vertices/flor.json" <<JSON
{
  "schema_version": "1.0",
  "plane": "mgmt",
  "kind": "vertex",
  "version": 1,
  "node": "alpha",
  "name": "flor",
  "generated_at": "2026-01-01T00:00:00Z",
  "payload": {
    "kind": "link",
    "ca_cert_path": "ca.crt",
    "transport_endpoint": { "type": "quic" },
    "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:31337" } ] },
    "workloads": [
      { "spiffe_id": "spiffe://$TRUST_DOMAIN/user/alice",
        "identity": { "cert_path": "alice.crt", "priv_path": "alice.key" },
        "io": [ { "kind": "socks5", "listen": "127.0.0.1:1080" } ] },
      { "spiffe_id": "spiffe://$TRUST_DOMAIN/user/bob",
        "identity": { "cert_path": "bob.crt", "priv_path": "bob.key" },
        "io": [ { "kind": "socks5", "listen": "127.0.0.1:1081" } ] }
    ],
    "links": [
      { "type": "list", "members": [
        { "name": "tcp-echo", "peer": "spiffe://$TRUST_DOMAIN/service/beta/tcp-echo", "via": { "type": "udp", "adapter": "wire", "addr": "127.0.0.1:31440" } }
      ] }
    ],
    "egress": [
      { "target": "spiffe://$TRUST_DOMAIN/service/beta/tcp-echo", "allow": ["spiffe://$TRUST_DOMAIN/user/alice", "spiffe://$TRUST_DOMAIN/user/bob"] }
    ]
  },
  "signature": { "alg": "none", "key_id": "spiffe://$TRUST_DOMAIN/management-plane/dev", "value": "dev-unsigned" }
}
JSON

# beta — the server node: serves tcp-echo, relaying to a local TCP upstream.
cat >"$RETES_DIR/beta/mgmt/vertices/flor.json" <<JSON
{
  "schema_version": "1.0",
  "plane": "mgmt",
  "kind": "vertex",
  "version": 1,
  "node": "beta",
  "name": "flor",
  "generated_at": "2026-01-01T00:00:00Z",
  "payload": {
    "kind": "link",
    "ca_cert_path": "ca.crt",
    "transport_endpoint": { "type": "quic" },
    "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:31440" } ] },
    "workloads": [
      { "spiffe_id": "spiffe://$TRUST_DOMAIN/service/beta/tcp-echo",
        "identity": { "cert_path": "tcp-echo.crt", "priv_path": "tcp-echo.key" },
        "io": [ { "kind": "tcp", "upstream": "127.0.0.1:32450" } ] }
    ],
    "ingress": [
      { "target": "spiffe://$TRUST_DOMAIN/service/beta/tcp-echo", "allow": ["spiffe://$TRUST_DOMAIN/user/alice", "spiffe://$TRUST_DOMAIN/user/bob"] }
    ]
  },
  "signature": { "alg": "none", "key_id": "spiffe://$TRUST_DOMAIN/management-plane/dev", "value": "dev-unsigned" }
}
JSON

echo
echo "Done. Dev material under $DEV_DIR:"
find "$DEV_DIR" -type f | sort | sed "s#^$ROOT/#  #"
