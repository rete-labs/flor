#!/usr/bin/env bash
# Copyright (C) 2026 ReteLabs LLC.
# Licensed under Apache-2.0 or MIT at your option.
#
# Mint the dev mTLS material the `flor demo` topology expects, into a
# gitignored `.flor-dev/` at the repo root:
#
#   .flor-dev/ca.crt                    rete CA certificate (trust bundle)
#   .flor-dev/ca.key                    rete CA private key  (mode 0600)
#   .flor-dev/<node>/<name>.crt|.key    per-principal SVID + private key
#
# Topology (mirrors src/main.rs), trust domain `demo.flor` (dotted on purpose —
# exercises ADR-0007 dotted-trust-domain support; override via
# $FLOR_DEV_TRUST_DOMAIN):
#   - alice, bob   on node alpha   (kind user,    rete-scoped)
#   - tcp-echo     on node beta    (kind service, node-scoped to beta)
#
# This is dev tooling only — it stitches together the same `flor` / `florctl`
# commands an operator runs by hand. It is deliberately *not* a subcommand of
# any production binary; the on-disk layout and the load path in main.rs are
# what production uses, but minting this material stays out of the shipped
# executables.
#
# Re-runnable: wipes and re-mints `.flor-dev/` on each invocation.
set -euo pipefail

# Repo root = parent of this script's dir, regardless of where we're invoked.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TRUST_DOMAIN="${FLOR_DEV_TRUST_DOMAIN:-demo.flor}"
DEV_DIR="$ROOT/.flor-dev"

# Throwaway CSRs live in a temp dir; only key+cert are kept.
CSR_DIR="$(mktemp -d)"
trap 'rm -rf "$CSR_DIR"' EXIT

echo "==> Building flor + florctl"
cargo build --quiet --bin flor --bin florctl
FLOR="$ROOT/target/debug/flor"
FLORCTL="$ROOT/target/debug/florctl"

echo "==> Resetting $DEV_DIR"
rm -rf "$DEV_DIR"
mkdir -p "$DEV_DIR"

echo "==> Initialising rete CA for trust domain '$TRUST_DOMAIN'"
"$FLORCTL" ca init \
  --trust-domain "$TRUST_DOMAIN" \
  --out-cert "$DEV_DIR/ca.crt" \
  --out-key "$DEV_DIR/ca.key"

# Mint one principal: keygen a CSR locally, then have the CA sign it.
#   $1 node   $2 kind   $3 name   $4 scope (empty for rete-scoped)
mint() {
  local node="$1" kind="$2" name="$3" scope="${4:-}"
  local out_dir="$DEV_DIR/$node"
  local key="$out_dir/$name.key" crt="$out_dir/$name.crt"
  local csr="$CSR_DIR/$node-$name.csr"
  mkdir -p "$out_dir"

  local scope_args=()
  [[ -n "$scope" ]] && scope_args=(--scope "$scope")

  "$FLOR" id keygen \
    --kind "$kind" --name "$name" --trust-domain "$TRUST_DOMAIN" \
    "${scope_args[@]}" \
    --out-key "$key" --out-csr "$csr"

  "$FLORCTL" ca sign \
    --csr "$csr" --kind "$kind" --name "$name" "${scope_args[@]}" \
    --ca-cert "$DEV_DIR/ca.crt" --ca-key "$DEV_DIR/ca.key" \
    --out "$crt"
}

echo "==> Minting principals"
mint alpha user    alice
mint alpha user    bob
mint beta  service tcp-echo beta

echo
echo "Done. Dev material under $DEV_DIR:"
find "$DEV_DIR" -type f | sort | sed "s#^$ROOT/#  #"
