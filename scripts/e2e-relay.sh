#!/usr/bin/env bash
# Copyright (C) 2026 ReteLabs LLC.
# Licensed under Apache-2.0 or MIT at your option.
#
# End-to-end smoke test for the mTLS data path: drives a SOCKS5 client through
# the Alpha node, over a real QUIC mTLS connection, to the Beta node, which
# relays to a local TCP echo upstream. A byte round-trip proves the whole chain
# (SOCKS5 → resolve → caller mTLS → server mTLS → publish/route → TCP relay).
#
# Each node runs as `flor vertex run` against its own rete root under
# .flor-dev/retes/<scope>/ (FLOR_HOME points the home dir there). Topology
# matches scripts/dev-bootstrap.sh:
#   - Alpha: SOCKS5 proxy for alice on 127.0.0.1:1080, QUIC on 127.0.0.1:31337
#   - Beta:  serves service tcp-echo, QUIC on 127.0.0.1:31440, upstream :32450
#
# Usage: scripts/e2e-relay.sh
# Exit code 0 = relay verified; non-zero = failure (node logs are printed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

readonly SOCKS5_ADDR="127.0.0.1:1080"
readonly ECHO_ADDR="127.0.0.1:32450"
readonly TARGET_HOST="tcp-echo.beta.demo.flor.rete"

command -v python3 >/dev/null || {
  echo "error: python3 is required (used for the echo upstream + SOCKS5 client)" >&2
  exit 1
}

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

# Print the tail of each node log (best-effort; logs exist only after startup).
dump_node_logs() {
  echo "--- alpha.log ---" >&2; tail -n 20 "$WORK/alpha.log" >&2 2>/dev/null || true
  echo "--- beta.log ---"  >&2; tail -n 20 "$WORK/beta.log"  >&2 2>/dev/null || true
}

# Wait until a TCP port accepts connections (bash /dev/tcp), or time out.
wait_for_port() {
  local host=$1 port=$2
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      exec 3>&- 3<&-
      return 0
    fi
    sleep 0.1
  done
  echo "error: timed out waiting for $host:$port" >&2
  return 1
}

echo "==> Building flor"
cargo build -q --bin flor
FLOR="$ROOT/target/debug/flor"

# Each node runs from its own rete root under .flor-dev/retes/<scope>/, located
# by pointing the flor home dir there.
export FLOR_HOME="$ROOT/.flor-dev"

# Always re-mint, rather than reusing whatever is on disk: dev-bootstrap.sh is
# re-runnable (it wipes and re-mints) and cheap next to the cargo build above.
# A cached rete root from an older artifact schema would otherwise be fed to
# `flor` and fail to parse — surfacing only as a confusing port-wait timeout.
echo "==> Minting fresh dev material"
bash "$ROOT/scripts/dev-bootstrap.sh" >"$WORK/bootstrap.log" 2>&1 \
  || { cat "$WORK/bootstrap.log"; exit 1; }

# TCP echo upstream that Beta's tcp-echo service forwards to.
cat >"$WORK/echo.py" <<PY
import socket
host, port = "${ECHO_ADDR}".split(":")
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port))); s.listen()
while True:
    conn, _ = s.accept()
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
PY

# SOCKS5 client: CONNECT to the .rete hostname, echo a nonce, verify the reply.
cat >"$WORK/client.py" <<PY
import socket, sys
addr_host, addr_port = "${SOCKS5_ADDR}".split(":")
host = b"${TARGET_HOST}"
nonce = b"flor-e2e-" + format(__import__("random").getrandbits(48), "x").encode()

s = socket.create_connection((addr_host, int(addr_port)), timeout=5)
s.settimeout(5)
s.sendall(b"\x05\x01\x00")                       # greeting: no-auth
if s.recv(2) != b"\x05\x00":
    sys.exit("SOCKS5 server did not accept no-auth")
# CONNECT, ATYP=domain, port 1 (the connector ignores the port)
s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x00\x01")
reply = s.recv(10)
if reply[1] != 0x00:
    sys.exit(f"SOCKS5 CONNECT failed, reply code {reply[1]}")
s.sendall(nonce)
got = b""
while len(got) < len(nonce):
    chunk = s.recv(len(nonce) - len(got))
    if not chunk:
        break
    got += chunk
if got != nonce:
    sys.exit(f"echo mismatch: sent {nonce!r}, got {got!r}")
print(f"round-tripped {len(nonce)} bytes through mTLS relay")
PY

echo "==> Starting echo upstream + Beta + Alpha (flor vertex run)"
python3 "$WORK/echo.py" & PIDS+=($!)
"$FLOR" vertex run --rete beta  --name flor >"$WORK/beta.log"  2>&1 & PIDS+=($!)
"$FLOR" vertex run --rete alpha --name flor >"$WORK/alpha.log" 2>&1 & PIDS+=($!)

wait_for_port "${ECHO_ADDR%:*}" "${ECHO_ADDR#*:}" || { dump_node_logs; exit 1; }
wait_for_port "${SOCKS5_ADDR%:*}" "${SOCKS5_ADDR#*:}" || { dump_node_logs; exit 1; }

echo "==> Running SOCKS5 client through ${SOCKS5_ADDR} → ${TARGET_HOST}"
if python3 "$WORK/client.py"; then
  echo "PASS: e2e mTLS relay verified"
else
  status=$?
  echo "FAIL: e2e relay did not complete (exit $status)" >&2
  dump_node_logs
  exit "$status"
fi
