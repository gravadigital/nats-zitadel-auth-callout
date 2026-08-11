#!/usr/bin/env bash
#
# run.sh — brings up NATS + the callout in the foreground (Ctrl-C to stop).
#
# It joins the two configuration sources: nats/.env (what a person decides) and
# nats/out/callout-env.sh (what the bootstrap generated). That way the seeds are never written
# by hand and regenerating the identity does not force editing anything.

set -euo pipefail
cd "$(dirname "$0")/.."

REPO_ROOT="$PWD"
NATS_DIR="$REPO_ROOT/nats"

command -v nats-server >/dev/null 2>&1 || {
  echo "ERROR: nats-server is not on PATH (go install github.com/nats-io/nats-server/v2@latest)" >&2
  exit 1
}

if [[ ! -f "$NATS_DIR/out/callout-env.sh" ]]; then
  echo "ERROR: the NATS identity is missing. Run this first: make bootstrap" >&2
  exit 1
fi

# .env is optional: without it the binary's defaults are used (mock mode, dev instance).
if [[ -f "$NATS_DIR/.env" ]]; then
  set -a; . "$NATS_DIR/.env"; set +a
fi

# The contract's paths are relative to nats/, so that is where it is anchored.
CALLOUT_NATS_DIR="$NATS_DIR"
export CALLOUT_NATS_DIR
set -a; . "$NATS_DIR/out/callout-env.sh"; set +a

# Templates are resolved relative to rules.yaml, so its path is all that is needed.
export CALLOUT_RULES_PATH="${CALLOUT_RULES_PATH:-$REPO_ROOT/examples/rules.yaml}"
export CALLOUT_NATS_URL="${CALLOUT_NATS_URL:-nats://127.0.0.1:4322}"

echo "==> Starting nats-server"
mkdir -p "$NATS_DIR/data"
(cd "$NATS_DIR" && nats-server -c nats-server.conf) &
NATS_PID=$!

# Only the nats-server THIS script started gets killed. A nats-server or a callout left over
# from a previous run is NOT touched — and those are the most common cause of "I changed the
# config and nothing happened": the old one keeps serving the callout subject while the new one
# could not bind the port.
cleanup() {
  echo
  echo "==> Stopping nats-server ($NATS_PID)"
  kill "$NATS_PID" 2>/dev/null || true
  wait "$NATS_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Waiting for NATS to accept connections"
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${NATS_MONITOR_PORT:-8322}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "==> Starting the callout"
exec go run ./cmd/callout
