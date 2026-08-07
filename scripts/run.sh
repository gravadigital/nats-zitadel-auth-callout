#!/usr/bin/env bash
#
# run.sh — levanta NATS + el callout en foreground (Ctrl-C para parar).
#
# Junta las dos fuentes de configuración: nats/.env (lo que decide una persona) y
# nats/out/callout-env.sh (lo que generó el bootstrap). Así las seeds nunca se escriben a
# mano y regenerar la identidad no obliga a editar nada.

set -euo pipefail
cd "$(dirname "$0")/.."

REPO_ROOT="$PWD"
NATS_DIR="$REPO_ROOT/nats"

command -v nats-server >/dev/null 2>&1 || {
  echo "ERROR: nats-server no está en PATH (go install github.com/nats-io/nats-server/v2@latest)" >&2
  exit 1
}

if [[ ! -f "$NATS_DIR/out/callout-env.sh" ]]; then
  echo "ERROR: falta la identidad NATS. Corré primero: make bootstrap" >&2
  exit 1
fi

# .env es opcional: sin él se usan los defaults del binario (modo mock, instancia dev).
if [[ -f "$NATS_DIR/.env" ]]; then
  set -a; . "$NATS_DIR/.env"; set +a
fi

# Las rutas del contrato son relativas a nats/, así que se ancla ahí.
GESTION_NATS_DIR="$NATS_DIR"
export GESTION_NATS_DIR
set -a; . "$NATS_DIR/out/callout-env.sh"; set +a

# Las plantillas se resuelven relativas al rules.yaml, así que alcanza con su path.
export GESTION_RULES_PATH="${GESTION_RULES_PATH:-$REPO_ROOT/config/rules.yaml}"
export GESTION_NATS_URL="${GESTION_NATS_URL:-nats://127.0.0.1:4322}"

echo "==> Arrancando nats-server"
mkdir -p "$NATS_DIR/data"
(cd "$NATS_DIR" && nats-server -c nats-server.conf) &
NATS_PID=$!

# Solo se mata el nats-server que arrancó ESTE script. Un nats-server o un callout que
# quedaron de una corrida anterior NO se tocan — y son la causa más común de "cambié la
# config y no pasó nada": el viejo sigue atendiendo el subject de callout mientras el
# nuevo no pudo bindear el puerto.
cleanup() {
  echo
  echo "==> Parando nats-server ($NATS_PID)"
  kill "$NATS_PID" 2>/dev/null || true
  wait "$NATS_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Esperando que NATS acepte conexiones"
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${NATS_MONITOR_PORT:-8322}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "==> Arrancando el callout"
exec go run ./cmd/callout
