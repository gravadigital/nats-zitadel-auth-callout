#!/usr/bin/env bash
#
# bootstrap.sh — genera la identidad NATS que necesita el auth-callout de gestión.
#
# Produce, en un store de nsc AISLADO bajo out/nsc (nunca toca tu ~/.local/share/nats):
#
#   operator + SYS
#   GESTION        cuenta APP  — donde aterrizan TODAS las conexiones (personas y servicios)
#   GESTION_AUTH   cuenta AUTH — donde vive el callout y sus dos sentinelas
#   la XKey del callout, la config de authcallout, y un resolver MEMORY autocontenido
#
# POR QUÉ UNA SOLA CUENTA APP
#   Personas y servicios comparten la cuenta `GESTION`. El aislamiento entre ellos lo dan
#   los permisos de subject que mintea el callout, que es el servidor quien los aplica.
#   Separarlos en dos cuentas agregaría una frontera que habría que perforar con
#   export/import para CADA endpoint y CADA bucket de KV que compartan — y en gestión
#   comparten casi todo, porque el BFF atiende a las personas. Una cuenta también deja
#   los buckets de KV en un solo namespace, que es lo que hace posible que una persona y
#   un servicio tengan permisos distintos sobre el MISMO bucket.
#
# LAS DOS SENTINELAS (el detalle que más se paga si se hace mal)
#   En modo operator, si el user con el que conecta un cliente es el MISMO que está
#   declarado en --auth-user, NATS lo autoriza directo y el callout NUNCA se dispara: el
#   cliente se queda con los permisos plenos de ese user. Por eso hacen falta dos:
#     sentinel-handler  va en --auth-user. Lo usa el CALLOUT (no puede autorizarse a sí
#                       mismo, así que tiene que saltear el callout).
#     sentinel-client   NO va en --auth-user, así que conectar con él DISPARA el callout.
#                       Se le niega todo permiso propio, para que el único acceso que
#                       tenga una conexión venga del User JWT que emite el callout.
#   Es seguro distribuir sentinel-client: por sí solo no autoriza nada.
#
# Idempotente: si ya hay identidad generada en out/, la reusa. Regenerar = borrar out/.
#
# Requisitos: nsc en PATH.  Uso: cp -n .env.example .env && ./bootstrap.sh

set -euo pipefail
cd "$(dirname "$0")"

if command -v go >/dev/null 2>&1; then
  export PATH="$PATH:$(go env GOPATH)/bin"
fi
command -v nsc >/dev/null 2>&1 || { echo "ERROR: nsc no está en PATH" >&2; exit 1; }

OPERATOR="gestion"
ACCT_APP="GESTION"
ACCT_AUTH="GESTION_AUTH"

OUT_DIR="./out"
NSC_HOME="$OUT_DIR/nsc"
KEYS_DIR="$NSC_HOME/keys"
RESOLVER_CONF="$OUT_DIR/nats-resolver.conf"
NSC=(nsc -H "$NSC_HOME")

# --- idempotencia ---------------------------------------------------------------------
# Regenerar la identidad rompe la confianza del server que ya está corriendo y obliga a
# reemitir todas las creds. Los tres archivos juntos son la señal de "ya está generado".
if [[ -f "$OUT_DIR/callout-env.sh" && -f "$RESOLVER_CONF" && -d "$KEYS_DIR" ]]; then
  echo "==> Identidad ya presente en $OUT_DIR — reusando."
  echo "    (para regenerar: rm -rf $OUT_DIR)"
  exit 0
fi

echo "==> Generando identidad NATS desde cero."
rm -rf "$NSC_HOME"
mkdir -p "$OUT_DIR" "$NSC_HOME"

# --- helpers --------------------------------------------------------------------------
acct_pub() { "${NSC[@]}" describe account "$1" --field sub | tr -d '"'; }
user_pub() { "${NSC[@]}" describe user --account "$1" --name "$2" --field sub | tr -d '"'; }

# Seed (S...) del primer signing key de una cuenta. Con `nsc -H`, las claves viven en
# $NSC_HOME/keys/<inicial>/<2 chars>/<KEY>.nk
acct_sk_seed() {
  local acct="$1" sk file
  sk="$("${NSC[@]}" describe account "$acct" --field 'nats.signing_keys[0]' | tr -d '"')"
  if [[ -z "$sk" || "$sk" == "null" ]]; then
    echo "ERROR: la cuenta $acct no tiene signing key (falta --sk generate)" >&2
    return 1
  fi
  file="$KEYS_DIR/${sk:0:1}/${sk:1:2}/${sk}.nk"
  [[ -f "$file" ]] || { echo "ERROR: no encuentro la seed en $file" >&2; return 1; }
  cat "$file"
}

echo "==> Operator + SYS"
"${NSC[@]}" add operator --generate-signing-key --sys --name "$OPERATOR"
"${NSC[@]}" edit operator --require-signing-keys

echo "==> Cuentas APP y AUTH (con signing key cada una)"
# La signing key es lo que el callout usa para firmar; la clave de cuenta se queda guardada
# y no circula. `--require-signing-keys` en el operator lo vuelve obligatorio.
for acct in "$ACCT_APP" "$ACCT_AUTH"; do
  "${NSC[@]}" add account --name "$acct" >/dev/null
  "${NSC[@]}" edit account --name "$acct" --sk generate >/dev/null
  echo "   + $acct (+sk)"
done

echo "==> JetStream en $ACCT_APP (requerido por los buckets KV)"
# Los buckets de KV son streams: sin JetStream habilitado en la cuenta, los permisos de KV
# que mintea el callout apuntarían a subjects que nadie atiende. Sin límites en dev.
"${NSC[@]}" edit account --name "$ACCT_APP" \
  --js-mem-storage -1 --js-disk-storage -1 --js-streams -1 --js-consumer -1 >/dev/null

echo "==> Sentinelas en $ACCT_AUTH (dos: handler + client)"
"${NSC[@]}" add user --account "$ACCT_AUTH" --name sentinel-handler >/dev/null
# Deny-all: el sentinel-client no debe conceder NADA por sí mismo. Todo el acceso de una
# conexión tiene que venir del User JWT que emite el callout.
"${NSC[@]}" add user --account "$ACCT_AUTH" --name sentinel-client \
  --deny-pub ">" --deny-sub ">" >/dev/null

"${NSC[@]}" generate creds --account "$ACCT_AUTH" --name sentinel-handler > "$OUT_DIR/sentinel-handler.creds"
"${NSC[@]}" generate creds --account "$ACCT_AUTH" --name sentinel-client  > "$OUT_DIR/sentinel-client.creds"

echo "==> XKey del callout (curve25519)"
# Encripta los requests de callout de punta a punta: sin esto, el access token del cliente
# viaja en claro por el subject $SYS.REQ.USER.AUTH.
# `nsc generate nkey --curve` imprime la seed (SX...) y después la pública (X...).
XKEY_OUT="$("${NSC[@]}" generate nkey --curve)"
XKEY_SEED="$(echo "$XKEY_OUT" | grep '^SX' | head -1)"
XKEY_PUB="$(echo "$XKEY_OUT" | grep '^X' | head -1)"
[[ -n "$XKEY_SEED" && -n "$XKEY_PUB" ]] || { echo "ERROR: no pude extraer la XKey" >&2; exit 1; }
printf '%s\n' "$XKEY_SEED" > "$OUT_DIR/callout-xkey.seed"
printf '%s\n' "$XKEY_PUB"  > "$OUT_DIR/callout-xkey.pub"
echo "   XKey pub: $XKEY_PUB"

APP_PUB="$(acct_pub "$ACCT_APP")"
AUTH_PUB="$(acct_pub "$ACCT_AUTH")"
HANDLER_PUB="$(user_pub "$ACCT_AUTH" sentinel-handler)"

echo "==> authcallout en $ACCT_AUTH (mintea hacia $ACCT_APP)"
# Los flags reciben PUBKEYS, no nombres. Y es --curve, no --xkey.
#   --auth-user       el sentinel-handler: la conexión que BYPASEA el callout
#   --allowed-account la cuenta APP: a dónde puede minteear el callout
"${NSC[@]}" edit authcallout \
  --account "$ACCT_AUTH" \
  --auth-user "$HANDLER_PUB" \
  --allowed-account "$APP_PUB" \
  --curve "$XKEY_PUB" >/dev/null

echo "==> Extrayendo claves para el binario"
# Dos signing keys DISTINTAS, con roles distintos:
#   APP  firma el User JWT            -> define en qué cuenta aterriza el usuario
#   AUTH firma el authorization_response -> es el issuer que el server tiene configurado
acct_sk_seed "$ACCT_APP"  > "$OUT_DIR/app-account.sk.seed"
acct_sk_seed "$ACCT_AUTH" > "$OUT_DIR/auth-account.sk.seed"
printf '%s\n' "$APP_PUB"  > "$OUT_DIR/app-account.pub"
printf '%s\n' "$AUTH_PUB" > "$OUT_DIR/auth-account.pub"

echo "==> Resolver MEMORY autocontenido ($RESOLVER_CONF)"
# --mem-resolver precarga todos los JWTs de cuenta en el archivo, así el server arranca
# solo, sin necesidad de `nsc push` contra un server que todavía no existe.
"${NSC[@]}" generate config --mem-resolver --sys-account SYS > "$RESOLVER_CONF"

echo "==> Contrato para el binario ($OUT_DIR/callout-env.sh)"
# El script de arranque hace `source` de este archivo. Así las seeds nunca se escriben a
# mano en el .env y regenerar la identidad no obliga a editar configuración.
cat > "$OUT_DIR/callout-env.sh" <<'EOF'
# callout-env.sh — GENERADO por bootstrap.sh. NO COMMITEAR (out/ está gitignored).
# Rutas relativas a nats/. Las variables apuntan a ARCHIVOS; el binario acepta tanto el
# path como la seed literal.
export GESTION_HANDLER_CREDS="${GESTION_NATS_DIR:-.}/out/sentinel-handler.creds"
export GESTION_APP_ACCOUNT_SK_SEED="${GESTION_NATS_DIR:-.}/out/app-account.sk.seed"
export GESTION_APP_ACCOUNT_PUB="${GESTION_NATS_DIR:-.}/out/app-account.pub"
export GESTION_AUTH_ACCOUNT_SK_SEED="${GESTION_NATS_DIR:-.}/out/auth-account.sk.seed"
export GESTION_XKEY_SEED="${GESTION_NATS_DIR:-.}/out/callout-xkey.seed"
EOF

cat <<EOF

==> Listo.

  Cuenta APP  ($ACCT_APP):  $APP_PUB
  Cuenta AUTH ($ACCT_AUTH): $AUTH_PUB

  Los clientes conectan con out/sentinel-client.creds + su access token de Zitadel.
  El callout conecta con out/sentinel-handler.creds (bypasea el callout).

  Siguiente: make run
EOF
