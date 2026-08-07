#!/usr/bin/env bash
#
# zitadel-token.sh — imprime un access token de Zitadel para un service user (machine user).
#
# Detecta automáticamente los dos formatos de credencial que entrega Zitadel:
#
#   A) key JSON  {keyId, key, userId}      → JWT-profile (private_key_jwt)
#      Se firma localmente un JWT con la private key y se intercambia por un token.
#      Es el formato de "Keys → New → JSON" en el machine user. Necesita openssl.
#
#   B) app creds {clientId, clientSecret}  → client_credentials (Basic auth)
#      Es el formato de "Secrets → Generate Client Secret" en el machine user.
#      Más simple: un solo curl, sin firmar nada.
#
# Uso:
#   ZITADEL_ISSUER_URL=https://id.grava.io ./scripts/zitadel-token.sh secrets/poc-user.json
#   cat creds.json | ZITADEL_ISSUER_URL=https://id.grava.io ./scripts/zitadel-token.sh
#
# Variables:
#   ZITADEL_ISSUER_URL        (obligatoria) la instancia de Zitadel
#   ZITADEL_PROJECT_ID        (recomendada) proyecto donde viven los roles; agrega el
#                             scope de audiencia para que el proyecto entre en el `aud`
#   ZITADEL_PROJECT_AUDIENCE  (opcional, solo formato A) audience del assertion JWT;
#                             por defecto el issuer

set -euo pipefail

ISSUER="${ZITADEL_ISSUER_URL:?falta ZITADEL_ISSUER_URL}"
ISSUER="${ISSUER%/}"

for bin in jq curl; do
  command -v "$bin" >/dev/null || { echo "falta $bin" >&2; exit 1; }
done

if [[ $# -ge 1 && -n "${1:-}" ]]; then
  [[ -f "$1" ]] || { echo "no existe el archivo: $1" >&2; exit 1; }
  JSON=$(cat "$1")
else
  JSON=$(cat)
fi
[[ -n "$JSON" ]] || { echo "JSON vacío (pasá un archivo o por stdin)" >&2; exit 1; }

has() { echo "$JSON" | jq -e "$1" >/dev/null 2>&1; }

# --- Scopes ---------------------------------------------------------------------------
#
# `urn:zitadel:iam:org:projects:roles` es OBLIGATORIO. Sin él, un token de machine user NO
# TRAE LOS ROLES: a diferencia del login web interactivo (que asserta roles según el flag
# del proyecto), los flujos machine-to-machine solo incluyen el claim
# `urn:zitadel:iam:org:project:<id>:roles` si se pide explícitamente este scope.
#
# Y es el scope GENÉRICO el que funciona: pedir los roles de un proyecto puntual
# (`...:project:id:<id>:roles`) no alcanzó en la práctica. Verificado en vivo.
#
# Sin roles en el token, el callout no matchea ninguna regla y rechaza la conexión. El
# síntoma es un `Authorization Violation` al conectar y un "no se pudo resolver permisos"
# con `roles=[]` en el log del callout.
SCOPE="openid profile urn:zitadel:iam:org:projects:roles"

# Mete el proyecto en el `aud` del token. Con verificación por JWKS no es imprescindible
# (la firma se valida localmente), pero sí lo es si algún día se usa introspección.
if [[ -n "${ZITADEL_PROJECT_ID:-}" ]]; then
  SCOPE="$SCOPE urn:zitadel:iam:org:project:id:${ZITADEL_PROJECT_ID}:aud"
fi

# --- Detección de formato -------------------------------------------------------------
if has '.key and .keyId' && ! has '.userId'; then
  echo "ERROR: el JSON tiene keyId/key pero NO userId." >&2
  echo "La key de machine user de Zitadel incluye 'userId' (es el iss/sub del assertion)." >&2
  echo "Reexportá la key completa desde el machine user." >&2
  exit 1
fi

if has '.key and .keyId and .userId'; then
  command -v openssl >/dev/null || { echo "falta openssl (formato keyId/key/userId)" >&2; exit 1; }

  AUD="${ZITADEL_PROJECT_AUDIENCE:-$ISSUER}"
  KEY_ID=$(echo "$JSON" | jq -r .keyId)
  USER_ID=$(echo "$JSON" | jq -r .userId)
  PRIV=$(mktemp)
  chmod 600 "$PRIV"
  echo "$JSON" | jq -r .key > "$PRIV"
  trap 'rm -f "$PRIV"' EXIT

  now=$(date +%s); exp=$((now + 300))
  b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
  header=$(printf '{"alg":"RS256","kid":"%s"}' "$KEY_ID" | b64)
  payload=$(printf '{"iss":"%s","sub":"%s","aud":"%s","iat":%d,"exp":%d}' \
    "$USER_ID" "$USER_ID" "$AUD" "$now" "$exp" | b64)
  sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$PRIV" | b64)

  resp=$(curl -s -X POST "$ISSUER/oauth/v2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
    --data-urlencode "scope=$SCOPE" \
    --data-urlencode "assertion=$header.$payload.$sig")

elif has '.clientId and .clientSecret'; then
  CID=$(echo "$JSON" | jq -r .clientId)
  CSECRET=$(echo "$JSON" | jq -r .clientSecret)

  resp=$(curl -s -X POST "$ISSUER/oauth/v2/token" \
    -u "$CID:$CSECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "scope=$SCOPE")

else
  echo "ERROR: JSON no reconocido. Esperaba {keyId,key,userId} o {clientId,clientSecret}." >&2
  echo "Claves presentes: $(echo "$JSON" | jq -r 'keys | join(", ")')" >&2
  exit 1
fi

token=$(echo "$resp" | jq -r '.access_token // empty')
if [[ -z "$token" ]]; then
  echo "ERROR: Zitadel no devolvió access_token. Respuesta:" >&2
  echo "$resp" | jq . >&2 2>/dev/null || echo "$resp" >&2
  exit 1
fi
echo "$token"
