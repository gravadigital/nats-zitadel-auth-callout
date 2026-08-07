#!/usr/bin/env bash
#
# token-info.sh — decodifica un access token de Zitadel y muestra lo que el callout
# necesita de él. NO verifica la firma: es una herramienta de diagnóstico.
#
# Contesta las dos preguntas que explican casi cualquier fallo de la prueba:
#
#   1. ¿Es un JWT?  El callout valida por JWKS. Si Zitadel emitió un token OPACO, no hay
#      nada que verificar localmente y el callout lo rechaza como inválido. Se arregla
#      poniendo el tipo de token en JWT en la app de Zitadel.
#   2. ¿Trae roles?  Sin la claim de roles el callout no matchea ninguna regla y rechaza la
#      conexión. Suele ser que falta el scope urn:zitadel:iam:org:projects:roles, o que el
#      rol no está concedido al usuario en el proyecto.
#
# Uso:
#   ./scripts/token-info.sh "$TOKEN"
#   echo "$TOKEN" | ./scripts/token-info.sh

set -euo pipefail

command -v jq >/dev/null || { echo "falta jq" >&2; exit 1; }

TOKEN="${1:-}"
[[ -n "$TOKEN" ]] || TOKEN=$(cat)
TOKEN=$(echo "$TOKEN" | tr -d '[:space:]')
[[ -n "$TOKEN" ]] || { echo "token vacío" >&2; exit 1; }

parts=$(echo "$TOKEN" | awk -F. '{print NF}')
if [[ "$parts" -ne 3 ]]; then
  echo "NO es un JWT (tiene $parts partes, un JWT tiene 3)."
  echo
  echo "Zitadel emitió un token OPACO. El callout valida por JWKS, así que no puede"
  echo "verificarlo y lo va a rechazar como inválido."
  echo
  echo "Arreglo: en Zitadel, en la aplicación que emite el token, poner el tipo de token"
  echo "de acceso en JWT (Token Settings -> Auth Token Type: JWT)."
  exit 1
fi

# base64url -> base64 con padding.
b64url_decode() {
  local data="${1//-/+}"; data="${data//_//}"
  case $(( ${#data} % 4 )) in
    2) data="${data}==" ;;
    3) data="${data}=" ;;
  esac
  echo "$data" | base64 -d 2>/dev/null
}

payload=$(b64url_decode "$(echo "$TOKEN" | cut -d. -f2)")

echo "Es un JWT. ✓"
echo
echo "iss  $(echo "$payload" | jq -r '.iss // "(falta)"')"
echo "sub  $(echo "$payload" | jq -r '.sub // "(falta)"')"
echo "aud  $(echo "$payload" | jq -rc '.aud // "(falta)"')"
exp=$(echo "$payload" | jq -r '.exp // empty')
if [[ -n "$exp" ]]; then
  echo "exp  $exp  ($(date -d "@$exp" '+%Y-%m-%d %H:%M:%S') — en $(( (exp - $(date +%s)) / 60 )) min)"
else
  echo "exp  (falta) — el callout va a acotar la sesión NATS a 1 hora"
fi
echo "user $(echo "$payload" | jq -r '.preferred_username // "(falta — se pide por userinfo)"')"
echo

echo "Claims de roles presentes:"
roles=$(echo "$payload" | jq -r 'to_entries
  | map(select(.key | test("urn:zitadel:iam:org:project:.*roles")))
  | .[] | "  \(.key)\n    -> \(.value | keys | join(", "))"')
if [[ -z "$roles" ]]; then
  echo "  NINGUNA."
  echo
  echo "El callout no va a poder matchear ninguna regla y va a rechazar la conexión."
  echo "Causas habituales:"
  echo "  - falta el scope 'urn:zitadel:iam:org:projects:roles' al pedir el token;"
  echo "  - el rol no está concedido al usuario en el proyecto (Authorizations);"
  echo "  - el proyecto vive en otra org y el rol no está habilitado en el project-grant."
  exit 1
fi
echo "$roles"
echo
echo "Esos nombres de rol son los que tienen que aparecer en config/rules.yaml como 'match'."

# La sesión derivada, para saber qué subjects y qué inbox le van a corresponder.
sub=$(echo "$payload" | jq -r '.sub // empty')
if [[ -n "$sub" ]] && command -v go >/dev/null 2>&1; then
  echo
  echo "Identidad que va a derivar el callout si la regla es 'type: person':"
  (cd "$(dirname "$0")/.." && go run ./cmd/session "$sub" "${GESTION_INSTANCE:-dev}" 2>/dev/null | sed 's/^/  /')
fi
