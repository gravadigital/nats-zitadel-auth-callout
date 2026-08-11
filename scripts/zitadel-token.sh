#!/usr/bin/env bash
#
# zitadel-token.sh — prints a Zitadel access token for a service user (machine user).
#
# It auto-detects the two credential formats Zitadel hands out:
#
#   A) key JSON  {keyId, key, userId}      → JWT-profile (private_key_jwt)
#      A JWT is signed locally with the private key and exchanged for a token.
#      This is the "Keys → New → JSON" format on the machine user. It needs openssl.
#
#   B) app creds {clientId, clientSecret}  → client_credentials (Basic auth)
#      This is the "Secrets → Generate Client Secret" format on the machine user.
#      Simpler: a single curl, nothing to sign.
#
# Usage:
#   ZITADEL_ISSUER_URL=https://id.example.com ./scripts/zitadel-token.sh secrets/app-user.json
#   cat creds.json | ZITADEL_ISSUER_URL=https://id.example.com ./scripts/zitadel-token.sh
#
# Variables:
#   ZITADEL_ISSUER_URL        (required) the Zitadel instance
#   ZITADEL_PROJECT_ID        (recommended) the project where the roles live; it adds the
#                             audience scope so the project ends up in the `aud`
#   ZITADEL_PROJECT_AUDIENCE  (optional, format A only) the assertion JWT's audience;
#                             defaults to the issuer

set -euo pipefail

ISSUER="${ZITADEL_ISSUER_URL:?ZITADEL_ISSUER_URL is not set}"
ISSUER="${ISSUER%/}"

for bin in jq curl; do
  command -v "$bin" >/dev/null || { echo "$bin is missing" >&2; exit 1; }
done

if [[ $# -ge 1 && -n "${1:-}" ]]; then
  [[ -f "$1" ]] || { echo "file does not exist: $1" >&2; exit 1; }
  JSON=$(cat "$1")
else
  JSON=$(cat)
fi
[[ -n "$JSON" ]] || { echo "empty JSON (pass a file or pipe it through stdin)" >&2; exit 1; }

has() { echo "$JSON" | jq -e "$1" >/dev/null 2>&1; }

# --- Scopes ---------------------------------------------------------------------------
#
# `urn:zitadel:iam:org:projects:roles` is MANDATORY. Without it, a machine user token does NOT
# CARRY THE ROLES: unlike the interactive web login (which asserts roles according to the
# project's flag), machine-to-machine flows only include the
# `urn:zitadel:iam:org:project:<id>:roles` claim if this scope is requested explicitly.
#
# And it is the GENERIC scope that works: requesting the roles of a specific project
# (`...:project:id:<id>:roles`) did not suffice in practice. Verified live.
#
# With no roles in the token, the callout matches no rule and rejects the connection. The
# symptom is an `Authorization Violation` when connecting and a "could not resolve permissions"
# with `roles=[]` in the callout's log.
SCOPE="openid profile urn:zitadel:iam:org:projects:roles"

# Puts the project into the token's `aud`. With JWKS verification it is not essential (the
# signature is validated locally), but it is if introspection is ever used.
if [[ -n "${ZITADEL_PROJECT_ID:-}" ]]; then
  SCOPE="$SCOPE urn:zitadel:iam:org:project:id:${ZITADEL_PROJECT_ID}:aud"
fi

# --- Format detection -----------------------------------------------------------------
if has '.key and .keyId' && ! has '.userId'; then
  echo "ERROR: the JSON has keyId/key but NOT userId." >&2
  echo "A Zitadel machine user key includes 'userId' (it is the assertion's iss/sub)." >&2
  echo "Re-export the complete key from the machine user." >&2
  exit 1
fi

if has '.key and .keyId and .userId'; then
  command -v openssl >/dev/null || { echo "openssl is missing (keyId/key/userId format)" >&2; exit 1; }

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
  echo "ERROR: unrecognized JSON. Expected {keyId,key,userId} or {clientId,clientSecret}." >&2
  echo "Keys present: $(echo "$JSON" | jq -r 'keys | join(", ")')" >&2
  exit 1
fi

token=$(echo "$resp" | jq -r '.access_token // empty')
if [[ -z "$token" ]]; then
  echo "ERROR: Zitadel returned no access_token. Response:" >&2
  echo "$resp" | jq . >&2 2>/dev/null || echo "$resp" >&2
  exit 1
fi
echo "$token"
