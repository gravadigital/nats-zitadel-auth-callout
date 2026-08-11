#!/usr/bin/env bash
#
# token-info.sh — decodes a Zitadel access token and shows what the callout needs from it.
# It does NOT verify the signature: this is a diagnostic tool.
#
# It answers the two questions that explain almost any test failure:
#
#   1. Is it a JWT?  The callout validates through JWKS. If Zitadel issued an OPAQUE token,
#      there is nothing to verify locally and the callout rejects it as invalid. The fix is
#      setting the token type to JWT in the Zitadel app.
#   2. Does it carry roles?  Without the roles claim the callout matches no rule and rejects
#      the connection. Usually the urn:zitadel:iam:org:projects:roles scope is missing, or the
#      role is not granted to the user in the project.
#
# Usage:
#   ./scripts/token-info.sh "$TOKEN"
#   echo "$TOKEN" | ./scripts/token-info.sh

set -euo pipefail

command -v jq >/dev/null || { echo "jq is missing" >&2; exit 1; }

TOKEN="${1:-}"
[[ -n "$TOKEN" ]] || TOKEN=$(cat)
TOKEN=$(echo "$TOKEN" | tr -d '[:space:]')
[[ -n "$TOKEN" ]] || { echo "empty token" >&2; exit 1; }

parts=$(echo "$TOKEN" | awk -F. '{print NF}')
if [[ "$parts" -ne 3 ]]; then
  echo "NOT a JWT (it has $parts parts, a JWT has 3)."
  echo
  echo "Zitadel issued an OPAQUE token. The callout validates through JWKS, so it cannot"
  echo "verify it and will reject it as invalid."
  echo
  echo "Fix: in Zitadel, on the application issuing the token, set the access token type"
  echo "to JWT (Token Settings -> Auth Token Type: JWT)."
  exit 1
fi

# base64url -> base64 with padding.
b64url_decode() {
  local data="${1//-/+}"; data="${data//_//}"
  case $(( ${#data} % 4 )) in
    2) data="${data}==" ;;
    3) data="${data}=" ;;
  esac
  echo "$data" | base64 -d 2>/dev/null
}

payload=$(b64url_decode "$(echo "$TOKEN" | cut -d. -f2)")

echo "It is a JWT. ✓"
echo
echo "iss  $(echo "$payload" | jq -r '.iss // "(missing)"')"
echo "sub  $(echo "$payload" | jq -r '.sub // "(missing)"')"
echo "aud  $(echo "$payload" | jq -rc '.aud // "(missing)"')"
exp=$(echo "$payload" | jq -r '.exp // empty')
if [[ -n "$exp" ]]; then
  echo "exp  $exp  ($(date -d "@$exp" '+%Y-%m-%d %H:%M:%S') — in $(( (exp - $(date +%s)) / 60 )) min)"
else
  echo "exp  (missing) — the callout will cap the NATS session at 1 hour"
fi
echo "user $(echo "$payload" | jq -r '.preferred_username // "(missing — requested through userinfo)"')"
echo

echo "Role claims present:"
roles=$(echo "$payload" | jq -r 'to_entries
  | map(select(.key | test("urn:zitadel:iam:org:project:.*roles")))
  | .[] | "  \(.key)\n    -> \(.value | keys | join(", "))"')
if [[ -z "$roles" ]]; then
  echo "  NONE."
  echo
  echo "The callout will not be able to match any rule and will reject the connection."
  echo "Common causes:"
  echo "  - the 'urn:zitadel:iam:org:projects:roles' scope was not requested with the token;"
  echo "  - the role is not granted to the user in the project (Authorizations);"
  echo "  - the project lives in another org and the role is not enabled in the project-grant."
  exit 1
fi
echo "$roles"
echo
echo "Those role names are the ones that have to appear in examples/rules.yaml as 'match'."

# The derived identity, to know which subjects and which inbox will correspond to it.
sub=$(echo "$payload" | jq -r '.sub // empty')
if [[ -n "$sub" ]] && command -v go >/dev/null 2>&1; then
  echo
  echo "Identity the callout will derive if the rule is 'type: person':"
  (cd "$(dirname "$0")/.." && go run ./cmd/session "$sub" "${CALLOUT_INSTANCE:-dev}" 2>/dev/null | sed 's/^/  /')
fi
