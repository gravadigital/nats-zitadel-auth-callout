#!/usr/bin/env bash
#
# nsc-extract.sh — read an nsc store and write the environment the callout needs.
#
# WHERE THIS RUNS
#   On the machine that holds the nsc store — an operator's workstation — NOT on the server
#   running the callout. The service never touches nsc: it only receives seeds and public keys
#   through environment variables. This is a one-time step whose output is then handed to
#   whatever manages secrets in the deployment.
#
# WHAT IT SOLVES
#   `nsc export keys` already extracts seeds, but names the files by public key. The question an
#   operator actually has is "which of these goes in CALLOUT_APP_ACCOUNT_SK_SEED and which in
#   CALLOUT_AUTH_ACCOUNT_SK_SEED?", and getting it backwards produces an Authorization Violation
#   with nothing in any log pointing at the cause.
#
#   Nothing here has to be guessed. The auth callout configuration inside an account JWT states
#   the whole topology:
#
#     the account that HAS `nats.authorization`      -> the AUTH account
#     its `allowed_accounts`                         -> the account clients land in (APP)
#     its `auth_users`                               -> the handler the callout connects as
#     its `xkey`                                     -> the encryption key's public half
#
#   So this discovers rather than asks, and refuses to continue when what it finds is ambiguous.
#
# Usage:
#   ./scripts/nsc-extract.sh --store PATH [--out DIR] [--env-file PATH]
#
#   --store      the nsc store directory (what `nsc -H` takes). Required.
#   --out        where to write the seed files. Default: ./secrets
#   --env-file   where to write the variables. Default: <out>/callout.env
#
# Requirements: nsc and jq on PATH.

set -euo pipefail

STORE=""
OUT_DIR="./secrets"
ENV_FILE=""

die() { echo "ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --store)    STORE="${2:-}"; shift 2 ;;
    --out)      OUT_DIR="${2:-}"; shift 2 ;;
    --env-file) ENV_FILE="${2:-}"; shift 2 ;;
    -h|--help)  sed -n '2,36p' "$0"; exit 0 ;;
    *)          die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ -n "$STORE" ]] || die "--store is required (the nsc store directory, what \`nsc -H\` takes)"
[[ -d "$STORE" ]] || die "no such nsc store: $STORE"
command -v nsc >/dev/null 2>&1 || die "nsc is not on PATH"
command -v jq  >/dev/null 2>&1 || die "jq is not on PATH"

ENV_FILE="${ENV_FILE:-$OUT_DIR/callout.env}"
NSC=(nsc -H "$STORE")

# --- discover the topology ------------------------------------------------------------------

echo "==> Reading $STORE"

# `nsc list --json` writes its JSON to STDERR, unlike `describe` and `generate`, which use
# stdout. Redirecting stderr away here yields an empty result rather than an error, so the
# streams are merged deliberately.
accounts_json="$("${NSC[@]}" list accounts --json 2>&1)" \
  || die "could not list accounts in $STORE — is it an nsc store?"

mapfile -t account_names < <(jq -r '.[].name' <<<"$accounts_json")
[[ ${#account_names[@]} -gt 0 ]] || die "the store declares no accounts"

# The AUTH account is the one carrying an auth callout configuration. Looking for it rather than
# taking it as an argument means a mistyped account name cannot silently produce a working-looking
# but wrong environment.
auth_name=""
auth_json=""
for name in "${account_names[@]}"; do
  json="$("${NSC[@]}" describe account "$name" --json 2>/dev/null)" || continue
  # Every account carries `nats.authorization`, empty for the ones with no callout, so its mere
  # presence proves nothing. `auth_users` is what makes an account a callout account: it names
  # the user the server authorizes directly instead of calling out for.
  if [[ "$(jq -r '.nats.authorization.auth_users // [] | length' <<<"$json")" != "0" ]]; then
    if [[ -n "$auth_name" ]]; then
      die "more than one account declares an auth callout ($auth_name and $name). This script handles one callout per store; extract the second one by hand."
    fi
    auth_name="$name"
    auth_json="$json"
  fi
done

[[ -n "$auth_name" ]] || die "no account in this store declares an auth callout.
       Run \`nsc edit authcallout\` first, or see examples/operator-mode/README.md."

auth_pub="$(jq -r '.sub' <<<"$auth_json")"
xkey_pub="$(jq -r '.nats.authorization.xkey // empty' <<<"$auth_json")"

mapfile -t allowed < <(jq -r '.nats.authorization.allowed_accounts[]? // empty' <<<"$auth_json")
mapfile -t auth_users < <(jq -r '.nats.authorization.auth_users[]? // empty' <<<"$auth_json")

# The callout mints into exactly one account, so more than one allowed account is a topology this
# configuration cannot express. Saying so is better than picking the first and being wrong later.
case ${#allowed[@]} in
  0) die "the auth callout on $auth_name declares no allowed_accounts, so there is no account to mint users into.
       Fix it with: nsc edit authcallout --account $auth_name --allowed-account <APP-PUBKEY>" ;;
  1) app_pub="${allowed[0]}" ;;
  *) die "the auth callout on $auth_name allows ${#allowed[@]} accounts. The callout mints into ONE account, so pick the intended one and set CALLOUT_APP_ACCOUNT_PUB by hand." ;;
esac

app_name="$(jq -r --arg pk "$app_pub" '.[] | select(.public_key == $pk) | .name' <<<"$accounts_json")"
[[ -n "$app_name" ]] || die "allowed_accounts names $app_pub, which is not an account in this store"

# The handler is the user the callout connects as. Anything else in auth_users bypasses the
# callout entirely, so more than one entry is worth stopping on rather than guessing.
case ${#auth_users[@]} in
  0) die "the auth callout on $auth_name declares no auth_users, so the callout has no user that bypasses it and it cannot authorize its own connection.
       Fix it with: nsc edit authcallout --account $auth_name --auth-user <HANDLER-PUBKEY>" ;;
  1) handler_pub="${auth_users[0]}" ;;
  *) die "auth_users on $auth_name lists ${#auth_users[@]} users. Everything listed there BYPASSES the callout, so only the callout's own handler belongs in it. Remove the others before extracting." ;;
esac

users_json="$("${NSC[@]}" list users --account "$auth_name" --json 2>&1 || echo '[]')"
handler_name="$(jq -r --arg pk "$handler_pub" '.[] | select(.public_key == $pk) | .name' <<<"$users_json")"
[[ -n "$handler_name" ]] || die "auth_users names $handler_pub, which is not a user of $auth_name"

# Both accounts sign with a signing key rather than the account key: that is what
# `--require-signing-keys` on the operator enforces, and what the callout expects.
app_json="$("${NSC[@]}" describe account "$app_name" --json 2>/dev/null)"
app_sk="$(jq -r '.nats.signing_keys[0] // empty' <<<"$app_json")"
auth_sk="$(jq -r '.nats.signing_keys[0] // empty' <<<"$auth_json")"

[[ -n "$app_sk" ]]  || die "account $app_name has no signing key. Add one: nsc edit account --name $app_name --sk generate"
[[ -n "$auth_sk" ]] || die "account $auth_name has no signing key. Add one: nsc edit account --name $auth_name --sk generate"

echo "    AUTH account     $auth_name ($auth_pub)"
echo "    target account   $app_name ($app_pub)"
echo "    handler user     $handler_name"
echo "    XKey             ${xkey_pub:-<none configured>}"

# --- extract the private material -----------------------------------------------------------

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

# nsc writes one file per key, named by public key; this maps them onto the two roles. Exporting
# into a temporary directory keeps every OTHER key in the store out of the output.
tmp_keys="$(mktemp -d)"
trap 'rm -rf "$tmp_keys"' EXIT

"${NSC[@]}" export keys --accounts --dir "$tmp_keys" >/dev/null 2>&1 \
  || die "could not export account keys from $STORE"

copy_seed() {
  local pub="$1" dest="$2" role="$3"
  local src="$tmp_keys/$pub.nk"
  [[ -f "$src" ]] || die "no seed for the $role key ($pub) in this store.
       The store holds the public key but not its seed, so it was created elsewhere. Extract it on the machine that generated it."
  install -m 600 /dev/null "$dest"
  cat "$src" > "$dest"
}

copy_seed "$app_sk"  "$OUT_DIR/app-account.sk.seed"  "User JWT signing"
copy_seed "$auth_sk" "$OUT_DIR/auth-account.sk.seed" "response signing"

printf '%s\n' "$app_pub" > "$OUT_DIR/app-account.pub"
chmod 644 "$OUT_DIR/app-account.pub"

"${NSC[@]}" generate creds --account "$auth_name" --name "$handler_name" > "$OUT_DIR/handler.creds" 2>/dev/null \
  || die "could not generate creds for $handler_name"
chmod 600 "$OUT_DIR/handler.creds"

# The XKey is a curve key, and nsc does NOT keep those in its store: `nsc generate nkey --curve`
# prints the seed and forgets it, which is why `nsc export keys` reports "no seed available" for
# it. So whoever ran the provisioning saved it somewhere, and only they know where.
#
# It is searched for next to the store anyway, because that is where bootstrap.sh puts it and
# where an operator following our own documentation would have it.
# derive_pubkey prints the public key a seed file derives to, or nothing when no tool that can
# do it is installed. Either `nats` or `nk` will do, and both ship with the NATS ecosystem.
derive_pubkey() {
  local file="$1"
  if command -v nats >/dev/null 2>&1; then
    nats auth nkey show "$file" 2>/dev/null | head -1 && return
  fi
  if command -v nk >/dev/null 2>&1; then
    nk -inkey "$file" -pubout 2>/dev/null | head -1 && return
  fi
  return 0
}

xkey_note=""
xkey_unverified=0
if [[ -n "$xkey_pub" ]]; then
  xkey_src=""
  for candidate in \
    "$STORE/keys/${xkey_pub:0:1}/${xkey_pub:1:2}/${xkey_pub}.nk" \
    "$(dirname "$STORE")/callout-xkey.seed"
  do
    [[ -f "$candidate" ]] || continue
    # Confirm the seed really derives to the key the server expects. A seed for a DIFFERENT XKey
    # decrypts nothing, and that failure surfaces as every connection being refused — a long way
    # from here. When neither tool that can derive it is installed, the candidate is taken on
    # trust and said so, rather than silently skipped.
    derived="$(derive_pubkey "$candidate")"
    if [[ -z "$derived" ]]; then
      xkey_src="$candidate"
      xkey_unverified=1
      break
    fi
    if [[ "$derived" == "$xkey_pub" ]]; then
      xkey_src="$candidate"
      break
    fi
  done

  if [[ -n "$xkey_src" ]]; then
    install -m 600 /dev/null "$OUT_DIR/callout-xkey.seed"
    cat "$xkey_src" > "$OUT_DIR/callout-xkey.seed"
    if [[ "$xkey_unverified" == "1" ]]; then
      echo "    XKey seed        $xkey_src (NOT verified: install \`nats\` or \`nk\` to confirm it matches)"
    else
      echo "    XKey seed        $xkey_src"
    fi
  else
    xkey_note="# The server expects requests encrypted toward
#   $xkey_pub
# nsc does not store curve seeds, so this one lives wherever it was saved when the callout was
# provisioned. Point this variable at it: without the matching seed the callout cannot decrypt
# any request and every connection fails.
"
    echo "    NOTE: the XKey seed is not in the store (nsc never keeps curve seeds) — see the env file."
  fi
fi

# --- write the environment ------------------------------------------------------------------

abs_out="$(cd "$OUT_DIR" && pwd)"

cat > "$ENV_FILE" <<EOF
# Generated by scripts/nsc-extract.sh from the nsc store at:
#   $STORE
#
# These variables are what the callout reads. The seed files they point at are private keys:
# they sign every User JWT this deployment mints, so anyone holding them can grant themselves
# any permission on the bus.
#
# Discovered topology:
#   AUTH account    $auth_name
#   target account  $app_name
#   handler user    $handler_name

CALLOUT_SERVER_MODE=operator
CALLOUT_NATS_URL=nats://127.0.0.1:4222

CALLOUT_HANDLER_CREDS=$abs_out/handler.creds

CALLOUT_APP_ACCOUNT_SK_SEED=$abs_out/app-account.sk.seed
CALLOUT_APP_ACCOUNT_PUB=$abs_out/app-account.pub
CALLOUT_AUTH_ACCOUNT_SK_SEED=$abs_out/auth-account.sk.seed
EOF

if [[ -n "$xkey_pub" ]]; then
  if [[ -n "$xkey_note" ]]; then
    printf '\n%s#CALLOUT_XKEY_SEED=\n' "$xkey_note" >> "$ENV_FILE"
  else
    printf '\nCALLOUT_XKEY_SEED=%s/callout-xkey.seed\n' "$abs_out" >> "$ENV_FILE"
  fi
else
  cat >> "$ENV_FILE" <<'EOF'

# No XKey is configured on the server, so callout requests — which carry the clients' access
# tokens — travel in the clear over $SYS.REQ.USER.AUTH. Configuring one is strongly recommended.
#CALLOUT_XKEY_SEED=
EOF
fi

cat >> "$ENV_FILE" <<'EOF'

# --- still to fill in -----------------------------------------------------------------------
# These describe the deployment rather than the NATS identity, so they cannot be discovered.
CALLOUT_RULES_PATH=/etc/auth-callout/rules.yaml
CALLOUT_INSTANCE=dev
CALLOUT_IDP_MODE=zitadel
CALLOUT_ZITADEL_ISSUER_URL=
CALLOUT_ZITADEL_PROJECT_ID=
EOF

chmod 600 "$ENV_FILE"

cat <<EOF

==> Wrote $ENV_FILE

    Fill in the identity provider settings at the bottom, then check the wiring
    before serving traffic:

      set -a; . $ENV_FILE; set +a
      auth-callout verify --client-creds <the creds YOUR CLIENTS use>

    $OUT_DIR holds private keys. Keep it out of version control.
EOF
