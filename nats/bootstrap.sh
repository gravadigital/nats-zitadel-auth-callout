#!/usr/bin/env bash
#
# bootstrap.sh — generates the NATS identity that nats-zitadel-auth-callout needs.
#
# It produces, in an ISOLATED nsc store under out/nsc (it never touches your
# ~/.local/share/nats):
#
#   operator + SYS
#   APP    APP account  — where ALL connections land (people and services)
#   AUTH   AUTH account — where the callout and its two sentinels live
#   the callout's XKey, the authcallout config, and a self-contained MEMORY resolver
#
# WHY A SINGLE APP ACCOUNT
#   People and services share the `APP` account. The isolation between them comes from the
#   subject permissions the callout mints, which the server is the one to enforce. Splitting
#   them into two accounts would add a boundary that would have to be punched through with
#   export/import for EVERY endpoint and EVERY KV bucket they share — and they share almost
#   everything, because the BFF serves the people. A single account also keeps the KV buckets
#   in one namespace, which is what makes it possible for a person and a service to hold
#   different permissions over the SAME bucket.
#
# THE TWO SENTINELS (the detail that costs the most if you get it wrong)
#   In operator mode, if the user a client connects with is the SAME one declared in
#   --auth-user, NATS authorizes it directly and the callout NEVER fires: the client keeps that
#   user's full permissions. That is why two are needed:
#     sentinel-handler  goes in --auth-user. The CALLOUT uses it (it cannot authorize itself,
#                       so it has to bypass the callout).
#     sentinel-client   does NOT go in --auth-user, so connecting with it TRIGGERS the callout.
#                       It is denied every permission of its own, so that the only access a
#                       connection has comes from the User JWT the callout issues.
#   sentinel-client is safe to distribute: on its own it authorizes nothing.
#
# Idempotent: if there is already a generated identity in out/, it is reused. To regenerate,
# delete out/.
#
# Requirements: nsc on PATH.  Usage: cp -n .env.example .env && ./bootstrap.sh

set -euo pipefail
cd "$(dirname "$0")"

if command -v go >/dev/null 2>&1; then
  export PATH="$PATH:$(go env GOPATH)/bin"
fi
command -v nsc >/dev/null 2>&1 || { echo "ERROR: nsc is not on PATH" >&2; exit 1; }

OPERATOR="nats-callout"
ACCT_APP="APP"
ACCT_AUTH="AUTH"

# The authentication event publisher's identity is generated here too, so that turning the
# feature on is one line in .env rather than a detour through nsc. Its grant needs to know the
# instance and the stream name, which are decisions and therefore live in .env.
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a
fi
EVENTS_INSTANCE="${CALLOUT_INSTANCE:-dev}"
EVENTS_STREAM="${CALLOUT_EVENTS_STREAM:-AUTH_EVENTS}"

OUT_DIR="./out"
NSC_HOME="$OUT_DIR/nsc"
KEYS_DIR="$NSC_HOME/keys"
RESOLVER_CONF="$OUT_DIR/nats-resolver.conf"
NSC=(nsc -H "$NSC_HOME")

# --- idempotency ----------------------------------------------------------------------
# Regenerating the identity breaks the trust of an already-running server and forces
# reissuing every cred. The three files together are the "already generated" signal.
if [[ -f "$OUT_DIR/callout-env.sh" && -f "$RESOLVER_CONF" && -d "$KEYS_DIR" ]]; then
  echo "==> Identity already present in $OUT_DIR — reusing."
  echo "    (to regenerate: rm -rf $OUT_DIR)"
  exit 0
fi

echo "==> Generating the NATS identity from scratch."
rm -rf "$NSC_HOME"
mkdir -p "$OUT_DIR" "$NSC_HOME"

# --- helpers --------------------------------------------------------------------------
acct_pub() { "${NSC[@]}" describe account "$1" --field sub | tr -d '"'; }
user_pub() { "${NSC[@]}" describe user --account "$1" --name "$2" --field sub | tr -d '"'; }

# Seed (S...) of an account's first signing key. With `nsc -H`, the keys live in
# $NSC_HOME/keys/<initial>/<2 chars>/<KEY>.nk
acct_sk_seed() {
  local acct="$1" sk file
  sk="$("${NSC[@]}" describe account "$acct" --field 'nats.signing_keys[0]' | tr -d '"')"
  if [[ -z "$sk" || "$sk" == "null" ]]; then
    echo "ERROR: account $acct has no signing key (missing --sk generate)" >&2
    return 1
  fi
  file="$KEYS_DIR/${sk:0:1}/${sk:1:2}/${sk}.nk"
  [[ -f "$file" ]] || { echo "ERROR: cannot find the seed at $file" >&2; return 1; }
  cat "$file"
}

echo "==> Operator + SYS"
"${NSC[@]}" add operator --generate-signing-key --sys --name "$OPERATOR"
"${NSC[@]}" edit operator --require-signing-keys

echo "==> APP and AUTH accounts (each with a signing key)"
# The signing key is what the callout signs with; the account key stays stored away and never
# circulates. `--require-signing-keys` on the operator makes that mandatory.
for acct in "$ACCT_APP" "$ACCT_AUTH"; do
  "${NSC[@]}" add account --name "$acct" >/dev/null
  "${NSC[@]}" edit account --name "$acct" --sk generate >/dev/null
  echo "   + $acct (+sk)"
done

echo "==> JetStream on $ACCT_APP (required by the KV buckets)"
# KV buckets are streams: without JetStream enabled on the account, the KV permissions the
# callout mints would point at subjects nobody serves. No limits in dev.
"${NSC[@]}" edit account --name "$ACCT_APP" \
  --js-mem-storage -1 --js-disk-storage -1 --js-streams -1 --js-consumer -1 >/dev/null

echo "==> Sentinels on $ACCT_AUTH (two: handler + client)"
"${NSC[@]}" add user --account "$ACCT_AUTH" --name sentinel-handler >/dev/null
# Deny-all: the sentinel-client must grant NOTHING on its own. All of a connection's access has
# to come from the User JWT the callout issues.
"${NSC[@]}" add user --account "$ACCT_AUTH" --name sentinel-client \
  --deny-pub ">" --deny-sub ">" >/dev/null

"${NSC[@]}" generate creds --account "$ACCT_AUTH" --name sentinel-handler > "$OUT_DIR/sentinel-handler.creds"
"${NSC[@]}" generate creds --account "$ACCT_AUTH" --name sentinel-client  > "$OUT_DIR/sentinel-client.creds"

echo "==> Events publisher and admin on $ACCT_APP"
# Two plain users of the APP account, for the OPTIONAL authentication event publisher:
#
#   callout-events  the callout's SECOND connection. It publishes one event per authenticated
#                   connection. It lands in APP rather than AUTH because that is where the
#                   consumers are: an event published in the callout's own account would be
#                   visible to nobody.
#   app-admin       stands in for the deployment itself. It is what creates the stream — the
#                   callout deliberately cannot, because creating streams is far more authority
#                   than publishing an event needs. DEV ONLY: it is unrestricted.
#
# The grant covers the whole `<instance>.events.>` subtree rather than one subject, so changing
# the last token of CALLOUT_EVENTS_SUBJECT in .env does not mean regenerating the identity. A
# real deployment grants the exact subject; see docs/events.md.
"${NSC[@]}" add user --account "$ACCT_APP" --name callout-events \
  --allow-pub "${EVENTS_INSTANCE}.events.>" \
  --allow-pub "\$JS.API.STREAM.INFO.${EVENTS_STREAM}" \
  --allow-sub "_INBOX.>" >/dev/null
"${NSC[@]}" add user --account "$ACCT_APP" --name app-admin >/dev/null

"${NSC[@]}" generate creds --account "$ACCT_APP" --name callout-events > "$OUT_DIR/callout-events.creds"
"${NSC[@]}" generate creds --account "$ACCT_APP" --name app-admin     > "$OUT_DIR/app-admin.creds"

echo "==> The callout's XKey (curve25519)"
# It encrypts the callout requests end to end: without this, the client's access token travels
# in the clear over the $SYS.REQ.USER.AUTH subject.
# `nsc generate nkey --curve` prints the seed (SX...) and then the public key (X...).
XKEY_OUT="$("${NSC[@]}" generate nkey --curve)"
XKEY_SEED="$(echo "$XKEY_OUT" | grep '^SX' | head -1)"
XKEY_PUB="$(echo "$XKEY_OUT" | grep '^X' | head -1)"
[[ -n "$XKEY_SEED" && -n "$XKEY_PUB" ]] || { echo "ERROR: could not extract the XKey" >&2; exit 1; }
printf '%s\n' "$XKEY_SEED" > "$OUT_DIR/callout-xkey.seed"
printf '%s\n' "$XKEY_PUB"  > "$OUT_DIR/callout-xkey.pub"
echo "   XKey pub: $XKEY_PUB"

APP_PUB="$(acct_pub "$ACCT_APP")"
AUTH_PUB="$(acct_pub "$ACCT_AUTH")"
HANDLER_PUB="$(user_pub "$ACCT_AUTH" sentinel-handler)"

echo "==> authcallout on $ACCT_AUTH (mints toward $ACCT_APP)"
# The flags take PUBKEYS, not names. And it is --curve, not --xkey.
#   --auth-user       the sentinel-handler: the connection that BYPASSES the callout
#   --allowed-account the APP account: where the callout may mint into
"${NSC[@]}" edit authcallout \
  --account "$ACCT_AUTH" \
  --auth-user "$HANDLER_PUB" \
  --allowed-account "$APP_PUB" \
  --curve "$XKEY_PUB" >/dev/null

echo "==> Extracting keys for the binary"
# Two DIFFERENT signing keys, with different roles:
#   APP  signs the User JWT               -> defines which account the user lands in
#   AUTH signs the authorization_response -> is the issuer the server has configured
acct_sk_seed "$ACCT_APP"  > "$OUT_DIR/app-account.sk.seed"
acct_sk_seed "$ACCT_AUTH" > "$OUT_DIR/auth-account.sk.seed"
printf '%s\n' "$APP_PUB"  > "$OUT_DIR/app-account.pub"
printf '%s\n' "$AUTH_PUB" > "$OUT_DIR/auth-account.pub"

echo "==> Self-contained MEMORY resolver ($RESOLVER_CONF)"
# --mem-resolver preloads every account JWT into the file, so the server starts on its own,
# with no need for `nsc push` against a server that does not exist yet.
"${NSC[@]}" generate config --mem-resolver --sys-account SYS > "$RESOLVER_CONF"

echo "==> Contract for the binary ($OUT_DIR/callout-env.sh)"
# The startup script sources this file. That way the seeds are never written by hand into the
# .env and regenerating the identity does not force editing any configuration.
cat > "$OUT_DIR/callout-env.sh" <<'EOF'
# callout-env.sh — GENERATED by bootstrap.sh. DO NOT COMMIT (out/ is gitignored).
# Paths are relative to nats/. The variables point at FILES; the binary accepts either the
# path or the literal seed.
export CALLOUT_HANDLER_CREDS="${CALLOUT_NATS_DIR:-.}/out/sentinel-handler.creds"
export CALLOUT_APP_ACCOUNT_SK_SEED="${CALLOUT_NATS_DIR:-.}/out/app-account.sk.seed"
export CALLOUT_APP_ACCOUNT_PUB="${CALLOUT_NATS_DIR:-.}/out/app-account.pub"
export CALLOUT_AUTH_ACCOUNT_SK_SEED="${CALLOUT_NATS_DIR:-.}/out/auth-account.sk.seed"
export CALLOUT_XKEY_SEED="${CALLOUT_NATS_DIR:-.}/out/callout-xkey.seed"

# The authentication event publisher's credential. It is NOT exported here on purpose: setting
# it while CALLOUT_EVENTS_SUBJECT is unset is a startup error, because a credential nothing
# reads is worth reporting rather than ignoring. scripts/run.sh exports it when the .env turns
# the publisher on.
#   ${CALLOUT_NATS_DIR:-.}/out/callout-events.creds   the publisher (pub-only, APP account)
#   ${CALLOUT_NATS_DIR:-.}/out/app-admin.creds        dev-only APP admin; creates the stream
EOF

cat <<EOF

==> Done.

  APP account  ($ACCT_APP):  $APP_PUB
  AUTH account ($ACCT_AUTH): $AUTH_PUB

  Clients connect with out/sentinel-client.creds + their Zitadel access token.
  The callout connects with out/sentinel-handler.creds (it bypasses the callout).
  Authentication events (optional): out/callout-events.creds publishes them, and
  out/app-admin.creds is the dev credential that creates their stream. Turn them on by
  uncommenting CALLOUT_EVENTS_SUBJECT in nats/.env.

  Next: make run
EOF
