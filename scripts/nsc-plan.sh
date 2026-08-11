#!/usr/bin/env bash
#
# nsc-plan.sh — print the nsc commands that provision the callout on an existing operator-mode
# NATS. It PRINTS them; it never runs anything.
#
# WHY IT ONLY PRINTS
#   Provisioning needs the operator key, and whoever deploys the callout usually does not have
#   it: it belongs to whoever owns the NATS. So this is a handoff — the output is meant to be
#   read, checked, and pasted into a ticket for the person who does. Nobody should run a script
#   they were handed against their production operator, and this one does not ask them to.
#
# Usage:
#   ./scripts/nsc-plan.sh [--app APP] [--auth AUTH] [--handler NAME] [--client NAME]
#
#   --app       account clients land in.        Default: APP
#   --auth      account the callout lives in.   Default: AUTH
#   --handler   the callout's own user.         Default: callout-handler
#   --client    the user clients connect with.  Default: callout-client
#
# For a NATS you are building from scratch, use nats/bootstrap.sh instead — it does all of this
# and brings up a working server.

set -euo pipefail

APP="APP"
AUTH="AUTH"
HANDLER="callout-handler"
CLIENT="callout-client"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app)     APP="${2:?}"; shift 2 ;;
    --auth)    AUTH="${2:?}"; shift 2 ;;
    --handler) HANDLER="${2:?}"; shift 2 ;;
    --client)  CLIENT="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "ERROR: unknown argument: $1 (try --help)" >&2; exit 1 ;;
  esac
done

cat <<EOF
# ============================================================================================
# Provisioning nats-zitadel-auth-callout on an existing operator-mode NATS
#
# Run these where the nsc store and the operator key are. Read them first: they modify the
# accounts of a running deployment.
#
#   target account (clients land here)  $APP
#   callout account                     $AUTH
#   callout's own user                  $HANDLER
#   user clients connect with           $CLIENT
#
# Nothing here touches accounts other than these, and existing users keep authenticating exactly
# as they do today until they are moved.
# ============================================================================================

# --- 1. The accounts ------------------------------------------------------------------------
# Skip whichever already exists. $APP is where authenticated clients land; $AUTH exists so the
# credential traffic on \$SYS.REQ.USER.AUTH is not visible to application connections.

nsc add account --name $APP
nsc add account --name $AUTH

# Both accounts sign with a SIGNING KEY, never the account key itself: the account key stays
# stored away, and a leaked signing key can be rotated without reissuing the account.

nsc edit account --name $APP  --sk generate
nsc edit account --name $AUTH --sk generate

# JetStream on the target account, if your templates use \`kv:\`. Once accounts exist it is
# opt-in per account, and a missing one makes KV fail as a client TIMEOUT rather than as a
# permissions error — the least obvious failure in this system. Adjust the limits.

nsc edit account --name $APP --js-mem-storage 1G --js-disk-storage 10G --js-streams -1 --js-consumer -1

# --- 2. The two sentinels -------------------------------------------------------------------
# This is the part that costs the most when it is wrong.
#
# A user listed in --auth-user is authorized by the server DIRECTLY: the callout never runs for
# it. That is required for the callout itself (it cannot authorize its own connection), and it
# is an authorization BYPASS for anyone else. Hence two users:
#
#   $HANDLER   goes in --auth-user. The callout connects with it.
#   $CLIENT    does NOT. Connecting with it triggers the callout. Denied everything of its own,
#              so every permission a connection ends up with comes from the User JWT the
#              callout mints. Safe to distribute.

nsc add user --account $AUTH --name $HANDLER
nsc add user --account $AUTH --name $CLIENT --deny-pub ">" --deny-sub ">"

# --- 3. The encryption key ------------------------------------------------------------------
# Without it the clients' access tokens travel in the clear over \$SYS.REQ.USER.AUTH, where
# anything else in that account can read them.
#
# This prints a seed (SX...) and a public key (X...). SAVE THE SEED SOMEWHERE SAFE: nsc does not
# keep curve keys in its store, so it cannot be recovered later. The public key goes in --curve
# below; the seed becomes CALLOUT_XKEY_SEED.

nsc generate nkey --curve

# --- 4. Wire the callout --------------------------------------------------------------------
# The flags take PUBLIC KEYS, not names. Collect them first:

nsc describe account $APP  --field sub                      # -> APP_PUB
nsc describe user --account $AUTH --name $HANDLER --field sub  # -> HANDLER_PUB

# Then, substituting the values (and the X... from step 3):

nsc edit authcallout \\
  --account $AUTH \\
  --auth-user       '<HANDLER_PUB>' \\
  --allowed-account '<APP_PUB>' \\
  --curve           '<XKEY_PUB>'

# --allowed-account is what lets you adopt INCREMENTALLY: accounts left out of it keep
# authenticating exactly as they do now.

# --- 5. Publish -----------------------------------------------------------------------------
# With a NATS-resolver deployment, push the changed accounts to the server. With a memory
# resolver, regenerate the server configuration and restart instead.

nsc push --account $APP
nsc push --account $AUTH

# --- 6. Hand back ---------------------------------------------------------------------------
# Whoever runs the callout needs, from this store:
#
#   - the creds for $HANDLER
#   - the signing key seeds of $APP and $AUTH
#   - the public key of $APP
#   - the XKey seed from step 3
#
# scripts/nsc-extract.sh collects all of that and writes it into a ready-to-use env file:
#
#   ./scripts/nsc-extract.sh --store <this store> --out ./secrets
#
# They should also get the creds for $CLIENT, which is what their clients connect with.

nsc generate creds --account $AUTH --name $CLIENT > $CLIENT.creds

# --- 7. Verify ------------------------------------------------------------------------------
# Before serving traffic, on the machine that will run the callout:
#
#   auth-callout verify --client-creds $CLIENT.creds
#
# It checks the handler can serve the callout subject and — the important one — that $CLIENT
# does NOT bypass the callout. Run it while the service is stopped: once it is answering, a
# bypassing client and an authorized one are indistinguishable.
EOF
