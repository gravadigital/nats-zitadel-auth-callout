# Operator mode

For a NATS whose authorization comes from operator-signed account JWTs — an `nsc` store and a
resolver. The callout is configured **inside the AUTH account's JWT**, not in
`nats-server.conf`, which is why the server file here is short.

## Trying it locally

The repository root has a bootstrap that generates a complete throwaway identity — operator,
accounts, sentinels, XKey and the callout configuration — into `nats/out/`:

```sh
make bootstrap    # generates it (idempotent; delete nats/out to regenerate)
make run          # NATS + the callout, in the foreground
```

That is the fastest way to see the example working. The rest of this file is for pointing the
callout at an **existing** operator-mode NATS.

## What has to exist on your NATS

Two accounts and two users:

| | Purpose |
|---|---|
| **APP account** | where authenticated clients land. Needs a signing key, and JetStream if you use KV |
| **AUTH account** | where the callout lives and `$SYS.REQ.USER.AUTH` is served. Needs a signing key |
| **handler user** (in AUTH) | the callout's own connection. Goes in `--auth-user` |
| **client user** (in AUTH) | what clients connect with. **Not** in `--auth-user`, denied everything of its own |
| **events user** (in APP) | OPTIONAL, for [authentication events](../../docs/events.md): the callout's second connection, publishing into the account the consumers live in |

Then the callout is declared on the AUTH account:

```sh
nsc edit authcallout --account AUTH \
  --auth-user       <handler user PUBKEY> \
  --allowed-account <APP account PUBKEY> \
  --curve           <XKey PUBKEY>
```

The flags take **pubkeys, not names**, and it is `--curve`, not `--xkey`.

If you turn the authentication events on, the publisher's user goes in the **APP** account — not
AUTH, because that is where the consumers are — with three permissions and no more:

```sh
nsc add user --account APP --name callout-events \
  --allow-pub 'prod.events.auth' \
  --allow-pub '$JS.API.STREAM.INFO.AUTH_EVENTS' \
  --allow-sub '_INBOX.>'
```

It deliberately cannot create streams; you create the stream. See
[events](../../docs/events.md).

## The two sentinels

This is the detail that costs the most if you get it wrong. In operator mode, **if a client
connects with the same user declared in `--auth-user`, NATS authorizes it directly and the
callout never fires** — the client keeps that user's full permissions. That fails *open* and
silently, which is why two users are needed rather than one:

- the **handler** goes in `--auth-user`, because the callout cannot authorize itself;
- the **client** stays out of it, so connecting with it triggers the callout. Deny it
  everything: every permission a connection ends up with should come from the minted User JWT.

The client credential is safe to distribute — on its own it authorizes nothing.

## The two signing keys

Also different, and also easy to confuse:

| Key | Signs | Why |
|---|---|---|
| APP account signing key | the **User JWT** | decides which account the user lands in (`IssuerAccount`) |
| AUTH account signing key | the **authorization_response** | it is the callout issuer the server has configured |

Getting these two backwards produces an `Authorization Violation` with nothing in any log
pointing at the cause, so rather than picking the seeds out of the store by hand:

```sh
./scripts/nsc-extract.sh --store ~/.local/share/nats/nsc/stores/myoperator --out ./secrets
```

It reads the callout configuration out of the account JWT and works the topology out from
there — the account carrying `auth_users` is the AUTH account, its `allowed_accounts` is the
account clients land in, its `auth_users` is the handler — so nothing has to be named on the
command line and nothing can be named wrongly. It writes the seeds, the handler creds and a
`callout.env` with each value already under the right variable.

Run it where the `nsc` store is, which is normally an operator's workstation rather than the
machine that will run the callout: the service never touches `nsc`, it only reads seeds and
public keys from its environment.

One thing it cannot always find is the XKey seed: `nsc` does not keep curve keys in its store,
so if it was not saved next to it, the generated file says where to point
`CALLOUT_XKEY_SEED` instead of guessing.

## Checking it worked

Before serving traffic, run the pre-flight check with the same configuration the service uses:

```sh
auth-callout verify --client-creds /path/to/client.creds
```

It confirms the handler can connect and serve `$SYS.REQ.USER.AUTH`, that requests are
encrypted, and — the important one — that the **client credential does not bypass the callout**.
Pass `--client-creds`: without it that check is skipped. It exits non-zero on failure, so it
works as a deployment gate.

Then start the callout: its first log line should say `serverMode=operator` and the IdP mode you
expect. A connection refused with `Authorization Violation` before the callout logs anything
means the request never reached it — check that the client is connecting with the client user
and not the handler.

---

If something does not work, see [troubleshooting](../../docs/troubleshooting.md).
