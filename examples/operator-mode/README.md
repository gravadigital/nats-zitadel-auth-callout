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

Then the callout is declared on the AUTH account:

```sh
nsc edit authcallout --account AUTH \
  --auth-user       <handler user PUBKEY> \
  --allowed-account <APP account PUBKEY> \
  --curve           <XKey PUBKEY>
```

The flags take **pubkeys, not names**, and it is `--curve`, not `--xkey`.

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

Extract both seeds from your `nsc` store — they live under
`<store>/keys/<initial>/<2 chars>/<KEY>.nk` — and give them to the callout as
`CALLOUT_APP_ACCOUNT_SK_SEED` and `CALLOUT_AUTH_ACCOUNT_SK_SEED`. See `env.example`.

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
