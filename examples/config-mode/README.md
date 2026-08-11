# Config mode

For a NATS whose users and permissions live in `nats-server.conf`. This is the common case for
a server an infra team brought up without needing multi-tenancy, and adopting the callout does
**not** require migrating it to operator mode.

## What you need

Two keys, generated once. Neither is derived from anything else, so keep the seeds:

```sh
nats auth nkey gen account --output callout-issuer.nk   # A... pubkey + S... seed
nats auth nkey gen curve   --output callout-xkey.nk     # X... pubkey + SX... seed
```

| Half | Goes in |
|---|---|
| issuer **pubkey** (`A…`) | `auth_callout.issuer` in `nats-server.conf` |
| issuer **seed** (`S…`) | `CALLOUT_APP_ACCOUNT_SK_SEED` |
| xkey **pubkey** (`X…`) | `auth_callout.xkey` in `nats-server.conf` |
| xkey **seed** (`SX…`) | `CALLOUT_XKEY_SEED` |

The pubkeys go in the server file, the seeds go to the callout. **A mismatch between the two
shows up as an authorization failure, not as a startup error**, so change them together.

## Setting it up

1. **Merge `nats-server.conf` into yours.** The parts that matter are the `accounts{}` block and
   the `authorization.auth_callout{}` block. Replace the two example keys with the pubkeys you
   just generated, and change both `CHANGE-ME-*` passwords.

2. **Copy `env.example`** and fill in the seeds and your identity provider. Point
   `CALLOUT_RULES_PATH` at the shared `rules.yaml` one directory up.

3. **Restart the server.** `auth_callout` is not reloadable — every field in it needs a restart,
   not a `nats-server --signal reload`.

4. **Check the wiring before serving traffic**, with the same configuration the service will
   use:

   ```sh
   auth-callout verify --client-user callout-client --client-password '...'
   ```

   It exits non-zero on any failure, so it works as a deployment gate. Pass the client
   credentials: without them it skips the bypass check, which is the highest-impact one here.

5. **Start the callout** and check its first log line says `serverMode=config` and the IdP mode
   you expect. If it says `idp=mock`, it did not pick up your configuration, and mock mode
   accepts any identity a client claims.

## Adopting incrementally

`allowed_accounts` restricts which accounts get delegated to the callout. With it absent, every
account is. Setting it means **accounts left out keep authenticating exactly as they do today**,
which is what lets you move one account at a time:

```
auth_callout {
  ...
  allowed_accounts: [ APP ]
}
```

## Three things that go wrong

**A client user listed in `auth_users`.** Anything there BYPASSES the callout entirely and keeps
its own permissions. This fails *open* and silently — the connection succeeds with the wrong
permissions — so it is the one to check first when a client seems to have too much access. Only
the callout's own user belongs in that list.

**Leaving the callout in the global account.** `account` defaults to `$G` when omitted, and then
any other `$G` connection can observe the credential traffic on `$SYS.REQ.USER.AUTH`. Give the
callout its own account.

**Forgetting `jetstream: enabled` on the target account.** Once an `accounts{}` block exists,
JetStream is per-account and off by default. A KV permission then fails as a client **timeout**,
not as a permissions violation — the least obvious failure in this whole system.
