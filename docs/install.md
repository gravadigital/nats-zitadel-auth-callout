# Installing

Adding the callout to a NATS server. It works against an existing deployment in either
authorization mode, and does not require migrating anything.

Read [concepts](concepts.md) first if you have not — in particular the part about the two
credentials, which is where most of the cost of getting this wrong lives.

## Which mode are you in?

```sh
grep -E 'operator|resolver' nats-server.conf
```

An `operator` or `resolver` line means **operator mode**: authorization comes from
operator-signed account JWTs, managed with `nsc`. Otherwise you are in **config mode**, with
users and permissions written in the configuration file.

Config mode is the shorter path on an existing server: no operator, no `nsc` store, no reissued
credentials. Pick it if you have the choice.

Either way, `allowed_accounts` lets you adopt **incrementally** — accounts left out of it keep
authenticating exactly as they do today.

## What has to exist

Whichever mode, the same four things:

1. an account for your clients to land in;
2. an account for the callout, so its credential traffic is not visible to application
   connections;
3. two users in it — the **handler** the callout connects as, and the **sentinel** your clients
   connect with;
4. the callout declared, naming the handler, the target account and an encryption key.

The worked configurations are in [examples/operator-mode/](../examples/operator-mode/) and
[examples/config-mode/](../examples/config-mode/), each with a server configuration, a
`callout.yaml` and a README.

## Config mode

Copy [examples/config-mode/nats-server.conf](../examples/config-mode/nats-server.conf) — it is
commented with the mistakes that cost the most, and a test keeps it valid.

Generate the two keys, saving both seeds:

```sh
nats auth nkey gen account --output callout-issuer.nk   # signs the User JWT
nats auth nkey gen curve   --output callout-xkey.nk     # encrypts callout requests
```

Then in `nats-server.conf`:

```
accounts {
  AUTH: {
    users: [
      { user: callout-handler, password: "..." }
      { user: callout-client,  password: "...", permissions: {
          publish: { deny: ">" }, subscribe: { deny: ">" } } }
    ]
  }
  APP: { jetstream: enabled }
}

authorization {
  timeout: 5
  auth_callout {
    issuer:     "A..."            # the account key's PUBLIC half
    account:    AUTH
    auth_users: [ callout-handler ]
    xkey:       "X..."            # the curve key's PUBLIC half
  }
}
```

Three things that do not fail loudly:

- **Only the handler goes in `auth_users`.** Anything there bypasses the callout and keeps its
  own permissions.
- **Do not leave the callout in `$G`** — the default when `account` is omitted. Any other `$G`
  connection could observe the credential traffic.
- **`jetstream: enabled` on the target account** if your templates use `kv:`. Once an
  `accounts {}` block exists it is per-account and off by default, and a missing one surfaces as
  a client *timeout*, not a permissions error.

`auth_callout` is not reloadable: every field needs a server restart.

## Operator mode

Provision the accounts, the two users and the callout configuration. `scripts/nsc-plan.sh` prints
the exact `nsc` commands, commented, without running anything — provisioning needs the operator
key, which whoever deploys the callout usually does not have, so the output is meant to be handed
to whoever does:

```sh
./scripts/nsc-plan.sh --app APP --auth AUTH
```

Once that is applied, extract what the service needs:

```sh
./scripts/nsc-extract.sh --store ~/.local/share/nats/nsc/stores/myoperator --out ./secrets
```

It reads the callout configuration out of the account JWT and works the topology out from there,
so nothing has to be named on the command line and nothing can be named wrongly. It writes the
seeds, the handler credentials and a ready-to-use environment file.

Run it where the `nsc` store is — normally an operator's workstation, not the machine that will
run the callout. The service never touches `nsc`.

## Running it

The image carries no configuration and no secrets:

```sh
docker run --rm \
  -v /etc/auth-callout:/etc/auth-callout:ro \
  -v /run/secrets:/etc/nats-creds:ro \
  -e CALLOUT_CONFIG_FILE=/etc/auth-callout/callout.yaml \
  -e CALLOUT_APP_ACCOUNT_SK_SEED=/etc/nats-creds/app.seed \
  -e CALLOUT_HANDLER_CREDS=/etc/nats-creds/handler.creds \
  -e CALLOUT_XKEY_SEED=/etc/nats-creds/xkey.seed \
  gravadigital/nats-zitadel-auth-callout:0.1.0
```

Everything except the secrets can live in the configuration file; see
[configuration](configuration.md). Seeds accept either the value itself or a path to a file
holding it, so Kubernetes secret references and Docker secret mounts both work unchanged.

Check the first log line. It names the version, the server mode and the identity provider — and
if it says `idp=mock`, the configuration was not picked up, because mock accepts any identity a
client claims.

## Verifying

Before serving traffic, with the same configuration the service will use:

```sh
auth-callout verify --client-creds /path/to/client.creds     # operator mode
auth-callout verify --client-user NAME --client-password ... # config mode
```

It exits non-zero on any failure, so it works as a deployment gate. It checks that the rules and
templates load, that the handler can connect and actually serve `$SYS.REQ.USER.AUTH`, whether
requests are encrypted, and — given a client credential — **that clients do not bypass the
callout**.

That last check is the reason the command exists. It works by confirming the server *refuses* the
client credential while the callout is not answering: a deployment where that connection succeeds
is one where the callout never runs. **Run it while the service is stopped** — once it is
answering, a bypassing client and an authorized one are indistinguishable.

## Next

- [Permissions](permissions.md) — write the rules and templates for your deployment.
- [Connecting a client](client.md) — what clients have to do differently.
- [Troubleshooting](troubleshooting.md) — when something does not work.
