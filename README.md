# nats-zitadel-auth-callout

Authenticate NATS connections against your OIDC identity provider, and give each one the
permissions its **role** entitles it to.

```
   ┌────────┐  1. connect + access token   ┌─────────────┐
   │ client │ ───────────────────────────▶ │ NATS server │
   └────────┘                              └──┬───────▲──┘
                     2. who is this? ─────────┘       │
                                        ┌─────────────┴──┐   3. verify the token
                                        │  auth callout  │ ─────────────────────▶  OIDC provider
                                        └────────────────┘
                                         4. role → permissions → signed User JWT
```

It steps in **once, during the handshake**. After that the NATS server enforces the permissions
on every publish and subscribe — the callout is not in the data path and adds nothing per
message.

Because it is the only component that knows an authentication happened, it can also **announce
one**: an optional event per authenticated connection, carrying the identity it just verified.
Off unless you configure it — see [events](docs/events.md).

## Why

Without it, NATS permissions live in server configuration or in account JWTs: to change what
someone can do you edit infrastructure and reload. Identity and authorization drift apart, and
"who can publish to this subject?" has no answer you can look up.

With it:

- **your identity provider is the source of truth.** Grant a role there, and the next connection
  gets those permissions.
- **permissions are two files** — a role-to-template mapping and the templates themselves —
  readable without running anything.
- **the session ends with the token.** A minted User JWT expires when the access token does.
- **nothing changes in your NATS deployment's shape.** It works against an existing server, in
  either authorization mode.

## What it does not decide for you

The service has no opinion about what your subjects look like. You write the permission
templates; it substitutes the authenticated identity into them and lets the server enforce the
result. Whether your subjects are tenant-first, service-first or something else is yours to
choose — see [concepts](docs/concepts.md).

## Requirements

- A **NATS server 2.10+**, in either `operator` mode (account JWTs, `nsc`) or `config` mode
  (`authorization {}` in `nats-server.conf`). No migration needed either way.
- An **OIDC provider**. Zitadel has first-class support; any standards-compliant provider works
  through the generic `oidc` mode.

## Try it

```sh
git clone https://github.com/gravadigital/nats-zitadel-auth-callout
cd nats-zitadel-auth-callout
make bootstrap && make run
```

That brings up a local NATS with a throwaway identity and the callout in front of it, using a
fake in-process identity provider so there are no secrets to set up. Then, in another terminal:

```sh
UID=alice
IHASH=$(go run ./cmd/session "$UID" dev | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')
NATS="nats --server nats://127.0.0.1:4322 --creds nats/out/sentinel-client.creds"

# A role that may publish here:
$NATS --token "mock:$UID:alice:app-user" --inbox-prefix "_INBOX.$IHASH" \
  pub "dev.$UID.demo.ping" hello

# The same client, under somebody else's id — refused by the server:
$NATS --token "mock:$UID:alice:app-user" --inbox-prefix "_INBOX.$IHASH" \
  pub "dev.someone-else.demo.ping" nope
```

Requires Go 1.26+, `nsc` and `nats-server` on the PATH. The subjects above come from
[examples/](examples/) and are only an example — you define your own.

## Documentation

**Start here**

- [Concepts](docs/concepts.md) — how a token becomes a set of permissions, and what the service
  does and does not impose. Read this before deciding whether it fits.

**Setting it up**

- [Installing](docs/install.md) — adding the callout to a NATS server, in either mode.
- [Configuration](docs/configuration.md) — every setting, in the file and in the environment.
- [Permissions](docs/permissions.md) — writing rules and templates, including KV.

**Using it**

- [Connecting a client](docs/client.md) — credentials, token, inbox prefix.
- [Authentication events](docs/events.md) — telling the bus who signed in, and what that costs.
- [Zitadel](docs/zitadel.md) — roles, service users, and checking a token.
- [Troubleshooting](docs/troubleshooting.md) — organised by symptom.

**Reference**

- [Examples](examples/) — a worked configuration for both server modes.
- [Changelog](CHANGELOG.md) · [Security policy](SECURITY.md) ·
  [Open issues](https://github.com/gravadigital/nats-zitadel-auth-callout/issues)

## Status

Stable. The mechanism is covered by tests that stand up real `nats-server` instances in both
authorization modes — every rule that decides whether a connection is accepted lives in the
server, so that is where it is verified.

Since 1.0 the configuration surface is a contract: the `rules.yaml` and template schema, the
built-in placeholders and subject grammar, the authentication event payload, the `CALLOUT_*`
variables and the CLI. Breaking any of them takes a major version, and a removal is preceded by
a deprecation that keeps working and warns. See the [changelog](CHANGELOG.md).

Known gaps: no metrics or health endpoint; a revoked token stays valid until it expires, since
verification is local with no introspection per connection.

## Installing

```sh
docker pull gravadigital/nats-zitadel-auth-callout:1.0.0
```

Tags are `MAJOR.MINOR.PATCH`, plus a rolling `MAJOR.MINOR`, plus `latest` on the newest stable
release. Prereleases publish only their own tag. See [installing](docs/install.md) for what to
mount and how to wire it up.

## License

**Apache-2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE). It may be used, modified and
redistributed, including commercially and inside proprietary software, keeping the copyright
notice and stating changes made in modified files. Apache-2.0 rather than MIT for the express
patent grant, and because it is the licence of the ecosystem this integrates with.

Distributed **as is, without warranties of any kind**. A misconfiguration of this service is an
authorization problem across your whole bus: [`auth-callout verify`](docs/install.md#verifying)
exists to catch the ones that fail silently, and it is worth running before serving traffic.
