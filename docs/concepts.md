# Concepts

How a token becomes a set of NATS permissions, and — just as important — which decisions the
service makes for you and which it leaves to you.

## The exchange

1. A client connects with a **sentinel credential** and passes its **access token**. The sentinel
   is the same for every client and grants nothing on its own; the token is the identity.
2. The NATS server does not authorize that credential itself. It publishes an authorization
   request on `$SYS.REQ.USER.AUTH`.
3. The callout verifies the token against the provider's JWKS — locally, no introspection call
   per connection — and reads its **roles**.
4. It matches the roles against `rules.yaml`, expands the matching **template** with the
   authenticated identity, and signs a **User JWT** carrying exactly those permissions.
5. The server accepts the connection with them, and enforces them from there on.

Nothing repeats while the connection lives. The cost is a slower handshake, not a hop per
message. The minted JWT expires when the access token does, so a NATS session never outlives the
token that authorized it.

## Roles decide, and only roles

There is no heuristic inspecting a token to guess what kind of client it is. `rules.yaml` maps a
role to a template, first match wins in file order:

```yaml
rules:
  - match: app-admin
    type: person
    template: templates/admin.yaml

  - match: app-backend
    type: service
    service: orders          # the endpoint name this identity serves
    template: templates/orders.yaml
```

With no match the connection is **refused**. There are no default permissions.

`type` decides how the identity is assembled, not how trustworthy it is:

| `type` | What it means |
|---|---|
| `person` | the identity is the token's subject |
| `service` | the same, plus an **endpoint name** declared in the rule |

A machine user holding a role whose rule says `type: person` gets a person identity — which is
deliberate, and is what lets you exercise every path without a browser login.

The endpoint name being separate from the user id is what lets several replicas of a service
serve the same endpoint (queue-group balancing) while each connects as itself.

## What the service gives you, and what you decide

**You write the subjects.** The service does not require any particular subject shape. It
substitutes values into the templates you write and checks the result is a legal NATS subject.

The values available:

| Placeholder | What it is |
|---|---|
| `{{user_id}}` | the token's `sub`, verbatim |
| `{{user_id_hash}}` | a stable, subject-safe hash of it — for inbox prefixes |
| `{{service}}` | the endpoint name, for `type: service` rules |
| `{{instance}}` | a deployment label, if you configure one. Optional |

Plus anything you declare from token claims:

```yaml
placeholders:
  tenant: tenant_id
  region: metadata.region
```

So a tenant-first grammar with no instance token is just as expressible as anything else:

```yaml
pub:
  allow: ["{{tenant}}.orders.{{user_id}}.create"]
```

Built-in names cannot be redefined, and claim values are validated as single subject tokens
before expansion: a claim containing `*`, `>` or `.` would widen the permission past what the
template says, which is the scoping bypass this design exists to prevent.

The [examples](../examples/) use `<instance>.<user-id>.<service>.<method>`. That is one workable
convention, not a requirement.

## Announcing an authentication

The callout is the only component that knows an authentication happened: the NATS server sees a
connection, the identity provider sees a token request. So it can optionally publish one event per
authenticated connection — who connected, with which roles, when, and until when — on a subject
you choose.

It does not change the shape of anything above. The event goes out *after* the server already has
its answer, from another goroutine, on a second connection into the account your consumers live
in; nothing about it can delay or refuse a connection. Consuming it is an ordinary subject
permission, granted per role by the same templates as everything else.

It is off unless configured. See [events](events.md).

## Why the caller's id belongs in the subject

A pattern worth understanding even if you choose differently: when the caller's user id is part
of the subject and the *permission* is what fixes it, a client can only publish under its own id.
The receiver reads who is calling off the subject and can trust it — vouched for by the callout,
not asserted by the message body.

The trade-off is that the user id is visible in subjects, logs and traces. If that matters to
you, use an opaque claim instead.

## Replies and inboxes

A NATS request needs somewhere for the reply to arrive, and that subscription needs a permission
like any other. Two modes:

**`hashed`** (default) scopes each identity's replies to `_INBOX.<hash(user-id)>`. Replies are
isolated per user, and **every client must set that prefix when connecting** — the client
derives it from its own token, no side channel. Without it the library picks a random inbox that
no permission covers, and replies silently never arrive.

**`passthrough`** leaves the inbox alone, so existing clients need no change. The template then
has to grant the inbox they actually use (typically `_INBOX.>`), which means any client in the
account can subscribe to another's replies.

`hashed` is the default because it is the safer one; `passthrough` exists because "change every
client" is not always available. See [connecting a client](client.md).

## KV

To NATS a KV permission is ordinary pub/sub over JetStream's internal subjects. The `kv:` block
exists so a template does not have to know them:

```yaml
kv:
  - bucket: user-settings
    access: read-write        # none | read | read-write — access to the DATA
    manage: false             # the bucket's LIFECYCLE — a separate axis
    keys: "{{user_id}}.>"     # WHICH keys, as a subject pattern
    watch: false
```

Three things the model handles that are worth knowing:

- **`access` and `manage` are independent.** A service can own a bucket — create and migrate
  it — while only *reading* the data, because writing a user's setting belongs to that user.
- **Every bucket needs exactly one `manage: true`.** With none, nobody can create it and
  operations fail with `stream not found`, which does not say why.
- **Some operations cannot be scoped by key.** Get-by-revision does not carry the key in the
  subject, so it is only granted when access already covers the whole bucket; a watcher sees the
  whole bucket, which is why `watch` is separate.

Details in [permissions](permissions.md).

## The two credentials that are easy to confuse

The callout needs its **own** connection to NATS, and that connection cannot be authorized by
the callout — it is not running yet. So the server is told to authorize one user directly:

| | Declared in `auth_users` / `--auth-user` | Used by |
|---|---|---|
| **handler** | yes → bypasses the callout | the callout itself |
| **client sentinel** | no → triggers the callout | your clients |

Anything listed there **skips the callout entirely** and keeps whatever permissions that user
carries. Only the handler belongs in it — a client placed there connects successfully and is
simply never authenticated, with nothing anywhere reporting it.

That failure is the reason [`auth-callout verify`](install.md#verifying) exists.

## Server modes

The service works against both NATS authorization models, and the difference reaches only one
thing: how the minted User JWT names the account the connection lands in.

| | `operator` | `config` |
|---|---|---|
| Authorization lives in | account JWTs (`nsc`) | `nats-server.conf` |
| Account named by | public key (`IssuerAccount`) | name (`Audience`) |
| Signing keys needed | two | one |
| Handler connects with | `.creds` | user/password or nkey |

Everything else — the protocol, encryption, verification, routing, templates — is identical.
`config` mode is usually the one for adopting an existing NATS, since it needs no operator, no
`nsc` store and no reissued credentials. See [installing](install.md).
