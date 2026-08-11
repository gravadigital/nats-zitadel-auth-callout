# Permissions

Two files decide what a connection can do. Both are read at startup and neither needs a
recompile:

```
rules.yaml        role  →  (identity type, template)     first match wins
templates/*.yaml  template  →  pub/sub subjects + KV access
```

`CALLOUT_RULES_PATH` points at the first; templates resolve relative to its directory.

## Rules

```yaml
version: 1

rules:
  - match: app-admin              # the role name, exactly as it travels in the token
    type: person
    template: templates/admin.yaml

  - match: app-backend
    type: service
    service: orders               # the endpoint this identity serves
    template: templates/orders.yaml

  - match: "*"                    # optional catch-all, must be last
    type: person
    template: templates/base.yaml
```

Rules are walked **in order**, and the first whose `match` is one of the token's roles wins. With
no match the connection is refused — there are no default permissions.

Order matters when a token carries several roles: put the most restrictive first. A repeated
`match`, or a catch-all that is not last, makes later rules unreachable and **fails at startup**
rather than silently never firing.

`type` decides how the identity is assembled: `person` uses the token's subject, `service` adds
the endpoint name from the rule. See [concepts](concepts.md).

## Templates

```yaml
pub:
  allow: ["orders.{{user_id}}.create"]
  deny:  []
sub:
  allow: ["_INBOX.{{user_id_hash}}.>"]
kv:
  - bucket: user-settings
    access: read-write
    keys: "{{user_id}}.>"
response:
  max: 1
  ttl: 45s
```

NATS evaluates `deny` over `allow`, so a deny is for trimming a broad allow rather than as the
main mechanism.

`response` is `allow_responses`: it lets a service reply to whoever called it without an explicit
publish permission toward that client's inbox. A service template without it cannot answer
anyone.

**Prefer allow-lists.** Enumerating methods is more work than denying a few, and that is the
point: with a deny-list a new method is reachable until somebody remembers to restrict it, and
with an allow-list nobody reaches it until it is enabled. It fails closed.

A template that grants nothing at all is a startup error — a client using it would authenticate
successfully and then be denied everything, which reads as a broken service rather than a
misconfigured template.

## Placeholders

| Placeholder | Expands to |
|---|---|
| `{{user_id}}` | the token's `sub`, verbatim |
| `{{user_id_hash}}` | a stable, subject-safe hash of it |
| `{{service}}` | the endpoint name, `type: service` rules only |
| `{{instance}}` | the configured instance, if any |

Names use underscores. A `{{...}}` that does not exist fails at startup, not per connection.

### From token claims

To use anything else the token carries, declare it:

```yaml
placeholders:
  tenant: tenant_id              # a top-level claim
  region: metadata.region        # dot-separated path into a nested one
```

Then `{{tenant}}` and `{{region}}` are available in every template. Some limits, each for a
reason:

- **Built-ins cannot be redefined.** Sourcing `user_id` from an arbitrary claim would let a token
  choose whose subjects it can reach.
- **A declared placeholder no template uses is a startup error.** It would otherwise keep
  requiring the claim on every connection while granting nothing.
- **A token missing a declared claim is refused**, rather than expanding to an empty segment that
  matches nothing.
- **Values must be a single subject token** — no `.`, `*`, `>`, whitespace, at most 128
  characters. A `tenant` claim of `*` would otherwise expand `{{tenant}}.{{user_id}}.>` into
  `*.<user>.>` and reach every tenant. The same applies to the token's `sub`, so an email-style
  `sub` is refused; map it to an opaque id in your provider.

`{{user_id_hash}}` is unavailable in `passthrough` inbox mode, and referencing it there fails at
startup: clients keep their default inbox, so a permission scoped to the hash would grant an
inbox nobody subscribes to.

## KV

To NATS a KV permission is pub/sub over JetStream's internal subjects. The `kv:` block exists so
templates do not have to know them:

| Operation | Subject | |
|---|---|---|
| open bucket | `$JS.API.STREAM.INFO.KV_<b>` | pub |
| `Get(key)` | `$JS.API.DIRECT.GET.KV_<b>.$KV.<b>.<key>` | pub |
| receive the value | `$KV.<b>.<key>` | sub |
| `Put` / `Delete(key)` | `$KV.<b>.<key>` | pub |
| `Watch` / `Keys` | `$JS.API.CONSUMER.CREATE.KV_<b>.>` | pub |
| create / migrate bucket | `$JS.API.STREAM.{CREATE,UPDATE,DELETE,PURGE}.KV_<b>` | pub |
| always, when `kv:` is present | `$JS.API.INFO` | pub |

That direct-get carries the key **inside the subject** is what makes per-key scoping possible,
and it is the server that enforces it:

```yaml
kv:
  - bucket: user-settings
    access: read-write         # none | read | read-write — the DATA
    manage: false              # create/reconfigure/purge — the LIFECYCLE
    keys: "{{user_id}}.>"      # which keys, as a subject pattern
    watch: false               # Watch()/Keys(), which cannot be key-scoped
```

**`access` and `manage` are independent axes.** A service can own a bucket — create and migrate
it — while only reading the data, because writing a user's setting belongs to that user. A single
"admin" level could not express that. `access: none` with `manage: true` is the extreme:
administers the bucket without seeing inside.

**Every bucket needs exactly one template with `manage: true`.** With none, nobody can create it
and operations fail with `stream not found`, which does not say why. With several, two services
can purge the same bucket.

**Two operations cannot be scoped by key.** Get-by-revision does not carry the key in the
subject, so it is granted only when access already covers the whole bucket. A watcher sees the
entire bucket, which is why `watch` is a separate flag.

Two entries over the same bucket express "sees everything, touches only its own":

```yaml
kv:
  - bucket: user-settings
    access: read
    keys: ">"
  - bucket: user-settings
    access: read-write
    keys: "{{user_id}}.>"
```

## Adding a role

1. Write the template in `templates/`.
2. Add the rule, in the right position — first match wins.
3. `make test` validates the shipped configuration: templates load, placeholders resolve, routing
   picks what you expect, and every bucket still has exactly one administrator.
4. Grant the role in your identity provider.

Restart the callout. Nothing else restarts, and nothing recompiles.

## What fails at startup

Deliberately, because each of these is invisible at runtime until something does not work:

| | |
|---|---|
| an unknown key in either file | a typo that would silently grant nothing |
| an unreachable rule | a repeated `match`, or a catch-all that is not last |
| a template granting nothing | authenticates, then everything denied |
| an undeclared `{{placeholder}}` | |
| a declared placeholder no template uses | would require the claim for nothing |
| `{{instance}}` with no instance, or the reverse | the deployment is not scoped the way it looks |

Warnings, rather than errors, for things with a legitimate reading — a template granting no
inbox, for instance, which is right for publish-only clients and wrong for everyone else.
