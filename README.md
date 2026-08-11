# nats-zitadel-auth-callout — NATS ↔ OIDC authentication with per-role permissions

A NATS **auth callout** service. It authenticates the two classes of connection to the bus
—**people** and **service users**— against an OIDC identity provider and mints for each one the
permissions it is entitled to **by role**, both for **messages** and for **KV**.

It is not a proxy and not a gatekeeper in the data path: it steps in **exactly once, during
the handshake** of each connection. After that, the one enforcing the permissions is the NATS
server itself, on every publish and every subscribe.

**It works against an existing NATS.** Both authorization models are supported —operator mode
and config mode— so adopting it does not require migrating your server. What the identity
provider is, what your subjects look like, and whether clients scope their inboxes are all
configuration. See [§10 Using it on an existing NATS](#10-using-it-on-an-existing-nats).

> **Status: the mechanism is production-shaped; everything under `examples/` is an example.**
> Those roles and subjects describe a made-up application, chosen to show the mechanism rather
> than any particular domain — copy them and replace them with your own. `CALLOUT_RULES_PATH`
> is required precisely so a deployment cannot fall back to them by accident.
>
> To run it against real Zitadel: **[docs/zitadel.md](docs/zitadel.md)**.

---

## 1. How the exchange works

```
                    ┌──────────────┐
                    │   Zitadel    │
                    └──────▲───────┘
                           │ 3. validates the token (JWKS, local)
                           │
  ┌────────┐   1. CONNECT  │        ┌──────────────┐
  │ client ├───sentinel-client──────▶  NATS server │
  └────────┘   + access token       └──┬────────▲──┘
                                       │        │
                    2. $SYS.REQ.USER.AUTH│      │ 5. User JWT signed
                       (XKey encrypted)  │      │    with the permissions
                                       ┌─▼──────┴──┐
                                       │auth-callout│ 4. role → template → permissions
                                       └────────────┘
```

1. The client connects with the **`sentinel-client`** creds (which grant nothing on their own)
   and passes its **Zitadel access token** in the CONNECT `Token` field.
2. Because that sentinel is **not** declared in `--auth-user`, the server does not authorize it
   by itself: it publishes an `authorization_request` on `$SYS.REQ.USER.AUTH`.
3. The callout validates the token against Zitadel's JWKS. **Local** verification, no
   introspection: there is no round-trip per connection.
4. It routes the token's **role** to a template and expands the permissions with that
   connection's identity.
5. It returns a freshly signed **User JWT** with those permissions and with the token's expiry.
   The server accepts the connection with exactly that.

None of this happens again while the connection lives. The cost is a slower handshake, not a
hop per message.

---

## 2. The subject grammar

```
<instance>.<user-id>.<svc>.<method>
```

| Segment | What it is | Example |
|---|---|---|
| `instance` | Deployment. Isolates dev/stage/prod on a single NATS. | `dev` |
| `user-id` | **Who is calling.** The Zitadel `sub`, raw. The same for people and for service users: both are Zitadel users. | `100000000000000001` |
| `svc` | **Who it is talking to.** | `api`, `jira`, `email` |
| `method` | What it is asking for. | `create_project` |

The piece that holds everything together is that **`user-id` is part of the subject and it is
the permission that fixes it, not the application**. A client can only publish under its own
user id, so the receiver can read from the subject who is talking to it and trust that value:
it is vouched for by the callout, not by the message body.

The user id goes into the subject **raw** on purpose: it is what makes a subject read fluently
and lets a service identify the caller without a translation table. The trade-off, stated
explicitly: the Zitadel userId is visible in subjects, logs and traces.

A service serves with the caller as a wildcard —`dev.*.api.>`— and replies through
`allow_responses`, without needing publish permission toward the client's inbox.

### The inbox prefix is not optional

Every identity has its private inbox, under the **hash** of its user id:
`_INBOX.<hash(user-id)>.>`. **The client has to configure it when connecting**:

```go
nats.Connect(url, nats.UserCredentials(sentinel), nats.Token(accessToken),
    nats.CustomInboxPrefix("_INBOX."+userIDHash))     // Go
```
```js
connect({ servers, authenticator, token, inboxPrefix: `_INBOX.${userIDHash}` })  // nats.js
```

Without that the library generates an `_INBOX.<random>` that no scoped permission authorizes,
and the replies never arrive. The alternative would be granting `_INBOX.>`, but then any client
in the account could subscribe to everyone else's replies.

The hash is `sha256(user-id)` in lowercase base32, 16 chars. It is not there to hide the user
id —which already travels raw in messaging subjects— but because the inbox prefix needs a token
that is **fixed-length and subject-safe**, and an arbitrary `sub` does not guarantee that.

It is **deterministic**: the client recomputes it from its own token, with no side channel.
`cmd/session` is the reference:

```console
$ go run ./cmd/session 100000000000000001 dev
user-id   100000000000000001
inbox     _INBOX.withgt5jnvimncs5
pub       dev.100000000000000001.<svc>.<method>
```

---

## 3. The permissions: two files, no recompiling

```
examples/rules.yaml        token role  →  (identity type, template)   [first-match-wins]
examples/templates/*.yaml  template    →  pub/sub permissions + KV access
```

Both are mounted by path and read at startup. Changing who can do what does **not** recompile.
`CALLOUT_RULES_PATH` points at the rules file, and the templates resolve relative to *its*
directory — so moving the whole configuration elsewhere means changing one variable.

A worked example of both files, plus a server configuration for each mode, is in
**[examples/](examples/)**. They are the same in both modes: the server mode changes how the
callout signs the User JWT, not which permissions go into it.

**The role is the only thing that decides.** There is no heuristic guessing whether a token
belongs to a person or to a service: `type` in the rule declares it, and whoever administers
Zitadel assigns the role. That way "what can X do?" is answered by reading two files, without
running anything.

```yaml
# examples/rules.yaml
rules:
  - match: app-admin        # person, broad permissions
    type: person
    template: templates/person-admin.yaml

  - match: app-user         # person, scoped permissions
    type: person
    template: templates/person.yaml

  - match: app-backend      # machine user
    type: service
    service: demo           # its endpoint (its user id comes from the token)
    template: templates/service.yaml
```

With no match, **the connection is rejected**. There are no default permissions — the example
declares no catch-all on purpose.

Order matters: if a token can carry two roles, the one placed **higher** wins. Put the most
restrictive one first.

`type` determines how the **identity** is built, not the permissions. The `user-id` is the same
in both cases —the token's `sub`—; what changes is whether there is also an endpoint:

| `type` | `user-id` | Endpoint (`{{service}}`) |
|---|---|---|
| `person` | its `sub` | — serves no endpoint |
| `service` | its `sub` (the machine user's) | the name declared in the rule, **shared between replicas** on purpose: it is what allows balancing with queue groups |

That the endpoint is an axis separate from the user id is what allows several replicas of a
service to serve the same `dev.*.api.>` even though each connects with its own user.

### Templates

```yaml
pub:
  allow: ["{{instance}}.{{user_id}}.demo.>"]
  deny:  []
sub:
  allow: ["_INBOX.{{user_id_hash}}.>"]
kv:
  - bucket: user-settings
    access: read-write          # none | read | read-write   (data)
    manage: false               # the bucket's lifecycle      (orthogonal)
    keys: "{{user_id}}.>"       # WHICH keys it reaches
    watch: false
response:
  max: 1                        # allow_responses
  ttl: 45s
```

Placeholders:

| Placeholder | What it expands to |
|---|---|
| `{{instance}}` | the deployment instance |
| `{{user_id}}` | the token's `sub`, raw |
| `{{user_id_hash}}` | the hash of the user id — for the inbox prefix |
| `{{service}}` | the endpoint name; only in `type: service` templates |

They use an **underscore** (`{{user_id}}`), not a hyphen: the placeholder's name is an
identifier, even though the subject segment reads `<user-id>`.

**Allow-list, not deny-list.** Person templates enumerate the methods one by one. It is more
work to maintain, and that is on purpose: with a deny-list, a new method stays accessible until
somebody remembers to restrict it. With an allow-list, nobody reaches it until it is enabled.
It fails closed.

---

## 4. Per-user KV permissions

To NATS a KV permission is nothing special: it is pub/sub over JetStream's internal subjects.
The `kv:` block exists so that no template has to know them.

| Operation | Subject | Permission |
|---|---|---|
| open bucket | `$JS.API.STREAM.INFO.KV_<b>` | pub |
| `Get(key)` | `$JS.API.DIRECT.GET.KV_<b>.$KV.<b>.<key>` | pub |
| receive the value | `$KV.<b>.<key>` | sub |
| `Put`/`Delete(key)` | `$KV.<b>.<key>` | pub |
| `Watch`/`Keys` | `$JS.API.CONSUMER.CREATE.KV_<b>.>` | pub |
| create/migrate bucket | `$JS.API.STREAM.{CREATE,UPDATE,DELETE,PURGE}.KV_<b>` | pub |
| (always, if there is `kv:`) | `$JS.API.INFO` | pub |

**That direct-get carries the key inside the subject is what makes per-user scoping possible**,
and it is the server that enforces it:

```yaml
kv:
  - bucket: user-settings
    access: read-write
    keys: "{{user_id}}.>"     # writes and reads ONLY its own
```

Three details the model resolves and that are worth knowing:

- **`access` and `manage` are separate axes.** A service can *own* a bucket —creating and
  migrating it— and at the same time only **read** the data: writing a user's preference belongs
  to that user. A single "admin" level could not express it. `access: none` with `manage: true`
  is the extreme: it administers the bucket without seeing what is inside.
- **Every bucket needs exactly one `manage: true`.** With zero, nobody can create it and
  operations fail with `stream not found`, which says nothing about the cause. With more than
  one, two services can purge the same bucket. There is a test that verifies this over the
  shipped config.
- **`Get` by revision and `Watch` cannot be scoped by key.** `STREAM.MSG.GET` does not carry the
  key in the subject, so it is only granted when the access already covers the whole bucket; and
  a watcher sees the entire bucket, which is why `watch` is a separate flag.

---

## 5. Account topology

```
operator nats-callout
├── SYS
├── APP     APP account  — this is where ALL connections land. JetStream + KV.
└── AUTH    AUTH account — the callout and its two sentinels.
```

**A single APP account for people and services.** The isolation between them comes from the
subject permissions, which the server enforces. Splitting them into two accounts would add a
boundary that would have to be punched through with export/import for **every** endpoint and
**every** bucket they share — and they share almost everything, because the BFF serves the
people. A single account also keeps the buckets in one namespace, which is what allows a person
and a service to hold **different permissions over the same bucket**.

### The two sentinels — the detail that costs the most if you get it wrong

In operator mode, if the user a client connects with is the **same** one declared in
`--auth-user`, NATS authorizes it directly and **the callout never fires**: the client keeps
that user's full permissions. That is why two are needed:

| Sentinel | In `--auth-user` | Who uses it |
|---|---|---|
| `sentinel-handler` | **yes** → bypasses the callout | the callout itself (it cannot authorize itself) |
| `sentinel-client` | **no** → triggers the callout | the clients. Deny-all of its own: the only access comes from the User JWT. |

`sentinel-client` is **safe to distribute**: on its own it authorizes nothing.

### The two signing keys

They are different too, and confusing them is the other classic mistake. **This applies to
operator mode**; config mode collapses them into one (see
[§10.1](#101-server-authorization-mode)):

| Key | Signs | What for |
|---|---|---|
| `APP` account signing key | the **User JWT** | defines which account the user lands in (`IssuerAccount`) |
| `AUTH` account signing key | the **authorization_response** | it is the callout issuer the server has configured |

The requests travel **XKey-encrypted** (curve25519): without that, the client's access token
would travel in the clear over `$SYS.REQ.USER.AUTH`.

> Careful with the two `aud` fields, which mean opposite things: the **inner** User JWT's audience
> is the target account name (config mode), while the **outer** `authorization_response`'s audience
> is the server ID. ADR-26 documents `aud` as the server key, which is true only of the outer one.

---

## 6. Bringing it up

Requirements: **Go 1.26+**, and `nsc` + `nats-server` on the PATH.

```sh
go install github.com/nats-io/nsc/v2@latest
go install github.com/nats-io/nats-server/v2@latest
```

```sh
make bootstrap    # generates operator, accounts, sentinels, XKey, authcallout and the resolver
make run          # brings up NATS + the callout in the foreground
make test         # unit tests (includes validating the shippable config)
make              # lists every target
```

The bootstrap is **idempotent**: if there is already an identity in `nats/out/`, it is reused.
Regenerating it breaks the server's trust and forces reissuing every cred
(`make clean-identity`).

### Trying it by hand

The default mode is `mock`: an in-process IdP that decodes the identity from the token text,
with no secrets and no network. The format is `mock:<sub>:<username>:<roles>`.

Watch out for the two distinct values: the subjects carry the **raw user id** (`$UID`) and the
inbox carries its **hash** (`$IHASH`).

```sh
NATS="nats --server nats://127.0.0.1:4322 --creds nats/out/sentinel-client.creds"
UID=zit-ana
IHASH=$(go run ./cmd/session "$UID" dev | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')
U="$NATS --token mock:$UID:ana@example.com:app-user --inbox-prefix _INBOX.$IHASH"

# Under its own user id and an enabled method: OK
$U pub "dev.$UID.demo.ping" hello

# A app-admin-only method: Permissions Violation
$U pub "dev.$UID.demo.admin_reset" x

# Someone else's user id: Permissions Violation
$U pub "dev.other.demo.ping" x

# Per-user scoped KV (the bucket is created beforehand by the app-backend service user)
$U kv put user-settings "$UID.theme" dark    # OK
$U kv put user-settings "other.theme" x      # fails
```

> **For what is supposed to fail, use `pub` and not `request`.** A denied publish is reported
> **asynchronously**: `nats request` sends it, receives no reply and **exits 0 printing
> nothing** — it looks like it worked. `nats pub` does show `permissions violation` right away.
>
> And **a violation on a JetStream subject never shows up as a violation**: the request goes
> unanswered and the client reports a timeout. When something in KV "does not respond", the
> exact missing subject is in the `nats-server` log as `Publish Violation`.

### Against real Zitadel

What to create in Zitadel, and how to check a token when something is refused:
**[docs/zitadel.md](docs/zitadel.md)**. In short:

```sh
CALLOUT_IDP_MODE=zitadel
CALLOUT_ZITADEL_ISSUER_URL=https://id.example.com
CALLOUT_ZITADEL_PROJECT_ID=<projectId>          # recommended
```

```sh
make test-live    # verifies discovery + JWKS before bringing anything up
```

The callout logs the mode on its first line: **check that it says `idp=zitadel`**, not
`idp=mock`.

Three things that break authentication and are not obvious:

- **The token has to be a JWT.** In Zitadel, a machine user with *Access Token Type: Bearer*
  issues an **opaque** token; the callout validates by signature and rejects it. You change it
  to **JWT** on the service user. `scripts/token-info.sh` detects it and says so.
- **The token has to carry the roles.** Machine-to-machine flows only include the roles claim if
  the `urn:zitadel:iam:org:projects:roles` scope is requested — the generic one, not the one for
  a specific project. `scripts/zitadel-token.sh` already sends it.
- **A self-hosted instance's JWKS is not where Cloud's is.** `id.example.com` serves it at
  `/oauth/v2/keys`, not at `/.well-known/jwks.json`. The callout resolves it through OIDC
  discovery, so it works with both.

`CALLOUT_ZITADEL_PROJECT_ID` narrows role reading to one project; without it the roles of every
project in the token are read, and a same-named role from another project could match a rule.

> If you relaunch the stack, **kill the previous one first**. `make run` only stops the
> `nats-server` it started itself. If an old callout stays alive, the new `nats-server` cannot
> bind the port and dies, while the old callout keeps serving the subject in its previous mode.
> The symptom is baffling: you change the config and nothing happens.

---

## 7. What lives where

```
cmd/callout                       the binary
cmd/session                       derives user id and inbox from a `sub` or from a token
internal/authz                    the permission engine: role routing, templates, KV, identity
internal/idp                      token verification (Zitadel, generic OIDC, mock for dev/CI)
internal/callout                  the auth callout protocol (XKey, JWTs, signing, server modes)
internal/config                   environment → Config, with per-mode validation
examples/                         a worked example: rules.yaml, templates, and a server
                                  configuration + variables for each mode. Copy, do not keep
nats/bootstrap.sh                 generates a throwaway operator-mode identity for `make run`
nats/nats-server.conf             the local demo server (what bootstrap.sh feeds)
nats/.env.example                 every variable, with what applies to which mode
scripts/run.sh                    make run
scripts/zitadel-token.sh          access token for a service user (key JSON or client secret)
scripts/token-info.sh             what a token carries and why the callout would reject it
docs/zitadel.md                   configuring Zitadel: roles, service users, token checks
```

The configuration is split into two sources on purpose: **`nats/.env`** carries what a person
decides, and **`nats/out/callout-env.sh`** —generated by the bootstrap— exposes the seeds, creds
and pubkeys. That way the keys are never written by hand and regenerating the identity does not
force editing any configuration.

---

## 8. Adding a role or a service

1. Create the template in your own `templates/` directory (start from `examples/templates/`).
2. Add the rule in your `rules.yaml`. **Order matters** (first-match-wins): the most restrictive
   on top, and `"*"` last if you want a catch-all. A catch-all anywhere else, or a repeated
   `match`, makes the rules below it unreachable and fails at startup.
3. `make test` — validates that the template loads, that it expands with no dangling
   placeholders, that the routing picks the right one, and that every bucket still has exactly
   one administrator.
4. Assign the role in Zitadel. For a service user: machine user + its key JSON + the role over
   the project.

Nothing needs recompiling or restarting other than the callout.

---

## 9. Status

**Proof of concept working.** Verified end-to-end against a real `nats-server` (mock mode, with
the config in `config/`) — the runbook's 16 cases:

- **messages:** `app-user` reaches only its own methods; `app-admin` reaches all of them; neither
  can publish under someone else's user id, cross instances, or subscribe as if it were the
  service;
- **KV, same bucket and different scopes per role:** `app-user` only its own key; `app-admin`
  reads all of them and writes only its own; the service user creates and operates it;
- **rejections:** with no token, with a malformed token, or with a role that is not in
  `rules.yaml` (there is no catch-all) → `Authorization Violation`.

Also verified against a **self-hosted Zitadel instance**: discovery resolves the JWKS at
`/oauth/v2/keys` — not the Zitadel Cloud path — and an invalid token is rejected as such.
`make test-live` runs that check against whatever instance `CALLOUT_ZITADEL_ISSUER_URL` names.

**Both server modes are covered by automated tests** that stand up a real `nats-server`
in-process (`make test`, no external tooling): acceptance in each mode, the `issuer_account`
rejection that makes config mode a real branch, the account name-vs-pubkey trap, and a foreign
tenant-first subject grammar end to end with cross-tenant isolation enforced by the server.

**What is missing:** a config-mode quickstart equivalent to `make bootstrap`, and a
`callout verify` that checks a deployment's wiring against the running server in both modes;
a `docker compose` example alongside the existing Dockerfile; and caching verified tokens if the
connection volume justifies it (today the signature is validated locally, which is cheap, but the
username enrichment through `userinfo` is one HTTP call per service user connection).

The repo name still says `zitadel`, which the generic `oidc` mode outgrew — worth settling before
publication.

---

## 10. Using it on an existing NATS

Everything this service assumes about *your* deployment is configuration. Four axes, each
independent.

### 10.1 Server authorization mode

`CALLOUT_SERVER_MODE=operator|config`, declared and never inferred — guessing it would silently
change the authorization model on a typo. `operator` is the default, so existing setups need no
new variable.

| | `operator` | `config` |
|---|---|---|
| Where authorization lives | operator-signed account JWTs (`nsc`) | `nats-server.conf` |
| Callout configured with | `nsc edit authcallout` | `authorization { auth_callout { … } }` |
| Account named in the User JWT | `IssuerAccount` = account **pubkey** | `Audience` = account **name** |
| Signing keys needed | two (APP signs users, AUTH signs responses) | one (`auth_callout.issuer`) |
| Handler connects with | `.creds` | user/password or nkey |

**Config mode is the one for adopting an existing NATS**: no operator, no `nsc` store, no
resolver, no reissuing credentials. Copy
[examples/config-mode/nats-server.conf](examples/config-mode/nats-server.conf) — it is commented with the
three mistakes that cost the most, and a test asserts it stays valid.

Three of those are worth repeating here, because none of them fails loudly:

- **Only the callout's own user goes in `auth_users`.** Anything listed there **bypasses the
  callout** and keeps its own permissions. A client placed there connects fine and is simply
  never authenticated.
- **Don't leave the callout in `$G`** (the default when `account` is omitted). Any other `$G`
  connection could observe credential traffic on `$SYS.REQ.USER.AUTH`.
- **`jetstream: enabled` on the target account** if your templates use `kv:`. Once an
  `accounts {}` block exists JetStream is opt-in per account, and a missing one surfaces as a
  client **timeout**, not a permissions error.

`allowed_accounts` lets you adopt **incrementally**: accounts left out of that list keep
authenticating exactly as they do today.

### 10.2 Identity provider

`CALLOUT_IDP_MODE=zitadel|oidc|mock`. The `oidc` mode works against any standards-compliant
provider; the only thing it cannot default is **where the roles live**, because there is no
cross-provider convention:

```sh
CALLOUT_IDP_MODE=oidc
CALLOUT_OIDC_ISSUER_URL=https://keycloak.example.com/realms/myrealm
CALLOUT_OIDC_ROLES_CLAIM=realm_access.roles   # Keycloak; Entra: roles; Auth0: a namespaced claim
CALLOUT_OIDC_AUDIENCE=nats                    # recommended, see below
```

The roles claim accepts an array, a space/comma-separated string, or an object keyed by role
name. It is required rather than defaulted on purpose: an unreadable roles claim yields an empty
role list, which means no rule matches and *every* connection is refused — with an error pointing
at your rules instead of at the claim.

Set `CALLOUT_OIDC_AUDIENCE` unless you have a reason not to. Without it, any token the provider
issued for **any** of its clients verifies here. The service logs `audienceChecked=false` at
startup when it is unset.

### 10.3 Subject grammar

The built-in grammar is this project's own. To express a different one, declare extra
placeholders in `rules.yaml` and source them from token claims:

```yaml
version: 1
placeholders:
  tenant: tenant_id            # a top-level claim
  region: metadata.region      # dot-separated path into a nested claim
rules:
  - match: app-user
    type: person
    template: templates/app.yaml
```

```yaml
# templates/app.yaml — a grammar with no instance token at all
pub:
  allow:
    - "{{tenant}}.{{region}}.orders.{{user_id}}.create"
```

- `CALLOUT_INSTANCE` is **optional** — leave it empty when there is nowhere to put a leading
  token. A template referencing `{{instance}}` without one still fails at startup.
- The built-ins (`instance`, `user_id`, `user_id_hash`, `service`) **cannot be redefined.**
  Sourcing `user_id` from an arbitrary claim would let a token choose whose subjects it can
  reach, which is the scoping bypass the grammar exists to prevent.
- A declared claim missing from a token is a **rejection**, not an empty expansion: a subject
  with an empty segment matches nothing and would be invisible until a client could not publish.

**Claim values must be a single subject token.** A value is accepted only if it carries no `.`,
`*`, `>`, whitespace or control characters, and is at most 128 characters. This is a
privilege-escalation guard, not hygiene: a `tenant` claim of `*` would expand
`{{tenant}}.{{user_id}}.>` into `*.<user>.>` and reach **every** tenant, and in `kv.bucket:` it
would reach every KV bucket in the account. A violating value **refuses the connection**; the
value itself is never logged, since it is token content.

The same rule applies to the token's `sub`, which feeds `{{user_id}}`. One consequence worth
knowing up front: **an email-style `sub` is refused** (the dots would shift the grammar), so a
provider issuing those has to map `sub` to an opaque id. Formats like Auth0's
`auth0|507f1f…` are fine — `|` is not a NATS metacharacter.

`{{user_id_hash}}` is **unavailable** when `CALLOUT_INBOX_MODE=passthrough`, and referencing it
there fails at startup: with clients keeping their default inbox, a permission scoped to the hash
would grant an inbox nobody subscribes to, and the symptom — replies never arriving — would say
nothing about the cause.

### 10.4 Inbox scoping

`CALLOUT_INBOX_MODE=hashed|passthrough`.

`hashed` is the default and isolates replies per user, but it requires **every client** to set a
custom inbox prefix — the most invasive demand this service makes. `passthrough` leaves the inbox
alone so existing clients need no change; the template then has to grant the inbox it uses
(typically `_INBOX.>`), which means any client in the account can subscribe to another's replies.
That trade-off is why `hashed` remains the default.

### 10.5 Validation is per-mode

A variable the selected mode does not read is an **error**, not silently ignored. Setting
`CALLOUT_APP_ACCOUNT_PUB` in config mode fails at startup and says why, rather than leaving you
to believe you configured something the service never reads.

---

## 11. License

**Apache-2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

It may be used, modified and redistributed, including commercially and inside proprietary
software. The two obligations are keeping the copyright notice and **stating the changes** made
in modified files. Apache-2.0 was chosen over MIT for the **express patent grant**, which is
what is expected of a piece of infrastructure, and because it is the license of the ecosystem it
integrates with — NATS and its libraries.

The software is distributed **"AS IS", without warranties of any kind and without assuming
liability** for its use: it is a proof of concept. It is worth insisting on what section 5 says
—the signing keys, the two sentinels— because a misconfiguration of this service is an
authorization problem across the whole bus.
