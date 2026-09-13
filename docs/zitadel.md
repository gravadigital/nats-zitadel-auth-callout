# Configuring Zitadel

What to create in Zitadel so the callout can authenticate your clients, and how to check a token
before blaming anything else.

Everything here applies to Zitadel Cloud and to a self-hosted instance alike. The examples use
`id.example.com` as the issuer — replace it with yours.

> Using a different OIDC provider? Set `CALLOUT_IDP_MODE=oidc` instead and point
> `CALLOUT_OIDC_ROLES_CLAIM` at wherever that provider puts roles. Only this document is
> Zitadel-specific; the rest of the service is not.

---

## 1. What to create

### 1.1 A project

Reuse an existing one or make a new one. Note its **Resource Id** (numeric, e.g.
`200000000000000002`): that is `CALLOUT_ZITADEL_PROJECT_ID`.

Setting it is recommended. Without it the callout reads the roles of *every* project in the
token, so a same-named role from an unrelated project could match one of your rules.

### 1.2 The roles

*Project → Roles → New.* The **Key** is what travels in the token and what `rules.yaml` matches
against, so it has to be exact — a mismatch here means no rule matches and the connection is
refused.

Create one role per rule in your `rules.yaml`. The shipped example config expects:

| Key | What for |
|---|---|
| `app-user` | person with scoped permissions |
| `app-admin` | person with broad permissions |
| `app-backend` | the service user serving the `demo` endpoint |

### 1.3 The users

People sign in normally — nothing to configure beyond granting them a role.

For backend services, create a **service user** (*Users → Service Users → New*).

> **Set Access Token Type = JWT.** It is a field on the service user's form and it defaults to
> **Bearer**, which issues an **opaque** token. The callout validates by signature against the
> JWKS, so with an opaque token there is nothing to verify and it rejects it as invalid. This is
> the single most common mistake when setting this up. `scripts/token-info.sh` detects it and
> says so.

Note that **the callout routes only by role**, never by Zitadel's class of user. A service user
holding a role that points at a person template gets those permissions, and that is by design —
it is what lets you exercise every path without a browser login.

### 1.4 Credentials for a service user

Either form works; `scripts/zitadel-token.sh` detects which one you have:

- **Client secret** (quicker): *Secrets → Generate Client Secret*, then save a JSON by hand:
  ```json
  { "clientId": "...", "clientSecret": "..." }
  ```
- **Key JSON**: *Keys → New → Type: JSON*. Downloads `{type, keyId, key, userId}` directly.
  Requires `openssl`.

Keep these out of the repository. `secrets/` is gitignored for this purpose.

### 1.5 The authorizations

*Project → Authorizations* (or *User → Authorizations*): grant each user its role in the project.
**Without this the token comes out with no roles** and the callout refuses the connection.

> If the project lives in a **different organization** than the users, the role additionally has
> to be enabled in the **project grant** toward the users' organization.

---

## 2. Pointing the callout at Zitadel

```sh
CALLOUT_IDP_MODE=zitadel
CALLOUT_ZITADEL_ISSUER_URL=https://id.example.com
CALLOUT_ZITADEL_PROJECT_ID=200000000000000002
```

Check connectivity **before** bringing anything up:

```sh
CALLOUT_ZITADEL_ISSUER_URL=https://id.example.com make test-live
```

It reports the issuer and the resolved JWKS URL. A self-hosted instance serves its keys at
`/oauth/v2/keys`, which is **not** where Zitadel Cloud serves them; the callout finds either
through OIDC discovery, so both work without configuration.

When the service starts, its first log line names the mode. **Check that it says
`idp=zitadel`** — if it says `idp=mock`, the configuration was not picked up, and mock mode
accepts any identity a client claims.

---

## 3. Checking a token

Almost every authentication failure is explained by the token itself, so inspect it before
looking anywhere else:

```sh
export ZITADEL_ISSUER_URL=https://id.example.com
export ZITADEL_PROJECT_ID=200000000000000002

TOKEN=$(./scripts/zitadel-token.sh secrets/my-service-user.json)
./scripts/token-info.sh "$TOKEN"
```

It should report `It is a JWT. ✓` and list the roles claim.

| Symptom | Cause | Fix |
|---|---|---|
| `NOT a JWT` | the service user is on Bearer | Access Token Type = JWT (§1.3) |
| `Role claims present: NONE` | missing authorization, or missing scope | grant the role (§1.5); the script already requests the right scope |
| an unexpected role | credential of a different service user | check which JSON you used |

The roles claim only appears in a machine-to-machine flow if the generic
`urn:zitadel:iam:org:projects:roles` scope is requested — the generic one, not the
project-specific variant. `scripts/zitadel-token.sh` already sends it.

---

## 4. Deriving a client's identity

A connecting client needs **two values from its own token**, and they are not interchangeable:

- the **raw user id** (`sub`) builds the subjects it may publish on;
- the **hash of the user id** builds its inbox prefix.

```sh
go run ./cmd/session --token "$TOKEN"
```
```console
user-id   100000000000000001
inbox     _INBOX.withgt5jnvimncs5
pub       dev.100000000000000001.<svc>.<method>
```

The client sets that inbox prefix when connecting (`nats.CustomInboxPrefix` in Go, `inboxPrefix`
in nats.js, `--inbox-prefix` in the CLI). Without it the library generates a random `_INBOX.<id>`
that no scoped permission authorizes, and replies never arrive.

If your clients cannot be changed, `CALLOUT_INBOX_MODE=passthrough` removes that requirement —
at the cost of the per-user reply isolation. See the README.

---

## 5. Zitadel-specific behaviour worth knowing

For symptoms in general — connections refused, clients that can do nothing, KV timing out — see
**[troubleshooting.md](troubleshooting.md)**. Two things below are properties of *this* verifier
rather than of the wiring, so they belong here.

**A revoked token stays valid until it expires.** Verification is local against the JWKS, with no
introspection call per connection, so revocation in Zitadel is not observed until the token's
`exp`. The minted NATS session expires with the token, so the exposure is bounded by the token
lifetime you configure in Zitadel — that setting is what to tune if this matters to you.

**An access token is not an ID token.** Zitadel's JWT access tokens carry `preferred_username`
and the project roles, but neither `name` nor `email` — even when the token was requested with the
`profile email` scopes. Those claims live in userinfo. It matters if you publish
[authentication events](events.md) and want them to name a person: set `CALLOUT_IDP_ENRICH=profile`
and the verifier fills them from userinfo, cached per identity. A machine user has a `name` there
and no email at all.

**Key rotation needs no restart.** The JWKS is refreshed periodically, and a token signed with an
unknown key triggers one immediate, rate-limited refetch. The rate limit exists because that path
runs *before* authentication: without it, a token with a made-up key id would let anyone force a
request to Zitadel.
