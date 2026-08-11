# Configuration

Two sources: an optional YAML file describing the deployment, and environment variables. The
environment always wins, and secrets come from it only.

## The two sources

```sh
CALLOUT_CONFIG_FILE=/etc/auth-callout/callout.yaml
```

```yaml
server:
  mode: operator                    # everything under here depends on this
  url: nats://nats.internal:4222
  app_account_pub: ABAC…
idp:
  mode: zitadel
  issuer_url: https://id.example.com
  project_id: "200000000000000002"
permissions:
  rules_path: /etc/auth-callout/rules.yaml
  instance: prod
  inbox_mode: hashed
log:
  level: info
```

Worked files for both modes: [operator](../examples/operator-mode/callout.yaml),
[config](../examples/config-mode/callout.yaml).

Three rules, without exceptions:

- **The environment wins**, including when set to empty — which is how a deployment clears
  something a file it does not own turned on. Startup logs every file key that lost to a
  variable, because "I changed the file and nothing happened" is otherwise a long afternoon.
- **Secrets never appear in the file.** One that does is a startup error naming the variable to
  use instead. A seed written into YAML ends up in version control eventually.
- **Unknown keys are rejected**, so a typo cannot leave the deployment running on a default
  nobody picked.

The file is optional; everything works through the environment alone.

## Settings

Anything not marked as a secret can go in either source. Which ones apply depends on the modes,
and setting one the selected mode does not read is a **startup error** rather than something
silently ignored.

### Server

| File key | Variable | Notes |
|---|---|---|
| `server.mode` | `CALLOUT_SERVER_MODE` | `operator` (default) or `config`. Never inferred |
| `server.url` | `CALLOUT_NATS_URL` | default `nats://127.0.0.1:4222` |
| `server.app_account_pub` | `CALLOUT_APP_ACCOUNT_PUB` | **operator only** — the target account's public key |
| `server.target_account` | `CALLOUT_TARGET_ACCOUNT` | **config only** — the account **name**, not its key |
| `server.handler.user` | `CALLOUT_HANDLER_USER` | the handler's user name |
| — | `CALLOUT_HANDLER_PASSWORD` | **secret** |
| — | `CALLOUT_HANDLER_CREDS` | **secret** — a `.creds` file, the operator-mode form |
| — | `CALLOUT_HANDLER_NKEY_SEED` | **secret** |
| — | `CALLOUT_APP_ACCOUNT_SK_SEED` | **secret** — signs the User JWT. Required in both modes |
| — | `CALLOUT_AUTH_ACCOUNT_SK_SEED` | **secret**, **operator only** — signs the response |
| — | `CALLOUT_XKEY_SEED` | **secret** — decrypts callout requests |

Exactly one handler credential form may be set. Two would leave it unclear which one is in use,
so it is an error rather than a precedence rule.

Seeds accept either the seed itself or a path to a file holding it.

### Identity provider

| File key | Variable | Notes |
|---|---|---|
| `idp.mode` | `CALLOUT_IDP_MODE` | `zitadel`, `oidc` or `mock` (default) |
| `idp.issuer_url` | `CALLOUT_ZITADEL_ISSUER_URL` / `CALLOUT_OIDC_ISSUER_URL` | one file key for both; the mode says which verifier reads it |
| `idp.project_id` | `CALLOUT_ZITADEL_PROJECT_ID` | zitadel: narrows role reading to one project |
| `idp.roles_claim` | `CALLOUT_OIDC_ROLES_CLAIM` | oidc: **required**, no default |
| `idp.username_claim` | `CALLOUT_OIDC_USERNAME_CLAIM` | oidc, default `preferred_username` |
| `idp.audience` | `CALLOUT_OIDC_AUDIENCE` | oidc: worth setting, see below |

**`mock` accepts any identity a client claims.** It is the development mode, warned about on
every startup, and never right in production.

**`roles_claim` has no default on purpose.** There is no cross-provider convention for where
roles live, and guessing would yield an empty role list — which means no rule matches and every
connection is refused, with an error pointing at your rules instead of at the claim.

```
Keycloak   realm_access.roles
Entra      roles
Auth0      a namespaced claim
```

The claim may be an array, a space- or comma-separated string, or an object keyed by role name.

**Set `audience` unless you have a reason not to.** Without it, any token the provider issued for
*any* of its clients verifies here. Startup logs `audienceChecked=false` when it is unset.

### Permissions

| File key | Variable | Notes |
|---|---|---|
| `permissions.rules_path` | `CALLOUT_RULES_PATH` | **required**, no default |
| `permissions.instance` | `CALLOUT_INSTANCE` | the `{{instance}}` placeholder. Optional |
| `permissions.inbox_mode` | `CALLOUT_INBOX_MODE` | `hashed` (default) or `passthrough` |

`rules_path` has no default so a deployment cannot silently fall back to the bundled example.
Templates resolve relative to *its* directory, so relocating a whole configuration means changing
one setting.

`instance` is optional, but the two halves have to agree: a template referencing `{{instance}}`
with none configured fails at startup, and so does configuring one no template uses. Both would
otherwise be invisible until a client could not publish.

### Logging

| File key | Variable | Notes |
|---|---|---|
| `log.level` | `CALLOUT_LOG_LEVEL` | `debug`, `info` (default), `warn`, `error` |

Access tokens are never logged.

## Checking what is loaded

```sh
auth-callout verify   # reports the file it read and which keys the environment overrode
auth-callout version  # which build this is
```

The service's first log line names the version, server mode, identity provider, instance and
inbox mode. When something behaves unexpectedly, that line is the first thing to read — see
[troubleshooting](troubleshooting.md).
