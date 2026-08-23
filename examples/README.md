# Example configuration

A worked example you can run, then copy and change. **It is not a starting configuration to
keep** — the roles and subjects here describe a made-up application.

## What it models

An application with a `demo` service and three kinds of caller:

| Role | Identity | What it can do |
|---|---|---|
| `app-user` | person | two methods (`ping`, `echo`); in KV only its own keys |
| `app-admin` | person | every method of `demo`; reads the whole bucket, writes only its own keys |
| `app-backend` | service | serves the `demo` endpoint; owns the `user-settings` bucket |

There is **no catch-all**, so a valid token whose role is not listed does not connect.

The templates also show, commented out, how a role is granted the
[authentication events](../docs/events.md) — it is an ordinary subject permission, on the admin
template rather than the general one because the payload names everyone who signs in.

The two person roles are the point of the example: **same service, same bucket, different
permissions by role** — and within a role, scoped per user by the NATS server rather than by
the application.

## What is here

```
rules.yaml            role -> (identity type, template)
templates/            the permissions each role gets
operator-mode/        server conf + variables for an operator-mode NATS
config-mode/          server conf + variables for a config-mode NATS
```

**`rules.yaml` and `templates/` are shared, and that is the point.** The server mode changes
how the callout signs the User JWT it mints; it does not change which permissions go into it.
Only the server configuration and the callout's own credentials differ per mode.

Which mode is yours:

| | Operator mode | Config mode |
|---|---|---|
| Authorization lives in | operator-signed account JWTs (`nsc`, a resolver) | `nats-server.conf` |
| The callout is configured with | `nsc edit authcallout` | an `auth_callout {}` block |
| Signing keys the callout needs | two (APP + AUTH) | one |
| The callout connects with | a `.creds` file | user/password or an nkey |
| Target account named by | account pubkey | account **name** |

If you already run NATS, you are almost certainly in **config mode** — it is what a server
brought up without multi-tenancy uses. Start at [config-mode/](config-mode/).

To try the example locally without touching any real NATS, `make run` from the repository root
brings up operator mode with a fake identity provider; see the main README.

## Using it as a starting point

1. Rename the roles to your own and create them in your identity provider.
2. Replace the subjects in `templates/` with your application's.
3. Point `CALLOUT_RULES_PATH` at your copy — the variable is required, so the service will not
   silently fall back to this example.
4. `make test` validates that templates load, expand with no dangling placeholders, and that
   every KV bucket still has exactly one administrator.
