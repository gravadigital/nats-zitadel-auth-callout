# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Since 1.0 the public contract is the `rules.yaml` and template schema, the built-in placeholders
and subject grammar, the authentication event payload, the `CALLOUT_*` variables and the CLI.
A change that breaks any of them is a **major**, called out under **Changed** with what a
deployment has to do.

## [Unreleased]

## [1.0.0] - 2026-09-13

First stable release. The configuration surface is what it is meant to be, so it is now a
contract: the `rules.yaml` and template schema, the built-in placeholders and the subject
grammar, the authentication event payload, the `CALLOUT_*` variables and the CLI. Breaking any
of them from here on takes a major version, and a removal is preceded by a deprecation that
keeps working and warns.

Nothing was added to get here — the opposite. This release removes the last piece of the rules
schema that did not describe the authenticated identity, which is what the schema is now free to
promise.

### Changed

- **BREAKING: `type` and `service` are gone from `rules.yaml`, and `{{service}}` is no longer a
  placeholder.** A rule is now only `match` plus `template`.

  Neither field decided anything a template could not say itself. `service` fed exactly one
  consumer, the `{{service}}` placeholder, and its value came from the rule rather than from the
  authenticated identity — so it was a constant a template could always have written literally,
  unlike every other built-in, which describes the connection that authenticated. `type` existed
  to gate `service`; it never reached template expansion or the minted User JWT, because routing
  has always been by role alone.

  **To migrate**, in this order:

  1. In every template, replace `{{service}}` with the endpoint written out —
     `"{{instance}}.*.{{service}}.>"` becomes `"{{instance}}.*.orders.>"`.
  2. In `rules.yaml`, delete the `type:` and `service:` lines. A rule keeps only `match` and
     `template`.

  Both files are parsed strictly, so a leftover key **fails at startup naming the line**
  (`line 22: field type not found in type authz.Rule`) rather than being ignored. A configuration
  that no longer means what it says does not start.

- **BREAKING: the authentication event drops `identity_type`, and its `version` is now `2`.** The
  field reported the rule's `type`, which described what the YAML said rather than anything
  verified about the principal. A consumer that needs the distinction derives it from
  `matched_role`, which is a fact read from the token. The callout's per-authentication log line
  drops the `identity` field for the same reason.

- `service` is now an ordinary placeholder name. A deployment whose tokens carry a `service` claim
  may declare it under `placeholders:` like any other.

### Notes for existing installations

Upgrading requires editing `rules.yaml` and any template using `{{service}}` — see the migration
above. Nothing else changes: no new variables, and no change to either server mode.

If you consume the authentication events, check whether anything reads `identity_type` before
upgrading; the payload's `version` moves to `2`.

## [0.2.0] - 2026-08-23

### Added

- **Authentication events.** The callout can publish one message per connection it authenticates,
  carrying the identity it just verified: the id, name, email, roles, when it happened and when
  the session expires, plus the audit context it already had (the matched role, the template, the
  client IP and the connection's nkey). It is **opt-in** — with no `events.subject` configured
  nothing about the service changes — and documented in [`docs/events.md`](docs/events.md).

  Three properties are worth knowing before turning it on. The publisher uses a **second
  connection, with its own credential**, into the account the consumers live in, because the
  callout's own connection is in the AUTH account whose subjects no application client can see.
  Delivery has **two modes**, and `events.stream` is the choice. With a stream, each event is
  published to JetStream and acked: a consumer that was down reads what it missed, retries carry
  the connection's nkey as `Nats-Msg-Id` so a lost ack cannot become two events, and the stream is
  yours to create — startup and `auth-callout verify` only check that it exists and actually
  captures the subject, which is the failure nothing reports at runtime. Without a stream, events
  are ordinary core NATS messages: at most once, to whoever is subscribed at that instant, and the
  credential needs a single publish permission. Neither is defaulted, and the startup line and
  `verify` both name the mode in effect.

  In both modes **the authentication path never waits for an event**: they are queued and
  published from another goroutine, and a full queue drops loudly rather than growing memory
  inside the service that authenticates the bus.

- **`CALLOUT_IDP_ENRICH`** (`idp.enrich`): how much the verifier asks the provider's userinfo
  endpoint for what the token did not carry — `none`, `username` or `profile`. An access token is
  not an ID token, and Zitadel keeps `name` and `email` out of it even with the `profile email`
  scopes granted, so `profile` is what makes an event name a person. The result is **cached per
  identity**, so it costs one call per user per five minutes rather than one per connection.

  Defaults reproduce the previous behaviour exactly (`username` for zitadel, `none` otherwise),
  so no deployment changes by upgrading.

### Changed

- The userinfo endpoint now comes from the **OIDC discovery document** instead of a hardcoded
  `/oidc/v1/userinfo`, and its results are cached. A provider behind a path prefix stops being a
  special case. (#1, #2)

- `examples/config-mode/nats-server.conf` suggested `allowed_accounts: [ APP ]`. **That value
  creates an authorization bypass** in the topology the example describes: the setting names the
  account a client CONNECTS AS, and clients connect as a user of the `AUTH` account, so naming
  `APP` stops delegating them to the callout — every client is then authorized directly with its
  own permissions and nothing says so. The correct value is `[ AUTH ]`, the comment now explains
  which account it is about, and a test pins the behaviour in both directions.

  If you copied that line, run `auth-callout verify --client-user … --client-password …`: it
  connects as a client while the callout is not serving, and a deployment that lets that
  connection through is bypassing.

- The Docker Hub overview is applied **by hand** rather than from the release workflow. The step
  added in 0.1.1 always fails with 403: Docker Hub refuses to edit a repository description with
  a personal access token whatever its scope. The alternatives — a password with 2FA disabled, or
  the deprecated Automated Builds — are both worse than pasting markdown occasionally, so the
  step is gone and the reasoning is recorded in `.github/workflows/release.yml`.

  No action needed by anyone deploying: the step only ever touched the Docker Hub page, never the
  image.

## [0.1.1] - 2026-08-11

### Added

- `docs/docker-hub.md`, the **Docker Hub repository overview**: what the image is, what to mount,
  the tag policy, and links back to the source and documentation.

### Known issue

- The release workflow's attempt to publish that overview fails with 403 and leaves the step
  marked as failed. The image itself is built, published and smoke-tested normally. Fixed in the
  next release.

## [0.1.0] - 2026-08-11

First public release.

### Added

- **NATS auth callout** against an OIDC identity provider: verifies the access token a client
  presents when connecting, routes its role to a permission template, and mints a User JWT
  carrying exactly those permissions and the token's expiry.
- **Both NATS authorization models.** `operator` mode (account JWTs, `nsc`) and `config` mode
  (`authorization {}` in `nats-server.conf`), selected with `CALLOUT_SERVER_MODE`. Config mode is
  what lets the service be adopted on an existing NATS without migrating it.
- **Permissions as configuration**: `rules.yaml` maps a role to a template, templates declare
  pub/sub subjects and KV access. Changing who can do what needs no recompile.
- **A configurable subject grammar.** Templates may declare extra placeholders sourced from token
  claims, so a deployment can express a grammar this project did not design. Built-in
  placeholders cannot be redefined, and claim values are validated as single subject tokens.
- **Identity providers**: `zitadel`, a generic `oidc` mode with a configurable roles claim, and
  `mock` for development.
- **`auth-callout verify`** — checks a deployment's wiring before it serves traffic, including
  whether a client credential bypasses the callout entirely.
- **`auth-callout version`** and a version on the startup log line.
- **An optional configuration file** (`CALLOUT_CONFIG_FILE`), with environment variables
  overriding it and secrets accepted only from the environment.
- **Per-mode validation**: a setting the selected mode does not read is a startup error rather
  than something silently ignored.
- **Startup coherence checks**: unreachable rules, unknown keys, declared placeholders no
  template uses, and templates that grant nothing all fail at startup instead of at runtime.
- Tooling for adopting an existing NATS: `scripts/nsc-extract.sh`, `scripts/nsc-plan.sh`, and a
  runnable example client.
- Documentation: configuring Zitadel, connecting a client, and troubleshooting organised by
  symptom.

### Security

- Claim-sourced placeholder values are validated as single subject tokens before expansion. A
  value containing `.`, `*`, `>` or whitespace would otherwise widen the minted permission past
  what the template describes — a `tenant` claim of `*` reaching every tenant, and in `kv.bucket`
  every KV bucket in the account. The same validation applies to the token's `sub`.

[Unreleased]: https://github.com/gravadigital/nats-zitadel-auth-callout/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/gravadigital/nats-zitadel-auth-callout/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/gravadigital/nats-zitadel-auth-callout/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/gravadigital/nats-zitadel-auth-callout/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gravadigital/nats-zitadel-auth-callout/releases/tag/v0.1.0
