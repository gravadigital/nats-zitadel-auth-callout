# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, a minor version may contain breaking changes; they are called out
under **Changed** with what a deployment has to do.

## [Unreleased]

### Changed

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

[Unreleased]: https://github.com/gravadigital/nats-zitadel-auth-callout/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/gravadigital/nats-zitadel-auth-callout/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gravadigital/nats-zitadel-auth-callout/releases/tag/v0.1.0
