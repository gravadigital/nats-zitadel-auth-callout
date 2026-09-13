# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead:

> [Report a vulnerability](https://github.com/gravadigital/nats-zitadel-auth-callout/security/advisories/new)

If that is not available to you, email **info@grava.digital** with `nats-zitadel-auth-callout`
in the subject.

Useful things to include, as far as you have them: what an attacker gains, the server mode
(`operator` or `config`), the identity provider, and a `rules.yaml` plus template that reproduces
it. A minimal reproduction matters more than a long description — this service turns
configuration into permissions, so the configuration usually *is* the report.

You should get an acknowledgement within a few working days. We will tell you whether we consider
it a vulnerability and, if so, keep you informed until a fix ships. Credit in the advisory unless
you would rather not be named.

## What counts

This service decides which permissions a NATS connection receives. Anything that lets a
connection obtain permissions it should not have is in scope. In particular:

- a token, or a claim in one, that widens the minted permissions beyond what its rule and
  template describe;
- reaching another user's, tenant's or account's subjects, KV keys or inbox;
- bypassing verification — accepting a token that should not verify, or getting a session that
  outlives the token that authorized it;
- forging or replaying the exchange on `$SYS.REQ.USER.AUTH`;
- leaking access tokens or signing key material into logs, errors or minted JWTs.

**Not in scope**, because these are documented properties rather than defects:

- `CALLOUT_IDP_MODE=mock` accepting any identity. It is the development mode; the service warns
  about it on every startup.
- A revoked token remaining valid until it expires. Verification is local against the JWKS with
  no introspection per connection; the minted session expires with the token, so the exposure is
  bounded by the token lifetime you configure.
- A user listed in `auth_users` / `--auth-user` bypassing the callout. That is how the mechanism
  works, and `auth-callout verify` exists to catch it in a deployment.
- `CALLOUT_INBOX_MODE=passthrough` reducing reply isolation between clients. It is a documented
  trade-off and not the default.

If you are unsure whether something is in scope, report it. We would rather read a report that
turns out to be intended behaviour than miss one that is not.

## Supported versions

Fixes go onto the **latest released minor version**. There are no long-term support branches:
a deployment on an older minor upgrades to the current one to receive a fix.

## Handling

Reports are triaged privately. When a fix is ready it ships as a release with a GitHub Security
Advisory describing the impact, the affected versions and what to do — including whether a
deployment needs to rotate keys or reissue credentials, which is the part that is easy to leave
out and expensive to miss.
