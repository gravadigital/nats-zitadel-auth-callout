<!--
This file is the Docker Hub repository overview. Applying it is MANUAL: Docker Hub → the
repository → General → Add overview, then paste everything below this comment.

It is not automated because Docker Hub refuses to edit a description with a personal access
token whatever its scope; see the note in .github/workflows/release.yml. Keep the links
absolute — relative ones break outside GitHub — and the whole file under 25,000 bytes.

The short description, edited in the same place, is limited to 100 characters:

  NATS auth callout: authenticate connections against OIDC and mint per-role permissions
-->

# nats-zitadel-auth-callout

Authenticate NATS connections against your OIDC identity provider, and give each one the
permissions its **role** entitles it to.

**Source and full documentation:**
[github.com/gravadigital/nats-zitadel-auth-callout](https://github.com/gravadigital/nats-zitadel-auth-callout)

The service steps in once, during the handshake of each connection: it verifies the access token
the client presents, matches the token's roles against your rules, and hands the NATS server a
freshly signed User JWT carrying exactly the permissions that role gets. From there the server
enforces them. It is **not in the data path** and adds nothing per message.

## Why

Without it, NATS permissions live in server configuration or account JWTs: changing what someone
can do means editing infrastructure. With it, your identity provider is the source of truth —
grant a role there and the next connection gets those permissions — and what each role can do is
two readable files.

- Works against an **existing NATS**, in either authorization mode (`operator` or `config`). No
  migration.
- **Zitadel** has first-class support; any standards-compliant OIDC provider works through the
  generic `oidc` mode.
- The NATS session **expires with the access token** that authorized it.
- You define your own subjects. The service substitutes the authenticated identity into the
  permission templates you write; it imposes no subject grammar of its own.

## Usage

The image carries no configuration and no secrets — mount them:

```sh
docker run --rm \
  -v /etc/auth-callout:/etc/auth-callout:ro \
  -v /run/secrets:/etc/nats-creds:ro \
  -e CALLOUT_CONFIG_FILE=/etc/auth-callout/callout.yaml \
  -e CALLOUT_APP_ACCOUNT_SK_SEED=/etc/nats-creds/app.seed \
  -e CALLOUT_HANDLER_CREDS=/etc/nats-creds/handler.creds \
  -e CALLOUT_XKEY_SEED=/etc/nats-creds/xkey.seed \
  gravadigital/nats-zitadel-auth-callout:0.1.0
```

Two mount points exist in the image:

| Path | What goes there |
|---|---|
| `/etc/auth-callout` | `callout.yaml`, `rules.yaml` and your permission templates |
| `/etc/nats-creds` | signing key seeds, handler credentials, the encryption key |

Everything except secrets can live in the configuration file. Secrets come from the environment
only — the service refuses to start if it finds one in the file. Seed settings accept either the
seed itself or a path to a file holding it, so Kubernetes secret references and Docker secret
mounts both work unchanged.

Useful commands:

```sh
docker run --rm gravadigital/nats-zitadel-auth-callout:0.1.0 version
docker run --rm ... gravadigital/nats-zitadel-auth-callout:0.1.0 verify --client-creds ...
```

`verify` checks a deployment's wiring before it serves traffic — including whether clients bypass
the callout entirely, which is the failure that produces no error anywhere. Run it while the
service is stopped, and it exits non-zero on any problem, so it works as a deployment gate.

## Tags

| Tag | What it tracks |
|---|---|
| `0.1.0` | an exact release. Use this in production |
| `0.1` | the latest patch of that minor version |
| `latest` | the newest stable release |

Prereleases (`1.0.0-rc.1`) publish only their own tag and never move `latest`.

Images are `linux/amd64`, built from the tagged commit, and every release is smoke-tested after
publishing.

## Requirements

- NATS server **2.10+**, in `operator` or `config` authorization mode.
- An OIDC identity provider.

## Documentation

- [Concepts](https://github.com/gravadigital/nats-zitadel-auth-callout/blob/main/docs/concepts.md)
  — how a token becomes permissions, and what the service does and does not impose
- [Installing](https://github.com/gravadigital/nats-zitadel-auth-callout/blob/main/docs/install.md)
  — adding the callout to a NATS server
- [Configuration](https://github.com/gravadigital/nats-zitadel-auth-callout/blob/main/docs/configuration.md)
  — every setting
- [Permissions](https://github.com/gravadigital/nats-zitadel-auth-callout/blob/main/docs/permissions.md)
  — rules, templates and KV
- [Troubleshooting](https://github.com/gravadigital/nats-zitadel-auth-callout/blob/main/docs/troubleshooting.md)
  — organised by symptom

## Support and security

Issues and questions:
[github.com/gravadigital/nats-zitadel-auth-callout/issues](https://github.com/gravadigital/nats-zitadel-auth-callout/issues)

Vulnerabilities: **do not open a public issue** — see the
[security policy](https://github.com/gravadigital/nats-zitadel-auth-callout/blob/main/SECURITY.md).

## License

[Apache-2.0](https://github.com/gravadigital/nats-zitadel-auth-callout/blob/main/LICENSE).
Copyright Grava Digital. Distributed as is, without warranties of any kind.
