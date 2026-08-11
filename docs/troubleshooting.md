# Troubleshooting

Organised by **what you observe**, because that is what you have when something breaks. The cause
is usually in a different layer than the symptom suggests.

Two properties of this system produce most of the confusion, and both are worth knowing before
reading anything below:

- **Permission failures are asynchronous.** The server accepts your publish and rejects it a
  moment later, so the client call that failed already returned successfully.
- **The failure and its cause are far apart.** A misconfigured template shows up as a client that
  cannot publish; a missing server setting shows up as a timeout. Nothing points at the file you
  need to edit.

**Before anything else**, run the pre-flight check — it catches most wiring problems in one go
and names the field to change:

```sh
auth-callout verify --client-creds /path/to/client.creds     # operator mode
auth-callout verify --client-user NAME --client-password ... # config mode
```

---

## Quick index

| What you see | Most likely cause |
|---|---|
| [Every connection is refused](#every-connection-is-refused) | the callout is not serving, or the wrong mode |
| [Connecting hangs, then times out](#connecting-hangs-then-times-out) | the callout is not answering the request |
| [A client connects but can do nothing](#a-client-connects-but-can-do-nothing) | no rule matched, or the template grants nothing |
| [A client has MORE access than it should](#a-client-has-more-access-than-it-should) | it bypasses the callout — the dangerous one |
| [`request` returns nothing and exits 0](#request-returns-nothing-and-exits-0) | a denied publish, reported asynchronously |
| [Replies never arrive](#replies-never-arrive) | the inbox prefix |
| [Anything with KV times out](#anything-with-kv-times-out) | JetStream off, or a missing subject |
| [The service will not start](#the-service-will-not-start) | configuration rejected on purpose |
| [Changes to the config do nothing](#changes-to-the-config-do-nothing) | an old process, or a non-reloadable field |

---

## Every connection is refused

`Authorization Violation` on every client, immediately.

**Check the callout is running and serving.** If it is not, no connection delegated to it can be
authorized. `auth-callout verify` reports whether the handler can reach `$SYS.REQ.USER.AUTH` at
all; without that subscription the service starts, logs that it is listening, and stays silent
while every connection fails.

**Check the declared mode matches the server.** `CALLOUT_SERVER_MODE` is declared, never inferred.
A config-mode server ignores a `.creds` JWT and an operator-mode server refuses user/password, so
a mismatch usually stops the *callout's own* connection first — look at the service's startup
error, which names the mode and the field the handler must appear in.

**Check the token, not the wiring.** If only *some* clients are refused, the callout is working
and rejecting them. Its log says why per connection: `token verification failed` (see
[zitadel.md](zitadel.md#3-checking-a-token)) or `could not resolve permissions`, which means the
token's roles matched no rule.

## Connecting hangs, then times out

The client reports `i/o timeout` rather than an authorization error.

This is what a client sees when **the callout is not answering**: the server is waiting for a
response on the callout subject, and the client's connect deadline expires first. It looks like
a network problem and is not.

- the callout process is down, or connected to a different NATS than the clients;
- it is up but cannot subscribe to `$SYS.REQ.USER.AUTH` (`verify` catches this);
- token verification is slower than the server's `authorization.timeout` — raise it above the
  default 2s (the shipped examples use 5) if your IdP's first JWKS fetch is slow.

## A client connects but can do nothing

The connection succeeds; every publish and subscribe is denied.

The callout authorized it, so this is about **which permissions were minted**. The service logs
one line per authentication with `matchedBy` (the winning role) and `template`. Compare that
template with what you expected:

- **`matchedBy` is not the role you expected** — rules are first-match-wins in file order. A
  token carrying two roles matches whichever rule is higher.
- **`matchedBy` is `*`** — the catch-all matched, so the role you meant to use is not in the
  token. Check the roles claim ([zitadel.md](zitadel.md#3-checking-a-token)).
- **The template is the one you expected** — then it does not grant what you think. Remember the
  subject includes the caller's own user id: a client may only publish under *its* id, so
  `dev.<someone-else>.svc.method` is denied by design.

A template that grants nothing at all is now rejected at startup, so this cannot be an empty
template.

## A client has MORE access than it should

**Treat this as the serious one.** The usual cause is that the client's user is listed in
`auth_users` (config mode) or `--auth-user` (operator mode). The server then authorizes it
*directly*, the callout never runs, and the connection keeps whatever permissions that user
carries. Nothing anywhere reports it: the connection succeeds exactly as a legitimate one does.

Only the callout's own handler belongs in that list.

```sh
auth-callout verify --client-creds /path/to/client.creds
```

The bypass check connects as a client while the callout is not serving. A correctly wired
deployment **refuses** that connection; one that accepts it is bypassing. Note this check only
works while the service is stopped — once it is answering, a bypassing client and an authorized
one are indistinguishable.

## `request` returns nothing and exits 0

A denied publish is reported **asynchronously**. `nats request` sends it, never gets a reply, and
exits 0 having printed nothing — indistinguishable from success.

Use `nats pub` when testing something you expect to be denied: it surfaces
`Permissions Violation` immediately. The authoritative record either way is the `nats-server`
log, which logs every violation with the exact subject.

## Replies never arrive

Requests are delivered — the service receives them — but responses never come back.

**The inbox prefix.** With `CALLOUT_INBOX_MODE=hashed` (the default) each client's replies are
scoped to `_INBOX.<hash(user-id)>`, and the client must set that prefix when connecting. By
default the library generates a random `_INBOX.<nuid>` that no permission authorizes, and the
subscription is silently denied.

```sh
go run ./cmd/session <sub>     # prints the inbox prefix for a user id
```

Set it with `nats.CustomInboxPrefix` (Go), `inboxPrefix` (nats.js) or `--inbox-prefix` (CLI). If
your clients cannot be changed, `CALLOUT_INBOX_MODE=passthrough` removes the requirement — at the
cost of per-user reply isolation, and the template then has to grant the inbox its clients
actually use.

**The responder's `response:` block.** A service replies to the caller's inbox through
`allow_responses`, without an explicit publish permission toward it. A template with no
`response:` block cannot answer anyone.

## Anything with KV times out

KV operations hang and fail with `context deadline exceeded`, never with a permissions error.
This is the least obvious failure in the system, because **a JetStream permission failure never
looks like one**: the request goes unanswered and the client reports a timeout.

In order of likelihood:

- **JetStream is not enabled on the target account.** Once an `accounts {}` block exists,
  JetStream is opt-in per account. Add `jetstream: enabled` to the account clients land in.
- **Nobody can create the bucket.** Every bucket needs exactly one template with `manage: true`.
  With none, the bucket never exists and operations fail with `stream not found`.
- **A subject is missing from the minted permissions.** The `nats-server` log names it as a
  `Publish Violation` — that log is the fastest way to the answer here.

Two operations cannot be scoped by key, by design: `Watch`/`Keys` (an ephemeral consumer sees the
whole bucket, hence the separate `watch:` flag) and get-by-revision, which is only granted when
the access already covers the whole bucket.

## The service will not start

Startup validation refuses configurations that cannot work, deliberately — the alternative is a
service that authenticates people into permissions nobody intended.

| Error | What it means |
|---|---|
| `missing environment variables` | including `CALLOUT_RULES_PATH`, which has no default so a deployment cannot fall back to the bundled example |
| `variables that do not apply to CALLOUT_SERVER_MODE=…` | a variable the selected mode never reads. Setting it means one of the two is wrong |
| `field … not found in type` | an unknown key in `rules.yaml` or a template — usually a typo like `publish:` for `pub:`. Ignoring it would grant nothing while still starting |
| `unreachable rule` | a repeated `match`, or a catch-all that is not last. The rules after it can never fire |
| `declared placeholder is never used` | a `placeholders:` entry no template references. It would still force every token to carry that claim |
| `an instance is configured but no template uses {{instance}}` | `CALLOUT_INSTANCE` has no effect — the deployment is not scoped per instance the way it appears to be |
| `template grants no permissions` | a client using it would authenticate and then be denied everything |
| `unknown placeholder in template` | a `{{name}}` that does not exist. In passthrough inbox mode this also covers `{{user_id_hash}}`, which is deliberately unavailable there |

## Changes to the config do nothing

**An old process is still serving.** The most common cause, and the most disorienting: you change
the configuration, restart, and behaviour does not change. A previous callout still subscribed to
the callout subject keeps answering in its old configuration. Check for a stale process before
suspecting the configuration.

**`auth_callout` is not reloadable.** In config mode, every field in that block requires a full
server restart — `nats-server --signal reload` does not pick it up.

**Rules and templates are read at startup.** Changing them requires restarting the callout (but
not the NATS server).

---

## Reading the logs

The callout logs one line per authentication. The fields that answer most questions:

| Field | What it tells you |
|---|---|
| `matchedBy` | the winning role. With several roles in a token, everything else is ambiguous without it |
| `template` | which template was expanded |
| `identity` | the identity *model* applied (person/service) — not the class of user in the IdP |
| `inboxHash` | the client's inbox prefix, which cannot be derived by eye from the rest |
| `pubAllow` / `subAllow` | how many permissions were minted. `0` means something is wrong upstream |

The startup line names `serverMode`, `idp`, `instance` and `inbox`. **Check `idp` first**: `mock`
accepts any identity a client claims and is never right in production.

Access tokens are never logged. `trace` is off in the shipped server configurations for the same
reason — it would log CONNECT messages, which carry them.
