# Authentication events

The callout can publish one message per connection it authenticates, carrying the identity it
just verified.

```
   ┌────────┐  connect + access token   ┌─────────────┐
   │ client │ ────────────────────────▶ │ NATS server │
   └────────┘                           └──┬───────▲──┘
                      who is this? ────────┘       │
                                     ┌─────────────┴──┐
                                     │  auth callout  │
                                     └───┬────────┬───┘
                 signed User JWT ────────┘        └──────▶ AUTH_EVENTS
                                                          prod.events.auth
```

It exists because the callout is the only component that knows an authentication happened. The
NATS server sees a connection, not a person; the identity provider sees a token request, not a
bus. Everything else has to be told.

**It is off unless you turn it on.** The payload carries a name and an email, and no deployment
should start announcing who signs in because it upgraded.

## What a consumer receives

```json
{
  "type": "authenticated",
  "version": 1,
  "id": "281234567890123456",
  "name": "Ana Pérez",
  "username": "ana@example.com",
  "email": "ana@example.com",
  "roles": ["app-user"],
  "authenticated_at": "2026-08-23T18:04:11.123Z",
  "expires_at": "2026-08-23T19:04:11Z",
  "instance": "prod",
  "identity_type": "person",
  "matched_role": "app-user",
  "template": "templates/person.yaml",
  "client_ip": "10.1.2.3",
  "session": "UAWUJEWODGQJGMUGZBJH4Y6XKTVD5V4G5EQZXUJA5QV3ZL2TP2JY3ZNH"
}
```

| Field | What it is |
|---|---|
| `type`, `version` | the event kind and the payload's version. `version` changes if a field's meaning does |
| `id` | the token's `sub` — the identity provider's user id. The field to join on |
| `name` | the human-readable name. Falls back to `username`; see [name and email](#name-and-email) |
| `username` | the token's username claim (`preferred_username` by default) |
| `email` | may be **absent**: a machine user has none |
| `roles` | the roles the token carried, as routed on. Never `null` |
| `authenticated_at` | when the callout authenticated the connection, UTC |
| `expires_at` | when the minted session expires — the same instant the server enforces |
| `instance` | the deployment instance |
| `identity_type` | `person` or `service`: the identity MODEL the rule applied, not the class of user in the IdP |
| `matched_role` | the winning rule's `match`, or `*`. With several roles in a token it is the only way to know which one applied |
| `template` | the permission template that was expanded, as the rule declares it |
| `client_ip` | the connecting client's host |
| `session` | the connection's user nkey. It identifies **one connection**, not one user — it is what correlates with `nats server report connections`, and it is the event's deduplication id |

The field names are a published contract. Treat a rename as breaking even though nothing in this
repository would fail to compile.

**Only successful authentications are published.** A token that does not verify, or a role that
matches no rule, produces no event: a consumer counting logins is counting logins.

## The account boundary, which is the whole setup

The callout's own connection lives in the **AUTH** account. Accounts are isolated subject
namespaces, so an event published there would be visible to nobody. The publisher therefore gets
a **second connection, with its own credential, into the account the consumers live in** — the
same account clients land in.

What that credential needs depends on the delivery mode below, and in neither case is it much:

| | subject | acked | core |
|---|---|:---:|:---:|
| pub | the events subject | ✓ | ✓ |
| pub | `$JS.API.STREAM.INFO.<stream>` | ✓ | — |
| sub | its own inbox (`_INBOX.>`) | ✓ | — |

Core delivery needs **one publish permission and nothing else**: there is no ack, so there is no
inbox to receive it on and no JetStream API to reach. Both sets are exactly what the test suite
grants — no more — so if either list were wrong the tests would fail rather than the
documentation being quietly optimistic.

Neither can create streams, and that is deliberate: creating streams is far more authority than
publishing an event needs.

## Choosing how it is delivered

`events.stream` is optional, and setting it is the choice:

| | **acked** (a stream) | **core** (no stream) |
|---|---|---|
| A consumer subscribed right then | receives it | receives it |
| A consumer that was down | reads it later | **the event never existed** |
| History, reprocessing | yes | no |
| The callout knows it arrived | yes, it waits for the ack | no |
| A lost ack | retried, deduplicated by `Nats-Msg-Id` | not applicable |
| Credential | three permissions | one |
| To operate | a stream, with retention | nothing |

Two things that trip people up. **A stream does not change how you consume**: a live subscriber
receives the message either way — the stream stores a copy, it does not intercept. And **there is
no ack without a stream**, because the ack *is* JetStream.

If disk and retention are the objection rather than the guarantee, a memory stream with a short
age is the middle ground: confirmed delivery plus an hour of history, no disk.

```sh
nats stream add AUTH_EVENTS --subjects 'prod.events.auth'   --storage memory --retention limits --discard old --max-age 1h --dupe-window 2m
```

Whichever you pick, the service **says which one on its startup line** (`delivery=…`) and
`auth-callout verify` reports it. That is on purpose: from outside a running service the two are
indistinguishable until the day somebody looks for an event that was never stored.

## Setting it up

### 1. The stream — only for acked delivery

Skip this entirely for core delivery. Otherwise you create it; the callout only checks it. Put it
in the account the events land in:

```sh
nats stream add AUTH_EVENTS \
  --subjects 'prod.events.auth' \
  --storage file --retention limits --discard old \
  --max-age 30d --dupe-window 2m
```

`--dupe-window` is not decoration. Every publish carries the connection's user nkey as
`Nats-Msg-Id`, so if an ack is lost on the way back the retry is collapsed by the server instead
of producing a second event for one connection.

Size `--max-age` for the volume you actually get: events fire for **every** authenticated
connection, and a backend that reconnects does so on every restart.

### 2. The credential

**Operator mode** — one user in the target account:

```sh
nsc add user --account APP --name callout-events \
  --allow-pub 'prod.events.auth' \
  --allow-pub '$JS.API.STREAM.INFO.AUTH_EVENTS' \   # acked delivery only
  --allow-sub '_INBOX.>'                             # acked delivery only
nsc generate creds --account APP --name callout-events > callout-events.creds
```

For core delivery, drop the last two flags and add `--deny-sub '>'`: publishing an event is the
only thing this credential ever has to do.

**Config mode** — a user in the `accounts {}` block, plus one line that is easy to miss:

```
accounts {
  APP: {
    jetstream: enabled
    users: [
      { user: callout-events, password: "…"
        permissions: {
          publish:   { allow: [ "prod.events.auth", "$JS.API.STREAM.INFO.AUTH_EVENTS" ] }
          subscribe: { allow: [ "_INBOX.>" ] }
        }
      }
    ]
  }
}

authorization {
  auth_callout {
    …
    # WITHOUT THIS, every account is delegated to the callout — including APP, so the
    # publisher's own connection would be sent to the callout, which has no token for it.
    # Clients that must go through the callout connect as an AUTH user, so scoping the
    # delegation here changes nothing about them.
    allowed_accounts: [ AUTH ]
  }
}
```

### 3. The callout

```yaml
events:
  subject: "{{instance}}.events.auth"
  stream: AUTH_EVENTS         # omit for core delivery
  user: callout-events        # config mode; operator mode uses CALLOUT_EVENTS_CREDS
```

with the credential's secret half from the environment (`CALLOUT_EVENTS_PASSWORD`,
`CALLOUT_EVENTS_CREDS` or `CALLOUT_EVENTS_NKEY_SEED`). Full list in
[configuration](configuration.md#authentication-events).

The subject is a **pattern**, expanded with the same placeholders permission templates use, and
it has to expand to one literal subject: no wildcards, and not `{{service}}`, which is empty for
people. `{{user_id}}` is allowed and gives consumers per-user filtering — at the price of one
subject per user in the stream.

### 4. Who may consume it

The events are an ordinary subject, so the answer is an ordinary template entry:

```yaml
sub:
  allow:
    - "{{instance}}.events.auth"
```

Grant it per role, like everything else. The payload carries the name and email of everyone who
signs in, so it belongs on an audit or admin role rather than on a general one.

## Name and email

An access token is not an ID token. Zitadel — and it is not alone — issues JWT access tokens
carrying the username and the roles but **not** `name` or `email`, even when the token was
requested with the `profile email` scopes. Those claims live in userinfo.

So if the events arrive with an empty name and email, that is why. Set:

```sh
CALLOUT_IDP_ENRICH=profile
```

and the verifier asks userinfo for what the token did not carry. It is **cached per identity**
(five minutes), so a reconnecting fleet costs one call per user per window rather than one per
connection — which matters, because the callout serves authentication requests one at a time.

The token always wins: userinfo only fills what is missing. And it is best effort — a provider
that is slow or down produces an event with fewer fields, never a refused connection.

If your provider puts them somewhere non-standard, point at the claim directly instead:

```yaml
events:
  name_claim: profile.full_name
  email_claim: profile.mail
```

## Delivery

**The authentication path never waits for an event**, in either mode.

A NATS subscription hands messages to its handler one at a time, so waiting for an ack inside the
callout's handler would stall every connection queued behind it. Events go to a bounded in-memory
queue and a publishing goroutine instead. What follows from that, whichever mode you run:

- **An event is never allowed to affect a connection.** It is published after the server already
  has its answer. A failure is logged, never propagated.
- **A full queue drops, loudly.** If the publisher stops keeping up, the queue fills and further
  events are dropped with an error naming the running total. The alternative — growing memory
  inside the service that authenticates your bus — is worse.
- **Shutdown drains** what is queued, for up to five seconds.

With a stream, additionally: three attempts with backoff, each carrying the same `Nats-Msg-Id`,
so an ack lost on the way back cannot become two events. Acked and retried — and still not a
ledger you can prove complete; the stream is what makes it one, and a dropped or failed event is
always in the log.

With no stream there is nothing to retry against and nothing to deduplicate: a core publish
either enters the connection's buffer or the connection is gone, and unlike a missing ack that
outcome is unambiguous. One attempt, and an error in the log if the connection refused it.

A **denied** publish is not an error the publisher sees, in either mode: the server drops the
message and reports it out of band. That is why the service installs an asynchronous error
handler on this connection, and why the log is where you find it.

## What is checked before it serves

At startup, and again by [`auth-callout verify`](install.md#verifying):

- the subject pattern expands, and is a literal subject;
- the events credential connects;
- with a stream: it exists, and **it actually captures that subject.**

That last one is the check worth having. A stream whose subject filter does not match reports
nothing at runtime: the publish is accepted, no permissions error is raised, and the events
accumulate nowhere. Both the service and `verify` refuse to proceed.

```
PASS  events connection
      connected to nats://127.0.0.1:4222 (server "nats-1")
PASS  events stream
      AUTH_EVENTS captures prod.events.auth
```

Core delivery has nothing to check, so `verify` states the consequence instead — at WARN, for the
same reason a missing XKey warns: it is weaker than the alternative and invisible once the service
is running.

```
WARN  events delivery
      no stream: prod.events.auth is published as a plain core message, so only a consumer
      subscribed at that instant receives it — nothing is stored, acked or retried
```

## When something is wrong

| Symptom | Cause |
|---|---|
| Startup fails: *the stream does not capture* | the stream's subject filter and `events.subject` disagree |
| Startup fails: *JetStream did not answer about the stream* | the stream does not exist, or the credential lacks `$JS.API.STREAM.INFO.<stream>` — a denied request gets no responder, not a refusal |
| Startup fails on the events connection | that credential belongs to the account the **consumers** live in, not the callout's AUTH account. In config mode, check `allowed_accounts` |
| Events have empty `name` and `email` | the access token does not carry them. Set `CALLOUT_IDP_ENRICH=profile` |
| No events, and the log says *permissions violation for publish* | the credential is missing publish on the subject. A denied publish is asynchronous, which is why this is logged rather than returned |
| No events and nothing in the log | the publisher is off: `events.subject` is unset |
| Events arrive live but the stream is empty | there is no stream: `events.stream` is unset, so delivery is core. The startup line says `delivery=core` |
| A consumer that restarts misses logins | same: core delivery keeps no history. Configure a stream |
| A consumer sees nothing, but the stream fills | the consumer's template does not grant `sub` on the subject |

## The trade-offs, stated plainly

- **It is personal data on a bus.** Name and email travel in the payload, unencrypted (the
  callout request is XKey-encrypted; this is an ordinary message). The control is the subject
  permission, and it is granted per role.
- **It is a second connection and a second credential** to deploy and rotate.
- **It publishes on every authentication**, including a backend's reconnections. With a stream,
  retention is yours to size; without one, there is nothing to size and nothing to look back at.
