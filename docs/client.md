# Connecting a client

Three things, and only the third is unusual:

1. connect with the **sentinel credentials** — the same for every client, and they authorize
   nothing on their own;
2. pass the **access token** in the CONNECT frame — that is the identity;
3. set the **inbox prefix**, derived from the token's own `sub`.

A runnable reference lives in [examples/client/main.go](../examples/client/main.go):

```sh
go run ./examples/client \
  --url nats://127.0.0.1:4222 \
  --creds sentinel-client.creds \
  --token "$ACCESS_TOKEN" \
  --subject "dev.<user-id>.demo.ping"
```

---

## The credentials are not the identity

Every client connects with the **same** sentinel credential. It is denied every permission of its
own and is safe to distribute: it exists so the server hands the connection to the callout rather
than authorizing it directly.

The identity is the **access token**. The callout verifies it, reads its roles, and mints the
permissions this connection gets. Two clients using the same credentials file get completely
different permissions, because they present different tokens.

## The inbox prefix is not optional

This is where most integrations lose an afternoon, because the failure says nothing: requests are
delivered, the service replies, and **the reply never arrives**.

With `CALLOUT_INBOX_MODE=hashed` (the default) each identity's replies are scoped to
`_INBOX.<hash(user-id)>`. By default a NATS client generates a random `_INBOX.<nuid>`, which no
permission authorizes, so the subscription is denied — asynchronously, after the call that
created it already returned.

The hash is derived from the token's own `sub`, with no side channel, so any client can compute
it: **sha256 → base32 without padding → lowercase → first 16 characters**.

```sh
go run ./cmd/session <sub>     # the reference implementation
```

Treat that command as the source of truth when porting the derivation: a prefix that differs by
one character behaves exactly like no prefix at all.

If your clients cannot be changed, `CALLOUT_INBOX_MODE=passthrough` removes the requirement, at
the cost of per-user reply isolation — any client in the account can then subscribe to another's
replies, so the templates must grant the inbox their clients actually use.

## Go

```go
import "github.com/nats-io/nats.go"

nc, err := nats.Connect(url,
    nats.UserCredentials("sentinel-client.creds"), // same for every client; grants nothing
    nats.Token(accessToken),                       // the identity
    nats.CustomInboxPrefix("_INBOX."+hash),        // hash = sha256/base32/lower[:16] of the sub
)
```

## JavaScript (nats.js)

```js
import { connect, credsAuthenticator } from "nats";
import { createHash } from "node:crypto";
import { base32 } from "rfc4648"; // or any base32 encoder

// Same derivation as the Go reference: sha256 -> base32, no padding -> lowercase -> 16 chars.
const hash = base32
  .stringify(createHash("sha256").update(sub).digest(), { pad: false })
  .toLowerCase()
  .slice(0, 16);

const nc = await connect({
  servers: url,
  authenticator: credsAuthenticator(new TextEncoder().encode(credsFileContents)),
  token: accessToken,
  inboxPrefix: `_INBOX.${hash}`,
});
```

## What a client may publish

The subject grammar in the shipped example puts the caller's user id in the subject:

```
<instance>.<user-id>.<service>.<method>
```

A client may only publish under **its own** user id — the permission fixes it, not the
application. That is what lets a service trust the caller identity it reads off the subject
instead of off the message body. Publishing under someone else's id is denied.

Your deployment's grammar may differ; see the README on declaring extra placeholders.

## Services

A service subscribes with the caller as a wildcard and replies through `allow_responses`, so it
needs no publish permission toward any client's inbox:

```go
nc.QueueSubscribe("dev.*.demo.>", "demo", func(m *nats.Msg) {
    // The caller's user id is subject token 2, vouched for by the callout.
    m.Respond([]byte("pong"))
})
```

Replicas of a service share the endpoint name — that is what makes queue-group balancing work —
while each connects with its own user, so their inboxes stay separate.

## When it does not work

See [troubleshooting.md](troubleshooting.md). The two most common:

- **replies never arrive** → the inbox prefix;
- **`request` returns nothing and exits 0** → a denied publish, reported asynchronously. Test
  with `pub` when you expect a denial, and read the `nats-server` log.
