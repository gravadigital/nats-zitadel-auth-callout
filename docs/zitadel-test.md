# Proof of concept: local NATS + production Zitadel (`id.grava.io`)

Runbook for validating the auth callout against real Zitadel. NATS runs locally; the identity
comes from `id.grava.io`.

**What is validated:** that the token's role and the user type change the permissions that get
minted, both for **messages** and for **KV**. The subjects are examples (a `demo` service with
three methods): what is being tested is the mechanism, not any particular domain.

---

## 1. What to create in Zitadel

### 1.1 A project

You can reuse an existing one. Note its **Resource Id** (numeric, e.g. `379892408592106248`):
that is the `CALLOUT_ZITADEL_PROJECT_ID`.

### 1.2 Three roles in that project

*Project → Roles → New.* The **Key** is what travels in the token and what matches
`config/rules.yaml`, so it has to be exact:

| Key | What for |
|---|---|
| `poc-user` | person with scoped permissions |
| `poc-admin` | person with broad permissions |
| `poc-service` | the service user serving `demo` |

### 1.3 Three service users

*Users → Service Users → New*, one per role:

| User Name | Role granted to it |
|---|---|
| `poc_user` | `poc-user` |
| `poc_admin` | `poc-admin` |
| `poc_demo` | `poc-service` |

> **Access Token Type = JWT** on each one. It is a field on the service user's form, and it
> defaults to **Bearer**, which issues an **opaque** token. The callout validates by signature
> (JWKS), so with an opaque token it has nothing to verify and rejects it as invalid. This is
> the easiest mistake to make here; `scripts/token-info.sh` detects it and says so in those
> words.

Using three *machine users* —rather than one human and two services— is deliberate: **the
callout routes only by role**, not by Zitadel's class of user. A machine user with the
`poc-user` role enters through the person path and receives a person identity. That makes it
possible to test all three paths without depending on a browser login. §5 covers how to use a
real human token if you also want to exercise that flow.

### 1.4 Credentials for each service user

Either of the two forms; the script detects it on its own:

- **Client secret** (quicker): *Secrets → Generate Client Secret*. Save a JSON by hand with what
  it shows you:
  ```json
  { "clientId": "...", "clientSecret": "..." }
  ```
- **Key JSON** (the path verified in the PoC): *Keys → New → Type: JSON*. A direct download of
  `{type, keyId, key, userId}`. It needs `openssl`.

### 1.5 The authorizations

*Project → Authorizations* (or *User → Authorizations*): grant each service user **its** role in
the project. Without this the token comes out with no roles and the callout rejects the
connection.

> If the project lives in **another organization** than the users, the role additionally has to
> be enabled in the **project-grant** toward the users' org.

---

## 2. Preparing the environment

```sh
cd nats-zitadel-auth-callout

# The credentials you downloaded from Zitadel (secrets/ is gitignored).
mkdir -p secrets
# -> secrets/poc-user.json  secrets/poc-admin.json  secrets/poc-service.json
```

```sh
# Configure the callout against real Zitadel.
cp -n nats/.env.example nats/.env
cat >> nats/.env <<'EOF'

CALLOUT_IDP_MODE=zitadel
CALLOUT_ZITADEL_ISSUER_URL=https://id.grava.io
CALLOUT_ZITADEL_PROJECT_ID=PUT_THE_PROJECT_ID_HERE
EOF
```

Verify that connectivity with Zitadel works **before** bringing anything up:

```sh
CALLOUT_ZITADEL_ISSUER_URL=https://id.grava.io make test-live
```

It has to say `discovery OK — issuer=https://id.grava.io jwks=https://id.grava.io/oauth/v2/keys`.
(`id.grava.io` is self-hosted and serves the keys at `/oauth/v2/keys`, not at the Zitadel Cloud
path; the callout resolves it through OIDC discovery.)

---

## 3. Bringing up NATS + the callout

```sh
make bootstrap     # generates operator, accounts, sentinels, XKey and the authcallout config
make run           # NATS + callout in the foreground; leave it running
```

The **log's first line has to say `idp=zitadel`**:

```
INF starting nats-zitadel-auth-callout idp=zitadel instance=dev nats=nats://127.0.0.1:4322
```

If it says `idp=mock`, it did not pick up the config. And if you relaunch, **kill the previous
one first**: `make run` only stops the `nats-server` it started itself, so an old callout can
keep serving the subject in its previous mode while the new `nats-server` cannot bind the port.

---

## 4. The tokens

In **another terminal**:

```sh
cd nats-zitadel-auth-callout
export ZITADEL_ISSUER_URL=https://id.grava.io
export ZITADEL_PROJECT_ID=PUT_THE_PROJECT_ID_HERE

T_USER=$(./scripts/zitadel-token.sh secrets/poc-user.json)
T_ADMIN=$(./scripts/zitadel-token.sh secrets/poc-admin.json)
T_DEMO=$(./scripts/zitadel-token.sh secrets/poc-service.json)
```

**Inspect them before touching NATS.** Almost any test failure is explained here:

```sh
./scripts/token-info.sh "$T_USER"
```

It has to say `It is a JWT. ✓` and list the roles claim with `poc-user`. If it does not:

| Symptom | Cause | Fix |
|---|---|---|
| `NOT a JWT` | the service user is on Bearer | Access Token Type = JWT |
| `Role claims present: NONE` | the scope or the grant is missing | see §1.5; the script already sends the scope |
| a role other than the expected one | wrong service user's credential | check which JSON you used |

The identities the callout will derive. They are **two values per user**, and they are not
interchangeable: the **raw user id** builds the subjects, and its **hash** builds the inbox.

```sh
# raw user id -> subjects
S_USER=$(go run ./cmd/session --token "$T_USER"  | awk '/^user-id/{print $2}')
S_ADMIN=$(go run ./cmd/session --token "$T_ADMIN" | awk '/^user-id/{print $2}')

# user id hash -> inbox
H_USER=$(go run ./cmd/session --token "$T_USER"  | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')
H_ADMIN=$(go run ./cmd/session --token "$T_ADMIN" | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')

echo "user=$S_USER ($H_USER)  admin=$S_ADMIN ($H_ADMIN)"
```

The service user `poc_demo` also has its own user id and its inbox also goes by hash — it is a
Zitadel user like any other. What sets it apart is the **endpoint** it serves (`demo`), which
comes from the rule and not from the token:

```sh
S_DEMO=$(go run ./cmd/session --token "$T_DEMO" | awk '/^user-id/{print $2}')
H_DEMO=$(go run ./cmd/session --token "$T_DEMO" | awk '/^inbox/{sub(/^_INBOX\./,"",$2); print $2}')
```

---

## 5. The test

```sh
NATS="nats --server nats://127.0.0.1:4322 --creds nats/out/sentinel-client.creds"
```

> **`--inbox-prefix` is not optional.** The permissions scope the inbox to
> `_INBOX.<hash(user-id)>`; by default the client generates an `_INBOX.<random>` that nobody
> authorizes. Careful: the inbox goes with the **hash**, not with the raw user id the subjects
> carry. In a real app it is set with `nats.CustomInboxPrefix` (Go) or `inboxPrefix` (nats.js).

### 5.1 The `demo` service serves and creates the bucket

Leave it running in a separate terminal — it is what answers the requests. It serves through its
**endpoint** (`demo`), but its inbox goes by the hash of **its** user id:

```sh
$NATS --token "$T_DEMO" --inbox-prefix "_INBOX.$H_DEMO" \
  reply 'dev.*.demo.>' 'reply from demo to {{Subject}}'
```

And in another one, have it create the test bucket (it is the only one with `manage: true`):

```sh
$NATS --token "$T_DEMO" --inbox-prefix "_INBOX.$H_DEMO" kv add poc-kv --history=1
```

### 5.2 Messages: the permissions change by role

```sh
U="$NATS --token $T_USER  --inbox-prefix _INBOX.$H_USER"
A="$NATS --token $T_ADMIN --inbox-prefix _INBOX.$H_ADMIN"
```

| # | Command | Expected |
|---|---|---|
| 1 | `$U request "dev.$S_USER.demo.ping" hello` | **replies** |
| 2 | `$U pub "dev.$S_USER.demo.admin_reset" x` | **Permissions Violation** (admin only) |
| 3 | `$A request "dev.$S_ADMIN.demo.admin_reset" x` | **replies** |
| 4 | `$U pub "dev.$S_ADMIN.demo.ping" x` | **Permissions Violation** (someone else's user id) |
| 5 | `$U pub "prod.$S_USER.demo.ping" x` | **Permissions Violation** (another instance) |
| 6 | `$U sub "dev.*.demo.>"` | **Permissions Violation** (not a service) |

1 and 3 prove that the role widens the surface. 2 is the heart of "per-role permissions": same
service, same client, method denied by the role. 4 is what makes the subject's identity
trustworthy. 6 is that a person cannot impersonate the service.

> **For the cases that must fail, use `pub` and not `request`.** A denied publish is reported
> **asynchronously**: `nats request` sends it, receives no reply and **exits with code 0 printing
> nothing** — it looks like it worked. `nats pub` does show `permissions violation` right away.
> Verified: with `request`, case 2 goes unnoticed; with `pub`, it says
> `Permissions Violation for Publish to "dev.<user-id>.demo.admin_reset"`.
> When in doubt, the source of truth is the `nats-server` log (§6).

### 5.3 KV: the permissions change by role and by user

| # | Command | Expected |
|---|---|---|
| 7 | `$U kv put poc-kv "$S_USER.theme" dark` | **ok** (its own key) |
| 8 | `$U kv get poc-kv "$S_USER.theme"` | **dark** |
| 9 | `$A kv put poc-kv "$S_ADMIN.theme" light` | **ok** |
| 10 | `$U kv get poc-kv "$S_ADMIN.theme"` | **fails** (someone else's key) |
| 11 | `$U kv put poc-kv "$S_ADMIN.theme" hacked` | **fails** (someone else's key) |
| 12 | `$A kv get poc-kv "$S_USER.theme"` | **dark** (the admin reads everything) |
| 13 | `$A kv put poc-kv "$S_USER.theme" imposed` | **fails** (writes only its own) |

10–13 are the point: **the same bucket, with different scopes depending on the role**, and
per-user scoping within the role. The NATS server enforces it, not the application — the scope
goes into the key's subject (`$KV.poc-kv.<user-id>.…`).

### 5.4 Rejections

| # | Command | Expected |
|---|---|---|
| 14 | `$NATS pub "dev.x.demo.ping" x` | **Authorization Violation** (no token) |
| 15 | `$NATS --token "garbage" pub "dev.x.demo.ping" x` | **Authorization Violation** |
| 16 | a token from a user **without** a PoC role | **Authorization Violation** |

For 16, a service user with any other `id.grava.io` role (or with none):
`config/rules.yaml` **has no catch-all**, so there are no default permissions.

---

## 6. If something fails

**A permissions violation on a JetStream subject does not look like one.** The request never
receives a reply and the client reports a timeout (`context deadline exceeded`). The exact
missing subject is in the `nats-server` log:

```sh
# in the `make run` terminal, or:
grep -i violation nats/data/../*.log 2>/dev/null
```

Look for `Publish Violation` / `Subscription Violation` and the subject.

What the **callout's** log says in each case:

| In the log | What it means |
|---|---|
| `authenticated ... template=... pubAllow=N` | all good: it shows which template it picked |
| `token verification failed` | signature, issuer or lifetime. Run `token-info.sh` |
| `could not resolve permissions ... roles=[]` | the token carries no roles (§1.5) |
| `could not resolve permissions ... roles=[other]` | the role is not in `rules.yaml` |

Turn up the detail with `CALLOUT_LOG_LEVEL=debug` in `nats/.env`.

---

## 7. After the test

```sh
make clean            # binaries and JetStream data
make clean-identity   # plus the NATS identity (forces reissuing the creds)
```

In Zitadel you can leave the three roles and the three service users: they are for testing and
they touch nothing else. If the project is shared, delete them so no stray roles are left
behind.
