# Roadmap to publishing

Working document. It tracks what is done and what is left before this repository is published,
so the state survives between sessions.

Last reviewed: 2026-08-11, against the working tree — not from memory.

**Decided and not up for re-discussion:**

- The repository keeps the name `nats-zitadel-auth-callout`, under the `gravadigital`
  organisation. Zitadel stays the headline provider even though a generic `oidc` mode exists.
- No multi-account support (`account:` per rule). It would only work in config mode — operator
  mode needs one signing key per target account — and both modes must behave the same.
- `NOTICE` keeps the copyright. Publishing does not give up authorship.

---

## Where things stand

| Theme | State |
|---|---|
| 1. Examples | **done** — `examples/`, split by server mode |
| 2. Identity provider | **mostly done** — one small item left |
| 3. Configuration model | **not started, needs discussion** |
| 4. Adopting an existing NATS | **done** |
| 5. CI/CD and publishing | **not started** — the biggest remaining block |
| 6. Removing internal references | **done** |
| 7. Code findings | **partly done** — the rest are small, individually |

---

## Blocking publication

Ordered by what would hurt most if it shipped without them.

### 5. CI/CD and publishing

Decided: GitHub Actions + Docker Hub. Nothing built yet — there is no `.github/` at all.

- [ ] **CI workflow**: `fmt-check`, `vet`, `test` on pull requests. `make ci` already runs
      exactly this, so the workflow is thin. The test suite stands up real `nats-server`
      instances in-process, which needs no extra services but does take ~15s.
- [ ] **Release workflow**: build and push the image on a tag.
- [ ] **Versioning**: no tags, no `CHANGELOG.md`. Nobody can depend on this without them.
- [ ] **Decide the image name** and who owns the Docker Hub namespace.

### OSS repository basics

None of these exist, and the first one matters more than the rest for a component that decides
who gets into a message bus.

- [ ] **`SECURITY.md`** — how to report a vulnerability privately.
- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates.
- [ ] **`docker-compose.yml`** — the shortest path from clone to something running. Today
      `make run` needs Go, `nsc` and `nats-server` installed locally.

### README

- [ ] It is **638 lines** and still opens §9 with *"Proof of concept working"*, and the licence
      section calls the software a proof of concept. Everything it describes is now tested and
      documented; the framing is the last thing that says otherwise.
- [ ] Splitting it is worth considering: the deep material (subject grammar, KV mapping, account
      topology) could live under `docs/`, leaving the README as what-it-is + quickstart +
      pointers.

---

## Worth doing, not blocking

### 3. Configuration model — needs a decision first

Everything is environment variables, and there are now around twenty. The `rules.yaml` +
templates format is liked and is not in question; what is open is whether the **service's own**
configuration should also have a file, with environment variables overriding it.

Arguments to weigh when we get to it:

- a `config.yaml` is what a Helm/Compose deployment expects, and it documents itself;
- environment variables are what containers and secret managers hand you naturally;
- two sources need a precedence rule, and a wrong guess about precedence in an authorization
  component is expensive.

Nothing else depends on this, which is why it has stayed open without cost.

### 2. Identity provider — one item left

- [ ] `fetchUsername` hardcodes `/oidc/v1/userinfo` instead of reading `userinfo_endpoint` from
      the discovery document ([`internal/idp/zitadel.go:349`](../internal/idp/zitadel.go#L349)).
      Same file also has no caching: it is one HTTP call per service-user connection, on the
      connection path.

### 7. Code findings still open

Each is small on its own. Verified as still present on 2026-08-11.

- [ ] **`Router.Resolve` re-finds the template with a linear scan** comparing `templatePath`
      ([`rules.go:569`](../internal/authz/rules.go#L569)) when `Match` already had the
      `resolvedRule`. It works because the pointer is cached, not because of an invariant — two
      rules sharing a template return the first one's.
- [ ] **`availablePlaceholders` hand-rolls an insertion sort**
      ([`template.go:405`](../internal/authz/template.go#L405)) where `sort.Strings` would do.
- [ ] **`maxUserJWTTTL` and `verifyTimeout` are compile-time constants**
      ([`service.go:81`](../internal/callout/service.go#L81)) and should be configurable.
- [ ] **No health/readiness endpoint and no metrics.** The only observability is the log. For
      infrastructure this is close to expected: authenticated connections, rejections by cause,
      verification latency, JWKS failures.

Two findings from the original review are now **done**: `internal/callout` and `internal/config`
have tests (they had none), and token claims are exposed as template placeholders.

---

## Not planned

Recorded so they do not come back as open questions.

- **Multi-account minting** — see the decisions at the top.
- **Config mode for JetStream-less deployments** — no reason to special-case it; KV works the
  same in both modes.
- **Caching verified tokens** — signature verification is local and cheap. The one call worth
  caching is `userinfo`, listed above.

---

## Suggested order

1. `SECURITY.md` and the CI workflow — cheap, and the two things whose absence is most visible
   in a public repository.
2. README framing, then the split if we want it.
3. `docker-compose.yml`.
4. Release workflow, image name, first tag, `CHANGELOG.md`.
5. The configuration model discussion (theme 3).
6. The code findings, in one pass.
