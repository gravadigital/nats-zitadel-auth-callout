# CLAUDE.md

Instructions for agents working in this repository.

---

## Cutting a release

**Triggers:** "versiona", "versionar", "cortá una release", "nueva versión", "bump de versión",
"release", "cut a release", "new version", "version bump", or any variant in either language.
When one appears, follow this procedure in full and in order.

### What holds the version number

**Nothing in the tree does.** There is no `VERSION` file and no manifest to edit: the number comes
from the git tag, injected at build time.

| Where | How |
| --- | --- |
| Local build | `Makefile` runs `git describe --tags --always --dirty` into `-ldflags -X main.version=…` |
| Released image | `release.yml` passes `VERSION=${{ github.ref_name }}` as a build arg |
| At runtime | `auth-callout version`, and the first line of the startup log |

So **the tag is the release**. There is no step that writes the number anywhere, and no
`set-version.sh` to run — the only artefacts this procedure edits are the CHANGELOG and whatever
documentation went stale.

---

### Step 1 — Pick the cut point

`main` is the release branch; work lands through `dev` and reaches `main` by pull request.

```sh
git fetch --all --tags
git describe --tags --abbrev=0                  # last published version
git rev-list --left-right --count main...dev    # is dev ahead?
git rev-list --left-right --count main...origin/main
git status --porcelain                          # must be clean
```

**Do not cut with an open pull request whose changes belong in the release.** Check with
`gh pr list --base dev --state open`. If something relevant is still open, say so and stop — do
not merge it yourself to make the release fit.

If `dev` is ahead of `main`, the cut is `main` and the extra work waits for the next one. **Say
that to the user**; do not resolve it silently.

### Step 2 — Check the tags against the CHANGELOG

A tag can exist without a CHANGELOG section — it happened with `v0.2.0`. Before adding anything,
confirm every published tag is documented:

```sh
git tag -l
git ls-remote --tags origin          # what is actually published
grep '^## \[' CHANGELOG.md
```

A tag that is published but undocumented gets its section written **retroactively**, with the
tag's real date (`git log -1 --format=%ci <tag>`), before the new entry goes above it. **Never
move or delete a tag that is already on the remote**: its image is on Docker Hub and someone may
be running it.

### Step 3 — Gather the actual changes

The entry has to cover everything that landed since the last tag. Commit subjects are not enough;
this repository puts the reasoning in the bodies.

```sh
git log v<last>..HEAD --oneline
git log v<last>..HEAD --format='%h%n%B'      # the bodies explain the why
git diff --stat v<last>..HEAD
```

Then review the diffs that produce entries nobody wrote down, because each one is a contract
somebody depends on:

```sh
git diff v<last>..HEAD -- internal/config/            # CALLOUT_* variables
git diff v<last>..HEAD -- internal/authz/rules.go     # the rules.yaml schema
git diff v<last>..HEAD -- internal/authz/identity.go  # built-in placeholders
git diff v<last>..HEAD -- internal/events/event.go    # the event payload and SchemaVersion
git diff v<last>..HEAD -- examples/                   # the shipped configuration
git diff v<last>..HEAD --diff-filter=D --name-only    # what was deleted
```

> **Every entry has to be verifiable in the tree being tagged.** If you cut from `main`, something
> that exists only on `dev` does not go in. Check with `git branch --contains <sha>`.

### Step 4 — Propose the number and WAIT

Since 1.0 this project follows semver strictly. What counts as a public contract:

- the `rules.yaml` schema and the template schema
- the built-in placeholders and the subject grammar
- the authentication event payload and its `SchemaVersion`
- the `CALLOUT_*` variables and the `callout.yaml` keys
- the CLI (`auth-callout verify`, `version`) and the image's tag policy

| Bump | When |
| --- | --- |
| **major** | Any of the above breaks: a removed or renamed key, a placeholder that no longer expands, a payload field that disappears, a variable that stops being read |
| **minor** | New functionality that leaves every one of them working — a new optional key, a new placeholder, an added payload field |
| **patch** | Bugs, docs, internals. Nothing an existing deployment has to react to |

The question that decides it: **does an existing installation have to change a file, a variable or
a consumer to keep working?** If yes it is a major, however small the diff. A deprecation ships as
a minor — the old form keeps working and warns — and the removal waits for the next major.

Present the proposed number, the reasoning, and the list of breaking changes found. **Do not
write the CHANGELOG or tag anything without explicit confirmation.** If the user corrects the
number, take it: state any disagreement in one line, keep the breaking changes prominent at the
top of the entry, and move on.

### Step 5 — Write the CHANGELOG entry

In [CHANGELOG.md](CHANGELOG.md), above the previous entry:

- Heading `## [X.Y.Z] - YYYY-MM-DD` with **today's real date** (`date +%F`).
- Leave `## [Unreleased]` in place and empty above it.
- Keep a Changelog sections, only those that apply: `Added`, `Changed`, `Deprecated`, `Removed`,
  `Fixed`, `Security`.
- Lead a breaking entry with **`BREAKING:`** in bold and say **what an operator has to do**, not
  just what changed. A migration a reader can follow line by line beats a description.
- In English, like the rest of the file. Bold lead-in on the entries that matter.
- Update the link definitions at the bottom — the `[Unreleased]` compare link moves to the new
  tag, and the new version gets its own line.
- **Never rewrite an entry of an already-published version.**

### Step 6 — Update documentation and examples

**Mandatory, not conditional.** `examples/` is executable configuration that the test suite loads
and validates, and `docs/` is what someone adopting this reads. Both go stale silently.

Walk the list and state explicitly what you reviewed and what you changed:

| What | Review when |
| --- | --- |
| `examples/rules.yaml`, `examples/templates/*.yaml` | the rules schema, a placeholder or the subject grammar changed |
| `examples/*/callout.yaml`, `examples/*/env.example` | any `CALLOUT_*` variable was added, renamed or removed |
| `examples/*/nats-server.conf` | anything about accounts, callout wiring or permissions changed |
| `examples/README.md` | the roles or what they can do changed |
| `docs/configuration.md` | **the one that rots fastest** — every variable, every mode |
| `docs/permissions.md`, `docs/concepts.md` | the rules schema, placeholders, templates |
| `docs/events.md` | the payload, `SchemaVersion`, delivery or subject rules |
| `docs/client.md` | how a client connects, the inbox prefix, the grammar |
| `docs/troubleshooting.md` | a log field, a startup error or a symptom changed |
| `docs/zitadel.md` | roles, token type, or what the IdP has to provide |
| `docs/docker-hub.md` | the image, its tags or what it mounts |
| `README.md` | the feature list, quickstart, or a link that no longer resolves |

Two things to grep for, because they are the usual stragglers:

```sh
grep -rn "<removed field or placeholder>" docs/ examples/ README.md
grep -rn "version.*[0-9]" docs/events.md          # a payload sample with a stale version
```

Then prove the examples still work — the suite validates the shipped configuration against the
code, so a stale example is a test failure, not a documentation nit:

```sh
make ci
```

### Step 7 — Commit

On the cut branch, staging the CHANGELOG and whatever documentation and examples you touched.
Prefer naming the files over `git add -A`.

```sh
git add CHANGELOG.md docs/ examples/ README.md
git status --porcelain              # confirm nothing unintended is staged
git commit -m "chore(release): X.Y.Z"
```

Close the message with the usual `Co-Authored-By:` line.

### Step 8 — Tag

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
```

> ### Pushing the tag publishes to Docker Hub
>
> `release.yml` triggers on `push: tags: ["v*"]`: it re-runs `make ci` against the tagged tree,
> builds the image, pushes `X.Y.Z`, `X.Y` and `latest`, and smoke-tests that the published image
> reports the tag.
>
> **Only push when the user asks for it in that exact exchange.** A standing "versiona" is not a
> push instruction. When they do ask:
>
> ```sh
> git push origin <branch> && git push origin vX.Y.Z
> ```
>
> Push the branch first: a tag pointing at a commit the remote does not have is a broken release.

### Step 9 — Report

- The version tagged, on which branch and commit.
- What was left out and why.
- Which documentation and examples were reviewed, and which changed.
- Whether the tag was pushed. If not, the exact command, as information.
- **The Docker Hub overview is maintained by hand** from `docs/docker-hub.md` (Docker Hub → the
  repository → General → Add overview). The workflow cannot do it: Docker Hub refuses to edit a
  description with a personal access token. Mention it when `docs/docker-hub.md` changed.
