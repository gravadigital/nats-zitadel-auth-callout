package authz

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Identity is a connection's already-resolved identity: what templates expand against.
//
// It is deliberately small: a template needs to know which instance it is in and who the
// caller is, plus whatever the deployment declares from token claims. Everything else about
// the connection — what it is allowed to serve, and under which subjects — is the template's
// call, written as literal subjects.
type Identity struct {
	// Instance is the deployment instance (dev/stage/prod). It is the first token of every
	// subject: it isolates deployments that share a single NATS.
	Instance string
	// UserID identifies the caller within the instance: it is the token's `sub`, the
	// Zitadel userId, verbatim. It applies equally to people and to machine users, because
	// both are Zitadel users.
	//
	// It goes into the subject RAW, on purpose: that is what makes a subject readable and
	// what lets a service learn who called it by reading the subject (vouched for by the
	// callout) instead of the message body. The trade-off is that the Zitadel userId is
	// visible in subjects, logs and traces.
	UserID string
	// Username is the human-readable name from the token, if one came through. It goes
	// into the User JWT's Name field, which is what shows up in
	// `nats server report connections`.
	Username string

	// Extra holds deployment-defined placeholders, read from token claims as declared in
	// rules.yaml (`placeholders:`).
	//
	// This is what lets the service adopt a subject grammar it did not design. The built-in
	// placeholders only describe the authenticated identity; a deployment's grammar may be
	// tenant-first, region-scoped or something else entirely, and no fixed set of built-ins
	// covers that. Claims are the only place such a value can come from and still be vouched
	// for by the IdP.
	//
	// A built-in name cannot be overridden: allowing `user_id` to be redefined from an
	// arbitrary claim would let a template mint permissions for a different identity than the
	// one that authenticated.
	Extra map[string]string

	// InboxMode selects how InboxPrefix and {{user_id_hash}} behave. Empty means hashed.
	InboxMode InboxMode
}

// InboxMode selects how a connection's private inbox is derived.
type InboxMode string

const (
	// InboxHashed scopes the inbox to `_INBOX.<hash(user-id)>`, isolating replies per user at
	// the cost of every client having to set that prefix.
	InboxHashed InboxMode = "hashed"
	// InboxPassthrough leaves the inbox alone, for an existing NATS whose clients cannot be
	// changed. The template then has to grant a broader inbox, which is less isolated.
	InboxPassthrough InboxMode = "passthrough"
)

// builtinPlaceholders are the names a deployment may not redefine, because each is derived
// from the authenticated identity rather than from arbitrary token content.
var builtinPlaceholders = map[string]struct{}{
	"instance":     {},
	"user_id":      {},
	"user_id_hash": {},
}

// IsBuiltinPlaceholder reports whether name is reserved.
func IsBuiltinPlaceholder(name string) bool {
	_, ok := builtinPlaceholders[name]
	return ok
}

// placeholders exposes the identity as the map templates consume.
//
// `user_id_hash` is exposed pre-computed so a template can write the inbox as
// `_INBOX.{{user_id_hash}}.>` without knowing how it is derived.
func (id Identity) placeholders() map[string]string {
	vars := map[string]string{
		"instance": id.Instance,
		"user_id":  id.UserID,
	}
	// In passthrough mode there is no per-user inbox, so `user_id_hash` is deliberately NOT
	// exposed: a template minting `_INBOX.{{user_id_hash}}.>` would grant a permission for an
	// inbox no client ever uses, and the symptom — replies never arriving — says nothing about
	// the cause. Leaving it undefined turns that into an ErrUnknownPlaceholder at startup.
	if id.InboxMode != InboxPassthrough {
		vars["user_id_hash"] = HashUserID(id.UserID)
	}
	// Deployment-defined placeholders are added second but cannot shadow a built-in: the
	// loader rejects those names, so this loop only ever adds new keys.
	for name, value := range id.Extra {
		if IsBuiltinPlaceholder(name) {
			continue
		}
		vars[name] = value
	}
	return vars
}

// InboxPrefix is the private inbox prefix belonging to this identity:
// `_INBOX.<hash(user-id)>`.
//
// The client MUST set this prefix when connecting (`nats.CustomInboxPrefix` in Go,
// `inboxPrefix` in nats.js). Without it the library generates a random `_INBOX.<nuid>`,
// which no scoped permission authorizes — and the only alternative would be granting
// `_INBOX.>`, which would let any client in the account read everyone else's replies.
//
// That is why the hash is deterministic: the client recomputes it from its own token, with
// no side channel. Each connection adds its own unique token under the prefix, so two
// connections from the same user do not cross.
// In passthrough mode there is no per-user prefix: the standard `_INBOX` is returned and the
// template is responsible for granting whatever inbox its clients actually use.
func (id Identity) InboxPrefix() string {
	if id.InboxMode == InboxPassthrough {
		return "_INBOX"
	}
	return "_INBOX." + HashUserID(id.UserID)
}

// userIDHashEncoding produces hashes that are short and safe for a NATS subject: base32
// without padding, lowercased, free of `.`, `*` and `>`.
var userIDHashEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// userIDHashLen is the hash length. 16 base32 characters are 80 bits of sha256: far more
// than enough to avoid collisions between users, and short enough to read in logs.
const userIDHashLen = 16

// HashUserID derives the user id hash used as the inbox prefix.
//
// It is deterministic on purpose (same user -> same inbox), because the client has to be
// able to reconstruct its prefix on its own. It does not distinguish connections of the
// same user; it does not need to, because the isolation being sought is between users.
//
// A note on what this protects and what it does not: the user id travels raw in messaging
// subjects, so this hash hides nobody's identity — whoever sees a subject has already seen
// the user id. It exists because the inbox needs ONE opaque, fixed-length token, not
// because it is a secret.
func HashUserID(userID string) string {
	sum := sha256.Sum256([]byte(userID))
	return strings.ToLower(userIDHashEncoding.EncodeToString(sum[:])[:userIDHashLen])
}
