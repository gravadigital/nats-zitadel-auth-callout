// Package events publishes one event per connection the callout authenticates.
//
// It is the service's second responsibility, and a deliberately subordinate one: the callout
// authenticates connections, and this only tells the bus about it. Two rules follow from that
// ordering and shape everything here:
//
//   - The authentication path never waits for an event. The publish happens after the
//     authorization_response is already on its way, from another goroutine, so a slow or
//     broken JetStream cannot add a millisecond to a handshake or turn a valid connection
//     into a rejected one.
//   - The event is never inferred from anything the callout did not already vouch for. Every
//     field comes from the verified token or from the routing decision the callout made; there
//     is no enrichment, no second lookup and no defaulting of an identity value.
//
// The event is opt-in: with no subject configured, nothing in this package runs.
package events

import (
	"time"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/idp"
)

// Type is the event's kind. It travels in the payload rather than only in the subject so a
// consumer reading a single message can tell what it is holding, and so that a second kind
// (a rejection, say) can be added without every deployment having to re-cut its subjects.
const TypeAuthenticated = "authenticated"

// SchemaVersion is the payload's version. It is part of the published contract: a change that
// would break a consumer parsing the current shape bumps it.
const SchemaVersion = 1

// Authentication is everything the callout knows about a connection it has just authenticated.
// It is the input to the publisher; the Event is what goes on the wire.
type Authentication struct {
	// Identity is the resolved identity the User JWT was minted for.
	Identity authz.Identity
	// Claims are the verified token claims. Name and email are read from them by claim path.
	Claims *idp.Claims
	// Decision is why this connection got these permissions: the winning rule, the template
	// and the identity model.
	Decision authz.Decision
	// ClientIP is the connecting client's host, as the server reported it.
	ClientIP string
	// Session is the client's user nkey — the public key the server generated for THIS
	// connection. It is the only value that identifies one connection rather than one user, so
	// it is both the event's session id and its deduplication key.
	Session string
	// At is when the connection was authenticated.
	At time.Time
	// ExpiresAt is when the minted session expires. It is the same instant that went into the
	// User JWT, so a consumer can tell how long this session may live without knowing how the
	// callout derives it.
	ExpiresAt time.Time
}

// Event is the published payload.
//
// The field names are a PUBLIC CONTRACT: consumers parse them, and they are the reason
// SchemaVersion exists. Renaming one is a breaking change even though nothing in this
// repository would fail to compile.
type Event struct {
	// Type is the kind of event. Always TypeAuthenticated today.
	Type string `json:"type"`
	// Version is SchemaVersion.
	Version int `json:"version"`

	// ID is the identity provider's subject claim: the Zitadel userId. It is the field to join
	// on, and the same value the subject grammar uses as {{user_id}}.
	ID string `json:"id"`
	// Name is the human-readable name, read from the configured name claim. It falls back to
	// the username when the token carries no name claim, because a name field that is empty
	// while a perfectly good username exists helps nobody.
	Name string `json:"name,omitempty"`
	// Username is the token's username claim (`preferred_username` by default), the same value
	// that goes into the User JWT's Name and shows up in `nats server report connections`.
	Username string `json:"username,omitempty"`
	// Email is read from the configured email claim. It is EMPTY for a machine user, and for a
	// person whose token was issued without the `email` scope; that is expected rather than an
	// error, because an informational event must not be able to refuse a connection.
	Email string `json:"email,omitempty"`
	// Roles are the token's roles, exactly as they were routed on. Never null: a consumer
	// should not have to distinguish "no roles" from "field missing".
	Roles []string `json:"roles"`

	// AuthenticatedAt is when the callout authenticated the connection.
	AuthenticatedAt time.Time `json:"authenticated_at"`
	// ExpiresAt is when the minted session expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Instance is the deployment instance the connection landed in.
	Instance string `json:"instance,omitempty"`
	// IdentityType is the identity MODEL that was applied — person or service — which is not
	// the class of user in the identity provider: a machine user matching a `type: person`
	// rule reports person, and that is correct.
	IdentityType string `json:"identity_type"`
	// MatchedRole is the winning rule's `match`: the role that decided the permissions, or "*"
	// for the catch-all. With a token carrying several roles it is the only way to know which
	// one applied.
	MatchedRole string `json:"matched_role"`
	// Template is the permission template that was expanded, as the rule declares it
	// (`templates/person.yaml`). It is deliberately NOT the resolved filesystem path: that would
	// publish where this deployment happens to mount its configuration, and would read
	// differently from a container than from a laptop for no gain to any consumer.
	Template string `json:"template"`
	// ClientIP is the connecting client's host.
	ClientIP string `json:"client_ip,omitempty"`
	// Session identifies THIS connection (the user nkey), for correlating with
	// `nats server report connections` and with the callout's own log line.
	Session string `json:"session"`
}

// newEvent assembles the payload.
//
// nameClaim and emailClaim are claim PATHS, read the same way declared placeholders are read,
// so a deployment whose provider puts them elsewhere configures a path instead of needing code.
func newEvent(in Authentication, nameClaim, emailClaim string) Event {
	event := Event{
		Type:            TypeAuthenticated,
		Version:         SchemaVersion,
		ID:              in.Identity.UserID,
		Username:        in.Identity.Username,
		Roles:           []string{},
		AuthenticatedAt: in.At.UTC(),
		ExpiresAt:       in.ExpiresAt.UTC(),
		Instance:        in.Identity.Instance,
		IdentityType:    string(in.Decision.IdentityModel),
		MatchedRole:     in.Decision.Rule,
		Template:        in.Decision.TemplateRef,
		ClientIP:        in.ClientIP,
		Session:         in.Session,
	}
	if in.Claims != nil && len(in.Claims.Roles) > 0 {
		// Copied rather than aliased: the claims outlive this call and the event travels to
		// another goroutine.
		event.Roles = append(event.Roles, in.Claims.Roles...)
	}
	// Three sources, in order of how specific they are to this deployment:
	//
	//  1. the configured claim path, for a provider that puts the value somewhere non-standard;
	//  2. the normalized claim, which the verifier read from the token's standard claim or
	//     filled from userinfo (see CALLOUT_IDP_ENRICH);
	//  3. for the name only, the username — a name field left empty while a perfectly good
	//     username exists helps nobody.
	if in.Claims != nil {
		if name, ok := in.Claims.ClaimString(nameClaim); ok {
			event.Name = name
		}
		if event.Name == "" {
			event.Name = in.Claims.Name
		}
		if email, ok := in.Claims.ClaimString(emailClaim); ok {
			event.Email = email
		}
		if event.Email == "" {
			event.Email = in.Claims.Email
		}
	}
	if event.Name == "" {
		event.Name = in.Identity.Username
	}
	return event
}
