// Package idp verifies the access token a client presents when connecting and extracts from
// it the only things the callout needs: who it is (sub), what it is called, when it expires
// and which roles it has.
//
// The callout does NOT issue tokens and does not speak the OIDC flow: that already happened
// between the client and Zitadel. Here an already-issued token is only validated.
package idp

import (
	"context"
	"errors"
	"time"
)

// Verification errors. The callout translates them into an AuthorizationResponse carrying an
// error; the client sees an authorization failure when connecting.
var (
	// ErrInvalidToken means a token that does not verify (signature, format, issuer, audience).
	ErrInvalidToken = errors.New("idp: invalid token")
	// ErrExpiredToken means a well-formed but expired token.
	ErrExpiredToken = errors.New("idp: expired token")
	// ErrNoSubject means a token with no `sub`. Without a sub there is no identity to derive.
	ErrNoSubject = errors.New("idp: the token carries no `sub`")
)

// Claims is what the callout extracts from the token, already normalized.
type Claims struct {
	// Subject is the `sub`: the Zitadel userId. It identifies the user or the service user.
	Subject string
	// Username is the human-readable name (`preferred_username`, or whatever userinfo
	// returns). It may be empty: machine user tokens often do not carry it.
	Username string
	// Roles are the token's project roles, already flattened into a list of names.
	Roles []string
	// ExpiresAt is the `exp`. It bounds the lifetime of the User JWT the callout mints, so
	// that the NATS session does not outlive the token that authorized it.
	ExpiresAt time.Time
}

// Verifier verifies an access token. It is an interface so the callout does not depend on
// Zitadel: tests and CI use a fake implementation (see Mock) without standing up an IdP.
type Verifier interface {
	// VerifyToken validates the token and returns its normalized claims.
	VerifyToken(ctx context.Context, token string) (*Claims, error)
}
