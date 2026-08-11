// Package idp verifies the access token a client presents when connecting and extracts from
// it the only things the callout needs: who it is (sub), what it is called, when it expires
// and which roles it has.
//
// The callout does NOT issue tokens and does not speak the OIDC flow: that already happened
// between the client and Zitadel. Here an already-issued token is only validated.
package idp

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
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

	// Raw exposes the token's claims for reading deployment-declared placeholders (see
	// rules.yaml `placeholders:`). It is only read through ClaimString, by claim path.
	//
	// It is deliberately NOT used for anything authorization-relevant on its own: roles,
	// subject and expiry are normalized above precisely so the routing logic never reaches
	// into raw token content.
	Raw map[string]any
}

// ClaimString reads a claim by dot-separated path and returns it as a string.
//
// Only scalars are accepted: a placeholder becomes a NATS subject token, and a subject token
// cannot be an object or a list. Numbers and booleans are rendered because a tenant or
// organisation id arriving as a JSON number is common enough to be worth handling rather than
// rejecting.
func (c *Claims) ClaimString(path string) (string, bool) {
	if c == nil || len(c.Raw) == 0 || path == "" {
		return "", false
	}

	var current any = c.Raw
	for _, segment := range strings.Split(path, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = obj[segment]
		if !ok {
			return "", false
		}
	}

	switch value := current.(type) {
	case string:
		return value, value != ""
	case bool:
		return strconv.FormatBool(value), true
	case float64:
		// JSON numbers decode as float64. Integers are rendered without a decimal point so an
		// id reads as `42`, not `42.000000`.
		if value == math.Trunc(value) && math.Abs(value) < 1e15 {
			return strconv.FormatInt(int64(value), 10), true
		}
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case json.Number:
		return value.String(), value.String() != ""
	default:
		// Objects, arrays and null cannot be subject tokens.
		return "", false
	}
}

// Verifier verifies an access token. It is an interface so the callout does not depend on
// Zitadel: tests and CI use a fake implementation (see Mock) without standing up an IdP.
type Verifier interface {
	// VerifyToken validates the token and returns its normalized claims.
	VerifyToken(ctx context.Context, token string) (*Claims, error)
}
