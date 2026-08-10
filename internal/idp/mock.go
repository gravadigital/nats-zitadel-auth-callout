package idp

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// mockTokenPrefix marks the tokens the fake IdP accepts.
const mockTokenPrefix = "mock:"

// mockTokenTTL is the lifetime attributed to a mock token.
const mockTokenTTL = time.Hour

// Mock is an in-process Verifier for development and CI. It decodes the identity from the
// token text instead of verifying a signature, so the whole stack (NATS + callout +
// clients) can be brought up and exercised without secrets or network access.
//
// The token format is:
//
//	mock:<sub>:<username>:<role1,role2,...>
//
// Examples:
//
//	mock:u-ana:ana@grava.io:admin
//	mock:svc-api:api:svc-api
//
// NEVER use in production: it accepts any identity written into it. The binary only
// instantiates it with CALLOUT_IDP_MODE=mock and logs the mode at startup, so a
// misconfigured deploy is visible on the log's first line.
type Mock struct{}

// NewMock builds the fake IdP.
func NewMock() *Mock { return &Mock{} }

// VerifyToken parses a mock token.
func (m *Mock) VerifyToken(_ context.Context, token string) (*Claims, error) {
	if !strings.HasPrefix(token, mockTokenPrefix) {
		return nil, fmt.Errorf("%w: a mock token has to start with %q", ErrInvalidToken, mockTokenPrefix)
	}

	// SplitN with 3 keeps the roles whole in the last field, even if they contain commas.
	parts := strings.SplitN(strings.TrimPrefix(token, mockTokenPrefix), ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected mock format mock:<sub>:<username>:<roles>", ErrInvalidToken)
	}

	subject := strings.TrimSpace(parts[0])
	if subject == "" {
		return nil, ErrNoSubject
	}

	var roles []string
	for _, role := range strings.Split(parts[2], ",") {
		if trimmed := strings.TrimSpace(role); trimmed != "" {
			roles = append(roles, trimmed)
		}
	}

	return &Claims{
		Subject:   subject,
		Username:  strings.TrimSpace(parts[1]),
		Roles:     roles,
		ExpiresAt: time.Now().Add(mockTokenTTL),
	}, nil
}

// Compile-time check.
var _ Verifier = (*Mock)(nil)
