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
//	mock:<sub>:<username>:<role1,role2,...>[:<claim=value,claim=value>]
//
// The fourth field is optional and populates Claims.Raw, so a rules.yaml declaring
// deployment-defined placeholders can be exercised with no real IdP.
//
// Examples:
//
//	mock:u-ana:ana@example.com:admin
//	mock:svc-api:api:svc-api
//	mock:u-ana:ana@example.com:admin:tenant_id=acme,region=eu
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

	// SplitN with 4 keeps the roles whole in the third field and leaves an OPTIONAL fourth for
	// extra claims. Existing three-field tokens keep working unchanged: with no fourth colon
	// the split simply yields three parts.
	parts := strings.SplitN(strings.TrimPrefix(token, mockTokenPrefix), ":", 4)
	if len(parts) < 3 {
		return nil, fmt.Errorf("%w: expected mock format mock:<sub>:<username>:<roles>[:<k=v,k=v>]", ErrInvalidToken)
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
		// The mock exposes the identity it decoded as claims too, so a rules.yaml declaring
		// placeholders can be exercised without a real IdP. `extra` is a convenience for tests:
		// mock:<sub>:<username>:<roles>:<k=v,k=v>
		Raw: mockRawClaims(subject, parts),
	}, nil
}

// mockRawClaims builds the claim map a mock token exposes. The optional fifth field carries
// arbitrary `key=value` pairs so declared placeholders can be driven from a token string.
func mockRawClaims(subject string, parts []string) map[string]any {
	raw := map[string]any{"sub": subject}
	if len(parts) < 4 {
		return raw
	}
	for _, pair := range strings.Split(parts[3], ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		if key = strings.TrimSpace(key); key != "" {
			raw[key] = strings.TrimSpace(value)
		}
	}
	return raw
}

// Compile-time check.
var _ Verifier = (*Mock)(nil)
