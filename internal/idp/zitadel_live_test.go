//go:build live

// Tests against a REAL Zitadel instance. They sit behind the `live` build tag because they
// need network access and a reachable instance: they do not run under `go test ./...`.
//
//	CALLOUT_ZITADEL_ISSUER_URL=https://id.example.com go test -tags live -v ./internal/idp/
//
// With a token at hand, the full validation path is verified as well:
//
//	CALLOUT_ZITADEL_ISSUER_URL=https://id.example.com \
//	CALLOUT_TEST_TOKEN="$(./scripts/zitadel-token.sh secrets/poc-service.json)" \
//	  go test -tags live -v ./internal/idp/
package idp

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// issuerFromEnv returns the issuer to test against, or skips the test if it is not configured.
func issuerFromEnv(t *testing.T) string {
	t.Helper()
	issuer := os.Getenv("CALLOUT_ZITADEL_ISSUER_URL")
	if issuer == "" {
		t.Skip("CALLOUT_ZITADEL_ISSUER_URL is not set")
	}
	return issuer
}

// Verifies what used to break in the PoC: that the JWKS resolves through OIDC discovery. A
// self-hosted instance serves it at /oauth/v2/keys, not at /.well-known/jwks.json.
func TestLiveDiscoveryResolvesJWKS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	verifier, err := NewZitadel(ctx, issuerFromEnv(t))
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}
	t.Logf("discovery OK — issuer=%s jwks=%s", verifier.issuer, verifier.jwksURL)

	// A malformed token has to yield ErrInvalidToken rather than an infrastructure error: that
	// is how "the client sent garbage" is told apart from "Zitadel is not responding".
	if _, err := verifier.VerifyToken(ctx, "not.a.jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

// With a real token, this verifies the full path: signature, issuer, lifetime, and that the
// sub and the roles come out. If this passes, the callout will be able to authenticate that
// token.
func TestLiveVerifyToken(t *testing.T) {
	token := os.Getenv("CALLOUT_TEST_TOKEN")
	if token == "" {
		t.Skip("CALLOUT_TEST_TOKEN is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	verifier, err := NewZitadel(ctx, issuerFromEnv(t),
		WithProjectID(os.Getenv("CALLOUT_ZITADEL_PROJECT_ID")),
	)
	if err != nil {
		t.Fatalf("NewZitadel: %v", err)
	}

	claims, err := verifier.VerifyToken(ctx, token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	t.Logf("sub=%s username=%q roles=%v expires=%s",
		claims.Subject, claims.Username, claims.Roles, claims.ExpiresAt.Format(time.RFC3339))

	if claims.Subject == "" {
		t.Fatal("the token carries no sub")
	}
	// With no roles the callout cannot match any rule, so this is the failure most worth
	// catching here rather than in the NATS handshake.
	if len(claims.Roles) == 0 {
		t.Fatal("the token carries no roles: the urn:zitadel:iam:org:projects:roles scope is " +
			"missing, or the role is not granted to the user in the project")
	}
}
