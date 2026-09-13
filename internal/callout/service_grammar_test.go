package callout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/idp"
)

// This is the end-to-end proof of the reusability goal: a deployment whose subject grammar this
// project did not design — tenant-first, no instance token, unscoped inbox — working against a
// real nats-server with nothing but configuration.

// TestForeignGrammarEndToEnd exercises the whole stack with a foreign grammar:
// `<tenant>.<region>.orders.<user-id>.<method>`, the tenant and region coming from token
// claims, no instance prefix, and the inbox left in passthrough.
func TestForeignGrammarEndToEnd(t *testing.T) {
	dir := t.TempDir()

	template := `
pub:
  allow:
    - "{{tenant}}.{{region}}.orders.{{user_id}}.create"
sub:
  allow:
    - "_INBOX.>"
`
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	rules := `
version: 1
placeholders:
  tenant: tenant_id
  region: region
rules:
  - match: app-user
    template: app.yaml
`
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	// No instance, passthrough inbox: the two things an existing deployment usually cannot
	// change about itself.
	router, err := authz.NewRouterFromFile(rulesPath, "",
		authz.WithInboxMode(authz.InboxPassthrough),
	)
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	fx := startConfigServer(t)

	svc, err := New(Config{
		Conn:          fx.connectHandler(t),
		Verifier:      idp.NewMock(),
		Router:        router,
		Mode:          ModeConfig,
		SigningKey:    fx.issuerKP,
		TargetAccount: testAccountName,
		XKey:          fx.xkey,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("start service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	// The mock token's fourth field carries the claims the placeholders read from.
	nc, err := fx.connectClient("mock:u-ana:ana@example.test:app-user:tenant_id=acme,region=eu")
	if err != nil {
		t.Fatalf("client should have connected: %v", err)
	}
	defer nc.Close()

	violations := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case violations <- err:
		default:
		}
	})

	// The grammar the deployment declared is what the server now enforces.
	if err := nc.Publish("acme.eu.orders.u-ana.create", []byte("order")); err != nil {
		t.Fatalf("allowed publish failed: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	select {
	case err := <-violations:
		t.Fatalf("the allowed subject drew a violation: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	// Another tenant's subject must be refused: the tenant came from a vouched-for claim, so
	// this is the isolation the grammar buys.
	if err := nc.Publish("other.eu.orders.u-ana.create", []byte("nope")); err != nil {
		t.Fatalf("publish call failed: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	select {
	case err := <-violations:
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got: %v", err)
		}
	case <-time.After(waitFor):
		t.Fatal("crossing tenants drew no violation: the declared grammar is not being enforced")
	}
}

// TestForeignGrammarRejectsWildcardClaim is the end-to-end guard against placeholder injection.
//
// The mirror image of TestForeignGrammarEndToEnd: there, a legitimate tenant claim buys
// isolation the server enforces. Here, a token claiming `tenant_id = "*"` tries to switch that
// isolation off by turning its own scoped permission into a wildcard one. It must not connect at
// all — being refused at the handshake is what keeps a cross-tenant JWT from ever being minted.
func TestForeignGrammarRejectsWildcardClaim(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "app.yaml"),
		[]byte("pub:\n  allow:\n    - \"{{tenant}}.orders.{{user_id}}.create\"\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(`
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: app-user
    template: app.yaml
`), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	router, err := authz.NewRouterFromFile(rulesPath, "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	fx := startConfigServer(t)
	svc, err := New(Config{
		Conn:          fx.connectHandler(t),
		Verifier:      idp.NewMock(),
		Router:        router,
		Mode:          ModeConfig,
		SigningKey:    fx.issuerKP,
		TargetAccount: testAccountName,
		XKey:          fx.xkey,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("start service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	for _, hostile := range []string{"*", ">", "other.acme"} {
		conn, err := fx.connectClient("mock:u-ana:ana@example.test:app-user:tenant_id=" + hostile)
		if err == nil {
			conn.Close()
			t.Fatalf("a token with tenant_id=%q connected; it could reach other tenants", hostile)
		}
	}

	// A legitimate tenant still connects: the guard must not break the feature.
	conn, err := fx.connectClient("mock:u-ana:ana@example.test:app-user:tenant_id=acme")
	if err != nil {
		t.Fatalf("a legitimate tenant should still connect: %v", err)
	}
	conn.Close()
}

// TestForeignGrammarRejectsTokenMissingClaim proves the runtime guard end to end: a token that
// does not carry a declared claim cannot connect at all. Authorizing it would mean minting a
// subject with an empty segment.
func TestForeignGrammarRejectsTokenMissingClaim(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "app.yaml"),
		[]byte("pub:\n  allow:\n    - \"{{tenant}}.orders.{{user_id}}\"\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(`
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: app-user
    template: app.yaml
`), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	router, err := authz.NewRouterFromFile(rulesPath, "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	fx := startConfigServer(t)
	svc, err := New(Config{
		Conn:          fx.connectHandler(t),
		Verifier:      idp.NewMock(),
		Router:        router,
		Mode:          ModeConfig,
		SigningKey:    fx.issuerKP,
		TargetAccount: testAccountName,
		XKey:          fx.xkey,
	})
	if err != nil {
		t.Fatalf("build service: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("start service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	// No tenant_id claim in the token.
	conn, err := fx.connectClient("mock:u-ana:ana@example.test:app-user")
	if err == nil {
		conn.Close()
		t.Fatal("a token missing a declared placeholder claim should not connect")
	}
}
