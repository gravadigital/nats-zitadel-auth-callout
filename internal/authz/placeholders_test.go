package authz

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests cover the deployment-configurable subject grammar: the feature that lets a team
// adopt the service against a NATS whose subjects this project did not design.

// writeRulesTree writes a rules.yaml plus its templates and returns the rules path.
func writeRulesTree(t *testing.T, rules string, templates map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range templates {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write template %s: %v", name, err)
		}
	}
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return path
}

// TestCustomPlaceholderExpands is the core of the reusability change: a grammar this project
// never designed — tenant-first, with no instance token — expressed purely in configuration.
func TestCustomPlaceholderExpands(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
  region: metadata.region
rules:
  - match: app-user
    type: person
    template: person.yaml
`
	templates := map[string]string{
		"person.yaml": `
pub:
  allow:
    - "{{tenant}}.{{region}}.orders.{{user_id}}.create"
`,
	}

	// No instance is configured: a deployment adopting an existing grammar has nowhere to put
	// one, and the template never asks for it.
	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	_, perms, _, err := router.Resolve(
		[]string{"app-user"}, "u-1", "ana",
		map[string]string{"tenant": "acme", "region": "eu"},
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	want := "acme.eu.orders.u-1.create"
	if len(perms.PubAllow) != 1 || perms.PubAllow[0] != want {
		t.Fatalf("expected pub allow [%s], got %v", want, perms.PubAllow)
	}
}

// TestBuiltinPlaceholderCannotBeRedefined guards the security property. Sourcing `user_id`
// from an arbitrary claim would let a token choose whose subjects it can reach, defeating the
// per-user scoping the whole grammar exists to enforce.
func TestBuiltinPlaceholderCannotBeRedefined(t *testing.T) {
	for _, name := range []string{"user_id", "user_id_hash", "instance", "service"} {
		t.Run(name, func(t *testing.T) {
			rules := "version: 1\nplaceholders:\n  " + name + ": some_claim\nrules:\n" +
				"  - match: r\n    type: person\n    template: t.yaml\n"
			templates := map[string]string{"t.yaml": "pub:\n  allow:\n    - \"a.b\"\n"}

			_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "dev")
			if !errors.Is(err, ErrReservedPlaceholder) {
				t.Fatalf("expected ErrReservedPlaceholder for %q, got: %v", name, err)
			}
		})
	}
}

// TestUndeclaredPlaceholderFailsAtStartup keeps the existing guarantee intact for the new
// names: a template referencing a placeholder nobody declared must break startup, not mint a
// broken subject later.
func TestUndeclaredPlaceholderFailsAtStartup(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "pub:\n  allow:\n    - \"{{tenant}}.{{nope}}.x\"\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "dev")
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("expected ErrUnknownPlaceholder, got: %v", err)
	}
}

// TestInstanceReferencedButNotConfiguredFails covers making the instance optional. Optional
// must not mean "silently expands to nothing": an empty segment produces a subject that matches
// nothing, which is invisible until a client cannot publish.
func TestInstanceReferencedButNotConfiguredFails(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "pub:\n  allow:\n    - \"{{instance}}.x.y\"\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err == nil {
		t.Fatal("a template using {{instance}} with no instance configured should fail at startup")
	}
	if !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("expected an invalid-subject error, got: %v", err)
	}
}

// TestMissingPlaceholderClaimIsRejected proves the runtime guard: a token that does not carry a
// declared claim is refused rather than authorized with a subject containing an empty segment.
func TestMissingPlaceholderClaimIsRejected(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "pub:\n  allow:\n    - \"{{tenant}}.x\"\n",
	}

	// No instance: this template does not use {{instance}}, and configuring one that no
	// template references is itself a startup error.
	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	_, _, _, err = router.Resolve([]string{"r"}, "u-1", "ana", nil)
	if !errors.Is(err, ErrMissingPlaceholderClaim) {
		t.Fatalf("expected ErrMissingPlaceholderClaim, got: %v", err)
	}
	// The error has to name the claim, otherwise diagnosing it means reading the source.
	if !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("error should name the claim path, got: %v", err)
	}
}

// TestInvalidPlaceholderNameRejected covers a name no template could ever reference: declaring
// it would look like it worked while nothing used it.
func TestInvalidPlaceholderNameRejected(t *testing.T) {
	rules := `
version: 1
placeholders:
  Tenant-ID: tenant_id
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{"t.yaml": "pub:\n  allow:\n    - \"a.b\"\n"}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "dev")
	if !errors.Is(err, ErrInvalidPlaceholderName) {
		t.Fatalf("expected ErrInvalidPlaceholderName, got: %v", err)
	}
}

// TestInboxPassthroughMode covers the opt-out that makes adoption possible without touching
// every client's connection code.
func TestInboxPassthroughMode(t *testing.T) {
	hashed := Identity{UserID: "u-1"}
	if got := hashed.InboxPrefix(); got != "_INBOX."+HashUserID("u-1") {
		t.Fatalf("hashed inbox: got %q", got)
	}

	passthrough := Identity{UserID: "u-1", InboxMode: InboxPassthrough}
	if got := passthrough.InboxPrefix(); got != "_INBOX" {
		t.Fatalf("passthrough inbox: expected _INBOX, got %q", got)
	}
}

// TestUserIDHashUnavailableInPassthrough covers the inconsistency between InboxPrefix() and the
// {{user_id_hash}} placeholder.
//
// In passthrough mode clients keep their default inbox, so a permission scoped to the hash grants
// an inbox nobody ever subscribes to. That failure is silent and presents as "replies never
// arrive", so it has to break startup instead — the same treatment {{instance}} gets when no
// instance is configured.
func TestUserIDHashUnavailableInPassthrough(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "sub:\n  allow: [\"_INBOX.{{user_id_hash}}.>\"]\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "dev",
		WithInboxMode(InboxPassthrough))
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("expected ErrUnknownPlaceholder, got: %v", err)
	}
	// The message must name the inbox mode: "unknown placeholder" alone would send the reader
	// hunting for a typo in a placeholder that does exist.
	if !strings.Contains(err.Error(), "passthrough") {
		t.Fatalf("the error should explain that the inbox mode withholds it, got: %v", err)
	}

	// The same template is fine in hashed mode, which is the default. No instance: the template
	// does not reference {{instance}}.
	if _, err := NewRouterFromFile(writeRulesTree(t, rules, templates), ""); err != nil {
		t.Fatalf("the hashed default should still accept {{user_id_hash}}: %v", err)
	}
}

// TestPassthroughTemplateWithBroadInboxWorks pins the intended way to write a passthrough
// template: grant the inbox the clients actually use.
func TestPassthroughTemplateWithBroadInboxWorks(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "sub:\n  allow: [\"_INBOX.>\"]\n",
	}

	// No instance: this template grants only the broad inbox and does not use {{instance}}.
	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "",
		WithInboxMode(InboxPassthrough))
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	_, perms, _, err := router.Resolve([]string{"r"}, "u-1", "ana", nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(perms.SubAllow) != 1 || perms.SubAllow[0] != "_INBOX.>" {
		t.Fatalf("expected [_INBOX.>], got %v", perms.SubAllow)
	}
}
