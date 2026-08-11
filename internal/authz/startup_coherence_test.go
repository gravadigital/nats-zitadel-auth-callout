package authz

import (
	"errors"
	"strings"
	"testing"
)

// These tests cover the startup rule: a configuration with no way to work must FAIL rather than
// start. Every case here previously started cleanly and misbehaved only at runtime, far from the
// mistake — a typo'd key granting nothing, a rule that can never fire, a declared input nothing
// consumes.
//
// They are grouped separately from placeholders_test.go because what they assert is not about
// any single subject: it is about whether the pieces of a configuration are coherent with each
// other.

// --- unknown keys ---------------------------------------------------------------------------

// TestTemplateTypoIsRejected is the worst of the silent failures: `publish:` parses as valid
// YAML, grants nothing, and the client connects fine and then has every publish denied.
func TestTemplateTypoIsRejected(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "publish:\n  allow: [\"app.{{user_id}}.>\"]\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err == nil {
		t.Fatal("a template with an unknown key should fail at startup")
	}
	// The message has to name the offending key: "parse error" alone sends the reader looking
	// for malformed YAML, which is not what is wrong.
	if !strings.Contains(err.Error(), "publish") {
		t.Fatalf("the error should name the unknown key, got: %v", err)
	}
}

// TestRulesTypoIsRejected covers the same class in rules.yaml. `templates:` used to be caught
// only incidentally, by the missing-template check, which names the wrong problem.
func TestRulesTypoIsRejected(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    templates: t.yaml
`
	templates := map[string]string{"t.yaml": "pub:\n  allow: [\"a.b\"]\n"}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err == nil {
		t.Fatal("a rule with an unknown key should fail at startup")
	}
	if !strings.Contains(err.Error(), "templates") {
		t.Fatalf("the error should name the unknown key, got: %v", err)
	}
}

// TestValidConfigStillParses guards against the strict decoder rejecting legitimate
// configuration: every documented key of both files, together.
func TestValidConfigStillParses(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: admin
    type: person
    template: person.yaml
  - match: svc
    type: service
    service: demo
    template: service.yaml
`
	templates := map[string]string{
		"person.yaml": `
pub:
  allow: ["{{instance}}.{{tenant}}.{{user_id}}.demo.ping"]
  deny:  ["{{instance}}.{{tenant}}.{{user_id}}.demo.secret"]
sub:
  allow: ["_INBOX.{{user_id_hash}}.>"]
kv:
  - bucket: data
    access: read-write
    manage: false
    keys: "{{user_id}}.>"
    watch: false
response:
  max: 1
  ttl: 45s
`,
		"service.yaml": `
sub:
  allow: ["{{instance}}.*.{{service}}.>"]
`,
	}

	if _, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "prod"); err != nil {
		t.Fatalf("a fully-populated valid configuration must still load: %v", err)
	}
}

// --- unreachable rules ----------------------------------------------------------------------

// TestDuplicateMatchIsRejected: the second rule can never fire, so the permissions its author
// wrote are never the ones minted.
func TestDuplicateMatchIsRejected(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: a.yaml
  - match: r
    type: person
    template: b.yaml
`
	templates := map[string]string{
		"a.yaml": "pub:\n  allow: [\"a.{{user_id}}\"]\n",
		"b.yaml": "pub:\n  allow: [\"b.{{user_id}}\"]\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if !errors.Is(err, ErrUnreachableRule) {
		t.Fatalf("expected ErrUnreachableRule, got: %v", err)
	}
}

// TestCatchAllMustBeLast: a catch-all placed early makes every following rule dead. This is the
// ordering mistake the README warns about; now it cannot start.
func TestCatchAllMustBeLast(t *testing.T) {
	rules := `
version: 1
rules:
  - match: "*"
    type: person
    template: a.yaml
  - match: admin
    type: person
    template: b.yaml
`
	templates := map[string]string{
		"a.yaml": "pub:\n  allow: [\"a.{{user_id}}\"]\n",
		"b.yaml": "pub:\n  allow: [\"b.{{user_id}}\"]\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if !errors.Is(err, ErrUnreachableRule) {
		t.Fatalf("expected ErrUnreachableRule, got: %v", err)
	}
}

// TestCatchAllLastIsFine is the counterpart: the documented, intended shape must keep working.
func TestCatchAllLastIsFine(t *testing.T) {
	rules := `
version: 1
rules:
  - match: admin
    type: person
    template: b.yaml
  - match: "*"
    type: person
    template: a.yaml
`
	templates := map[string]string{
		"a.yaml": "pub:\n  allow: [\"a.{{user_id}}\"]\n",
		"b.yaml": "pub:\n  allow: [\"b.{{user_id}}\"]\n",
	}

	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("a catch-all in last position is the documented shape: %v", err)
	}
	// And it still behaves as first-match-wins.
	if _, _, decision, err := router.Resolve([]string{"admin"}, "u-1", "", nil); err != nil {
		t.Fatalf("resolve: %v", err)
	} else if decision.Rule != "admin" {
		t.Fatalf("expected the specific rule to win, got %q", decision.Rule)
	}
}

// --- dead configuration ---------------------------------------------------------------------

// TestUnusedPlaceholderIsRejected: a leftover declaration is not inert. Resolve rejects any
// token missing a declared claim, so the declaration silently becomes an authentication
// requirement that grants nothing.
func TestUnusedPlaceholderIsRejected(t *testing.T) {
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
		"t.yaml": "pub:\n  allow: [\"app.{{user_id}}.>\"]\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if !errors.Is(err, ErrUnusedPlaceholder) {
		t.Fatalf("expected ErrUnusedPlaceholder, got: %v", err)
	}
	if !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("the error should name the unused placeholder, got: %v", err)
	}
}

// TestPlaceholderUsedByAnyTemplateIsEnough: templates differ, and a placeholder used by one of
// them is legitimately absent from the others.
func TestPlaceholderUsedByAnyTemplateIsEnough(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: a
    type: person
    template: uses.yaml
  - match: b
    type: person
    template: plain.yaml
`
	templates := map[string]string{
		"uses.yaml":  "pub:\n  allow: [\"{{tenant}}.{{user_id}}.>\"]\n",
		"plain.yaml": "pub:\n  allow: [\"app.{{user_id}}.>\"]\n",
	}

	if _, err := NewRouterFromFile(writeRulesTree(t, rules, templates), ""); err != nil {
		t.Fatalf("one template using the placeholder is enough: %v", err)
	}
}

// TestUnusedInstanceIsRejected is the mirror of "{{instance}} with no instance configured",
// which already failed. A deployment believing it is scoped per instance while no minted subject
// mentions one is the failure that is invisible from the outside.
func TestUnusedInstanceIsRejected(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "pub:\n  allow: [\"app.{{user_id}}.>\"]\n",
	}

	_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "prod")
	if !errors.Is(err, ErrUnusedInstance) {
		t.Fatalf("expected ErrUnusedInstance, got: %v", err)
	}
	if !strings.Contains(err.Error(), "prod") {
		t.Fatalf("the error should name the configured instance, got: %v", err)
	}
}

// TestNoInstanceAndNoReferenceIsFine: a deployment adopting a foreign grammar has no instance
// token at all, which is the case the optional instance exists for.
func TestNoInstanceAndNoReferenceIsFine(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "pub:\n  allow: [\"app.{{user_id}}.>\"]\n",
	}

	if _, err := NewRouterFromFile(writeRulesTree(t, rules, templates), ""); err != nil {
		t.Fatalf("no instance and no reference is a valid combination: %v", err)
	}
}

// --- templates that grant nothing -------------------------------------------------------------

// TestTemplateGrantingNothingIsRejected: a client would authenticate and then be denied every
// operation, which reads as a broken service rather than a misconfigured template.
func TestTemplateGrantingNothingIsRejected(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	for name, body := range map[string]string{
		"no keys at all": "{}\n",
		"empty allow":    "pub:\n  allow: []\n",
		"deny-only":      "pub:\n  deny: [\"app.>\"]\n",
		"response-only":  "response:\n  max: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			templates := map[string]string{"t.yaml": body}
			_, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
			if !errors.Is(err, ErrEmptyPermissions) {
				t.Fatalf("expected ErrEmptyPermissions, got: %v", err)
			}
		})
	}
}

// TestKVOnlyTemplateIsNotEmpty: a KV-only template grants real subjects, so it must load. It is
// the case that would break if the emptiness check looked at the YAML instead of the expansion.
func TestKVOnlyTemplateIsNotEmpty(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "kv:\n  - bucket: data\n    access: read\n    keys: \"{{user_id}}.>\"\n",
	}

	if _, err := NewRouterFromFile(writeRulesTree(t, rules, templates), ""); err != nil {
		t.Fatalf("a KV-only template grants subjects and must load: %v", err)
	}
}

// --- warnings -----------------------------------------------------------------------------

// TestNoInboxWarns covers the one case that is suspicious rather than wrong: publish-only
// clients are a real shape, so it warns instead of refusing to start.
func TestNoInboxWarns(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "pub:\n  allow: [\"app.{{user_id}}.>\"]\n",
	}

	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("a publish-only template must still start: %v", err)
	}
	warnings := router.Warnings()
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %v", warnings)
	}
	// The warning has to say what to add, or it only tells the reader something is wrong.
	if !strings.Contains(warnings[0], "_INBOX") {
		t.Fatalf("the warning should name the missing inbox permission, got: %v", warnings[0])
	}
}

// TestInboxGrantedDoesNotWarn: the normal shape must be silent, or the warning becomes noise
// that gets ignored.
func TestInboxGrantedDoesNotWarn(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    type: person
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": "pub:\n  allow: [\"app.{{user_id}}.>\"]\nsub:\n  allow: [\"_INBOX.{{user_id_hash}}.>\"]\n",
	}

	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}
	if warnings := router.Warnings(); len(warnings) != 0 {
		t.Fatalf("a template granting an inbox must not warn, got %v", warnings)
	}
}
