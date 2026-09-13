package authz

import (
	"errors"
	"strings"
	"testing"
)

// These tests cover hostile CLAIM VALUES against well-formed configuration — the gap that let a
// token-controlled claim widen its own permissions.
//
// The threat model: the deployment's rules.yaml and templates are trusted (an operator wrote
// them), but a placeholder's VALUE comes from the token. In a multi-tenant deployment the tenant
// claim is exactly what the scoping is meant to constrain, so it must never be able to turn a
// scoped subject into a wildcard one.

// injectionValues are the values that must never reach a minted subject, with the reason each
// one is dangerous.
var injectionValues = map[string]string{
	"*":      "NATS wildcard for one token — matches every tenant at that position",
	">":      "NATS wildcard for the rest of the subject",
	"a.b":    "adds a segment, shifting every following token in the grammar",
	" ":      "whitespace is not a usable subject token",
	"a b":    "embedded whitespace",
	"a\tb":   "embedded tab",
	"a\nb":   "embedded newline",
	"x\x00y": "embedded NUL",
	"pre*":   "wildcard in a suffix position",
	"*.>":    "both wildcards combined",
	"a.*":    "dot plus wildcard",
	"\x7f":   "DEL control character",
}

// TestPlaceholderInjectionRejectedOnEverySurface is the core regression test. Each template
// exercises a different surface a placeholder can reach, because they escalate differently: a
// wildcard in `kv.bucket` reaches every bucket in the ACCOUNT, not just other tenants' rows.
func TestPlaceholderInjectionRejectedOnEverySurface(t *testing.T) {
	surfaces := map[string]string{
		"pub.allow": `
pub:
  allow: ["{{tenant}}.{{user_id}}.demo.>"]
`,
		"sub.allow": `
sub:
  allow: ["{{tenant}}.>"]
`,
		"pub.deny": `
pub:
  allow: ["fixed.{{user_id}}.>"]
  deny:  ["{{tenant}}.secret"]
`,
		"kv.keys": `
kv:
  - bucket: data
    access: read-write
    keys: "{{tenant}}.{{user_id}}.>"
`,
		// The worst case: the value becomes the STREAM name, so `*` reaches every KV bucket in
		// the account, and with manage:true also STREAM.DELETE and STREAM.PURGE over all of them.
		"kv.bucket": `
kv:
  - bucket: "{{tenant}}"
    access: read-write
    manage: true
`,
	}

	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: user
    template: t.yaml
`

	for surface, template := range surfaces {
		t.Run(surface, func(t *testing.T) {
			router, err := NewRouterFromFile(
				writeRulesTree(t, rules, map[string]string{"t.yaml": template}), "")
			if err != nil {
				t.Fatalf("build router: %v", err)
			}

			for value, why := range injectionValues {
				_, perms, _, err := router.Resolve([]string{"user"}, "attacker", "a",
					map[string]string{"tenant": value})
				if err == nil {
					t.Errorf("value %q was ACCEPTED (%s); minted pub=%v sub=%v",
						value, why, perms.PubAllow, perms.SubAllow)
					continue
				}
				if !errors.Is(err, ErrUnsafePlaceholderValue) {
					t.Errorf("value %q: expected ErrUnsafePlaceholderValue, got: %v", value, err)
				}
			}
		})
	}
}

// TestPlaceholderInjectionErrorDoesNotLeakTheValue matters because this error travels to the
// client and into the logs, and the value is token content.
func TestPlaceholderInjectionErrorDoesNotLeakTheValue(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: user
    template: t.yaml
`
	templates := map[string]string{"t.yaml": "pub:\n  allow: [\"{{tenant}}.x\"]\n"}

	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	secret := "super-secret-tenant-value*"
	_, _, _, err = router.Resolve([]string{"user"}, "u1", "a", map[string]string{"tenant": secret})
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error leaks the claim value: %v", err)
	}
	// It must still name the placeholder and the claim path, or diagnosing it means reading source.
	if !strings.Contains(err.Error(), "tenant") || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("the error should name the placeholder and claim path, got: %v", err)
	}
}

// TestPlaceholderValueLengthBounded keeps a multi-kilobyte claim from becoming a multi-kilobyte
// subject in every minted JWT.
func TestPlaceholderValueLengthBounded(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: user
    template: t.yaml
`
	templates := map[string]string{"t.yaml": "pub:\n  allow: [\"{{tenant}}.x\"]\n"}

	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	// At the limit: accepted.
	atLimit := strings.Repeat("a", maxPlaceholderValueLen)
	if _, _, _, err := router.Resolve([]string{"user"}, "u1", "a",
		map[string]string{"tenant": atLimit}); err != nil {
		t.Fatalf("a value at the length limit should be accepted: %v", err)
	}

	// One over: rejected.
	tooLong := strings.Repeat("a", maxPlaceholderValueLen+1)
	_, _, _, err = router.Resolve([]string{"user"}, "u1", "a", map[string]string{"tenant": tooLong})
	if !errors.Is(err, ErrUnsafePlaceholderValue) {
		t.Fatalf("an over-long value should be rejected, got: %v", err)
	}
}

// TestTemplateLiteralWildcardsStillWork is the guard against over-correcting. The fix must
// constrain claim VALUES only — templates legitimately contain wildcards, and the shipped service
// template depends on it (`{{instance}}.*.api.>`).
func TestTemplateLiteralWildcardsStillWork(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: svc
    template: t.yaml
`
	templates := map[string]string{
		// Wildcards written by the template author, in the same subjects as a placeholder.
		"t.yaml": `
pub:
  allow: ["{{instance}}.{{tenant}}.>"]
sub:
  allow:
    - "{{instance}}.*.api.>"
    - "{{tenant}}.*.events.>"
kv:
  - bucket: shared
    access: read
    keys: ">"
`,
	}

	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "prod")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	_, perms, _, err := router.Resolve([]string{"svc"}, "svc-1", "svc",
		map[string]string{"tenant": "acme"})
	if err != nil {
		t.Fatalf("literal wildcards in a template must still work: %v", err)
	}

	assertContains(t, "subAllow", perms.SubAllow, "prod.*.api.>")
	assertContains(t, "subAllow", perms.SubAllow, "acme.*.events.>")
	assertContains(t, "pubAllow", perms.PubAllow, "prod.acme.>")

	// `keys: ">"` written by the author still unlocks the unscoped read path, as designed.
	assertContains(t, "pubAllow", perms.PubAllow, "$JS.API.STREAM.MSG.GET.KV_shared")
}

// TestInjectedWildcardCannotUnlockUnscopedKVRead covers the subtler KV escalation: the
// get-by-revision path is granted only when `keys` is exactly `>`, because it cannot be scoped by
// key. A token-supplied `>` must not satisfy that condition.
func TestInjectedWildcardCannotUnlockUnscopedKVRead(t *testing.T) {
	rules := `
version: 1
placeholders:
  tenant: tenant_id
rules:
  - match: user
    template: t.yaml
`
	templates := map[string]string{
		"t.yaml": `
kv:
  - bucket: data
    access: read
    keys: "{{tenant}}"
`,
	}

	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	// The injected `>` must be refused outright, so the unscoped path is never reached.
	_, _, _, err = router.Resolve([]string{"user"}, "u1", "a", map[string]string{"tenant": ">"})
	if !errors.Is(err, ErrUnsafePlaceholderValue) {
		t.Fatalf("an injected `>` should be rejected, got: %v", err)
	}

	// A benign value must NOT get the unscoped read path either, since it does not cover the
	// whole bucket.
	_, perms, _, err := router.Resolve([]string{"user"}, "u1", "a",
		map[string]string{"tenant": "acme"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, subject := range perms.PubAllow {
		if strings.HasPrefix(subject, "$JS.API.STREAM.MSG.GET.") {
			t.Fatalf("a key-scoped KV grant must not include the unscoped read path, got %q", subject)
		}
	}
}

// TestHostileUserIDRejected covers the same injection through the built-in {{user_id}}, which is
// the token's `sub`.
//
// This surface is broader than any declared placeholder: `{{user_id}}` appears in essentially
// every template, so a `sub` of `*` would widen the per-user scoping the whole grammar rests on,
// not just one deployment's tenant field.
func TestHostileUserIDRejected(t *testing.T) {
	rules := `
version: 1
rules:
  - match: r
    template: t.yaml
`
	templates := map[string]string{"t.yaml": "pub:\n  allow: [\"app.{{user_id}}.>\"]\n"}

	// No instance: the template does not reference {{instance}}, and configuring one that no
	// template uses is a startup error in its own right.
	router, err := NewRouterFromFile(writeRulesTree(t, rules, templates), "")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	for value := range injectionValues {
		_, perms, _, err := router.Resolve([]string{"r"}, value, "x", nil)
		if err == nil {
			t.Errorf("sub %q was ACCEPTED; minted pub=%v", value, perms.PubAllow)
			continue
		}
		if !errors.Is(err, ErrUnsafePlaceholderValue) {
			t.Errorf("sub %q: expected ErrUnsafePlaceholderValue, got: %v", value, err)
		}
	}

	// Real subject formats from actual providers must all still work.
	for _, sub := range []string{
		"100000000000000001",                   // Zitadel
		"0198f3a2-1c4e-7c3a-9f2b-6d5e4c3b2a10", // UUID
		"auth0|507f1f77bcf86cd799439011",       // Auth0 — `|` is not a NATS metacharacter
		"00u1a2b3c4d5e6f7g8h9",                 // Okta
		"107654321098765432109",                // Google
	} {
		if _, _, _, err := router.Resolve([]string{"r"}, sub, "x", nil); err != nil {
			t.Errorf("a real provider sub %q should be accepted: %v", sub, err)
		}
	}

	// A dotted `sub` — some LDAP-backed providers issue an email address — is refused rather than
	// silently adding segments to every subject. Pinned deliberately: it is a real
	// incompatibility, and such a deployment must map `sub` to an opaque id in the IdP instead.
	if _, _, _, err := router.Resolve([]string{"r"}, "ana@example.test", "x", nil); !errors.Is(err, ErrUnsafePlaceholderValue) {
		t.Fatalf("a dotted sub should be refused, got: %v", err)
	}
}

// TestValidatePlaceholderValueUnit pins the rule directly, including the values that must remain
// acceptable — ids in the wild carry hyphens, underscores and mixed case.
func TestValidatePlaceholderValueUnit(t *testing.T) {
	valid := []string{
		"acme", "ACME", "acme-corp", "acme_corp", "tenant42", "42",
		"a", "eu-west-1", "0198f3a2-1c4e-7c3a-9f2b-6d5e4c3b2a10",
		// Provider-specific `sub` formats. `|` and `@` are not NATS metacharacters, so they are
		// fine inside a single subject token.
		"auth0|507f1f77bcf86cd799439011", "user@example",
	}
	for _, value := range valid {
		if err := validatePlaceholderValue(value); err != nil {
			t.Errorf("%q should be valid: %v", value, err)
		}
	}

	for value := range injectionValues {
		if err := validatePlaceholderValue(value); err == nil {
			t.Errorf("%q should be rejected", value)
		}
	}
}

// assertContains fails unless list holds want.
func assertContains(t *testing.T, label string, list []string, want string) {
	t.Helper()
	for _, got := range list {
		if got == want {
			return
		}
	}
	t.Errorf("%s should contain %q, got %v", label, want, list)
}
