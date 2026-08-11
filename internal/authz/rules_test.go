package authz

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeRules drops a rules.yaml and the templates it references into a temp directory.
func writeRules(t *testing.T, rules string, templates map[string]string) string {
	t.Helper()
	dir := t.TempDir()

	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules.yaml: %v", err)
	}

	tmplDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(tmplDir, 0o750); err != nil {
		t.Fatalf("create templates/: %v", err)
	}
	for name, content := range templates {
		if err := os.WriteFile(filepath.Join(tmplDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return rulesPath
}

// minimalPersonTemplate is a valid person template.
const minimalPersonTemplate = `
pub:
  allow:
    - "{{instance}}.{{user_id}}.api.>"
sub:
  allow:
    - "_INBOX.{{user_id_hash}}.>"
`

// minimalServiceTemplate is a valid service template.
const minimalServiceTemplate = `
sub:
  allow:
    - "{{instance}}.*.{{service}}.>"
`

func TestMatchIsFirstMatchWins(t *testing.T) {
	// `external-user` is declared BEFORE `user`: an account holding both roles must land on
	// the more restrictive one. That is the guarantee the ordering of rules.yaml rests on.
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: external-user
    type: person
    template: templates/external.yaml
  - match: user
    type: person
    template: templates/user.yaml
`, map[string]string{
		"external.yaml": minimalPersonTemplate,
		"user.yaml":     minimalPersonTemplate,
	})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	rule, _, ok := router.Match([]string{"user", "external-user"})
	if !ok {
		t.Fatal("expected a match")
	}
	if rule.Match != "external-user" {
		t.Fatalf("expected external-user to win, %q won", rule.Match)
	}
}

func TestMatchCatchAll(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: admin
    type: person
    template: templates/admin.yaml
  - match: "*"
    type: person
    template: templates/guest.yaml
`, map[string]string{
		"admin.yaml": minimalPersonTemplate,
		"guest.yaml": minimalPersonTemplate,
	})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	rule, _, ok := router.Match([]string{"role-that-does-not-exist"})
	if !ok || rule.Match != MatchAny {
		t.Fatalf("expected the catch-all, got %q (ok=%v)", rule.Match, ok)
	}

	// With no roles at all it also lands on the catch-all.
	if _, _, ok := router.Match(nil); !ok {
		t.Fatal("expected a token with no roles to land on the catch-all")
	}
}

// Without a catch-all, an unknown role is REJECTED. There are no default permissions.
func TestResolveWithoutCatchAllRejects(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: svc-api
    type: service
    service: api
    template: templates/svc.yaml
`, map[string]string{"svc.yaml": minimalServiceTemplate})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	_, _, _, err = router.Resolve([]string{"another-role"}, "sub-1", "whoever", nil)
	if !errors.Is(err, ErrNoRuleMatched) {
		t.Fatalf("expected ErrNoRuleMatched, got %v", err)
	}
}

func TestResolvePersonIdentity(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: "*"
    type: person
    template: templates/person.yaml
`, map[string]string{"person.yaml": minimalPersonTemplate})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	id, perms, _, err := router.Resolve([]string{"user"}, "zitadel-user-123", "ana@example.com", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if id.Type != UserTypePerson {
		t.Fatalf("expected type person, got %q", id.Type)
	}
	if id.UserID != "zitadel-user-123" {
		t.Fatalf("the user id must be the token sub, got %q", id.UserID)
	}
	// The user id goes RAW into messaging subjects: it is what makes the subject readable
	// and what lets a service learn who called it just by reading it.
	if !slices.Contains(perms.PubAllow, "prod.zitadel-user-123.api.>") {
		t.Fatalf("expected the raw user id in the pub subject, got %v", perms.PubAllow)
	}
	// The inbox, by contrast, goes under the hash.
	wantInbox := "_INBOX." + HashUserID("zitadel-user-123") + ".>"
	if !slices.Contains(perms.SubAllow, wantInbox) {
		t.Fatalf("expected the inbox %q, got %v", wantInbox, perms.SubAllow)
	}
	if id.Username != "ana@example.com" {
		t.Fatalf("expected the token username, got %q", id.Username)
	}
}

func TestResolveServiceIdentity(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: svc-jira
    type: service
    service: jira
    template: templates/svc.yaml
`, map[string]string{"svc.yaml": minimalServiceTemplate})

	router, err := NewRouterFromFile(rulesPath, "prod")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	id, perms, _, err := router.Resolve([]string{"svc-jira"}, "machine-user-9", "", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if id.Type != UserTypeService {
		t.Fatalf("expected type service, got %q", id.Type)
	}
	// A service user has BOTH things: its own user id (the `sub`, just like a person) and
	// the name of the endpoint it serves. They are distinct axes.
	if id.UserID != "machine-user-9" || id.Service != "jira" {
		t.Fatalf("expected userID=machine-user-9 service=jira, got userID=%q service=%q", id.UserID, id.Service)
	}
	assertSubjects(t, "sub allow", perms.SubAllow, []string{"prod.*.jira.>"})
}

// The identity model is decided by the RULE, not by the class of user in Zitadel.
//
// A machine user whose role is declared `type: person` receives a person identity: with no
// service name, so it cannot serve an endpoint. This is intentional — it lets the person
// path be exercised without an interactive login — and it is what the log reports as
// `identity=person`, which reads oddly next to a service user unless you know this.
func TestIdentityModelComesFromTheRuleNotThePrincipal(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: poc-user
    type: person
    template: templates/person.yaml
`, map[string]string{"person.yaml": minimalPersonTemplate})

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	// The `sub` belongs to a Zitadel machine user; the rule says person.
	id, _, decision, err := router.Resolve([]string{"poc-user"}, "100000000000000001", "poc_user", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if decision.IdentityModel != UserTypePerson || id.Type != UserTypePerson {
		t.Fatalf("expected the person model, got decision=%q identity=%q", decision.IdentityModel, id.Type)
	}
	if id.UserID != "100000000000000001" {
		t.Fatalf("the user id must be the token sub, got %q", id.UserID)
	}
	if id.Service != "" {
		t.Fatalf("a person identity carries no service name, got %q", id.Service)
	}
	// The winning role has to be recorded: with several roles in the token, a log without it
	// makes it impossible to tell why those permissions were granted.
	if decision.Rule != "poc-user" {
		t.Fatalf("expected matchedBy=poc-user, got %q", decision.Rule)
	}
}

// Two different users cannot share a hash: that is what isolates their inboxes.
func TestHashUserIDIsStableAndDistinct(t *testing.T) {
	a1 := HashUserID("user-a")
	a2 := HashUserID("user-a")
	b := HashUserID("user-b")

	if a1 != a2 {
		t.Fatalf("the derivation must be deterministic: %q != %q", a1, a2)
	}
	if a1 == b {
		t.Fatal("two different user ids cannot derive the same hash")
	}
	if len(a1) != userIDHashLen {
		t.Fatalf("expected %d characters, got %d (%q)", userIDHashLen, len(a1), a1)
	}
	// It has to be a valid subject token: no separators and no wildcards.
	if err := validateSubject("_INBOX." + a1 + ".x"); err != nil {
		t.Fatalf("the derived hash is not a valid subject token: %v", err)
	}
}

// The inbox does NOT use the raw user id: a Zitadel `sub` may carry characters that are not
// a valid subject token, and the prefix has to be fixed-length.
func TestInboxPrefixUsesHashNotRawUserID(t *testing.T) {
	id := Identity{Instance: "prod", UserID: "100000000000000001"}

	want := "_INBOX." + HashUserID("100000000000000001")
	if got := id.InboxPrefix(); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if strings.Contains(id.InboxPrefix(), id.UserID) {
		t.Fatalf("the inbox must not carry the raw user id: %q", id.InboxPrefix())
	}
}

// --- configuration validation ---------------------------------------------------------
//
// All of this has to fail when the router is built, not when the first connection arrives.

func TestRouterRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		want  error
	}{
		{
			name: "invalid type",
			rules: `
version: 1
rules:
  - match: x
    type: robot
    template: templates/person.yaml
`,
			want: ErrInvalidUserType,
		},
		{
			name: "no template",
			rules: `
version: 1
rules:
  - match: x
    type: person
`,
			want: ErrEmptyTemplate,
		},
		{
			name: "service without a name",
			rules: `
version: 1
rules:
  - match: svc-x
    type: service
    template: templates/svc.yaml
`,
			want: ErrServiceNameRequired,
		},
		{
			name: "person with service",
			rules: `
version: 1
rules:
  - match: x
    type: person
    service: api
    template: templates/person.yaml
`,
			want: ErrServiceNameOnPerson,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rulesPath := writeRules(t, tc.rules, map[string]string{
				"person.yaml": minimalPersonTemplate,
				"svc.yaml":    minimalServiceTemplate,
			})
			_, err := NewRouterFromFile(rulesPath, "prod")
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestRouterRejectsMissingTemplateFile(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: x
    type: person
    template: templates/does-not-exist.yaml
`, nil)

	if _, err := NewRouterFromFile(rulesPath, "prod"); err == nil {
		t.Fatal("expected an error for a non-existent template")
	}
}

func TestRouterRejectsEmptyInstance(t *testing.T) {
	rulesPath := writeRules(t, `
version: 1
rules:
  - match: "*"
    type: person
    template: templates/person.yaml
`, map[string]string{"person.yaml": minimalPersonTemplate})

	if _, err := NewRouterFromFile(rulesPath, ""); err == nil {
		t.Fatal("expected an error for an empty instance")
	}
}

// --- the configuration that ships -----------------------------------------------------

// Validates config/rules.yaml and ALL of its real templates. It is the net that makes a
// typo in a template show up in `go test` rather than in a deploy.
func TestShippedConfigIsValid(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no shippable config at %s: %v", rulesPath, err)
	}

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("the shippable configuration does not validate: %v", err)
	}

	// Every declared role has to resolve to expandable permissions.
	for _, roles := range [][]string{
		{"poc-admin"}, {"poc-user"}, {"poc-service"},
	} {
		t.Run(roles[0], func(t *testing.T) {
			id, perms, decision, err := router.Resolve(roles, "test-sub", "test", nil)
			if err != nil {
				t.Fatalf("Resolve(%v): %v", roles, err)
			}
			if len(perms.PubAllow) == 0 && len(perms.SubAllow) == 0 {
				t.Fatalf("%s grants no permissions at all", decision.Template)
			}
			// No template may leave a placeholder unexpanded.
			for _, subject := range slices.Concat(perms.PubAllow, perms.SubAllow, perms.PubDeny, perms.SubDeny) {
				if placeholderRE.MatchString(subject) {
					t.Fatalf("%s left a placeholder unexpanded: %q", decision.Template, subject)
				}
			}
			// A person must never receive a service's permissions or vice versa: isolation
			// between user types depends on this.
			if id.Type == UserTypePerson && id.Service != "" {
				t.Fatalf("%s: a person must not have a service name", decision.Template)
			}
		})
	}
}

// Every KV bucket needs EXACTLY one service with `manage: true`.
//
// With zero, nobody can create it and data operations fail with "stream not found", which
// says nothing about the real cause. With more than one, two services can reconfigure or
// purge the same bucket and whichever migration runs last wins.
//
// A template loader cannot check this invariant — it is global to the config — so it is
// verified here.
func TestEveryKVBucketHasExactlyOneManager(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no shippable config: %v", err)
	}

	cfg, err := LoadRulesConfig(rulesPath)
	if err != nil {
		t.Fatalf("LoadRulesConfig: %v", err)
	}

	managers := map[string][]string{} // bucket -> templates that administer it
	seen := map[string]bool{}         // bucket -> appears in some template

	for _, rule := range cfg.Rules {
		path := filepath.Join(filepath.Dir(rulesPath), rule.Template)
		tmpl, err := LoadTemplate(path, probeIdentity())
		if err != nil {
			t.Fatalf("LoadTemplate(%s): %v", path, err)
		}
		for _, kv := range tmpl.KV {
			seen[kv.Bucket] = true
			if kv.Manage {
				managers[kv.Bucket] = append(managers[kv.Bucket], filepath.Base(path))
			}
		}
	}

	if len(seen) == 0 {
		t.Skip("the config references no KV bucket")
	}

	for bucket := range seen {
		switch n := len(managers[bucket]); {
		case n == 0:
			t.Errorf("bucket %q has no template with `manage: true`: nobody can create it", bucket)
		case n > 1:
			t.Errorf("bucket %q has %d administrators (%v): it must have exactly one",
				bucket, n, managers[bucket])
		}
	}
}

// A person may only publish under ITS OWN user id. This is the property the whole model
// rests on: if a client could publish under another user id, the receiver could not trust
// the identity it reads from the subject and every service would have to re-authorize.
func TestPersonTemplatesPublishOnlyUnderOwnUserID(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no shippable config: %v", err)
	}

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	for _, role := range []string{"poc-admin", "poc-user"} {
		id, perms, decision, err := router.Resolve([]string{role}, "sub-"+role, role, nil)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", role, err)
		}
		if id.Type != UserTypePerson {
			t.Fatalf("%s: expected a person identity", decision.Template)
		}
		for _, subject := range perms.PubAllow {
			// KV/JetStream subjects do not follow this grammar; skip them.
			if strings.HasPrefix(subject, "$") {
				continue
			}
			want := "dev." + id.UserID + "."
			if !strings.HasPrefix(subject, want) {
				t.Fatalf("%s: a person should not be able to publish to %q (expected the prefix %q)",
					decision.Template, subject, want)
			}
		}
	}
}

// With no catch-all in the shipped config, a valid Zitadel token carrying an undeclared role
// does NOT connect. It is one of the things the test against real Zitadel verifies.
func TestShippedConfigRejectsUnknownRole(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "config", "rules.yaml")
	if _, err := os.Stat(rulesPath); err != nil {
		t.Skipf("no shippable config: %v", err)
	}

	router, err := NewRouterFromFile(rulesPath, "dev")
	if err != nil {
		t.Fatalf("NewRouterFromFile: %v", err)
	}

	for _, roles := range [][]string{nil, {"nonexistent-role"}, {"ad-admin", "vd-user"}} {
		if _, _, _, err := router.Resolve(roles, "sub-x", "x", nil); !errors.Is(err, ErrNoRuleMatched) {
			t.Fatalf("Resolve(%v): expected ErrNoRuleMatched, got %v", roles, err)
		}
	}
}
