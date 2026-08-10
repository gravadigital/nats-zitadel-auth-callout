package authz

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// personIdentity is a test person identity.
func personIdentity() Identity {
	return Identity{Instance: "prod", UserID: "abc123", Type: UserTypePerson}
}

// serviceIdentity is a test service identity. A service user has its own user id (its
// `sub`) in addition to the endpoint name: they are distinct axes, so here they carry
// different values on purpose.
func serviceIdentity() Identity {
	return Identity{Instance: "prod", UserID: "svc-sub-1", Service: "api", Type: UserTypeService}
}

func TestExpandPlaceholders(t *testing.T) {
	tmpl := &Template{
		Pub: SubjectSet{
			Allow: []string{"{{instance}}.{{user_id}}.api.>"},
			Deny:  []string{"{{instance}}.{{user_id}}.api.danger"},
		},
		Sub: SubjectSet{Allow: []string{"_INBOX.{{user_id_hash}}.>"}},
	}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	assertSubjects(t, "pub allow", perms.PubAllow, []string{"prod.abc123.api.>"})
	assertSubjects(t, "pub deny", perms.PubDeny, []string{"prod.abc123.api.danger"})
	// The inbox goes under the HASH of the user id, not under the raw user id.
	assertSubjects(t, "sub allow", perms.SubAllow, []string{"_INBOX." + HashUserID("abc123") + ".>"})
}

func TestExpandServicePlaceholder(t *testing.T) {
	tmpl := &Template{
		Sub: SubjectSet{Allow: []string{"{{instance}}.*.{{service}}.>"}},
	}

	perms, err := tmpl.Expand(serviceIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	assertSubjects(t, "sub allow", perms.SubAllow, []string{"prod.*.api.>"})
}

func TestExpandUnknownPlaceholderFails(t *testing.T) {
	tmpl := &Template{Pub: SubjectSet{Allow: []string{"{{instance}}.{{tenant}}.api.>"}}}

	_, err := tmpl.Expand(personIdentity())
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("expected ErrUnknownPlaceholder, got %v", err)
	}
}

// An unknown placeholder must not resolve to empty: that would produce a subject with a
// missing segment that never matches, leaving the permission inert without anyone noticing.
func TestExpandUnknownPlaceholderDoesNotSilentlyDrop(t *testing.T) {
	tmpl := &Template{Pub: SubjectSet{Allow: []string{"{{instance}}.{{nope}}.api.>"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err == nil {
		t.Fatalf("expected an error, got permissions %v", perms.PubAllow)
	}
}

func TestExpandRejectsInvalidSubject(t *testing.T) {
	cases := map[string][]string{
		"empty segment":  {"prod..api.>"},
		"non-terminal >": {"prod.>.api"},
		"empty subject":  {""},
	}
	for name, subjects := range cases {
		t.Run(name, func(t *testing.T) {
			tmpl := &Template{Pub: SubjectSet{Allow: subjects}}
			_, err := tmpl.Expand(personIdentity())
			if !errors.Is(err, ErrInvalidSubject) {
				t.Fatalf("expected ErrInvalidSubject, got %v", err)
			}
		})
	}
}

func TestResponseRule(t *testing.T) {
	t.Run("explicit ttl", func(t *testing.T) {
		tmpl := &Template{Response: &ResponseRule{Max: 2, TTL: "45s"}}
		perms, err := tmpl.Expand(personIdentity())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if perms.RespMax != 2 || perms.RespTTL != 45*time.Second {
			t.Fatalf("expected max=2 ttl=45s, got max=%d ttl=%s", perms.RespMax, perms.RespTTL)
		}
	})

	t.Run("default ttl", func(t *testing.T) {
		tmpl := &Template{Response: &ResponseRule{Max: 1}}
		perms, err := tmpl.Expand(personIdentity())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if perms.RespTTL != defaultResponseTTL {
			t.Fatalf("expected the default TTL %s, got %s", defaultResponseTTL, perms.RespTTL)
		}
	})

	t.Run("no response means no allow_responses", func(t *testing.T) {
		perms, err := (&Template{}).Expand(personIdentity())
		if err != nil {
			t.Fatalf("Expand: %v", err)
		}
		if perms.RespMax != 0 {
			t.Fatalf("expected RespMax=0, got %d", perms.RespMax)
		}
	})
}

// --- KV -------------------------------------------------------------------------------
//
// These tests pin down the KV access -> JetStream subject mapping. It is the part of the
// design that is easiest to break without noticing: a malformed subject does not fail at
// startup, it simply makes KV not work (or work too much).

func TestKVReadSubjects(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "demo-catalog", Access: KVRead, Keys: ">"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	assertSubjects(t, "pub", perms.PubAllow, []string{
		jsAccountInfoSubject,
		"$JS.API.STREAM.INFO.KV_demo-catalog",
		"$JS.API.DIRECT.GET.KV_demo-catalog.$KV.demo-catalog.>",
		"$JS.API.STREAM.MSG.GET.KV_demo-catalog",
	})
	assertSubjects(t, "sub", perms.SubAllow, []string{"$KV.demo-catalog.>"})

	// Reading does not imply writing: the data subject must not appear in pub.
	if slices.Contains(perms.PubAllow, "$KV.demo-catalog.>") {
		t.Fatal("read access must not grant pub on the data subject (that would be writing)")
	}
}

// The case that underpins "per-user KV permissions": direct-get carries the key INSIDE the
// subject, so scoping by {{user_id}} makes the server enforce it.
func TestKVScopedByUserID(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "demo-prefs",
		Access: KVReadWrite,
		Keys:   "{{user_id}}.>",
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	assertSubjects(t, "pub", perms.PubAllow, []string{
		jsAccountInfoSubject,
		"$JS.API.STREAM.INFO.KV_demo-prefs",
		"$JS.API.DIRECT.GET.KV_demo-prefs.$KV.demo-prefs.abc123.>",
		"$KV.demo-prefs.abc123.>",
	})
	assertSubjects(t, "sub", perms.SubAllow, []string{"$KV.demo-prefs.abc123.>"})
}

// With key-scoped access STREAM.MSG.GET is NOT granted: that subject does not carry the
// key, so allowing it would let the whole bucket be read by revision number and would
// defeat the scoping.
func TestKVScopedAccessDeniesRevisionGet(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "demo-prefs",
		Access: KVRead,
		Keys:   "{{user_id}}.>",
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if slices.Contains(perms.PubAllow, "$JS.API.STREAM.MSG.GET.KV_demo-prefs") {
		t.Fatal("key-scoped access must not grant STREAM.MSG.GET (it would allow reading the whole bucket)")
	}
}

func TestKVWatchAddsConsumerSubjects(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "demo-sessions",
		Access: KVRead,
		Keys:   ">",
		Watch:  true,
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	for _, want := range []string{
		"$JS.API.CONSUMER.CREATE.KV_demo-sessions.>",
		"$JS.API.CONSUMER.DELETE.KV_demo-sessions.>",
	} {
		if !slices.Contains(perms.PubAllow, want) {
			t.Fatalf("missing %q in pub allow: %v", want, perms.PubAllow)
		}
	}
}

func TestKVWatchDisabledByDefault(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b", Access: KVRead, Keys: ">"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if slices.Contains(perms.PubAllow, "$JS.API.CONSUMER.CREATE.KV_b.>") {
		t.Fatal("watch must not be enabled if the template does not ask for it")
	}
}

func TestKVManageAddsStreamManagement(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "demo-catalog",
		Access: KVRead,
		Manage: true,
		Keys:   ">",
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	for _, want := range []string{
		"$JS.API.STREAM.CREATE.KV_demo-catalog",
		"$JS.API.STREAM.UPDATE.KV_demo-catalog",
		"$JS.API.STREAM.DELETE.KV_demo-catalog",
		"$JS.API.STREAM.PURGE.KV_demo-catalog",
	} {
		if !slices.Contains(perms.PubAllow, want) {
			t.Fatalf("missing %q in pub allow: %v", want, perms.PubAllow)
		}
	}
	// `manage` is the bucket's lifecycle, NOT data access: administering without
	// `read-write` must not grant writing. It is what lets the BFF own the preferences
	// bucket while being unable to write anyone's preferences.
	if slices.Contains(perms.PubAllow, "$KV.demo-catalog.>") {
		t.Fatal("manage must not grant data writes")
	}
}

// The manage-without-data case: administering someone else's bucket without being able to
// read what is inside.
func TestKVManageWithoutDataAccess(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{
		Bucket: "demo-sync-state",
		Access: KVNone,
		Manage: true,
	}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	// Creating a bucket starts by checking whether it exists, so STREAM.INFO is required.
	for _, want := range []string{
		"$JS.API.STREAM.CREATE.KV_demo-sync-state",
		"$JS.API.STREAM.INFO.KV_demo-sync-state",
	} {
		if !slices.Contains(perms.PubAllow, want) {
			t.Fatalf("missing %q in pub allow: %v", want, perms.PubAllow)
		}
	}

	// And no data at all: neither read nor write.
	if len(perms.SubAllow) != 0 {
		t.Fatalf("access none must not grant sub on the data: %v", perms.SubAllow)
	}
	for _, unwanted := range []string{
		"$KV.demo-sync-state.>",
		"$JS.API.DIRECT.GET.KV_demo-sync-state.$KV.demo-sync-state.>",
	} {
		if slices.Contains(perms.PubAllow, unwanted) {
			t.Fatalf("access none must not grant %q: %v", unwanted, perms.PubAllow)
		}
	}
}

// access: none without manage grants NOTHING on the bucket — it is an inert entry, but a
// valid one (useful for documenting it in the template and enabling it later).
//
// All that remains is $JS.API.INFO, which is granted per template and not per bucket: it is
// the account info request, and it exposes no data.
func TestKVNoneWithoutManageGrantsNothingOnTheBucket(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b", Access: KVNone}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	assertSubjects(t, "pub", perms.PubAllow, []string{jsAccountInfoSubject})
	if len(perms.SubAllow) != 0 {
		t.Fatalf("expected no sub, got %v", perms.SubAllow)
	}
}

// $JS.API.INFO is granted only if the template declares some KV access: a template without
// `kv:` must not be able to query the JetStream account.
func TestJetStreamInfoOnlyWhenKVDeclared(t *testing.T) {
	tmpl := &Template{Pub: SubjectSet{Allow: []string{"{{instance}}.{{user_id}}.api.>"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if slices.Contains(perms.PubAllow, jsAccountInfoSubject) {
		t.Fatalf("a template without kv: must not grant %s", jsAccountInfoSubject)
	}
}

func TestKVDefaultsToReadAllKeys(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b"}}}

	perms, err := tmpl.Expand(personIdentity())
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	assertSubjects(t, "sub", perms.SubAllow, []string{"$KV.b.>"})
	if slices.Contains(perms.PubAllow, "$KV.b.>") {
		t.Fatal("the default access must be read-only")
	}
}

func TestKVInvalidAccessFails(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Bucket: "b", Access: "write-only"}}}

	_, err := tmpl.Expand(personIdentity())
	if !errors.Is(err, ErrInvalidKVAccess) {
		t.Fatalf("expected ErrInvalidKVAccess, got %v", err)
	}
}

func TestKVEmptyBucketFails(t *testing.T) {
	tmpl := &Template{KV: []KVAccess{{Access: KVRead}}}

	_, err := tmpl.Expand(personIdentity())
	if !errors.Is(err, ErrEmptyBucket) {
		t.Fatalf("expected ErrEmptyBucket, got %v", err)
	}
}

// --- loading from disk ----------------------------------------------------------------

func TestLoadTemplateRejectsBadPlaceholderAtLoad(t *testing.T) {
	// Validation has to happen at LOAD time, not on the first connection: a typo in a
	// template must prevent startup.
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	content := "pub:\n  allow:\n    - \"{{instance}}.{{nope}}.api.>\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LoadTemplate(path); !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("expected ErrUnknownPlaceholder at load time, got %v", err)
	}
}

func TestLoadTemplateMissingFile(t *testing.T) {
	if _, err := LoadTemplate(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a non-existent file")
	}
}

// assertSubjects compares regardless of order: order in the JWT does not change the
// permission's semantics, and pinning it would make the test brittle against a harmless
// reordering.
func assertSubjects(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: expected %d subjects %v, got %d %v", label, len(want), want, len(got), got)
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Fatalf("%s: missing %q in %v", label, w, got)
		}
	}
}
