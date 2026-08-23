package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
	"github.com/gravadigital/nats-zitadel-auth-callout/internal/idp"
)

// The payload is a PUBLIC CONTRACT: consumers parse these field names. That is what these tests
// are for — not to check that Go can marshal a struct, but to make a rename or a dropped field
// fail here rather than in somebody else's service.

// sampleAuthentication is a person authenticating, with everything the callout would know.
func sampleAuthentication() Authentication {
	authenticated := time.Date(2026, 8, 23, 18, 4, 11, 0, time.UTC)
	return Authentication{
		Identity: authz.Identity{
			Instance: "prod",
			UserID:   "281234567890123456",
			Username: "ana@example.com",
			Type:     authz.UserTypePerson,
		},
		Claims: &idp.Claims{
			Subject:  "281234567890123456",
			Username: "ana@example.com",
			Roles:    []string{"app-user", "app-reader"},
			Raw: map[string]any{
				"name":  "Ana Pérez",
				"email": "ana@example.com",
			},
		},
		Decision: authz.Decision{
			Rule:          "app-user",
			Template:      "templates/person.yaml",
			IdentityModel: authz.UserTypePerson,
		},
		ClientIP:  "10.1.2.3",
		Session:   "UAWUJEWODGQJGMUGZBJH4Y6XKTVD5V4G5EQZXUJA5QV3ZL2TP2JY3ZNH",
		At:        authenticated,
		ExpiresAt: authenticated.Add(time.Hour),
	}
}

func TestEventPayloadCarriesEveryDocumentedField(t *testing.T) {
	data, err := json.Marshal(newEvent(sampleAuthentication(), DefaultNameClaim, DefaultEmailClaim))
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}

	want := map[string]any{
		"type":             "authenticated",
		"version":          float64(1),
		"id":               "281234567890123456",
		"name":             "Ana Pérez",
		"username":         "ana@example.com",
		"email":            "ana@example.com",
		"authenticated_at": "2026-08-23T18:04:11Z",
		"expires_at":       "2026-08-23T19:04:11Z",
		"instance":         "prod",
		"identity_type":    "person",
		"matched_role":     "app-user",
		"template":         "templates/person.yaml",
		"client_ip":        "10.1.2.3",
		"session":          "UAWUJEWODGQJGMUGZBJH4Y6XKTVD5V4G5EQZXUJA5QV3ZL2TP2JY3ZNH",
	}
	for key, expected := range want {
		if got[key] != expected {
			t.Errorf("%s = %#v, want %#v", key, got[key], expected)
		}
	}

	roles, ok := got["roles"].([]any)
	if !ok {
		t.Fatalf("roles = %#v, want a list", got["roles"])
	}
	if len(roles) != 2 || roles[0] != "app-user" || roles[1] != "app-reader" {
		t.Errorf("roles = %#v, want [app-user app-reader]", roles)
	}

	// A field appearing that nothing documents is worth catching too: the payload is a contract
	// and an accidental addition is a change to it.
	for key := range got {
		if _, documented := want[key]; !documented && key != "roles" {
			t.Errorf("undocumented field in the payload: %q", key)
		}
	}
}

func TestEventTimestampsAreUTC(t *testing.T) {
	in := sampleAuthentication()
	// A deployment in Buenos Aires must not publish local time: consumers correlate these with
	// logs from everywhere else.
	buenosAires := time.FixedZone("ART", -3*60*60)
	in.At = in.At.In(buenosAires)
	in.ExpiresAt = in.ExpiresAt.In(buenosAires)

	event := newEvent(in, DefaultNameClaim, DefaultEmailClaim)
	if zone, _ := event.AuthenticatedAt.Zone(); zone != "UTC" {
		t.Errorf("authenticated_at zone = %q, want UTC", zone)
	}
	if zone, _ := event.ExpiresAt.Zone(); zone != "UTC" {
		t.Errorf("expires_at zone = %q, want UTC", zone)
	}
}

func TestEventNameFallsBackToTheUsername(t *testing.T) {
	in := sampleAuthentication()
	// A machine user's token carries no `name`. Leaving the field empty while a perfectly good
	// username exists helps nobody.
	in.Claims.Raw = map[string]any{}

	event := newEvent(in, DefaultNameClaim, DefaultEmailClaim)
	if event.Name != "ana@example.com" {
		t.Errorf("name = %q, want the username as the fallback", event.Name)
	}
}

func TestEventOmitsAnAbsentEmail(t *testing.T) {
	in := sampleAuthentication()
	// A Zitadel machine user has no email at all. That is not an error: an informational event
	// must never be able to refuse a connection.
	in.Claims.Raw = map[string]any{"name": "api backend"}

	data, err := json.Marshal(newEvent(in, DefaultNameClaim, DefaultEmailClaim))
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if _, present := got["email"]; present {
		t.Errorf("email is present with no email claim: %#v", got["email"])
	}
}

func TestEventRolesAreNeverNull(t *testing.T) {
	in := sampleAuthentication()
	in.Claims.Roles = nil

	data, err := json.Marshal(newEvent(in, DefaultNameClaim, DefaultEmailClaim))
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	// A consumer should not have to tell "no roles" from "field missing".
	if want := `"roles":[]`; !strings.Contains(string(data), want) {
		t.Errorf("payload does not carry %s: %s", want, data)
	}
}

func TestEventReadsConfiguredClaimPaths(t *testing.T) {
	in := sampleAuthentication()
	// A provider that nests them. This is the same claim-path mechanism declared placeholders
	// use, which is why no verifier code has to know about the event.
	in.Claims.Raw = map[string]any{
		"profile": map[string]any{
			"full_name": "Ana Pérez",
			"mail":      "ana@example.com",
		},
	}

	event := newEvent(in, "profile.full_name", "profile.mail")
	if event.Name != "Ana Pérez" {
		t.Errorf("name = %q, want the value at profile.full_name", event.Name)
	}
	if event.Email != "ana@example.com" {
		t.Errorf("email = %q, want the value at profile.mail", event.Email)
	}
}

func TestEventSurvivesMissingClaims(t *testing.T) {
	// Claims are never nil in the service, but an event that panics would take the callout's
	// goroutine with it — the one that serves every authentication.
	in := sampleAuthentication()
	in.Claims = nil

	event := newEvent(in, DefaultNameClaim, DefaultEmailClaim)
	if event.ID != "281234567890123456" {
		t.Errorf("id = %q, want the identity's user id", event.ID)
	}
	if len(event.Roles) != 0 {
		t.Errorf("roles = %#v, want empty", event.Roles)
	}
}
