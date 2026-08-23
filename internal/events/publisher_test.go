package events

import (
	"strings"
	"testing"

	"github.com/gravadigital/nats-zitadel-auth-callout/internal/authz"
)

// probe is the identity a subject pattern is validated against at startup.
func probe(instance string) authz.Identity {
	return authz.Identity{Instance: instance, UserID: "probe", Service: "probe"}
}

func TestProbeSubjectExpandsThePattern(t *testing.T) {
	got, err := ProbeSubject("{{instance}}.events.auth", probe("prod"))
	if err != nil {
		t.Fatalf("ProbeSubject: %v", err)
	}
	if got != "prod.events.auth" {
		t.Errorf("subject = %q, want prod.events.auth", got)
	}
}

func TestProbeSubjectRejectsWhatCannotWork(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		// wantIn is a fragment the error has to name, so the message stays diagnosable rather
		// than just non-nil.
		wantIn string
	}{
		{
			// The events subject is expanded for EVERY authenticated connection, and `service` is
			// empty for a person: the subject would have an empty segment for every human being.
			name:    "service placeholder",
			pattern: "{{instance}}.events.{{service}}",
			wantIn:  "{{service}}",
		},
		{
			name:    "unknown placeholder",
			pattern: "{{instance}}.events.{{tenant}}",
			wantIn:  "tenant",
		},
		{
			// A message is published to ONE subject. A wildcard here would be silently dropped by
			// the server, which reports nothing to the publisher.
			name:    "wildcard",
			pattern: "{{instance}}.events.*",
			wantIn:  "wildcard",
		},
		{
			name:    "trailing greater-than",
			pattern: "{{instance}}.events.>",
			wantIn:  "wildcard",
		},
		{
			// $SYS, $JS and $KV are the server's own namespaces.
			name:    "reserved namespace",
			pattern: "$SYS.events.auth",
			wantIn:  "reserved namespace",
		},
		{
			name:    "empty segment",
			pattern: "{{instance}}..events",
			wantIn:  "empty segment",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ProbeSubject(tc.pattern, probe("prod"))
			if err == nil {
				t.Fatalf("ProbeSubject(%q) succeeded, want an error", tc.pattern)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q does not mention %q", err, tc.wantIn)
			}
		})
	}
}

func TestProbeSubjectRejectsInstancePlaceholderWithNoInstance(t *testing.T) {
	// The mirror of the templates' rule: {{instance}} with nothing configured would expand to an
	// empty segment, which is a subject that matches nothing.
	if _, err := ProbeSubject("{{instance}}.events.auth", probe("")); err == nil {
		t.Fatal("ProbeSubject with no instance succeeded, want an error")
	}
}

func TestSubjectMatches(t *testing.T) {
	cases := []struct {
		filter, subject string
		want            bool
	}{
		{"prod.events.auth", "prod.events.auth", true},
		{"prod.events.auth", "prod.events.other", false},
		{"prod.events.>", "prod.events.auth", true},
		{"prod.events.>", "prod.events.auth.extra", true},
		// `>` needs at least one token to cover: a stream filtered on `prod.events.>` does not
		// capture `prod.events`.
		{"prod.events.>", "prod.events", false},
		{"prod.*.auth", "prod.events.auth", true},
		{"prod.*.auth", "prod.events.more.auth", false},
		{"*.events.auth", "prod.events.auth", true},
		{">", "prod.events.auth", true},
		{"prod.events.auth", "prod.events", false},
		{"prod.events", "prod.events.auth", false},
	}

	for _, tc := range cases {
		if got := subjectMatches(tc.filter, tc.subject); got != tc.want {
			t.Errorf("subjectMatches(%q, %q) = %v, want %v", tc.filter, tc.subject, got, tc.want)
		}
	}
}

func TestSubjectsCoverTakesAnyFilter(t *testing.T) {
	filters := []string{"other.>", "prod.events.>"}
	if !subjectsCover(filters, "prod.events.auth") {
		t.Errorf("subjectsCover(%v, prod.events.auth) = false, want true", filters)
	}
	if subjectsCover(filters, "stage.events.auth") {
		t.Errorf("subjectsCover(%v, stage.events.auth) = true, want false", filters)
	}
}

// A nil publisher is the DISABLED publisher: the service holds nil when no subject is
// configured, and every call site goes through these methods unguarded.
func TestNilPublisherIsSafe(t *testing.T) {
	var p *Publisher
	p.Authenticated(sampleAuthentication())
	if err := p.Close(nil); err != nil { //nolint:staticcheck // a nil ctx is never reached
		t.Errorf("Close on a nil publisher: %v", err)
	}
	if p.Subject() != "" || p.Stream() != "" {
		t.Errorf("a nil publisher reports subject %q stream %q, want empty", p.Subject(), p.Stream())
	}
}
