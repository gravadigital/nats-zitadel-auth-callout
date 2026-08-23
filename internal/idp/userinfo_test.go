package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The enrichment is an HTTP call on the path that authenticates a NATS connection, and that path
// is serialized. So what these tests pin is not "does it parse JSON" but the three properties
// that make it safe to switch on: it caches, the token always wins, and a provider that fails
// does not fail the authentication.

// userinfoServer serves a fixed userinfo response and counts the requests.
func userinfoServer(t *testing.T, body string, status int) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got == "" {
			t.Errorf("userinfo called with no bearer token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

const anaUserinfo = `{"sub":"u-ana","preferred_username":"ana","name":"Ana Pérez","email":"ana@example.com"}`

func TestUserinfoFetchCachesPerSubject(t *testing.T) {
	srv, calls := userinfoServer(t, anaUserinfo, http.StatusOK)
	fetcher := newUserinfoFetcher(srv.URL, srv.Client(), time.Second)

	for i := 0; i < 5; i++ {
		got, ok := fetcher.fetch(context.Background(), "u-ana", "token")
		if !ok || got.Email != "ana@example.com" {
			t.Fatalf("fetch %d = %#v, ok=%v", i, got, ok)
		}
	}
	// A reconnecting backend must not turn the callout into a request amplifier against the IdP.
	if n := calls.Load(); n != 1 {
		t.Errorf("userinfo was called %d times for one subject, want 1", n)
	}

	// A different identity is a different question.
	if _, ok := fetcher.fetch(context.Background(), "u-bob", "token"); !ok {
		t.Fatal("fetch for a second subject failed")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("userinfo was called %d times for two subjects, want 2", n)
	}
}

func TestUserinfoCacheExpires(t *testing.T) {
	srv, calls := userinfoServer(t, anaUserinfo, http.StatusOK)
	fetcher := newUserinfoFetcher(srv.URL, srv.Client(), time.Second)

	now := time.Now()
	fetcher.now = func() time.Time { return now }

	if _, ok := fetcher.fetch(context.Background(), "u-ana", "token"); !ok {
		t.Fatal("first fetch failed")
	}
	// Just inside the window: still cached.
	now = now.Add(userinfoTTL - time.Second)
	if _, ok := fetcher.fetch(context.Background(), "u-ana", "token"); !ok {
		t.Fatal("fetch inside the TTL failed")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("userinfo was called %d times inside the TTL, want 1", n)
	}
	// Past it: a name change has to become visible eventually.
	now = now.Add(2 * time.Second)
	if _, ok := fetcher.fetch(context.Background(), "u-ana", "token"); !ok {
		t.Fatal("fetch after the TTL failed")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("userinfo was called %d times after the TTL, want 2", n)
	}
}

func TestUserinfoFailureIsNotAnError(t *testing.T) {
	srv, _ := userinfoServer(t, `{"error":"no"}`, http.StatusInternalServerError)
	fetcher := newUserinfoFetcher(srv.URL, srv.Client(), time.Second)

	// Best effort by contract: these fields are informational, and a provider having a bad day
	// must never turn into a refused NATS connection.
	if _, ok := fetcher.fetch(context.Background(), "u-ana", "token"); ok {
		t.Error("a 500 from userinfo reported success")
	}
}

func TestUserinfoNilFetcherIsDisabled(t *testing.T) {
	// A provider whose discovery document declares no userinfo_endpoint.
	var fetcher *userinfoFetcher
	if _, ok := fetcher.fetch(context.Background(), "u-ana", "token"); ok {
		t.Error("a nil fetcher reported success")
	}
}

func TestProfileNeverOverwritesTheToken(t *testing.T) {
	claims := &Claims{
		Subject:  "u-ana",
		Username: "from-token",
		Name:     "From Token",
		Email:    "token@example.com",
	}
	profile{
		PreferredUsername: "from-userinfo",
		Name:              "From Userinfo",
		Email:             "userinfo@example.com",
	}.applyTo(claims)

	// What the token asserts was signed for this specific token; userinfo is a later, separately
	// scoped answer about the same identity. Letting it win would change what the callout read.
	if claims.Username != "from-token" || claims.Name != "From Token" || claims.Email != "token@example.com" {
		t.Errorf("userinfo overwrote the token's claims: %+v", claims)
	}
}

func TestProfileFillsOnlyWhatIsMissing(t *testing.T) {
	claims := &Claims{Subject: "u-ana", Username: "ana"}
	profile{PreferredUsername: "ignored", Name: "Ana Pérez", Email: "ana@example.com"}.applyTo(claims)

	if claims.Username != "ana" {
		t.Errorf("username = %q, want the token's", claims.Username)
	}
	if claims.Name != "Ana Pérez" || claims.Email != "ana@example.com" {
		t.Errorf("name/email = %q/%q, want them filled", claims.Name, claims.Email)
	}
}

func TestNeedsEnrichment(t *testing.T) {
	cases := []struct {
		name   string
		claims *Claims
		want   bool
	}{
		// The point of the check: a token that carries everything costs nothing.
		{"complete", &Claims{Username: "ana", Name: "Ana", Email: "ana@example.com"}, false},
		{"no email", &Claims{Username: "ana", Name: "Ana"}, true},
		{"no name", &Claims{Username: "ana", Email: "ana@example.com"}, true},
		{"nothing", &Claims{}, true},
	}
	for _, tc := range cases {
		if got := needsEnrichment(tc.claims); got != tc.want {
			t.Errorf("%s: needsEnrichment = %v, want %v", tc.name, got, tc.want)
		}
	}
}
