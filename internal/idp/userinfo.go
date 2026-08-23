package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// This file holds the OIDC userinfo enrichment: the name and email of the identity behind a
// token, for the deployments that need them.
//
// WHY IT EXISTS AT ALL. An access token is not an ID token. Zitadel — and it is not alone in
// this — issues JWT access tokens that carry `preferred_username` and the roles, and NOT `name`
// or `email`, even when the token was requested with the `profile email` scopes. Those claims
// live in userinfo. So a deployment that wants an authentication event to say who signed in, by
// name, has exactly one standards-compliant place to get it.
//
// WHY IT IS OPT-IN AND CACHED. It is an HTTP call to the identity provider on the path that
// authenticates a NATS connection, and that path is serialized: the callout subscription hands
// requests to its handler one at a time. Uncached, a reconnecting fleet of backends would turn
// into a request amplifier against the IdP and add its latency to every connection. Cached per
// subject, it is one call per user per TTL — and off entirely unless a deployment asks for it.

// userinfoTTL is how long a fetched profile is reused.
//
// Five minutes is chosen against what the data is for: a display name and an email in an event
// payload. A user who changes their name sees it reflected within the window, and nothing about
// authorization depends on this — roles come from the token, always.
const userinfoTTL = 5 * time.Minute

// userinfoCacheMax bounds the cache. Without a bound, a deployment where every connection is a
// distinct identity would grow this map forever inside a long-lived process.
const userinfoCacheMax = 4096

// profile is what userinfo contributes. It is deliberately only these three fields: everything
// authorization-relevant comes from the token itself.
type profile struct {
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Email             string `json:"email"`
}

// empty reports whether the profile carries nothing worth caching or applying.
func (p profile) empty() bool {
	return p.PreferredUsername == "" && p.Name == "" && p.Email == ""
}

// userinfoFetcher reads the userinfo endpoint and caches the result per subject.
//
// It is shared by the Zitadel and the generic OIDC verifier: the endpoint comes from the
// discovery document in both cases, so there is nothing provider-specific left to justify two
// implementations.
type userinfoFetcher struct {
	endpoint string
	client   *http.Client
	// timeout bounds one call. The enrichment is a nicety, so it gives up quickly rather than
	// holding a connection's handshake.
	timeout time.Duration
	// now is the cache's time source, replaceable in tests.
	now func() time.Time

	mu     sync.Mutex
	cached map[string]cachedProfile
}

// cachedProfile is a profile with its expiry.
type cachedProfile struct {
	profile profile
	expires time.Time
}

// newUserinfoFetcher builds a fetcher against endpoint. A nil fetcher is a disabled one: every
// method is safe on it, which is what keeps the enrichment opt-in without a flag at each call
// site.
func newUserinfoFetcher(endpoint string, client *http.Client, timeout time.Duration) *userinfoFetcher {
	if endpoint == "" {
		return nil
	}
	return &userinfoFetcher{
		endpoint: endpoint,
		client:   client,
		timeout:  timeout,
		now:      time.Now,
		cached:   make(map[string]cachedProfile),
	}
}

// fetch returns the profile for subject, from the cache when it is still fresh.
//
// token is the CLIENT's access token: userinfo is a bearer-authenticated endpoint, so the only
// thing that can ask about an identity is that identity's own token. It is never logged and
// never stored — only the resulting profile is cached, keyed by subject.
func (f *userinfoFetcher) fetch(ctx context.Context, subject, token string) (profile, bool) {
	if f == nil {
		return profile{}, false
	}

	if cached, ok := f.lookup(subject); ok {
		return cached, true
	}

	fetched, err := f.request(ctx, token)
	if err != nil || fetched.empty() {
		// Best effort by design: the fields it fills are informational, so a provider that is
		// slow, down, or simply not returning them must not turn into a failed authentication.
		return profile{}, false
	}

	f.store(subject, fetched)
	return fetched, true
}

// lookup returns a cached profile if it has not expired.
func (f *userinfoFetcher) lookup(subject string) (profile, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	entry, ok := f.cached[subject]
	if !ok || !entry.expires.After(f.now()) {
		return profile{}, false
	}
	return entry.profile, true
}

// store caches a profile, sweeping expired entries when the cache is at its bound.
func (f *userinfoFetcher) store(subject string, p profile) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if len(f.cached) >= userinfoCacheMax {
		for key, entry := range f.cached {
			if !entry.expires.After(now) {
				delete(f.cached, key)
			}
		}
		// Still full: every entry is live. Serving without caching is the right trade — the
		// alternative is evicting something useful or growing without a bound.
		if len(f.cached) >= userinfoCacheMax {
			return
		}
	}
	f.cached[subject] = cachedProfile{profile: p, expires: now.Add(userinfoTTL)}
}

// request calls the userinfo endpoint with the client's token.
func (f *userinfoFetcher) request(ctx context.Context, token string) (profile, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.endpoint, nil)
	if err != nil {
		return profile{}, fmt.Errorf("idp: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := f.client.Do(req)
	if err != nil {
		return profile{}, fmt.Errorf("idp: userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return profile{}, fmt.Errorf("idp: userinfo returned %s", resp.Status)
	}

	var info profile
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return profile{}, fmt.Errorf("idp: parse userinfo: %w", err)
	}
	return info, nil
}

// applyTo fills in the claims the token did not carry, without ever overwriting one it did.
//
// The token wins on every field. What the token asserts was signed by the provider for this
// specific token; userinfo is a second, later answer about the same identity, and preferring it
// would let a stale or differently-scoped response change what the callout already read.
func (p profile) applyTo(claims *Claims) {
	if claims.Username == "" {
		claims.Username = p.PreferredUsername
	}
	if claims.Name == "" {
		claims.Name = p.Name
	}
	if claims.Email == "" {
		claims.Email = p.Email
	}
}

// needsEnrichment reports whether anything is still missing that userinfo could supply.
//
// It is what keeps the common case free: a token that already carries a username, a name and an
// email never triggers a call, so the enrichment costs nothing where the provider puts the
// claims in the token.
func needsEnrichment(claims *Claims) bool {
	return claims.Username == "" || claims.Name == "" || claims.Email == ""
}
