package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// The Zitadel claims we care about.
const (
	// claimRolesAllProjects carries the roles of ALL projects the token has access to.
	claimRolesAllProjects = "urn:zitadel:iam:org:project:roles"
	// claimRolesProjectFmt carries the roles of ONE project. More precise: it prevents a
	// same-named role from another project matching a rule. Used when ProjectID is configured.
	claimRolesProjectFmt = "urn:zitadel:iam:org:project:%s:roles"
	// claimPreferredUsername is the user's human-readable name.
	claimPreferredUsername = "preferred_username"
)

// jwksRefreshInterval is how often Zitadel's JWKS is refreshed in the background.
//
// It is a FLOOR, not the exact interval: httprc uses the response's `max-age` if it is
// larger. With Zitadel it makes no difference — it answers `cache-control: no-store` and an
// `expires` in the past, so there is no `max-age` to latch onto and this value is the real
// interval.
//
// On its own this refresh is NOT enough to handle a rotation: between Zitadel starting to
// sign with a new key and the next refresh, tokens carrying that `kid` would be rejected.
// What closes that window is the on-demand refetch in refreshForUnknownKey.
const jwksRefreshInterval = 15 * time.Minute

// jwksRefetchCooldown is the minimum time between two on-demand refetches triggered by an
// unknown `kid`.
//
// Without this brake, a token with a made-up `kid` forces a GET against Zitadel's JWKS on
// every attempt — and that happens BEFORE authentication, so anyone can trigger it. It would
// turn the callout into a traffic amplifier against the IdP.
//
// One minute is generous for what it has to solve: in a real rotation a SINGLE refetch is
// enough to pick up the new key, and from then on the cache serves it.
const jwksRefetchCooldown = time.Minute

// userinfoTimeout bounds the call to /oidc/v1/userinfo. It is an optional enrichment: if it
// is slow or fails, authentication proceeds without a username.
const userinfoTimeout = 3 * time.Second

// errUnknownKeyIDFragment is the fragment jwx uses to report that the token's `kid` is not in
// the JWKS (jws/key_provider.go). It is the signal of a key rotation.
//
// It is detected by text because jwx v2 exposes no typed error for this case. That is fragile
// against a library change, which is why there is a test that fails if the message changes
// (TestUnknownKeyIDFragmentStillMatches): if jwx rewrites it, the refetch would stop firing
// and we would silently be back to the rejection window.
const errUnknownKeyIDFragment = "failed to find key with key ID"

// Zitadel verifies Zitadel access tokens against its JWKS.
//
// Verification is local (signature + claims), with no introspection: there is no round-trip
// to Zitadel per connection. The trade-off is that a revoked token stays valid until its
// `exp` — acceptable because the User JWT that gets minted expires with the token.
type Zitadel struct {
	issuer     string
	projectID  string
	cache      *jwk.Cache
	jwksURL    string
	httpClient *http.Client
	// enrichUsername requests /oidc/v1/userinfo when the token carries no human-readable
	// name. Machine user tokens usually do not carry one, and the name is what makes
	// `nats server report connections` readable.
	enrichUsername bool

	// now is the cooldown's time source. It exists so tests can move the clock without
	// sleeping; in production it is time.Now.
	now func() time.Time

	// mu guards lastRefetch. VerifyToken runs concurrently — once per incoming connection —
	// so the cooldown is shared state.
	mu sync.Mutex
	// lastRefetch is when the last on-demand refetch happened. Zero means there has not been
	// one yet.
	lastRefetch time.Time
}

// ZitadelOption configures a Zitadel.
type ZitadelOption func(*Zitadel)

// WithProjectID narrows role extraction to a single project. Without it, the roles of every
// project in the token are read.
func WithProjectID(projectID string) ZitadelOption {
	return func(z *Zitadel) { z.projectID = projectID }
}

// WithUsernameEnrichment enables querying userinfo when the token carries no name.
func WithUsernameEnrichment(enabled bool) ZitadelOption {
	return func(z *Zitadel) { z.enrichUsername = enabled }
}

// withClock replaces the refetch cooldown's time source. Tests only: it allows exercising the
// rate limit without sleeping for a minute.
func withClock(now func() time.Time) ZitadelOption {
	return func(z *Zitadel) {
		if now != nil {
			z.now = now
		}
	}
}

// WithHTTPClient replaces the HTTP client (for tests, or to pin timeouts/proxy settings).
func WithHTTPClient(client *http.Client) ZitadelOption {
	return func(z *Zitadel) {
		if client != nil {
			z.httpClient = client
		}
	}
}

// NewZitadel builds a verifier against the Zitadel instance at issuerURL.
//
// It discovers the JWKS through OIDC discovery and starts a cache with automatic refresh, so
// a key rotation in Zitadel does not require restarting the callout.
func NewZitadel(ctx context.Context, issuerURL string, opts ...ZitadelOption) (*Zitadel, error) {
	if issuerURL == "" {
		return nil, errors.New("idp: missing the Zitadel issuer URL")
	}
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	z := &Zitadel{
		issuer:         issuerURL,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		enrichUsername: true,
		now:            time.Now,
	}
	for _, opt := range opts {
		opt(z)
	}

	jwksURL, err := z.discoverJWKS(ctx)
	if err != nil {
		return nil, err
	}
	z.jwksURL = jwksURL

	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURL,
		jwk.WithMinRefreshInterval(jwksRefreshInterval),
		jwk.WithHTTPClient(z.httpClient),
	); err != nil {
		return nil, fmt.Errorf("idp: register JWKS %q: %w", jwksURL, err)
	}
	// First fetch at startup: if the JWKS cannot be read, better to fail here than to reject
	// every connection once up.
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("idp: read JWKS %q: %w", jwksURL, err)
	}
	z.cache = cache

	return z, nil
}

// discoverJWKS resolves jwks_uri through the OpenID Connect well-known document.
func (z *Zitadel) discoverJWKS(ctx context.Context) (string, error) {
	return discoverJWKSURL(ctx, z.httpClient, z.issuer, &z.issuer)
}

// discoverJWKSURL resolves jwks_uri through the OpenID Connect well-known document.
//
// issuerOut, when non-nil, receives the issuer the document DECLARES. That value wins over the
// URL used to reach it: tokens are validated against the declared issuer, and the two legimately
// differ behind a proxy or on an internal host.
func discoverJWKSURL(ctx context.Context, client *http.Client, issuerURL string, issuerOut *string) (string, error) {
	url := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("idp: build discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("idp: OIDC discovery at %q: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idp: OIDC discovery at %q returned %s", url, resp.Status)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("idp: parse discovery from %q: %w", url, err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("idp: the discovery document at %q carries no jwks_uri", url)
	}
	if doc.Issuer != "" && issuerOut != nil {
		*issuerOut = strings.TrimSuffix(doc.Issuer, "/")
	}
	return doc.JWKSURI, nil
}

// VerifyToken validates the token's signature, issuer and lifetime, and extracts the claims.
//
// Faced with a `kid` that is not in the cached JWKS — the case of a key rotation in Zitadel —
// it forces ONE refetch of the JWKS and retries. Without that, tokens signed with the new key
// would be rejected until the next periodic refresh (see jwksRefreshInterval).
func (z *Zitadel) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	set, err := z.cache.Get(ctx, z.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("idp: get JWKS: %w", err)
	}

	parsed, err := z.parse(token, set)
	if err != nil && isUnknownKeyID(err) {
		// The `kid` is not in the cache. It may be a rotation (reloading fixes it) or a token
		// with a made-up `kid` (reloading changes nothing, hence the cooldown).
		if fresh, ok := z.refreshForUnknownKey(ctx); ok {
			parsed, err = z.parse(token, fresh)
		}
	}
	if err != nil {
		// jwx does not expose expiry as a typed error, so it is distinguished by text. It
		// matters because an expired token is a normal case (the client must renew) and not an
		// invalid access attempt: they are audited differently.
		if strings.Contains(err.Error(), `"exp" not satisfied`) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	subject := parsed.Subject()
	if subject == "" {
		return nil, ErrNoSubject
	}

	claims := &Claims{
		Subject:   subject,
		ExpiresAt: parsed.Expiration(),
		Roles:     extractRoles(parsed, z.projectID),
		// Raw carries the private claims so deployment-declared placeholders can be read from
		// them. Only the claims declared in rules.yaml are ever looked up.
		Raw: parsed.PrivateClaims(),
	}

	if username, ok := stringClaim(parsed, claimPreferredUsername); ok {
		claims.Username = username
	}
	if claims.Username == "" && z.enrichUsername {
		// Best-effort: the username is for readability, not for authorization.
		if username, err := z.fetchUsername(ctx, token); err == nil {
			claims.Username = username
		}
	}

	return claims, nil
}

// parse validates the token against a specific JWKS. It is separate from VerifyToken because
// it runs twice: with the cached set and, if the `kid` was not there, with the freshly
// fetched set.
func (z *Zitadel) parse(token string, set jwk.Set) (jwt.Token, error) {
	return jwt.ParseString(token,
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(z.issuer),
		jwt.WithValidate(true),
	)
}

// isUnknownKeyID reports whether the error is "the token's `kid` is not in the JWKS".
func isUnknownKeyID(err error) bool {
	return err != nil && strings.Contains(err.Error(), errUnknownKeyIDFragment)
}

// refreshForUnknownKey forces a refetch of the JWKS and returns the new set.
//
// It returns ok=false if the cooldown has not elapsed yet or if the refetch failed; in both
// cases the caller keeps the original verification error. A JWKS that does not respond must
// not turn into a different error: for the client the outcome is the same — its token does not
// verify — and a signature error is more honest than a network one.
//
// The cooldown is marked BEFORE requesting the JWKS, not after: that way N concurrent
// connections with an unknown `kid` trigger a single fetch rather than N. It is what makes the
// rate limit useful exactly when it matters most, which is under load.
func (z *Zitadel) refreshForUnknownKey(ctx context.Context) (jwk.Set, bool) {
	z.mu.Lock()
	now := z.now()
	if !z.lastRefetch.IsZero() && now.Sub(z.lastRefetch) < jwksRefetchCooldown {
		z.mu.Unlock()
		return nil, false
	}
	z.lastRefetch = now
	z.mu.Unlock()

	set, err := z.cache.Refresh(ctx, z.jwksURL)
	if err != nil {
		return nil, false
	}
	return set, true
}

// extractRoles flattens the token's project roles into a list of names.
//
// Zitadel emits them as a nested object `{ "<role>": { "<orgId>": "<domain>" } }`. The
// callout only routes by role name, so it keeps the keys.
func extractRoles(token jwt.Token, projectID string) []string {
	claimNames := make([]string, 0, 2)
	if projectID != "" {
		claimNames = append(claimNames, fmt.Sprintf(claimRolesProjectFmt, projectID))
	}
	claimNames = append(claimNames, claimRolesAllProjects)

	for _, name := range claimNames {
		raw, ok := token.Get(name)
		if !ok {
			continue
		}
		nested, ok := raw.(map[string]any)
		if !ok || len(nested) == 0 {
			continue
		}
		roles := make([]string, 0, len(nested))
		for role := range nested {
			roles = append(roles, role)
		}
		return roles
	}
	return nil
}

// stringClaim reads a string-typed claim.
func stringClaim(token jwt.Token, name string) (string, bool) {
	raw, ok := token.Get(name)
	if !ok {
		return "", false
	}
	value, ok := raw.(string)
	return value, ok
}

// fetchUsername requests /oidc/v1/userinfo with the client's token to obtain a
// human-readable name. It is only used when the token carries no `preferred_username` — the
// typical case for a machine user.
func (z *Zitadel) fetchUsername(ctx context.Context, token string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, userinfoTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, z.issuer+"/oidc/v1/userinfo", nil)
	if err != nil {
		return "", fmt.Errorf("idp: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("idp: userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idp: userinfo returned %s", resp.Status)
	}

	var info struct {
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("idp: parse userinfo: %w", err)
	}
	if info.PreferredUsername != "" {
		return info.PreferredUsername, nil
	}
	return info.Name, nil
}

// Compile-time check.
var _ Verifier = (*Zitadel)(nil)
